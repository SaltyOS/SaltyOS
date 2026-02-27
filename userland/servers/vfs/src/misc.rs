// SPDX-License-Identifier: GPL-2.0-only
//! Terminal I/O, ioctl, fcntl, shared memory, and mmap handlers.

use besalt::consts::*;
use besalt::ipc;
use besalt::types::*;

use crate::client::{extract_path, get_client};
use crate::consts::*;
use crate::fileops::normalize_path_for_client;
use crate::mount::mount_truncate;
use crate::path::{resolve_parent, resolve_path};
use crate::pipe::dup_fd_entry;
use crate::poll::wake_poll_waiters;
use crate::ramfs::{alloc_inode, chain_truncate, dir_add_entry, dir_remove_entry, inode_by_ino};
use crate::socket::alloc_reply_slot;
use crate::types::*;
use crate::{
    ipc_ctx, max_clients, max_shm_objects, max_shm_pages, vfs_grow_pool, CLIENTS, SHM_DATA,
};

/// Handle a deferred PTY device read. Called from main loop when fd is DEV_PTY_SLAVE.
/// Returns true if reply is deferred (skip_reply), false if reply is ready now.
pub(crate) unsafe fn handle_pty_dev_read(
    msg: *const BesaltMsg,
    fde: *mut FdEntry,
    reply: *mut BesaltMsg,
    badge: u64,
) -> bool {
    unsafe {
        let count = (*msg).regs[1];
        let max = if count > 152 { 152 } else { count };
        let pty_id = (*fde).sock_id as u64;

        // Try-read from ttyd (always returns immediately)
        let mut treq = BesaltMsg::zeroed();
        let mut treply = BesaltMsg::zeroed();
        treq.label = TTYD_PTY_READ;
        treq.regs[0] = pty_id;
        treq.regs[1] = max;
        treq.length = 2;

        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
        if err != 0 || treply.label != BESALT_OK {
            (*reply).label = BESALT_INVALID_OPERATION;
            return false;
        }

        let actual = treply.regs[0];
        if actual > 0 {
            // Data available — return immediately
            (*reply).label = BESALT_OK;
            (*reply).length = 1 + (actual + 7) / 8;
            (*reply).regs[0] = actual;
            let src = &treply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for i in 0..actual as usize {
                *dst.add(i) = *src.add(i);
            }
            return false;
        }

        // WOULD_BLOCK — save caller's reply cap, enqueue pending reader
        let pid = pty_id as usize;
        if pid >= MAX_PTYS || crate::PTY_PENDING_COUNT[pid] >= MAX_PTY_WAITERS {
            (*reply).label = BESALT_BUSY;
            return false;
        }

        let slot = alloc_reply_slot();
        let save_err = besalt::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if save_err != 0 {
            (*reply).label = BESALT_INVALID_OPERATION;
            return false;
        }

        let idx = crate::PTY_PENDING_COUNT[pid];
        crate::PTY_PENDING[pid][idx] = PtyPendingReader {
            active: 1,
            badge,
            reply_slot: slot,
            max_count: max,
        };
        crate::PTY_PENDING_COUNT[pid] += 1;

        true // deferred — VFS will wake this reader when ttyd signals data-ready
    }
}

/// Handle bound notification from ttyd signalling PTY data ready.
/// Called when VFS wakes from reply_recv with a notification (msg.length==0, badge!=0).
/// Wakes pending PTY readers by collecting data from ttyd and forwarding to saved reply caps.
pub(crate) unsafe fn handle_pty_notification(ntfn_badge: u64) {
    unsafe {
        for pty_id in 0..MAX_PTYS {
            if ntfn_badge & (1u64 << pty_id) == 0 {
                continue;
            }

            // Wake pending readers for this PTY in FIFO order
            while crate::PTY_PENDING_COUNT[pty_id] > 0 {
                let reader = crate::PTY_PENDING[pty_id][0];
                if reader.active == 0 {
                    break;
                }

                // Collect data from ttyd
                let mut creq = BesaltMsg::zeroed();
                let mut creply = BesaltMsg::zeroed();
                creq.label = TTYD_PTY_COLLECT;
                creq.regs[0] = pty_id as u64;
                creq.regs[1] = reader.max_count;
                creq.length = 2;
                let cerr =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const creq, &raw mut creply);

                let actual = creply.regs[0];
                if actual == 0 {
                    break; // buffer drained
                }

                // Forward data to saved client reply cap
                let mut wake = BesaltMsg::zeroed();
                wake.label = BESALT_OK;
                wake.length = 1 + (actual + 7) / 8;
                wake.regs[0] = actual;
                let src = &creply.regs[1] as *const u64 as *const u8;
                let dst = &raw mut wake.regs[1] as *mut u8;
                for i in 0..actual as usize {
                    *dst.add(i) = *src.add(i);
                }
                ipc::send_ctx(ipc_ctx(), reader.reply_slot, &raw const wake);

                // Shift remaining waiters forward (FIFO)
                for j in 1..crate::PTY_PENDING_COUNT[pty_id] {
                    crate::PTY_PENDING[pty_id][j - 1] = crate::PTY_PENDING[pty_id][j];
                }
                crate::PTY_PENDING_COUNT[pty_id] -= 1;
                if crate::PTY_PENDING_COUNT[pty_id] < MAX_PTY_WAITERS {
                    crate::PTY_PENDING[pty_id][crate::PTY_PENDING_COUNT[pty_id]] =
                        PtyPendingReader::zeroed();
                }
            }

            // Wake poll/epoll waiters for PTY fds (POLLIN event)
            // Iterate all clients to find PTY fds on this pty_id
            for ci in 0..max_clients() {
                let cli = &*(&raw const CLIENTS!()[ci]);
                if cli.active == 0 {
                    continue;
                }
                for fi in 0..(*cli).fds_cap as usize {
                    if (*cli.fds.add(fi)).active != 0
                        && (*cli.fds.add(fi)).fd_type == FD_TYPE_DEVICE
                        && (*cli.fds.add(fi)).dev_type == DEV_PTY_SLAVE
                        && (*cli.fds.add(fi)).sock_id as usize == pty_id
                    {
                        wake_poll_waiters(cli.badge, fi as i32, 0x001); // POLLIN
                    }
                }
            }
        }
    }
}

pub(crate) unsafe fn handle_isatty(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let is_tty = if (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_DEVICE
            && ((*(*cli).fds.add(fd as usize)).dev_type == DEV_CONSOLE
                || (*(*cli).fds.add(fd as usize)).dev_type == DEV_PTY_SLAVE)
        {
            1u64
        } else {
            0u64
        };

        (*reply).label = BESALT_OK;
        (*reply).length = 1;
        (*reply).regs[0] = is_tty;
    }
}

/// Forward tcgetattr to ttyd (for PTY) or console server (for /dev/console)
pub(crate) unsafe fn handle_tcgetattr(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);
        if fde.fd_type != FD_TYPE_DEVICE {
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        if fde.dev_type == DEV_PTY_SLAVE {
            // Forward to ttyd via TTYD_PTY_TCGETATTR
            let mut treq = BesaltMsg::zeroed();
            let mut treply = BesaltMsg::zeroed();
            treq.label = TTYD_PTY_TCGETATTR;
            treq.regs[0] = fde.sock_id as u64; // pty_id
            treq.length = 1;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != BESALT_OK {
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }
            (*reply).label = BESALT_OK;
            (*reply).length = treply.length;
            for i in 0..treply.length as usize {
                (*reply).regs[i] = treply.regs[i];
            }
        } else if fde.dev_type == DEV_CONSOLE {
            // Forward to console server
            let mut creq = BesaltMsg::zeroed();
            let mut creply = BesaltMsg::zeroed();
            creq.label = CONSOLE_TCGETATTR;
            creq.length = 0;
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_CONSOLE_EP,
                &raw const creq,
                &raw mut creply,
            );
            if err != 0 || creply.label != BESALT_OK {
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }
            (*reply).label = BESALT_OK;
            (*reply).length = creply.length;
            for i in 0..creply.length as usize {
                (*reply).regs[i] = creply.regs[i];
            }
        } else {
            (*reply).label = BESALT_INVALID_OPERATION;
        }
    }
}

/// Forward tcsetattr to ttyd (for PTY) or console server (for /dev/console)
pub(crate) unsafe fn handle_tcsetattr(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);
        if fde.fd_type != FD_TYPE_DEVICE {
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        if fde.dev_type == DEV_PTY_SLAVE {
            // Forward to ttyd via TTYD_PTY_TCSETATTR
            // msg layout: regs[0]=fd, regs[1]=action, regs[2..11]=termios data
            let mut treq = BesaltMsg::zeroed();
            let mut treply = BesaltMsg::zeroed();
            treq.label = TTYD_PTY_TCSETATTR;
            treq.regs[0] = fde.sock_id as u64; // pty_id
                                               // Copy termios data from regs[1..] (action + flags + c_cc)
            let copy_len = if (*msg).length > 1 {
                (*msg).length - 1
            } else {
                0
            };
            for i in 0..copy_len as usize {
                treq.regs[i + 1] = (*msg).regs[i + 1];
            }
            treq.length = 1 + copy_len;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != BESALT_OK {
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }
            (*reply).label = BESALT_OK;
            (*reply).length = 0;
        } else if fde.dev_type == DEV_CONSOLE {
            // Forward to console server
            let mut creq = BesaltMsg::zeroed();
            let mut creply = BesaltMsg::zeroed();
            creq.label = CONSOLE_TCSETATTR;
            creq.length = (*msg).length;
            for i in 0..(*msg).length as usize {
                creq.regs[i] = (*msg).regs[i];
            }
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_CONSOLE_EP,
                &raw const creq,
                &raw mut creply,
            );
            if err != 0 || creply.label != BESALT_OK {
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }
            (*reply).label = BESALT_OK;
            (*reply).length = 0;
        } else {
            (*reply).label = BESALT_INVALID_OPERATION;
        }
    }
}

pub(crate) unsafe fn handle_ioctl(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let request = (*msg).regs[1];
        let arg = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);

        if fde.fd_type == FD_TYPE_DEVICE && fde.dev_type == DEV_FB0 {
            handle_ioctl_fb0(request, reply);
            return;
        }

        // Terminal ioctls — supported by both console and PTY devices
        if fde.fd_type != FD_TYPE_DEVICE
            || (fde.dev_type != DEV_CONSOLE && fde.dev_type != DEV_PTY_SLAVE)
        {
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        let pty_id = if fde.dev_type == DEV_PTY_SLAVE {
            fde.sock_id as u64
        } else {
            0u64
        };

        match request {
            // TIOCGPGRP: get foreground process group
            0x540F => {
                let mut treq = BesaltMsg::zeroed();
                let mut treply = BesaltMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x540F; // TIOCGPGRP
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != BESALT_OK {
                    (*reply).label = BESALT_INVALID_OPERATION;
                    return;
                }
                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = treply.regs[0];
            }
            // TIOCSPGRP: set foreground process group
            0x5410 => {
                let mut treq = BesaltMsg::zeroed();
                let mut treply = BesaltMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5410; // TIOCSPGRP
                treq.regs[2] = (*msg).regs[2]; // pgid
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    BESALT_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCSCTTY: acquire controlling tty
            0x540E => {
                let mut treq = BesaltMsg::zeroed();
                let mut treply = BesaltMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x540E; // TIOCSCTTY
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    BESALT_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCNOTTY: release controlling tty
            0x5422 => {
                let mut treq = BesaltMsg::zeroed();
                let mut treply = BesaltMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5422; // TIOCNOTTY
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    BESALT_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCGWINSZ: get terminal window size
            0x5413 => {
                let mut treq = BesaltMsg::zeroed();
                let mut treply = BesaltMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5413; // TIOCGWINSZ
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != BESALT_OK {
                    // Fallback to default 80x24
                    (*reply).label = BESALT_OK;
                    (*reply).length = 2;
                    (*reply).regs[0] = 24;
                    (*reply).regs[1] = 80;
                    return;
                }
                (*reply).label = BESALT_OK;
                (*reply).length = 2;
                (*reply).regs[0] = treply.regs[0];
                (*reply).regs[1] = treply.regs[1];
            }
            _ => {
                (*reply).label = BESALT_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_ioctl_fb0(request: u64, reply: *mut BesaltMsg) {
    unsafe {
        match request {
            // FBIOGET_VSCREENINFO
            0x4600 => {
                (*reply).label = BESALT_OK;
                (*reply).length = 5;
                (*reply).regs[0] = crate::FB_WIDTH as u64;
                (*reply).regs[1] = crate::FB_HEIGHT as u64;
                (*reply).regs[2] = crate::FB_BPP as u64;
                (*reply).regs[3] = ((crate::FB_RED_POS as u64) << 24)
                    | ((crate::FB_RED_SIZE as u64) << 16)
                    | ((crate::FB_GREEN_POS as u64) << 8)
                    | (crate::FB_GREEN_SIZE as u64);
                (*reply).regs[4] =
                    ((crate::FB_BLUE_POS as u64) << 24) | ((crate::FB_BLUE_SIZE as u64) << 16);
            }
            // FBIOGET_FSCREENINFO
            0x4602 => {
                (*reply).label = BESALT_OK;
                (*reply).length = 3;
                (*reply).regs[0] = crate::FB_PITCH as u64;
                (*reply).regs[1] = crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64;
                (*reply).regs[2] = 0; // type = packed pixels
            }
            _ => {
                (*reply).label = BESALT_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_munmap(_msg: *const BesaltMsg, reply: *mut BesaltMsg, _badge: u64) {
    unsafe {
        // VFS does not manage user virtual address space directly; munmap is
        // handled on the client side via mmsrv.  Acknowledge the request so
        // the caller is not blocked.
        (*reply).label = BESALT_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_mmap(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let _offset = (*msg).regs[1];
        let length = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);

        // SHM mmap — delegate to mmsrv
        if fde.fd_type == FD_TYPE_SHM {
            let inode = inode_by_ino(fde.inode);
            if inode.is_null() || (*inode).ftype != FTYPE_SHM {
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }

            let shm_idx = (*inode).dev_type as usize;
            if shm_idx >= max_shm_objects() {
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }

            let prot = (*msg).regs[3];

            let mut mm_msg = BesaltMsg::zeroed();
            let mut mm_reply = BesaltMsg::zeroed();
            mm_msg.label = MM_SHM_MAP;
            mm_msg.length = 4;
            mm_msg.regs[0] = shm_idx as u64;
            mm_msg.regs[1] = badge; // client badge = pid
            mm_msg.regs[2] = 0; // vaddr = 0 (let mmsrv pick)
            mm_msg.regs[3] = prot;
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != BESALT_OK {
                (*reply).label = BESALT_OUT_OF_MEMORY;
                return;
            }

            // Store the mapped vaddr in fd.offset for MM_SHM_UNMAP on close
            (*(*cli).fds.add(fd as usize)).offset = mm_reply.regs[0];

            (*reply).label = BESALT_OK;
            (*reply).length = 3;
            (*reply).regs[0] = mm_reply.regs[0]; // mapped base addr
            (*reply).regs[1] = 0;
            (*reply).regs[2] = 1; // server-side mapped flag
            return;
        }

        // FB0 device mmap — cap transfer
        if fde.fd_type != FD_TYPE_DEVICE || fde.dev_type != DEV_FB0 {
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        if crate::FB_MMAP_BADGE != 0 && crate::FB_MMAP_BADGE != badge {
            (*reply).label = BESALT_BUSY;
            return;
        }

        let smem_len = crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64;
        if length > smem_len {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        ipc::set_send_cap_ctx(ipc_ctx(), 0, VFS_CAP_FB_UNTYPED);

        crate::FB_MMAP_BADGE = badge;

        (*reply).label = BESALT_OK;
        (*reply).length = 3;
        (*reply).regs[0] = smem_len;
        (*reply).regs[1] = crate::FB_PITCH as u64;
        (*reply).regs[2] = 0;
    }
}

pub(crate) unsafe fn handle_fcntl(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cmd = (*msg).regs[1] as i32;
        let arg = (*msg).regs[2] as i64;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        match cmd {
            // F_DUPFD: duplicate fd, new fd >= arg
            0 | 1030 => {
                // F_DUPFD (0) and F_DUPFD_CLOEXEC (1030)
                let min_fd = if arg < 0 { 0 } else { arg as usize };
                let mut newfd: i32 = -1;
                let mut i = min_fd;
                while i < (*cli).fds_cap as usize {
                    if (*(*cli).fds.add(i)).active == 0 {
                        newfd = i as i32;
                        break;
                    }
                    i += 1;
                }
                if newfd < 0 {
                    (*reply).label = BESALT_OUT_OF_MEMORY;
                    return;
                }

                dup_fd_entry(cli, fd, newfd);
                // F_DUPFD_CLOEXEC sets FD_CLOEXEC on new fd
                if cmd == 1030 {
                    *(*cli).fd_flags.add(newfd as usize) = 1; // FD_CLOEXEC
                } else {
                    *(*cli).fd_flags.add(newfd as usize) = 0;
                }

                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = newfd as u64;
            }
            // F_GETFD: get fd flags
            1 => {
                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = *(*cli).fd_flags.add(fd as usize) as u64;
            }
            // F_SETFD: set fd flags
            2 => {
                *(*cli).fd_flags.add(fd as usize) = arg as u8;
                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            // F_GETFL: get file status flags
            3 => {
                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = (*(*cli).fds.add(fd as usize)).flags as u64;
            }
            // F_SETFL: set file status flags (only O_APPEND, O_NONBLOCK are changeable)
            4 => {
                let changeable = O_APPEND | O_NONBLOCK;
                let preserved = (*(*cli).fds.add(fd as usize)).flags & !changeable;
                (*(*cli).fds.add(fd as usize)).flags = preserved | (arg as u32 & changeable);
                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            _ => {
                (*reply).label = BESALT_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_chdir(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        };

        // Validate that path exists and is a directory
        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }
        if (*inode).ftype != FTYPE_DIRECTORY && (*inode).ftype != FTYPE_MOUNT_POINT {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return;
        }

        // Store the new cwd
        let copy_len = if (path_len as usize) < 127 {
            path_len as usize
        } else {
            127
        };
        let mut i = 0;
        while i < copy_len {
            (*cli).cwd[i] = *path_ptr.add(i);
            i += 1;
        }
        // Ensure null-terminated
        (*cli).cwd[copy_len] = 0;
        // Zero rest
        i = copy_len + 1;
        while i < 128 {
            (*cli).cwd[i] = 0;
            i += 1;
        }

        (*reply).label = BESALT_OK;
    }
}

pub(crate) unsafe fn handle_getcwd(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let max_size = (*msg).regs[0] as usize;

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return;
        }

        // Measure cwd length
        let mut cwd_len: usize = 0;
        while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
            cwd_len += 1;
        }
        if cwd_len == 0 {
            // Default to "/"
            cwd_len = 1;
            (*cli).cwd[0] = b'/';
            (*cli).cwd[1] = 0;
        }

        // POSIX getcwd(): caller buffer must fit full path + trailing NUL.
        if max_size == 0 || cwd_len + 1 > max_size {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        // Pack cwd bytes into reply regs[1..]
        let copy_len = cwd_len;
        (*reply).label = BESALT_OK;
        (*reply).regs[0] = copy_len as u64;
        let dst = &mut (*reply).regs[1] as *mut u64 as *mut u8;
        let mut i = 0;
        while i < copy_len {
            *dst.add(i) = (*cli).cwd[i];
            i += 1;
        }
        (*reply).length = 1 + ((copy_len as u64 + 7) / 8);
    }
}

pub(crate) unsafe fn handle_shm_open(
    msg: *const BesaltMsg,
    reply: *mut BesaltMsg,
    badge: u64,
) -> bool {
    unsafe {
        let flags = (*msg).regs[0] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 1, path.as_mut_ptr());

        // Build full path /dev/shm/<name>
        let mut full_path = [0u8; MAX_PATH_LEN];
        let prefix = b"/dev/shm/";
        for i in 0..prefix.len() {
            full_path[i] = prefix[i];
        }
        for i in 0..name_len as usize {
            if prefix.len() + i >= MAX_PATH_LEN {
                break;
            }
            full_path[prefix.len() + i] = path[i];
        }
        let full_len = (prefix.len() + name_len as usize) as u8;

        let existing = resolve_path(full_path.as_ptr(), full_len);

        if !existing.is_null() {
            if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
                (*reply).label = BESALT_ALREADY_EXISTS;
                return false;
            }
            // Open existing
            let cli = get_client(badge);
            if cli.is_null() {
                (*reply).label = BESALT_OUT_OF_MEMORY;
                return false;
            }
            for fd in 0..(*cli).fds_cap as usize {
                if (*(*cli).fds.add(fd)).active == 0 {
                    (*(*cli).fds.add(fd)).active = 1;
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_SHM;
                    (*(*cli).fds.add(fd)).inode = (*existing).ino;
                    crate::ramfs::inode_open((*existing).ino);
                    (*reply).label = BESALT_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = fd as u64;
                    return false;
                }
            }
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return false;
        }

        if (flags & O_CREAT) == 0 {
            // O_CREAT not set
            (*reply).label = BESALT_NOT_FOUND;
            return false;
        }

        // Ensure /dev/shm exists
        let shm_dir = resolve_path(b"/dev/shm".as_ptr(), 8);
        let parent = if shm_dir.is_null() {
            // Create /dev/shm
            let dev_dir = resolve_path(b"/dev".as_ptr(), 4);
            if dev_dir.is_null() {
                (*reply).label = BESALT_INVALID_OPERATION;
                return false;
            }
            let d = alloc_inode();
            if d.is_null() {
                (*reply).label = BESALT_OUT_OF_MEMORY;
                return false;
            }
            (*d).ftype = FTYPE_DIRECTORY;
            (*d).mode = S_IFDIR_L | 0o755;
            (*d).nlink = 2;
            (*d).parent_ino = (*dev_dir).ino;
            dir_add_entry(dev_dir, b"shm".as_ptr(), 3, (*d).ino);
            d
        } else {
            shm_dir
        };

        // Create SHM inode
        let inode = alloc_inode();
        if inode.is_null() {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return false;
        }
        (*inode).ftype = FTYPE_SHM;
        (*inode).mode = S_IFREG_L | 0o666;
        (*inode).parent_ino = (*parent).ino;
        (*inode).size = 0;
        dir_add_entry(parent, path.as_ptr(), name_len, (*inode).ino);

        // Allocate SHM data
        let mut shm_idx: i32 = -1;
        for i in 0..max_shm_objects() {
            if SHM_DATA!()[i].active == 0 {
                shm_idx = i as i32;
                SHM_DATA!()[i].active = 1;
                break;
            }
        }
        if shm_idx < 0 {
            // No free slot: grow and retry
            if vfs_grow_pool(
                &raw mut crate::SHM_DATA_PTR as *mut *mut u8,
                &raw mut crate::SHM_CAP,
                core::mem::size_of::<ShmData>(),
            ) == 0
            {
                for i in 0..max_shm_objects() {
                    if SHM_DATA!()[i].active == 0 {
                        shm_idx = i as i32;
                        SHM_DATA!()[i].active = 1;
                        break;
                    }
                }
            }
            if shm_idx < 0 {
                (*inode).active = 0;
                (*reply).label = BESALT_OUT_OF_MEMORY;
                return false;
            }
        }

        // Store SHM index in inode dev_type field (repurposed)
        (*inode).dev_type = shm_idx as u8;

        let cli = get_client(badge);
        if cli.is_null() {
            (*inode).active = 0;
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_SHM;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                crate::ramfs::inode_open((*inode).ino);
                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return false;
            }
        }

        (*inode).active = 0;
        (*reply).label = BESALT_OUT_OF_MEMORY;
        false
    }
}

pub(crate) unsafe fn handle_shm_unlink(msg: *const BesaltMsg, reply: *mut BesaltMsg) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 0, path.as_mut_ptr());

        let mut full_path = [0u8; MAX_PATH_LEN];
        let prefix = b"/dev/shm/";
        for i in 0..prefix.len() {
            full_path[i] = prefix[i];
        }
        for i in 0..name_len as usize {
            if prefix.len() + i >= MAX_PATH_LEN {
                break;
            }
            full_path[prefix.len() + i] = path[i];
        }
        let full_len = (prefix.len() + name_len as usize) as u8;

        let inode = resolve_path(full_path.as_ptr(), full_len);
        if inode.is_null() || (*inode).ftype != FTYPE_SHM {
            (*reply).label = BESALT_NOT_FOUND;
            return false;
        }

        // Remove from parent
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(
            full_path.as_ptr(),
            full_len,
            &mut child_name,
            &mut child_len,
        );
        if !parent.is_null() {
            dir_remove_entry(parent, child_name, child_len);
        }
        // Reset SHM data slot
        let shm_idx = (*inode).dev_type as usize;
        if shm_idx < max_shm_objects() {
            SHM_DATA!()[shm_idx].active = 0;
            SHM_DATA!()[shm_idx].num_pages = 0;
        }

        (*inode).active = 0;
        (*reply).label = BESALT_OK;
        false
    }
}

pub(crate) unsafe fn handle_ftruncate(
    msg: *const BesaltMsg,
    reply: *mut BesaltMsg,
    badge: u64,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let length = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return false;
        }

        let fde = *(*cli).fds.add(fd as usize);

        if fde.fd_type == FD_TYPE_MOUNT {
            mount_truncate(fde.dev_type as usize, fde.sock_id as u64, length, reply);
            return false;
        }

        if fde.fd_type == FD_TYPE_SHM {
            let inode = inode_by_ino(fde.inode);
            if inode.is_null() || (*inode).ftype != FTYPE_SHM {
                (*reply).label = BESALT_INVALID_OPERATION;
                return false;
            }

            let shm_idx = (*inode).dev_type as usize;
            if shm_idx >= max_shm_objects() {
                (*reply).label = BESALT_INVALID_OPERATION;
                return false;
            }

            let num_pages = ((length + 4095) / 4096) as u16;
            if num_pages as usize > max_shm_pages() {
                (*reply).label = BESALT_OUT_OF_MEMORY;
                return false;
            }

            // Delegate frame allocation to mmsrv via MM_SHM_CREATE
            let shm = &raw mut SHM_DATA!()[shm_idx];

            {
                let mut mm_msg = BesaltMsg::zeroed();
                let mut mm_reply = BesaltMsg::zeroed();
                mm_msg.label = MM_SHM_CREATE;
                mm_msg.length = 2;
                mm_msg.regs[0] = shm_idx as u64;
                mm_msg.regs[1] = num_pages as u64;
                let err = ipc::call_ctx(
                    ipc_ctx(),
                    VFS_CAP_MMSRV_EP,
                    &raw const mm_msg,
                    &raw mut mm_reply,
                );
                if err != 0 || mm_reply.label != BESALT_OK {
                    (*reply).label = BESALT_OUT_OF_MEMORY;
                    return false;
                }
            }

            (*shm).num_pages = num_pages;
            (*inode).size = length;

            (*reply).label = BESALT_OK;
            return false;
        }

        // Regular file truncate
        let inode = inode_by_ino(fde.inode);
        if inode.is_null() || (*inode).readonly != 0 {
            (*reply).label = BESALT_INVALID_OPERATION;
            return false;
        }
        if !(*inode).rw_data.is_null() && length < (*inode).size {
            chain_truncate((*inode).rw_data, length);
        }
        (*inode).size = length;
        (*reply).label = BESALT_OK;
        false
    }
}
