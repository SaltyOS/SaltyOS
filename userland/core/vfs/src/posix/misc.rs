// SPDX-License-Identifier: GPL-2.0-only
//! Terminal I/O, ioctl, fcntl, shared memory, and mmap pager handlers.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::client::{
    extract_path, get_client, object_descriptor_flags, object_set_cloexec,
    object_status_flags,
};
use crate::consts::*;
use crate::fileops::normalize_path_for_client;
use crate::mount::{mount_stat, mount_truncate, try_root_underlay};
use crate::path::{resolve_parent, resolve_path};
use crate::pipe::dup_object_entry;
use super::poll::wake_poll_waiters;
use crate::ramfs::{alloc_inode, chain_truncate, dir_add_entry, dir_remove_entry, inode_by_ino};
use super::socket::alloc_reply_slot;
use crate::types::*;
use crate::{
    ipc_ctx, max_clients, max_shm_objects, max_shm_pages, vfs_grow_pool, CLIENTS, SHM_DATA,
};

const VTIME: usize = 5;
const VMIN: usize = 6;

unsafe fn fetch_pty_termios(pty_id: u64, termios: *mut Termios) -> bool {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = POSIX_TTYSRV_PTY_TCGETATTR;
        req.regs[0] = pty_id;
        req.length = 1;

        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const req, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }

        (*termios).c_iflag = reply.regs[0] as u32;
        (*termios).c_oflag = reply.regs[1] as u32;
        (*termios).c_cflag = reply.regs[2] as u32;
        (*termios).c_lflag = reply.regs[3] as u32;
        (*termios).c_ispeed = reply.regs[4] as u32;
        (*termios).c_ospeed = reply.regs[5] as u32;
        (*termios).c_line = 0;
        let src = &reply.regs[6] as *const u64 as *const u8;
        for i in 0..32 {
            (*termios).c_cc[i] = *src.add(i);
        }

        true
    }
}

unsafe fn remove_pty_pending_reader(pty_id: usize, index: usize) {
    unsafe {
        let count = crate::PTY_PENDING_COUNT[pty_id];
        for j in (index + 1)..count {
            crate::PTY_PENDING[pty_id][j - 1] = crate::PTY_PENDING[pty_id][j];
        }
        crate::PTY_PENDING_COUNT[pty_id] -= 1;
        crate::PTY_PENDING[pty_id][crate::PTY_PENDING_COUNT[pty_id]] = PtyPendingReader::zeroed();
    }
}

unsafe fn send_pty_timeout_reply(reply_slot: u64) {
    unsafe {
        let mut wake = TronaMsg::zeroed();
        wake.label = TRONA_OK;
        wake.length = 1;
        wake.regs[0] = 0;
        ipc::send_ctx(ipc_ctx(), reply_slot, &raw const wake);
    }
}

pub(crate) unsafe fn expire_pty_read_timeouts(now_ns: u64) -> bool {
    unsafe {
        let mut expired = false;

        for pty_id in 0..MAX_PTYS {
            let mut index = 0usize;
            while index < crate::PTY_PENDING_COUNT[pty_id] {
                let reader = crate::PTY_PENDING[pty_id][index];
                if reader.active == 0 || reader.deadline_ns == 0 || reader.deadline_ns > now_ns {
                    index += 1;
                    continue;
                }

                send_pty_timeout_reply(reader.reply_slot);
                remove_pty_pending_reader(pty_id, index);
                expired = true;
            }
        }

        expired
    }
}

pub(crate) unsafe fn next_pty_read_timeout_ns(now_ns: u64) -> u64 {
    unsafe {
        let mut earliest = u64::MAX;

        for pty_id in 0..MAX_PTYS {
            for index in 0..crate::PTY_PENDING_COUNT[pty_id] {
                let reader = crate::PTY_PENDING[pty_id][index];
                if reader.active == 0 || reader.deadline_ns == 0 {
                    continue;
                }
                if reader.deadline_ns <= now_ns {
                    return 1;
                }
                if reader.deadline_ns < earliest {
                    earliest = reader.deadline_ns;
                }
            }
        }

        if earliest == u64::MAX {
            0
        } else {
            earliest.saturating_sub(now_ns)
        }
    }
}

unsafe fn read_backing_bytes(
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
    offset: u64,
    dst: *mut u8,
    count: u64,
) -> Option<u64> {
    match backing_kind {
        MMAP_BACKING_FILE => {
            let inode = inode_by_ino(backing_id0 as u32);
            if inode.is_null() {
                return None;
            }
            if offset >= (*inode).size {
                return Some(0);
            }
            let mut take = count;
            let avail = (*inode).size - offset;
            if take > avail {
                take = avail;
            }
            if !(*inode).ro_data.is_null() {
                let src = (*inode).ro_data.add(offset as usize);
                for i in 0..take as usize {
                    *dst.add(i) = *src.add(i);
                }
                Some(take)
            } else if !(*inode).rw_data.is_null() {
                Some(crate::ramfs::chain_read((*inode).rw_data, offset, dst, take))
            } else {
                Some(0)
            }
        }
        MMAP_BACKING_MOUNT => {
            let mount_idx = backing_id0 as usize;
            let remote_ino = backing_id1;
            if *(&raw const crate::VFS_SHM_ACTIVE) {
                let mut total = 0u64;
                let shm_chunk_max = crate::consts::VFS_SALTYFS_SHM_PAGES * 4096;
                while total < count {
                    let chunk = core::cmp::min(count - total, shm_chunk_max);
                    let mut reply = TronaMsg::zeroed();
                    crate::mount::mount_read_shm(
                        mount_idx,
                        remote_ino,
                        offset + total,
                        chunk,
                        0,
                        &raw mut reply,
                    );
                    if reply.label != TRONA_OK {
                        break;
                    }
                    let bytes = reply.regs[0];
                    let src = VFS_SALTYFS_SHM_VADDR as *const u8;
                    if bytes == 0 {
                        break;
                    }
                    for i in 0..bytes as usize {
                        *dst.add(total as usize + i) = *src.add(i);
                    }
                    total += bytes;
                    if bytes < chunk {
                        break;
                    }
                }
                if total == count {
                    Some(total)
                } else {
                    while total < count {
                        let chunk = (count - total).min(152);
                        let mut reply = TronaMsg::zeroed();
                        crate::mount::mount_read_inline(
                            mount_idx,
                            remote_ino,
                            offset + total,
                            chunk,
                            &raw mut reply,
                        );
                        if reply.label != TRONA_OK {
                            return None;
                        }
                        let bytes = reply.regs[0];
                        if bytes == 0 {
                            break;
                        }
                        let src = &raw const reply.regs[1] as *const u8;
                        for i in 0..bytes as usize {
                            *dst.add(total as usize + i) = *src.add(i);
                        }
                        total += bytes;
                        if bytes < chunk {
                            break;
                        }
                    }
                    Some(total)
                }
            } else {
                let mut total = 0u64;
                while total < count {
                    let chunk = (count - total).min(152);
                    let mut reply = TronaMsg::zeroed();
                    crate::mount::mount_read_inline(
                        mount_idx,
                        remote_ino,
                        offset + total,
                        chunk,
                        &raw mut reply,
                    );
                    if reply.label != TRONA_OK {
                        return None;
                    }
                    let bytes = reply.regs[0];
                    if bytes == 0 {
                        break;
                    }
                    let src = &raw const reply.regs[1] as *const u8;
                    for i in 0..bytes as usize {
                        *dst.add(total as usize + i) = *src.add(i);
                    }
                    total += bytes;
                    if bytes < chunk {
                        break;
                    }
                }
                Some(total)
            }
        }
        _ => None,
    }
}

unsafe fn write_backing_bytes(
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
    offset: u64,
    src: *const u8,
    count: u64,
) -> Option<u64> {
    match backing_kind {
        MMAP_BACKING_FILE => {
            let inode = inode_by_ino(backing_id0 as u32);
            if inode.is_null() || (*inode).readonly != 0 {
                return None;
            }
            if (*inode).rw_data.is_null() && count > 0 {
                (*inode).rw_data = crate::ramfs::alloc_writable();
                if (*inode).rw_data.is_null() {
                    return None;
                }
            }
            let written = crate::ramfs::chain_write((*inode).rw_data, offset, src, count);
            if written == 0 && count > 0 {
                return None;
            }
            let end = offset + written;
            if end > (*inode).size {
                (*inode).size = end;
            }
            Some(written)
        }
        MMAP_BACKING_MOUNT => {
            let mount_idx = backing_id0 as usize;
            let remote_ino = backing_id1;
            let mut total = 0u64;
            if *(&raw const crate::VFS_SHM_ACTIVE) {
                while total < count {
                    let chunk = core::cmp::min(count - total, crate::consts::VFS_SALTYFS_SHM_PAGES * 4096);
                    let dst = crate::consts::VFS_SALTYFS_SHM_VADDR as *mut u8;
                    for i in 0..chunk as usize {
                        *dst.add(i) = *src.add(total as usize + i);
                    }
                    let mut reply = TronaMsg::zeroed();
                    crate::mount::mount_write_shm(mount_idx, remote_ino, offset + total, chunk, 0, &raw mut reply);
                    if reply.label != TRONA_OK {
                        break;
                    }
                    let wrote = reply.regs[0];
                    total += wrote;
                    if wrote < chunk {
                        break;
                    }
                }
                if total == count {
                    Some(total)
                } else {
                    while total < count {
                        let chunk = core::cmp::min(count - total, 136);
                        let mut reply = TronaMsg::zeroed();
                        crate::mount::mount_write_inline(
                            mount_idx,
                            remote_ino,
                            offset + total,
                            src.add(total as usize),
                            chunk,
                            &raw mut reply,
                        );
                        if reply.label != TRONA_OK {
                            return None;
                        }
                        let wrote = reply.regs[0];
                        total += wrote;
                        if wrote < chunk {
                            break;
                        }
                    }
                    Some(total)
                }
            } else {
                while total < count {
                    let chunk = core::cmp::min(count - total, 136);
                    let mut reply = TronaMsg::zeroed();
                    crate::mount::mount_write_inline(
                        mount_idx,
                        remote_ino,
                        offset + total,
                        src.add(total as usize),
                        chunk,
                        &raw mut reply,
                    );
                    if reply.label != TRONA_OK {
                        return None;
                    }
                    let wrote = reply.regs[0];
                    total += wrote;
                    if wrote < chunk {
                        break;
                    }
                }
                Some(total)
            }
        }
        _ => None,
    }
}

/// Notify mmsrv that a file write occurred so it can invalidate cached mmap pages.
///
/// mmsrv will decommit committed MO pages in the write range; on next client
/// access the VMFault triggers VFS_PAGER_READ to re-read fresh data.
pub(crate) unsafe fn notify_mmsrv_mmap_write(
    fde: &ObjectEntry,
    ext: &PosixObjExt,
    offset: u64,
    count: u64,
    old_size: u64,
    new_size: u64,
) {
    let (backing_kind, id0, id1) = match fde.obj_type {
        OBJ_TYPE_FILE => (MMAP_BACKING_FILE, ext.inode as u64, 0u64),
        OBJ_TYPE_MOUNT => (MMAP_BACKING_MOUNT, ext.mount_idx as u64, ext.mount_remote_ino),
        _ => return,
    };

    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_SYNC_MMAP_WRITE;
    msg.length = 7;
    msg.regs[0] = backing_kind;
    msg.regs[1] = id0;
    msg.regs[2] = id1;
    msg.regs[3] = offset;
    msg.regs[4] = count;
    msg.regs[5] = old_size;
    msg.regs[6] = new_size;
    let _ = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
}

/// Notify mmsrv that a file was truncated so it can update region metadata.
pub(crate) unsafe fn notify_mmsrv_mmap_truncate(
    fde: &ObjectEntry,
    ext: &PosixObjExt,
    old_size: u64,
    new_size: u64,
) {
    let (backing_kind, id0, id1) = match fde.obj_type {
        OBJ_TYPE_FILE => (MMAP_BACKING_FILE, ext.inode as u64, 0u64),
        OBJ_TYPE_MOUNT => (MMAP_BACKING_MOUNT, ext.mount_idx as u64, ext.mount_remote_ino),
        _ => return,
    };

    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_SYNC_FILE_BACKING;
    msg.length = 5;
    msg.regs[0] = backing_kind;
    msg.regs[1] = id0;
    msg.regs[2] = id1;
    msg.regs[3] = new_size;
    msg.regs[4] = if new_size < old_size { MM_SYNC_BACKING_TRUNCATE } else { 0 };
    let _ = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
}

pub(crate) unsafe fn handle_pager_read(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let mo_cap = *(&raw const crate::CURRENT_RECV_SLOT);
        if mo_cap == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let backing_kind = (*msg).regs[0];
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let file_offset = (*msg).regs[3];
        let mo_page_idx = (*msg).regs[4];
        let bytes = (*msg).regs[5];

        let (has_err, has_page) = trona::invoke::mo_has_page(mo_cap, mo_page_idx);
        if has_err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        if has_page {
            (*reply).label = TRONA_OK;
            return;
        }

        let (commit_err, committed) = trona::invoke::mo_commit(mo_cap, mo_page_idx, 1, 0);
        if commit_err != 0 || committed != 1 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let map_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let map_err = trona::invoke::vspace_map_mo(
            CAP_SELF_VSPACE,
            mo_cap,
            VFS_FILE_MMAP_SCRATCH_VADDR,
            mo_page_idx,
            map_flags,
        );
        if map_err != 0 {
            let _ = trona::invoke::mo_decommit(mo_cap, mo_page_idx, 1);
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let dst = VFS_FILE_MMAP_SCRATCH_VADDR as *mut u8;
        core::ptr::write_bytes(dst, 0, 4096);
        if bytes > 0 && read_backing_bytes(backing_kind, backing_id0, backing_id1, file_offset, dst, bytes).is_none() {
            let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
            let _ = trona::invoke::mo_decommit(mo_cap, mo_page_idx, 1);
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
        (*reply).label = TRONA_OK;
    }
}

pub(crate) unsafe fn handle_pager_write(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let mo_cap = *(&raw const crate::CURRENT_RECV_SLOT);
        if mo_cap == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let backing_kind = (*msg).regs[0];
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let file_offset = (*msg).regs[3];
        let mo_page_idx = (*msg).regs[4];
        let bytes = (*msg).regs[5];

        let (has_err, has_page) = trona::invoke::mo_has_page(mo_cap, mo_page_idx);
        if has_err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        if !has_page || bytes == 0 {
            (*reply).label = TRONA_OK;
            return;
        }

        let map_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let map_err = trona::invoke::vspace_map_mo(
            CAP_SELF_VSPACE,
            mo_cap,
            VFS_FILE_MMAP_SCRATCH_VADDR,
            mo_page_idx,
            map_flags,
        );
        if map_err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let src = VFS_FILE_MMAP_SCRATCH_VADDR as *const u8;
        let wrote = write_backing_bytes(backing_kind, backing_id0, backing_id1, file_offset, src, bytes);
        let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
        if wrote == Some(bytes) {
            (*reply).label = TRONA_OK;
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}

/// Handle a deferred PTY device read. Called from main loop when fd is DEV_PTY_SLAVE.
/// Returns true if reply is deferred (skip_reply), false if reply is ready now.
pub(crate) unsafe fn handle_pty_dev_read(
    msg: *const TronaMsg,
    fde: *mut ObjectEntry,
    ext: *mut PosixObjExt,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let count = (*msg).regs[1];
        let max = if count > 152 { 152 } else { count };
        let pty_id = (*ext).pty_id as u64;

        // Try-read from posix_ttysrv (always returns immediately)
        let mut treq = TronaMsg::zeroed();
        let mut treply = TronaMsg::zeroed();
        treq.label = POSIX_TTYSRV_PTY_READ;
        treq.regs[0] = pty_id;
        treq.regs[1] = max;
        treq.length = 2;

        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
        if err != 0 || treply.label != TRONA_OK {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let actual = treply.regs[0];
        if actual > 0 {
            // Data available — return immediately
            (*reply).label = TRONA_OK;
            (*reply).length = 1 + (actual + 7) / 8;
            (*reply).regs[0] = actual;
            let src = &treply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for i in 0..actual as usize {
                *dst.add(i) = *src.add(i);
            }
            return false;
        }

        if ((*fde).flags & O_NONBLOCK as u32) != 0 {
            (*reply).label = TRONA_WOULD_BLOCK;
            return false;
        }

        let mut deadline_ns = 0u64;
        let mut termios = Termios::zeroed();
        if fetch_pty_termios(pty_id, &raw mut termios) {
            let vmin = termios.c_cc[VMIN] as u64;
            let vtime = termios.c_cc[VTIME] as u64;
            if vmin == 0 {
                if vtime == 0 {
                    (*reply).label = TRONA_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return false;
                }

                deadline_ns = super::poll::monotonic_now_ns()
                    .saturating_add(vtime.saturating_mul(100_000_000));
            }
        }

        // WOULD_BLOCK — save caller's reply cap, enqueue pending reader
        let pid = pty_id as usize;
        if pid >= MAX_PTYS || crate::PTY_PENDING_COUNT[pid] >= MAX_PTY_WAITERS {
            (*reply).label = TRONA_BUSY;
            return false;
        }

        let slot = alloc_reply_slot();
        let save_err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if save_err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let idx = crate::PTY_PENDING_COUNT[pid];
        crate::PTY_PENDING[pid][idx] = PtyPendingReader {
            active: 1,
            badge,
            reply_slot: slot,
            max_count: max,
            deadline_ns,
        };
        crate::PTY_PENDING_COUNT[pid] += 1;

        true // deferred — VFS will wake this reader when posix_ttysrv signals data-ready
    }
}

/// Handle bound notification from posix_ttysrv signalling PTY data ready.
/// Called when VFS wakes from reply_recv with a notification (msg.length==0, badge!=0).
/// Wakes pending PTY readers by collecting data from posix_ttysrv and forwarding to saved reply caps.
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

                // Collect data from posix_ttysrv
                let mut creq = TronaMsg::zeroed();
                let mut creply = TronaMsg::zeroed();
                creq.label = POSIX_TTYSRV_PTY_COLLECT;
                creq.regs[0] = pty_id as u64;
                creq.regs[1] = reader.max_count;
                creq.length = 2;
                let cerr =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const creq, &raw mut creply);

                let actual = creply.regs[0];
                if actual == 0 {
                    break; // buffer drained
                }

                // Forward data to saved client reply cap
                let mut wake = TronaMsg::zeroed();
                wake.label = TRONA_OK;
                wake.length = 1 + (actual + 7) / 8;
                wake.regs[0] = actual;
                let src = &creply.regs[1] as *const u64 as *const u8;
                let dst = &raw mut wake.regs[1] as *mut u8;
                for i in 0..actual as usize {
                    *dst.add(i) = *src.add(i);
                }
                ipc::send_ctx(ipc_ctx(), reader.reply_slot, &raw const wake);

                remove_pty_pending_reader(pty_id, 0);
            }

            // Wake poll/epoll waiters for PTY objects (POLLIN event)
            // Iterate all clients to find PTY objects on this pty_id
            for ci in 0..max_clients() {
                let cli = &*(&raw const CLIENTS!()[ci]);
                if cli.active == 0 {
                    continue;
                }
                for fi in 0..(*cli).objects_cap as usize {
                    if (*cli.objects.add(fi)).active != 0
                        && (*cli.objects.add(fi)).obj_type == OBJ_TYPE_DEVICE
                        && (*cli.objects.add(fi)).dev_type == DEV_PTY_SLAVE
                        && (*cli.posix_ext.add(fi)).pty_id as usize == pty_id
                    {
                        wake_poll_waiters(cli.badge, fi as i32, 0x001); // POLLIN
                    }
                }
            }
        }
    }
}

pub(crate) unsafe fn handle_isatty(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let is_tty = if (*(*cli).objects.add(fd as usize)).obj_type == OBJ_TYPE_DEVICE
            && ((*(*cli).objects.add(fd as usize)).dev_type == DEV_CONSOLE
                || (*(*cli).objects.add(fd as usize)).dev_type == DEV_PTY_SLAVE)
        {
            1u64
        } else {
            0u64
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = is_tty;
    }
}

/// Forward tcgetattr to posix_ttysrv (for PTY) or console server (for /dev/console)
pub(crate) unsafe fn handle_tcgetattr(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).objects.add(fd as usize);
        let ext = *(*cli).posix_ext.add(fd as usize);
        if fde.obj_type != OBJ_TYPE_DEVICE {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if fde.dev_type == DEV_PTY_SLAVE {
            // Forward to posix_ttysrv via POSIX_TTYSRV_PTY_TCGETATTR
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = POSIX_TTYSRV_PTY_TCGETATTR;
            treq.regs[0] = ext.pty_id as u64;
            treq.length = 1;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = treply.length;
            for i in 0..treply.length as usize {
                (*reply).regs[i] = treply.regs[i];
            }
        } else if fde.dev_type == DEV_CONSOLE {
            // Forward to console server
            let mut creq = TronaMsg::zeroed();
            let mut creply = TronaMsg::zeroed();
            creq.label = CONSOLE_TCGETATTR;
            creq.length = 0;
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_CONSOLE_EP,
                &raw const creq,
                &raw mut creply,
            );
            if err != 0 || creply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = creply.length;
            for i in 0..creply.length as usize {
                (*reply).regs[i] = creply.regs[i];
            }
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}

/// Forward tcsetattr to posix_ttysrv (for PTY) or console server (for /dev/console)
pub(crate) unsafe fn handle_tcsetattr(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).objects.add(fd as usize);
        let ext = *(*cli).posix_ext.add(fd as usize);
        if fde.obj_type != OBJ_TYPE_DEVICE {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if fde.dev_type == DEV_PTY_SLAVE {
            // Forward to posix_ttysrv via POSIX_TTYSRV_PTY_TCSETATTR
            // msg layout: regs[0]=fd, regs[1]=action, regs[2..11]=termios data
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = POSIX_TTYSRV_PTY_TCSETATTR;
            treq.regs[0] = ext.pty_id as u64;
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
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
        } else if fde.dev_type == DEV_CONSOLE {
            // Forward to console server
            let mut creq = TronaMsg::zeroed();
            let mut creply = TronaMsg::zeroed();
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
            if err != 0 || creply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}

pub(crate) unsafe fn handle_ioctl(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let request = (*msg).regs[1];
        let arg = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).objects.add(fd as usize);
        let ext = *(*cli).posix_ext.add(fd as usize);
        if fde.obj_type == OBJ_TYPE_INET_SOCKET {
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] inet ioctl fd=");
                _lb.dec(fd as u64);
                _lb.str(b" req=");
                _lb.hex(request);
                _lb.putc(b'\n');
            });
        }

        fn is_net_ioctl(request: u64) -> bool {
            matches!(
                request,
                0x8910 | 0x8912 | 0x8913 | 0x8915 | 0x8919 | 0x891B | 0x8933
            )
        }

        if fde.obj_type == OBJ_TYPE_DEVICE && fde.dev_type == DEV_FB0 {
            handle_ioctl_fb0(request, reply);
            return;
        }

        if fde.obj_type == OBJ_TYPE_INET_SOCKET && is_net_ioctl(request) {
            let mut nreq = TronaMsg::zeroed();
            let mut nreply = TronaMsg::zeroed();
            nreq.label = NET_GET_CONFIG;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const nreq, &raw mut nreply);
            if err != 0 || nreply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }

            let our_ip = nreply.regs[1] as u32;
            let subnet_mask = nreply.regs[2] as u32;
            let flags = if our_ip != 0 {
                0x1u64 | 0x2u64 | 0x40u64 | 0x1000u64
            } else {
                0
            };

            (*reply).label = TRONA_OK;
            match request {
                0x8910 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = 1;
                }
                0x8912 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = our_ip as u64;
                }
                0x8913 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = flags;
                }
                0x8915 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = our_ip as u64;
                }
                0x8919 => {
                    let broadcast = if our_ip != 0 && subnet_mask != 0 {
                        ((our_ip & subnet_mask) | !subnet_mask) as u64
                    } else {
                        0
                    };
                    (*reply).length = 1;
                    (*reply).regs[0] = broadcast;
                }
                0x891B => {
                    (*reply).length = 1;
                    (*reply).regs[0] = subnet_mask as u64;
                }
                0x8933 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = 1;
                }
                _ => {
                    (*reply).label = TRONA_INVALID_OPERATION;
                }
            }
            let _ = arg;
            return;
        }

        // Terminal ioctls — supported by both console and PTY devices
        if fde.obj_type != OBJ_TYPE_DEVICE
            || (fde.dev_type != DEV_CONSOLE && fde.dev_type != DEV_PTY_SLAVE)
        {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let pty_id = if fde.dev_type == DEV_PTY_SLAVE {
            ext.pty_id as u64
        } else {
            0u64
        };

        match request {
            // TIOCGPGRP: get foreground process group
            0x540F => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x540F; // TIOCGPGRP
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != TRONA_OK {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = treply.regs[0];
            }
            // TIOCSPGRP: set foreground process group
            0x5410 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5410; // TIOCSPGRP
                treq.regs[2] = (*msg).regs[2]; // pgid
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCSCTTY: acquire controlling tty
            0x540E => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x540E; // TIOCSCTTY
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCNOTTY: release controlling tty
            0x5422 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5422; // TIOCNOTTY
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCGWINSZ: get terminal window size
            0x5413 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5413; // TIOCGWINSZ
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != TRONA_OK {
                    // Fallback to default 80x24
                    (*reply).label = TRONA_OK;
                    (*reply).length = 2;
                    (*reply).regs[0] = 24;
                    (*reply).regs[1] = 80;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 2;
                (*reply).regs[0] = treply.regs[0];
                (*reply).regs[1] = treply.regs[1];
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_ioctl_fb0(request: u64, reply: *mut TronaMsg) {
    unsafe {
        match request {
            // FBIOGET_VSCREENINFO
            0x4600 => {
                (*reply).label = TRONA_OK;
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
                (*reply).label = TRONA_OK;
                (*reply).length = 3;
                (*reply).regs[0] = crate::FB_PITCH as u64;
                (*reply).regs[1] = crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64;
                (*reply).regs[2] = 0; // type = packed pixels
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_fcntl(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cmd = (*msg).regs[1] as i32;
        let arg = (*msg).regs[2] as i64;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if (*(*cli).objects.add(fd as usize)).obj_type == OBJ_TYPE_INET_SOCKET {
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] inet fcntl fd=");
                _lb.dec(fd as u64);
                _lb.str(b" cmd=");
                _lb.dec(cmd as u64);
                _lb.putc(b'\n');
            });
        }

        match cmd {
            // F_DUPFD: duplicate fd, new fd >= arg
            0 | 1030 => {
                // F_DUPFD (0) and F_DUPFD_CLOEXEC (1030)
                let min_fd = if arg < 0 { 0 } else { arg as usize };
                let mut newfd: i32 = -1;
                let mut i = min_fd;
                while i < (*cli).objects_cap as usize {
                    if (*(*cli).objects.add(i)).active == 0 {
                        newfd = i as i32;
                        break;
                    }
                    i += 1;
                }
                if newfd < 0 {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }

                dup_object_entry(cli, fd, newfd);
                // F_DUPFD_CLOEXEC sets FD_CLOEXEC on new fd
                object_set_cloexec((*cli).objects.add(newfd as usize), cmd == 1030);

                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = newfd as u64;
            }
            // F_GETFD: get fd flags
            1 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = object_descriptor_flags((*cli).objects.add(fd as usize));
            }
            // F_SETFD: set fd flags
            2 => {
                object_set_cloexec((*cli).objects.add(fd as usize), (arg & 1) != 0);
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            // F_GETFL: get file status flags
            3 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = object_status_flags((*(*cli).objects.add(fd as usize)).flags) as u64;
            }
            // F_SETFL: set file status flags (only O_APPEND, O_NONBLOCK are changeable)
            4 => {
                let changeable = O_APPEND | O_NONBLOCK;
                let preserved = (*(*cli).objects.add(fd as usize)).flags & !changeable;
                (*(*cli).objects.add(fd as usize)).flags = preserved | (arg as u32 & changeable);
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_chdir(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        // Validate that path exists and is a directory
        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() {
            // Root underlay fallback: validate path exists on disk and is a directory
            if let Some((mi, rino)) = try_root_underlay(path_ptr, path_len) {
                if let Some((_, _, _, _, is_dir)) = mount_stat(mi, rino) {
                    if !is_dir {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
            } else {
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            // Path exists on underlay and is a directory — store cwd string below
        } else {
            if (*inode).ftype != FTYPE_DIRECTORY && (*inode).ftype != FTYPE_MOUNT_POINT {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
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

        (*reply).label = TRONA_OK;
    }
}

pub(crate) unsafe fn handle_getcwd(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let max_size = (*msg).regs[0] as usize;

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
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
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Pack cwd bytes into reply regs[1..]
        let copy_len = cwd_len;
        (*reply).label = TRONA_OK;
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
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
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
                (*reply).label = TRONA_ALREADY_EXISTS;
                return false;
            }
            // Open existing
            let cli = get_client(badge);
            if cli.is_null() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
            for fd in 0..(*cli).objects_cap as usize {
                if (*(*cli).objects.add(fd)).active == 0 {
                    (*(*cli).objects.add(fd)).active = 1;
                    (*(*cli).objects.add(fd)).obj_type = OBJ_TYPE_SHM;
                    (*(*cli).posix_ext.add(fd)).inode = (*existing).ino;
                    crate::ramfs::inode_open((*existing).ino);
                    (*reply).label = TRONA_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = fd as u64;
                    return false;
                }
            }
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        if (flags & O_CREAT) == 0 {
            // O_CREAT not set
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Ensure /dev/shm exists
        let shm_dir = resolve_path(b"/dev/shm".as_ptr(), 8);
        let parent = if shm_dir.is_null() {
            // Create /dev/shm
            let dev_dir = resolve_path(b"/dev".as_ptr(), 4);
            if dev_dir.is_null() {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
            let d = alloc_inode();
            if d.is_null() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
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
            (*reply).label = TRONA_OUT_OF_MEMORY;
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
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // Store SHM index in inode dev_type field (repurposed)
        (*inode).dev_type = shm_idx as u8;

        let cli = get_client(badge);
        if cli.is_null() {
            (*inode).active = 0;
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..(*cli).objects_cap as usize {
            if (*(*cli).objects.add(fd)).active == 0 {
                (*(*cli).objects.add(fd)).active = 1;
                (*(*cli).objects.add(fd)).obj_type = OBJ_TYPE_SHM;
                (*(*cli).posix_ext.add(fd)).inode = (*inode).ino;
                crate::ramfs::inode_open((*inode).ino);
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return false;
            }
        }

        (*inode).active = 0;
        (*reply).label = TRONA_OUT_OF_MEMORY;
        false
    }
}

pub(crate) unsafe fn handle_shm_unlink(msg: *const TronaMsg, reply: *mut TronaMsg) -> bool {
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
            (*reply).label = TRONA_NOT_FOUND;
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
        (*reply).label = TRONA_OK;
        false
    }
}

pub(crate) unsafe fn handle_ftruncate(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let length = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let fde = *(*cli).objects.add(fd as usize);
        let ext = *(*cli).posix_ext.add(fd as usize);

        if fde.obj_type == OBJ_TYPE_MOUNT {
            let old_size = mount_stat(ext.mount_idx as usize, ext.mount_remote_ino)
                .map(|s| s.0)
                .unwrap_or(0);
            mount_truncate(ext.mount_idx as usize, ext.mount_remote_ino, length, reply);
            if (*reply).label == TRONA_OK {
                notify_mmsrv_mmap_truncate(&fde, &ext, old_size, length);
            }
            return false;
        }

        if fde.obj_type == OBJ_TYPE_SHM {
            let inode = inode_by_ino(ext.inode);
            if inode.is_null() || (*inode).ftype != FTYPE_SHM {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            let shm_idx = (*inode).dev_type as usize;
            if shm_idx >= max_shm_objects() {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            let num_pages = ((length + 4095) / 4096) as u16;
            if num_pages as usize > max_shm_pages() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            // Delegate frame allocation to mmsrv via MM_SHM_CREATE
            let shm = &raw mut SHM_DATA!()[shm_idx];

            {
                let mut mm_msg = TronaMsg::zeroed();
                let mut mm_reply = TronaMsg::zeroed();
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
                if err != 0 || mm_reply.label != TRONA_OK {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                }
            }

            (*shm).num_pages = num_pages;
            (*inode).size = length;

            (*reply).label = TRONA_OK;
            return false;
        }

        // Regular file truncate
        let inode = inode_by_ino(ext.inode);
        if inode.is_null() || (*inode).readonly != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        let old_size = (*inode).size;
        if !(*inode).rw_data.is_null() && length < (*inode).size {
            chain_truncate((*inode).rw_data, length);
        }
        (*inode).size = length;
        notify_mmsrv_mmap_truncate(&fde, &ext, old_size, length);
        (*reply).label = TRONA_OK;
        false
    }
}

/// Handle VFS_RESOLVE_BACKING: resolve an fd to its backing store identity.
///
/// Message layout:
///   regs[0] = fd
///
/// Reply:
///   label = TRONA_OK
///   regs[0] = backing_kind (MMAP_BACKING_*)
///   regs[1] = backing_id0 (inode or mount index)
///   regs[2] = backing_id1 (remote inode for mounts, 0 otherwise)
///   regs[3] = file_size
///   regs[4] = flags (bit 0 = writable, bit 1 = readonly inode)
pub(crate) unsafe fn handle_resolve_backing(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let client_badge = (*msg).regs[1];
        let cli = crate::client::get_client_noalloc(client_badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).objects_cap as i32 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let fde = &*(*cli).objects.add(fd as usize);
        let ext = &*(*cli).posix_ext.add(fd as usize);
        if fde.active == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mut resolve_flags: u64 = 0;
        if crate::client::flags_allow_write(fde.flags) {
            resolve_flags |= 1;
        }

        match fde.obj_type {
            OBJ_TYPE_FILE | OBJ_TYPE_SHM => {
                let inode = inode_by_ino(ext.inode);
                let file_size = if inode.is_null() { 0 } else { (*inode).size };
                if !inode.is_null() && (*inode).readonly != 0 {
                    resolve_flags |= 2;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 5;
                (*reply).regs[0] = MMAP_BACKING_FILE;
                (*reply).regs[1] = ext.inode as u64;
                (*reply).regs[2] = 0;
                (*reply).regs[3] = file_size;
                (*reply).regs[4] = resolve_flags;
            }
            OBJ_TYPE_MOUNT => {
                let file_size = mount_stat(ext.mount_idx as usize, ext.mount_remote_ino)
                    .map(|s| s.0)
                    .unwrap_or(0);
                (*reply).label = TRONA_OK;
                (*reply).length = 5;
                (*reply).regs[0] = MMAP_BACKING_MOUNT;
                (*reply).regs[1] = ext.mount_idx as u64;
                (*reply).regs[2] = ext.mount_remote_ino;
                (*reply).regs[3] = file_size;
                (*reply).regs[4] = resolve_flags;
            }
            OBJ_TYPE_DEVICE if fde.dev_type == DEV_FB0 => {
                let smem_len = crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64;
                // Transfer FB untyped cap to mmsrv so it can map the device
                ipc::set_send_cap_ctx(ipc_ctx(), 0, crate::consts::VFS_CAP_FB_UNTYPED);
                (*reply).label = TRONA_OK;
                (*reply).length = 5;
                (*reply).regs[0] = MMAP_BACKING_DEVICE;
                (*reply).regs[1] = fde.dev_type as u64;
                (*reply).regs[2] = 0;
                (*reply).regs[3] = smem_len;
                (*reply).regs[4] = resolve_flags;
            }
            _ => {
                (*reply).label = TRONA_OK;
                (*reply).length = 5;
                (*reply).regs[0] = MMAP_BACKING_NONE;
                (*reply).regs[1] = 0;
                (*reply).regs[2] = 0;
                (*reply).regs[3] = 0;
                (*reply).regs[4] = 0;
            }
        }
    }
}
