// SPDX-License-Identifier: GPL-2.0-only
//! Per-client state management and file descriptor cleanup on exit.

use trona::consts::*;
use trona::ipc;
use trona::types::*;

use crate::consts::*;
use crate::path::resolve_path;
use crate::pipe::close_pipe;
use crate::ramfs::{inode_by_ino, inode_close};
use crate::socket::close_socket;
use crate::types::*;
use crate::{
    ipc_ctx, max_clients, max_epoll_instances, max_pipes, max_poll_waiters, max_sockets,
    vfs_alloc_array, vfs_grow_pool, CLIENTS, EPOLLS, PIPES, POLL_WAITERS, SOCKETS,
};

pub(crate) unsafe fn get_client(badge: u64) -> *mut ClientState {
    unsafe {
        for i in 0..max_clients() {
            if CLIENTS!()[i].active != 0 && CLIENTS!()[i].badge == badge {
                return &raw mut CLIENTS!()[i];
            }
        }
        for i in 0..max_clients() {
            if CLIENTS!()[i].active == 0 {
                CLIENTS!()[i].badge = badge;
                CLIENTS!()[i].active = 1;
                // Allocate fds/fd_flags if not yet allocated
                if CLIENTS!()[i].fds.is_null() {
                    let fds_ptr = vfs_alloc_array::<FdEntry>(INITIAL_FDS);
                    let flags_ptr = vfs_alloc_array::<u8>(INITIAL_FDS);
                    if fds_ptr.is_null() || flags_ptr.is_null() {
                        CLIENTS!()[i].active = 0;
                        return core::ptr::null_mut();
                    }
                    CLIENTS!()[i].fds = fds_ptr;
                    CLIENTS!()[i].fds_cap = INITIAL_FDS as u16;
                    CLIENTS!()[i].fd_flags = flags_ptr;
                }
                for j in 0..CLIENTS!()[i].fds_cap as usize {
                    (*CLIENTS!()[i].fds.add(j)).active = 0;
                    *CLIENTS!()[i].fd_flags.add(j) = 0;
                }
                // Initialize cwd to "/"
                CLIENTS!()[i].cwd[0] = b'/';
                let mut k = 1;
                while k < 128 {
                    CLIENTS!()[i].cwd[k] = 0;
                    k += 1;
                }
                return &raw mut CLIENTS!()[i];
            }
        }
        // No free slot: grow the pool and retry
        if vfs_grow_pool(
            &raw mut crate::CLIENTS_PTR as *mut *mut u8,
            &raw mut crate::CLIENTS_CAP,
            core::mem::size_of::<ClientState>(),
        ) != 0
        {
            return core::ptr::null_mut();
        }
        get_client(badge)
    }
}

pub(crate) unsafe fn extract_path(msg: *const TronaMsg, reg_offset: usize, path: *mut u8) -> u8 {
    unsafe {
        let mut path_len = (*msg).regs[reg_offset] as u8;
        if (path_len as usize) > MAX_PATH_LEN {
            path_len = MAX_PATH_LEN as u8;
        }
        let raw = &(*msg).regs[reg_offset + 1] as *const u64 as *const u8;
        for i in 0..path_len as usize {
            *path.add(i) = *raw.add(i);
        }
        path_len
    }
}

/// Extract two packed paths from an IPC message with bounds validation.
/// `hdr_regs` = number of header registers before the two length fields.
/// Lengths are at `regs[hdr_regs]` and `regs[hdr_regs+1]`.
/// Path data starts at `regs[hdr_regs+2]`, old path first (8-byte aligned), then new path.
/// Returns `Some((old_len, new_len))` on success, or sets `(*reply).label` and returns `None`.
pub(crate) unsafe fn extract_dual_paths(
    msg: *const TronaMsg,
    hdr_regs: usize,
    old_path: *mut u8,
    new_path: *mut u8,
    reply: *mut TronaMsg,
) -> Option<(u8, u8)> {
    unsafe {
        let old_len = (*msg).regs[hdr_regs] as u8;
        let new_len = (*msg).regs[hdr_regs + 1] as u8;
        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return None;
        }
        if (old_len as usize) > MAX_PATH_LEN || (new_len as usize) > MAX_PATH_LEN {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return None;
        }
        let data_start = hdr_regs + 2;
        let old_regs = ((old_len as usize) + 7) / 8;
        let new_regs = ((new_len as usize) + 7) / 8;
        let required = data_start + old_regs + new_regs;
        if required > 20 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return None;
        }
        if required as u64 > (*msg).length {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return None;
        }
        // SAFETY: required <= 20 <= regs.len(), old_len <= MAX_PATH_LEN, buffers are caller-provided.
        let old_raw = &(*msg).regs[data_start] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            *old_path.add(i) = *old_raw.add(i);
        }
        let new_raw = &(*msg).regs[data_start + old_regs] as *const u64 as *const u8;
        for i in 0..new_len as usize {
            *new_path.add(i) = *new_raw.add(i);
        }
        Some((old_len, new_len))
    }
}

pub(crate) fn flags_allow_read(flags: u32) -> bool {
    (flags & O_ACCMODE) != O_WRONLY
}

pub(crate) fn flags_allow_write(flags: u32) -> bool {
    let mode = flags & O_ACCMODE;
    mode == O_WRONLY || mode == O_RDWR
}

pub(crate) unsafe fn get_client_cwd_ino(badge: u64) -> u32 {
    unsafe {
        let cli = get_client_noalloc(badge);
        if cli.is_null() {
            return ROOT_INO;
        }
        let mut cwd_len: usize = 0;
        while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
            cwd_len += 1;
        }
        if cwd_len == 0 {
            return ROOT_INO;
        }
        let inode = resolve_path((*cli).cwd.as_ptr(), cwd_len as u8);
        if inode.is_null() {
            ROOT_INO
        } else {
            (*inode).ino
        }
    }
}

pub(crate) unsafe fn get_client_noalloc(badge: u64) -> *mut ClientState {
    unsafe {
        for i in 0..max_clients() {
            if CLIENTS!()[i].active != 0 && CLIENTS!()[i].badge == badge {
                return &raw mut CLIENTS!()[i];
            }
        }
        core::ptr::null_mut()
    }
}

pub(crate) unsafe fn send_client_exit_error(reply_slot: u64) {
    unsafe {
        if reply_slot == 0 {
            return;
        }
        let mut wake = TronaMsg::zeroed();
        wake.label = TRONA_INVALID_OPERATION;
        ipc::send_ctx(ipc_ctx(), reply_slot, &raw const wake);
    }
}

pub(crate) unsafe fn purge_poll_waiters_by_badge(dead_badge: u64) {
    unsafe {
        for i in 0..max_poll_waiters() {
            if POLL_WAITERS!()[i].active == 0 || POLL_WAITERS!()[i].badge != dead_badge {
                continue;
            }
            send_client_exit_error(POLL_WAITERS!()[i].reply_slot);
            POLL_WAITERS!()[i] = PollWaiter::zeroed();
        }
    }
}

pub(crate) unsafe fn purge_pty_waiters_by_badge(dead_badge: u64) {
    unsafe {
        for pty in 0..MAX_PTYS {
            let mut r = 0usize;
            while r < crate::PTY_PENDING_COUNT[pty] {
                let ent = crate::PTY_PENDING[pty][r];
                if ent.active == 0 || ent.badge != dead_badge {
                    r += 1;
                    continue;
                }
                send_client_exit_error(ent.reply_slot);
                for j in (r + 1)..crate::PTY_PENDING_COUNT[pty] {
                    crate::PTY_PENDING[pty][j - 1] = crate::PTY_PENDING[pty][j];
                }
                crate::PTY_PENDING_COUNT[pty] -= 1;
                crate::PTY_PENDING[pty][crate::PTY_PENDING_COUNT[pty]] = PtyPendingReader::zeroed();
            }
        }
    }
}

pub(crate) unsafe fn purge_pipe_waiters_by_badge(pipe: *mut PipeState, dead_badge: u64) {
    unsafe {
        let recv_count = (*pipe).recv_waiter_count as usize;
        let mut recv_dst = 0usize;
        for i in 0..recv_count {
            let w = *(*pipe).recv_waiters.add(i);
            if w.badge == dead_badge {
                send_client_exit_error(w.reply_slot);
            } else {
                *(*pipe).recv_waiters.add(recv_dst) = w;
                recv_dst += 1;
            }
        }
        let recv_kept = recv_dst as u8;
        while recv_dst < (*pipe).recv_waiter_cap as usize {
            *(*pipe).recv_waiters.add(recv_dst) = PipeReadWaiter::zeroed();
            recv_dst += 1;
        }
        (*pipe).recv_waiter_count = recv_kept;

        let write_count = (*pipe).write_waiter_count as usize;
        let mut write_dst = 0usize;
        for i in 0..write_count {
            let w = *(*pipe).write_waiters.add(i);
            if w.badge == dead_badge {
                send_client_exit_error(w.reply_slot);
            } else {
                *(*pipe).write_waiters.add(write_dst) = w;
                write_dst += 1;
            }
        }
        let write_kept = write_dst as u8;
        while write_dst < (*pipe).write_waiter_cap as usize {
            *(*pipe).write_waiters.add(write_dst) = PipeWriteWaiter::zeroed();
            write_dst += 1;
        }
        (*pipe).write_waiter_count = write_kept;
    }
}

pub(crate) unsafe fn purge_socket_waiters_by_badge(sock: *mut SocketState, dead_badge: u64) {
    unsafe {
        if (*sock).accept_badge == dead_badge {
            send_client_exit_error((*sock).accept_reply_slot);
            (*sock).accept_reply_slot = 0;
            (*sock).accept_badge = 0;
        }
        if (*sock).recv_badge == dead_badge {
            send_client_exit_error((*sock).recv_reply_slot);
            (*sock).recv_reply_slot = 0;
            (*sock).recv_badge = 0;
        }
        let mut pending = 0u8;
        for i in 0..(*sock).pending_cap as usize {
            if (*(*sock).pending.add(i)).active != 0
                && (*(*sock).pending.add(i)).client_badge == dead_badge
            {
                send_client_exit_error((*(*sock).pending.add(i)).reply_slot);
                *(*sock).pending.add(i) = PendingConn::zeroed();
            }
            if (*(*sock).pending.add(i)).active != 0 {
                pending = pending.saturating_add(1);
            }
        }
        (*sock).pending_count = pending;
    }
}

pub(crate) unsafe fn cleanup_client_state(dead_badge: u64) {
    unsafe {
        let cli = get_client_noalloc(dead_badge);
        if cli.is_null() {
            return;
        }

        // Clear all deferred waiters/callers tied to this badge before fd teardown.
        purge_poll_waiters_by_badge(dead_badge);
        purge_pty_waiters_by_badge(dead_badge);

        for i in 0..max_pipes() {
            if PIPES!()[i].active != 0 {
                purge_pipe_waiters_by_badge(&raw mut PIPES!()[i], dead_badge);
            }
        }

        for i in 0..max_sockets() {
            if SOCKETS!()[i].active != 0 {
                purge_socket_waiters_by_badge(&raw mut SOCKETS!()[i], dead_badge);
            }
        }

        // Close every open fd owned by the dead client to drop pipe/socket refs.
        for i in 0..(*cli).fds_cap as usize {
            let fde = (*cli).fds.add(i);
            if (*fde).active == 0 {
                continue;
            }
            match (*fde).fd_type {
                FD_TYPE_SOCKET => close_socket(fde),
                FD_TYPE_PIPE => close_pipe(fde),
                FD_TYPE_EPOLL => {
                    let ep_idx = (*fde).sock_id as usize;
                    if ep_idx < max_epoll_instances() {
                        EPOLLS!()[ep_idx].active = 0;
                    }
                }
                _ => {
                    // Decrement inode open_count; frees if nlink==0
                    if (*fde).inode != 0 {
                        inode_close((*fde).inode);
                    }
                }
            }
            *(*cli).fds.add(i) = FdEntry::zeroed();
            *(*cli).fd_flags.add(i) = 0;
        }

        // Defensive cleanup for leaked epoll instances.
        for i in 0..max_epoll_instances() {
            if EPOLLS!()[i].active != 0 && EPOLLS!()[i].owner_badge == dead_badge {
                EPOLLS!()[i] = EpollInstance::zeroed();
            }
        }

        // Notify ttyd to release any controlling terminal owned by this dead client.
        let mut treq = TronaMsg::zeroed();
        treq.label = TTYD_CLIENT_EXIT;
        treq.regs[0] = dead_badge;
        treq.length = 1;
        let _ = ipc::nbsend_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq);

        // Unmap per-client bulk SHM from VFS address space.
        crate::bulk::cleanup_bulk_shm(cli);

        (*cli) = ClientState::zeroed();
    }
}

pub(crate) unsafe fn handle_client_exit(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let dead_badge = (*msg).regs[0];
        cleanup_client_state(dead_badge);
        (*reply).label = TRONA_OK;
    }
}
