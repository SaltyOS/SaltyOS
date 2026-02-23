// SPDX-License-Identifier: GPL-2.0-only
//! Pipe subsystem and file descriptor duplication (dup/dup2/dup3).

use salty::consts::*;
use salty::ipc;
use salty::types::*;

use crate::client::{get_client, get_client_noalloc};
use crate::consts::*;
use crate::ramfs::{inode_close, inode_open};
use crate::socket::{alloc_reply_slot, close_socket, find_socket};
use crate::types::*;
use crate::{
    ipc_ctx, max_pipes, max_poll_waiters, vfs_alloc_array, vfs_grow_array_with_min, vfs_grow_pool,
    NEXT_PIPE_ID, PIPES, PIPES_CAP, PIPES_PTR, POLL_WAITERS,
};

pub(crate) unsafe fn find_pipe(pipe_id: u32) -> *mut PipeState {
    unsafe {
        for i in 0..max_pipes() {
            if PIPES!()[i].active != 0 && PIPES!()[i].pipe_id == pipe_id {
                return &raw mut PIPES!()[i];
            }
        }
        core::ptr::null_mut()
    }
}

pub(crate) unsafe fn alloc_pipe() -> *mut PipeState {
    unsafe {
        for i in 0..max_pipes() {
            if PIPES!()[i].active == 0 {
                let p = &raw mut PIPES!()[i];
                (*p).active = 1;
                (*p).pipe_id = NEXT_PIPE_ID;
                NEXT_PIPE_ID += 1;
                (*p).read_refcount = 1;
                (*p).write_refcount = 1;
                (*p).data_head = 0;
                (*p).data_tail = 0;
                (*p).recv_waiter_count = 0;
                (*p).write_waiter_count = 0;
                // Allocate waiter arrays if not yet allocated
                if (*p).recv_waiters.is_null() {
                    let rw = vfs_alloc_array::<PipeReadWaiter>(INITIAL_PIPE_WAITERS);
                    let ww = vfs_alloc_array::<PipeWriteWaiter>(INITIAL_PIPE_WAITERS);
                    if rw.is_null() || ww.is_null() {
                        (*p).active = 0;
                        return core::ptr::null_mut();
                    }
                    (*p).recv_waiters = rw;
                    (*p).recv_waiter_cap = INITIAL_PIPE_WAITERS as u8;
                    (*p).write_waiters = ww;
                    (*p).write_waiter_cap = INITIAL_PIPE_WAITERS as u8;
                }
                return p;
            }
        }
        // No free slot: grow the pool and retry
        if vfs_grow_pool(
            &raw mut PIPES_PTR as *mut *mut u8,
            &raw mut PIPES_CAP,
            core::mem::size_of::<PipeState>(),
        ) != 0
        {
            return core::ptr::null_mut();
        }
        alloc_pipe()
    }
}

pub(crate) unsafe fn pipe_buf_len(p: *const PipeState) -> u16 {
    unsafe {
        let h = (*p).data_head;
        let t = (*p).data_tail;
        if h >= t {
            h - t
        } else {
            PIPE_BUF_SIZE as u16 - t + h
        }
    }
}

pub(crate) unsafe fn pipe_buf_free(p: *const PipeState) -> u16 {
    (PIPE_BUF_SIZE as u16 - 1) - unsafe { pipe_buf_len(p) }
}

pub(crate) unsafe fn pipe_buf_write(p: *mut PipeState, data: *const u8, len: u16) -> u16 {
    unsafe {
        let free = pipe_buf_free(p);
        let actual = if len < free { len } else { free };
        for i in 0..actual as usize {
            (*p).data_buf[(*p).data_head as usize] = *data.add(i);
            (*p).data_head = ((*p).data_head + 1) % PIPE_BUF_SIZE as u16;
        }
        actual
    }
}

pub(crate) unsafe fn pipe_buf_read(p: *mut PipeState, data: *mut u8, len: u16) -> u16 {
    unsafe {
        let avail = pipe_buf_len(p);
        let actual = if len < avail { len } else { avail };
        for i in 0..actual as usize {
            *data.add(i) = (*p).data_buf[(*p).data_tail as usize];
            (*p).data_tail = ((*p).data_tail + 1) % PIPE_BUF_SIZE as u16;
        }
        actual
    }
}

/// Push a read waiter onto the pipe's FIFO queue. Returns false if full.
pub(crate) unsafe fn pipe_push_recv_waiter(
    pipe: *mut PipeState,
    slot: u64,
    badge: u64,
    req_len: u16,
) -> bool {
    unsafe {
        let count = (*pipe).recv_waiter_count as usize;
        if count >= (*pipe).recv_waiter_cap as usize {
            return false;
        }
        (*(*pipe).recv_waiters.add(count)).reply_slot = slot;
        (*(*pipe).recv_waiters.add(count)).badge = badge;
        (*(*pipe).recv_waiters.add(count)).requested_len = req_len;
        (*pipe).recv_waiter_count = (count + 1) as u8;
        true
    }
}

/// Pop the first read waiter from the pipe's FIFO queue.
pub(crate) unsafe fn pipe_pop_recv_waiter(pipe: *mut PipeState) -> Option<PipeReadWaiter> {
    unsafe {
        let count = (*pipe).recv_waiter_count as usize;
        if count == 0 {
            return None;
        }
        let waiter = *(*pipe).recv_waiters.add(0);
        // Shift remaining waiters down
        for i in 1..count {
            *(*pipe).recv_waiters.add(i - 1) = *(*pipe).recv_waiters.add(i);
        }
        *(*pipe).recv_waiters.add(count - 1) = PipeReadWaiter::zeroed();
        (*pipe).recv_waiter_count = (count - 1) as u8;
        Some(waiter)
    }
}

/// Push a write waiter onto the pipe's FIFO queue with saved data. Returns false if full.
pub(crate) unsafe fn pipe_push_write_waiter(
    pipe: *mut PipeState,
    slot: u64,
    badge: u64,
    src: *const u8,
    len: u16,
) -> bool {
    unsafe {
        let count = (*pipe).write_waiter_count as usize;
        if count >= (*pipe).write_waiter_cap as usize {
            return false;
        }
        (*(*pipe).write_waiters.add(count)).reply_slot = slot;
        (*(*pipe).write_waiters.add(count)).badge = badge;
        (*(*pipe).write_waiters.add(count)).data_len = len;
        let actual = if len > 144 { 144 } else { len };
        for i in 0..actual as usize {
            (*(*pipe).write_waiters.add(count)).data[i] = *src.add(i);
        }
        (*pipe).write_waiter_count = (count + 1) as u8;
        true
    }
}

/// Pop the first write waiter from the pipe's FIFO queue.
pub(crate) unsafe fn pipe_pop_write_waiter(pipe: *mut PipeState) -> Option<PipeWriteWaiter> {
    unsafe {
        let count = (*pipe).write_waiter_count as usize;
        if count == 0 {
            return None;
        }
        let waiter = *(*pipe).write_waiters.add(0);
        // Shift remaining waiters down
        for i in 1..count {
            *(*pipe).write_waiters.add(i - 1) = *(*pipe).write_waiters.add(i);
        }
        *(*pipe).write_waiters.add(count - 1) = PipeWriteWaiter::zeroed();
        (*pipe).write_waiter_count = (count - 1) as u8;
        Some(waiter)
    }
}

/// Close a pipe FD — decrement refcount, wake blocked peers, free if both zero.
pub(crate) unsafe fn close_pipe(fde: *mut FdEntry) {
    unsafe {
        let pipe = find_pipe((*fde).pipe_id());
        if pipe.is_null() {
            return;
        }

        let is_read_end = ((*fde).flags & O_ACCMODE) == 0; // O_RDONLY = 0
        if is_read_end {
            (*pipe).read_refcount = (*pipe).read_refcount.saturating_sub(1);
            // No readers left — wake ALL blocked writers with EPIPE
            if (*pipe).read_refcount == 0 {
                while let Some(w) = pipe_pop_write_waiter(pipe) {
                    let mut wake = SaltyMsg::zeroed();
                    wake.label = SALTY_INVALID_OPERATION; // EPIPE
                    ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
                }
                wake_poll_waiters_pipe(pipe, false, 0x008); // POLLERR on write end
            }
        } else {
            (*pipe).write_refcount = (*pipe).write_refcount.saturating_sub(1);
            // No writers left — wake ALL blocked readers with EOF
            if (*pipe).write_refcount == 0 {
                while let Some(w) = pipe_pop_recv_waiter(pipe) {
                    let mut wake = SaltyMsg::zeroed();
                    wake.label = SALTY_OK;
                    wake.length = 1;
                    wake.regs[0] = 0; // EOF
                    ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
                }
                wake_poll_waiters_pipe(pipe, true, 0x010); // POLLHUP on read end
            }
        }

        // Free pipe if both ends closed
        if (*pipe).read_refcount == 0 && (*pipe).write_refcount == 0 {
            (*pipe).active = 0;
        }
    }
}

/// Wake poll waiters for any fd that is a pipe end matching the given pipe.
/// `is_read_end`: true = wake waiters on read-end fds, false = wake waiters on write-end fds.
pub(crate) unsafe fn wake_poll_waiters_pipe(
    pipe: *const PipeState,
    is_read_end: bool,
    revents: u16,
) {
    unsafe {
        let pipe_id = (*pipe).pipe_id;
        for i in 0..max_poll_waiters() {
            if POLL_WAITERS!()[i].active == 0 {
                continue;
            }
            let badge = POLL_WAITERS!()[i].badge;
            let cli = get_client_noalloc(badge);
            if cli.is_null() {
                continue;
            }

            let mut ready_count: u64 = 0;
            let mut wake_reply = SaltyMsg::zeroed();
            wake_reply.label = SALTY_OK;

            for j in 0..POLL_WAITERS!()[i].nfds as usize {
                let pfd = POLL_WAITERS!()[i].fds[j].0;
                if pfd < 0 || pfd >= (*cli).fds_cap as i32 {
                    continue;
                }
                let fde = *(*cli).fds.add(pfd as usize);
                if fde.active == 0 || fde.fd_type != FD_TYPE_PIPE {
                    continue;
                }
                if fde.pipe_id() != pipe_id {
                    continue;
                }
                let fd_is_read = (fde.flags & O_ACCMODE) == 0;
                if fd_is_read != is_read_end {
                    continue;
                }

                let requested = POLL_WAITERS!()[i].fds[j].1;
                let matched = revents & (requested | 0x010 | 0x008);
                if matched != 0 {
                    wake_reply.regs[1 + j] = matched as u64;
                    ready_count += 1;
                }
            }

            if ready_count > 0 {
                wake_reply.regs[0] = ready_count;
                wake_reply.length = 1 + POLL_WAITERS!()[i].nfds as u64;
                ipc::send_ctx(
                    ipc_ctx(),
                    POLL_WAITERS!()[i].reply_slot,
                    &raw const wake_reply,
                );
                POLL_WAITERS!()[i].active = 0;
            }
        }
    }
}

/// handle_pipe: create a pipe pair, return read_fd and write_fd
pub(crate) unsafe fn handle_pipe(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let flags = (*msg).regs[0] as u32;

        let pipe = alloc_pipe();
        if pipe.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*pipe).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Allocate read-end fd
        let mut read_fd: i32 = -1;
        for i in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(i)).active == 0 {
                read_fd = i as i32;
                break;
            }
        }
        if read_fd < 0 {
            (*pipe).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Allocate write-end fd
        let mut write_fd: i32 = -1;
        for i in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(i)).active == 0 && i as i32 != read_fd {
                write_fd = i as i32;
                break;
            }
        }
        if write_fd < 0 {
            (*pipe).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Set up read-end fd
        (*(*cli).fds.add(read_fd as usize)).active = 1;
        (*(*cli).fds.add(read_fd as usize)).fd_type = FD_TYPE_PIPE;
        (*(*cli).fds.add(read_fd as usize)).sock_id = (*pipe).pipe_id; // reuse sock_id for pipe_id
        (*(*cli).fds.add(read_fd as usize)).flags = if flags & O_NONBLOCK != 0 {
            O_NONBLOCK
        } else {
            0
        }; // O_NONBLOCK on read end
        (*(*cli).fds.add(read_fd as usize)).offset = 0;

        // Set up write-end fd
        (*(*cli).fds.add(write_fd as usize)).active = 1;
        (*(*cli).fds.add(write_fd as usize)).fd_type = FD_TYPE_PIPE;
        (*(*cli).fds.add(write_fd as usize)).sock_id = (*pipe).pipe_id;
        (*(*cli).fds.add(write_fd as usize)).flags = O_WRONLY
            | (if flags & O_NONBLOCK != 0 {
                O_NONBLOCK
            } else {
                0
            }); // O_WRONLY + O_NONBLOCK
        (*(*cli).fds.add(write_fd as usize)).offset = 0;

        // O_CLOEXEC
        if flags & O_CLOEXEC != 0 {
            *(*cli).fd_flags.add(read_fd as usize) = 1; // FD_CLOEXEC
            *(*cli).fd_flags.add(write_fd as usize) = 1;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 2;
        (*reply).regs[0] = read_fd as u64;
        (*reply).regs[1] = write_fd as u64;
    }
}

/// Handle read on a pipe fd
pub(crate) unsafe fn handle_pipe_read(
    msg: *const SaltyMsg,
    fde: *mut FdEntry,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    unsafe {
        // Bug 6: Verify read-end access mode
        if ((*fde).flags & O_ACCMODE) != 0 {
            // Not O_RDONLY — reject read on write-end
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let pipe = find_pipe((*fde).pipe_id());
        if pipe.is_null() {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Bug 1: Respect requested length from msg
        let requested = (*msg).regs[1] as u16;
        let avail = pipe_buf_len(pipe);
        if avail > 0 {
            let mut count = avail;
            if requested > 0 && requested < count {
                count = requested;
            }
            if count > 152 {
                count = 152;
            }
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            let actual = pipe_buf_read(pipe, dst, count);
            (*reply).label = SALTY_OK;
            (*reply).length = 1 + ((actual as u64 + 7) / 8);
            (*reply).regs[0] = actual as u64;

            // Bug 2+7: Wake blocked writer — write their saved data into buffer
            if let Some(w) = pipe_pop_write_waiter(pipe) {
                let written = pipe_buf_write(pipe, w.data.as_ptr(), w.data_len);
                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_OK;
                wake.length = 1;
                wake.regs[0] = written as u64;
                ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
            }

            // Wake poll waiters on write-end (POLLOUT — space available)
            wake_poll_waiters_pipe(pipe, false, 0x004);
            return false;
        }

        // Buffer empty
        if (*pipe).write_refcount == 0 {
            // No writers — return EOF
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return false;
        }

        // O_NONBLOCK: return EAGAIN instead of blocking
        if (*fde).flags & O_NONBLOCK != 0 {
            (*reply).label = SALTY_WOULD_BLOCK;
            return false;
        }

        // Block reader — save caller (Bug 7: multi-waiter)
        let slot = alloc_reply_slot();
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }
        let req_len = if requested > 0 && requested < 152 {
            requested
        } else {
            152
        };
        if !pipe_push_recv_waiter(pipe, slot, badge, req_len) {
            // Waiter queue full — return EAGAIN
            (*reply).label = SALTY_WOULD_BLOCK;
            return false;
        }
        true // deferred
    }
}

/// Handle write on a pipe fd
pub(crate) unsafe fn handle_pipe_write(
    msg: *const SaltyMsg,
    fde: *mut FdEntry,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    unsafe {
        // Bug 6: Verify write-end access mode
        if ((*fde).flags & O_ACCMODE) != O_WRONLY {
            // Not O_WRONLY — reject write on read-end
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let pipe = find_pipe((*fde).pipe_id());
        if pipe.is_null() {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // No readers — EPIPE
        if (*pipe).read_refcount == 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let count = (*msg).regs[1];
        let src = &(*msg).regs[2] as *const u64 as *const u8;
        let mut actual_count = count;
        if actual_count > 144 {
            actual_count = 144;
        }

        let free = pipe_buf_free(pipe);
        if free == 0 {
            // O_NONBLOCK: return EAGAIN instead of blocking
            if (*fde).flags & O_NONBLOCK != 0 {
                (*reply).label = SALTY_WOULD_BLOCK;
                return false;
            }

            // Buffer full — block writer with saved data (Bug 2+7: multi-waiter)
            let slot = alloc_reply_slot();
            let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
            if err != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return false;
            }
            if !pipe_push_write_waiter(pipe, slot, badge, src, actual_count as u16) {
                // Waiter queue full — return EAGAIN
                (*reply).label = SALTY_WOULD_BLOCK;
                return false;
            }
            return true; // deferred
        }

        let written = pipe_buf_write(pipe, src, actual_count as u16);

        // Bug 7: Wake blocked reader — pop from multi-waiter queue
        if written > 0 {
            if let Some(w) = pipe_pop_recv_waiter(pipe) {
                let mut wake = SaltyMsg::zeroed();
                let avail = pipe_buf_len(pipe);
                let mut rcount = avail;
                if w.requested_len > 0 && w.requested_len < rcount {
                    rcount = w.requested_len;
                }
                if rcount > 152 {
                    rcount = 152;
                }
                let dst = &raw mut wake.regs[1] as *mut u8;
                let actual = pipe_buf_read(pipe, dst, rcount);
                wake.label = SALTY_OK;
                wake.length = 1 + ((actual as u64 + 7) / 8);
                wake.regs[0] = actual as u64;
                ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
            }
        }

        // Wake poll waiters on read-end (POLLIN — data available)
        if written > 0 {
            wake_poll_waiters_pipe(pipe, true, 0x001);
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}

pub(crate) unsafe fn handle_dup(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || oldfd < 0
            || oldfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(oldfd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Find lowest free fd
        let mut newfd: i32 = -1;
        for i in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(i)).active == 0 {
                newfd = i as i32;
                break;
            }
        }
        if newfd < 0 {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        dup_fd_entry(cli, oldfd, newfd);

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

pub(crate) unsafe fn handle_dup2(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let newfd = (*msg).regs[1] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || oldfd < 0
            || oldfd >= (*cli).fds_cap as i32
            || newfd < 0
            || newfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(oldfd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if oldfd == newfd {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = newfd as u64;
            return;
        }

        // Close newfd if open
        if (*(*cli).fds.add(newfd as usize)).active != 0 {
            let fde = (*cli).fds.add(newfd as usize);
            if (*fde).fd_type == FD_TYPE_SOCKET {
                close_socket(fde);
            } else if (*fde).fd_type == FD_TYPE_PIPE {
                close_pipe(fde);
            } else {
                inode_close((*fde).inode);
            }
            (*(*cli).fds.add(newfd as usize)).active = 0;
        }

        dup_fd_entry(cli, oldfd, newfd);

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

pub(crate) unsafe fn handle_dup3(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let newfd = (*msg).regs[1] as i32;
        let flags = (*msg).regs[2] as u32;
        let cli = get_client(badge);
        if cli.is_null()
            || oldfd < 0
            || oldfd >= (*cli).fds_cap as i32
            || newfd < 0
            || newfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(oldfd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // dup3: oldfd == newfd is an error (unlike dup2)
        if oldfd == newfd {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Close newfd if open
        if (*(*cli).fds.add(newfd as usize)).active != 0 {
            let fde = (*cli).fds.add(newfd as usize);
            if (*fde).fd_type == FD_TYPE_SOCKET {
                close_socket(fde);
            } else if (*fde).fd_type == FD_TYPE_PIPE {
                close_pipe(fde);
            } else {
                inode_close((*fde).inode);
            }
            (*(*cli).fds.add(newfd as usize)).active = 0;
        }

        dup_fd_entry(cli, oldfd, newfd);

        // Apply flags (O_CLOEXEC)
        if flags & O_CLOEXEC != 0 {
            *(*cli).fd_flags.add(newfd as usize) = 1; // FD_CLOEXEC
        } else {
            *(*cli).fd_flags.add(newfd as usize) = 0;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

/// Copy fd entry and increment refcounts as needed.
pub(crate) unsafe fn dup_fd_entry(cli: *mut ClientState, oldfd: i32, newfd: i32) {
    unsafe {
        *(*cli).fds.add(newfd as usize) = *(*cli).fds.add(oldfd as usize);
        let fde = *(*cli).fds.add(newfd as usize);
        if fde.fd_type == FD_TYPE_PIPE {
            let pipe = find_pipe(fde.pipe_id());
            if !pipe.is_null() {
                let is_read = (fde.flags & O_ACCMODE) == 0;
                if is_read {
                    (*pipe).read_refcount += 1;
                } else {
                    (*pipe).write_refcount += 1;
                }
            }
        } else if fde.fd_type == FD_TYPE_SOCKET {
            let sock = find_socket(fde.sock_id);
            if !sock.is_null() {
                (*sock).refcount += 1;
            }
        } else {
            inode_open(fde.inode);
        }
    }
}

pub(crate) unsafe fn handle_clone_fds(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let parent_badge = (*msg).regs[0];
        let child_badge = (*msg).regs[1];

        let parent = get_client_noalloc(parent_badge);
        if parent.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let child = get_client(child_badge);
        if child.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // If parent has more FDs than child, grow child's FD table to match
        if (*parent).fds_cap > (*child).fds_cap {
            let required = (*parent).fds_cap as usize;
            let (new_fds, new_cap) =
                vfs_grow_array_with_min((*child).fds, (*child).fds_cap as usize, required);
            let (new_flags, _) =
                vfs_grow_array_with_min((*child).fd_flags, (*child).fds_cap as usize, required);
            if new_fds.is_null() || new_flags.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            (*child).fds = new_fds;
            (*child).fd_flags = new_flags;
            (*child).fds_cap = new_cap as u16;
        }

        // Copy all FDs from parent to child
        for i in 0..(*parent).fds_cap as usize {
            *(*child).fds.add(i) = *(*parent).fds.add(i);
            *(*child).fd_flags.add(i) = *(*parent).fd_flags.add(i);
            if (*(*child).fds.add(i)).active == 0 {
                continue;
            }
            // Increment pipe refcounts
            if (*(*child).fds.add(i)).fd_type == FD_TYPE_PIPE {
                let pipe = find_pipe((*(*child).fds.add(i)).pipe_id());
                if !pipe.is_null() {
                    let is_read = ((*(*child).fds.add(i)).flags & O_ACCMODE) == 0;
                    if is_read {
                        (*pipe).read_refcount += 1;
                    } else {
                        (*pipe).write_refcount += 1;
                    }
                }
            }
            // Increment socket refcounts
            if (*(*child).fds.add(i)).fd_type == FD_TYPE_SOCKET {
                let sock = find_socket((*(*child).fds.add(i)).sock_id);
                if !sock.is_null() {
                    (*sock).refcount += 1;
                }
            }
            // Increment inode open count for inode-based FDs
            if (*(*child).fds.add(i)).fd_type != FD_TYPE_PIPE
                && (*(*child).fds.add(i)).fd_type != FD_TYPE_SOCKET
            {
                inode_open((*(*child).fds.add(i)).inode);
            }
        }

        // Copy cwd
        let mut i = 0;
        while i < 128 {
            (*child).cwd[i] = (*parent).cwd[i];
            i += 1;
        }

        (*reply).label = SALTY_OK;
    }
}
