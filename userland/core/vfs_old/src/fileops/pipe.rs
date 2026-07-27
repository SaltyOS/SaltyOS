// SPDX-License-Identifier: GPL-2.0-only
//! Pipe subsystem — anonymous pipe lifecycle and I/O.
//!
//! POSIX fd duplication (dup/dup2/dup3/clone_fds) is in
//! `personality/posix/fd_ops.rs`.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::posix::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::arena::Handle;
use crate::fs::pipefs::{PIPEFS_VOPS, PipefsMountData, PipefsVnodeData};
use crate::fs::ramfs::{RAMFS_VOPS, RamfsVnodeData};
use crate::fs::tmpfs::{TMPFS_VOPS, TmpfsVnodeData};
use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::owner::op::{OpCore, OpKind, OwnerPostOp};
use crate::personality::posix::consts::*;
use crate::personality::posix::poll;
use crate::personality::posix::types::*;
use crate::server::client::{
    OpenAccessMode, flags_nonblocking, open_access_mode, pipe_end_open_flags,
};
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_alloc_array;
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) unsafe fn find_pipe(
    state: &mut VfsState,
    pipe_handle: Handle<PipeState>,
) -> *mut PipeState {
    match state.pipes.get_mut(pipe_handle) {
        Some(pipe) => pipe as *mut PipeState,
        None => core::ptr::null_mut(),
    }
}

pub(crate) unsafe fn owner_pipe_ptr(
    state: &mut VfsState,
    pipe_handle: Handle<PipeState>,
) -> *mut PipeState {
    unsafe { find_pipe(state, pipe_handle) }
}

pub(crate) unsafe fn alloc_pipe(state: &mut VfsState) -> Option<Handle<PipeState>> {
    unsafe {
        let pipe_handle = state.pipes.alloc()?;
        let Some(pipe) = state.pipes.get_mut(pipe_handle) else {
            let _ = state.pipes.release(pipe_handle);
            return None;
        };

        if pipe.recv_waiters.is_null() {
            let recv_waiters = vfs_alloc_array::<PipeReadWaiter>(INITIAL_PIPE_WAITERS);
            let write_waiters = vfs_alloc_array::<PipeWriteWaiter>(INITIAL_PIPE_WAITERS);
            if recv_waiters.is_null() || write_waiters.is_null() {
                let _ = state.pipes.release(pipe_handle);
                return None;
            }
            pipe.recv_waiters = recv_waiters;
            pipe.recv_waiter_cap = INITIAL_PIPE_WAITERS as u8;
            pipe.write_waiters = write_waiters;
            pipe.write_waiter_cap = INITIAL_PIPE_WAITERS as u8;
        }

        pipe.active = 1;
        pipe.read_refcount = 1;
        pipe.write_refcount = 1;
        pipe.data_head = 0;
        pipe.data_tail = 0;
        pipe.recv_waiter_count = 0;
        pipe.write_waiter_count = 0;
        Some(pipe_handle)
    }
}

pub(crate) unsafe fn alloc_pipe_from_owner(state: &mut VfsState) -> Option<Handle<PipeState>> {
    unsafe { alloc_pipe(state) }
}

pub(crate) unsafe fn release_pipe(state: &mut VfsState, pipe_handle: Handle<PipeState>) {
    unsafe {
        if let Some(pipe) = state.pipes.get_mut(pipe_handle) {
            pipe.active = 0;
            pipe.read_refcount = 0;
            pipe.write_refcount = 0;
            pipe.data_head = 0;
            pipe.data_tail = 0;
            pipe.recv_waiter_count = 0;
            pipe.write_waiter_count = 0;
        }
        let _ = state.pipes.release(pipe_handle);
    }
}

pub(crate) unsafe fn release_pipe_from_owner(state: &mut VfsState, pipe_handle: Handle<PipeState>) {
    unsafe { release_pipe(state, pipe_handle) }
}

pub(crate) unsafe fn fifo_pipe_from_vnode(
    state: &mut VfsState,
    vh: VnodeHandle,
) -> Handle<PipeState> {
    unsafe {
        let (ops, data) = match state.vnodes.get(vh) {
            Some(vnode) => (vnode.ops, vnode.data),
            None => return Handle::<PipeState>::INVALID,
        };

        if ops == &raw const RAMFS_VOPS {
            let vd = data as *const RamfsVnodeData;
            if !vd.is_null() {
                return (*vd).fifo_pipe;
            }
        }

        if ops == &raw const TMPFS_VOPS {
            let vd = data as *const TmpfsVnodeData;
            if !vd.is_null() {
                return (*vd).fifo_pipe;
            }
        }

        if ops == &raw const PIPEFS_VOPS {
            let mut pipe = Handle::<PipeState>::INVALID;
            if let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh)
            {
                let vd = ctx.data as *const PipefsVnodeData;
                let md = ctx.mount_data as *const PipefsMountData;
                if !vd.is_null() && !md.is_null() {
                    let slot_idx = (*vd).slot_idx as usize;
                    if slot_idx < crate::fs::pipefs::types::MAX_NAMED_PIPES {
                        pipe = (*md).slots[slot_idx].pipe;
                    }
                }
            }
            return pipe;
        }

        Handle::<PipeState>::INVALID
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

pub(crate) unsafe fn pipe_push_recv_waiter(
    pipe: *mut PipeState,
    op: OpCore,
    badge: u64,
    req_len: u16,
) -> bool {
    unsafe {
        let count = (*pipe).recv_waiter_count as usize;
        if count >= (*pipe).recv_waiter_cap as usize {
            return false;
        }
        (*(*pipe).recv_waiters.add(count)).op = op;
        (*(*pipe).recv_waiters.add(count)).badge = badge;
        (*(*pipe).recv_waiters.add(count)).requested_len = req_len;
        (*pipe).recv_waiter_count = (count + 1) as u8;
        true
    }
}

pub(crate) unsafe fn pipe_pop_recv_waiter(pipe: *mut PipeState) -> Option<PipeReadWaiter> {
    unsafe {
        let count = (*pipe).recv_waiter_count as usize;
        if count == 0 {
            return None;
        }
        let waiter = *(*pipe).recv_waiters.add(0);
        for i in 1..count {
            *(*pipe).recv_waiters.add(i - 1) = *(*pipe).recv_waiters.add(i);
        }
        *(*pipe).recv_waiters.add(count - 1) = PipeReadWaiter::zeroed();
        (*pipe).recv_waiter_count = (count - 1) as u8;
        Some(waiter)
    }
}

pub(crate) unsafe fn pipe_push_write_waiter(
    pipe: *mut PipeState,
    op: OpCore,
    badge: u64,
    src: *const u8,
    len: u16,
) -> bool {
    unsafe {
        let count = (*pipe).write_waiter_count as usize;
        if count >= (*pipe).write_waiter_cap as usize {
            return false;
        }
        (*(*pipe).write_waiters.add(count)).op = op;
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

pub(crate) unsafe fn pipe_pop_write_waiter(pipe: *mut PipeState) -> Option<PipeWriteWaiter> {
    unsafe {
        let count = (*pipe).write_waiter_count as usize;
        if count == 0 {
            return None;
        }
        let waiter = *(*pipe).write_waiters.add(0);
        for i in 1..count {
            *(*pipe).write_waiters.add(i - 1) = *(*pipe).write_waiters.add(i);
        }
        *(*pipe).write_waiters.add(count - 1) = PipeWriteWaiter::zeroed();
        (*pipe).write_waiter_count = (count - 1) as u8;
        Some(waiter)
    }
}

pub(crate) unsafe fn wake_poll_waiters_pipe(
    state: &mut VfsState,
    pipe_handle: Handle<PipeState>,
    is_read_end: bool,
    revents: u16,
) {
    unsafe {
        // Collect (client badge, fd) pairs that reference `pipe_handle`
        // with the expected read/write end. We cannot call
        // `state.open_object_at` from inside `for_each_active`'s
        // closure (it borrows `state.clients`), so the closure only
        // records `(client_handle, fd)` pairs and the resolution
        // happens after it returns.
        let mut matches: [(ClientHandle, i32); MAX_CLIENT_OBJECTS] =
            [(ClientHandle::INVALID, -1); MAX_CLIENT_OBJECTS];
        let mut match_count = 0usize;
        state.clients.for_each_active(|ch, cli| {
            for fd in 0..MAX_CLIENT_OBJECTS {
                if cli.slots[fd].is_free() {
                    continue;
                }
                if match_count < matches.len() {
                    matches[match_count] = (ch, fd as i32);
                    match_count += 1;
                }
            }
            let _ = cli;
            true
        });
        for &(ch, fd) in matches[..match_count].iter() {
            let Some(obj) = state.open_object_at(ch, fd as usize) else {
                continue;
            };
            if obj.kind() != ObjectKind::Pipe || obj.pipe_handle() != pipe_handle {
                continue;
            }
            let fd_is_read = (obj.rights & OBJ_RIGHT_READ) != 0;
            if fd_is_read != is_read_end {
                continue;
            }
            let badge = match state.clients.get(ch) {
                Some(c) => c.badge,
                None => continue,
            };
            poll::wake_poll_waiters(state, badge, fd, revents);
        }
    }
}

pub(crate) unsafe fn handle_pipe(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let flags = (*msg).regs[0] as u32;

        let Some(pipe_handle) = alloc_pipe(state) else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        };

        let Some(read_fd) = state.reserve_fd_owned(cli_handle) else {
            release_pipe(state, pipe_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        };
        let Some(write_fd) = state.reserve_fd_owned(cli_handle) else {
            state.slot_release(cli_handle, read_fd as usize);
            release_pipe(state, pipe_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        };

        let rs_flags = pipe_end_open_flags(flags, OpenAccessMode::ReadOnly);
        let ws_flags = pipe_end_open_flags(flags, OpenAccessMode::WriteOnly);
        let nonblocking = if flags_nonblocking(flags) { 1 } else { 0 };

        if let Some(rs) = state.open_object_at_mut(cli_handle, read_fd as usize) {
            rs.set_pipe(pipe_handle);
            rs.rights = OBJ_RIGHT_READ;
            rs.flags = rs_flags;
            rs.nonblocking = nonblocking;
            rs.offset = 0;
        }
        if let Some(ws) = state.open_object_at_mut(cli_handle, write_fd as usize) {
            ws.set_pipe(pipe_handle);
            ws.rights = OBJ_RIGHT_WRITE;
            ws.flags = ws_flags;
            ws.nonblocking = nonblocking;
            ws.offset = 0;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 2;
        (*reply).regs[0] = read_fd as u64;
        (*reply).regs[1] = write_fd as u64;
    }
}

pub(crate) unsafe fn handle_pipe_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let badge = match state.clients.get(cli_handle) {
            Some(c) => c.badge,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let (pipe_handle, rights, nonblocking) = match state.open_object_at(cli_handle, fd as usize)
        {
            Some(obj) => (obj.pipe_handle(), obj.rights, obj.nonblocking != 0),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        if (rights & OBJ_RIGHT_READ) == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let pipe = find_pipe(state, pipe_handle);
        if pipe.is_null() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

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
            (*reply).label = TRONA_OK;
            (*reply).length = 1 + ((actual as u64 + 7) / 8);
            (*reply).regs[0] = actual as u64;

            if let Some(w) = pipe_pop_write_waiter(pipe) {
                let written = pipe_buf_write(pipe, w.data.as_ptr(), w.data_len);
                let mut wake = TronaMsg::zeroed();
                wake.label = TRONA_OK;
                wake.length = 1;
                wake.regs[0] = written as u64;
                state.complete_op(w.op, OwnerPostOp::None, &raw const wake);
            }

            wake_poll_waiters_pipe(state, pipe_handle, false, 0x004);
            return false;
        }

        if (*pipe).write_refcount == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return false;
        }

        if nonblocking {
            (*reply).label = TRONA_WOULD_BLOCK;
            return false;
        }

        let op = match state.begin_op_for_client(cli_handle, OpKind::PipeRead) {
            Ok(op) => op,
            Err(err) => {
                (*reply).label = err.to_trona();
                return false;
            }
        };
        let req_len = if requested > 0 && requested < 152 {
            requested
        } else {
            152
        };
        if !pipe_push_recv_waiter(pipe, op, badge, req_len) {
            state.cancel_op(op);
            (*reply).label = TRONA_WOULD_BLOCK;
            return false;
        }
        true
    }
}

pub(crate) unsafe fn handle_pipe_write(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let badge = match state.clients.get(cli_handle) {
            Some(c) => c.badge,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let (pipe_handle, rights, nonblocking) = match state.open_object_at(cli_handle, fd as usize)
        {
            Some(obj) => (obj.pipe_handle(), obj.rights, obj.nonblocking != 0),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        if (rights & OBJ_RIGHT_WRITE) == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let pipe = find_pipe(state, pipe_handle);
        if pipe.is_null() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        if (*pipe).read_refcount == 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
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
            if nonblocking {
                (*reply).label = TRONA_WOULD_BLOCK;
                return false;
            }

            let op = match state.begin_op_for_client(cli_handle, OpKind::PipeWrite) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    return false;
                }
            };
            if !pipe_push_write_waiter(pipe, op, badge, src, actual_count as u16) {
                state.cancel_op(op);
                (*reply).label = TRONA_WOULD_BLOCK;
                return false;
            }
            return true;
        }

        let written = pipe_buf_write(pipe, src, actual_count as u16);

        if written > 0 {
            if let Some(w) = pipe_pop_recv_waiter(pipe) {
                let mut wake = TronaMsg::zeroed();
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
                wake.label = TRONA_OK;
                wake.length = 1 + ((actual as u64 + 7) / 8);
                wake.regs[0] = actual as u64;
                state.complete_op(w.op, OwnerPostOp::None, &raw const wake);
            }
            wake_poll_waiters_pipe(state, pipe_handle, true, 0x001);
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}
