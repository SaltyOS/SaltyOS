// SPDX-License-Identifier: GPL-2.0-only
//! Pipe subsystem — anonymous pipe lifecycle and I/O.
//!
//! POSIX fd duplication (dup/dup2/dup3/clone_fds) is in
//! `personality/posix/fd_ops.rs`.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::posix::*;
use trona::types::core::*;

use crate::arena::Handle;
use crate::fs::pipefs::{PipefsMountData, PipefsVnodeData, PIPEFS_VOPS};
use crate::fs::ramfs::{RamfsVnodeData, RAMFS_VOPS};
use crate::fs::tmpfs::{TmpfsVnodeData, TMPFS_VOPS};
use crate::ipc_ctx;
use crate::owner::loop_::OWNER_STATE_PTR;
use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::personality::posix::poll;
use crate::personality::posix::types::*;
use crate::server::client::{
    flags_nonblocking, open_access_mode, pipe_end_open_flags, OpenAccessMode,
};
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::vnode::VnodeHandle;
use crate::vfs_alloc_array;

unsafe fn owner_state() -> Option<&'static mut VfsState> {
    unsafe {
        if OWNER_STATE_PTR.is_null() {
            None
        } else {
            Some(&mut *OWNER_STATE_PTR)
        }
    }
}

pub(crate) unsafe fn find_pipe(
    state: &mut VfsState,
    pipe_handle: Handle<PipeState>,
) -> *mut PipeState {
    match state.pipes.get_mut(pipe_handle) {
        Some(pipe) => pipe as *mut PipeState,
        None => core::ptr::null_mut(),
    }
}

pub(crate) unsafe fn owner_pipe_ptr(pipe_handle: Handle<PipeState>) -> *mut PipeState {
    unsafe {
        match owner_state() {
            Some(state) => find_pipe(state, pipe_handle),
            None => core::ptr::null_mut(),
        }
    }
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

pub(crate) unsafe fn alloc_pipe_from_owner() -> Option<Handle<PipeState>> {
    unsafe {
        match owner_state() {
            Some(state) => alloc_pipe(state),
            None => None,
        }
    }
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

pub(crate) unsafe fn release_pipe_from_owner(pipe_handle: Handle<PipeState>) {
    unsafe {
        if let Some(state) = owner_state() {
            release_pipe(state, pipe_handle);
        }
    }
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
            if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vh) {
                let vd = ctx.data as *const PipefsVnodeData;
                let md = ctx.mount_data as *const PipefsMountData;
                if !vd.is_null() && !md.is_null() {
                    let slot_idx = (*vd).slot_idx as usize;
                    if slot_idx < crate::fs::pipefs::types::MAX_NAMED_PIPES {
                        pipe = (*md).slots[slot_idx].pipe;
                    }
                }
                crate::vfs_core::mount_ctl::clear_trampolines();
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

pub(crate) unsafe fn close_pipe(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) {
    unsafe {
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            return;
        }

        let (pipe_handle, rights) = match state.clients.get(cli_handle) {
            Some(cli) => (cli.objects[fd as usize].pipe_handle(), cli.objects[fd as usize].rights),
            None => return,
        };
        if !pipe_handle.is_valid() {
            return;
        }

        let pipe = find_pipe(state, pipe_handle);
        if pipe.is_null() {
            return;
        }

        let is_read_end = (rights & OBJ_RIGHT_READ) != 0;
        if is_read_end {
            (*pipe).read_refcount = (*pipe).read_refcount.saturating_sub(1);
            if (*pipe).read_refcount == 0 {
                while let Some(w) = pipe_pop_write_waiter(pipe) {
                    let mut wake = TronaMsg::zeroed();
                    wake.label = TRONA_INVALID_OPERATION;
                    ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
                }
                wake_poll_waiters_pipe(state, pipe_handle, false, 0x008);
            }
        } else {
            (*pipe).write_refcount = (*pipe).write_refcount.saturating_sub(1);
            if (*pipe).write_refcount == 0 {
                while let Some(w) = pipe_pop_recv_waiter(pipe) {
                    let mut wake = TronaMsg::zeroed();
                    wake.label = TRONA_OK;
                    wake.length = 1;
                    wake.regs[0] = 0;
                    ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
                }
                wake_poll_waiters_pipe(state, pipe_handle, true, 0x010);
            }
        }

        if (*pipe).read_refcount == 0 && (*pipe).write_refcount == 0 {
            release_pipe(state, pipe_handle);
        }
    }
}

pub(crate) unsafe fn wake_poll_waiters_pipe(
    state: &VfsState,
    pipe_handle: Handle<PipeState>,
    is_read_end: bool,
    revents: u16,
) {
    unsafe {
        state.clients.for_each_active(|_, cli| {
            for fd in 0..MAX_CLIENT_OBJECTS {
                let slot = &cli.objects[fd];
                if !slot.is_live() || slot.kind() != ObjectKind::Pipe || slot.pipe_handle() != pipe_handle {
                    continue;
                }
                let fd_is_read = (slot.rights & OBJ_RIGHT_READ) != 0;
                if fd_is_read != is_read_end {
                    continue;
                }
                poll::wake_poll_waiters(cli.badge, fd as i32, revents);
            }
            true
        });
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

        let Some(read_fd) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
            release_pipe(state, pipe_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        };
        let Some(write_fd) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
            if let Some(cli) = state.clients.get_mut(cli_handle) {
                cli.objects[read_fd as usize].clear();
                cli.obj_count = cli.obj_count.saturating_sub(1);
            }
            release_pipe(state, pipe_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        };

        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => {
                if let Some(cli2) = state.clients.get_mut(cli_handle) {
                    cli2.objects[read_fd as usize].clear();
                    cli2.objects[write_fd as usize].clear();
                    cli2.obj_count = cli2.obj_count.saturating_sub(2);
                }
                release_pipe(state, pipe_handle);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let rs = &mut cli.objects[read_fd as usize];
        rs.set_pipe(pipe_handle);
        rs.rights = OBJ_RIGHT_READ;
        rs.flags = pipe_end_open_flags(flags, OpenAccessMode::ReadOnly);
        rs.nonblocking = if flags_nonblocking(flags) { 1 } else { 0 };
        rs.offset = 0;

        let ws = &mut cli.objects[write_fd as usize];
        ws.set_pipe(pipe_handle);
        ws.rights = OBJ_RIGHT_WRITE;
        ws.flags = pipe_end_open_flags(flags, OpenAccessMode::WriteOnly);
        ws.nonblocking = if flags_nonblocking(flags) { 1 } else { 0 };
        ws.offset = 0;

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
        let (pipe_handle, rights, nonblocking, badge) = match state.clients.get(cli_handle) {
            Some(cli) => {
                let slot = &cli.objects[fd as usize];
                (slot.pipe_handle(), slot.rights, slot.nonblocking != 0, cli.badge)
            }
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
                ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
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

        let slot = state.alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        let req_len = if requested > 0 && requested < 152 {
            requested
        } else {
            152
        };
        if !pipe_push_recv_waiter(pipe, slot, badge, req_len) {
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
        let (pipe_handle, rights, nonblocking, badge) = match state.clients.get(cli_handle) {
            Some(cli) => {
                let slot = &cli.objects[fd as usize];
                (slot.pipe_handle(), slot.rights, slot.nonblocking != 0, cli.badge)
            }
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

            let slot = state.alloc_reply_slot();
            let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
            if err != 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
            if !pipe_push_write_waiter(pipe, slot, badge, src, actual_count as u16) {
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
                ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
            }
            wake_poll_waiters_pipe(state, pipe_handle, true, 0x001);
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}

