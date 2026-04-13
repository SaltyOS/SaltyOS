// SPDX-License-Identifier: GPL-2.0-only
//! Socket state management: allocation and buffer ops.

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::personality::posix::types::*;
use crate::vfs_alloc_array;

pub(crate) fn alloc_socket(state: &mut VfsState) -> Option<Handle<SocketState>> {
    let handle = state.sockets.alloc()?;
    let socket = state.sockets.get_mut(handle)?;
    socket.active = 1;
    socket.sock_id = state.next_sock_id;
    state.next_sock_id = state.next_sock_id.wrapping_add(1);
    socket.state = SOCK_UNBOUND;
    socket.bound_ino = 0;
    socket.backlog = 0;
    socket.pending_count = 0;
    if socket.pending.is_null() {
        let ptr = unsafe { vfs_alloc_array::<PendingConn>(INITIAL_PENDING_CONN) };
        if ptr.is_null() {
            let _ = state.sockets.release(handle);
            return None;
        }
        socket.pending = ptr;
        socket.pending_cap = INITIAL_PENDING_CONN as u8;
    }
    for index in 0..socket.pending_cap as usize {
        unsafe { *socket.pending.add(index) = PendingConn::zeroed(); }
    }
    socket.peer_socket = Handle::<SocketState>::INVALID;
    socket.peer_badge = 0;
    socket.data_head = 0;
    socket.data_tail = 0;
    socket.accept_reply_slot = 0;
    socket.accept_badge = 0;
    socket.recv_reply_slot = 0;
    socket.recv_badge = 0;
    socket.pending_cap_count = 0;
    socket.shut_rd = 0;
    socket.shut_wr = 0;
    socket.peer_closed = 0;
    socket.refcount = 1;
    Some(handle)
}

pub(crate) unsafe fn find_socket(state: &VfsState, handle: Handle<SocketState>) -> *mut SocketState {
    unsafe { state.sockets.raw_ptr(handle).unwrap_or(core::ptr::null_mut()) }
}

pub(crate) fn release_socket(state: &mut VfsState, handle: Handle<SocketState>) {
    if let Some(socket) = state.sockets.get_mut(handle) {
        socket.active = 0;
    }
    let _ = state.sockets.release(handle);
}

pub(crate) unsafe fn sock_buf_len(s: *const SocketState) -> u16 {
    unsafe {
        let h = (*s).data_head;
        let t = (*s).data_tail;
        if h >= t {
            h - t
        } else {
            SOCK_BUF_SIZE as u16 - t + h
        }
    }
}

pub(crate) unsafe fn sock_buf_free(s: *const SocketState) -> u16 {
    (SOCK_BUF_SIZE as u16 - 1) - unsafe { sock_buf_len(s) }
}

pub(crate) unsafe fn sock_buf_write(s: *mut SocketState, data: *const u8, len: u16) -> u16 {
    unsafe {
        let free = sock_buf_free(s);
        let actual = if len < free { len } else { free };
        for i in 0..actual as usize {
            (*s).data_buf[(*s).data_head as usize] = *data.add(i);
            (*s).data_head = ((*s).data_head + 1) % SOCK_BUF_SIZE as u16;
        }
        actual
    }
}

pub(crate) unsafe fn sock_buf_read(s: *mut SocketState, data: *mut u8, len: u16) -> u16 {
    unsafe {
        let avail = sock_buf_len(s);
        let actual = if len < avail { len } else { avail };
        for i in 0..actual as usize {
            *data.add(i) = (*s).data_buf[(*s).data_tail as usize];
            (*s).data_tail = ((*s).data_tail + 1) % SOCK_BUF_SIZE as u16;
        }
        actual
    }
}
