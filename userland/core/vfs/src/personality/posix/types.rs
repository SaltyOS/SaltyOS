// SPDX-License-Identifier: GPL-2.0-only
//! POSIX-specific data structures for the VFS server.
//!
//! These types were extracted from `server/types.rs` because they encode
//! POSIX-only concepts (pipes, sockets, epoll, PTY, inode numbers).
//! Neutral code should use `ObjectSlot` and `ClientState` from
//! `server::types` instead.

use crate::arena::Handle;
use crate::personality::posix::consts::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PendingConn {
    pub(crate) active: u8,
    pub(crate) client_badge: u64,
    pub(crate) socket: Handle<SocketState>,
    pub(crate) reply_slot: u64,
}

impl PendingConn {
    pub(crate) const fn zeroed() -> Self {
        PendingConn {
            active: 0,
            client_badge: 0,
            socket: Handle::<SocketState>::INVALID,
            reply_slot: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct SocketState {
    pub(crate) active: u8,
    pub(crate) state: u8,
    pub(crate) sock_id: u32,
    pub(crate) bound_ino: u32,
    pub(crate) backlog: u8,
    pub(crate) pending_count: u8,
    pub(crate) pending: *mut PendingConn,
    pub(crate) pending_cap: u8,
    pub(crate) peer_socket: Handle<SocketState>,
    pub(crate) peer_badge: u64,
    pub(crate) data_buf: [u8; SOCK_BUF_SIZE],
    pub(crate) data_head: u16,
    pub(crate) data_tail: u16,
    pub(crate) accept_reply_slot: u64,
    pub(crate) accept_badge: u64,
    pub(crate) recv_reply_slot: u64,
    pub(crate) recv_badge: u64,
    pub(crate) pending_caps: [u64; 4],
    pub(crate) pending_cap_count: u8,
    pub(crate) shut_rd: u8,
    pub(crate) shut_wr: u8,
    pub(crate) peer_closed: u8,
    pub(crate) refcount: u16,
}

impl SocketState {
    pub(crate) const fn zeroed() -> Self {
        SocketState {
            active: 0,
            state: SOCK_UNBOUND,
            sock_id: 0,
            bound_ino: 0,
            backlog: 0,
            pending_count: 0,
            pending: core::ptr::null_mut(),
            pending_cap: 0,
            peer_socket: Handle::<SocketState>::INVALID,
            peer_badge: 0,
            data_buf: [0; SOCK_BUF_SIZE],
            data_head: 0,
            data_tail: 0,
            accept_reply_slot: 0,
            accept_badge: 0,
            recv_reply_slot: 0,
            recv_badge: 0,
            pending_caps: [0; 4],
            pending_cap_count: 0,
            shut_rd: 0,
            shut_wr: 0,
            peer_closed: 0,
            refcount: 0,
        }
    }
}

unsafe impl Sync for SocketState {}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PollWaiter {
    pub(crate) active: u8,
    pub(crate) kind: u8,
    pub(crate) badge: u64,
    pub(crate) reply_slot: u64,
    pub(crate) deadline_ns: u64,
    pub(crate) objects: [(i32, u16); 8],
    pub(crate) data: [u64; 8],
    pub(crate) nfds: u8,
}

impl PollWaiter {
    pub(crate) const fn zeroed() -> Self {
        PollWaiter {
            active: 0,
            kind: 0,
            badge: 0,
            reply_slot: 0,
            deadline_ns: 0,
            objects: [(-1, 0); 8],
            data: [0; 8],
            nfds: 0,
        }
    }
}

pub(crate) struct EpollEntry {
    pub(crate) active: u8,
    pub(crate) fd: i32,
    pub(crate) events: u32,
    pub(crate) data: u64,
}

impl EpollEntry {
    pub(crate) const fn zeroed() -> Self {
        EpollEntry {
            active: 0,
            fd: -1,
            events: 0,
            data: 0,
        }
    }
}

pub(crate) struct EpollInstance {
    pub(crate) active: u8,
    pub(crate) owner_badge: u64,
    pub(crate) entries: *mut EpollEntry,
    pub(crate) entries_cap: u16,
}

impl EpollInstance {
    pub(crate) const fn zeroed() -> Self {
        EpollInstance {
            active: 0,
            owner_badge: 0,
            entries: core::ptr::null_mut(),
            entries_cap: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct ShmData {
    pub(crate) active: u8,
    pub(crate) unlinked: u8,
    pub(crate) num_pages: u16,
}

impl ShmData {
    pub(crate) const fn zeroed() -> Self {
        ShmData {
            active: 0,
            unlinked: 0,
            num_pages: 0,
        }
    }
}

unsafe impl Sync for ShmData {}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PipeReadWaiter {
    pub(crate) reply_slot: u64,
    pub(crate) badge: u64,
    pub(crate) requested_len: u16,
}

impl PipeReadWaiter {
    pub(crate) const fn zeroed() -> Self {
        PipeReadWaiter {
            reply_slot: 0,
            badge: 0,
            requested_len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PipeWriteWaiter {
    pub(crate) reply_slot: u64,
    pub(crate) badge: u64,
    pub(crate) data: [u8; 144],
    pub(crate) data_len: u16,
}

impl PipeWriteWaiter {
    pub(crate) const fn zeroed() -> Self {
        PipeWriteWaiter {
            reply_slot: 0,
            badge: 0,
            data: [0; 144],
            data_len: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct PipeState {
    pub(crate) active: u8,
    pub(crate) read_refcount: u16,
    pub(crate) write_refcount: u16,
    pub(crate) data_buf: [u8; PIPE_BUF_SIZE],
    pub(crate) data_head: u16,
    pub(crate) data_tail: u16,
    pub(crate) recv_waiters: *mut PipeReadWaiter,
    pub(crate) recv_waiter_cap: u8,
    pub(crate) recv_waiter_count: u8,
    pub(crate) write_waiters: *mut PipeWriteWaiter,
    pub(crate) write_waiter_cap: u8,
    pub(crate) write_waiter_count: u8,
}

impl PipeState {
    pub(crate) const fn zeroed() -> Self {
        PipeState {
            active: 0,
            read_refcount: 0,
            write_refcount: 0,
            data_buf: [0; PIPE_BUF_SIZE],
            data_head: 0,
            data_tail: 0,
            recv_waiters: core::ptr::null_mut(),
            recv_waiter_cap: 0,
            recv_waiter_count: 0,
            write_waiters: core::ptr::null_mut(),
            write_waiter_cap: 0,
            write_waiter_count: 0,
        }
    }
}

unsafe impl Sync for PipeState {}

#[derive(Clone, Copy)]
pub(crate) struct PtyPendingReader {
    pub(crate) active: u8,
    pub(crate) badge: u64,
    pub(crate) reply_slot: u64,
    pub(crate) max_count: u64,
    pub(crate) deadline_ns: u64,
}

impl PtyPendingReader {
    pub(crate) const fn zeroed() -> Self {
        PtyPendingReader {
            active: 0,
            badge: 0,
            reply_slot: 0,
            max_count: 0,
            deadline_ns: 0,
        }
    }
}
