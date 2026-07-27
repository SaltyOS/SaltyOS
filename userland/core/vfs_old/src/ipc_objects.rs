// SPDX-License-Identifier: GPL-2.0-only
//! Personality-neutral IPC object backings used by the VFS server layer.
//!
//! The VFS server's `ObjectBacking` discriminant (in `server/types.rs`)
//! carries concrete handles into this module. The types modelled here
//! — pipes, local-domain sockets, epoll instances, POSIX SHM objects —
//! are the shared in-memory representations every personality that
//! reuses the VFS wire format exposes. POSIX is the only live
//! personality today; a future Win32 / Starnite personality layered on
//! the same wire format imports from here. A personality that ships a
//! semantically different pipe / socket model parameterises the
//! `ObjectBacking` enum with its own variant instead of overloading
//! these definitions.
//!
//! The buffer-size and waiter-count constants are local to this module
//! so the struct layouts do not reach back into `personality::posix`
//! for sizing choices. Semantic enums that encode POSIX state machines
//! (e.g. socket state transitions) continue to live under
//! `personality::posix::consts` — they describe personality behaviour,
//! not the shared layout.

use crate::arena::Handle;
use crate::owner::op::OpCore;

// =============================================================================
// Buffer sizing — shared defaults for the in-memory backings.
// =============================================================================

/// Per-socket in-memory scratch buffer for AF_UNIX SOCK_STREAM / DGRAM
/// when the peer has not yet drained prior writes. Matches the POSIX
/// default pipe buffer so the socket and pipe back-pressure pathways
/// stay symmetric.
pub(crate) const SOCK_BUF_SIZE: usize = 4096;

/// Per-pipe in-memory circular buffer used by `pipe(2)` /
/// `pipe2(2)` / `socketpair(2)`. Sized to the historical POSIX.1
/// minimum guarantee of 4 KiB; callers that need larger buffers use
/// the AF_UNIX SOCK_STREAM path instead.
pub(crate) const PIPE_BUF_SIZE: usize = 4096;

// =============================================================================
// Socket backing
// =============================================================================

/// Parked `connect(2)` waiter slot. Lives inside `SocketState.pending`
/// so the listener's pending queue can remember the connector even
/// when no `accept` is currently blocked.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PendingConn {
    pub(crate) active: u8,
    pub(crate) client_badge: u64,
    pub(crate) socket: Handle<SocketState>,
    pub(crate) op: OpCore,
}

impl PendingConn {
    pub(crate) const fn zeroed() -> Self {
        PendingConn {
            active: 0,
            client_badge: 0,
            socket: Handle::<SocketState>::INVALID,
            op: OpCore::INVALID,
        }
    }
}

/// AF_UNIX socket backing. The `state` byte encodes the connection
/// phase (UNBOUND → BOUND → LISTENING → CONNECTING → CONNECTED →
/// CLOSED); the concrete transition table is owned by the POSIX
/// personality in `personality::posix::socket::*`. `zeroed()` initialises
/// `state = 0` which by convention is the UNBOUND sentinel.
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
    pub(crate) accept_op: OpCore,
    pub(crate) accept_badge: u64,
    pub(crate) recv_op: OpCore,
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
            state: 0, // UNBOUND sentinel — personality may override on init.
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
            accept_op: OpCore::INVALID,
            accept_badge: 0,
            recv_op: OpCore::INVALID,
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

// =============================================================================
// Epoll backing
// =============================================================================

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

// =============================================================================
// POSIX SHM backing
// =============================================================================

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

// =============================================================================
// Pipe backing
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PipeReadWaiter {
    pub(crate) op: OpCore,
    pub(crate) badge: u64,
    pub(crate) requested_len: u16,
}

impl PipeReadWaiter {
    pub(crate) const fn zeroed() -> Self {
        PipeReadWaiter {
            op: OpCore::INVALID,
            badge: 0,
            requested_len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PipeWriteWaiter {
    pub(crate) op: OpCore,
    pub(crate) badge: u64,
    pub(crate) data: [u8; 144],
    pub(crate) data_len: u16,
}

impl PipeWriteWaiter {
    pub(crate) const fn zeroed() -> Self {
        PipeWriteWaiter {
            op: OpCore::INVALID,
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
