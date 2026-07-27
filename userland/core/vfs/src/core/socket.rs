// SPDX-License-Identifier: GPL-2.0-only
//
//! Socket backing state shared by socket personalities and backend
//! completion routers.

use crate::server::consts::SOCK_BUF_SIZE;

pub(crate) const NETRESUME_OP_BIND: u8 = 1;
pub(crate) const NETRESUME_OP_LISTEN: u8 = 2;
pub(crate) const NETRESUME_OP_ACCEPT: u8 = 3;
pub(crate) const NETRESUME_OP_CONNECT: u8 = 4;
pub(crate) const NETRESUME_OP_SEND: u8 = 5;
pub(crate) const NETRESUME_OP_RECV: u8 = 6;
pub(crate) const NETRESUME_OP_SHUTDOWN: u8 = 7;
pub(crate) const SCM_RIGHTS_MAX_FDS: usize = 4;

/// Per-side ring buffer carried by `SocketState`. Two of these
/// stitched back-to-back form a full socketpair.
#[repr(C)]
pub(crate) struct SocketRing {
    pub(crate) buf: [u8; SOCK_BUF_SIZE],
    pub(crate) head: u16,
    pub(crate) tail: u16,
    pub(crate) closed: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct WaitQueueHead {
    pub(crate) head: u32,
    pub(crate) _pad: [u8; 4],
}

impl WaitQueueHead {
    pub(crate) const EMPTY: Self = Self {
        head: u32::MAX,
        _pad: [0; 4],
    };
}

impl SocketRing {
    pub(crate) const fn zeroed() -> Self {
        SocketRing {
            buf: [0; SOCK_BUF_SIZE],
            head: 0,
            tail: 0,
            closed: 0,
        }
    }

    pub(crate) fn len(&self) -> u16 {
        let head = self.head as usize;
        let tail = self.tail as usize;
        let len = if tail >= head {
            tail - head
        } else {
            SOCK_BUF_SIZE - head + tail
        };
        len as u16
    }

    pub(crate) fn avail(&self) -> u16 {
        ((SOCK_BUF_SIZE - 1) - self.len() as usize) as u16
    }

    pub(crate) unsafe fn read(&mut self, dst: *mut u8, count: u16) -> u16 {
        let want = count.min(self.len());
        if want == 0 {
            return 0;
        }
        let mut head = self.head as usize;
        for i in 0..want as usize {
            unsafe {
                *dst.add(i) = self.buf[head];
            }
            head += 1;
            if head == SOCK_BUF_SIZE {
                head = 0;
            }
        }
        self.head = head as u16;
        want
    }

    pub(crate) unsafe fn write(&mut self, src: *const u8, count: u16) -> u16 {
        let want = count.min(self.avail());
        if want == 0 {
            return 0;
        }
        let mut tail = self.tail as usize;
        for i in 0..want as usize {
            unsafe {
                self.buf[tail] = *src.add(i);
            }
            tail += 1;
            if tail == SOCK_BUF_SIZE {
                tail = 0;
            }
        }
        self.tail = tail as u16;
        want
    }
}

/// `sockaddr_storage` byte length — fits the largest concrete
/// sockaddr the vfs server services (AF_INET6 sockaddr_in6 = 28
/// bytes; padded to the POSIX storage size).
pub(crate) const SOCKADDR_STORAGE_BYTES: usize = 128;

/// Socket lifecycle state — drives the connect / listen / accept
/// state machine on backend-backed sockets and is mostly inert on
/// in-process socketpairs.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketLifeState {
    Initial = 0,
    Bound = 1,
    Listening = 2,
    Connecting = 3,
    Connected = 4,
    Closed = 5,
}

/// Backend identity — discriminates in-process and backend-backed
/// sockets. In-process sockets keep the rings; backend-backed
/// sockets delegate bytes through `PendingOp` dispatch.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketBacking {
    Unset = 0,
    Unix = 1,
    Inet = 2,
}

/// Per-socket bookkeeping. The struct stays a single inline shape
/// so arena slots remain fixed-size and raw pointers stay stable
/// across arena growth.
#[repr(C)]
pub(crate) struct SocketState {
    pub(crate) active: u8,
    pub(crate) backing: SocketBacking,
    pub(crate) domain: u16,
    pub(crate) sock_type: u16,
    pub(crate) protocol: u16,
    pub(crate) state: SocketLifeState,

    pub(crate) remote: u32,
    pub(crate) remote_epoch: u32,
    pub(crate) tx: SocketRing,
    pub(crate) rx: SocketRing,
    pub(crate) wait_queue: WaitQueueHead,
    pub(crate) inet_wait_queue: WaitQueueHead,

    pub(crate) conn_id: u32,
    pub(crate) netsrv_gen: u32,
    pub(crate) pending_recv_op: u64,
    pub(crate) listen_backlog: u32,
    pub(crate) accept_head: u32,
    pub(crate) accept_tail: u32,
    pub(crate) accept_count: u32,
    pub(crate) accept_next: u32,
    pub(crate) shutdown_flags: u8,
    pub(crate) local_addr: [u8; SOCKADDR_STORAGE_BYTES],
    pub(crate) local_addr_len: u32,
    pub(crate) peer_addr: [u8; SOCKADDR_STORAGE_BYTES],
    pub(crate) peer_addr_len: u32,
    /// Source address of the most recently delivered datagram. For an
    /// unconnected `SOCK_DGRAM` receiver this holds the sender's bound
    /// address so `recvfrom` can report the message source; the
    /// connected case still reports its fixed peer via `peer_addr`.
    /// Kept distinct from `peer_addr` so `getpeername` on an
    /// unconnected socket is unaffected.
    pub(crate) last_src_addr: [u8; SOCKADDR_STORAGE_BYTES],
    pub(crate) last_src_addr_len: u32,
    /// One pending SCM_RIGHTS batch attached to the next readable
    /// UNIX-domain message. Stored as raw arena slot/epoch pairs so
    /// core socket state stays independent of `OpenObject`'s type.
    pub(crate) rights_slots: [u32; SCM_RIGHTS_MAX_FDS],
    pub(crate) rights_epochs: [u32; SCM_RIGHTS_MAX_FDS],
    pub(crate) rights_count: u8,
}

impl SocketState {
    pub(crate) const fn zeroed() -> Self {
        SocketState {
            active: 0,
            backing: SocketBacking::Unset,
            domain: 0,
            sock_type: 0,
            protocol: 0,
            state: SocketLifeState::Initial,
            remote: u32::MAX,
            remote_epoch: 0,
            tx: SocketRing::zeroed(),
            rx: SocketRing::zeroed(),
            wait_queue: WaitQueueHead::EMPTY,
            inet_wait_queue: WaitQueueHead::EMPTY,
            conn_id: u32::MAX,
            netsrv_gen: 0,
            pending_recv_op: 0,
            listen_backlog: 0,
            accept_head: u32::MAX,
            accept_tail: u32::MAX,
            accept_count: 0,
            accept_next: u32::MAX,
            local_addr: [0u8; SOCKADDR_STORAGE_BYTES],
            local_addr_len: 0,
            peer_addr: [0u8; SOCKADDR_STORAGE_BYTES],
            peer_addr_len: 0,
            last_src_addr: [0u8; SOCKADDR_STORAGE_BYTES],
            last_src_addr_len: 0,
            rights_slots: [u32::MAX; SCM_RIGHTS_MAX_FDS],
            rights_epochs: [0; SCM_RIGHTS_MAX_FDS],
            rights_count: 0,
            shutdown_flags: 0,
        }
    }

    #[inline]
    pub(crate) fn is_inet(&self) -> bool {
        matches!(self.backing, SocketBacking::Inet)
    }

    #[inline]
    pub(crate) fn is_unix(&self) -> bool {
        matches!(self.backing, SocketBacking::Unix)
    }
}

// SAFETY: Socket state is owned by the VFS owner thread; worker
// access is through owner-managed handles and existing dispatch
// serialization.
unsafe impl Sync for SocketState {}
