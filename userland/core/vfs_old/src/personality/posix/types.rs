// SPDX-License-Identifier: GPL-2.0-only
//! POSIX-specific helper structs. The shared IPC object backings
//! (`PipeState`, `SocketState`, `EpollInstance`, `ShmData` plus their
//! inline helpers) live in `crate::ipc_objects` as the neutral
//! server-layer surface; POSIX-only waiter layouts (poll, pty) stay
//! here because they encode personality-specific parking semantics.

use crate::owner::op::OpCore;

// Re-exports for callers that historically imported from
// `personality::posix::types`. The concrete definitions now live
// alongside the `ObjectBacking` discriminant in `ipc_objects`.
pub(crate) use crate::ipc_objects::{
    EpollEntry, EpollInstance, PendingConn, PipeReadWaiter, PipeState, PipeWriteWaiter, ShmData,
    SocketState,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PollWaiter {
    pub(crate) active: u8,
    pub(crate) kind: u8,
    pub(crate) badge: u64,
    pub(crate) op: OpCore,
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
            op: OpCore::INVALID,
            deadline_ns: 0,
            objects: [(-1, 0); 8],
            data: [0; 8],
            nfds: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PtyPendingReader {
    pub(crate) active: u8,
    pub(crate) badge: u64,
    pub(crate) op: OpCore,
    pub(crate) max_count: u64,
    pub(crate) deadline_ns: u64,
}

impl PtyPendingReader {
    pub(crate) const fn zeroed() -> Self {
        PtyPendingReader {
            active: 0,
            badge: 0,
            op: OpCore::INVALID,
            max_count: 0,
            deadline_ns: 0,
        }
    }
}
