// SPDX-License-Identifier: GPL-2.0-only
//! Hierarchical pending-reply resume context.
//!
//! The top-level [`Resume`] enum identifies **which VFS subsystem**
//! owns the parked continuation: filesystem reads/writes, networking,
//! pseudo-terminals, or the `Placeholder` sentinel set by
//! `reserve_fs_pending` before the caller has stamped its real
//! continuation.
//!
//! Routing is **not** done here — that responsibility lives on each
//! `BackendSessionSlot::completion_fn`, which receives the `Resume`
//! alongside the backend-opaque [`PendingKindPayload`] and the raw
//! completion message. This module provides only the data structures
//! and invariants.

pub(crate) mod fs;

/// Networking continuation payload. Carries the identity-stable fields
/// the owner needs to drive a netsrv callback back to a parked client
/// without re-resolving through the per-op inet table. Populated by
/// `personality::posix::inet` when it issues a request; consumed by
/// the netsrv callback arm of the owner dispatcher.
#[derive(Clone, Copy)]
pub(crate) struct NetResume {
    /// Netsrv-provided connection identifier echoed on the callback.
    pub(crate) conn_id: u32,
    /// Netsrv registration generation at issue time. The callback
    /// gate drops replies whose generation pre-dates the current
    /// netsrv re-registration (see `VfsState::next_netsrv_gen`).
    pub(crate) netsrv_gen: u32,
    /// Operation discriminant mirrored from `NET_*` opcodes so the
    /// resume handler can route without re-decoding the reply.
    pub(crate) op_type: u8,
}

/// Pseudo-terminal continuation payload. Carries the pty side and
/// badge identity so the pty resume handler can locate the parked
/// reader / writer without walking the pty table a second time.
#[derive(Clone, Copy)]
pub(crate) struct PtyResume {
    pub(crate) pty_index: u16,
    pub(crate) side: u8,
    pub(crate) client_badge: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum Resume {
    /// Sentinel installed by `reserve_fs_pending`. The fileops caller
    /// is expected to overwrite it via `stamp_resume_ctx` before
    /// returning control to the owner loop. A live `Placeholder`
    /// observed by a completion router indicates a caller-side bug
    /// and should be dropped with a log.
    Placeholder,
    /// Filesystem continuation. See [`fs::FsResume`].
    Fs(fs::FsResume),
    /// Networking continuation — see [`NetResume`].
    Net(NetResume),
    /// Pseudo-terminal continuation — see [`PtyResume`].
    Pty(PtyResume),
}
