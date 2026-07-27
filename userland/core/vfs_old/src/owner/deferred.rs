// SPDX-License-Identifier: GPL-2.0-only
//! Deferred backend RPC issue snapshot.
//!
//! When a VOP tries to issue a backend request but the target session has no
//! available inflight credit, the request cannot be sent immediately. Instead
//! the request payload is parked in a
//! [`crate::owner::pending::PendingOpState::DeferredFs`] entry, and the
//! entry's handle is pushed onto the session's waiter ring.
//!
//! [`DeferredIssue`] itself is now just the stable snapshot shape the owner
//! uses when parking and inspecting those slots. The parked slot has no live
//! `TxId` and no correlation-bearing wire state — it only captures what the
//! owner needs to eventually issue the request when credit becomes available.

use crate::owner::op::OpCore;
use crate::owner::pending::PendingKindPayload;
use crate::owner::resume::Resume;

/// A backend RPC whose issue has been deferred because no inflight credit was
/// available at the point of origin. The record carries every field needed to
/// either (a) issue the request when credit frees up, or (b) synthesise a
/// failure completion on session teardown.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct DeferredIssue {
    /// Backend session this deferred issue targets. Held as the stable
    /// `session_id` (monotonic) so a teardown + reallocation sequence does
    /// not confuse an abandoned entry with a fresh session reusing the same
    /// arena slot.
    pub(crate) session_id: u32,
    /// Generation counter snapshotted from the owning
    /// [`crate::owner::session::BackendSessionSlot`] at park time. Checked
    /// at promotion so a session that was torn down and re-mounted into the
    /// same slot does not resurrect an abandoned deferred issue.
    pub(crate) session_gen: u32,
    /// Client IPC badge so the eventual reply can be routed back.
    pub(crate) client_badge: u64,
    /// Saved owner-side continuation for the parked client reply.
    pub(crate) reply_op: OpCore,
    /// What the owner wants done when the completion arrives.
    pub(crate) resume: Resume,
    /// Backend-opaque op payload. Only the session's registered
    /// push / drain hooks interpret these bytes — the generic layer
    /// copies them verbatim into a promoted [`PendingOp`] slot on
    /// issue. See [`crate::owner::pending::PendingKindPayload`].
    pub(crate) op: PendingKindPayload,
    /// Caller's incarnation sequence for the primary target node at
    /// park time. Stamped into the request's correlation header when
    /// the deferred issue promotes, so the backend's stale-incarnation
    /// gate fires on replayed ops exactly as it does on fresh ones.
    /// Zero when the op targets no specific node (session-open style).
    pub(crate) target_seq: u32,
    pub(crate) _pad: u32,
}

impl DeferredIssue {
    pub(crate) const fn zeroed() -> Self {
        DeferredIssue {
            session_id: 0,
            session_gen: 0,
            client_badge: 0,
            reply_op: OpCore::INVALID,
            resume: Resume::Placeholder,
            op: PendingKindPayload::zeroed(),
            target_seq: 0,
            _pad: 0,
        }
    }
}

impl Default for DeferredIssue {
    fn default() -> Self {
        DeferredIssue::zeroed()
    }
}
