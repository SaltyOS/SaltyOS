// SPDX-License-Identifier: GPL-2.0-only
//
//! `DeferredIssue` — credit-throttle snapshot for a request that
//! arrived while the backing session was at its `inflight_max`.
//!
//! When a posix handler issues against a backend that has no
//! credit, the handler stamps a `DeferredIssue` with the resume
//! coordinates (which session, which seq, which op-payload) and
//! enqueues it on the session's `wait_q`. As completions drain
//! and credit returns, the session's drain hook pops one
//! `DeferredIssue` per freed credit and re-issues against the
//! backend; the original PendingOp moves from `Queued` to
//! `Running` on success.
//!
//! Plan-local invariants:
//!   * The deferred entry holds a *snapshot* of the issue
//!     parameters, not a borrow into `VfsState`. The owning
//!     PendingOp can be cancelled or evicted while the entry
//!     waits; on drain the session walks `wait_q`, validates the
//!     PendingOp handle is still alive, and skips otherwise.
//!   * `client_badge` is duplicated here because cancellation
//!     sweeps walk the wait-queue without resolving the
//!     PendingOp — `cancel_for_badge` just compares badge bytes.
//!   * The seq number is the per-session monotonic counter that
//!     orders deferred re-issues: when ten WRITE calls back up,
//!     they re-issue in the order they were received, not the
//!     order their PendingOp handles happened to land in the
//!     arena.

use crate::owner::pending::PendingOpHandle;

/// One queued re-issue snapshot.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct DeferredIssue {
    /// Session index inside `VfsState.backend_sessions` whose
    /// drain hook owns this entry.
    pub session_idx: u32,
    /// `live_gen` of the session at enqueue time. Drain compares
    /// before re-issue: stale entries (session torn down + new
    /// generation started) get dropped silently.
    pub session_gen: u32,
    /// Original caller's badge (copy). Used by the
    /// `cancel_for_badge` sweep so it can purge wait-queue entries
    /// without resolving each PendingOp.
    pub client_badge: u64,
    /// PendingOp handle so the drain hook can re-stamp the resume
    /// payload after the backend RPC fires.
    pub op: PendingOpHandle,
    /// Per-session monotonic enqueue ordering counter. The drain
    /// hook pops the lowest seq first.
    pub target_seq: u64,
    /// Discriminator for the issue kind. The session's drain hook
    /// branches on this to pick the right backend RPC label and
    /// payload reconstruction path. Each backend (saltyfs, netsrv,
    /// posix_ttysrv) registers its own values inside its module
    /// — the field is opaque at this layer.
    pub op_kind_payload: u32,
    /// Resume-payload scratch: 8 words of issue-parameter
    /// snapshot. Each backend lays its own struct over this
    /// (e.g. saltyfs WRITE stores fd / offset / count / src_va).
    pub payload: [u64; 8],
}
