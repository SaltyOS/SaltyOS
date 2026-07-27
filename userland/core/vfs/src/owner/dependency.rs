// SPDX-License-Identifier: GPL-2.0-only
//
//! PendingOp dependency graph.
//!
//! Two edge kinds:
//! * **PRED_TX** — transactional happens-after. Successor cannot
//!   issue until the predecessor's reply has been applied.
//!   Examples: rename's lookup_src → lookup_dst → mutation, link
//!   chain, MAP_SHARED writeback → fsync.
//! * **PRED_BARRIER** — group barrier. Successor blocks until
//!   *all* `predecessor_remaining` predecessors complete.
//!   Example: fsync waits on every outstanding write to that fd.
//!
//! Storage: `PendingOp` carries `predecessors: [Handle; MAX_PRED_FANIN]`
//! for inline PRED_TX (rare fan-in ≤ 4) and a `successors_head` /
//! `sibling_next` intrusive list of forward-direction successors.
//! PRED_BARRIER needs only the counter on the successor side; the
//! barrier preds carry the successor on their `successors_head`
//! list as usual.
//!
//! First-error propagation: predecessor failure / cancel sets
//! `aggregate_error` on every successor; successor unblock sees the
//! value and fails with that error instead of issuing the backend
//! RPC. Rationale: fsync after a failed write must report the
//! upstream EIO, not a fresh fsync error.

use crate::core::error::VfsError;
use crate::owner::op::OpState;
use crate::owner::pending::{PendingOpHandle, fail_op_handle};

/// Predecessor-completion hook. Walks `pred.successors_head` and
/// for each successor:
/// * decrements `predecessor_remaining`,
/// * propagates `error` into `aggregate_error` (first-write wins),
/// * if remaining reaches 0 and the op is still `Queued`, hands
///   off:
///   - `aggregate_error.is_some()` → cancel with the error,
///   - else → caller's responsibility (the kind-specific handler
///     owns the issue path and is invoked by the reactor's main
///     queue). We mark the slot ready to issue by setting
///     `predecessor_remaining = 0` (already true at this point).
pub(crate) fn unblock_successors(
    state: &mut crate::owner::VfsState,
    pred: PendingOpHandle,
    error: Option<VfsError>,
) {
    // Drain pred.successors_head into a stack-local list to avoid
    // a long borrow on `state.pending_ops` while we iterate. The
    // upper limit matches `MAX_PRED_FANIN * a few barriers`.
    let mut succs: [PendingOpHandle; 16] = [PendingOpHandle::INVALID; 16];
    let mut n = 0usize;
    if let Some(p) = state.pending_ops.get(pred) {
        let mut cur = p.successors_head;
        while cur.is_valid() && n < succs.len() {
            succs[n] = cur;
            n += 1;
            cur = state
                .pending_ops
                .get(cur)
                .map(|s| s.sibling_next)
                .unwrap_or(PendingOpHandle::INVALID);
        }
    }
    // Clear pred.successors_head so the slot can be reclaimed
    // safely.
    if let Some(p) = state.pending_ops.get_mut(pred) {
        p.successors_head = PendingOpHandle::INVALID;
    }
    for succ in succs.iter().take(n).copied() {
        if let Some(s) = state.pending_ops.get_mut(succ) {
            if s.predecessor_remaining > 0 {
                s.predecessor_remaining -= 1;
            }
            if let Some(err) = error {
                if s.aggregate_error.is_none() {
                    s.aggregate_error = Some(err);
                }
            }
            s.sibling_next = PendingOpHandle::INVALID;
        }
        // Promotion: if the successor is fully unblocked and was
        // sitting in `Queued`, decide its fate.
        let promote = state
            .pending_ops
            .get(succ)
            .map(|s| s.predecessor_remaining == 0 && s.core.state == OpState::Queued)
            .unwrap_or(false);
        if !promote {
            continue;
        }
        let aggregated = state.pending_ops.get(succ).and_then(|s| s.aggregate_error);
        if let Some(err) = aggregated {
            // Translate aggregate error into a real reply for the
            // client. This preserves the first upstream failure
            // rather than collapsing dependency failure to a
            // generic cancellation.
            fail_op_handle(state, succ, err);
        } else {
            // Ready-to-issue. The kind-specific completion router
            // owns the re-issue: it must observe that
            // `predecessor_remaining == 0` before it next gets
            // dispatched, and walks its own waiting queue. The
            // dependency layer keeps the slot alive without
            // re-issuing — that's the kind-specific handler's job.
        }
    }
}
