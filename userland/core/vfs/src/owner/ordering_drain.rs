// SPDX-License-Identifier: GPL-2.0-only
//
//! `OrderingGate` ready-queue drain.
//!
//! Called once per reactor iteration after the inbound event has
//! been dispatched. Drains every ready entry the gate has
//! accumulated since the last drain. The drain currently handles
//! `OpKind::Sync` ordering holds (fsync / fdatasync) and
//! ordered metadata mutation replays (setattr / truncate);
//! future ordering-aware ops (multi-step rename, MAP_SHARED
//! writeback barrier coalescing) plug in through the same drain.
//!
//! For each ready entry the drain:
//! 1. Resolves `tx` → `PendingOpHandle`. Stale entries (slot
//!    already released through a teardown) are dropped silently.
//! 2. Takes the parked reply lease back into a live
//!    `ReplyLease`.
//! 3. Combines the lane's aggregate `error` with the saved
//!    backend-ack label — the public reply is `OK` only when
//!    both report success; otherwise the propagated upstream
//!    error wins.
//! 4. Emits the public reply through `reply_send` and
//!    releases the PendingOp arena slot.

use trona_kernel::core_types::TronaMsg;

use crate::arena::segmented_array::SegmentedArray;
use crate::core::error::VfsError;
use crate::ipc::protocol::backend::VFS_BACKEND_REPLY_OK;
use crate::ipc::protocol::public::vfs_error_to_public_reply;
use crate::owner::VfsState;
use crate::owner::op::OpKind;
use crate::owner::ordering::OrderingReady;
use trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;

/// Drain every ready-to-issue entry the gate accumulated since
/// the previous call and emit the matching public-protocol reply.
/// Owner-thread only; runs after the dispatcher returns from
/// `EventLoop::run_iteration`.
pub(crate) fn drain(state: &mut VfsState) {
    let mut ready_buf: SegmentedArray<OrderingReady> = SegmentedArray::new_empty();
    state.ordering.take_ready_issues(&mut ready_buf);
    let n = ready_buf.len();
    for i in 0..n {
        let entry = match ready_buf.get(i) {
            Some(e) => *e,
            None => continue,
        };
        finalize_one(state, entry);
    }
}

fn finalize_one(state: &mut VfsState, ready: OrderingReady) {
    let Some(handle) = state.find_pending_op(ready.tx) else {
        // The held op has already been released — typical when
        // a session teardown or client cancel raced the gate's
        // promotion. Complete the lane head, if this entry was
        // one, so a dead queued op cannot wedge the FIFO.
        let _ = state.ordering.complete(ready.key, ready.tx, None);
        return;
    };
    let (kind, saved_ack_label) = state
        .pending_ops
        .get(handle)
        .map(|op| (op.core.kind, op.saved_ack_label))
        .unwrap_or((OpKind::Empty, None));

    if ready.error.is_none() && kind == OpKind::Sync && saved_ack_label.is_none() {
        match crate::fs::saltyfs_client::mutate_rpc::issue_parked_fsync(state, handle) {
            Ok(()) => return,
            Err(VfsError::Busy) => {
                state.ordering.requeue_ready(ready);
                return;
            }
            Err(err) => {
                finalize_reply(state, handle, Some(err), None);
                return;
            }
        }
    }

    if kind == OpKind::AttrMutate {
        if let Some(err) = ready.error {
            finalize_reply(state, handle, Some(err), None);
            let _ = state.ordering.complete(ready.key, ready.tx, Some(err));
            return;
        }
        match crate::fs::saltyfs_client::mutate_rpc::issue_parked_attr_mutation(state, handle) {
            Ok(()) => return,
            Err(VfsError::Busy) => {
                state.ordering.requeue_ready(ready);
                return;
            }
            Err(err) => {
                finalize_reply(state, handle, Some(err), None);
                let _ = state.ordering.complete(ready.key, ready.tx, Some(err));
                return;
            }
        }
    }

    finalize_reply(state, handle, ready.error, saved_ack_label);
}

fn finalize_reply(
    state: &mut VfsState,
    handle: crate::owner::pending::PendingOpHandle,
    ready_error: Option<VfsError>,
    saved_ack_label: Option<u64>,
) {
    let parked = state
        .pending_ops
        .get_mut(handle)
        .and_then(|op| ::core::mem::take(&mut op.reply_lease));
    state.pending_ops.release(handle);
    let Some(parked) = parked else {
        // Lease was already consumed via a non-ordering path —
        // for example the slot was cancelled with a payload-bearing
        // disposition. Skip so we never double-consume.
        return;
    };
    let lease = parked.unpark();
    let mut out = TronaMsg::default();
    out.length = 0;
    if let Some(err) = ready_error {
        out.label = vfs_error_to_public_reply(err);
    } else if let Some(label) = saved_ack_label {
        if label == VFS_BACKEND_REPLY_OK {
            out.label = VFS_PUBLIC_REPLY_OK;
        } else {
            out.label = vfs_error_to_public_reply(VfsError::from_backend_reply(label));
        }
    } else {
        // The barrier promoted before the held op's backend ack
        // landed. That can happen if every predecessor settled
        // before the held op's BACKEND_FSYNC reached the wire —
        // the gate counts the held op against the lane head, so
        // we wait for its own completion to stamp the ack. Until
        // that happens we surface `Io` so the caller never
        // observes a synthetic OK; the next ordering completion
        // will drive the held op's reply through this drain.
        out.label = vfs_error_to_public_reply(VfsError::Io);
    }
    crate::owner::op::reply_send(lease, &out);
}
