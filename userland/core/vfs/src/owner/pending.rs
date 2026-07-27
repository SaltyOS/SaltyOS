// SPDX-License-Identifier: GPL-2.0-only
//
//! `PendingOp` arena + reply-completion router.
//!
//! Issue-side invariant: every PendingOp carries a 5-tuple
//! `(tx_id, client_id, reply_endpoint, backend_session_gen,
//! vnode_stable_key)`. Completion-side invariant: the inbound
//! reply's `(fs_instance_id, mount_handle, session_id, live_gen,
//! tx_id)` is re-checked against the live `BackendSessionSlot` at
//! every backend reply. A mismatch on any field drops the reply
//! silently — slot reuse / remount cycle / stale incarnation all
//! surface as drops here, not as wrong-target dispatches.
//!
//! Dependency edges live next to the 5-tuple core:
//! [`PendingOp::predecessors`] (PRED_TX),
//! [`predecessor_remaining`] (PRED_BARRIER counter),
//! [`successors_head`] / [`sibling_next`] (intrusive linked list of
//! successors), [`aggregate_error`] (first-error propagation slot).

use crate::core::error::{IntegrityDetail, VfsError, audit_integrity_failure};
use crate::core::identity::FsInstanceId;
use crate::owner::op::{CancelDisposition, OpCore, OpKind, OpState};
use crate::owner::resume::Resume;
use trona_kernel::core_types::TronaMsg;
use trona_server::ParkedReply;

/// Maximum path-component byte length carried inline on a single
/// `PendingOp` — saltyfs `BACKEND_LOOKUP` and friends pack their
/// `name` directly into the opaque kind payload so the deferred
/// re-issue path never has to round-trip through the SHM region.
pub(crate) const WALK_NAME_MAX: usize = 144;

/// Maximum symlink-target byte length carried inline. Mirrors the
/// per-walk symlink resolution depth's per-step buffer used by
/// the namei state machine.
pub(crate) const WALK_SYMLINK_TARGET_MAX: usize = 1024;

/// Per-walk path-buffer cap. The async namei state machine carries
/// the in-progress path through symlink expansions in this
/// fixed-size buffer; growing past `WALK_PATH_MAX` returns
/// `VfsError::NameTooLong`.
pub(crate) const WALK_PATH_MAX: usize = 4096;

/// Snapshot of the in-progress async namei walk. Captures every
/// piece of state the resume handler needs to pick up at the next
/// component boundary after a backend round-trip.
///
/// Layout mirrors `vfs_old`'s mature walker — `cwd_vkey` is the
/// directory the *next* lookup runs under, `root_vkey` pins the
/// namespace root for `..` rebound checks, `remaining_path` carries
/// the unconsumed tail (Approach Y shift-left through every step),
/// `policy` discriminates terminal handling (StopAtParent /
/// CreateOrOpen / FinalMustExist / Continue), and `cred` is the
/// caller's credential snapshot at walk start so a privilege change
/// mid-walk cannot corrupt access decisions.
#[derive(Clone, Copy)]
pub(crate) struct WalkCursor {
    /// Vnode of the directory the next component resolves under.
    pub cwd_vkey: crate::core::identity::VnodeKey,
    /// Namespace root identity. `..` rebound at this vnode pins
    /// the walk inside the caller's namespace.
    pub root_vkey: crate::core::identity::VnodeKey,
    /// Live, in-progress path tail. Components are popped from the
    /// front and the tail is shift-left-compacted on every step.
    pub remaining_path: [u8; WALK_PATH_MAX],
    /// Live byte count of `remaining_path[..remaining_len]`.
    pub remaining_len: u16,
    /// Symlink follow depth — bumped on each successful symlink
    /// expansion, compared against `NAMEI_SYMLINK_MAX_DEPTH`.
    pub follow_depth: u8,
    /// Flags carried from the caller's `NAMEI_*` mask. Determines
    /// final-component nofollow / directory-required / case-fold
    /// behaviour.
    pub flags: u32,
    /// Walk policy + per-policy state. Drives terminal arms
    /// (StopAtParent / CreateOrOpen / FinalMustExist / Continue).
    pub policy: WalkPolicy,
    /// Parent/name of the lookup currently in flight. Set before
    /// a backend lookup parks so completion can recover the final
    /// dirent anchor after the local stack frame is gone.
    pub lookup_anchor: crate::server::open_object::OpenObjectAnchor,
    /// Parent/name of the resolved terminal leaf. Copied into
    /// `NameiAsyncResult` so open can install a handle sidecar.
    pub leaf_anchor: crate::server::open_object::OpenObjectAnchor,
    /// Caller credential snapshot — frozen at walk start so a
    /// concurrent setuid does not corrupt mid-walk decisions.
    pub cred: crate::core::cred::VfsCred,
}

/// Walk-policy discriminator. Drives the terminal arm of every
/// async walk and is consulted on every `walk_step` to decide
/// whether a missing final component is an error or a clean
/// short-circuit.
#[derive(Clone, Copy)]
pub(crate) enum WalkPolicy {
    /// Every component must resolve and the terminal arm returns
    /// the resolved leaf as `result.vp`.
    FinalMustExist,
    /// `O_CREAT` / `mkdir` / `symlink` semantics — the walker
    /// records the final-component name (so the create site can
    /// re-issue against the parent) and reports `final_missing`
    /// when the final component does not exist. Both branches
    /// return: `final_missing = true` → `result.dvp` = parent and
    /// `result.last_name` = child name; `final_missing = false`
    /// → `result.vp` = resolved leaf.
    CreateOrOpen {
        final_name: [u8; WALK_NAME_MAX],
        final_name_len: u8,
        final_missing: bool,
    },
    /// `mkdir` / `symlink` semantics — the walker stops one
    /// component short of the path and surfaces the parent + final
    /// name. The final component itself is never resolved against
    /// the backend.
    StopAtParent {
        final_name: [u8; WALK_NAME_MAX],
        final_name_len: u8,
    },
    /// `unlink` / `rename` / `link` semantics that need to inspect
    /// an existing final component before mutating the parent. The
    /// walker still returns parent + final name, but also resolves
    /// the raw final vnode into `result.vnode_h` when it exists. It
    /// deliberately does not cross covering mounts for that final
    /// component; mutation dispatchers use the raw vnode to reject
    /// operations on mountpoints with `EBUSY`.
    StopAtParentLookup {
        final_name: [u8; WALK_NAME_MAX],
        final_name_len: u8,
        missing_ok: bool,
    },
}

/// Stage of the async walk state machine the cursor is currently
/// in. Each stage has its own resume entry point on the saltyfs
/// completion side (and equivalents on netsrv / pty backends if
/// they ever participate in walks).
#[derive(Clone, Copy)]
pub(crate) enum WalkPhase {
    /// Resolving the next single component via `BACKEND_LOOKUP`.
    Lookup,
    /// Following a symlink — the backend `BACKEND_READLINK` round
    /// trip is in flight; the resume splices the target into the
    /// path buffer and re-enters `Lookup`.
    Readlink,
}

/// Backing storage size of the per-backend opaque kind payload.
/// Each backend (saltyfs / netsrv / posix_ttysrv / mmsrv-pager)
/// packs its own struct into these bytes at issue time and unpacks
/// at completion time. Sized so the largest variant
/// (`saltyfs::Symlink` with two inline name buffers) fits with a
/// few words of headroom.
pub(crate) const PENDING_KIND_PAYLOAD_WORDS: usize = 48;
pub(crate) const PENDING_KIND_PAYLOAD_BYTES: usize = PENDING_KIND_PAYLOAD_WORDS * 8;

/// Opaque per-PendingOp scratch for backend-specific resume state.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct PendingKindPayload {
    pub(crate) words: [u64; PENDING_KIND_PAYLOAD_WORDS],
}

impl PendingKindPayload {
    pub(crate) const fn zeroed() -> Self {
        Self {
            words: [0; PENDING_KIND_PAYLOAD_WORDS],
        }
    }
}

/// Monotonic per-VFS transaction id wrapper. Keeps tx ids
/// type-distinguished from raw `u64` arena slots and similar bare
/// integers; `TxId(0)` is the reserved sentinel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct TxId(pub u64);

impl TxId {
    pub(crate) const INVALID: TxId = TxId(0);

    #[inline]
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub(crate) const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

/// Maximum predecessor list depth carried inline on a single
/// PendingOp. fsync's PRED_BARRIER carries a counter, not the
/// individual edges — the backward edges live on each pred's
/// successors list, so the inline array only needs the rare-case
/// PRED_TX fan-in (rename's src+dst lookup, link's dst+target).
pub(crate) const MAX_PRED_FANIN: usize = 4;

/// PendingOp body.
#[repr(C)]
pub(crate) struct PendingOp {
    pub core: OpCore,
    pub resume: Resume,
    /// Opaque per-backend scratch — saltyfs / netsrv / posix_ttysrv
    /// / pager each define their own struct and `pack`/`unpack`
    /// it through these bytes. The generic pending layer never
    /// inspects the contents.
    pub kind_payload: PendingKindPayload,
    /// Saved parked reply endpoint reference. `None` for
    /// fire-and-forget ops (no caller waiting on a reply);
    /// `Some(_)` for the typical MP_CALL path where the dispatcher
    /// parked the frontend MessagePipe endpoint lease into this
    /// slot and handed active lease ownership to the PendingOp.
    /// The completion router unparks it back into a fresh
    /// `ReplyLease` and takes the terminal action
    /// (consume / cancel / drop) on the resume hook.
    pub reply_lease: Option<ParkedReply>,
    /// Backend-side ack stashed for ordering-hold ops (currently
    /// `OpKind::Sync` — fsync / fdatasync). The dispatch router
    /// records the inbound `BACKEND_FSYNC` reply's `label` here
    /// instead of forwarding it to the client; the
    /// `OrderingGate::take_ready_issues` drain merges it with the
    /// barrier's aggregate error and emits the public reply when
    /// every predecessor has settled. `None` for non-hold ops.
    pub saved_ack_label: Option<u64>,
    /// Absolute monotonic deadline for owner-local timeout driven
    /// ops. `0` means no deadline. Today this is used by parked
    /// POSIX `poll(2)` waits; backend RPCs keep timeout policy in
    /// their backend-specific payloads.
    pub deadline_ns: u64,
    /// Inline PRED_TX predecessor handles. Slot count > 0 means
    /// this op is gated on each pred's completion.
    pub predecessors: [PendingOpHandle; MAX_PRED_FANIN],
    /// PRED_BARRIER counter. Decremented on each pred-completion
    /// hook; when it reaches 0 the op promotes from `Queued` to
    /// `Running` (or fails immediately if `aggregate_error` is
    /// `Some`).
    pub predecessor_remaining: u32,
    /// Head of the intrusive successor list. Each successor's
    /// `sibling_next` chains to the next sibling under the same
    /// pred.
    pub successors_head: PendingOpHandle,
    /// Next sibling under the same predecessor (intrusive list).
    pub sibling_next: PendingOpHandle,
    /// First error observed across this op's completed
    /// predecessors. Successor inherits on `unblock_successors` so
    /// fsync can fail with the upstream write's error.
    pub aggregate_error: Option<VfsError>,
}

impl PendingOp {
    pub(crate) const EMPTY: Self = Self {
        core: OpCore::EMPTY,
        resume: Resume::EMPTY,
        kind_payload: PendingKindPayload::zeroed(),
        reply_lease: None,
        saved_ack_label: None,
        deadline_ns: 0,
        predecessors: [PendingOpHandle::INVALID; MAX_PRED_FANIN],
        predecessor_remaining: 0,
        successors_head: PendingOpHandle::INVALID,
        sibling_next: PendingOpHandle::INVALID,
        aggregate_error: None,
    };
}

/// Stable, ABA-safe handle into the `pending_ops`
/// [`trona_server::ContinuationArena`]. Aliases the generic
/// [`trona_server::ContHandle`]: pending ops are keyed in the arena by
/// their own monotonic [`OpCore::tx_id`] (the correlation token the
/// backend echoes), and the handle pins a slot + epoch so a stale
/// reference fails resolution after the slot is reused.
pub(crate) type PendingOpHandle = trona_server::ContHandle;

/// Dispatcher entry point for a backend reply that arrived on a
/// per-session callback MP.
///
/// The router validates the completion 5-tuple
/// `(fs_instance_id, mount_handle, session_id, live_gen, tx_id)`
/// against the live `BackendSessionSlot`. Any mismatch drops the
/// reply silently. The actual reply-shape decoding (FS vs net vs
/// pager) happens via the `Resume` discriminator after validation,
/// dispatched in the kind-specific handler module.
///
/// Called from the owner reactor when a backend-session cookie
/// fires. Single-mutator: this function holds an exclusive
/// `&mut VfsState` throughout, no nested re-entry through outbound
/// IPC.
///
/// Returns `Ok(())` on a successful resume / drop, `Err(VfsError)`
/// when the resume handler reports a fatal mismatch the router can
/// surface to the operator (logged but otherwise dropped — backend
/// replies have no caller waiting for an error reply on this code
/// path; the original PendingOp's `client_id` already received the
/// fault via `reply_send` or `reply_drop`).
pub(crate) fn dispatch_pending_reply(
    state: &mut crate::owner::VfsState,
    tx_id: TxId,
    expected_fs_instance_id: FsInstanceId,
    expected_mount_handle: u64,
    expected_session_id: u32,
    expected_live_gen: u32,
    reply_msg: &trona_kernel::core_types::TronaMsg,
) -> Result<(), VfsError> {
    let Some(op_handle) = state.find_pending_op(tx_id) else {
        // Stale completion — PendingOp already cancelled / freed.
        // Drop silently. The reply slot is gone; nothing else to do.
        return Ok(());
    };

    // Read-only op snapshot. Inspect the slot without touching
    // `reply_lease`: a mismatch on the op-side 5-tuple drops the
    // reply silently and leaves the parked lease intact for a
    // later teardown sweep, so the active lease never escapes
    // its parked slot through an early return.
    let (op_core, resume_ctx, kind_payload, session_idx, cancelled) = {
        let op = state
            .pending_ops
            .get(op_handle)
            .ok_or(VfsError::StaleIncarnation)?;
        if op.core.backend_session_gen != expected_live_gen {
            audit_integrity_failure(expected_fs_instance_id, IntegrityDetail::StaleSession);
            return Ok(());
        }
        if op.core.tx_id != tx_id {
            audit_integrity_failure(expected_fs_instance_id, IntegrityDetail::Malformed);
            return Ok(());
        }
        (
            op.core,
            op.resume,
            op.kind_payload,
            op.core.backend_session_idx as usize,
            op.core.cancelled,
        )
    };

    // Session-side 5-tuple validation. Same invariant: every
    // mismatch path returns before the lease is unparked.
    let completion_fn = {
        let Some(session) = state.backend_session_at(session_idx) else {
            audit_integrity_failure(expected_fs_instance_id, IntegrityDetail::UnknownMount);
            return Ok(());
        };
        if session.fs_instance_id != expected_fs_instance_id {
            audit_integrity_failure(expected_fs_instance_id, IntegrityDetail::UnknownMount);
            return Ok(());
        }
        if session.mount_handle_raw != expected_mount_handle {
            audit_integrity_failure(expected_fs_instance_id, IntegrityDetail::UnknownMount);
            return Ok(());
        }
        if session.session_id != expected_session_id {
            audit_integrity_failure(expected_fs_instance_id, IntegrityDetail::StaleSession);
            return Ok(());
        }
        if session.live_gen != expected_live_gen {
            audit_integrity_failure(expected_fs_instance_id, IntegrityDetail::StaleSession);
            return Ok(());
        }
        session.completion_fn
    };

    // Cancel-first short-circuit. When the op was marked
    // cancelled mid-flight (PEER_CLOSED sweep, explicit teardown,
    // dependency-graph aggregate-error reroute) the completion fn
    // never runs; `cancel_op_handle` is the single owner of the
    // parked lease's terminal — it unparks, applies the saved
    // disposition (Drop / Cancelled / ServerDied), and releases
    // the arena slot.
    if cancelled {
        crate::owner::pending::cancel_op_handle(state, op_handle, op_core.cancel_disposition);
        return Ok(());
    }

    // Empty-kind diagnostic. The slot was alloc'd without a
    // resume stamp — issuing-site bug. Drop the saved reply
    // token to avoid wedging the caller; the kernel finaliser
    // surfaces a cancel.
    if op_core.kind == OpKind::Empty {
        let parked = state
            .pending_ops
            .get_mut(op_handle)
            .and_then(|op| ::core::mem::take(&mut op.reply_lease));
        if let Some(p) = parked {
            crate::owner::op::reply_drop(p.unpark());
        }
        state.pending_ops.release(op_handle);
        return Ok(());
    }

    // Ordering-hold short-circuit. `OpKind::Sync` (fsync /
    // fdatasync) is barrier-gated: the backend's reply is *not*
    // the client-facing terminal. Stash the ack label on the
    // slot, run the ordering / dependency hooks so other waiters
    // observe the completion, and leave the parked reply lease
    // in place. `OrderingGate::take_ready_issues` (drained from
    // the reactor's per-iteration hook) merges the lane's
    // aggregate error with `saved_ack_label` and emits the
    // public reply once every predecessor settles.
    // Release-on-return is suppressed here; the ordering drain
    // owns the slot's terminal.
    if op_core.kind == OpKind::Sync {
        if let Some(op) = state.pending_ops.get_mut(op_handle) {
            op.core.state = OpState::Completing;
            op.saved_ack_label = Some(reply_msg.label);
        }
        // Backend round-trip is settled: hand the reserved
        // credit back to the session so deferred ops can drain
        // even though the caller's reply stays held until the
        // ordering barrier promotes.
        if op_core.credit_held && op_core.backend_session_idx != u32::MAX {
            state.backend_credit_release_for_session_idx(op_core.backend_session_idx);
            if let Some(op) = state.pending_ops.get_mut(op_handle) {
                op.core.credit_held = false;
            }
        }
        let ordering_gate_seen = ordering_key_for(&op_core)
            .map(|key| {
                state
                    .ordering
                    .complete(key, tx_id, ordering_error_for_reply(reply_msg))
            })
            .unwrap_or(false);
        crate::owner::dependency::unblock_successors(
            state,
            op_handle,
            ordering_error_for_reply(reply_msg),
        );
        if !ordering_gate_seen {
            finish_sync_without_ordering_gate(state, op_handle, reply_msg);
        }
        return Ok(());
    }

    // Unpark the lease and invoke the completion fn. Every
    // prior mismatch / cancel path has returned, so the active
    // lease ownership now flows into the completion fn (which
    // consumes / drops it on its own resume hook).
    let reply_lease = {
        let op = state
            .pending_ops
            .get_mut(op_handle)
            .ok_or(VfsError::StaleIncarnation)?;
        op.core.state = OpState::Completing;
        let parked = ::core::mem::take(&mut op.reply_lease);
        parked.map(|p| p.unpark())
    };

    match completion_fn {
        Some(f) => unsafe {
            f(
                state,
                expected_fs_instance_id,
                tx_id,
                &kind_payload,
                resume_ctx,
                op_core.backend_session_idx,
                reply_lease,
                reply_msg,
                op_core.personality,
            );
        },
        None => {
            // Session never registered a completion hook — drop
            // the saved reply slot so the caller observes a
            // kernel-side cancellation rather than wedging
            // forever. This is a registration bug; surfacing it
            // through the reply stream is preferable to silent
            // hang.
            if let Some(l) = reply_lease {
                crate::owner::op::reply_drop(l);
            }
        }
    }
    // Notify the ordering gate so a successor queued behind this
    // op is promoted (clean) or failed with the aggregate error
    // (label != VFS_BACKEND_REPLY_OK).
    if let Some(key) = ordering_key_for(&op_core) {
        state
            .ordering
            .complete(key, tx_id, ordering_error_for_reply(reply_msg));
    }
    // Drive the dependency graph forward: every successor parked
    // on a PRED_TX or PRED_BARRIER edge against `op_handle` has
    // its remaining counter decremented, and the upstream error
    // (label != VFS_BACKEND_REPLY_OK) propagates into the
    // successor's `aggregate_error` so a fsync barrier fed by a
    // failed write surfaces that same error to its caller.
    crate::owner::dependency::unblock_successors(
        state,
        op_handle,
        ordering_error_for_reply(reply_msg),
    );
    state.pending_ops.release(op_handle);
    Ok(())
}

fn finish_sync_without_ordering_gate(
    state: &mut crate::owner::VfsState,
    op_handle: PendingOpHandle,
    reply_msg: &trona_kernel::core_types::TronaMsg,
) {
    use crate::ipc::protocol::backend::VFS_BACKEND_REPLY_OK;
    use crate::ipc::protocol::public::vfs_error_to_public_reply;
    use trona_kernel::core_types::TronaMsg;
    use trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;

    let parked = state
        .pending_ops
        .get_mut(op_handle)
        .and_then(|op| ::core::mem::take(&mut op.reply_lease));
    state.pending_ops.release(op_handle);
    let Some(parked) = parked else {
        return;
    };
    let mut out = TronaMsg::default();
    out.length = 0;
    out.label = if reply_msg.label == VFS_BACKEND_REPLY_OK {
        VFS_PUBLIC_REPLY_OK
    } else {
        vfs_error_to_public_reply(VfsError::from_backend_reply(reply_msg.label))
    };
    crate::owner::op::reply_send(parked.unpark(), &out);
}

/// Derive the ordering key for `op_core`. `None` means the
/// op-kind is not currently plumbed into the ordering gate; the
/// dispatcher skips the `complete` call rather than synthesising
/// an empty lane. Pager writeback is tracked on the vnode lane so
/// `fsync` waits for every MAP_SHARED writeback issued before the
/// barrier.
fn ordering_key_for(core: &OpCore) -> Option<crate::owner::ordering::OrderingKey> {
    use crate::owner::ordering::OrderingKey;
    match core.kind {
        OpKind::Write | OpKind::DirMutate | OpKind::AttrMutate | OpKind::Sync | OpKind::Pager => {
            Some(OrderingKey::VnodeMutate(core.vnode_key))
        }
        _ => None,
    }
}

/// Translate a backend reply label into the ordering error
/// channel. `VFS_BACKEND_REPLY_OK` is success (returns `None`);
/// anything else is mapped through `VfsError::from_backend_reply`
/// so successor barriers inherit the upstream failure.
fn ordering_error_for_reply(msg: &trona_kernel::core_types::TronaMsg) -> Option<VfsError> {
    use crate::ipc::protocol::backend::VFS_BACKEND_REPLY_OK;
    if msg.label == VFS_BACKEND_REPLY_OK {
        None
    } else {
        Some(VfsError::from_backend_reply(msg.label))
    }
}

/// Allocate a PendingOp slot and stamp `OpCore::tx_id`. The
/// reply endpoint lease is *not* attached here — frontend async ops
/// park their lease through `stamp_resume_ctx` after the issue
/// site succeeds. Returns `None` if the arena is exhausted.
pub(crate) fn alloc_pending(
    state: &mut crate::owner::VfsState,
    kind: OpKind,
    client_id: u32,
    client_badge: u64,
    backend_session_idx: u32,
    backend_session_gen: u32,
    vnode_key: crate::core::identity::VnodeKey,
) -> Option<PendingOpHandle> {
    let tx_id = state.alloc_tx_id();
    // Build the op on the stack, then hand it to the continuation arena
    // keyed by its own monotonic `tx_id` — the low-range correlation
    // token the backend echoes in its completion header. PendingOp
    // carries non-zero invalid sentinels (handles, tx ids, resume
    // state), so start from the typed empty value before stamping the
    // live core.
    let mut op = PendingOp::EMPTY;
    op.core.state = OpState::Queued;
    op.core.kind = kind;
    op.core.cancel_disposition = CancelDisposition::None;
    op.core.cancelled = false;
    op.core.client_id = client_id;
    op.core.client_badge = client_badge;
    op.core.tx_id = tx_id;
    op.core.backend_session_idx = backend_session_idx;
    op.core.backend_session_gen = backend_session_gen;
    op.core.vnode_key = vnode_key;
    op.core.coalesce_primary_tx = TxId::INVALID;
    op.core.credit_held = false;
    op.resume = Resume::EMPTY;
    op.kind_payload = PendingKindPayload::zeroed();
    op.reply_lease = None;
    op.saved_ack_label = None;
    op.deadline_ns = 0;
    op.predecessors = [PendingOpHandle::INVALID; MAX_PRED_FANIN];
    op.predecessor_remaining = 0;
    op.successors_head = PendingOpHandle::INVALID;
    op.sibling_next = PendingOpHandle::INVALID;
    op.aggregate_error = None;
    let mut alloc = crate::arena::segmented_array::MmapAllocator::new();
    // SAFETY: `MmapAllocator` satisfies the `SegmentAllocator` contract
    // (page-aligned, zeroed, lives for the arena's lifetime).
    unsafe {
        state
            .pending_ops
            .alloc_with_token(&mut alloc, tx_id.raw(), op)
            .ok()
    }
}

/// Cancel a PendingOp at any point in its lifetime. The reply slot
/// disposition is determined by `disp`:
/// * [`CancelDisposition::Drop`] — `cnode_delete` the reply slot;
///   client observes a kernel cancellation.
/// * [`CancelDisposition::ServerDied`] — send a real reply with
///   `VfsError::SessionTornDown`.
/// * [`CancelDisposition::Failed`] — send a real reply with the
///   supplied upstream error (`VfsError::PredecessorFailed` when
///   no concrete error is available).
///
/// Idempotent — calling on an already-cancelled op is a no-op.
pub(crate) fn cancel_op_handle(
    state: &mut crate::owner::VfsState,
    op_handle: PendingOpHandle,
    disp: CancelDisposition,
) {
    let terminal_error = match disp {
        CancelDisposition::None | CancelDisposition::Drop => None,
        CancelDisposition::Cancelled => Some(VfsError::Intr),
        CancelDisposition::ServerDied => Some(VfsError::SessionTornDown),
        CancelDisposition::Failed => Some(VfsError::PredecessorFailed),
    };
    terminate_op_handle(state, op_handle, disp, terminal_error);
}

/// Fail a PendingOp because a predecessor or ordering gate
/// reported a concrete upstream error. This preserves the first
/// observed `VfsError` so fsync / metadata barriers surface the
/// real failure rather than a generic teardown result.
pub(crate) fn fail_op_handle(
    state: &mut crate::owner::VfsState,
    op_handle: PendingOpHandle,
    err: VfsError,
) {
    terminate_op_handle(state, op_handle, CancelDisposition::Failed, Some(err));
}

fn terminate_op_handle(
    state: &mut crate::owner::VfsState,
    op_handle: PendingOpHandle,
    disp: CancelDisposition,
    terminal_error: Option<VfsError>,
) {
    let Some(op) = state.pending_ops.get_mut(op_handle) else {
        return;
    };
    if op.core.state == OpState::Cancelled {
        return;
    }
    let prev_state = op.core.state;
    let parked = ::core::mem::take(&mut op.reply_lease);
    // An init-query op holds no lease of its own — the client lease lives
    // on its `InitQuerySnapshot`. Capture the snapshot handle before the
    // resume is cleared so it can be reaped after release (below).
    let init_snapshot = match op.resume {
        Resume::Init(ir) => Some(ir.snapshot),
        // The ctty-dump pre-stage op also points at a snapshot (its lease
        // lives there); reap it on teardown like an init-query op.
        Resume::Fs(crate::owner::resume::FsResume::CttyDump { snapshot }) => Some(snapshot),
        _ => None,
    };
    op.resume = Resume::EMPTY;
    op.core.cancelled = true;
    op.core.cancel_disposition = disp;
    op.core.state = OpState::Cancelled;
    let kind_for_drain = op.core.kind;
    let credit_held = op.core.credit_held;
    let session_idx = op.core.backend_session_idx;
    op.core.credit_held = false;
    let _ = (prev_state, kind_for_drain);

    // In the page-cache supply model a cancelled Pager op owns no
    // vfs-side resources to release — the page is sourced and copied by
    // the kernel inside a single `PAGER_SUPPLY_COPY`, and the staging
    // buffer / SHM ring are shared, not per-op.

    // Hand back any backend-session credit the op was holding.
    // Without this, every cancelled in-flight op would leak a
    // unit of `inflight_now` and starve the session's deferred
    // FIFO once enough cancels accumulate. The session mutator
    // saturating-decrements, so a stale handle here is safe.
    if credit_held && session_idx != u32::MAX {
        state.backend_credit_release_for_session_idx(session_idx);
    }
    match disp {
        CancelDisposition::None => {
            // Non-cancellation path — caller misuse. Reattach the
            // parked record so a real terminator can release it.
            if let Some(op) = state.pending_ops.get_mut(op_handle) {
                op.reply_lease = parked;
                op.core.state = prev_state;
                op.core.cancelled = false;
            }
        }
        CancelDisposition::Drop => {
            if let Some(p) = parked {
                crate::owner::op::reply_drop(p.unpark());
            }
        }
        CancelDisposition::Cancelled
        | CancelDisposition::ServerDied
        | CancelDisposition::Failed => {
            let mut reply = TronaMsg::zeroed();
            reply.label = crate::ipc::protocol::public::vfs_error_to_public_reply(
                terminal_error.unwrap_or(VfsError::PredecessorFailed),
            );
            reply.length = 0;
            if let Some(p) = parked {
                crate::owner::op::reply_send(p.unpark(), &reply);
            }
        }
    }
    state.pending_ops.release(op_handle);
    // Reap the init-query snapshot (and cancel its parked client lease)
    // for a cancelled init read. Non-init ops have `None` here.
    if let Some(snap_h) = init_snapshot {
        crate::owner::init_rpc::drop_snapshot(state, snap_h);
    }
}

/// Cancel every PendingOp whose `client_badge` matches. Used on
/// inbound `STATE_PEER_CLOSED` from a client's request MP — the
/// client is gone, no reply will reach it, drop every outstanding
/// op without sending a payload.
pub(crate) fn cancel_for_badge(state: &mut crate::owner::VfsState, badge: u64) {
    // Two-pass — collect handles first (`for_each_active` borrows
    // `pending_ops` shared) then mutate.
    let mut victims: [PendingOpHandle; 32] = [PendingOpHandle::INVALID; 32];
    let mut count = 0usize;
    state.pending_ops.for_each_active(|h, op| {
        if count == victims.len() {
            return false;
        }
        if op.core.client_badge == badge {
            victims[count] = h;
            count += 1;
        }
        true
    });
    for victim in victims.iter().take(count).copied() {
        cancel_op_handle(state, victim, CancelDisposition::Drop);
    }
    // If we hit the local buffer limit we may have left victims on
    // a busy client. Loop until none remain — the typical case is
    // `count < 32` so this is one pass.
    if count == victims.len() {
        cancel_for_badge(state, badge);
    }
}
