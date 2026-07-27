// SPDX-License-Identifier: GPL-2.0-only
//! Syscall continuation framework.
//!
//! Helpers used by path-syscall handlers (open, stat, access, …) when
//! a path lookup or vop yields mid-call. The handler reserves a
//! `PendingOp` up front (with the syscall family `PO_KIND_*_CONT`),
//! stashes its tail-state in the typed payload, and lets the worker
//! drive the backend RPC. When the reply lands, `complete_namei_resume`
//! routes through `dispatch_syscall_continuation` to the matching
//! `complete_*_continuation` handler.

use trona_kernel::core_types::TronaMsg;

use crate::owner::VfsState;
use crate::owner::namei::{NAMEI_STEP_DONE, NameiResumeAux, NameiResumeState};
use crate::owner::pending_ops::{self, PendingOpId, PendingOpKind};
use crate::server::types::ClientHandle;
use crate::vfs_core::vnode::VnodeHandle;

/// Reserve a `PendingOp` for a syscall continuation. Captures the
/// caller's reply slot via `tty_wait::save_current_caller` and marks
/// the request reply as deferred so the worker can deliver later.
/// Returns `None` when the slot pool is exhausted — the caller must
/// reply with the canonical OOM error inline.
///
/// # Safety
///
/// Owner-thread only; `reply` must be a valid pointer to a
/// caller-owned `TronaMsg`.
pub(crate) unsafe fn prepare_continuation(
    kind: PendingOpKind,
    badge: u64,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
) -> Option<PendingOpId> {
    unsafe {
        let reply_slot = crate::fileops::tty_wait::save_current_caller(reply)?;
        let Some(op_id) = pending_ops::alloc(kind, badge, cli_handle, reply_slot) else {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
            return None;
        };
        (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        Some(op_id)
    }
}

/// Initialise the continuation payload for a syscall whose namei walk
/// has already resolved (sync path). `current` is the vnode the
/// syscall continuation will operate on once a backend RPC replies.
/// `aux_kind` + `aux` populate the syscall-body variant of the union;
/// the caller picks one of `NAMEI_AUX_OPEN` / `NAMEI_AUX_STAT` / etc.
/// and constructs the matching union body inline.
///
/// # Safety
///
/// Owner-thread only; `op_id` must be a freshly allocated PendingOp
/// whose `payload_ref` has not yet been set.
pub(crate) unsafe fn init_continuation_payload_done(
    op_id: PendingOpId,
    current: VnodeHandle,
    aux_kind: u8,
    aux: NameiResumeAux,
) -> bool {
    unsafe {
        let Some(payload_ref) = pending_ops::alloc_payload() else {
            return false;
        };
        let Some(buf) = pending_ops::payload_bytes_mut(payload_ref) else {
            pending_ops::release_payload(payload_ref);
            return false;
        };
        let Some(op) = pending_ops::get_mut(op_id) else {
            pending_ops::release_payload(payload_ref);
            return false;
        };
        let state_ptr = buf.as_mut_ptr() as *mut NameiResumeState;
        (*state_ptr) = NameiResumeState {
            path: [0; super::BOOTSTRAP_PATH_MAX],
            path_len: 0,
            pos: 0,
            depth: 0,
            follow_final_symlink: 0,
            ignore_case: 0,
            skip_posix_only: 0,
            skip_win32_only: 0,
            resume_step: NAMEI_STEP_DONE,
            aux_kind,
            _pad: [0; 5],
            current_packed: ((current.epoch() as u64) << 32) | (current.slot() as u64),
            aux,
        };
        op.payload_ref = payload_ref;
        true
    }
}

/// Adopt an existing PendingOp produced inside a deferred-aware vop
/// (e.g. `ensure_pts_slave_vnode` returning `Deferred(op_id)`) for the
/// caller's syscall continuation. Stamps the syscall family `kind`,
/// transfers the caller's reply slot onto the op, overwrites the
/// op's `saved.path` with `abs_path`, and replaces the placeholder
/// `aux` with the `PO_KIND_*_CONT` body. `reply` is marked deferred
/// so the worker delivers the final reply.
///
/// Returns `false` when the reply slot pool is exhausted, the op has
/// been garbage-collected, or the op has no valid payload. On
/// failure the reply slot (if reserved) is released so the syscall
/// caller's reply is not orphaned. Callers must then abort the
/// continuation — the underlying op was already enqueued, so dropping
/// the reference lets `drain_cancelled` tear it down.
///
/// # Safety
///
/// Owner-thread only; `reply` must be a valid pointer to a
/// caller-owned `TronaMsg`. The caller must guarantee `op_id` already
/// carries a valid `payload_ref` — walk-deferred ops satisfy this via
/// `save_namei_resume_state`; non-walk vop deferrals (saltyfs
/// `create_regular_child` / `truncate` / …) are responsible for
/// allocating their own payload before returning `Deferred(op_id)`.
pub(crate) unsafe fn adopt_deferred_op_for_continuation(
    op_id: PendingOpId,
    new_kind: PendingOpKind,
    badge: u64,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
    abs_path: &[u8],
    aux_kind: u8,
    aux: NameiResumeAux,
) -> bool {
    unsafe {
        let Some(reply_slot) = crate::fileops::tty_wait::save_current_caller(reply) else {
            return false;
        };
        let Some(op) = pending_ops::get_mut(op_id) else {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
            return false;
        };
        op.kind = new_kind;
        op.badge = badge;
        op.client_handle_raw = crate::owner::dispatch::pack_client_handle(cli_handle);
        op.reply_slot = reply_slot;
        let payload_ref = op.payload_ref;
        let Some(buf) = pending_ops::payload_bytes_mut(payload_ref) else {
            // Caller-broken contract: deferred op without payload would
            // orphan the reply slot. Surface loudly instead of silently
            // skipping the payload init.
            op.reply_slot = 0;
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
            return false;
        };
        let state_ptr = buf.as_mut_ptr() as *mut NameiResumeState;
        let copy_len = core::cmp::min(abs_path.len(), super::BOOTSTRAP_PATH_MAX);
        (&mut (*state_ptr).path)[..copy_len].copy_from_slice(&abs_path[..copy_len]);
        (*state_ptr).path_len = copy_len as u16;
        (*state_ptr).aux_kind = aux_kind;
        (*state_ptr).aux = aux;
        (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

/// Fail a continuation early: take the reply slot, free the op, and
/// send `err_label` to the saved caller. Used when the syscall handler
/// detects an error after `prepare_continuation` but before any
/// backend RPC is enqueued.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn fail_continuation(op_id: PendingOpId, err_label: u64) {
    unsafe {
        let reply_slot = pending_ops::take_reply_and_free(op_id);
        if reply_slot != 0 {
            let mut reply = TronaMsg::zeroed();
            reply.label = err_label;
            crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
        }
    }
}

/// Deliver `reply` to the saved caller and free the continuation op.
/// Used by `complete_*_continuation` once the syscall's tail-work is
/// finished and the final wire message is ready.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn finish_continuation(op_id: PendingOpId, reply: TronaMsg) {
    unsafe {
        let reply_slot = pending_ops::take_reply_and_free(op_id);
        if reply_slot != 0 {
            crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
        }
    }
}

/// Transfer a continuation op's caller context (kind / badge / client
/// handle / reply slot) onto a fresh `new_op_id` produced by a chained
/// inner-vop deferral while re-driving the namei walk. After the
/// transfer, `old_op_id` is freed; its `payload_ref` is released and
/// reply ownership has moved to `new_op_id`. The worker driving the
/// chained backend RPC will re-enter `complete_namei_resume` against
/// `new_op_id`, whose payload already carries the updated
/// `NameiResumeState` saved by the walk's second yield.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn transition_to_chained_op(
    old_op_id: PendingOpId,
    new_op_id: PendingOpId,
) -> bool {
    unsafe {
        let (old_kind, old_badge, old_cli, old_reply) = match pending_ops::get(old_op_id) {
            Some(op) => (op.kind, op.badge, op.client_handle_raw, op.reply_slot),
            None => return false,
        };
        let Some(new) = pending_ops::get_mut(new_op_id) else {
            return false;
        };
        new.kind = old_kind;
        new.badge = old_badge;
        new.client_handle_raw = old_cli;
        new.reply_slot = old_reply;
        if let Some(old_mut) = pending_ops::get_mut(old_op_id) {
            old_mut.reply_slot = 0;
        }
        pending_ops::free(old_op_id);
        true
    }
}

/// Variant of `transition_to_chained_op` that *also* overwrites the
/// chained op's `aux` body. Used when a syscall continuation
/// re-enters its sync tail inside backend-completion context and a
/// downstream vop yields a fresh deferral — the caller cannot reach
/// `tty_wait::save_current_caller` (no syscall reply cap is active),
/// so it must move the original reply slot from the *current* op
/// onto the *new* op via this transfer instead of `adopt_*`.
///
/// Transfers `(kind, badge, client_handle_raw, reply_slot)` from
/// `old_op_id` to `new_op_id` and overwrites *only* `aux_kind` /
/// `aux` in the new op's `NameiResumeState`. `path` / `pos` /
/// `current_packed` / `resume_step` are preserved — those are the
/// vop's own walk state for resuming. After the transfer,
/// `old_op_id` is freed (with `reply_slot=0` first).
///
/// # Safety
///
/// Owner-thread only. The caller guarantees that `new_op_id` already
/// has a valid `payload_ref` (the walk's `save_namei_resume_state` or
/// the backend vop's own allocation).
pub(crate) unsafe fn transition_to_chained_op_with_aux(
    old_op_id: PendingOpId,
    new_op_id: PendingOpId,
    new_kind: PendingOpKind,
    aux_kind: u8,
    aux: NameiResumeAux,
) -> bool {
    unsafe {
        let (old_badge, old_cli, old_reply) = match pending_ops::get(old_op_id) {
            Some(op) => (op.badge, op.client_handle_raw, op.reply_slot),
            None => return false,
        };
        let Some(new) = pending_ops::get_mut(new_op_id) else {
            return false;
        };
        new.kind = new_kind;
        new.badge = old_badge;
        new.client_handle_raw = old_cli;
        new.reply_slot = old_reply;
        let payload_ref = new.payload_ref;
        let Some(buf) = pending_ops::payload_bytes_mut(payload_ref) else {
            return false;
        };
        let state_ptr = buf.as_mut_ptr() as *mut NameiResumeState;
        (*state_ptr).aux_kind = aux_kind;
        (*state_ptr).aux = aux;
        if let Some(old_mut) = pending_ops::get_mut(old_op_id) {
            old_mut.reply_slot = 0;
        }
        pending_ops::free(old_op_id);
        true
    }
}

/// Fill caller context (badge / client_handle_raw / reply_slot) onto a
/// PendingOp that was allocated with placeholder context. Used by sync
/// vops that allocate the op + payload up front and only learn the
/// caller's badge / reply when a deferred-aware syscall handler picks
/// the op up. Mirrors `prepare_continuation`'s reply-slot capture but
/// operates on an existing op instead of allocating a fresh one.
///
/// Returns `false` when `tty_wait::save_current_caller` is exhausted or
/// the op has been garbage-collected. On failure the caller must free
/// the op via `pending_ops::free` and reply with the canonical OOM
/// error inline so the client is not orphaned.
///
/// # Safety
///
/// Owner-thread only; `reply` must be a valid pointer to a
/// caller-owned `TronaMsg`. The caller guarantees `op_id` is alive
/// (allocated this dispatch round) and its reply_slot is currently
/// zero (no other helper has captured a caller for it).
pub(crate) unsafe fn populate_alloced_op_for_caller(
    state: &VfsState,
    op_id: PendingOpId,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
        let Some(reply_slot) = crate::fileops::tty_wait::save_current_caller(reply) else {
            return false;
        };
        let Some(op) = pending_ops::get_mut(op_id) else {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
            return false;
        };
        op.badge = badge;
        op.client_handle_raw = crate::owner::dispatch::pack_client_handle(cli_handle);
        op.reply_slot = reply_slot;
        (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}
