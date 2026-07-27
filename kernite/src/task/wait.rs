// SPDX-License-Identifier: GPL-2.0-only
//! TCB wait/wake state transitions.
//!
//! Owns the small set of transitions that move a thread between
//! `Runnable` and `Blocked` (with a specific `BlockedReason`) outside
//! of stop/kill/exit flows — those live in `task::stop` /
//! `task::quiesce`. Every helper expects the per-TCB lock to already
//! be held by the caller; the tag is in the function name.

use crate::mm::VSpace;
use crate::sched::thread::{BlockedReason, Tcb};
use crate::task::state::ThreadState;

/// Set TCB state to `Runnable`. Caller must hold the appropriate
/// scheduler / TCB lock context. Every `state =` mutation routes
/// through a `task::*` helper — scheduler internals (switch / rq /
/// wake / slots) call this for run-state transitions.
///
/// Runnable is a scheduler-visible state, so the blocked-reason tag
/// must be cleared at the same boundary. Wait-queue detachment remains
/// the caller's responsibility; ready-queue insertion still asserts
/// that no intrusive wait links are left behind.
///
/// # Safety
/// `tcb` must point to a live TCB whose state field is currently
/// safe to write under the caller's lock.
#[inline]
pub(crate) unsafe fn mark_runnable_locked(tcb: *mut Tcb) {
    unsafe {
        (*tcb).blocked_reason = None;
        (*tcb).state = ThreadState::Runnable;
    }
}

/// Set TCB state to `Blocked` (without setting `blocked_reason` —
/// the caller is responsible for that, typically via
/// `prepare_blocked_reason_locked` which writes both atomically
/// under the per-TCB lock). Used by `wake.rs`'s park path which
/// flips the state immediately before yielding.
///
/// # Safety
/// Same as `mark_runnable_locked`.
#[inline]
pub(crate) unsafe fn mark_blocked_locked(tcb: *mut Tcb) {
    unsafe { (*tcb).state = ThreadState::Blocked };
}

/// Park the thread in `BlockedReason` with `state = Blocked`. Used
/// by IPC / mailbox / fault wait sites that have already published
/// the wait-side bookkeeping (carrier slot, wait queue, etc.)
/// and need the scheduler-visible state flip.
pub(crate) fn prepare_blocked_reason_locked(tcb: &mut Tcb, reason: BlockedReason) {
    tcb.blocked_reason = Some(reason);
    tcb.state = ThreadState::Blocked;
}

/// Roll a freshly-parked thread back to Runnable. Used by syscall
/// arms that detect a pre-park condition (peer closed, mailbox
/// already populated, deadline = 0 = WouldBlock) after they have
/// already called `prepare_blocked_reason_locked`.
pub(crate) fn rollback_blocked_to_running_locked(tcb: &mut Tcb) {
    tcb.blocked_reason = None;
    tcb.state = ThreadState::Runnable;
}

/// Park the thread on a futex address (untimed wait).
pub(crate) fn prepare_futex_block_locked(tcb: &mut Tcb, addr: u64, vspace: *mut VSpace) {
    tcb.futex_addr = addr;
    tcb.futex_vspace = vspace;
    tcb.futex_next = core::ptr::null_mut();
    tcb.blocked_reason = Some(BlockedReason::FutexBlocked);
    tcb.state = ThreadState::Blocked;
}

/// Park the thread on a futex address with a deadline registered.
/// `futex_wakeup_result = 0` resets any prior wake-result so a stale
/// timeout from the previous wait cannot leak into the new one.
pub(crate) fn prepare_futex_timed_block_locked(tcb: &mut Tcb, addr: u64, vspace: *mut VSpace) {
    tcb.futex_addr = addr;
    tcb.futex_vspace = vspace;
    tcb.futex_next = core::ptr::null_mut();
    tcb.futex_wakeup_result = 0;
    tcb.blocked_reason = Some(BlockedReason::FutexTimedBlocked);
    tcb.state = ThreadState::Blocked;
}

/// Wake a futex-blocked thread. Returns `true` when the transition
/// `Blocked(Futex*) → Runnable` actually fired. Stale wakers (the
/// thread is no longer Blocked, or is blocked on something else)
/// observe `false` and are responsible for not double-counting.
pub(crate) fn prepare_futex_wake_locked(tcb: &mut Tcb) -> bool {
    if !matches!(tcb.state, ThreadState::Blocked) {
        return false;
    }

    match tcb.blocked_reason {
        Some(BlockedReason::FutexBlocked) | Some(BlockedReason::FutexTimedBlocked) => {
            tcb.futex_wakeup_result = 0;
            tcb.blocked_reason = None;
            tcb.state = ThreadState::Runnable;
            true
        }
        _ => false,
    }
}
