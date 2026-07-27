// SPDX-License-Identifier: GPL-2.0-only
//! Task lifecycle state — owned by the `task` plane. The scheduler
//! holds the field on `Tcb` because that is where placement reads
//! it, but the *meaning* (Created/Configured/Runnable/Blocked/
//! Stopped/Dying transitions) and every mutation helper lives here
//! and in the sibling `task::*` modules.

use crate::sched::thread::Tcb;

/// Thread lifecycle state. Placement (which CPU runs the thread,
/// whether it is ready-queued) lives in the scheduler's placement
/// fields, not in this enum. Structural mutation is gated on `state ∈
/// {Created, Stopped}` via `can_mutate_thread_structure`; `Dying`
/// rejects all structural changes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// TCB carved from untyped but not yet `TCB_CONFIGURE`d. No vspace,
    /// no cspace, no entry point. Structural mutation allowed.
    Created,
    /// `TCB_CONFIGURE` has run. Ready for `TCB_START`. Reconfigure
    /// requires `TCB_STOP` first.
    Configured,
    /// Eligible to run. Whether currently running or ready-queued is
    /// the scheduler's placement concern, not this enum's.
    Runnable,
    /// Blocked on an IPC, futex, fault, watcher event, or VSpace
    /// quiesce. The reason is in `blocked_reason`.
    Blocked,
    /// `TCB_STOP` has run. Resumable via `TCB_START`. Structural
    /// mutation allowed.
    Stopped,
    /// Termination underway (fault, `TCB_KILL`, last cap revoke). No
    /// structural mutation; reaper finalizes once `sched_ref` hits zero.
    Dying,
}

impl Tcb {
    /// Read the thread's lifecycle state. The field is narrow-visible
    /// to `crate::task` only; everyone outside (scheduler internals,
    /// syscalls, IPC) goes through this accessor.
    #[inline]
    pub fn state(&self) -> ThreadState {
        self.state
    }
}

/// Structural mutation (configure / set_space / set_stack /
/// bind_sched_context / set_ipc_buffer / etc.) is allowed only on a
/// not-running, not-dying thread. `Configured` is excluded —
/// reconfigure requires explicit `TCB_STOP` to make the boundary
/// observable.
#[inline]
pub(crate) fn can_mutate_thread_structure(tcb: &Tcb) -> bool {
    matches!(tcb.state(), ThreadState::Created | ThreadState::Stopped)
}

/// Set TCB state to `Created`. The fresh-init state — used only by
/// `Tcb::init_at` (and the bootstrap/idle TCB seed paths). Wrapping
/// the assignment here keeps every `state =` mutation under
/// `crate::task`.
///
/// # Safety
/// `tcb` must point to TCB storage that the caller owns exclusively
/// (init time, before the scheduler ever sees it).
#[inline]
pub(crate) unsafe fn mark_created_locked(tcb: *mut Tcb) {
    unsafe { (*tcb).state = ThreadState::Created };
}

/// Set TCB state to `Configured` after `TCB_CONFIGURE` has installed
/// the run context. `TCB_START` only enqueues `Configured` or
/// `Stopped` TCBs, so configure must publish this lifecycle boundary.
///
/// # Safety
/// Caller must hold the TCB lock while mutating the lifecycle state.
#[inline]
pub(crate) unsafe fn mark_configured_locked(tcb: *mut Tcb) {
    unsafe { (*tcb).state = ThreadState::Configured };
}
