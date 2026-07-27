// SPDX-License-Identifier: GPL-2.0-only
//! `TCB_STOP` and resume transitions.
//!
//! The stop plane only flips the TCB state to `Stopped` (or back to
//! Runnable on resume) and detaches its in-flight wait-queue links.
//! Kill / exit / final destroy live in `task::quiesce`.

use crate::sched::thread::Tcb;
use crate::task::state::ThreadState;

/// Set TCB state to `Stopped`. Used by scheduler internals
/// (switch / rq / slots) when a thread is being parked into the
/// stopped slot.
///
/// # Safety
/// Caller must hold the lock context that protects the TCB's state
/// field.
#[inline]
pub(crate) unsafe fn mark_stopped_locked(tcb: *mut Tcb) {
    unsafe { (*tcb).state = ThreadState::Stopped };
}

pub(crate) struct ResumeAction {
    pub(crate) enqueue: bool,
    pub(crate) release_vspace_waiter: bool,
}

pub(crate) struct AffinityAction {
    pub(crate) requeue_ready: bool,
    pub(crate) resched_cpu: Option<usize>,
}

pub(crate) enum SuspendActionKind {
    None,
    RescheduleSelf,
    WaitForQuiesce,
}

pub(crate) struct SuspendAction {
    pub(crate) kind: SuspendActionKind,
    pub(crate) cpu_hint: Option<usize>,
    pub(crate) release_vspace_waiter: bool,
}

/// Apply a `TCB_RESUME` against `tcb` and report the follow-up
/// scheduler work. The caller is expected to hold the per-TCB lock
/// across this call.
///
/// `enqueue = true` means the scheduler must place `tcb` back on the
/// ready queue once its run context is restored. `release_vspace_waiter`
/// piggybacks the VSpace-wait pin release that the suspend path took.
pub(crate) unsafe fn prepare_resume_locked(tcb: &mut Tcb) -> ResumeAction {
    match tcb.state {
        ThreadState::Runnable | ThreadState::Created | ThreadState::Dying => ResumeAction {
            enqueue: false,
            release_vspace_waiter: false,
        },
        ThreadState::Configured | ThreadState::Stopped => ResumeAction {
            enqueue: true,
            release_vspace_waiter: false,
        },
        ThreadState::Blocked => {
            let release_vspace_waiter = matches!(
                tcb.blocked_reason,
                Some(crate::sched::thread::BlockedReason::VSpaceWait)
            );
            unsafe {
                crate::sched::thread::detach_thread_wait_queues(tcb as *mut Tcb);
            }
            tcb.blocked_reason = None;
            ResumeAction {
                enqueue: true,
                release_vspace_waiter,
            }
        }
    }
}

/// Apply a `TCB_STOP` against `tcb`. Returns the follow-up
/// scheduler work — the caller is responsible for calling
/// `release_suspended_waiter` (in `task::quiesce`) and for blocking
/// in `wait_for_tcb_quiesced_blocking` when `kind = WaitForQuiesce`.
///
/// `this_cpu` is the CPU executing this syscall; `running_cpu` is
/// the CPU currently running `tcb` (if any), looked up by the
/// caller under the scheduler lock before this call.
pub(crate) unsafe fn prepare_suspend_locked(
    tcb: &mut Tcb,
    this_cpu: usize,
    running_cpu: Option<usize>,
) -> SuspendAction {
    unsafe {
        crate::sched::pip::pip_cleanup(tcb as *mut Tcb);
    }

    match tcb.state {
        ThreadState::Created
        | ThreadState::Configured
        | ThreadState::Stopped
        | ThreadState::Dying => SuspendAction {
            kind: SuspendActionKind::None,
            cpu_hint: None,
            release_vspace_waiter: false,
        },
        ThreadState::Runnable => {
            let release_vspace_waiter = matches!(
                tcb.blocked_reason,
                Some(crate::sched::thread::BlockedReason::VSpaceWait)
            );
            tcb.state = ThreadState::Stopped;
            unsafe {
                crate::sched::thread::detach_thread_wait_queues(tcb as *mut Tcb);
            }
            match running_cpu {
                Some(cpu) if cpu == this_cpu => SuspendAction {
                    kind: SuspendActionKind::RescheduleSelf,
                    cpu_hint: None,
                    release_vspace_waiter,
                },
                other => SuspendAction {
                    kind: SuspendActionKind::WaitForQuiesce,
                    cpu_hint: other,
                    release_vspace_waiter,
                },
            }
        }
        ThreadState::Blocked => {
            let release_vspace_waiter = matches!(
                tcb.blocked_reason,
                Some(crate::sched::thread::BlockedReason::VSpaceWait)
            );
            unsafe {
                crate::sched::thread::detach_thread_wait_queues(tcb as *mut Tcb);
            }
            tcb.state = ThreadState::Stopped;
            tcb.blocked_reason = None;
            SuspendAction {
                kind: SuspendActionKind::WaitForQuiesce,
                cpu_hint: None,
                release_vspace_waiter,
            }
        }
    }
}

pub(crate) fn set_affinity_locked(tcb: &mut Tcb, affinity: u32) -> AffinityAction {
    tcb.cpu_affinity = affinity;
    let requeue_ready = tcb.state == ThreadState::Runnable;
    let resched_cpu = if tcb.state == ThreadState::Runnable
        && affinity != 0xFFFF_FFFF
        && tcb.run_owner() != Some(affinity as usize)
    {
        tcb.run_owner()
    } else {
        None
    };
    AffinityAction {
        requeue_ready,
        resched_cpu,
    }
}
