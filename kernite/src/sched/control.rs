// SPDX-License-Identifier: GPL-2.0-only
//! Scheduler follow-up for task control mutations.

use super::scheduler::{DeferredReleaseList, Scheduler};
use super::thread::{BlockedReason, Tcb};
use crate::syscall::SyscallError;
use crate::task::control::{PriorityAction, SchedClassAction, WriteRegistersAction};
use crate::task::state::ThreadState;
use crate::task::stop::{AffinityAction, ResumeAction};

#[derive(Clone, Copy)]
pub(crate) enum WakeTransition {
    Futex,
    VSpaceWait,
    /// Wake a thread blocked on any pipe-style wait —
    /// `BlockedReason::{PipeRead, PipeWrite, DataPipeRead,
    /// DataPipeWrite}`. The caller is responsible for removing the
    /// thread from the corresponding pipe waiter queue before issuing
    /// the wake plan.
    PipeWait,
    /// Wake a thread blocked on `BlockedReason::EventQueueWait`.
    EventQueueWait,
}

#[derive(Clone, Copy)]
pub(crate) struct ThreadWakePlan {
    pub tcb: *mut Tcb,
    pub transition: WakeTransition,
}

impl ThreadWakePlan {
    #[inline]
    pub(crate) const fn new(tcb: *mut Tcb, transition: WakeTransition) -> Self {
        Self { tcb, transition }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimedWaitResult {
    Completed,
    TimedOut(u64),
}

#[derive(Clone, Copy)]
enum TimeoutQueueAction {
    None,
    Futex,
}

#[derive(Clone, Copy)]
pub(crate) struct TimeoutWakePlan {
    tcb: *mut Tcb,
    action: TimeoutQueueAction,
}

#[derive(Clone, Copy)]
struct TimeoutTraceSnapshot {
    state: ThreadState,
    reason: Option<BlockedReason>,
    futex_addr: u64,
    futex_vspace: u64,
    futex_deadline_ns: u64,
}

impl TimeoutTraceSnapshot {
    const fn empty() -> Self {
        Self {
            state: ThreadState::Stopped,
            reason: None,
            futex_addr: 0,
            futex_vspace: 0,
            futex_deadline_ns: 0,
        }
    }
}

#[inline]
unsafe fn capture_timeout_trace_snapshot(tcb: *mut Tcb) -> TimeoutTraceSnapshot {
    if tcb.is_null() {
        return TimeoutTraceSnapshot::empty();
    }

    unsafe {
        let mut snapshot = TimeoutTraceSnapshot::empty();
        let _ = Tcb::with_lock_enqueue(tcb, |thread| {
            snapshot.state = thread.state();
            snapshot.reason = thread.blocked_reason;
            snapshot.futex_addr = thread.futex_addr;
            snapshot.futex_vspace = thread.futex_vspace as u64;
            snapshot.futex_deadline_ns = thread.timer_wakeup_ns;
            false
        });
        snapshot
    }
}

#[inline]
#[cfg(any(klog_trace, klog_mod_sched))]
unsafe fn ktrace_timeout_result(tcb: *mut Tcb, before: TimeoutTraceSnapshot, ok: bool) {
    if tcb.is_null() {
        return;
    }

    crate::kernel::printk::ktrace!(sched, |_g| {
        let tcb_ref = unsafe { &*tcb };
        _g.puts("[SCHED] timeout cpu=");
        _g.dec(crate::arch::current_cpu() as u64);
        _g.puts(" tcb=");
        _g.hex(tcb as u64);
        crate::sched::thread::ktrace_tcb_identity(&_g, tcb_ref);
        _g.puts(" state=");
        crate::sched::thread::ktrace_thread_state(&_g, before.state);
        _g.puts(" reason=");
        match before.reason {
            Some(BlockedReason::FutexTimedBlocked) => {
                _g.puts("FutexTimedBlocked addr=");
                _g.hex(before.futex_addr);
                _g.puts(" vspace=");
                _g.hex(before.futex_vspace);
                if before.futex_deadline_ns != 0 {
                    _g.puts(" deadline=");
                    _g.hex(before.futex_deadline_ns);
                }
            }
            _ => crate::sched::thread::ktrace_blocked_reason(&_g, tcb_ref, before.reason),
        }
        _g.puts(" ok=");
        _g.dec(ok as u64);
        _g.putc(b'\n');
    });
}

#[inline]
#[cfg(not(any(klog_trace, klog_mod_sched)))]
unsafe fn ktrace_timeout_result(_tcb: *mut Tcb, _before: TimeoutTraceSnapshot, _ok: bool) {}

impl TimedWaitResult {
    #[inline]
    pub(crate) fn raw(self) -> u64 {
        match self {
            TimedWaitResult::Completed => 0,
            TimedWaitResult::TimedOut(result) => result,
        }
    }
}

#[inline]
pub(crate) unsafe fn disarm_timed_wait(tcb: *mut Tcb) {
    unsafe {
        // Cancel any deadline-queue arm (FutexTimed / IpcTimeout)
        // — `cancel_thread` is a no-op when the node is not Queued.
        let _ = crate::sched::deadline_queue::cancel_thread(tcb);
        (*tcb).timer_wakeup_ns = 0;
        (*tcb).futex_wakeup_result = 0;
    }
}

#[inline]
fn apply_wake_transition_locked(thread: &mut Tcb, transition: WakeTransition) -> bool {
    match transition {
        WakeTransition::Futex => crate::task::wait::prepare_futex_wake_locked(thread),
        WakeTransition::VSpaceWait => {
            if thread.state() == ThreadState::Blocked
                && matches!(thread.blocked_reason, Some(BlockedReason::VSpaceWait))
            {
                unsafe { crate::task::wait::mark_runnable_locked(thread as *mut Tcb) };
                thread.blocked_reason = None;
                true
            } else {
                false
            }
        }
        WakeTransition::PipeWait => {
            if thread.state() == ThreadState::Blocked
                && thread.blocked_reason.map_or(false, |r| r.is_pipe_wait())
            {
                unsafe { crate::task::wait::mark_runnable_locked(thread as *mut Tcb) };
                thread.blocked_reason = None;
                true
            } else {
                false
            }
        }
        WakeTransition::EventQueueWait => {
            if thread.state() == ThreadState::Blocked
                && matches!(thread.blocked_reason, Some(BlockedReason::EventQueueWait))
            {
                unsafe { crate::task::wait::mark_runnable_locked(thread as *mut Tcb) };
                thread.blocked_reason = None;
                true
            } else {
                false
            }
        }
    }
}

#[inline]
pub(crate) unsafe fn wake_blocked_thread(tcb: *mut Tcb, transition: WakeTransition) -> bool {
    if tcb.is_null() {
        return false;
    }

    unsafe {
        Tcb::with_lock_enqueue(tcb, |thread| {
            apply_wake_transition_locked(thread, transition)
        })
    }
}

#[inline]
unsafe fn wake_timeout_expired(tcb: *mut Tcb, before: TimeoutTraceSnapshot) -> bool {
    if tcb.is_null() {
        return false;
    }

    unsafe {
        let woke = Tcb::with_lock_enqueue(tcb, |thread| match thread.blocked_reason {
            Some(BlockedReason::FutexTimedBlocked) => {
                thread.futex_wakeup_result = SyscallError::Cancelled as u64;
                crate::task::wait::mark_runnable_locked(thread as *mut Tcb);
                thread.blocked_reason = None;
                true
            }
            _ => false,
        });
        ktrace_timeout_result(tcb, before, woke);
        woke
    }
}

/// Wake a thread parked on any pipe-wait or `EventQueue`-wait kind
/// because its `IpcTimeout` deadline expired. Sets `futex_wakeup_result
/// = TimedOut` ONLY when the lock-protected `Blocked → Runnable`
/// transition actually fires — i.e. when the timeout, not a normal
/// reply / publish wake, is the wait completion winner.
///
/// The previous design wrote `futex_wakeup_result = TimedOut` BEFORE
/// invoking the wake plan, which left a stale `TimedOut` on the TCB
/// when a normal wake had already moved the thread to `Runnable`.
/// On a finite-timeout `MP_CALL` that race burned a live reply: the
/// caller's post-park check saw `TimedOut`, called `cancel_pending`,
/// and discarded the published mailbox record.
///
/// Returns `true` when this fn was the arbitration winner, `false`
/// when a prior wake had already retired the thread.
#[inline]
pub(crate) unsafe fn wake_ipc_timeout(tcb: *mut Tcb) -> bool {
    if tcb.is_null() {
        return false;
    }

    unsafe {
        Tcb::with_lock_enqueue(tcb, |thread| {
            let is_ipc_wait = thread.blocked_reason.map_or(false, |r| {
                r.is_pipe_wait() || matches!(r, BlockedReason::EventQueueWait)
            });
            if thread.state() == ThreadState::Blocked && is_ipc_wait {
                thread.futex_wakeup_result = SyscallError::TimedOut as u64;
                crate::task::wait::mark_runnable_locked(thread as *mut Tcb);
                thread.blocked_reason = None;
                true
            } else {
                false
            }
        })
    }
}

#[inline]
pub(crate) unsafe fn consume_timed_wait_result(tcb: *mut Tcb) -> TimedWaitResult {
    if tcb.is_null() {
        return TimedWaitResult::Completed;
    }

    unsafe {
        let result = (*tcb).futex_wakeup_result;
        (*tcb).futex_wakeup_result = 0;
        if result == 0 {
            TimedWaitResult::Completed
        } else {
            TimedWaitResult::TimedOut(result)
        }
    }
}

#[inline]
pub(crate) unsafe fn block_current_timed_wait(wakeup_ns: u64) -> TimedWaitResult {
    unsafe {
        super::scheduler::scheduler().block_current_futex_timed(wakeup_ns);
        consume_timed_wait_result(super::scheduler::scheduler().current())
    }
}

#[inline]
pub(crate) unsafe fn prepare_timeout_wake_plan(tcb: *mut Tcb) -> Option<TimeoutWakePlan> {
    if tcb.is_null() {
        return None;
    }

    unsafe {
        let action = match (*tcb).blocked_reason {
            Some(BlockedReason::FutexTimedBlocked) => TimeoutQueueAction::Futex,
            _ => return None,
        };

        Some(TimeoutWakePlan { tcb, action })
    }
}

#[inline]
pub(crate) unsafe fn execute_timeout_wake_plan(plan: TimeoutWakePlan) -> bool {
    if plan.tcb.is_null() {
        return false;
    }

    unsafe {
        let before = capture_timeout_trace_snapshot(plan.tcb);
        match plan.action {
            TimeoutQueueAction::None => {}
            TimeoutQueueAction::Futex => {
                crate::ipc::futex::futex_remove_thread(plan.tcb);
                if !matches!(
                    (*plan.tcb).blocked_reason,
                    Some(BlockedReason::FutexTimedBlocked)
                ) {
                    return false;
                }
            }
        }

        wake_timeout_expired(plan.tcb, before)
    }
}

#[inline]
pub(crate) unsafe fn execute_wake_plan(plan: ThreadWakePlan) -> bool {
    if plan.tcb.is_null() {
        return false;
    }

    unsafe {
        // Any `Blocked -> Runnable` wake must cancel a still-armed
        // deadline node for this TCB, regardless of which
        // `WakeTransition` woke it. The embedded `deadline_node` is
        // single-use: a normal reply / pipe / event wake that left it
        // `Queued` made the thread's next timed block silently fail to
        // arm (`arm_thread`'s `Idle -> Queued` CAS no-ops), losing
        // timeout/wake arbitration for every later timed wait by that
        // thread. The deadline-node state is the source of truth — the
        // wake transition does not encode it.
        let armed = (*plan.tcb)
            .deadline_node
            .state
            .load(core::sync::atomic::Ordering::Acquire)
            == crate::sched::deadline_queue::DeadlineNodeState::Queued as u8;

        if !armed {
            return wake_blocked_thread(plan.tcb, plan.transition);
        }

        // Hold a transient pin across disarm + wake so the deadline
        // membership-pin release inside `disarm_timed_wait` cannot
        // drop `sched_ref` to zero before the wake/enqueue takes its
        // own ready-slot pin — inc-destination-before-dec-source (see
        // `apply_resume_locked`). The node must still be cancelled
        // before the thread can run again, so disarm precedes the wake.
        (*plan.tcb).sched_ref_inc();
        let woke = {
            disarm_timed_wait(plan.tcb);
            if (*plan.tcb).blocked_reason.is_none() {
                false
            } else {
                wake_blocked_thread(plan.tcb, plan.transition)
            }
        };
        super::scheduler::scheduler().sched_ref_release_may_destroy(plan.tcb);
        woke
    }
}

#[inline]
pub(crate) unsafe fn execute_wake_plan_locked(
    tcb: *mut Tcb,
    thread: &mut Tcb,
    plan: ThreadWakePlan,
) -> bool {
    if tcb.is_null() {
        return false;
    }

    unsafe {
        let armed = (*tcb)
            .deadline_node
            .state
            .load(core::sync::atomic::Ordering::Acquire)
            == crate::sched::deadline_queue::DeadlineNodeState::Queued as u8;
        if armed {
            disarm_timed_wait(tcb);
            if (*tcb).blocked_reason.is_none() {
                return false;
            }
        }
    }

    apply_wake_transition_locked(thread, plan.transition)
}

#[inline]
pub(crate) const fn futex_wake_plan(tcb: *mut Tcb) -> ThreadWakePlan {
    ThreadWakePlan::new(tcb, WakeTransition::Futex)
}

#[inline]
pub(crate) const fn vspace_wait_wake_plan(tcb: *mut Tcb) -> ThreadWakePlan {
    ThreadWakePlan::new(tcb, WakeTransition::VSpaceWait)
}

#[inline]
pub(crate) const fn pipe_wait_wake_plan(tcb: *mut Tcb) -> ThreadWakePlan {
    ThreadWakePlan::new(tcb, WakeTransition::PipeWait)
}

#[inline]
pub(crate) const fn eq_wait_wake_plan(tcb: *mut Tcb) -> ThreadWakePlan {
    ThreadWakePlan::new(tcb, WakeTransition::EventQueueWait)
}

#[inline]
pub(crate) unsafe fn finish_locked_mutation(
    scheduler: &mut Scheduler,
    releases: &mut DeferredReleaseList,
) {
    unsafe {
        scheduler.drain_release(releases);
    }
}

#[inline]
pub(crate) fn apply_resume_locked(
    scheduler: &mut Scheduler,
    tcb: *mut Tcb,
    action: &ResumeAction,
    releases: &mut DeferredReleaseList,
) {
    if action.enqueue {
        // enqueue() calls `sched_ref_inc` for the ready-queue slot
        // BEFORE we release the waiter slot below — inc-dest-
        // before-dec-source prevents a zero-window UAF against a
        // concurrent last-cap-drop `release_object`.
        scheduler.enqueue_with_releases_locked(tcb, releases);
    }
}

#[inline]
pub(crate) unsafe fn finish_resume(
    scheduler: &mut Scheduler,
    tcb: *mut Tcb,
    action: &ResumeAction,
    releases: &mut DeferredReleaseList,
) {
    unsafe {
        finish_locked_mutation(scheduler, releases);
    }
    if action.release_vspace_waiter {
        unsafe {
            scheduler.sched_ref_release_may_destroy(tcb);
        }
    }
}

#[inline]
pub(crate) fn apply_write_registers_locked(
    scheduler: &mut Scheduler,
    tcb: *mut Tcb,
    action: &WriteRegistersAction,
    releases: &mut DeferredReleaseList,
) {
    if action.enqueue {
        scheduler.enqueue_with_releases_locked(tcb, releases);
    }
}

#[inline]
pub(crate) fn apply_affinity_locked(
    scheduler: &mut Scheduler,
    tcb: *mut Tcb,
    action: &AffinityAction,
    releases: &mut DeferredReleaseList,
) -> Option<usize> {
    if action.requeue_ready {
        scheduler.requeue_thread_with_releases_locked(tcb, releases);
    }
    action.resched_cpu
}

#[inline]
pub(crate) fn apply_priority_locked(
    scheduler: &mut Scheduler,
    tcb: *mut Tcb,
    action: &PriorityAction,
    releases: &mut DeferredReleaseList,
) {
    if let Some(weight) = action.fair_reweight {
        unsafe {
            scheduler.reweight_fair_thread_locked(tcb, weight);
        }
    } else if action.requeue_ready {
        scheduler.requeue_thread_with_releases_locked(tcb, releases);
    }
}

#[inline]
pub(crate) fn apply_sched_class_locked(
    scheduler: &mut Scheduler,
    tcb: *mut Tcb,
    action: &SchedClassAction,
    releases: &mut DeferredReleaseList,
) {
    if action.requeue_ready {
        scheduler.requeue_thread_with_releases_locked(tcb, releases);
    }
}

#[inline]
pub(crate) fn dispatch_reschedule(scheduler: &mut Scheduler, cpu: Option<usize>) {
    if let Some(cpu) = cpu {
        let this_cpu = crate::arch::current_cpu() as usize;
        if cpu == this_cpu {
            scheduler.reschedule();
        } else {
            unsafe {
                crate::arch::send_ipi(cpu, crate::arch::IpiKind::Reschedule);
            }
        }
    }
}

#[inline]
pub(crate) unsafe fn publish_fastpath_switch_locked(
    scheduler: &mut Scheduler,
    cpu_id: usize,
    old_tcb: *mut Tcb,
    new_tcb: *mut Tcb,
    releases: &mut DeferredReleaseList,
) {
    unsafe {
        scheduler.publish_switch_target_locked(cpu_id, old_tcb, new_tcb, releases);
    }
}

// Quiescence (`wait_for_tcb_quiesced`, `wait_for_tcb_quiesced_blocking`,
// `release_suspended_waiter`, `cleanup_quiesced_thread`,
// `finish_current_exit`) and SUSPEND_SPIN_LIMIT live in
// `crate::task::quiesce` now — they are part of the kill / exit /
// destroy plane, not the scheduler-internal wake-plan plane.
