// SPDX-License-Identifier: GPL-2.0-only
//! Thread quiescence — kill / exit / final destroy.
//!
//! Stop transitions live in `task::stop`; this module owns the
//! one-way path from any live state to `Dying`, the cross-CPU
//! quiescence wait, and the final reaper hand-off.

use super::stop::{SuspendAction, SuspendActionKind};
use crate::sched::scheduler::{DeferredReleaseList, Scheduler};
use crate::sched::thread::{BlockedReason, Tcb};
use crate::task::state::ThreadState;
use core::sync::atomic::Ordering;

/// Set TCB state to `Dying`. The terminal state — once set, the
/// reaper / cleanup path takes over. Used by `Tcb::cleanup` and any
/// caller that needs to mark a thread for destruction without going
/// through the full kill flow.
///
/// # Safety
/// Caller must hold the lock context that protects the TCB's state
/// field.
#[inline]
pub(crate) unsafe fn mark_dying_locked(tcb: *mut Tcb) {
    unsafe { (*tcb).state = ThreadState::Dying };
}

/// Maximum spin iterations waiting for cross-CPU suspend / kill to
/// complete. ~1 ms at 2 GHz — the target CPU will process the
/// reschedule IPI within single-digit microseconds, the spin is just
/// a cap on a pathological busy CPU.
const SUSPEND_SPIN_LIMIT: u32 = 2_000_000;

pub(crate) struct ExitAction {
    pub(crate) release_vspace_waiter: bool,
}

/// Apply a `TCB_KILL` against `tcb`. Drives the state into `Dying`
/// regardless of where it was, returns the same shape of action as
/// `prepare_suspend_locked` so the caller can route through
/// `release_suspended_waiter` + `wait_for_tcb_quiesced_blocking`.
pub(crate) unsafe fn prepare_kill_locked(
    tcb: &mut Tcb,
    this_cpu: usize,
    running_cpu: Option<usize>,
) -> SuspendAction {
    unsafe {
        crate::sched::pip::pip_cleanup(tcb as *mut Tcb);
    }

    match tcb.state {
        ThreadState::Dying => SuspendAction {
            kind: SuspendActionKind::None,
            cpu_hint: None,
            release_vspace_waiter: false,
        },
        ThreadState::Created | ThreadState::Configured | ThreadState::Stopped => {
            tcb.state = ThreadState::Dying;
            SuspendAction {
                kind: SuspendActionKind::None,
                cpu_hint: None,
                release_vspace_waiter: false,
            }
        }
        ThreadState::Runnable => {
            let release_vspace_waiter =
                matches!(tcb.blocked_reason, Some(BlockedReason::VSpaceWait));
            tcb.state = ThreadState::Dying;
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
            let release_vspace_waiter =
                matches!(tcb.blocked_reason, Some(BlockedReason::VSpaceWait));
            unsafe {
                crate::sched::thread::detach_thread_wait_queues(tcb as *mut Tcb);
            }
            tcb.state = ThreadState::Dying;
            tcb.blocked_reason = None;
            SuspendAction {
                kind: SuspendActionKind::WaitForQuiesce,
                cpu_hint: None,
                release_vspace_waiter,
            }
        }
    }
}

/// Self-exit transition (the running thread is killing itself).
pub(crate) unsafe fn prepare_thread_exit_locked(tcb: &mut Tcb) -> ExitAction {
    unsafe {
        crate::sched::pip::pip_cleanup(tcb as *mut Tcb);
    }

    let release_vspace_waiter = matches!(tcb.blocked_reason, Some(BlockedReason::VSpaceWait));
    unsafe {
        crate::sched::thread::detach_thread_wait_queues(tcb as *mut Tcb);
    }
    tcb.state = ThreadState::Dying;
    tcb.blocked_reason = None;
    ExitAction {
        release_vspace_waiter,
    }
}

/// Fault-context wrapper for `begin_destroy`. The architectural fault
/// handlers route here when `deliver_fault` returned `false` — i.e.
/// the faulting TCB has no bound fault `MessagePipe`, so the fault
/// has nowhere to go.
///
/// SaltyOS invariant: every user TCB must register a fault handler
/// pipe via `TCB_SET_FAULT_PIPE` before it can run faulting code.
/// Init's supervisor binds the pipe for every spawned process; core
/// services (init / namesrv / rsrcsrv / mmsrv) are themselves the
/// fault sinks for the rest of the system, so a self-fault on those
/// processes has no recoverable destination. In both cases, reaching
/// this path means the system cannot make forward progress — halt
/// to keep state inspectable rather than tearing down a TCB whose
/// loss would deadlock the system.
pub(crate) unsafe fn begin_destroy_on_fault(target: *mut Tcb) {
    if target.is_null() {
        return;
    }
    if unsafe { (*target).fault_pipe.is_null() } {
        crate::kernel::printk::serial_puts_raw(
            "[FAULT] self-fault on TCB without fault sink — system halt\n",
        );
        crate::arch::system_halt();
    }
    unsafe {
        begin_destroy(target);
    }
}

/// Begin asynchronous destruction of `target`. Self-exits skip the
/// quiesce wait; cross-thread kills run prepare_kill + cleanup +
/// quiesce wait.
pub(crate) unsafe fn begin_destroy(target: *mut Tcb) {
    if target.is_null() {
        return;
    }

    unsafe {
        let irq = crate::mm::save_irq_disable();
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        let is_self = core::ptr::eq(target as *const Tcb, current as *const Tcb);

        let tcb = &mut *target;
        tcb.tcb_lock();

        if is_self {
            let action = prepare_thread_exit_locked(tcb);
            tcb.tcb_unlock();
            finish_current_exit(scheduler, target, &action);
            crate::mm::restore_irq(irq);
            return;
        }

        let running_cpu = if tcb.state == ThreadState::Runnable {
            scheduler.lock();
            let cpu = scheduler.find_running_cpu(target);
            scheduler.unlock();
            cpu
        } else {
            None
        };

        let action = prepare_kill_locked(tcb, crate::arch::current_cpu() as usize, running_cpu);

        tcb.tcb_unlock();
        release_suspended_waiter(scheduler, target, &action);
        crate::mm::restore_irq(irq);

        if matches!(action.kind, SuspendActionKind::WaitForQuiesce) {
            wait_for_tcb_quiesced_blocking(target, action.cpu_hint);
            cleanup_quiesced_thread(scheduler, target);
        }
    }
}

/// Wait for cross-CPU drain of a thread that has just transitioned
/// to `Stopped` or `Dying`. Polls the scheduler's running-CPU /
/// pending-CPU / run-owner state until none of them point at `tcb`.
///
/// A thread is not safe to reuse the moment its state changes away
/// from `Running`: another CPU may still own its live kernel context,
/// or the thread may be parked in a deferred switch-out slot waiting
/// post-switch cleanup. `exec` reuses the same TCB immediately after
/// `TCB_STOP`, so the suspend path must wait for both conditions to
/// clear.
pub(crate) unsafe fn wait_for_tcb_quiesced(tcb: *mut Tcb, cpu_hint: Option<usize>) -> bool {
    let this_cpu = crate::arch::current_cpu() as usize;

    for spins in 0..SUSPEND_SPIN_LIMIT {
        let (running_cpu, pending_cpu, run_owner_cpu) = {
            let irq = unsafe { crate::mm::save_irq_disable() };
            let scheduler = crate::sched::scheduler::scheduler();
            let mut releases = DeferredReleaseList::new();
            scheduler.lock();

            if scheduler.pending_cpu_for(tcb) == Some(this_cpu) {
                scheduler.process_pending_enqueue(&mut releases);
            }

            let running_cpu = scheduler.find_running_cpu(tcb);
            let pending_cpu = scheduler.pending_cpu_for(tcb);
            let run_owner_cpu = unsafe { (*tcb).run_owner() };
            scheduler.unlock();
            unsafe {
                scheduler.drain_release(&mut releases);
            }
            unsafe { crate::mm::restore_irq(irq) };
            (running_cpu, pending_cpu, run_owner_cpu)
        };

        if running_cpu.is_none() && run_owner_cpu.is_none() {
            return true;
        }

        if spins == 0 || (spins & 0x3ff) == 0 {
            if let Some(cpu) = running_cpu.or(pending_cpu).or(run_owner_cpu).or(cpu_hint) {
                if cpu != this_cpu {
                    unsafe {
                        crate::arch::send_ipi(cpu, crate::arch::IpiKind::Reschedule);
                    }
                }
            }
        }

        core::hint::spin_loop();
    }

    #[allow(unused_variables)]
    let (running_cpu, pending_cpu, run_owner_cpu, state, ready_queued, queued_cpu, sched_ref) = {
        let irq = unsafe { crate::mm::save_irq_disable() };
        let scheduler = crate::sched::scheduler::scheduler();
        scheduler.lock();
        let snapshot = (
            scheduler.find_running_cpu(tcb),
            scheduler.pending_cpu_for(tcb),
            unsafe { (*tcb).run_owner() },
            unsafe { (*tcb).state as u64 },
            unsafe { (*tcb).placement.ready_queued },
            unsafe { (*tcb).placement.queued_cpu as u64 },
            unsafe { (*tcb).sched_ref.load(Ordering::Acquire) as u64 },
        );
        scheduler.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        snapshot
    };
    crate::kernel::printk::kdebug!(sched, |_g| {
        _g.puts("[TCB_STOP] quiesce timeout tcb=");
        _g.hex(tcb as u64);
        _g.puts(" state=");
        _g.dec(state);
        _g.puts(" running_cpu=");
        match running_cpu {
            Some(cpu) => _g.dec(cpu as u64),
            None => _g.puts("none"),
        }
        _g.puts(" pending_cpu=");
        match pending_cpu {
            Some(cpu) => _g.dec(cpu as u64),
            None => _g.puts("none"),
        }
        _g.puts(" run_owner=");
        match run_owner_cpu {
            Some(cpu) => _g.dec(cpu as u64),
            None => _g.puts("none"),
        }
        _g.puts(" ready=");
        _g.dec(ready_queued as u64);
        _g.puts(" queued_cpu=");
        _g.dec(queued_cpu);
        _g.puts(" sched_ref=");
        _g.dec(sched_ref);
        _g.putc(b'\n');
    });

    false
}

/// Panicking wrapper around `wait_for_tcb_quiesced` for syscall
/// paths that cannot proceed past the quiesce point.
pub(crate) unsafe fn wait_for_tcb_quiesced_blocking(tcb: *mut Tcb, cpu_hint: Option<usize>) {
    if unsafe { wait_for_tcb_quiesced(tcb, cpu_hint) } {
        return;
    }

    panic!("[TCB_STOP] failed to quiesce tcb=0x{:x}", tcb as u64);
}

#[inline]
pub(crate) unsafe fn release_suspended_waiter(
    scheduler: &mut Scheduler,
    tcb: *mut Tcb,
    action: &SuspendAction,
) {
    if action.release_vspace_waiter {
        unsafe {
            scheduler.sched_ref_release_may_destroy(tcb);
        }
    }
}

#[inline]
pub(crate) fn cleanup_quiesced_thread(scheduler: &mut Scheduler, tcb: *mut Tcb) {
    scheduler.cancel_pending_enqueue(tcb);
    scheduler.remove_from_ready_queue(tcb);
}

#[inline]
pub(crate) unsafe fn finish_current_exit(
    scheduler: &mut Scheduler,
    tcb: *mut Tcb,
    action: &ExitAction,
) {
    if action.release_vspace_waiter {
        unsafe {
            scheduler.sched_ref_release_may_destroy(tcb);
        }
    }
    scheduler.reschedule();
}
