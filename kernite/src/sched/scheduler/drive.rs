// SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::Ordering;

use super::support::{checked_cpu_id, is_bootstrap_tcb};
use super::{
    DeferredReleaseList, RUNTIME_MODE_KERNEL, RUNTIME_MODE_USER, SCHED_CLASS_DEADLINE,
    SCHED_CLASS_FAIR, SCHED_CLASS_IDLE, SCHED_CLASS_RT_FIFO, Scheduler,
};
use crate::task::state::ThreadState;

impl Scheduler {
    /// Handle timer tick — called from interrupt context.
    ///
    /// Uses a lock-free next-deadline hint to skip the sleep-queue slowpath on
    /// most ticks, and only acquires the per-CPU scheduler lock after wakeup
    /// processing has finished. Entry/exit hooks already attribute user/kernel
    /// runtime windows, so the interrupt-mode hint is retained only for the
    /// architecture-facing call shape.
    pub fn timer_tick(&mut self, _interrupted_user_mode: bool) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let now_ns = crate::arch::now_ns();

        if crate::sched::deadline_queue::peek_expired(now_ns) {
            crate::sched::deadline_queue::check_wakeups(now_ns);
        }

        let mut releases = DeferredReleaseList::new();
        self.lock();

        // Flush any deferred enqueue left over from a previous switch to a
        // fresh thread whose entry point never returned through do_context_switch.
        self.process_pending_enqueue(&mut releases);

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];

            // Count timer ticks on this CPU
            self.timer_ticks[cpu_id].fetch_add(1, Ordering::Release);

            if current.is_null() {
                self.unlock();
                self.drain_release(&mut releases);
                crate::mm::restore_irq(irq_flag);
                return;
            }

            let _ = self.account_current_runtime_unlocked(cpu_id, now_ns);
            let _ = self.account_current_observed_runtime_unlocked(cpu_id, now_ns);

            if is_bootstrap_tcb(current) {
                self.unlock();
                self.drain_release(&mut releases);
                crate::mm::restore_irq(irq_flag);
                return;
            }

            match (*current).sched_class {
                SCHED_CLASS_IDLE => {
                    let new_tcb = self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                    if self.switch_if_changed_locked(current, new_tcb, irq_flag, &mut releases) {
                        return;
                    }
                    self.unlock();
                    self.drain_release(&mut releases);
                    crate::mm::restore_irq(irq_flag);
                    return;
                }
                SCHED_CLASS_FAIR => {
                    let slice_expired = (*current).fair_entity_slice_expired();

                    if slice_expired {
                        if (*current).state() == ThreadState::Stopped {
                            let new_tcb =
                                self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                            if self.switch_if_changed_locked(
                                current,
                                new_tcb,
                                irq_flag,
                                &mut releases,
                            ) {
                                return;
                            }
                        } else {
                            (*current).reset_fair_slice();
                            self.set_pending_enqueue(cpu_id, current, &mut releases);
                            let new_tcb =
                                self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                            if self.finish_runnable_schedule_decision_locked(
                                cpu_id,
                                current,
                                new_tcb,
                                irq_flag,
                                &mut releases,
                            ) {
                                return;
                            }
                        }
                    } else if self.needs_reschedule() {
                        if (*current).state() != ThreadState::Stopped {
                            self.set_pending_enqueue(cpu_id, current, &mut releases);
                        }
                        let new_tcb = self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                        if self.finish_runnable_schedule_decision_locked(
                            cpu_id,
                            current,
                            new_tcb,
                            irq_flag,
                            &mut releases,
                        ) {
                            return;
                        }
                    }
                }
                SCHED_CLASS_RT_FIFO => {
                    if self.needs_reschedule() {
                        if (*current).state() != ThreadState::Stopped {
                            self.set_pending_enqueue(cpu_id, current, &mut releases);
                        }
                        let new_tcb = self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                        if self.finish_runnable_schedule_decision_locked(
                            cpu_id,
                            current,
                            new_tcb,
                            irq_flag,
                            &mut releases,
                        ) {
                            return;
                        }
                    }
                }
                SCHED_CLASS_DEADLINE => {
                    let sched_ctx = (*current).sched_context;
                    if sched_ctx.is_null() {
                        if self.needs_reschedule() {
                            if (*current).state() != ThreadState::Stopped {
                                self.set_pending_enqueue(cpu_id, current, &mut releases);
                            }
                            let new_tcb =
                                self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                            if self.finish_runnable_schedule_decision_locked(
                                cpu_id,
                                current,
                                new_tcb,
                                irq_flag,
                                &mut releases,
                            ) {
                                return;
                            }
                        }
                    } else if (*current).deadline_entity_needs_replenish() {
                        if (*current).state() == ThreadState::Stopped {
                            let new_tcb =
                                self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                            if self.switch_if_changed_locked(
                                current,
                                new_tcb,
                                irq_flag,
                                &mut releases,
                            ) {
                                return;
                            }
                        } else {
                            self.replenish_budget_unlocked(current);
                            self.set_pending_enqueue(cpu_id, current, &mut releases);
                            let new_tcb =
                                self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                            if self.finish_runnable_schedule_decision_locked(
                                cpu_id,
                                current,
                                new_tcb,
                                irq_flag,
                                &mut releases,
                            ) {
                                return;
                            }
                        }
                    } else {
                        (*current).recompute_sched_key();
                        if self.needs_reschedule() {
                            if (*current).state() != ThreadState::Stopped {
                                self.set_pending_enqueue(cpu_id, current, &mut releases);
                            }
                            let new_tcb =
                                self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
                            if self.finish_runnable_schedule_decision_locked(
                                cpu_id,
                                current,
                                new_tcb,
                                irq_flag,
                                &mut releases,
                            ) {
                                return;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Periodic load balancing: BSP checks every 100 ticks (~100ms)
        let cpu_id = crate::arch::current_cpu() as usize;
        let rebalance_ipi_mask = if cpu_id == 0 {
            self.rebalance_counter += 1;
            if self.rebalance_counter >= 100 {
                self.rebalance_counter = 0;
                self.try_rebalance()
            } else {
                0
            }
        } else {
            0
        };

        self.unlock();
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }

        // Send rebalance IPIs AFTER releasing lock to prevent deadlock
        if rebalance_ipi_mask != 0 {
            let online = self.online_cpus as usize;
            for cpu in 0..online {
                if rebalance_ipi_mask & (1 << cpu) != 0 {
                    unsafe {
                        crate::arch::send_ipi(cpu, crate::arch::IpiKind::Reschedule);
                    }
                }
            }
        }
    }

    /// Account the current thread's elapsed runtime and mark the local CPU as
    /// executing in kernel mode.
    ///
    /// Called from architecture entry paths with local IRQs already masked.
    pub unsafe fn runtime_enter_kernel_local(&mut self) {
        unsafe {
            // A first-dispatch thread resumes at its entry point, not at
            // `switch_common()`'s post-switch continuation, so the previous
            // current[] slot may still be awaiting release when this CPU next
            // enters the kernel.
            self.flush_deferred_current_release();
            let cpu_id = checked_cpu_id("runtime_enter_kernel_local");
            let now_ns = crate::arch::now_ns();
            self.account_current_observed_runtime_unlocked(cpu_id, now_ns);
            self.set_runtime_mode_unlocked(cpu_id, RUNTIME_MODE_KERNEL);
            self.current_observed_started_ns[cpu_id] = now_ns;
        }
    }

    /// Account the current thread's elapsed runtime and mark the local CPU as
    /// executing in user mode.
    ///
    /// Called from architecture return-to-user paths immediately before the
    /// final `sysret` / `iret` / `eret`.
    pub unsafe fn runtime_exit_to_user_local(&mut self) {
        unsafe {
            let cpu_id = checked_cpu_id("runtime_exit_to_user_local");
            let now_ns = crate::arch::now_ns();
            self.account_current_observed_runtime_unlocked(cpu_id, now_ns);
            self.set_runtime_mode_unlocked(cpu_id, RUNTIME_MODE_USER);
            self.current_observed_started_ns[cpu_id] = now_ns;
        }
    }

    /// Handle reschedule IPI — checks ready queue for work on this CPU.
    ///
    /// No global lock needed — operates entirely with per-CPU scheduler lock.
    pub fn handle_reschedule_ipi(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        self.lock();

        // Flush any deferred enqueue left over from a previous switch to a
        // fresh thread whose entry point never returned through do_context_switch.
        self.process_pending_enqueue(&mut releases);

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            self.ipi_reschedules[cpu_id].fetch_add(1, Ordering::Release);
            let current = self.current[cpu_id];
            if current.is_null() {
                self.unlock();
                self.drain_release(&mut releases);
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Deferred enqueue: mark Ready but don't insert into queue yet.
            // The Running check prevents re-enqueuing Inactive threads that were
            // suspended by a cross-CPU TCB_STOP + IPI.
            if current != self.idle[cpu_id] && (*current).state() == ThreadState::Runnable {
                self.set_pending_enqueue(cpu_id, current, &mut releases);
            }

            let new_tcb = self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
            if self.finish_runnable_schedule_decision_locked(
                cpu_id,
                current,
                new_tcb,
                irq_flag,
                &mut releases,
            ) {
                return;
            }
        }

        self.unlock();
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }
    }

    // ---------------------------------------------------------------
    // Reschedule (acquires lock, then drops before context switch)
    // ---------------------------------------------------------------

    /// Perform a context switch to the next thread.
    ///
    /// No global lock required — uses only per-CPU scheduler locks.
    /// Callers must NOT hold any IPC core lock across this call
    /// (release before calling, reacquire after if needed).
    ///
    /// Acquires the scheduler lock internally for the scheduling decision.
    pub fn reschedule(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        self.lock();

        // Flush any deferred enqueue left over from a previous switch to a
        // fresh thread whose entry point never returned through do_context_switch.
        self.process_pending_enqueue(&mut releases);

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let old_tcb = self.current[cpu_id];
            if !old_tcb.is_null() && old_tcb != self.idle[cpu_id] {
                match (*old_tcb).state() {
                    ThreadState::Runnable => {
                        self.set_pending_enqueue(cpu_id, old_tcb, &mut releases)
                    }
                    ThreadState::Stopped
                    | ThreadState::Blocked
                    | ThreadState::Dying
                    | ThreadState::Created
                    | ThreadState::Configured => {
                        self.track_pending_switch_out(cpu_id, old_tcb, &mut releases)
                    }
                }
            }
            let new_tcb = self.schedule_unlocked(core::ptr::null_mut(), &mut releases);

            if self.switch_if_changed_locked(old_tcb, new_tcb, irq_flag, &mut releases) {
                return;
            }
        }

        self.unlock();
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }
    }

    // ---------------------------------------------------------------
    // Yield (acquires lock, deferred enqueue before context switch)
    // ---------------------------------------------------------------

    /// Yield the current thread to the scheduler.
    ///
    /// Uses deferred enqueue to prevent double-schedule race on SMP:
    /// the current thread is NOT inserted into the ready queue until
    /// `context_switch` has saved its registers.
    ///
    /// No global lock required — uses only per-CPU scheduler locks.
    pub fn yield_current(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];
            if current.is_null() || current == self.idle[cpu_id] {
                self.unlock();
                self.drain_release(&mut releases);
                crate::mm::restore_irq(irq_flag);
                return;
            }

            if (*current).state() != ThreadState::Stopped {
                self.set_pending_enqueue(cpu_id, current, &mut releases);
            }

            let new_tcb = self.schedule_unlocked(core::ptr::null_mut(), &mut releases);
            if self.finish_runnable_schedule_decision_locked(
                cpu_id,
                current,
                new_tcb,
                irq_flag,
                &mut releases,
            ) {
                return;
            }
        }

        self.unlock();
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }
    }

    // ---------------------------------------------------------------
    // Kernel exit epilogue
    // ---------------------------------------------------------------

    /// Kernel exit epilogue - MUST be called from ALL kernel exit points
    ///
    /// Returns any VSpace that just became inactive so the caller can
    /// run the lock-free wake phase after releasing the scheduler lock
    /// (`tcb_lock > scheduler.lock_state` ordering).
    ///
    /// # Safety
    /// Must be called with scheduler lock held and IRQs disabled.
    fn kernel_exit_epilogue(&mut self) -> *const crate::mm::VSpaceTracking {
        self.process_pending_deactivates()
    }

    /// Process pending deactivates (internal, called by kernel_exit_epilogue).
    ///
    /// Returns the tracking pointer of a VSpace that just became
    /// inactive (or null). The caller runs
    /// `finish_deactivate_wake(tracking)` after releasing the
    /// scheduler lock.
    ///
    /// CRITICAL: Must be called with scheduler lock held and IRQs disabled!
    fn process_pending_deactivates(&mut self) -> *const crate::mm::VSpaceTracking {
        let cpu_id = crate::arch::current_cpu() as usize;

        let inactive = unsafe {
            let old_tracking = crate::mm::take_pending_deactivate(cpu_id);

            if !old_tracking.is_null() {
                match (*old_tracking).deactivate_nosched(cpu_id) {
                    crate::mm::DeactivateResult::BecameInactive => {
                        old_tracking as *const crate::mm::VSpaceTracking
                    }
                    _ => core::ptr::null(),
                }
            } else {
                core::ptr::null()
            }
        };

        // Always advance quiescent generation - we passed a safe point
        crate::mm::advance_quiescent_gen(cpu_id);
        inactive
    }

    /// Execute closure with scheduler lock held and IRQs disabled
    ///
    /// **IMPORTANT**: Use this ONLY for operations that do NOT block/switch!
    /// For blocking operations like VSpace wait, use `block_current_on_vspace()` instead.
    ///
    /// Automatically calls `kernel_exit_epilogue()` to collect any
    /// VSpace that just became inactive; the wake runs AFTER the
    /// scheduler lock is released so `tcb_lock` can be taken per
    /// waiter without violating the `tcb_lock > scheduler.lock_state`
    /// ordering.
    pub fn with_lock<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Scheduler) -> R,
    {
        // Save interrupt flag and disable IRQs
        let irq_flag = unsafe { crate::mm::save_irq_disable() };

        // Take scheduler lock
        self.lock();

        // Observe any pending deactivate's "became inactive" transition;
        // the actual waiter wake runs after unlock.
        let inactive_tracking = self.kernel_exit_epilogue();

        let result = f(self);

        // Release scheduler lock
        self.unlock();

        // Wake inactive VSpace waiters outside scheduler lock.
        if !inactive_tracking.is_null() {
            unsafe {
                self.finish_deactivate_wake(&*inactive_tracking);
            }
        }

        // Restore interrupt flag
        unsafe { crate::mm::restore_irq(irq_flag) };

        result
    }
}
