// SPDX-License-Identifier: GPL-2.0-only

use super::{Scheduler, Tcb};

impl Scheduler {
    /// Replenish budget for a Deadline-class thread whose budget expired.
    ///
    /// Advances deadline, updates priority, and replenishes budget.
    /// Does NOT enqueue the thread — caller must use `set_pending_enqueue()`.
    ///
    /// Caller MUST hold the scheduler lock.
    pub(super) fn replenish_budget_unlocked(&mut self, tcb: *mut Tcb) {
        unsafe {
            let sched_ctx = (*tcb).sched_context;
            if sched_ctx.is_null() {
                return;
            }

            if (*sched_ctx).period > 0 {
                // Periodic: move the absolute deadline to the next release.
                let now_ns = crate::arch::now_ns();
                let mut deadline = (*sched_ctx).deadline.saturating_add((*sched_ctx).period);
                if deadline <= now_ns {
                    let late = now_ns.saturating_sub(deadline);
                    let periods_missed = late / (*sched_ctx).period + 1;
                    deadline =
                        deadline.saturating_add((*sched_ctx).period.saturating_mul(periods_missed));
                }
                (*sched_ctx).deadline = deadline;
            } else {
                // Sporadic: move to lowest EDF priority
                (*sched_ctx).deadline = u64::MAX;
            }

            // Update base priority (unaffected by PIP)
            (*tcb).base_priority = Tcb::encode_deadline_priority((*sched_ctx).deadline);

            // Update effective priority only if no active PIP donation
            if (*tcb).pip_donation_count == 0 {
                (*tcb).priority = (*tcb).base_priority;
            }

            // Replenish budget
            (*sched_ctx).remaining = (*sched_ctx).budget;
        }
    }

    /// Periodic rebalancing: check if any CPU is running a lower-ranked
    /// thread while the ready queue has a higher-ranked compatible thread.
    ///
    /// Returns a bitmask of CPUs that should receive a reschedule IPI.
    /// IPIs are sent AFTER the scheduler lock is released to avoid
    /// deadlocks (target CPU spins on lock in IPI handler).
    ///
    /// Caller MUST hold the local CPU scheduler lock. Remote CPU queues are
    /// inspected only while that CPU's scheduler lock is held.
    pub(super) fn try_rebalance(&mut self) -> u32 {
        let mut ipi_mask: u32 = 0;
        let this_cpu = crate::arch::current_cpu() as usize;
        let online = self.online_cpus as usize;

        // O(online_cpus): for each remote CPU, check if its best queued
        // thread outranks the currently running thread on that CPU.
        for cpu in 0..online {
            if cpu == this_cpu {
                continue; // this CPU handles its own preemption
            }

            // Keep per-CPU scheduler lock acquisition monotonic with the
            // enqueue path. Today this runs from BSP only, but this guard
            // prevents a future non-BSP caller from taking a lower CPU lock
            // while holding its local one.
            if cpu < this_cpu {
                continue;
            }

            self.lock_cpu(cpu);
            let running = self.current[cpu];
            let head = unsafe { self.peek_best_ready_unlocked(cpu, running) };

            if running.is_null() || running == self.idle[cpu] {
                // Idle CPU — if it has work queued, wake it
                if !head.is_null() {
                    ipi_mask |= 1 << cpu;
                }
                self.unlock_cpu(cpu);
                continue;
            }

            if !head.is_null() {
                unsafe {
                    if self.should_preempt_tcb(cpu, head, running) {
                        ipi_mask |= 1 << cpu;
                    }
                }
            }
            self.unlock_cpu(cpu);
        }

        ipi_mask
    }
}
