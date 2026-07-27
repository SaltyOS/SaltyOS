// SPDX-License-Identifier: GPL-2.0-only

use super::support::is_bootstrap_tcb;
use super::{RUNTIME_MODE_USER, SCHED_CLASS_DEADLINE, SCHED_CLASS_FAIR, Scheduler};
use core::sync::atomic::Ordering;

impl Scheduler {
    #[inline]
    unsafe fn account_running_fair_runtime_unlocked(
        &mut self,
        cpu: usize,
        current: *mut crate::sched::thread::Tcb,
        delta_ns: u64,
    ) {
        unsafe {
            let _ = (*current).advance_fair_vruntime(delta_ns);
            self.fair_refresh_min_vruntime_unlocked(cpu);
            // The current Fair entity is not in the ready tree. Rebuild its
            // encoded key when it is enqueued again, after any slice refill.
        }
    }

    #[inline]
    unsafe fn account_running_deadline_runtime_unlocked(
        &mut self,
        current: *mut crate::sched::thread::Tcb,
        delta_ns: u64,
    ) {
        unsafe {
            let sched_ctx = (*current).sched_context;
            if !sched_ctx.is_null() {
                (*sched_ctx).consumed = (*sched_ctx).consumed.saturating_add(delta_ns);
                (*sched_ctx).remaining = (*sched_ctx).remaining.saturating_sub(delta_ns);
                (*current).recompute_sched_key();
            }
        }
    }

    /// Lock a specific CPU's scheduler queue.
    #[inline]
    #[track_caller]
    pub(crate) fn lock_cpu(&self, cpu: usize) {
        let loc = core::panic::Location::caller();
        if self.lock_states[cpu]
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.lock_cpu_acquired_loc[cpu].store(loc as *const _ as usize, Ordering::Relaxed);
            return;
        }
        self.lock_cpu_contended(cpu, loc);
    }

    #[inline(never)]
    #[cold]
    fn lock_cpu_contended(&self, cpu: usize, loc: &'static core::panic::Location<'static>) {
        let mut backoff: u32 = 0;
        let mut total_spins: u64 = 0;
        let contender_since = crate::arch::now_ns();
        loop {
            let spins = 1u32 << backoff.min(6);
            for _ in 0..spins {
                core::hint::spin_loop();
            }
            total_spins = total_spins.saturating_add(spins as u64);
            if total_spins > crate::mm::SPINLOCK_HARD_TIMEOUT_SPINS {
                crate::mm::spinlock_hard_timeout_panic(
                    "scheduler.lock_cpu",
                    &self.lock_states[cpu] as *const _ as usize,
                    loc,
                    self.lock_cpu_acquired_loc[cpu].load(Ordering::Relaxed),
                    cpu as u64,
                    u64::MAX,
                    crate::arch::now_ns().saturating_sub(contender_since),
                );
            }

            if self.lock_states[cpu].load(Ordering::Relaxed) == 0
                && self.lock_states[cpu]
                    .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                self.lock_cpu_acquired_loc[cpu].store(loc as *const _ as usize, Ordering::Relaxed);
                return;
            }

            if backoff < 6 {
                backoff += 1;
            }
        }
    }

    /// Unlock a specific CPU's scheduler queue.
    pub(crate) fn unlock_cpu(&self, cpu: usize) {
        self.lock_states[cpu].store(0, core::sync::atomic::Ordering::Release);
    }

    /// Take the local CPU's scheduler lock.
    #[inline]
    #[track_caller]
    pub(crate) fn lock(&self) {
        self.lock_cpu(crate::arch::current_cpu() as usize);
    }

    /// Release the local CPU's scheduler lock.
    pub(crate) fn unlock(&self) {
        self.unlock_cpu(crate::arch::current_cpu() as usize);
    }

    #[inline]
    pub(super) unsafe fn account_current_runtime_unlocked(
        &mut self,
        cpu: usize,
        now_ns: u64,
    ) -> u64 {
        unsafe {
            let current = self.current[cpu];
            if current.is_null() {
                self.current_started_ns[cpu] = now_ns;
                return 0;
            }

            let started_ns = self.current_started_ns[cpu];
            if started_ns == 0 || now_ns <= started_ns {
                self.current_started_ns[cpu] = now_ns;
                return 0;
            }

            let delta_ns = now_ns - started_ns;
            self.current_started_ns[cpu] = now_ns;

            if current == self.idle[cpu] || is_bootstrap_tcb(current) {
                return delta_ns;
            }

            match (*current).sched_class {
                SCHED_CLASS_FAIR => {
                    self.account_running_fair_runtime_unlocked(cpu, current, delta_ns);
                }
                SCHED_CLASS_DEADLINE => {
                    self.account_running_deadline_runtime_unlocked(current, delta_ns);
                }
                _ => {}
            }

            delta_ns
        }
    }

    #[inline]
    pub(super) unsafe fn account_current_observed_runtime_unlocked(
        &mut self,
        cpu: usize,
        now_ns: u64,
    ) -> u64 {
        unsafe {
            let current = self.current[cpu];
            if current.is_null() {
                self.current_observed_started_ns[cpu] = now_ns;
                return 0;
            }

            let started_ns = self.current_observed_started_ns[cpu];
            if started_ns == 0 || now_ns <= started_ns {
                self.current_observed_started_ns[cpu] = now_ns;
                return 0;
            }

            let delta_ns = now_ns - started_ns;
            self.current_observed_started_ns[cpu] = now_ns;

            if current == self.idle[cpu] {
                self.idle_runtime_ns[cpu].fetch_add(delta_ns, Ordering::Release);
                return delta_ns;
            }

            if is_bootstrap_tcb(current) {
                return delta_ns;
            }

            if self.current_runtime_mode[cpu] == RUNTIME_MODE_USER {
                (*current)
                    .user_runtime_ns
                    .fetch_add(delta_ns, Ordering::Release);
                self.per_cpu_user_runtime_ns[cpu].fetch_add(delta_ns, Ordering::Release);
            } else {
                (*current)
                    .system_runtime_ns
                    .fetch_add(delta_ns, Ordering::Release);
                self.per_cpu_system_runtime_ns[cpu].fetch_add(delta_ns, Ordering::Release);
            }

            delta_ns
        }
    }

    #[inline]
    pub(super) unsafe fn set_runtime_mode_unlocked(&mut self, cpu: usize, mode: u8) {
        unsafe {
            self.current_runtime_mode[cpu] = mode;
            let current = self.current[cpu];
            if !current.is_null() && current != self.idle[cpu] && !is_bootstrap_tcb(current) {
                (*current).runtime_mode = mode;
            }
        }
    }
}
