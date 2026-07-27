// SPDX-License-Identifier: GPL-2.0-only

use super::support::{checked_cpu_id, is_bootstrap_tcb};
use super::{DeferredReleaseList, Scheduler, Tcb};
use crate::task::state::ThreadState;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_context_saved(old_tcb: *mut Tcb) {
    if old_tcb.is_null() {
        return;
    }

    unsafe {
        (*old_tcb).clear_run_owner_cpu();
    }
}

impl Scheduler {
    #[inline]
    pub(crate) unsafe fn publish_switch_target_locked(
        &mut self,
        cpu_id: usize,
        old_tcb: *mut Tcb,
        new_tcb: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) {
        unsafe {
            if crate::sched::scheduler::debug_reply_wake_once(new_tcb, 2) {
                crate::kernel::printk::ktrace!(sched, |_g| {
                    _g.puts("[FORK_WAKE_PUBLISH] cpu=");
                    _g.dec(cpu_id as u64);
                    _g.puts(" old=");
                    _g.hex(old_tcb as u64);
                    _g.puts(" new=");
                    _g.hex(new_tcb as u64);
                    _g.puts(" pc=");
                    #[cfg(target_arch = "x86_64")]
                    {
                        _g.hex((*new_tcb).context.rip);
                        _g.puts(" sp=");
                        _g.hex((*new_tcb).context.rsp);
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        _g.hex(crate::arch::aarch64::context::resume_pc(
                            &(*new_tcb).context,
                        ));
                        _g.puts(" sp=");
                        _g.hex((*new_tcb).context.sp);
                        _g.puts(" user_sp=");
                        _g.hex((*new_tcb).context.user_sp);
                    }
                    _g.puts("\n");
                });
            }
            crate::task::wait::mark_runnable_locked(new_tcb);
            (*new_tcb).placement.last_cpu = cpu_id as u32;
            if !old_tcb.is_null() {
                self.publish_outgoing_before_current_flip_locked(cpu_id, old_tcb, releases);
            }
            self.set_current(new_tcb);
        }
    }

    /// Publish an outgoing current thread before another thread replaces it in
    /// `current[]`.
    ///
    /// This is only needed for paths that block the current thread (or
    /// otherwise remove it from the runnable set) and then switch directly to a
    /// different thread without first routing the old thread through
    /// `set_pending_enqueue()`.
    ///
    /// # Preconditions
    /// - Caller MUST hold the local scheduler lock.
    pub(crate) unsafe fn publish_outgoing_before_current_flip_locked(
        &mut self,
        cpu_id: usize,
        old_tcb: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) {
        unsafe {
            if old_tcb.is_null()
                || old_tcb == self.idle[cpu_id]
                || is_bootstrap_tcb(old_tcb)
                || (*old_tcb).placement.ready_queued
                || self.is_pending_on_any_cpu(old_tcb)
            {
                return;
            }

            self.validate_tcb_ptr(
                old_tcb,
                "publish_outgoing_before_current_flip_locked",
                cpu_id,
            );
            match (*old_tcb).state() {
                ThreadState::Runnable => {
                    self.set_pending_enqueue(cpu_id, old_tcb, releases);
                }
                ThreadState::Blocked
                | ThreadState::Stopped
                | ThreadState::Dying
                | ThreadState::Created
                | ThreadState::Configured => {
                    self.track_pending_switch_out(cpu_id, old_tcb, releases);
                }
            }
        }
    }

    #[inline]
    fn bump_context_switch_count(&mut self) {
        let cs_cpu = checked_cpu_id("bump_context_switch_count");
        self.context_switches[cs_cpu].fetch_add(1, core::sync::atomic::Ordering::Release);
    }

    #[inline]
    unsafe fn keep_running_on_idle_fallback_unlocked(
        &self,
        cpu_id: usize,
        current: *mut Tcb,
    ) -> bool {
        unsafe {
            if current.is_null() || current == self.idle[cpu_id] {
                return false;
            }

            let affinity = (*current).cpu_affinity;
            if affinity != 0xFFFF_FFFF && affinity as usize != cpu_id {
                return false;
            }

            self.select_target_cpu(current) == cpu_id
        }
    }

    #[inline]
    pub(super) unsafe fn try_cancel_pending_keep_current_on_idle_fallback_unlocked(
        &mut self,
        cpu_id: usize,
        current: *mut Tcb,
        new_tcb: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) -> bool {
        if new_tcb != self.idle[cpu_id]
            || !unsafe { self.keep_running_on_idle_fallback_unlocked(cpu_id, current) }
        {
            return false;
        }

        if self.pending_enqueue[cpu_id]
            .compare_exchange(
                current,
                core::ptr::null_mut(),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            // Cancel only our own deferred enqueue deposit. If a remote wake
            // already displaced `current` into the ready queue, the CAS fails
            // and the caller falls through to the normal switch/drain path.
            unsafe {
                releases.push(current);
                crate::task::wait::mark_runnable_locked(current);
            }
            return true;
        }

        false
    }

    #[inline]
    pub(super) unsafe fn restore_current_running_after_pending_cancel_unlocked(
        &mut self,
        cpu_id: usize,
        current: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) {
        if self.pending_enqueue[cpu_id]
            .compare_exchange(
                current,
                core::ptr::null_mut(),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            unsafe {
                releases.push(current);
            }
        }

        unsafe {
            if (*current).state() != ThreadState::Stopped {
                crate::task::wait::mark_runnable_locked(current);
            }
        }
    }

    /// Install the target thread's kernel stack into per-CPU entry state.
    ///
    /// This updates both the syscall-entry kernel stack cache (`GS:8`) and
    /// the TSS RSP0 used for privilege transitions.
    unsafe fn install_switch_kernel_stack(&self, new_tcb: *mut Tcb) {
        unsafe {
            if (*new_tcb).kernel_stack_top != 0 {
                crate::arch::set_kernel_stack((*new_tcb).kernel_stack_top);
                crate::arch::set_tss_rsp0((*new_tcb).kernel_stack_top);
            }
        }
    }

    /// Replace a just-published switch target with this CPU's idle thread.
    ///
    /// This is used when activation fails after `set_current(new_tcb)` already
    /// moved the target into the local current slot. The fallback clears the
    /// failed target's run-owner metadata, flips `current[]` to idle, and
    /// drops the extra scheduler slot reference outside the scheduler lock.
    unsafe fn fallback_failed_switch_target_to_idle(
        &mut self,
        failed_target: *mut Tcb,
    ) -> *mut Tcb {
        unsafe {
            // `set_current(new_tcb)` in the caller incremented
            // `new_tcb.sched_ref` for the current[] slot and saved the
            // preceding old TCB to `deferred_current_release`. That slot is
            // occupied, so the idle fallback cannot stash `new_tcb` there too.
            // Release `new_tcb`'s sched_ref and `run_owner_cpu` explicitly —
            // otherwise `wait_for_tcb_quiesced` on a cross-CPU suspend/destroy
            // would block forever on a slot that nobody else will clear.
            crate::task::stop::mark_stopped_locked(failed_target);

            self.lock();
            let cpu_id = checked_cpu_id("fallback_failed_switch_target_to_idle");
            let idle = self.idle[cpu_id];
            self.set_current(idle);
            (*failed_target).clear_run_owner_cpu();
            self.unlock();

            // CAP_LOCK ordering forbids the destroy path while the scheduler
            // lock is held — the release helper decrements `sched_ref` outside
            // the lock and queues reaper final cleanup only if this was the
            // last slot and the cap refcount had already hit 0.
            self.sched_ref_release_may_destroy(failed_target);

            // Idle has null vspace_root — VSpace switch will be skipped by the
            // caller, keeping the current CR3.
            idle
        }
    }

    /// Prepare a switch target for the normal scheduler path.
    ///
    /// Handles VSpace-switch failure by marking the target inactive and
    /// falling back to this CPU's idle thread, matching historical behavior.
    ///
    /// Returns the actual thread to switch to (possibly idle fallback).
    unsafe fn prepare_switch_target_full(&mut self, new_tcb: *mut Tcb) -> *mut Tcb {
        let mut new_tcb = new_tcb;

        unsafe {
            if !(*new_tcb).vspace_root.is_null() {
                let vspace = &*(*new_tcb).vspace_root;
                if !vspace.switch_to() {
                    new_tcb = self.fallback_failed_switch_target_to_idle(new_tcb);
                }
            }

            self.install_switch_kernel_stack(new_tcb);
        }

        new_tcb
    }

    /// Prepare a switch target for IPC fastpath.
    ///
    /// Fastpath already validated the receiver's basic invariants, so this
    /// path skips scheduler fallback logic in the common case. If activation
    /// fails (e.g. VSpace turned Dying concurrently), returns `false` so the
    /// caller can fall back to the checked path.
    unsafe fn prepare_switch_target_fast(&self, new_tcb: *mut Tcb) -> bool {
        unsafe {
            if (*new_tcb).vspace_root.is_null() || (*new_tcb).kernel_stack_top == 0 {
                return false;
            }

            let vspace = &*(*new_tcb).vspace_root;
            if !vspace.switch_to() {
                return false;
            }

            self.install_switch_kernel_stack(new_tcb);
        }

        true
    }

    /// Shared low-level switch sequence after the target thread is prepared.
    ///
    /// This is the delicate portion that must remain consistent across normal
    /// scheduler switches and IPC fastpath direct switches.
    ///
    /// Callers must enter with local IRQs disabled and only restore them from
    /// the resumed continuation after this function returns.
    unsafe fn switch_common(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        unsafe {
            let cpu_id = checked_cpu_id("switch_common");
            self.validate_tcb_ptr(old_tcb, "switch old_tcb", cpu_id);
            self.validate_switch_target_context(new_tcb);

            // Save outgoing thread's TLS base (FS_BASE MSR)
            (*old_tcb).tls_base = crate::arch::read_fs_base();

            // Eager FPU: save outgoing thread's state and restore incoming thread's
            // in one atomic step. After this returns, the new thread can issue FPU
            // instructions immediately and old_tcb's save area is in sync with the
            // hardware, ready for migration to another CPU.
            crate::arch::fpu::switch(old_tcb, new_tcb);

            // Restore incoming thread's TLS base (FS_BASE MSR).
            // Always write — 0 clears the previous thread's FS_BASE.
            crate::arch::write_fs_base((*new_tcb).tls_base);
            crate::arch::write_abi_tp_base((*new_tcb).abi_tp_base);

            // Update per-CPU canary cache to incoming thread's canary.
            crate::arch::set_per_cpu_canary((*new_tcb).stack_canary);

            // Pure register save/restore — no shared state accessed.
            // No global lock held during switch (IRQs disabled is sufficient).
            let old_ctx = &mut (*old_tcb).context as *mut _;
            let new_ctx = &(*new_tcb).context as *const _;
            crate::arch::context_switch(old_ctx, new_ctx, old_tcb);

            // This continuation runs only when `old_tcb` is scheduled again.
            // Flush any deferred enqueue work that was left parked while this
            // thread was switched out.
            if crate::sched::scheduler::debug_reply_wake_once(old_tcb, 3) {
                crate::kernel::printk::ktrace!(sched, |_g| {
                    _g.puts("[FORK_WAKE_CONT] before_lock tcb=");
                    _g.hex(old_tcb as u64);
                    _g.puts(" cpu=");
                    _g.dec(checked_cpu_id("switch_common_cont_trace") as u64);
                    _g.puts("\n");
                });
            }
            let mut releases = DeferredReleaseList::new();
            self.lock();
            if crate::sched::scheduler::debug_reply_wake_once(old_tcb, 4) {
                crate::kernel::printk::ktrace!(sched, |_g| {
                    _g.puts("[FORK_WAKE_CONT] got_lock tcb=");
                    _g.hex(old_tcb as u64);
                    _g.puts("\n");
                });
            }
            self.process_pending_enqueue(&mut releases);
            self.unlock();

            // Flush deferred sched_ref decrements (outside scheduler lock).
            // This may trigger deferred TCB destruction under CAP_LOCK in
            // the rare case where a TCB's last capability was deleted while
            // it was still referenced by the scheduler (current[] slot,
            // ready-queue slot, or pending_enqueue slot).
            self.flush_deferred_current_release();
            self.drain_release(&mut releases);
            if crate::sched::scheduler::debug_reply_wake_once(old_tcb, 5) {
                crate::kernel::printk::ktrace!(sched, |_g| {
                    _g.puts("[FORK_WAKE_CONT] done tcb=");
                    _g.hex(old_tcb as u64);
                    _g.puts("\n");
                });
            }
        }
    }

    /// Fastpath-specific switch path that shares the common register/TLS/FPU
    /// sequence but uses a lighter target-preparation step in the hot path.
    unsafe fn switch_common_fast(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        unsafe {
            if self.prepare_switch_target_fast(new_tcb) {
                self.switch_common(old_tcb, new_tcb);
            } else {
                // Fall back to the fully-checked preparation path on races.
                let prepared = self.prepare_switch_target_full(new_tcb);
                self.switch_common(old_tcb, prepared);
            }
        }
    }

    /// Fastpath wrapper for the scheduler's full context-switch path.
    ///
    /// IPC fastpath uses this to avoid duplicating switch machinery while still
    /// preserving a lighter-weight target-preparation path.
    ///
    /// # Preconditions
    /// - Scheduler lock (`lock_states` / per-CPU lock) MUST NOT be held.
    /// - No IPC core locks should be held (release before calling).
    /// - `set_current(new_tcb)` and thread state transitions were already done.
    /// - If `old_tcb` was not already routed through `set_pending_enqueue()`,
    ///   the caller MUST have published it via
    ///   `publish_outgoing_before_current_flip_locked()` before flipping
    ///   `current[]`.
    /// - Local IRQs MUST remain disabled across the switch; restore them only
    ///   after the resumed continuation returns from this call.
    pub(crate) unsafe fn do_context_switch_fastpath(
        &mut self,
        old_tcb: *mut Tcb,
        new_tcb: *mut Tcb,
    ) {
        unsafe {
            self.bump_context_switch_count();
            self.switch_common_fast(old_tcb, new_tcb);
        }
    }

    /// Perform the actual context switch (VSpace, kernel stack, registers).
    ///
    /// # Preconditions
    /// - Scheduler lock (`lock_states` / per-CPU lock) MUST NOT be held.
    /// - No IPC core locks should be held (release before calling).
    /// - `set_current(new_tcb)` and any thread state transitions were already
    ///   done.
    /// - If `old_tcb` was not already routed through `set_pending_enqueue()`,
    ///   the caller MUST have published it via
    ///   `publish_outgoing_before_current_flip_locked()` before flipping
    ///   `current[]`.
    /// - Local IRQs MUST remain disabled across the switch; restore them only
    ///   after the resumed continuation returns from this call.
    unsafe fn do_context_switch(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        unsafe {
            self.bump_context_switch_count();
            let prepared = self.prepare_switch_target_full(new_tcb);
            self.switch_common(old_tcb, prepared);
        }
    }

    /// Perform a context switch from timer/IPI path.
    ///
    /// Releases per-CPU scheduler lock, performs the context switch (no
    /// global lock needed — Zircon-style), then restores IRQ state.
    /// Caller must hold the per-CPU scheduler lock on entry.
    unsafe fn context_switch_local(
        &mut self,
        old_tcb: *mut Tcb,
        new_tcb: *mut Tcb,
        irq_flag: u64,
        releases: &mut DeferredReleaseList,
    ) {
        unsafe {
            self.unlock();
            // Drain any sched_ref releases staged during the locked
            // section BEFORE the switch: once `do_context_switch`
            // swaps register state, this thread's stack (and thus
            // `releases`) is suspended and only revisited when the
            // scheduler picks this thread again. Firing
            // `sched_ref_release_may_destroy` here keeps destruction
            // promptly serialized with the transition.
            self.drain_release(releases);
            self.do_context_switch(old_tcb, new_tcb);
            crate::mm::restore_irq(irq_flag);
        }
    }

    #[inline]
    unsafe fn switch_current_local_locked(
        &mut self,
        old_tcb: *mut Tcb,
        new_tcb: *mut Tcb,
        irq_flag: u64,
        releases: &mut DeferredReleaseList,
    ) {
        self.set_current(new_tcb);
        unsafe {
            self.context_switch_local(old_tcb, new_tcb, irq_flag, releases);
        }
    }

    #[inline]
    pub(crate) unsafe fn switch_if_changed_locked(
        &mut self,
        old_tcb: *mut Tcb,
        new_tcb: *mut Tcb,
        irq_flag: u64,
        releases: &mut DeferredReleaseList,
    ) -> bool {
        if old_tcb == new_tcb {
            return false;
        }

        unsafe {
            self.switch_current_local_locked(old_tcb, new_tcb, irq_flag, releases);
        }
        true
    }

    #[inline]
    pub(crate) unsafe fn finish_runnable_schedule_decision_locked(
        &mut self,
        cpu_id: usize,
        current: *mut Tcb,
        new_tcb: *mut Tcb,
        irq_flag: u64,
        releases: &mut DeferredReleaseList,
    ) -> bool {
        if unsafe {
            self.try_cancel_pending_keep_current_on_idle_fallback_unlocked(
                cpu_id, current, new_tcb, releases,
            )
        } {
            return false;
        }

        unsafe { self.switch_if_changed_locked(current, new_tcb, irq_flag, releases) }
    }
}
