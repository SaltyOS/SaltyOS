// SPDX-License-Identifier: GPL-2.0-only

use super::support::{checked_cpu_id, is_aligned_to, is_bootstrap_tcb, is_kernel_addr};
use super::{
    DeferredReleaseList, RUNTIME_MODE_KERNEL, SCHED_CLASS_FAIR, Scheduler, Tcb,
    global::{CURRENT_ON_CPU, current_on_cpu},
};
use crate::arch::MAX_CPUS;
use crate::cap::ObjectType;
use crate::task::state::ThreadState;
use core::sync::atomic::Ordering;

impl Scheduler {
    /// Current running thread (on calling CPU)
    pub fn current(&self) -> *mut Tcb {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.current[cpu_id]
    }

    /// Set current running thread (on calling CPU).
    ///
    /// Manages `sched_ref`: increments on the new TCB, saves the old TCB
    /// to `deferred_current_release` for later `sched_ref` decrement
    /// (done by `flush_deferred_current_release()` after lock release).
    ///
    /// Idempotent: if `current[cpu]` already equals `tcb`, this is a no-op.
    /// This handles the case where `schedule_unlocked()` already set
    /// `current[cpu]` and the caller calls `set_current` redundantly.
    pub fn set_current(&mut self, tcb: *mut Tcb) {
        let cpu_id = crate::arch::current_cpu() as usize;
        let old = self.current[cpu_id];

        if old == tcb {
            return;
        }

        let now_ns = crate::arch::now_ns();
        unsafe {
            self.account_current_runtime_unlocked(cpu_id, now_ns);
            self.account_current_observed_runtime_unlocked(cpu_id, now_ns);
            if !old.is_null()
                && old != self.idle[cpu_id]
                && !is_bootstrap_tcb(old)
                && (*old).sched_class == SCHED_CLASS_FAIR
                && (*old).state() != ThreadState::Runnable
            {
                self.fair_snapshot_lag_unlocked(cpu_id, old, old);
            }
            if !old.is_null() && old != self.idle[cpu_id] && !is_bootstrap_tcb(old) {
                (*old).runtime_mode = self.current_runtime_mode[cpu_id];
            }
        }

        self.current[cpu_id] = tcb;
        self.current_started_ns[cpu_id] = now_ns;
        self.current_observed_started_ns[cpu_id] = now_ns;
        unsafe {
            if !tcb.is_null() {
                (*tcb).set_run_owner_cpu(cpu_id);
            }
        }
        self.current_runtime_mode[cpu_id] = unsafe {
            if tcb.is_null() || tcb == self.idle[cpu_id] || is_bootstrap_tcb(tcb) {
                RUNTIME_MODE_KERNEL
            } else {
                (*tcb).runtime_mode
            }
        };
        CURRENT_ON_CPU[cpu_id].store(tcb as usize, Ordering::Release);

        // Increment sched_ref on new TCB (skip idle/bootstrap — static, never destroyed)
        if !tcb.is_null() && tcb != self.idle[cpu_id] && !is_bootstrap_tcb(tcb) {
            unsafe {
                (*tcb).sched_ref.fetch_add(1, Ordering::AcqRel);
            }
        }

        // Save old for deferred sched_ref decrement.
        // Only the first old per scheduling cycle matters — if the slot is
        // already occupied (shouldn't happen in practice since flush runs
        // between context switches), keep the first one.
        if !old.is_null()
            && old != self.idle[cpu_id]
            && !is_bootstrap_tcb(old)
            && self.deferred_current_release[cpu_id].is_null()
        {
            self.deferred_current_release[cpu_id] = old;
        }
    }

    /// Get idle thread for calling CPU
    pub fn get_idle(&self) -> *mut Tcb {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.idle[cpu_id]
    }

    /// Set idle thread for a specific CPU
    pub fn set_idle(&mut self, cpu_id: usize, tcb: *mut Tcb) {
        self.idle[cpu_id] = tcb;
    }

    /// Return the CPU that still owns this TCB's scheduler slot.
    ///
    /// Unlike `find_running_cpu()`, this intentionally trusts `run_owner_cpu`
    /// without requiring `CURRENT_ON_CPU[owner]` to still point at the TCB. The
    /// old current TCB remains CPU-owned after `set_current(new)` flips the
    /// current mirror and until `sched_context_saved(old)` clears this owner;
    /// a ready-queue consumer also claims the TCB before unlinking it so no
    /// observer can see it as both unqueued and unowned before `set_current`.
    ///
    /// Caller must have already validated `tcb`.
    pub(super) unsafe fn live_owner_cpu(
        &self,
        tcb: *mut Tcb,
        site: &'static str,
        observer_cpu: usize,
    ) -> Option<usize> {
        unsafe {
            let owner = (*tcb).run_owner()?;
            let online = self.online_cpus as usize;
            if owner >= online {
                panic!(
                    "[SCHED] {}: invalid run_owner_cpu={} for tcb=0x{:x} (online={} observer_cpu={})",
                    site, owner, tcb as u64, online, observer_cpu
                );
            }
            Some(owner)
        }
    }

    /// Find which CPU a thread is currently running on by scanning the atomic
    /// current pointer mirror.
    ///
    /// Checks `last_cpu` hint first for O(1) fast path, then falls back
    /// to scanning only online CPUs.
    /// Returns `None` if the thread is not the current thread on any CPU. This
    /// is a CURRENT_ON_CPU mirror query only; use `live_owner_cpu()` when the
    /// context-switch save window matters.
    ///
    /// The per-CPU `current[]` slots are protected by each CPU's own
    /// scheduler lock, so cross-CPU callers must use `CURRENT_ON_CPU`
    /// instead of directly reading remote slots while holding only the
    /// local CPU lock.
    pub fn find_running_cpu(&self, tcb: *mut Tcb) -> Option<usize> {
        if tcb.is_null() {
            return None;
        }

        let tcb_addr = tcb as usize;
        let online = self.online_cpus as usize;

        if let Some(owner) = unsafe { (*tcb).run_owner() } {
            if owner < online && current_on_cpu(owner) == tcb_addr {
                return Some(owner);
            }
        }

        // Fast path: check last_cpu hint first
        let last = unsafe { (*tcb).placement.last_cpu } as usize;
        if last < online && current_on_cpu(last) == tcb_addr {
            return Some(last);
        }
        for cpu in 0..online {
            if current_on_cpu(cpu) == tcb_addr {
                return Some(cpu);
            }
        }
        None
    }

    /// Validate a TCB pointer before dereferencing it in scheduler hot paths.
    ///
    /// These checks intentionally fail-fast on obviously corrupted pointers so
    /// we panic at the source instead of returning into random data later.
    pub(super) unsafe fn validate_tcb_ptr(&self, tcb: *mut Tcb, site: &'static str, cpu_id: usize) {
        let addr = tcb as u64;
        if tcb.is_null() {
            panic!("[SCHED] {}: null TCB pointer (cpu={})", site, cpu_id);
        }
        if !is_kernel_addr(addr) {
            panic!(
                "[SCHED] {}: non-kernel/non-canonical TCB pointer 0x{:x} (cpu={})",
                site, addr, cpu_id
            );
        }
        if !is_aligned_to::<Tcb>(addr) {
            panic!(
                "[SCHED] {}: misaligned TCB pointer 0x{:x} (align={} cpu={})",
                site,
                addr,
                core::mem::align_of::<Tcb>(),
                cpu_id
            );
        }
        let obj_type_raw = unsafe {
            core::ptr::addr_of!((*tcb).header.obj_type)
                .cast::<u8>()
                .read_unaligned()
        };
        if obj_type_raw != ObjectType::Tcb as u8 {
            panic!(
                "[SCHED] {}: bad TCB obj_type={} at 0x{:x} (cpu={})",
                site, obj_type_raw, addr, cpu_id
            );
        }
    }

    /// Validate the incoming target context before low-level register restore.
    ///
    /// `context_switch` assumes `new_tcb->context.rsp/rip` are valid kernel
    /// values and will `ret` to `rip`. If either is corrupt, stack/control-flow
    /// corruption propagates far from the source.
    pub(super) unsafe fn validate_switch_target_context(&self, new_tcb: *mut Tcb) {
        let cpu_id = checked_cpu_id("validate_switch_target_context");
        unsafe {
            self.validate_tcb_ptr(new_tcb, "switch target", cpu_id);

            #[cfg(target_arch = "x86_64")]
            let (resume_pc, stack_ptr) = ((*new_tcb).context.rip, (*new_tcb).context.rsp);
            #[cfg(target_arch = "aarch64")]
            let (resume_pc, stack_ptr) = (
                crate::arch::aarch64::context::resume_pc(&(*new_tcb).context),
                (*new_tcb).context.sp,
            );
            let kstack = (*new_tcb).kernel_stack_top;
            let text_start = core::ptr::addr_of!(super::_text_start) as u64;
            let text_end = core::ptr::addr_of!(super::_text_end) as u64;

            if kstack == 0 || !is_kernel_addr(kstack) || !is_aligned_to::<u64>(kstack) {
                panic!(
                    "[SCHED] switch target: bad kernel_stack_top=0x{:x} tcb=0x{:x} cpu={}",
                    kstack, new_tcb as u64, cpu_id
                );
            }

            if resume_pc < text_start || resume_pc >= text_end {
                panic!(
                    "[SCHED] switch target: resume_pc out of kernel .text pc=0x{:x} text=[0x{:x},0x{:x}) tcb=0x{:x} cpu={}",
                    resume_pc, text_start, text_end, new_tcb as u64, cpu_id
                );
            }
            if !is_kernel_addr(stack_ptr) || (stack_ptr & 0xF) != 0 {
                panic!(
                    "[SCHED] switch target: bad stack_ptr=0x{:x} (kernel={} align16={}) tcb=0x{:x} cpu={}",
                    stack_ptr,
                    is_kernel_addr(stack_ptr),
                    (stack_ptr & 0xF) == 0,
                    new_tcb as u64,
                    cpu_id
                );
            }
        }
    }

    /// Mark thread for deferred enqueue after context switch completes.
    ///
    /// Sets state to Ready but does NOT insert into the ready queue.
    /// The thread will be enqueued by `process_pending_enqueue()` after
    /// `context_switch` has saved its registers.
    ///
    /// If there is already a pending thread in the slot (e.g. from a
    /// previous switch to a fresh thread whose entry point never returned
    /// through `do_context_switch`), it is enqueued now before being
    /// overwritten.
    ///
    /// Caller MUST hold the scheduler lock.
    pub(super) fn set_pending_enqueue(
        &mut self,
        cpu_id: usize,
        tcb: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) {
        if cpu_id >= MAX_CPUS {
            panic!(
                "[SCHED] set_pending_enqueue: invalid cpu_id={} (max={})",
                cpu_id, MAX_CPUS
            );
        }
        if is_bootstrap_tcb(tcb) {
            unsafe {
                self.validate_tcb_ptr(tcb, "set_pending_enqueue bootstrap", cpu_id);
                crate::task::stop::mark_stopped_locked(tcb);
            }
            return;
        }

        unsafe {
            self.validate_tcb_ptr(tcb, "set_pending_enqueue new slot", cpu_id);
            // Cross-CPU TCB_STOP/terminate may already have marked this
            // thread non-runnable while the local CPU is still unwinding
            // toward a switch point. Never overwrite that back to Ready here.
            if matches!((*tcb).state(), ThreadState::Stopped | ThreadState::Dying) {
                return;
            }
            crate::task::wait::mark_runnable_locked(tcb);
            // Pending-slot takes ownership — inc before the atomic swap
            // so a concurrent release_object always observes a non-zero
            // sched_ref while the pointer lives in the slot.
            (*tcb).sched_ref_inc();
        }

        // Atomic swap: safely exchange with whatever the target CPU has
        // pending. This avoids the read-then-write race where the local
        // CPU's process_pending_enqueue could clear the slot between our
        // read and write.
        let old = self.pending_enqueue[cpu_id].swap(tcb, Ordering::AcqRel);

        if old == tcb {
            // The slot already published this exact TCB. The extra
            // sched_ref taken above does not correspond to a distinct
            // scheduler-owned slot, so release it after the caller drops
            // the scheduler lock.
            unsafe {
                releases.push(tcb);
            }
            return;
        }

        if !old.is_null() {
            unsafe {
                self.validate_tcb_ptr(old, "set_pending_enqueue displaced", cpu_id);
                if let Some(owner) =
                    self.live_owner_cpu(old, "set_pending_enqueue displaced", cpu_id)
                {
                    panic!(
                        "[SCHED] set_pending_enqueue: displaced pending tcb=0x{:x} still owned by cpu={}",
                        old as u64, owner
                    );
                }
                // Transfer the old TCB's pending-slot ref to the ready
                // queue (via enqueue_unlocked which re-incs for that
                // slot) and queue the pending-slot dec for post-unlock
                // release. If state is not Ready, just drop the pending
                // ref — the TCB was torn down concurrently.
                if (*old).state() == ThreadState::Runnable {
                    self.enqueue_unlocked(old, releases);
                }
                releases.push(old);
            }
        }
    }

    /// Track an outgoing thread in a non-Ready state (typically Blocked).
    ///
    /// This protects against a cross-CPU wake racing with `context_switch`:
    /// the waker may mark the thread Ready, but enqueue_unlocked() will defer
    /// the queue insertion until the pending slot is flushed after registers are
    /// safely saved.
    ///
    /// Caller MUST hold the scheduler lock.
    pub(crate) fn track_pending_switch_out(
        &mut self,
        cpu_id: usize,
        tcb: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) {
        if cpu_id >= MAX_CPUS {
            panic!(
                "[SCHED] track_pending_switch_out: invalid cpu_id={} (max={})",
                cpu_id, MAX_CPUS
            );
        }
        if is_bootstrap_tcb(tcb) {
            unsafe {
                self.validate_tcb_ptr(tcb, "track_pending_switch_out bootstrap", cpu_id);
                crate::task::stop::mark_stopped_locked(tcb);
            }
            return;
        }

        unsafe {
            self.validate_tcb_ptr(tcb, "track_pending_switch_out", cpu_id);
            // Same ownership rule as set_pending_enqueue: pending slot
            // takes a sched_ref before the swap.
            (*tcb).sched_ref_inc();
        }

        let old = self.pending_enqueue[cpu_id].swap(tcb, Ordering::AcqRel);
        if old == tcb {
            unsafe {
                releases.push(tcb);
            }
            return;
        }
        if !old.is_null() {
            unsafe {
                self.validate_tcb_ptr(old, "track_pending_switch_out stale slot", cpu_id);
                if let Some(owner) =
                    self.live_owner_cpu(old, "track_pending_switch_out stale slot", cpu_id)
                {
                    panic!(
                        "[SCHED] track_pending_switch_out: displaced pending tcb=0x{:x} still owned by cpu={}",
                        old as u64, owner
                    );
                }
                if (*old).state() == ThreadState::Runnable {
                    self.enqueue_unlocked(old, releases);
                }
                releases.push(old);
            }
        }
    }

    /// Returns true if a thread is present in any deferred-switch slot.
    ///
    /// Caller MUST hold the scheduler lock.
    pub(super) fn is_pending_on_any_cpu(&self, tcb: *mut Tcb) -> bool {
        self.pending_cpu_for(tcb).is_some()
    }

    /// Return the CPU whose deferred-switch slot currently references `tcb`.
    ///
    /// Caller MUST hold the scheduler lock.
    pub(crate) fn pending_cpu_for(&self, tcb: *mut Tcb) -> Option<usize> {
        let online = self.online_cpus as usize;
        for cpu in 0..online {
            if self.pending_enqueue[cpu].load(Ordering::Acquire) == tcb {
                return Some(cpu);
            }
        }
        None
    }

    /// Remove a thread from any deferred enqueue slot on any CPU.
    ///
    /// This is used by cross-CPU suspend/terminate after the target has been
    /// forced off-CPU. The thread may still be parked in a pending slot if the
    /// local CPU was unwinding through yield/preemption when suspend landed.
    pub fn cancel_pending_enqueue(&mut self, tcb: *mut Tcb) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        let online = self.online_cpus as usize;
        let mut cancelled_count: u32 = 0;
        for cpu in 0..online {
            if self.pending_enqueue[cpu]
                .compare_exchange(
                    tcb,
                    core::ptr::null_mut(),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                cancelled_count += 1;
            }
        }

        self.unlock();
        // `cancelled_count` pending slots each held their own sched_ref
        // on `tcb`. Release them directly outside the scheduler lock —
        // the intrusive `DeferredReleaseList` cannot hold the same TCB
        // twice, so multiple releases on one pointer cannot be batched
        // through the list and are fired one at a time here.
        unsafe {
            for _ in 0..cancelled_count {
                self.sched_ref_release_may_destroy(tcb);
            }
            crate::mm::restore_irq(irq_flag);
        }
    }

    /// Decrement `sched_ref` on `tcb` and, if the count hits zero while
    /// `pending_destroy` is set, hand the TCB to the reaper for final
    /// cleanup. Null-safe. Used by every post-unlock release path
    /// (current[] flush, ready-queue/pending-slot deferred flush,
    /// switch-target fallback cleanup).
    ///
    /// # Safety
    /// Must be called with scheduler lock NOT held — the CAP_LOCK
    /// acquisition would otherwise violate the lock ordering.
    pub(crate) unsafe fn sched_ref_release_may_destroy(&self, tcb: *mut Tcb) {
        if tcb.is_null() {
            return;
        }
        unsafe {
            let prev = (*tcb).sched_ref.fetch_sub(1, Ordering::AcqRel);
            if prev == 1 && (*tcb).pending_destroy.swap(false, Ordering::AcqRel) {
                crate::object::enqueue_reap(
                    tcb as *mut crate::cap::KernelObject,
                    crate::cap::ObjectType::Tcb,
                );
                crate::object::drain_reaper();
            }
        }
    }

    /// Flush deferred current[] release after scheduler lock is released.
    ///
    /// # Safety
    /// Must be called with scheduler lock NOT held.
    pub(crate) unsafe fn flush_deferred_current_release(&mut self) {
        let cpu_id = crate::arch::current_cpu() as usize;
        let old = self.deferred_current_release[cpu_id];
        if old.is_null() {
            return;
        }
        unsafe {
            self.validate_tcb_ptr(old, "flush_deferred_current_release", cpu_id);
            if self.live_owner_cpu(old, "flush_deferred_current_release", cpu_id) == Some(cpu_id) {
                return;
            }
        }
        self.deferred_current_release[cpu_id] = core::ptr::null_mut();
        unsafe {
            self.sched_ref_release_may_destroy(old);
        }
    }

    /// Drain a `DeferredReleaseList` accumulated during a scheduler
    /// critical section, firing `sched_ref_release_may_destroy` (and,
    /// transitively, reaper final cleanup under `CAP_LOCK`) for each
    /// pushed TCB.
    ///
    /// # Safety
    /// MUST be called with the scheduler lock NOT held. Each TCB on the
    /// list had its `sched_ref` incremented for a scheduler-owned slot
    /// whose release was deferred past the lock boundary; draining here
    /// is what actually performs the decrement and any destroy.
    pub(crate) unsafe fn drain_release(&self, releases: &mut DeferredReleaseList) {
        let mut cur = releases.head;
        let owner = releases.owner_cpu;
        releases.head = core::ptr::null_mut();
        while !cur.is_null() {
            // Snapshot the intrusive link and owed count, then clear
            // the TCB's list-membership fields BEFORE firing any
            // release: the final `sched_ref_release_may_destroy` may
            // trigger reaper final cleanup → `tcb.cleanup()`, which
            // must see a pristine `deferred_release_*` pair.
            let next = unsafe { (*cur).deferred_release_next[owner] };
            let count = unsafe { (*cur).deferred_release_count[owner] };
            unsafe {
                (*cur).deferred_release_next[owner] = core::ptr::null_mut();
                (*cur).deferred_release_count[owner] = 0;
            }
            for _ in 0..count {
                unsafe {
                    self.sched_ref_release_may_destroy(cur);
                }
            }
            cur = next;
        }
    }

    /// Process deferred enqueue after context switch.
    ///
    /// If there is a pending thread and its state is still Ready
    /// (guards against TCB_STOP setting Inactive), enqueue it.
    /// Clears the pending slot.
    ///
    /// Caller MUST hold the scheduler lock.
    pub(crate) fn process_pending_enqueue(&mut self, releases: &mut DeferredReleaseList) {
        let cpu_id = checked_cpu_id("process_pending_enqueue");
        // Atomic swap: take ownership of the slot so a concurrent
        // set_pending_enqueue on another CPU cannot race with our read.
        let tcb = self.pending_enqueue[cpu_id].swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !tcb.is_null() {
            unsafe {
                self.validate_tcb_ptr(tcb, "process_pending_enqueue", cpu_id);
                if let Some(owner) = self.live_owner_cpu(tcb, "process_pending_enqueue", cpu_id) {
                    if owner == cpu_id {
                        if self.pending_enqueue[cpu_id]
                            .compare_exchange(
                                core::ptr::null_mut(),
                                tcb,
                                Ordering::AcqRel,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                        {
                            return;
                        }
                    }
                    panic!(
                        "[SCHED] process_pending_enqueue: pending tcb=0x{:x} still owned by cpu={} while processing cpu={}",
                        tcb as u64, owner, cpu_id
                    );
                }
                if (*tcb).state() == ThreadState::Runnable {
                    // Transfer the pending-slot sched_ref into a
                    // ready-queue slot: enqueue_unlocked increments
                    // for the new slot, and we queue the old pending
                    // ref for post-unlock release.
                    self.enqueue_unlocked(tcb, releases);
                }
                // Whether or not we re-enqueued (state could be
                // Inactive from a concurrent TCB_STOP), the pending
                // slot's sched_ref must be released.
                releases.push(tcb);
            }
        }
    }
}
