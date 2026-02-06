//! EDF Scheduler
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::thread::{BlockedReason, Tcb, ThreadState};
use crate::arch::MAX_CPUS;

/// EDF Scheduler
pub struct Scheduler {
    /// Ready queue head (sorted by deadline)
    ready_head: *mut Tcb,
    /// Per-CPU currently running thread
    current: [*mut Tcb; MAX_CPUS],
    /// Per-CPU idle thread
    idle: [*mut Tcb; MAX_CPUS],
    /// Lock state (simple test-and-set spinlock)
    lock_state: core::sync::atomic::AtomicU8,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            ready_head: core::ptr::null_mut(),
            current: [core::ptr::null_mut(); MAX_CPUS],
            idle: [core::ptr::null_mut(); MAX_CPUS],
            lock_state: core::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Take scheduler lock
    fn lock(&self) {
        use core::sync::atomic::Ordering;
        while self
            .lock_state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    /// Release scheduler lock
    fn unlock(&self) {
        self.lock_state
            .store(0, core::sync::atomic::Ordering::Release);
    }

    // ---------------------------------------------------------------
    // Unlocked queue operations (caller must hold lock + IRQs disabled)
    // ---------------------------------------------------------------

    /// Add thread to ready queue (sorted by deadline) — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn enqueue_unlocked(&mut self, tcb: *mut Tcb) {
        unsafe {
            (*tcb).state = ThreadState::Ready;

            // Insert sorted by deadline (priority field stores deadline)
            if self.ready_head.is_null() || (*tcb).priority < (*self.ready_head).priority {
                (*tcb).next = self.ready_head;
                self.ready_head = tcb;
            } else {
                let mut current = self.ready_head;
                while !(*current).next.is_null() && (*(*current).next).priority <= (*tcb).priority {
                    current = (*current).next;
                }
                (*tcb).next = (*current).next;
                (*current).next = tcb;
            }

            // If thread has specific CPU affinity, check if target CPU needs waking
            let affinity = (*tcb).cpu_affinity;
            if affinity != 0xFFFF_FFFF {
                let target = affinity as usize;
                let this_cpu = crate::arch::current_cpu() as usize;
                if target != this_cpu
                    && target < MAX_CPUS
                    && !self.idle[target].is_null()
                    && self.current[target] == self.idle[target]
                {
                    crate::arch::send_ipi(
                        target,
                        crate::arch::IpiKind::Reschedule,
                    );
                }
            }
        }
    }

    /// Remove highest priority (earliest deadline) thread — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn dequeue_unlocked(&mut self) -> Option<*mut Tcb> {
        if self.ready_head.is_null() {
            None
        } else {
            unsafe {
                let tcb = self.ready_head;
                self.ready_head = (*tcb).next;
                (*tcb).next = core::ptr::null_mut();
                Some(tcb)
            }
        }
    }

    /// Remove highest priority thread for a CPU — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn dequeue_for_cpu_unlocked(&mut self, cpu_id: usize) -> Option<*mut Tcb> {
        unsafe {
            let mut prev: *mut Tcb = core::ptr::null_mut();
            let mut current = self.ready_head;

            while !current.is_null() {
                let affinity = (*current).cpu_affinity;
                if affinity == 0xFFFF_FFFF || affinity as usize == cpu_id {
                    // Remove from queue
                    if prev.is_null() {
                        self.ready_head = (*current).next;
                    } else {
                        (*prev).next = (*current).next;
                    }
                    (*current).next = core::ptr::null_mut();
                    return Some(current);
                }
                prev = current;
                current = (*current).next;
            }
            None
        }
    }

    /// Remove a specific thread from the ready queue — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn remove_from_ready_queue_unlocked(&mut self, tcb: *mut Tcb) -> bool {
        unsafe {
            let mut prev: *mut Tcb = core::ptr::null_mut();
            let mut current = self.ready_head;
            while !current.is_null() {
                if current == tcb {
                    if prev.is_null() {
                        self.ready_head = (*current).next;
                    } else {
                        (*prev).next = (*current).next;
                    }
                    (*current).next = core::ptr::null_mut();
                    return true;
                }
                prev = current;
                current = (*current).next;
            }
            false
        }
    }

    // ---------------------------------------------------------------
    // Locking wrapper methods (for external callers without lock held)
    // ---------------------------------------------------------------

    /// Add thread to ready queue with IRQ-safe locking.
    ///
    /// Acquires the scheduler spinlock with IRQs disabled.
    /// External callers (syscall, IPC, init) should use this.
    pub fn enqueue(&mut self, tcb: *mut Tcb) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();
        self.enqueue_unlocked(tcb);
        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
    }

    /// Remove highest priority thread with IRQ-safe locking.
    pub fn dequeue(&mut self) -> Option<*mut Tcb> {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();
        let result = self.dequeue_unlocked();
        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
        result
    }

    /// Remove highest priority thread for a CPU with IRQ-safe locking.
    pub fn dequeue_for_cpu(&mut self, cpu_id: usize) -> Option<*mut Tcb> {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();
        let result = self.dequeue_for_cpu_unlocked(cpu_id);
        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
        result
    }

    /// Remove a specific thread from the ready queue with IRQ-safe locking.
    pub fn remove_from_ready_queue(&mut self, tcb: *mut Tcb) -> bool {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();
        let result = self.remove_from_ready_queue_unlocked(tcb);
        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
        result
    }

    // ---------------------------------------------------------------
    // Schedule decision (unlocked — caller must hold lock)
    // ---------------------------------------------------------------

    /// Pick next thread to run on the current CPU — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    fn schedule_unlocked(&mut self) -> *mut Tcb {
        let cpu_id = crate::arch::current_cpu() as usize;
        if let Some(tcb) = self.dequeue_for_cpu_unlocked(cpu_id) {
            unsafe {
                (*tcb).state = ThreadState::Running;
            }
            self.current[cpu_id] = tcb;
            tcb
        } else {
            // Return idle thread for this CPU
            self.idle[cpu_id]
        }
    }

    /// Current running thread (on calling CPU)
    pub fn current(&self) -> *mut Tcb {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.current[cpu_id]
    }

    /// Set current running thread (on calling CPU)
    pub fn set_current(&mut self, tcb: *mut Tcb) {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.current[cpu_id] = tcb;
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

    /// Check if reschedule needed (preemption) on the calling CPU
    pub fn needs_reschedule(&self) -> bool {
        let cpu_id = crate::arch::current_cpu() as usize;
        let current = self.current[cpu_id];
        if self.ready_head.is_null() || current.is_null() {
            return false;
        }
        unsafe {
            // Check that the head of the ready queue can actually run on this CPU
            let head = self.ready_head;
            let affinity = (*head).cpu_affinity;
            if affinity != 0xFFFF_FFFF && affinity as usize != cpu_id {
                return false;
            }
            (*head).priority < (*current).priority
        }
    }

    // ---------------------------------------------------------------
    // Context switch helpers
    // ---------------------------------------------------------------

    /// Perform the actual context switch (VSpace, kernel stack, registers).
    ///
    /// MUST be called WITHOUT the scheduler lock held — context_switch does
    /// not return until the old thread is re-scheduled.
    unsafe fn do_context_switch(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        unsafe {
            // Switch to the target thread's user VSpace
            if !(*new_tcb).vspace_root.is_null() {
                let vspace = &*(*new_tcb).vspace_root;
                if !vspace.switch_to() {
                    crate::serial_puts("[SCHED] WARN: VSpace switch failed\n");
                }
            }

            // Switch per-CPU kernel stack
            if (*new_tcb).kernel_stack_top != 0 {
                crate::arch::set_kernel_stack((*new_tcb).kernel_stack_top);
                crate::arch::set_tss_rsp0((*new_tcb).kernel_stack_top);
            }

            // Perform context switch
            let old_ctx = &mut (*old_tcb).context as *mut _;
            let new_ctx = &(*new_tcb).context as *const _;
            crate::arch::context_switch(old_ctx, new_ctx);
        }
    }

    // ---------------------------------------------------------------
    // Timer tick (acquires lock internally)
    // ---------------------------------------------------------------

    /// Handle timer tick — called from interrupt context.
    ///
    /// Acquires the scheduler lock, performs budget accounting, and if a
    /// context switch is needed, releases the lock before switching.
    pub fn timer_tick(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];

            if current.is_null() {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            let sched_ctx = (*current).sched_context;
            if sched_ctx.is_null() {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Track consumed time
            (*sched_ctx).consumed += 1;

            // Decrement remaining budget
            (*sched_ctx).remaining = (*sched_ctx).remaining.saturating_sub(1);

            // Check if budget exhausted
            if (*sched_ctx).remaining == 0 {
                self.handle_budget_exhausted_unlocked(current);
                // handle_budget_exhausted_unlocked enqueued + made schedule decision
                // Check if switch is needed
                let new_tcb = self.schedule_unlocked();
                let old_tcb = current;
                if old_tcb != new_tcb {
                    self.set_current(new_tcb);
                    self.unlock();
                    crate::mm::restore_irq(irq_flag);
                    self.do_context_switch(old_tcb, new_tcb);
                    return;
                }
            }
            // Check for preemption (earlier deadline ready)
            else if self.needs_reschedule() {
                // Put current back in ready queue
                self.enqueue_unlocked(current);
                let new_tcb = self.schedule_unlocked();
                let old_tcb = current;
                if old_tcb != new_tcb {
                    self.set_current(new_tcb);
                    self.unlock();
                    crate::mm::restore_irq(irq_flag);
                    self.do_context_switch(old_tcb, new_tcb);
                    return;
                }
            }
        }

        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
    }

    /// Handle budget exhaustion for a thread — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    fn handle_budget_exhausted_unlocked(&mut self, tcb: *mut Tcb) {
        unsafe {
            let sched_ctx = (*tcb).sched_context;
            if sched_ctx.is_null() {
                return;
            }

            if (*sched_ctx).period > 0 {
                // Periodic: advance deadline by period
                (*sched_ctx).deadline += (*sched_ctx).period;
            } else {
                // Sporadic: move to lowest EDF priority
                (*sched_ctx).deadline = u64::MAX;
            }

            // Update priority (deadline) in TCB
            (*tcb).priority = (*sched_ctx).deadline;

            // Replenish budget
            (*sched_ctx).remaining = (*sched_ctx).budget;

            // Re-enqueue thread (enqueue sets state = Ready)
            self.enqueue_unlocked(tcb);
        }
    }

    // ---------------------------------------------------------------
    // Reschedule (acquires lock, then drops before context switch)
    // ---------------------------------------------------------------

    /// Perform a context switch to the next thread.
    ///
    /// Acquires the scheduler lock for the scheduling decision, then
    /// releases it before performing the actual context switch.
    pub fn reschedule(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let old_tcb = self.current[cpu_id];
            let new_tcb = self.schedule_unlocked();

            if old_tcb == new_tcb {
                // No switch needed
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Update current pointer
            self.set_current(new_tcb);

            // Release lock before context switch
            self.unlock();
            crate::mm::restore_irq(irq_flag);

            self.do_context_switch(old_tcb, new_tcb);
        }
    }

    // ---------------------------------------------------------------
    // VSpace blocking / wakeup (manages lock internally)
    // ---------------------------------------------------------------

    /// Enqueue thread in VSpace's intrusive wait queue
    ///
    /// Must be called with scheduler lock held and IRQs disabled.
    unsafe fn enqueue_vspace_waiter_locked(
        &mut self,
        tracking: &crate::mm::VSpaceTracking,
        tcb: *mut Tcb,
    ) {
        unsafe {
            (*tcb).vspace_wait_next = core::ptr::null_mut();

            // Get and update waiter head (UnsafeCell, scheduler lock sync)
            let head = tracking.waiter_head_get_locked();
            (*tcb).vspace_wait_next = head;
            tracking.waiter_head_set_locked(tcb);
        }
    }

    /// Wake all threads waiting on a VSpace
    ///
    /// Called when last core exits the VSpace.
    /// CRITICAL: Must be called with scheduler lock held and IRQs disabled!
    fn wakeup_vspace_waiters_locked(&mut self, tracking: &crate::mm::VSpaceTracking) {
        unsafe {
            // Clear waiter head and get all waiters
            let mut current = tracking.waiter_head_get_locked();
            tracking.waiter_head_set_locked(core::ptr::null_mut());

            // Wake all waiters
            while !current.is_null() {
                let next = (*current).vspace_wait_next;

                (*current).state = ThreadState::Ready;
                (*current).blocked_reason = None;
                (*current).blocked_vspace_tracking = core::ptr::null_mut();
                (*current).vspace_wait_next = core::ptr::null_mut();

                self.enqueue_unlocked(current);
                current = next;
            }
        }
    }

    /// Finish deactivate operation - wake waiters if VSpace became inactive
    ///
    /// CRITICAL: Must be called with scheduler lock held and IRQs disabled!
    pub fn finish_deactivate(&mut self, tracking: &crate::mm::VSpaceTracking) {
        self.wakeup_vspace_waiters_locked(tracking);
    }

    /// Block current thread on VSpace teardown (MAY switch, manages IRQ state internally)
    ///
    /// CRITICAL: This function may call reschedule() which performs context switch.
    /// The function manages IRQ state internally - do NOT wrap with with_lock().
    pub fn block_current_on_vspace(&mut self, tracking: &crate::mm::VSpaceTracking) {
        // Take scheduler lock and disable IRQs
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];

            // Fast path: check if already inactive
            if !tracking.is_active() {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Mark as blocked
            (*current).state = ThreadState::Blocked;
            (*current).blocked_reason = Some(BlockedReason::VSpaceWait);
            (*current).blocked_vspace_tracking = tracking as *const _ as *mut _;

            // Add to VSpace's intrusive wait queue
            self.enqueue_vspace_waiter_locked(tracking, current);

            // Make schedule decision while still holding lock
            let new_tcb = self.schedule_unlocked();
            let old_tcb = current;

            // Release lock before context switch
            self.unlock();

            if old_tcb != new_tcb {
                self.set_current(new_tcb);
                self.do_context_switch(old_tcb, new_tcb);
            }

            // Thread resumed - restore IRQ state
            crate::mm::restore_irq(irq_flag);
        }
    }

    // ---------------------------------------------------------------
    // Kernel exit epilogue
    // ---------------------------------------------------------------

    /// Kernel exit epilogue - MUST be called from ALL kernel exit points
    ///
    /// # Safety
    /// Must be called with scheduler lock held and IRQs disabled.
    fn kernel_exit_epilogue(&mut self) {
        // Process pending VSpace deactivates
        self.process_pending_deactivates();
    }

    /// Process pending deactivates (internal, called by kernel_exit_epilogue)
    ///
    /// CRITICAL: Must be called with scheduler lock held and IRQs disabled!
    fn process_pending_deactivates(&mut self) {
        let cpu_id = crate::arch::current_cpu() as usize;

        unsafe {
            // Take pending if any (null check is implicit)
            let old_tracking = crate::mm::take_pending_deactivate(cpu_id);

            if !old_tracking.is_null() {
                // Perform deactivate_nosched and check result
                match (*old_tracking).deactivate_nosched(cpu_id) {
                    crate::mm::DeactivateResult::BecameInactive => {
                        // We hold scheduler lock, call finish_deactivate
                        self.finish_deactivate(&*old_tracking);
                    }
                    _ => {
                        // Not active or still active, no wakeup needed
                    }
                }
            }
        }

        // Always advance quiescent generation - we passed a safe point
        crate::mm::advance_quiescent_gen(cpu_id);
    }

    /// Execute closure with scheduler lock held and IRQs disabled
    ///
    /// **IMPORTANT**: Use this ONLY for operations that do NOT block/switch!
    /// For blocking operations like VSpace wait, use `block_current_on_vspace()` instead.
    ///
    /// Automatically calls `kernel_exit_epilogue()` to process pending deactivates.
    pub fn with_lock<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Scheduler) -> R,
    {
        // Save interrupt flag and disable IRQs
        let irq_flag = unsafe { crate::mm::save_irq_disable() };

        // Take scheduler lock
        self.lock();

        // Process pending deactivates (we hold lock + IRQs disabled)
        self.kernel_exit_epilogue();

        let result = f(self);

        // Release scheduler lock
        self.unlock();

        // Restore interrupt flag
        unsafe { crate::mm::restore_irq(irq_flag) };

        result
    }
}

static mut SCHEDULER: Scheduler = Scheduler::new();

/// Global scheduler instance
pub fn scheduler() -> &'static mut Scheduler {
    // SAFETY: Single-threaded kernel access, interrupts disabled during scheduler operations
    unsafe { &mut *(&raw mut SCHEDULER) }
}
