//! EDF Scheduler
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::thread::{BlockedReason, Tcb, ThreadState};

/// EDF Scheduler
pub struct Scheduler {
    /// Ready queue head (sorted by deadline)
    ready_head: *mut Tcb,
    /// Currently running thread
    current: *mut Tcb,
    /// Idle thread
    idle: *mut Tcb,
    /// Lock state (simple test-and-set spinlock)
    lock_state: core::sync::atomic::AtomicU8,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            ready_head: core::ptr::null_mut(),
            current: core::ptr::null_mut(),
            idle: core::ptr::null_mut(),
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

    /// Add thread to ready queue (sorted by deadline)
    pub fn enqueue(&mut self, tcb: *mut Tcb) {
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
        }
    }

    /// Remove highest priority (earliest deadline) thread
    pub fn dequeue(&mut self) -> Option<*mut Tcb> {
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

    /// Pick next thread to run
    pub fn schedule(&mut self) -> *mut Tcb {
        if let Some(tcb) = self.dequeue() {
            unsafe {
                (*tcb).state = ThreadState::Running;
            }
            self.current = tcb;
            tcb
        } else {
            // Return idle thread
            self.idle
        }
    }

    /// Current running thread
    pub fn current(&self) -> *mut Tcb {
        self.current
    }

    /// Set current running thread
    ///
    /// Used when switching to a new thread.
    pub fn set_current(&mut self, tcb: *mut Tcb) {
        self.current = tcb;
    }

    /// Get idle thread
    pub fn get_idle(&self) -> *mut Tcb {
        self.idle
    }

    /// Set idle thread
    ///
    /// Called during scheduler initialization.
    pub fn set_idle(&mut self, tcb: *mut Tcb) {
        self.idle = tcb;
    }

    /// Check if reschedule needed (preemption)
    pub fn needs_reschedule(&self) -> bool {
        if self.ready_head.is_null() || self.current.is_null() {
            return false;
        }
        unsafe { (*self.ready_head).priority < (*self.current).priority }
    }

    /// Handle timer tick - called from interrupt context
    ///
    /// Decrements the current thread's budget and handles budget exhaustion.
    /// Also checks for preemption if a higher priority thread is ready.
    pub fn timer_tick(&mut self) {
        unsafe {
            let current = self.current;

            if current.is_null() {
                return;
            }

            let sched_ctx = (*current).sched_context;
            if sched_ctx.is_null() {
                return;
            }

            // Decrement remaining budget
            (*sched_ctx).remaining = (*sched_ctx).remaining.saturating_sub(1);

            // Check if budget exhausted
            if (*sched_ctx).remaining == 0 {
                self.handle_budget_exhausted(current);
            }
            // Check for preemption (earlier deadline ready)
            else if self.needs_reschedule() {
                // Put current back in ready queue
                self.enqueue(current);
                self.reschedule();
            }
        }
    }

    /// Handle budget exhaustion for a thread
    ///
    /// When a thread's budget is exhausted:
    /// 1. Mark it as blocked
    /// 2. Calculate next deadline (current + period)
    /// 3. Replenish budget
    /// 4. Re-enqueue the thread
    /// 5. Trigger reschedule
    fn handle_budget_exhausted(&mut self, tcb: *mut Tcb) {
        unsafe {
            let sched_ctx = (*tcb).sched_context;
            if sched_ctx.is_null() {
                return;
            }

            // Block the thread
            (*tcb).state = ThreadState::Blocked;

            // Calculate next deadline (current + period)
            (*sched_ctx).deadline += (*sched_ctx).period;

            // Update priority (deadline) in TCB
            (*tcb).priority = (*sched_ctx).deadline;

            // Replenish budget
            (*sched_ctx).remaining = (*sched_ctx).budget;

            // Re-enqueue thread
            self.enqueue(tcb);

            // Trigger reschedule
            self.reschedule();
        }
    }

    /// Perform a context switch to the next thread
    ///
    /// This function is called when:
    /// - The current thread's budget is exhausted
    /// - A higher priority thread becomes ready
    /// - The current thread yields
    pub fn reschedule(&mut self) {
        unsafe {
            let old_tcb = self.current;
            let new_tcb = self.schedule();

            if old_tcb == new_tcb {
                // No switch needed
                return;
            }

            // Update current pointer
            self.set_current(new_tcb);

            // Perform context switch
            // SAFETY: Both TCBs are valid, interrupts are disabled
            let old_ctx = &mut (*old_tcb).context as *mut _;
            let new_ctx = &(*new_tcb).context as *const _;
            crate::arch::context_switch(old_ctx, new_ctx);
        }
    }

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

                self.enqueue(current);
                current = next;
            }
        }
    }

    /// Finish deactivate operation - wake waiters if VSpace became inactive
    ///
    /// CRITICAL: Must be called with scheduler lock held and IRQs disabled!
    ///
    /// This is the centralized handler for all "last core exited" cases.
    /// All callers of `deactivate_nosched()` that get `BecameInactive` MUST
    /// call this function (with scheduler lock held).
    ///
    /// This centralization ensures:
    /// - Single point for wakeup logic (easier debugging/tracing)
    /// - Structurally enforced lock requirement
    /// - Consistent handling across all code paths
    pub fn finish_deactivate(&mut self, tracking: &crate::mm::VSpaceTracking) {
        self.wakeup_vspace_waiters_locked(tracking);
    }

    /// Block current thread on VSpace teardown (MAY switch, manages IRQ state internally)
    ///
    /// CRITICAL: This function may call reschedule() which performs context switch.
    /// The function manages IRQ state internally - do NOT wrap with with_lock().
    ///
    /// Use this instead of with_lock() for blocking operations:
    /// ```rust
    /// scheduler.block_current_on_vspace(tracking);
    /// ```
    ///
    /// This forms one half of the "structurally-enforced shared lock" pattern.
    /// The other half is `finish_deactivate()`, which handles wakeup when
    /// deactivate_nosched() returns `BecameInactive`.
    pub fn block_current_on_vspace(&mut self, tracking: &crate::mm::VSpaceTracking) {
        // Take scheduler lock and disable IRQs
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        unsafe {
            let current = self.current;

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

            // Context switch - reschedule() handles lock release and IRQ restore
            // NOTE: reschedule() will NOT return here until this thread is scheduled again
            self.reschedule_with_irq_restore(irq_flag);
        }

        // When we return here, IRQ state has been restored by reschedule_with_irq_restore
    }

    /// Reschedule with IRQ state management (internal, for blocking operations)
    ///
    /// This is called by blocking functions like `block_current_on_vspace()`.
    /// It handles context switch and ensures IRQ state is properly restored
    /// when the thread resumes.
    ///
    /// # Safety
    /// Must be called with scheduler lock held and IRQs disabled.
    /// irq_flag is the saved interrupt flag to restore when thread resumes.
    unsafe fn reschedule_with_irq_restore(&mut self, irq_flag: u64) {
        unsafe {
            // Release scheduler lock
            self.unlock();

            // Perform context switch
            // When we return here (thread resumed), restore IRQ state
            self.reschedule();

            // Thread resumed - restore IRQ state
            crate::mm::restore_irq(irq_flag);
        }
    }

    /// Kernel exit epilogue - MUST be called from ALL kernel exit points
    ///
    /// **STRUCTURALLY ENFORCED**: This function MUST be called from:
    /// 1. Context switch paths (before/after thread switch)
    /// 2. Scheduler lock acquisition points (when taking lock for non-blocking operations)
    /// 3. Timer tick handler (which already holds scheduler lock)
    ///
    /// IMPORTANT: Do NOT call from arbitrary interrupt return paths!
    /// Only call from contexts that already safely interact with scheduler.
    ///
    /// This is automatically called by `with_lock()` - no manual call needed for most cases.
    ///
    /// # Safety
    /// Must be called with scheduler lock held and IRQs disabled.
    fn kernel_exit_epilogue(&mut self) {
        // Process pending VSpace deactivates
        self.process_pending_deactivates();

        // Future: add other "must-run" epilogue tasks here
        // e.g., deferred work, signal handling, etc.
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
        // This signals to deferred free that this CPU processed pending
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
