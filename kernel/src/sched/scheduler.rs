//! EDF Scheduler
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::thread::{Tcb, ThreadState};

/// EDF Scheduler
pub struct Scheduler {
    /// Ready queue head (sorted by deadline)
    ready_head: *mut Tcb,
    /// Currently running thread
    current: *mut Tcb,
    /// Idle thread
    idle: *mut Tcb,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            ready_head: core::ptr::null_mut(),
            current: core::ptr::null_mut(),
            idle: core::ptr::null_mut(),
        }
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
}

static mut SCHEDULER: Scheduler = Scheduler::new();

/// Global scheduler instance
pub fn scheduler() -> &'static mut Scheduler {
    // SAFETY: Single-threaded kernel access, interrupts disabled during scheduler operations
    unsafe { &mut *(&raw mut SCHEDULER) }
}
