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

    /// Check if reschedule needed (preemption)
    pub fn needs_reschedule(&self) -> bool {
        if self.ready_head.is_null() || self.current.is_null() {
            return false;
        }
        unsafe { (*self.ready_head).priority < (*self.current).priority }
    }
}

static mut SCHEDULER: Scheduler = Scheduler::new();

/// Global scheduler instance
pub fn scheduler() -> &'static mut Scheduler {
    // SAFETY: Single-threaded kernel access, interrupts disabled during scheduler operations
    unsafe { &mut *(&raw mut SCHEDULER) }
}
