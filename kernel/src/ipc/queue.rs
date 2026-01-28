//! Thread Queue for IPC Blocking
//!
//! FIFO queue of TCB pointers using Tcb.next linkage.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::Tcb;

/// FIFO queue of TCB pointers
pub struct WaitQueue {
    head: *mut Tcb,
    tail: *mut Tcb,
}

impl WaitQueue {
    /// Create a new empty queue
    pub const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
        }
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    /// Push thread to back of queue
    pub fn push(&mut self, tcb: *mut Tcb) {
        unsafe {
            (*tcb).next = core::ptr::null_mut();
            if self.tail.is_null() {
                // First element
                self.head = tcb;
                self.tail = tcb;
            } else {
                (*self.tail).next = tcb;
                self.tail = tcb;
            }
        }
    }

    /// Pop thread from front of queue
    pub fn pop(&mut self) -> Option<*mut Tcb> {
        if self.head.is_null() {
            None
        } else {
            unsafe {
                let tcb = self.head;
                self.head = (*tcb).next;
                if self.head.is_null() {
                    self.tail = core::ptr::null_mut();
                }
                (*tcb).next = core::ptr::null_mut();
                Some(tcb)
            }
        }
    }

    /// Peek at front thread without removing
    pub fn peek(&self) -> Option<*mut Tcb> {
        if self.head.is_null() {
            None
        } else {
            Some(self.head)
        }
    }
}
