//! Asynchronous Notification
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::{KernelObject, ObjectType};
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

use crate::sched::scheduler::scheduler as get_scheduler;

/// Notification object for async signaling
#[repr(C)]
pub struct Notification {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Pending notification bits (atomic for concurrent access)
    bits: AtomicU64,
    /// Waiting thread (if any)
    waiting: *mut Tcb,
}

impl Notification {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Notification, 0),
            bits: AtomicU64::new(0),
            waiting: core::ptr::null_mut(),
        }
    }

    /// Signal notification (set bits) - never blocks
    pub fn signal(&mut self, bits: u64) {
        unsafe {
            // Atomically OR bits into notification word
            self.bits.fetch_or(bits, Ordering::SeqCst);

            // Wake waiting thread if any
            if !self.waiting.is_null() {
                let waiter = self.waiting;
                self.waiting = core::ptr::null_mut();

                // Clear blocked reason and make runnable
                (*waiter).blocked_reason = None;
                (*waiter).blocked_notification = core::ptr::null_mut();
                (*waiter).state = ThreadState::Ready;
                get_scheduler().enqueue(waiter);
            }
        }
    }

    /// Wait for notification (blocks if no bits set)
    pub fn wait(&mut self) -> u64 {
        unsafe {
            // Try to consume notification atomically
            let bits = self.bits.swap(0, Ordering::SeqCst);

            if bits != 0 {
                // Bits were pending - return immediately
                return bits;
            }

            // No bits - block current thread
            let current = get_scheduler().current();
            self.waiting = current;
            (*current).blocked_notification = self as *mut Notification as *mut u8;

            // Block and wait for signal
            super::block_current_thread(current, BlockedReason::NotificationWait);

            // When we wake, try to consume bits again
            // (in case signal raced with our block)
            self.bits.swap(0, Ordering::SeqCst)
        }
    }

    /// Poll without blocking
    pub fn poll(&mut self) -> Option<u64> {
        let bits = self.bits.swap(0, Ordering::SeqCst);
        if bits != 0 {
            Some(bits)
        } else {
            None
        }
    }

    /// Remove a specific TCB from the waiting slot
    ///
    /// Used when suspending a thread that is blocked on this notification.
    /// Returns true if the thread was the waiter and was removed.
    pub fn remove_waiter(&mut self, tcb: *mut Tcb) -> bool {
        if self.waiting == tcb {
            self.waiting = core::ptr::null_mut();
            return true;
        }
        false
    }

    /// Cleanup when notification is destroyed
    ///
    /// Wake any waiting thread.
    pub fn cleanup(&mut self) {
        unsafe {
            if !self.waiting.is_null() {
                let waiter = self.waiting;
                self.waiting = core::ptr::null_mut();

                (*waiter).blocked_reason = None;
                (*waiter).blocked_notification = core::ptr::null_mut();
                (*waiter).state = ThreadState::Ready;
                get_scheduler().enqueue(waiter);
            }
        }
    }
}
