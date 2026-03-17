//! Asynchronous Notification
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::cap::{KernelObject, ObjectType};
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

use crate::sched::scheduler::scheduler as get_scheduler;

/// Notification object for async signaling
#[repr(C)]
pub struct Notification {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Per-notification spinlock
    lock: AtomicU8,
    /// Pending notification bits (atomic for concurrent access)
    pub bits: AtomicU64,
    /// Waiting thread (if any)
    waiting: *mut Tcb,
    /// TCB that has this notification bound (for combined IPC wait)
    pub bound_tcb: *mut Tcb,
}

impl Notification {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Notification, 0),
            lock: AtomicU8::new(0),
            bits: AtomicU64::new(0),
            waiting: core::ptr::null_mut(),
            bound_tcb: core::ptr::null_mut(),
        }
    }

    /// Acquire per-notification lock.
    #[inline]
    pub fn ntfn_lock(&self) {
        if self.lock.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return;
        }
        let mut backoff: u32 = 0;
        loop {
            for _ in 0..(1u32 << backoff.min(6)) {
                core::hint::spin_loop();
            }
            if self.lock.load(Ordering::Relaxed) == 0
                && self.lock.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
            {
                return;
            }
            if backoff < 6 { backoff += 1; }
        }
    }

    /// Release per-notification lock.
    #[inline]
    pub fn ntfn_unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }

    /// Signal notification (set bits) - never blocks
    pub fn signal(&mut self, bits: u64) {
        unsafe {
            self.ntfn_lock();

            self.bits.fetch_or(bits, Ordering::SeqCst);

            if !self.waiting.is_null() {
                let waiter = self.waiting;
                self.waiting = core::ptr::null_mut();

                (*waiter).blocked_reason = None;
                (*waiter).blocked_notification = core::ptr::null_mut();
                (*waiter).state = ThreadState::Ready;
                self.ntfn_unlock();
                get_scheduler().enqueue(waiter);
            } else if !self.bound_tcb.is_null() {
                let tcb = self.bound_tcb;
                if (*tcb).state == ThreadState::Blocked
                    && matches!((*tcb).blocked_reason, Some(BlockedReason::RecvBlocked))
                {
                    // Remove from endpoint recv queue (need endpoint lock)
                    let ep_ptr = (*tcb).blocked_endpoint;
                    if !ep_ptr.is_null() {
                        let ep = &mut *(ep_ptr as *mut super::Endpoint);
                        ep.ep_lock();
                        ep.remove_from_queue(tcb);
                        ep.ep_unlock();
                    }

                    let all_bits = self.bits.swap(0, Ordering::SeqCst);
                    (*tcb).saved_caller_badge = all_bits;
                    (*tcb).saved_caller_msg = super::Message::empty();
                    (*tcb).blocked_reason = None;
                    (*tcb).blocked_endpoint = core::ptr::null_mut();
                    (*tcb).state = ThreadState::Ready;
                    self.ntfn_unlock();
                    get_scheduler().enqueue(tcb);
                } else {
                    self.ntfn_unlock();
                }
            } else {
                self.ntfn_unlock();
            }
        }
    }

    /// Wait for notification (blocks if no bits set)
    pub fn wait(&mut self) -> u64 {
        unsafe {
            self.ntfn_lock();

            let bits = self.bits.swap(0, Ordering::SeqCst);
            if bits != 0 {
                self.ntfn_unlock();
                return bits;
            }

            // No bits - block current thread
            let current = get_scheduler().current();
            self.waiting = current;
            (*current).blocked_notification = self as *mut Notification as *mut u8;
            super::block_current_thread_no_switch(current, BlockedReason::NotificationWait);

            // Release lock before reschedule (no lock held during context switch)
            self.ntfn_unlock();
            get_scheduler().reschedule();

            // When we wake, consume bits
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
    pub fn remove_waiter(&mut self, tcb: *mut Tcb) -> bool {
        if self.waiting == tcb {
            self.waiting = core::ptr::null_mut();
            return true;
        }
        false
    }

    /// Cleanup when notification is destroyed
    pub fn cleanup(&mut self) {
        self.ntfn_lock();

        unsafe {
            if !self.waiting.is_null() {
                let waiter = self.waiting;
                self.waiting = core::ptr::null_mut();

                (*waiter).blocked_reason = None;
                (*waiter).blocked_notification = core::ptr::null_mut();
                (*waiter).state = ThreadState::Ready;
                get_scheduler().enqueue(waiter);
            }

            if !self.bound_tcb.is_null() {
                let tcb = self.bound_tcb;
                (*tcb).bound_notification = core::ptr::null_mut();
                self.bound_tcb = core::ptr::null_mut();
            }
        }

        self.ntfn_unlock();
    }
}
