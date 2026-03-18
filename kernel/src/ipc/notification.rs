//! Asynchronous Notification
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::cap::{KernelObject, ObjectType};
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

use crate::sched::scheduler::scheduler as get_scheduler;

/// Per-CPU saved IRQ flags for ntfn_lock/ntfn_unlock.
/// Same pattern as EP_IRQ_FLAGS — prevents timer tick deadlock.
static mut NTFN_IRQ_FLAGS: [u64; crate::arch::MAX_CPUS] = [0; crate::arch::MAX_CPUS];

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

    /// Acquire per-notification lock with IRQ disable.
    #[inline]
    pub fn ntfn_lock(&self) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        let cpu = crate::arch::current_cpu() as usize;
        unsafe { *(&raw mut NTFN_IRQ_FLAGS[cpu]) = irq; }

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

    /// Release per-notification lock and restore IRQs.
    #[inline]
    pub fn ntfn_unlock(&self) {
        self.lock.store(0, Ordering::Release);
        let cpu = crate::arch::current_cpu() as usize;
        let irq = unsafe { *(&raw const NTFN_IRQ_FLAGS[cpu]) };
        unsafe { crate::mm::restore_irq(irq); }
    }

    /// Signal notification (set bits) - never blocks.
    ///
    /// Lock ordering: releases ntfn_lock before acquiring ep_lock to avoid
    /// ntfn_lock → ep_lock nesting (normal IPC acquires ep_lock first).
    /// The bound_tcb state is re-validated after reacquiring ep_lock to
    /// handle the TOCTOU window.
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
                let ep_ptr = (*tcb).blocked_endpoint;
                if ep_ptr.is_null() {
                    self.ntfn_unlock();
                    return;
                }

                // Snapshot and consume bits under ntfn_lock, then release
                // before acquiring ep_lock to prevent lock ordering inversion.
                let all_bits = self.bits.swap(0, Ordering::SeqCst);
                self.ntfn_unlock();

                let ep = &mut *(ep_ptr as *mut super::Endpoint);
                ep.ep_lock();

                // Re-validate: TCB state may have changed while no locks
                // were held (timeout, another signal, or IPC completion).
                let wake_recv = (*tcb).state == ThreadState::Blocked
                    && (*tcb).blocked_endpoint == ep_ptr
                    && matches!(
                        (*tcb).blocked_reason,
                        Some(BlockedReason::RecvBlocked) | Some(BlockedReason::RecvTimedBlocked)
                    );

                if !wake_recv {
                    ep.ep_unlock();
                    // Restore bits so they aren't lost — a future poll/wait
                    // or another signal() call will pick them up.
                    self.bits.fetch_or(all_bits, Ordering::SeqCst);
                    return;
                }

                let timed = matches!((*tcb).blocked_reason, Some(BlockedReason::RecvTimedBlocked));
                ep.remove_from_queue(tcb);

                (*tcb).saved_caller_badge = all_bits;
                (*tcb).saved_caller_msg = super::Message::empty();
                (*tcb).blocked_endpoint = core::ptr::null_mut();

                ep.ep_unlock();

                if timed {
                    crate::sched::sleep_queue::remove(tcb);
                    (*tcb).timer_wakeup_ns = 0;
                    (*tcb).futex_wakeup_result = 0;
                }

                (*tcb).blocked_reason = None;
                (*tcb).state = ThreadState::Ready;
                get_scheduler().enqueue(tcb);
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

    /// Remove a specific TCB from the waiting slot.
    /// Acquires ntfn_lock internally for SMP safety.
    pub fn remove_waiter(&mut self, tcb: *mut Tcb) -> bool {
        self.ntfn_lock();
        let removed = if self.waiting == tcb {
            self.waiting = core::ptr::null_mut();
            true
        } else {
            false
        };
        self.ntfn_unlock();
        removed
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
