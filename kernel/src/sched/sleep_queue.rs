//! Sleep queue for nanosleep
//!
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Sorted singly-linked list by timer_wakeup_ns.
//! Protected by a dedicated SLEEP_LOCK for SMP safety.

use crate::mm::SpinLock;
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

/// Dedicated lock protecting the global sleep queue.
/// Required because timer ticks on multiple CPUs can call
/// insert/remove/check_wakeups concurrently.
static SLEEP_LOCK: SpinLock = SpinLock::new();

static mut HEAD: *mut Tcb = core::ptr::null_mut();

/// Insert TCB into sleep queue, sorted by wakeup time (ascending).
///
/// Acquires SLEEP_LOCK internally.
///
/// # Safety
/// Caller must have IRQs disabled.
pub unsafe fn insert(tcb: *mut Tcb) {
    SLEEP_LOCK.lock();
    unsafe {
        let wakeup = (*tcb).timer_wakeup_ns;

        let head_ptr = &raw mut HEAD;
        if (*head_ptr).is_null() || wakeup < (**head_ptr).timer_wakeup_ns {
            (*tcb).sleep_next = *head_ptr;
            *head_ptr = tcb;
            SLEEP_LOCK.unlock();
            return;
        }

        let mut current = *head_ptr;
        while !(*current).sleep_next.is_null()
            && (*(*current).sleep_next).timer_wakeup_ns <= wakeup
        {
            current = (*current).sleep_next;
        }
        (*tcb).sleep_next = (*current).sleep_next;
        (*current).sleep_next = tcb;
    }
    SLEEP_LOCK.unlock();
}

/// Remove a specific TCB from the sleep queue.
/// Returns true if found and removed.
///
/// Acquires SLEEP_LOCK internally.
///
/// # Safety
/// Caller must have IRQs disabled.
pub unsafe fn remove(tcb: *mut Tcb) -> bool {
    SLEEP_LOCK.lock();
    let result = unsafe {
        let head_ptr = &raw mut HEAD;
        if (*head_ptr).is_null() {
            false
        } else if *head_ptr == tcb {
            *head_ptr = (*tcb).sleep_next;
            (*tcb).sleep_next = core::ptr::null_mut();
            true
        } else {
            let mut current = *head_ptr;
            let mut found = false;
            while !(*current).sleep_next.is_null() {
                if (*current).sleep_next == tcb {
                    (*current).sleep_next = (*tcb).sleep_next;
                    (*tcb).sleep_next = core::ptr::null_mut();
                    found = true;
                    break;
                }
                current = (*current).sleep_next;
            }
            found
        }
    };
    SLEEP_LOCK.unlock();
    result
}

/// Peek whether the sleep queue head has expired.
///
/// # Safety
/// Caller must have IRQs disabled.
pub unsafe fn peek_expired(now_ns: u64) -> bool {
    SLEEP_LOCK.lock();
    let result = unsafe {
        let head = *(&raw const HEAD);
        !head.is_null() && (*head).timer_wakeup_ns <= now_ns
    };
    SLEEP_LOCK.unlock();
    result
}

/// Check for expired sleepers and wake them.
/// Returns the number of threads woken.
///
/// Acquires SLEEP_LOCK, ep_lock, FUTEX_LOCK as needed.
///
/// # Safety
/// Caller must have IRQs disabled.
pub unsafe fn check_wakeups(now_ns: u64) -> usize {
    SLEEP_LOCK.lock();
    unsafe {
        let head_ptr = &raw mut HEAD;
        let mut count = 0usize;

        while !(*head_ptr).is_null() && (**head_ptr).timer_wakeup_ns <= now_ns {
            let tcb = *head_ptr;
            *head_ptr = (*tcb).sleep_next;
            (*tcb).sleep_next = core::ptr::null_mut();
            (*tcb).timer_wakeup_ns = 0;

            // Futex timed wait: remove from futex hash table under FUTEX_LOCK
            if matches!((*tcb).blocked_reason, Some(BlockedReason::FutexTimedBlocked)) {
                // SLEEP_LOCK is held; FUTEX_LOCK acquisition is safe (no ordering conflict)
                crate::ipc::futex::futex_remove_thread(tcb);
                (*tcb).futex_wakeup_result = 12; // SyscallError::Cancelled = timeout
            }

            // Timed IPC: remove from endpoint queue under ep_lock
            if matches!(
                (*tcb).blocked_reason,
                Some(BlockedReason::SendTimedBlocked { .. }) | Some(BlockedReason::RecvTimedBlocked)
            ) {
                let ep = (*tcb).blocked_endpoint as *mut crate::ipc::Endpoint;
                if !ep.is_null() {
                    (*ep).ep_lock();
                    (*ep).remove_from_queue(tcb);
                    (*ep).ep_unlock();
                    (*tcb).blocked_endpoint = core::ptr::null_mut();
                }
                (*tcb).futex_wakeup_result = 12; // SyscallError::Cancelled = timeout
            }

            (*tcb).state = ThreadState::Ready;
            (*tcb).blocked_reason = None;
            crate::sched::scheduler::scheduler().enqueue_unlocked(tcb);
            count += 1;
        }

        SLEEP_LOCK.unlock();
        count
    }
}
