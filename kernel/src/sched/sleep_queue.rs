//! Sleep queue for nanosleep
//!
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Sorted singly-linked list by timer_wakeup_ns.
//! Protected by a dedicated SLEEP_LOCK for SMP safety.

use crate::mm::SpinLock;
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};
use core::sync::atomic::{AtomicU64, Ordering};

/// Dedicated lock protecting the global sleep queue.
/// Required because timer ticks on multiple CPUs can call
/// insert/remove/check_wakeups concurrently.
static SLEEP_LOCK: SpinLock = SpinLock::new();

static mut HEAD: *mut Tcb = core::ptr::null_mut();
static NEXT_WAKEUP_NS: AtomicU64 = AtomicU64::new(u64::MAX);

#[inline]
unsafe fn refresh_next_wakeup_locked() {
    unsafe {
        let head = *(&raw const HEAD);
        let next = if head.is_null() {
            u64::MAX
        } else {
            (*head).timer_wakeup_ns
        };
        NEXT_WAKEUP_NS.store(next, Ordering::Release);
    }
}

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
            refresh_next_wakeup_locked();
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
        refresh_next_wakeup_locked();
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
            refresh_next_wakeup_locked();
            true
        } else {
            let mut current = *head_ptr;
            let mut found = false;
            while !(*current).sleep_next.is_null() {
                if (*current).sleep_next == tcb {
                    (*current).sleep_next = (*tcb).sleep_next;
                    (*tcb).sleep_next = core::ptr::null_mut();
                    refresh_next_wakeup_locked();
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
    NEXT_WAKEUP_NS.load(Ordering::Acquire) <= now_ns
}

/// Check for expired sleepers and wake them.
/// Returns the number of threads woken.
///
/// Detaches the entire expired prefix under SLEEP_LOCK, then releases it
/// before touching endpoint/futex/scheduler state to avoid cross-subsystem
/// lock nesting from the timer interrupt path and to keep the timer slowpath
/// proportional to the number of actual wakeups.
///
/// # Safety
/// Caller must have IRQs disabled.
pub unsafe fn check_wakeups(now_ns: u64) -> usize {
    let wake_head = unsafe {
        SLEEP_LOCK.lock();

        let head_ptr = &raw mut HEAD;
        let head = *head_ptr;
        if head.is_null() || (*head).timer_wakeup_ns > now_ns {
            refresh_next_wakeup_locked();
            SLEEP_LOCK.unlock();
            return 0;
        }

        let mut tail = head;
        while !(*tail).sleep_next.is_null()
            && (*(*tail).sleep_next).timer_wakeup_ns <= now_ns
        {
            tail = (*tail).sleep_next;
        }

        *head_ptr = (*tail).sleep_next;
        (*tail).sleep_next = core::ptr::null_mut();
        refresh_next_wakeup_locked();
        SLEEP_LOCK.unlock();
        head
    };

    let mut count = 0usize;
    let mut tcb = wake_head;

    while !tcb.is_null() {
        let next = unsafe { (*tcb).sleep_next };

        unsafe {
            (*tcb).sleep_next = core::ptr::null_mut();
            (*tcb).timer_wakeup_ns = 0;

            // Timed futex wait: detach from futex hash table and report timeout.
            // Re-validate after futex_remove_thread — a concurrent futex_wake
            // may have already removed this TCB from the hash table and
            // enqueued it between SLEEP_LOCK release and FUTEX_LOCK acquisition.
            if matches!((*tcb).blocked_reason, Some(BlockedReason::FutexTimedBlocked)) {
                crate::ipc::futex::futex_remove_thread(tcb);
                if !matches!((*tcb).blocked_reason, Some(BlockedReason::FutexTimedBlocked)) {
                    // Already woken by concurrent futex_wake — skip.
                    tcb = next;
                    continue;
                }
                (*tcb).futex_wakeup_result = 12; // SyscallError::Cancelled = timeout
            }

            // Timed IPC: remove from endpoint queue and report timeout.
            // Re-validate blocked_reason under ep_lock — a concurrent
            // notification signal or IPC send may have already woken this
            // thread between SLEEP_LOCK release and ep_lock acquisition.
            if matches!(
                (*tcb).blocked_reason,
                Some(BlockedReason::SendTimedBlocked { .. }) | Some(BlockedReason::RecvTimedBlocked)
            ) {
                let ep = (*tcb).blocked_endpoint as *mut crate::ipc::Endpoint;
                if !ep.is_null() {
                    (*ep).ep_lock();
                    // Re-check: signal()/send() may have cleared blocked_reason
                    // and enqueued the thread while we waited for ep_lock.
                    if matches!(
                        (*tcb).blocked_reason,
                        Some(BlockedReason::SendTimedBlocked { .. }) | Some(BlockedReason::RecvTimedBlocked)
                    ) && (*tcb).blocked_endpoint == ep as *mut u8
                    {
                        (*ep).remove_from_queue(tcb);
                        (*ep).ep_unlock();
                        (*tcb).blocked_endpoint = core::ptr::null_mut();
                        (*tcb).futex_wakeup_result = 12; // SyscallError::Cancelled = timeout
                    } else {
                        // Already woken by concurrent signal/IPC — skip.
                        (*ep).ep_unlock();
                        tcb = next;
                        continue;
                    }
                } else {
                    // blocked_endpoint is null → signal() already cleared it
                    // and is handling (or has handled) this thread's wake.
                    tcb = next;
                    continue;
                }
            }

            (*tcb).state = ThreadState::Ready;
            (*tcb).blocked_reason = None;
            crate::sched::scheduler::scheduler().enqueue(tcb);
            count += 1;
        }

        tcb = next;
    }

    count
}
