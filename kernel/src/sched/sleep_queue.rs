//! Sleep queue for nanosleep
//!
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Sorted singly-linked list by timer_wakeup_ns.
//! All operations run with scheduler lock held.

use crate::sched::thread::{Tcb, ThreadState};

static mut HEAD: *mut Tcb = core::ptr::null_mut();

/// Insert TCB into sleep queue, sorted by wakeup time (ascending).
///
/// # Safety
/// Caller must hold the scheduler lock.
pub unsafe fn insert(tcb: *mut Tcb) {
    unsafe {
        let wakeup = (*tcb).timer_wakeup_ns;

        let head_ptr = &raw mut HEAD;
        if (*head_ptr).is_null() || wakeup < (**head_ptr).timer_wakeup_ns {
            (*tcb).sleep_next = *head_ptr;
            *head_ptr = tcb;
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
}

/// Remove a specific TCB from the sleep queue.
/// Returns true if found and removed.
///
/// # Safety
/// Caller must hold the scheduler lock.
pub unsafe fn remove(tcb: *mut Tcb) -> bool {
    unsafe {
        let head_ptr = &raw mut HEAD;
        if (*head_ptr).is_null() {
            return false;
        }

        if *head_ptr == tcb {
            *head_ptr = (*tcb).sleep_next;
            (*tcb).sleep_next = core::ptr::null_mut();
            return true;
        }

        let mut current = *head_ptr;
        while !(*current).sleep_next.is_null() {
            if (*current).sleep_next == tcb {
                (*current).sleep_next = (*tcb).sleep_next;
                (*tcb).sleep_next = core::ptr::null_mut();
                return true;
            }
            current = (*current).sleep_next;
        }
        false
    }
}

/// Check for expired sleepers and wake them.
/// Returns the number of threads woken.
///
/// # Safety
/// Caller must hold the scheduler lock.
pub unsafe fn check_wakeups(now_ns: u64) -> usize {
    unsafe {
        let head_ptr = &raw mut HEAD;
        let mut count = 0usize;

        while !(*head_ptr).is_null() && (**head_ptr).timer_wakeup_ns <= now_ns {
            let tcb = *head_ptr;
            *head_ptr = (*tcb).sleep_next;
            (*tcb).sleep_next = core::ptr::null_mut();
            (*tcb).timer_wakeup_ns = 0;
            (*tcb).state = ThreadState::Ready;
            (*tcb).blocked_reason = None;
            crate::sched::scheduler::scheduler().enqueue_unlocked(tcb);
            count += 1;
        }

        count
    }
}
