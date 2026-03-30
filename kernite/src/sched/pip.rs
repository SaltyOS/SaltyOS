//! Priority Inheritance Protocol (PIP)
//!
//! Prevents priority inversion when a high-priority (early deadline) client
//! calls a low-priority server via IPC endpoint.
//!
//! Design: SaltyOS servers hold at most one reply_tcb at a time (single
//! reply capability), so donation is always 0 or 1. Transitive chains are
//! bounded to MAX_PIP_DEPTH to prevent unbounded traversal.
//!
//! All PIP operations MUST be called with per-object lock (endpoint or TCB) held.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::thread::{Tcb, ThreadState};

/// Maximum transitive chain depth to prevent unbounded traversal
pub const MAX_PIP_DEPTH: u8 = 8;

/// Donate priority from a caller (donor) to a server (holder).
///
/// If donor has an earlier deadline (lower priority value) than holder,
/// boost holder's effective priority to donor's level. Propagates
/// transitively through the pip_donating_to chain.
///
/// # Safety
/// - Both pointers must be valid TCBs.
/// - per-object lock (endpoint or TCB) must be held by the caller.
pub unsafe fn pip_donate(donor: *mut Tcb, holder: *mut Tcb) {
    unsafe {
        if donor.is_null() || holder.is_null() {
            return;
        }

        // Only donate if donor has earlier (smaller) deadline
        if (*donor).priority >= (*holder).priority {
            (*donor).pip_donating_to = holder;
            (*holder).pip_donation_count += 1;
            return;
        }

        // Record the donation relationship
        (*donor).pip_donating_to = holder;
        (*holder).pip_donation_count += 1;

        // Boost holder and propagate transitively
        let mut current = holder;
        let donor_priority = (*donor).priority;
        let mut depth: u8 = 0;

        while !current.is_null() && depth < MAX_PIP_DEPTH {
            if donor_priority >= (*current).priority {
                break;
            }

            let old_priority = (*current).priority;
            (*current).priority = donor_priority;

            // If the boosted thread is in the ready queue, re-sort it
            if (*current).state == ThreadState::Ready {
                crate::sched::scheduler::scheduler().resort_ready_thread(current);
            }

            // Follow the chain: if this thread is itself donating to someone
            let _ = old_priority; // suppress unused warning
            current = (*current).pip_donating_to;
            depth += 1;
        }
    }
}

/// Revert priority donation when the server replies.
///
/// Restores holder's priority to base_priority and clears the donation
/// relationship. If holder has no more donations, its priority returns
/// to base.
///
/// # Safety
/// - Both pointers must be valid TCBs.
/// - per-object lock (endpoint or TCB) must be held by the caller.
pub unsafe fn pip_undonate(holder: *mut Tcb, caller: *mut Tcb) {
    unsafe {
        if holder.is_null() || caller.is_null() {
            return;
        }

        // Clear donation relationship
        if (*caller).pip_donating_to == holder {
            (*caller).pip_donating_to = core::ptr::null_mut();
        }

        if (*holder).pip_donation_count > 0 {
            (*holder).pip_donation_count -= 1;
        }

        // Restore to base priority if no more donations
        if (*holder).pip_donation_count == 0 {
            (*holder).priority = (*holder).base_priority;

            // If in ready queue, re-sort with restored priority
            if (*holder).state == ThreadState::Ready {
                crate::sched::scheduler::scheduler().resort_ready_thread(holder);
            }
        }
    }
}

/// Clean up PIP state when a TCB is destroyed or suspended.
///
/// If this thread was donating to someone, undo the donation.
/// If this thread had donations, reset to base priority.
///
/// # Safety
/// - `tcb` must be a valid TCB pointer.
/// - per-object lock (endpoint or TCB) should be held or thread must be inactive.
pub unsafe fn pip_cleanup(tcb: *mut Tcb) {
    unsafe {
        if tcb.is_null() {
            return;
        }

        // If we were donating to someone, undo it
        let holder = (*tcb).pip_donating_to;
        if !holder.is_null() {
            (*tcb).pip_donating_to = core::ptr::null_mut();
            if (*holder).pip_donation_count > 0 {
                (*holder).pip_donation_count -= 1;
            }
            if (*holder).pip_donation_count == 0 {
                (*holder).priority = (*holder).base_priority;
            }
        }

        // Reset own PIP state
        (*tcb).pip_donation_count = 0;
        (*tcb).priority = (*tcb).base_priority;
        (*tcb).pip_donating_to = core::ptr::null_mut();
    }
}
