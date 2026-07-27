//! Priority Inheritance Protocol (PIP)
//!
//! Prevents priority inversion when a high-priority (early deadline) client
//! calls a low-priority server through `MessagePipe` MP_CALL.
//!
//! Design: a SaltyOS server holds at most one outstanding reply lease per
//! caller, so donation is always 0 or 1. Transitive chains are
//! bounded to MAX_PIP_DEPTH to prevent unbounded traversal.
//!
//! PIP operations may run after the caller drops its outer per-object lock.
//! `pip_donate` / `pip_undonate` therefore self-serialise raw-pointer relation
//! updates with the donor/caller's `tcb_lock`, then serialise priority/counter
//! bookkeeping with the holder's `tcb_lock`. `pip_cleanup` still acquires the
//! holder's `tcb_lock` to serialise against concurrent `pip_undonate`.
//!
//! `pip_donating_to` is a refcounted raw pointer — `set_pip_target` /
//! `clear_pip_target` on `Tcb` manage the reference count so the holder TCB
//! stays alive for the duration of the donation, making the `tcb_lock`
//! dereference safe even if the holder's last capability has been deleted.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::thread::Tcb;
use crate::task::state::ThreadState;

/// Maximum transitive chain depth to prevent unbounded traversal
pub const MAX_PIP_DEPTH: u8 = 8;

/// Donate priority from a caller (donor) to a server (holder).
///
/// If donor has an earlier deadline (lower priority value) than holder,
/// boost holder's effective priority to donor's level. Propagates
/// transitively through the `pip_donating_to` chain.
///
/// Lock discipline:
/// - Acquires `donor.tcb_lock` long enough to serialise `set_pip_target`
///   against concurrent suspend/destroy cleanup on the donor.
/// - Acquires `holder.tcb_lock` (and, hop by hop, the `tcb_lock` of each
///   transitive boost target) to serialise `pip_donation_count` /
///   `priority` mutations against concurrent `pip_undonate` and
///   `pip_cleanup` on the same TCB, and against other donors racing to
///   donate to the same holder.
/// - Never holds more than one per-TCB `tcb_lock` at a time: each chain
///   hop releases the outgoing lock before acquiring the next. This
///   keeps the ordering `per-object-lock → tcb_lock → scheduler.lock_cpu`
///   (documented in `CLAUDE.md > Lock Ordering`) irrespective of the
///   traversal order.
/// - `resort_ready_thread` is called with `tcb_lock` held; it acquires
///   `scheduler.lock_cpu` internally, matching the above ordering.
///
/// # Safety
/// - Both pointers must be valid TCBs.
pub unsafe fn pip_donate(donor: *mut Tcb, holder: *mut Tcb) {
    unsafe {
        if donor.is_null() || holder.is_null() || donor == holder {
            return;
        }

        (*donor).tcb_lock();
        let donor_priority = (*donor).priority;

        // Record the donation relationship first — this bumps holder's
        // capability refcount via `set_pip_target`, keeping it alive for
        // the rest of this function even if holder's last cap is dropped
        // concurrently.
        (*donor).set_pip_target(holder);
        (*donor).tcb_unlock();

        (*holder).tcb_lock();
        (*holder).pip_donation_count += 1;

        // Nothing to boost: donor's deadline is not earlier. The donation
        // relationship has been recorded so pip_undonate still decrements
        // the counter on reply.
        if donor_priority >= (*holder).priority {
            (*holder).tcb_unlock();
            return;
        }

        // Boost holder and propagate transitively through the donation
        // chain. Each hop hands off `tcb_lock` (release outgoing, acquire
        // next) so we never hold two TCB locks simultaneously — this
        // closes the door on a cycle-induced deadlock even if a bogus
        // `pip_donating_to` value ever appeared.
        let mut current = holder;
        let mut depth: u8 = 0;

        loop {
            (*current).priority = donor_priority;
            if (*current).state() == ThreadState::Runnable {
                crate::sched::scheduler::scheduler().resort_ready_thread(current);
            }
            let next = (*current).pip_donating_to;
            (*current).tcb_unlock();

            if next.is_null() {
                return;
            }
            depth += 1;
            if depth >= MAX_PIP_DEPTH {
                return;
            }

            (*next).tcb_lock();
            if donor_priority >= (*next).priority {
                (*next).tcb_unlock();
                return;
            }
            current = next;
        }
    }
}

/// Revert priority donation when the server replies.
///
/// Restores holder's priority to base_priority and clears the donation
/// relationship. If holder has no more donations, its priority returns
/// to base.
///
/// Acquires `caller.tcb_lock` to serialise relation teardown against
/// concurrent suspend/destroy cleanup, then `holder.tcb_lock` to serialise
/// priority restoration against `pip_cleanup`.
///
/// # Safety
/// - Both pointers must be valid TCBs (holder is kept alive by the
///   refcount held via `pip_donating_to`).
pub unsafe fn pip_undonate(holder: *mut Tcb, caller: *mut Tcb) {
    unsafe {
        if holder.is_null() || caller.is_null() {
            return;
        }

        // Self-donation is invalid, but handle it defensively without
        // reacquiring the same TCB lock through the normal holder path.
        if holder == caller {
            (*caller).tcb_lock();
            if (*caller).pip_donating_to == holder {
                (*caller).clear_pip_target();
            }
            (*caller).pip_donation_count = 0;
            (*caller).priority = (*caller).base_priority;
            if (*caller).state() == ThreadState::Runnable {
                crate::sched::scheduler::scheduler().resort_ready_thread(caller);
            }
            (*caller).tcb_unlock();
            return;
        }

        // Clear donation relationship (releases refcount on holder, but
        // the caller's own reply_tcb still keeps holder alive through
        // this function).
        (*caller).tcb_lock();
        if (*caller).pip_donating_to == holder {
            (*caller).clear_pip_target();
        }
        (*caller).tcb_unlock();

        (*holder).tcb_lock();

        if (*holder).pip_donation_count > 0 {
            (*holder).pip_donation_count -= 1;
        }

        // Restore to base priority if no more donations
        if (*holder).pip_donation_count == 0 {
            (*holder).priority = (*holder).base_priority;

            // If in ready queue, re-sort with restored priority
            if (*holder).state() == ThreadState::Runnable {
                crate::sched::scheduler::scheduler().resort_ready_thread(holder);
            }
        }

        (*holder).tcb_unlock();
    }
}

/// Clean up PIP state when a TCB is destroyed or suspended.
///
/// If this thread was donating to someone, undo the donation.
/// If this thread had donations, reset to base priority.
///
/// Acquires `holder.tcb_lock` to serialise against `pip_undonate`.
///
/// # Safety
/// - `tcb` must be a valid TCB pointer.
/// - per-object lock (MessagePipeCore / DataPipeCore or TCB) should be held or thread must be inactive.
pub unsafe fn pip_cleanup(tcb: *mut Tcb) {
    unsafe {
        if tcb.is_null() {
            return;
        }

        // If we were donating to someone, undo it.
        // The refcount held via pip_donating_to keeps holder alive for
        // the duration of this block. We acquire holder.tcb_lock to
        // serialise donation bookkeeping, do the bookkeeping, then
        // release the lock before clear_pip_target drops the refcount.
        let holder = (*tcb).pip_donating_to;
        if !holder.is_null() {
            if holder != tcb {
                (*holder).tcb_lock();
                if (*holder).pip_donation_count > 0 {
                    (*holder).pip_donation_count -= 1;
                }
                if (*holder).pip_donation_count == 0 {
                    (*holder).priority = (*holder).base_priority;
                    if (*holder).state() == ThreadState::Runnable {
                        crate::sched::scheduler::scheduler().resort_ready_thread(holder);
                    }
                }
                (*holder).tcb_unlock();
            }
            (*tcb).clear_pip_target(); // releases refcount on holder
        }

        // Reset own PIP state
        (*tcb).pip_donation_count = 0;
        (*tcb).priority = (*tcb).base_priority;
    }
}
