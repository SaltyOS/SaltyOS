// SPDX-License-Identifier: GPL-2.0-only
//! Timer object — driven by the global ns-precision deadline queue.
//!
//! Each `Timer` is a capability object bound to an `EventQueue`.
//! `TIMER_SET` arms it with an absolute monotonic deadline (and an
//! optional repeat period); the timer's embedded `DeadlineNode` is
//! inserted into `crate::sched::deadline_queue`. When the per-CPU
//! tick path observes the deadline crossing, dispatch calls
//! `Timer::fire_from_dispatch` which asserts `STATE_SIGNALED`, fires
//! any registered watches, enqueues an `EVENT_TYPE_TIMER` record,
//! and re-arms a repeating timer at the next deadline (with
//! missed-period coalescing — `next_deadline > now`).

use core::sync::atomic::{AtomicU64, Ordering};

const EVENT_STATUS_OK: u32 = uapi::KERNITE_EVENT_STATUS_OK;
const EVENT_TYPE_TIMER: u32 = uapi::KERNITE_EVENT_TYPE_TIMER;
const STATE_SIGNALED: u64 = uapi::KERNITE_STATE_SIGNALED as u64;

use crate::cap::ObjectType;
use crate::cap::object::KernelObject;
use crate::event::event_queue::EventQueue;
use crate::event::record::EventRecord;
use crate::event::watcher_list::WatcherList;
use crate::mm::SpinLock;
use crate::sched::deadline_queue::{DEADLINE_INACTIVE, DeadlineNode};

/// Sentinel deadline meaning "not armed". Greater than any real
/// monotonic time. Mirrors `deadline_queue::DEADLINE_INACTIVE`.
pub const TIMER_DEADLINE_INACTIVE: u64 = DEADLINE_INACTIVE;

#[repr(C)]
pub struct Timer {
    pub header: KernelObject,
    pub state_flags: AtomicU64,
    pub watcher_list: WatcherList,
    pub deadline_ns: AtomicU64,
    pub period_ns: u64,
    pub cookie: u64,
    pub key: u64,
    pub bound_eq: *mut EventQueue,
    /// Per-timer lock. Serialises `set` / `cancel` against
    /// `fire_from_dispatch`'s snapshot of `bound_eq` and the
    /// `deadline_seq` validation, so a cancel cannot release the EQ
    /// underneath a concurrent fire on a different CPU.
    pub timer_lock: SpinLock,
    /// Monotonically incremented every time `set` arms the timer.
    /// `fire_from_dispatch` rejects stale dispatches whose `seq`
    /// snapshot no longer matches — closes the cancel-vs-fire race.
    pub deadline_seq: AtomicU64,
    /// Embedded deadline-queue node — inserted on `set`, removed on
    /// `cancel` or `fire_from_dispatch`.
    pub deadline_node: DeadlineNode,
}

unsafe impl Sync for Timer {}

impl Timer {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Timer, 0),
            state_flags: AtomicU64::new(0),
            watcher_list: WatcherList::new(),
            deadline_ns: AtomicU64::new(TIMER_DEADLINE_INACTIVE),
            period_ns: 0,
            cookie: 0,
            key: 0,
            bound_eq: core::ptr::null_mut(),
            timer_lock: SpinLock::new(),
            deadline_seq: AtomicU64::new(0),
            deadline_node: DeadlineNode::new(),
        }
    }

    /// Arm the timer with a new `bound_eq`.
    ///
    /// `deadline_ns` is an absolute monotonic time; `period_ns = 0`
    /// makes the timer one-shot, otherwise the timer auto-rearms with
    /// `deadline_ns + period_ns` after each fire.
    ///
    /// The caller is responsible for incrementing `bound_eq`'s
    /// refcount before passing it in; this function takes ownership
    /// of that ref. The previously bound EQ (if any) is released as
    /// part of the swap.
    ///
    /// # Safety
    /// `bound_eq` must point at a live `EventQueue` whose refcount
    /// was bumped by the caller.
    pub unsafe fn set(
        &mut self,
        deadline_ns: u64,
        period_ns: u64,
        bound_eq: *mut EventQueue,
        key: u64,
        cookie: u64,
    ) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.timer_lock.lock();

        // Bump the sequence so any in-flight dispatch for a prior arm is
        // rejected as stale. This does NOT detach the deadline-queue node;
        // that happens via `cancel_timer` below before re-arming.
        self.cancel_locked();

        let prev_eq = self.bound_eq;
        self.bound_eq = bound_eq;
        self.period_ns = period_ns;
        self.cookie = cookie;
        self.key = key;
        self.deadline_ns.store(deadline_ns, Ordering::Release);
        let seq = self.deadline_seq.fetch_add(1, Ordering::AcqRel) + 1;

        // Insert into the global deadline queue. The queue takes a
        // membership pin on `self` (KernelObject ref bump).
        let timer_ptr = self as *mut Timer;

        self.timer_lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        // Re-arm. Each iteration first detaches any current membership:
        // `cancel_timer` turns a `Queued` node (e.g. one a concurrent periodic
        // re-arm just installed) back to `Idle` and drops its pin; it is a
        // no-op for an `Idle` / `Dispatching` node. Then arm. `arm_timer`
        // returns false only while the node is `Dispatching` — an in-flight
        // fire on another CPU owns it; that fire observes our bumped
        // `deadline_seq`, is dropped as stale, and releases the node to `Idle`.
        // This thread is never the dispatcher, so the node reaches `Idle` and
        // the loop terminates promptly.
        loop {
            let _ = unsafe { crate::sched::deadline_queue::cancel_timer(timer_ptr) };
            if unsafe { crate::sched::deadline_queue::arm_timer(timer_ptr, deadline_ns, seq) } {
                break;
            }
            core::hint::spin_loop();
        }

        if !prev_eq.is_null() {
            unsafe {
                crate::cap::release_object(prev_eq as *mut KernelObject, ObjectType::EventQueue);
            }
        }
    }

    /// Disarm the timer if active. Releases the bound EQ ref as the
    /// channel is no longer producing into it. Returns `true` if it
    /// was armed.
    pub fn cancel(&mut self) -> bool {
        let timer_ptr = self as *mut Timer;
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.timer_lock.lock();

        let was_armed = self.cancel_locked();
        let prev_eq = self.bound_eq;
        self.bound_eq = core::ptr::null_mut();

        self.timer_lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        // Detach from deadline queue OUTSIDE timer_lock — queue cancel
        // releases the membership pin (KernelObject refcount drop).
        let _ = unsafe { crate::sched::deadline_queue::cancel_timer(timer_ptr) };

        if !prev_eq.is_null() {
            unsafe {
                crate::cap::release_object(prev_eq as *mut KernelObject, ObjectType::EventQueue);
            }
        }
        was_armed
    }

    fn cancel_locked(&mut self) -> bool {
        let was_armed = self
            .deadline_ns
            .swap(TIMER_DEADLINE_INACTIVE, Ordering::AcqRel)
            != TIMER_DEADLINE_INACTIVE;
        // Bump seq so any in-flight dispatch with the previous seq is
        // rejected as stale.
        self.deadline_seq.fetch_add(1, Ordering::AcqRel);
        was_armed
    }

    /// Returns the remaining time until fire, or `None` if disarmed.
    pub fn query(&self, now_ns: u64) -> Option<u64> {
        let dl = self.deadline_ns.load(Ordering::Acquire);
        if dl == TIMER_DEADLINE_INACTIVE {
            None
        } else {
            Some(dl.saturating_sub(now_ns))
        }
    }

    /// Dispatch entry point — called by
    /// `crate::sched::deadline_queue::check_wakeups` once a popped
    /// node's `seq` has been validated against the live timer. Asserts
    /// `SIGNALED` (publishing to any registered watches) and enqueues
    /// the timer record. For a repeating timer it returns the next
    /// `(deadline, seq)` (with missed-period coalescing — `next_deadline >
    /// now`) for the dispatcher to re-arm AFTER releasing the node to `Idle`;
    /// returns `None` for a one-shot. Arming here, while the node is still
    /// `Dispatching`, would be refused by `arm_timer`'s Idle→Queued CAS.
    ///
    /// `bound_eq` is snapshotted under `timer_lock` with the EQ's
    /// refcount bumped before the lock drops, so a concurrent
    /// `cancel` on another CPU cannot release the EventQueue while
    /// this fire is still using it. The transient `STATE_SIGNALED`
    /// bit is cleared at the end of the fire so the next periodic
    /// fire can re-publish.
    ///
    /// # Safety
    /// Caller must have popped the timer from the deadline queue and
    /// validated the popped node's `seq` against `Timer::deadline_seq`.
    pub unsafe fn fire_from_dispatch(
        timer: *mut Timer,
        now_ns: u64,
        dispatch_seq: u64,
    ) -> Option<(u64, u64)> {
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*timer).timer_lock.lock() };

        // Recheck `seq` under `timer_lock`. A `set()` on another CPU may have
        // bumped `deadline_seq` and replaced `bound_eq` / `cookie` /
        // `deadline_ns` between the dispatcher popping this node and our taking
        // the lock. If superseded, do NOT publish or mutate any field — the
        // live arm owns the timer; proceeding would fire a stale cookie/EQ or
        // overwrite the freshly-armed `deadline_ns` with `INACTIVE`.
        if unsafe { (*timer).deadline_seq.load(Ordering::Acquire) } != dispatch_seq {
            unsafe { (*timer).timer_lock.unlock() };
            unsafe { crate::mm::restore_irq(irq) };
            return None;
        }

        let eq_local = unsafe { (*timer).bound_eq };
        if !eq_local.is_null() {
            unsafe {
                crate::cap::increment_refcount(eq_local as *mut KernelObject);
            }
        }
        let cookie = unsafe { (*timer).cookie };
        let key = unsafe { (*timer).key };
        let period_ns = unsafe { (*timer).period_ns };

        let prev = unsafe {
            (*timer)
                .state_flags
                .fetch_or(STATE_SIGNALED, Ordering::Release)
        };
        let publish_bits = if (prev & STATE_SIGNALED) == 0 {
            STATE_SIGNALED
        } else {
            0
        };
        let watchers = unsafe { &mut (*timer).watcher_list as *mut WatcherList };

        // Compute next deadline + bump seq under the lock so a
        // concurrent cancel sees the new arm coherently.
        let mut reinsert_deadline: u64 = TIMER_DEADLINE_INACTIVE;
        let mut reinsert_seq: u64 = 0;
        if period_ns > 0 {
            // Missed-period coalescing — if `now` already passed
            // multiple periods, advance to the next future period
            // boundary so the dispatch loop does not tight-loop.
            let cur_deadline = unsafe { (*timer).deadline_ns.load(Ordering::Acquire) };
            let mut next = cur_deadline.saturating_add(period_ns);
            if next <= now_ns {
                let lag = now_ns.saturating_sub(cur_deadline);
                let skipped_periods = lag / period_ns + 1;
                next = cur_deadline.saturating_add(period_ns.saturating_mul(skipped_periods));
            }
            unsafe { (*timer).deadline_ns.store(next, Ordering::Release) };
            reinsert_deadline = next;
            reinsert_seq = unsafe { (*timer).deadline_seq.fetch_add(1, Ordering::AcqRel) + 1 };
        } else {
            unsafe {
                (*timer)
                    .deadline_ns
                    .store(TIMER_DEADLINE_INACTIVE, Ordering::Release);
            }
        }

        unsafe { (*timer).timer_lock.unlock() };
        unsafe { crate::mm::restore_irq(irq) };

        if publish_bits != 0 {
            unsafe { (*watchers).publish(publish_bits) };
        }

        if !eq_local.is_null() {
            let mut record = EventRecord::empty();
            record.kind = EVENT_TYPE_TIMER;
            record.status = EVENT_STATUS_OK;
            record.cookie = cookie;
            record.object_id = key;
            record.state_set = STATE_SIGNALED;
            record.payload0 = now_ns;
            unsafe {
                let _ = (*eq_local).enqueue(record);
                crate::cap::release_object(eq_local as *mut KernelObject, ObjectType::EventQueue);
            }
        }

        // Drop the transient SIGNALED bit so the next fire can
        // re-trigger the watcher chain.
        unsafe {
            (*timer)
                .state_flags
                .fetch_and(!STATE_SIGNALED, Ordering::Release);
        }

        // Hand the periodic reinsert back to the dispatcher; it re-arms AFTER
        // transitioning the node to `Idle`. Arming here (still `Dispatching`)
        // would be refused by `arm_timer`'s Idle→Queued CAS.
        if reinsert_deadline != TIMER_DEADLINE_INACTIVE {
            Some((reinsert_deadline, reinsert_seq))
        } else {
            None
        }
    }
}

/// Arch-facing timer entry: drives the global ns-precision deadline
/// queue and the scheduler tick. Called from the per-CPU timer
/// interrupt after EOI. The lockless `peek_expired` short-circuits
/// when no deadline is currently due.
pub fn dispatch_tick(interrupted_user_mode: bool) {
    let now_ns = crate::arch::now_ns();
    if crate::sched::deadline_queue::peek_expired(now_ns) {
        crate::sched::deadline_queue::check_wakeups(now_ns);
    }
    crate::sched::timer_tick(interrupted_user_mode);
}
