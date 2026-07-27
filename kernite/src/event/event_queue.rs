// SPDX-License-Identifier: GPL-2.0-only
//! Bounded event queue.
//!
//! Receives `EventRecord` entries from `Watch` registrations, IRQ
//! sources, `Timer` fires, fault deliveries, and userspace user-event
//! producers. A blocked thread waiting on the queue (`EQ_WAIT`) is
//! awoken as soon as one record is enqueued.
//!
//! Overflow policy: when the ring is full a single dropped-event
//! record is fused — one slot reserved for `EVENT_STATUS_DROPPED` is
//! always kept available so the consumer learns about loss in order.
//! Subsequent overflows bump the `dropped` counter without consuming
//! more ring slots; the next consumer drain converts the counter into
//! the dropped record's `payload0` and clears it.

use core::sync::atomic::{AtomicU64, Ordering};

const EVENT_STATUS_DROPPED: u32 = uapi::KERNITE_EVENT_STATUS_DROPPED;
const EVENT_STATUS_OBJECT_CLOSED: u32 = uapi::KERNITE_EVENT_STATUS_OBJECT_CLOSED;
const EVENT_STATUS_OK: u32 = uapi::KERNITE_EVENT_STATUS_OK;
const EVENT_TYPE_OVERFLOW: u32 = uapi::KERNITE_EVENT_TYPE_OVERFLOW;
const EVENT_TYPE_STATE: u32 = uapi::KERNITE_EVENT_TYPE_STATE;
const STATE_CLOSED: u64 = uapi::KERNITE_STATE_CLOSED as u64;
const STATE_PEER_CLOSED: u64 = uapi::KERNITE_STATE_PEER_CLOSED as u64;
const STATE_READABLE: u64 = uapi::KERNITE_STATE_READABLE as u64;
const STATE_SIGNALED: u64 = uapi::KERNITE_STATE_SIGNALED as u64;
const STATE_OVERRUN: u64 = uapi::KERNITE_STATE_OVERRUN as u64;
const EVENT_TYPE_IRQ: u32 = uapi::KERNITE_EVENT_TYPE_IRQ;

use crate::cap::ObjectType;
use crate::cap::object::KernelObject;
use crate::event::irq::IrqHandler;
use crate::event::record::EventRecord;
use crate::event::watcher_list::WatcherList;
use crate::mm::SpinLock;
use crate::sched::thread::Tcb;

/// Ring capacity in records. Picked to comfortably hold a tick's
/// worth of producer fan-in (IRQ + timer + watcher fires + user
/// events) without engaging the dropped-record fallback in normal
/// operation.
pub const EVENT_QUEUE_CAPACITY: usize = 128;

#[repr(C)]
pub struct EventQueue {
    pub header: KernelObject,
    pub state_flags: AtomicU64,
    pub watcher_list: WatcherList,
    pub lock: SpinLock,
    pub head: u32,
    pub tail: u32,
    pub used: u32,
    pub _pad: u32,
    /// Number of records that overflowed and were rolled into a single
    /// dropped record at the consumer end. Cleared when that record is
    /// drained.
    pub dropped: AtomicU64,
    /// Whether a `STATE_DROPPED` placeholder has been emitted into the
    /// ring tail. While set, additional overflows just bump `dropped`.
    pub dropped_pending: AtomicU64,
    /// FIFO of TCBs blocked in `EQ_WAIT`.
    pub waiter_head: *mut Tcb,
    pub waiter_tail: *mut Tcb,
    /// FIFO of `IrqHandler`s with a pending interrupt — drained before
    /// `ring` so interrupt delivery has priority and never competes for ring
    /// slots. Linked intrusively via the handler's `eq_next`.
    pub irq_head: *mut IrqHandler,
    pub irq_tail: *mut IrqHandler,
    pub ring: [EventRecord; EVENT_QUEUE_CAPACITY],
}

unsafe impl Sync for EventQueue {}

/// Outcome of a deadline-bounded `EQ_WAIT` block.
pub enum EqWaitOutcome {
    /// A record was dequeued.
    Record(EventRecord),
    /// The queue was closed / torn down while waiting.
    Closed,
    /// The absolute deadline expired before a record arrived.
    TimedOut,
}

impl EventQueue {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::EventQueue, 0),
            state_flags: AtomicU64::new(0),
            watcher_list: WatcherList::new(),
            lock: SpinLock::new(),
            head: 0,
            tail: 0,
            used: 0,
            _pad: 0,
            dropped: AtomicU64::new(0),
            dropped_pending: AtomicU64::new(0),
            waiter_head: core::ptr::null_mut(),
            waiter_tail: core::ptr::null_mut(),
            irq_head: core::ptr::null_mut(),
            irq_tail: core::ptr::null_mut(),
            ring: [EventRecord::empty(); EVENT_QUEUE_CAPACITY],
        }
    }

    /// Push a record onto the queue.
    ///
    /// Returns `true` if the record was placed in the ring, `false`
    /// if the ring was full and the producer's record was rolled into
    /// the dropped counter instead.
    ///
    /// # Safety
    /// Caller must hold no kernel locks below the EventQueue lock in
    /// the lock-ordering hierarchy.
    pub unsafe fn enqueue(&mut self, record: EventRecord) -> bool {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();

        let mut overrun_edge = false;
        let stored = if self.used as usize == EVENT_QUEUE_CAPACITY {
            self.dropped.fetch_add(1, Ordering::AcqRel);
            self.dropped_pending.store(1, Ordering::Release);
            // Raise STATE_OVERRUN so a Watch on OVERRUN fires; the bit is
            // cleared when the synthesized EVENT_TYPE_OVERFLOW record is
            // finally dequeued (see dequeue_locked).
            let prev = self.state_flags.fetch_or(STATE_OVERRUN, Ordering::Release);
            overrun_edge = (prev & STATE_OVERRUN) == 0;
            false
        } else {
            let slot = self.tail as usize;
            self.ring[slot] = record;
            self.tail = ((self.tail as usize + 1) % EVENT_QUEUE_CAPACITY) as u32;
            self.used += 1;
            true
        };

        let (publish_edge, waiter) = self.arm_readable_locked();

        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if overrun_edge {
            unsafe { self.watcher_list.publish(STATE_OVERRUN) };
        }
        unsafe { self.publish_readable_and_wake(publish_edge, waiter) };

        stored
    }

    /// Set `STATE_READABLE` and pop one `EQ_WAIT` waiter. Caller holds
    /// `self.lock`. Returns whether this raised the 0→1 readable edge (so the
    /// caller publishes to watchers) and the waiter to wake. The publish and
    /// wake MUST run after the lock is released — see
    /// [`Self::publish_readable_and_wake`].
    fn arm_readable_locked(&mut self) -> (bool, *mut Tcb) {
        let prev = self.state_flags.fetch_or(STATE_READABLE, Ordering::Release);
        let waiter = self.waiter_pop_head_locked();
        ((prev & STATE_READABLE) == 0, waiter)
    }

    /// Publish the readable edge to watchers and wake the popped waiter.
    /// MUST run after `self.lock` is released: publishing under the queue
    /// lock can deadlock through a watch fire path, and the wake plan touches
    /// the scheduler.
    ///
    /// # Safety
    /// `waiter` must be a waiter popped by [`Self::arm_readable_locked`] (or
    /// null).
    unsafe fn publish_readable_and_wake(&mut self, publish_edge: bool, waiter: *mut Tcb) {
        if publish_edge {
            unsafe { self.watcher_list.publish(STATE_READABLE) };
        }
        if !waiter.is_null() {
            unsafe {
                let _ = crate::sched::control::execute_wake_plan(
                    crate::sched::control::eq_wait_wake_plan(waiter),
                );
                crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(waiter);
            }
        }
    }

    /// Link an `IrqHandler` onto the priority interrupt lane.
    /// Called from `signal_fire` in interrupt context, under `IRQ_LOCK`. The
    /// handler is the reserved delivery slot: while linked it occupies no
    /// ring capacity and cannot be dropped. A handler already on the lane
    /// coalesces — re-fires before the pending delivery is dequeued fold into
    /// the one queued entry.
    ///
    /// # Safety
    /// `handler` must point at a live `IrqHandler` bound to this queue. Its
    /// `eq_next` / `eq_queued` are owned by this queue's lock while linked.
    pub unsafe fn link_irq(&mut self, handler: *mut IrqHandler) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();

        let armed = unsafe {
            if (*handler).eq_queued.load(Ordering::Relaxed) {
                false
            } else {
                (*handler).eq_queued.store(true, Ordering::Relaxed);
                (*handler)
                    .eq_next
                    .store(core::ptr::null_mut(), Ordering::Relaxed);
                if self.irq_tail.is_null() {
                    self.irq_head = handler;
                } else {
                    (*self.irq_tail).eq_next.store(handler, Ordering::Relaxed);
                }
                self.irq_tail = handler;
                true
            }
        };

        let (publish_edge, waiter) = if armed {
            self.arm_readable_locked()
        } else {
            (false, core::ptr::null_mut())
        };

        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if armed {
            unsafe { self.publish_readable_and_wake(publish_edge, waiter) };
        }
    }

    /// Remove an `IrqHandler` from the interrupt lane by pointer.
    /// Called from unbind / handler cleanup under `IRQ_LOCK`. No-op if the
    /// handler is not linked. Never matches by cookie.
    ///
    /// # Safety
    /// `handler` must point at a live `IrqHandler`; the caller serializes
    /// against `link_irq` via `IRQ_LOCK`.
    pub unsafe fn unlink_irq(&mut self, handler: *mut IrqHandler) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();

        unsafe {
            if (*handler).eq_queued.load(Ordering::Relaxed) {
                let next = (*handler).eq_next.load(Ordering::Relaxed);
                if self.irq_head == handler {
                    self.irq_head = next;
                    if self.irq_tail == handler {
                        self.irq_tail = core::ptr::null_mut();
                    }
                } else {
                    let mut prev = self.irq_head;
                    while !prev.is_null() && (*prev).eq_next.load(Ordering::Relaxed) != handler {
                        prev = (*prev).eq_next.load(Ordering::Relaxed);
                    }
                    if !prev.is_null() {
                        (*prev).eq_next.store(next, Ordering::Relaxed);
                        if self.irq_tail == handler {
                            self.irq_tail = prev;
                        }
                    }
                }
                (*handler)
                    .eq_next
                    .store(core::ptr::null_mut(), Ordering::Relaxed);
                (*handler).eq_queued.store(false, Ordering::Relaxed);

                if self.irq_head.is_null()
                    && self.used == 0
                    && self.dropped_pending.load(Ordering::Acquire) == 0
                {
                    self.state_flags
                        .fetch_and(!STATE_READABLE, Ordering::Release);
                }
            }
        }

        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
    }

    /// Drain one record. Returns `None` if empty.
    pub fn dequeue(&mut self) -> Option<EventRecord> {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();

        let result = self.dequeue_locked();

        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        result
    }

    fn dequeue_locked(&mut self) -> Option<EventRecord> {
        // Drain the priority interrupt lane before the ring, synthesizing the
        // IRQ record from the popped handler's fields.
        if !self.irq_head.is_null() {
            let handler = self.irq_head;
            unsafe {
                self.irq_head = (*handler).eq_next.load(Ordering::Relaxed);
                (*handler)
                    .eq_next
                    .store(core::ptr::null_mut(), Ordering::Relaxed);
                (*handler).eq_queued.store(false, Ordering::Relaxed);
            }
            if self.irq_head.is_null() {
                self.irq_tail = core::ptr::null_mut();
            }
            let mut record = EventRecord::empty();
            record.kind = EVENT_TYPE_IRQ;
            record.status = EVENT_STATUS_OK;
            record.state_set = STATE_SIGNALED;
            unsafe {
                record.cookie = (*handler).bound_cookie.load(Ordering::Acquire);
                record.object_id = (*handler).irq_num as u64;
                record.payload0 = (*handler).irq_num as u64;
            }
            if self.irq_head.is_null()
                && self.used == 0
                && self.dropped_pending.load(Ordering::Acquire) == 0
            {
                self.state_flags
                    .fetch_and(!STATE_READABLE, Ordering::Release);
            }
            return Some(record);
        }

        if self.used == 0 {
            if self.dropped_pending.load(Ordering::Acquire) != 0 {
                let count = self.dropped.swap(0, Ordering::AcqRel);
                self.dropped_pending.store(0, Ordering::Release);
                let mut record = EventRecord::empty();
                record.kind = EVENT_TYPE_OVERFLOW;
                record.status = EVENT_STATUS_DROPPED;
                record.payload0 = count;
                // The drop count has now been delivered to the consumer, so
                // acknowledge the overrun: clear STATE_OVERRUN alongside the
                // drained STATE_READABLE.
                self.state_flags
                    .fetch_and(!(STATE_READABLE | STATE_OVERRUN), Ordering::Release);
                return Some(record);
            }
            self.state_flags
                .fetch_and(!STATE_READABLE, Ordering::Release);
            return None;
        }

        let slot = self.head as usize;
        let record = self.ring[slot];
        self.head = ((self.head as usize + 1) % EVENT_QUEUE_CAPACITY) as u32;
        self.used -= 1;

        if self.used == 0 && self.dropped_pending.load(Ordering::Acquire) == 0 {
            self.state_flags
                .fetch_and(!STATE_READABLE, Ordering::Release);
        }

        Some(record)
    }

    /// Remove every queued record whose `cookie` matches. Called by
    /// `WATCH_CANCEL` to drop already-enqueued state events the caller
    /// will no longer process. Records already drained by `EQ_WAIT`
    /// cannot be recalled — the userland dispatcher must validate the
    /// cookie's `live_gen` field. `EQ_WAIT` waiters and the
    /// dropped-event counter are not affected. Returns the number of
    /// records purged.
    pub fn purge_matching(&mut self, cookie: u64) -> u32 {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();

        if self.used == 0 {
            self.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return 0;
        }

        // Two-pointer compaction: walk every used slot starting at
        // `head`, copy non-matching records back at the dst cursor,
        // skip matching ones. After the walk, `tail` lands at the dst
        // cursor and `used` reflects the surviving count.
        let mut src = self.head as usize;
        let mut dst = self.head as usize;
        let mut surviving: u32 = 0;
        let mut removed: u32 = 0;
        let total = self.used;

        for _ in 0..total {
            let rec = self.ring[src];
            if rec.cookie == cookie {
                removed += 1;
            } else {
                if dst != src {
                    self.ring[dst] = rec;
                }
                dst = (dst + 1) % EVENT_QUEUE_CAPACITY;
                surviving += 1;
            }
            src = (src + 1) % EVENT_QUEUE_CAPACITY;
        }

        self.tail = dst as u32;
        self.used = surviving;

        // Never clear readable while the interrupt lane is non-empty; the lane
        // is purged only by pointer (unbind / cleanup), never by cookie here.
        if self.used == 0
            && self.irq_head.is_null()
            && self.dropped_pending.load(Ordering::Acquire) == 0
        {
            self.state_flags
                .fetch_and(!STATE_READABLE, Ordering::Release);
        }

        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        removed
    }

    /// Block the current TCB on this queue until a record arrives, the
    /// queue is torn down, or the absolute `deadline` (monotonic ns;
    /// `u64::MAX` blocks forever) expires.
    ///
    /// # Safety
    /// Must be called from current-thread context.
    pub unsafe fn wait_block(&mut self, deadline: u64) -> EqWaitOutcome {
        loop {
            let irq = unsafe { crate::mm::save_irq_disable() };
            self.lock.lock();

            if (self.state_flags.load(Ordering::Acquire) & (STATE_CLOSED | STATE_PEER_CLOSED)) != 0
            {
                self.lock.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                return EqWaitOutcome::Closed;
            }

            if let Some(rec) = self.dequeue_locked() {
                self.lock.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                return EqWaitOutcome::Record(rec);
            }

            let scheduler = crate::sched::scheduler::scheduler();
            let current = scheduler.current();
            if current.is_null() {
                self.lock.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                return EqWaitOutcome::Closed;
            }

            // Absolute deadline; an already-expired one returns without
            // parking. `u64::MAX` never expires.
            if deadline != u64::MAX && crate::arch::now_ns() >= deadline {
                self.lock.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                return EqWaitOutcome::TimedOut;
            }

            unsafe {
                self.waiter_push_tail_locked(current);
                let tcb = &mut *current;
                tcb.wait_object = self as *mut EventQueue as *mut core::ffi::c_void;
                tcb.wait_seq = tcb.wait_seq.wrapping_add(1);
                // Cleared so the post-reschedule read distinguishes a
                // deadline wake (`wake_ipc_timeout` writes `TimedOut`)
                // from a normal publish wake (which leaves it `0`).
                tcb.futex_wakeup_result = 0;
                tcb.tcb_lock();
                crate::task::wait::prepare_blocked_reason_locked(
                    tcb,
                    crate::sched::thread::BlockedReason::EventQueueWait,
                );
                tcb.tcb_unlock();
            }

            self.lock.unlock();
            unsafe {
                if deadline != u64::MAX {
                    crate::sched::deadline_queue::arm_thread_ipc_timeout(current, deadline);
                }
                scheduler.reschedule();
                if deadline != u64::MAX {
                    let _ = crate::sched::deadline_queue::cancel_thread(current);
                }
                crate::mm::restore_irq(irq);

                let result = (*current).futex_wakeup_result;
                (*current).futex_wakeup_result = 0;
                if result == crate::syscall::SyscallError::TimedOut as u64 {
                    // The deadline wake only flipped us Runnable; our waiter
                    // node may still be queued. Remove it so a later publish
                    // does not pop a stale node.
                    self.cancel_waiter(current);
                    return EqWaitOutcome::TimedOut;
                }
            }
            // Normal publish wake — loop to re-check closed / dequeue.
        }
    }

    /// Cancel any waiter whose blocked context matches `tcb`.
    pub fn cancel_waiter(&mut self, tcb: *mut Tcb) -> bool {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();
        let removed = self.waiter_remove_locked(tcb);
        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        removed
    }

    /// Push a closed placeholder + assert CLOSED so any current waiter
    /// returns `EVENT_STATUS_OBJECT_CLOSED`.
    pub fn signal_closed(&mut self) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();

        let mut record = EventRecord::empty();
        record.kind = EVENT_TYPE_STATE;
        record.status = EVENT_STATUS_OBJECT_CLOSED;
        record.state_set = STATE_CLOSED;
        let _ = EVENT_STATUS_OK;

        if (self.used as usize) < EVENT_QUEUE_CAPACITY {
            let slot = self.tail as usize;
            self.ring[slot] = record;
            self.tail = ((self.tail as usize + 1) % EVENT_QUEUE_CAPACITY) as u32;
            self.used += 1;
        }

        self.state_flags
            .fetch_or(STATE_CLOSED | STATE_READABLE, Ordering::Release);

        loop {
            let waiter = self.waiter_pop_head_locked();
            if waiter.is_null() {
                break;
            }
            unsafe {
                let _ = crate::sched::control::execute_wake_plan(
                    crate::sched::control::eq_wait_wake_plan(waiter),
                );
                crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(waiter);
            }
        }

        self.lock.unlock();
        unsafe {
            self.watcher_list.publish(STATE_CLOSED | STATE_READABLE);
            crate::mm::restore_irq(irq);
        }
    }

    fn waiter_push_tail_locked(&mut self, tcb: *mut Tcb) {
        unsafe { (*tcb).eq_wait_next = core::ptr::null_mut() };
        // Pin the TCB via `sched_ref` for the waiter slot before the
        // pointer becomes reachable from `waiter_head`. Released in
        // `wake_thread` (drain path) or in
        // `detach_thread_wait_queues` via `cancel_waiter` (destroy
        // path).
        unsafe { (*tcb).sched_ref_inc() };
        if self.waiter_tail.is_null() {
            self.waiter_head = tcb;
        } else {
            unsafe { (*self.waiter_tail).eq_wait_next = tcb };
        }
        self.waiter_tail = tcb;
    }

    fn waiter_pop_head_locked(&mut self) -> *mut Tcb {
        let head = self.waiter_head;
        if head.is_null() {
            return core::ptr::null_mut();
        }
        let next = unsafe { (*head).eq_wait_next };
        self.waiter_head = next;
        if next.is_null() {
            self.waiter_tail = core::ptr::null_mut();
        }
        unsafe { (*head).eq_wait_next = core::ptr::null_mut() };
        head
    }

    fn waiter_remove_locked(&mut self, tcb: *mut Tcb) -> bool {
        let mut prev: *mut Tcb = core::ptr::null_mut();
        let mut cur = self.waiter_head;
        while !cur.is_null() {
            let next = unsafe { (*cur).eq_wait_next };
            if cur == tcb {
                if prev.is_null() {
                    self.waiter_head = next;
                } else {
                    unsafe { (*prev).eq_wait_next = next };
                }
                if self.waiter_tail == cur {
                    self.waiter_tail = prev;
                }
                unsafe { (*cur).eq_wait_next = core::ptr::null_mut() };
                return true;
            }
            prev = cur;
            cur = next;
        }
        false
    }
}
