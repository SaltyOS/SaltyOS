// SPDX-License-Identifier: GPL-2.0-only
//! Per-watchable-object watcher list.
//!
//! Each watchable kernel object embeds a `WatcherList` and asserts /
//! clears bits in its `state_flags` while holding the list's lock. The
//! `publish` helper walks the list, fires every `Watch` whose mask
//! intersects the asserted bits, and removes one-shot fires from the
//! list atomically with the state-flag mutation — closing the
//! lost-wakeup window between assert and notify.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::ObjectType;
use crate::cap::object::KernelObject;
use crate::event::event_queue::EventQueue;
use crate::event::record::EventRecord;
use crate::event::watch::Watch;
use crate::mm::SpinLock;

const EVENT_TYPE_STATE: u32 = uapi::KERNITE_EVENT_TYPE_STATE;
const EVENT_STATUS_OK: u32 = uapi::KERNITE_EVENT_STATUS_OK;
const EVENT_STATUS_OBJECT_CLOSED: u32 = uapi::KERNITE_EVENT_STATUS_OBJECT_CLOSED;

#[repr(C)]
pub struct WatcherList {
    /// List head behind `UnsafeCell` so `publish` / `insert` / `remove` /
    /// `drain_closed` take `&self`: the list is concurrently published from
    /// interrupt context (an IRQ fire on a watched object) and mutated from
    /// syscall context, serialized by `lock`, never exclusively owned.
    pub head: UnsafeCell<*mut Watch>,
    pub lock: SpinLock,
    /// Monotonically incremented once per `publish` call. Used to
    /// stamp watches as "already fired in this publish" so subsequent
    /// `FIRE_BATCH_SIZE` chunks of the same publish skip them — a
    /// list of >32 repeating watches would otherwise re-walk from the
    /// head and re-fire the same matches forever.
    pub publish_epoch: AtomicU64,
}

unsafe impl Sync for WatcherList {}

impl WatcherList {
    pub const fn new() -> Self {
        Self {
            head: UnsafeCell::new(core::ptr::null_mut()),
            lock: SpinLock::new(),
            publish_epoch: AtomicU64::new(0),
        }
    }

    /// Insert a `Watch` into this list. Caller owns the watch's
    /// linkage state and is registering it for the first time.
    ///
    /// # Safety
    /// `watch` must be a live `Watch` whose `next_in_object` is null
    /// and whose `watched_object` matches the object owning this list.
    pub unsafe fn insert(&self, watch: *mut Watch) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();
        let current_epoch = self.publish_epoch.load(Ordering::Acquire);
        let head = self.head.get();
        unsafe {
            // The stamp is scoped to this WatcherList, so reset reused
            // Watch objects to this list's current epoch before linking.
            (*watch)
                .last_publish_epoch
                .store(current_epoch, Ordering::Release);
            (*watch).next_in_object = *head;
            *head = watch;
        }
        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
    }

    /// Remove a specific watch from this list. Used by `WATCH_DISARM`
    /// and by the watched object's destroy path.
    ///
    /// Returns true if the watch was found and removed.
    pub unsafe fn remove(&self, watch: *mut Watch) -> bool {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();
        let removed = unsafe { self.remove_locked(watch) };
        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        removed
    }

    pub unsafe fn remove_locked(&self, watch: *mut Watch) -> bool {
        let mut prev_link: *mut *mut Watch = self.head.get();
        unsafe {
            let mut cur = *prev_link;
            while !cur.is_null() {
                let next = (*cur).next_in_object;
                if cur == watch {
                    *prev_link = next;
                    (*cur).next_in_object = core::ptr::null_mut();
                    return true;
                }
                prev_link = &mut (*cur).next_in_object;
                cur = next;
            }
        }
        false
    }

    /// Walk the list, firing every armed watch whose mask intersects
    /// `asserted_bits`. One-shot watches that fire are detached from
    /// the list under the same lock acquisition so producers see a
    /// consistent before/after snapshot.
    ///
    /// `fire()` itself runs **outside** the list lock — it pushes a
    /// record into the bound `EventQueue`, which acquires its own
    /// lock and may itself fire watcher chains; nesting that path
    /// inside this list's lock would risk a recursive deadlock when
    /// an `EventQueue` watches its own state. Each call collects up
    /// to `FIRE_BATCH_SIZE` matching watches into a stack-local
    /// snapshot under the lock, drops the lock, dispatches the fires,
    /// and loops while more matches remain.
    ///
    /// # Safety
    /// Caller must have already published `asserted_bits` into the
    /// owning object's `state_flags` so producers and consumers agree
    /// on visibility ordering.
    pub unsafe fn publish(&self, asserted_bits: u64) {
        const FIRE_BATCH_SIZE: usize = 32;

        // Allocate this publish's epoch up-front. Wraparound at u64
        // is not a real concern (62-bit lifetime at 1 GHz publish rate).
        let epoch = self.publish_epoch.fetch_add(1, Ordering::AcqRel) + 1;

        loop {
            let mut batch: [(*mut Watch, *mut EventQueue, EventRecord, u64); FIRE_BATCH_SIZE] = [(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                EventRecord::empty(),
                0,
            );
                FIRE_BATCH_SIZE];
            let mut count = 0usize;
            let mut more = false;

            let irq = unsafe { crate::mm::save_irq_disable() };
            self.lock.lock();

            let mut prev_link: *mut *mut Watch = self.head.get();
            unsafe {
                let mut cur = *prev_link;
                while !cur.is_null() {
                    if count >= FIRE_BATCH_SIZE {
                        more = true;
                        break;
                    }
                    let next = (*cur).next_in_object;
                    let watch = &mut *cur;
                    let already = watch.last_publish_epoch.load(Ordering::Acquire) >= epoch;
                    if !already
                        && watch.armed.load(Ordering::Acquire) != 0
                        && (watch.mask & asserted_bits) != 0
                        && !watch.event_queue.is_null()
                    {
                        let matched = watch.mask & asserted_bits;
                        let eq = watch.event_queue;
                        // Pin BOTH the watch and the EQ across the
                        // unlocked dispatch. The EQ pin defends
                        // against a concurrent WATCH_DISARM /
                        // WATCH_REGISTER that could otherwise
                        // release the EQ behind our back; the watch
                        // pin already kept the watch struct alive.
                        let watch_obj = cur as *mut KernelObject;
                        (*watch_obj).ref_count.fetch_add(1, Ordering::AcqRel);
                        (*(eq as *mut KernelObject))
                            .ref_count
                            .fetch_add(1, Ordering::AcqRel);
                        // Snapshot key + cookie + matched into the
                        // batch under the lock so a concurrent
                        // WATCH_REGISTER reconfigure doesn't bleed
                        // a stale (cookie, key) tuple into our
                        // record. Snapshot the cancel epoch too —
                        // a concurrent `WATCH_CANCEL` between this
                        // batch fill and the unlocked enqueue path
                        // bumps it, and the fire-time re-read drops
                        // the enqueue when it diverges.
                        let mut rec = EventRecord::empty();
                        rec.kind = EVENT_TYPE_STATE;
                        rec.status = EVENT_STATUS_OK;
                        rec.cookie = watch.cookie;
                        rec.object_id = watch.key;
                        rec.state_set = matched;
                        let cancel_snap = watch.cancel_epoch.load(Ordering::Acquire);
                        watch.last_publish_epoch.store(epoch, Ordering::Release);
                        batch[count] = (cur, eq, rec, cancel_snap);
                        count += 1;
                        // One-shot only: every fire detaches and
                        // disarms. Userland re-arms via a fresh
                        // `WATCH_REGISTER` to observe the next edge.
                        watch.armed.store(0, Ordering::Release);
                        *prev_link = next;
                        watch.next_in_object = core::ptr::null_mut();
                        cur = next;
                        continue;
                    }
                    prev_link = &mut (*cur).next_in_object;
                    cur = next;
                }
            }

            self.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };

            for i in 0..count {
                let (watch, eq, rec, cancel_snap) = batch[i];
                if !watch.is_null() {
                    unsafe {
                        // Re-read the cancel epoch after the lock has
                        // been released. A `WATCH_CANCEL` that arrived
                        // between batch fill and this point bumps the
                        // counter — drop the enqueue, but always
                        // release the refs we pinned under the lock.
                        let cancel_now = (*watch).cancel_epoch.load(Ordering::Acquire);
                        if cancel_now == cancel_snap {
                            let _ = (*eq).enqueue(rec);
                        }
                        crate::cap::release_object(eq as *mut KernelObject, ObjectType::EventQueue);
                        crate::cap::release_object(watch as *mut KernelObject, ObjectType::Watch);
                    }
                }
            }

            if !more {
                break;
            }
        }
    }

    /// Drain every watch with status `EVENT_STATUS_OBJECT_CLOSED`. Used
    /// when the watched object is being torn down. Always clears the
    /// `watched_object` pointer on every watch (armed or not) so that
    /// a later watch destructor cannot dereference a reaped target.
    ///
    /// Same lock discipline as `publish`: collect armed watches into
    /// a stack batch under the list lock, refcount-pin them so they
    /// survive the dispatch, drop the lock, then call `fire_closed`
    /// outside. Firing inside the list lock would deadlock when the
    /// fire path enqueues into an `EventQueue` whose own watcher
    /// list is `self` (e.g. an `EventQueue` watching its own state),
    /// or when the EventQueue's enqueue triggers a `publish` that
    /// re-enters this lock.
    pub unsafe fn drain_closed(&self) {
        const FIRE_BATCH_SIZE: usize = 32;

        loop {
            let mut batch: [(*mut Watch, *mut EventQueue, EventRecord); FIRE_BATCH_SIZE] = [(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                EventRecord::empty(),
            );
                FIRE_BATCH_SIZE];
            let mut count = 0usize;
            let mut more = false;

            let irq = unsafe { crate::mm::save_irq_disable() };
            self.lock.lock();
            unsafe {
                let head_cell = self.head.get();
                let mut cur = *head_cell;
                *head_cell = core::ptr::null_mut();
                while !cur.is_null() {
                    if count >= FIRE_BATCH_SIZE {
                        // Re-anchor the un-walked tail so the next
                        // batch iteration picks it up.
                        *head_cell = cur;
                        more = true;
                        break;
                    }
                    let next = (*cur).next_in_object;
                    let watch = &mut *cur;
                    if watch.armed.load(Ordering::Acquire) != 0 && !watch.event_queue.is_null() {
                        let eq = watch.event_queue;
                        // Pin watch + EQ across the unlocked
                        // dispatch — same race-protection shape as
                        // `publish`.
                        let watch_obj = cur as *mut KernelObject;
                        (*watch_obj).ref_count.fetch_add(1, Ordering::AcqRel);
                        (*(eq as *mut KernelObject))
                            .ref_count
                            .fetch_add(1, Ordering::AcqRel);
                        let mut rec = EventRecord::empty();
                        rec.kind = EVENT_TYPE_STATE;
                        rec.status = EVENT_STATUS_OBJECT_CLOSED;
                        rec.cookie = watch.cookie;
                        rec.object_id = watch.key;
                        watch.armed.store(0, Ordering::Release);
                        batch[count] = (cur, eq, rec);
                        count += 1;
                    }
                    watch.watched_object = core::ptr::null_mut();
                    watch.next_in_object = core::ptr::null_mut();
                    cur = next;
                }
            }
            self.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };

            for i in 0..count {
                let (watch, eq, rec) = batch[i];
                if !watch.is_null() {
                    unsafe {
                        let _ = (*eq).enqueue(rec);
                        crate::cap::release_object(eq as *mut KernelObject, ObjectType::EventQueue);
                        crate::cap::release_object(watch as *mut KernelObject, ObjectType::Watch);
                    }
                }
            }

            if !more {
                break;
            }
        }
    }
}
