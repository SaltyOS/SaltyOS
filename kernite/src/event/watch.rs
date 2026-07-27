// SPDX-License-Identifier: GPL-2.0-only
//! Watch — one-shot state-flag watcher.
//!
//! A `Watch` couples a watched object (anything carrying `state_flags`
//! and a `WatcherList`) to a target `EventQueue`. When any masked bit
//! becomes asserted in the object's state word, an `EventRecord` is
//! enqueued and the watch detaches from the list — one-shot only. To
//! observe a future edge, userland re-arms via a fresh `WATCH_REGISTER`.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::ObjectType;
use crate::cap::object::KernelObject;
use crate::event::event_queue::EventQueue;

#[repr(C)]
pub struct Watch {
    pub header: KernelObject,
    pub armed: AtomicU64,
    pub mask: u64,
    pub key: u64,
    pub cookie: u64,
    /// Watched object back-pointer (weak — does not bump refcount).
    /// Cleared when the watched object's destructor runs `drain_closed`
    /// on its watcher list.
    pub watched_object: *mut KernelObject,
    /// Bound `EventQueue`. Strong reference — refcount incremented at
    /// `WATCH_REGISTER` and decremented at watch destroy.
    pub event_queue: *mut EventQueue,
    /// Intrusive next pointer in `WatcherList`.
    pub next_in_object: *mut Watch,
    /// Last `WatcherList` publish epoch this watch was already fired
    /// against. Suppresses re-firing the same watch in subsequent
    /// `FIRE_BATCH_SIZE` chunks of the same publish call.
    pub last_publish_epoch: AtomicU64,
    /// Monotonic counter incremented by `WATCH_CANCEL`.
    /// `WatcherList::publish` snapshots this value when the watch is
    /// added to a fire batch and re-reads it just before enqueuing
    /// into the bound `EventQueue`; a delta observed at fire time
    /// means a cancellation arrived between snapshot and enqueue, so
    /// the fire is dropped. Closes the race window that a pure
    /// `armed → 0` flip + watcher-list remove cannot close on its own
    /// when a publish batch already snapshotted the watch.
    pub cancel_epoch: AtomicU64,
}

unsafe impl Sync for Watch {}

impl Watch {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Watch, 0),
            armed: AtomicU64::new(0),
            mask: 0,
            key: 0,
            cookie: 0,
            watched_object: core::ptr::null_mut(),
            event_queue: core::ptr::null_mut(),
            next_in_object: core::ptr::null_mut(),
            last_publish_epoch: AtomicU64::new(0),
            cancel_epoch: AtomicU64::new(0),
        }
    }

    /// Configure the watch with its target object, mask, EQ binding,
    /// and caller cookie/key. The watch is not yet armed — the caller
    /// transitions to armed after publishing this configuration so
    /// `WatcherList::publish` sees a consistent snapshot.
    pub fn configure(
        &mut self,
        watched: *mut KernelObject,
        mask: u64,
        eq: *mut EventQueue,
        key: u64,
        cookie: u64,
    ) {
        self.watched_object = watched;
        self.mask = mask;
        self.event_queue = eq;
        self.key = key;
        self.cookie = cookie;
    }

    pub fn arm(&self) {
        self.armed.store(1, Ordering::Release);
    }

    pub fn disarm(&self) {
        self.armed.store(0, Ordering::Release);
    }

    /// Bump `cancel_epoch`. Called from `syscall_watch_cancel` after
    /// `disarm()` and `WatcherList::remove` so that any in-flight
    /// publish batch already past the lock detects the cancellation
    /// at fire time and drops the enqueue.
    pub fn cancel_epoch_inc(&self) {
        self.cancel_epoch.fetch_add(1, Ordering::AcqRel);
    }
}
