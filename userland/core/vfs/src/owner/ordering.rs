// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-key FIFO + barrier waiter for vfs reply ordering.
//!
//! `OrderingGate` replaces the inline PendingOp dependency graph
//! (`PendingOp.predecessors`, `PendingOp.successors_head`,
//! `PendingOp.predecessor_remaining`, `PendingOp.aggregate_error`)
//! with an external coordinator. Two ordering shapes collapse
//! into two structures:
//!
//! * Per-key FIFO lane — happens-after between two RPCs that
//!   share an [`OrderingKey`]. The first RPC issues immediately;
//!   subsequent RPCs queue on the lane and are promoted to the
//!   head when the predecessor completes. Covers saltyfs RENAME
//!   multi-step, link chains, and other transactional sequences
//!   where the backend cannot reorder requests safely.
//! * Barrier waiter — fsync waits on every outstanding write and
//!   MAP_SHARED writeback against a vnode key. The barrier RPC is
//!   held off the wire until the lane's `remaining` count reaches
//!   zero, at which point the dispatcher picks the entry up via
//!   [`OrderingGate::take_ready_issues`] and either issues it
//!   (clean barrier) or fails it with the propagated upstream
//!   error.
//!
//! Kernel MO state owns page-level dirty/writeback exclusion.
//! VFS ordering is deliberately vnode-scoped: normal writes,
//! metadata mutations, pager writeback, and fsync/fdatasync all
//! rendezvous on [`OrderingKey::VnodeMutate`].
//!
//! `first_error` propagation: every lane completion records the
//! observed error (or `None` for success); pending barrier
//! waiters then collect the aggregate error so a fsync after a
//! failed write surfaces the upstream failure rather than a
//! synthetic "fsync ok" reply.
//!
//! Storage: lanes live in a [`SegmentedArray<OrderingLane>`] so
//! the table grows segment-by-segment as new keys appear. Each
//! lane carries its own [`SegmentedArray<LaneEntry>`] queue and
//! [`SegmentedArray<BarrierWaiter>`] waiter list. There is no
//! fixed cap on any of these arrays.

use crate::arena::segmented_array::{MmapAllocator, SegmentedArray};
use crate::core::error::VfsError;
use crate::core::identity::VnodeKey;
use crate::owner::pending::TxId;

/// Lane discriminator. Selects the per-vnode ordering domain the
/// [`OrderingGate`] applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrderingKey {
    /// Per-vnode mutation lane. Caller pairs this with the vnode
    /// key when issuing rename / link / setattr / write / mkdir
    /// / unlink / truncate / setmode / setowner / settimes. Two
    /// requests against the same vnode are guaranteed to issue
    /// in submission order.
    VnodeMutate(VnodeKey),
}

/// Outcome of [`OrderingGate::try_issue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrderingDecision {
    /// Lane is idle; caller proceeds to issue the backend RPC
    /// immediately.
    Issue,
    /// Lane head is busy with a predecessor; `tx` has been
    /// queued. The predecessor's [`OrderingGate::complete`] will
    /// promote `tx` and surface it via
    /// [`OrderingGate::take_ready_issues`].
    Queued,
}

#[derive(Clone, Copy)]
struct LaneEntry {
    tx: TxId,
}

#[derive(Clone, Copy)]
struct BarrierWaiter {
    pending_tx: TxId,
    remaining: u32,
    aggregate_error: Option<VfsError>,
}

struct OrderingLane {
    key: OrderingKey,
    head_tx: TxId,
    queue: SegmentedArray<LaneEntry>,
    unordered: SegmentedArray<LaneEntry>,
    waiters: SegmentedArray<BarrierWaiter>,
}

impl OrderingLane {
    fn empty(key: OrderingKey) -> Self {
        Self {
            key,
            head_tx: TxId::INVALID,
            queue: SegmentedArray::new_empty(),
            unordered: SegmentedArray::new_empty(),
            waiters: SegmentedArray::new_empty(),
        }
    }
}

/// Ready-to-issue entry surfaced through
/// [`OrderingGate::take_ready_issues`]. Each entry pairs a
/// `tx` the caller must now act on with the aggregate
/// `first_error` collected by the gate. `error == None` means
/// the caller should issue the backend RPC normally;
/// `error == Some(_)` means the caller should fail the `tx`
/// with the propagated error rather than issuing the RPC (the
/// fsync-after-failed-write case).
#[derive(Clone, Copy, Debug)]
pub(crate) struct OrderingReady {
    pub key: OrderingKey,
    pub tx: TxId,
    pub error: Option<VfsError>,
}

/// Per-key FIFO + barrier coordinator.
pub(crate) struct OrderingGate {
    lanes: SegmentedArray<OrderingLane>,
    pending_ready: SegmentedArray<OrderingReady>,
}

impl OrderingGate {
    pub(crate) fn new() -> Self {
        Self {
            lanes: SegmentedArray::new_empty(),
            pending_ready: SegmentedArray::new_empty(),
        }
    }

    /// Attempt to issue `tx` against `key`. Returns
    /// [`OrderingDecision::Issue`] if the caller should proceed
    /// to the backend immediately; [`OrderingDecision::Queued`]
    /// if a predecessor is still in flight — the caller must not
    /// invoke `mp_write` for `tx` until
    /// [`Self::take_ready_issues`] surfaces it.
    pub(crate) fn try_issue(&mut self, key: OrderingKey, tx: TxId) -> OrderingDecision {
        let mut alloc = MmapAllocator::new();
        let idx = self.find_or_insert(key, &mut alloc);
        let lane = match self.lanes.get_mut(idx) {
            Some(l) => l,
            None => return OrderingDecision::Issue,
        };
        if !lane.head_tx.is_valid() {
            lane.head_tx = tx;
            return OrderingDecision::Issue;
        }
        unsafe {
            let _ = lane.queue.push(LaneEntry { tx }, &mut alloc);
        }
        OrderingDecision::Queued
    }

    /// Track an already-issued op that participates in barriers
    /// but must not be FIFO-held by this gate. This is used for
    /// payload-bearing writes: the bytes / transferred MO have
    /// already crossed the backend IPC boundary, so the gate's job
    /// is to make subsequent barriers wait for their completion,
    /// not to reorder or replay the write itself.
    pub(crate) fn begin_unordered(&mut self, key: OrderingKey, tx: TxId) {
        let mut alloc = MmapAllocator::new();
        let idx = self.find_or_insert(key, &mut alloc);
        if let Some(lane) = self.lanes.get_mut(idx) {
            unsafe {
                let _ = lane.unordered.push(LaneEntry { tx }, &mut alloc);
            }
        }
    }

    /// Record completion of `tx` against `key`. Promotes the
    /// next queued entry to the lane head (surfaced through
    /// [`Self::take_ready_issues`]) and decrements every
    /// barrier waiter, propagating `error` into their aggregate
    /// slot (first observed wins). Waiters whose `remaining`
    /// counter hits zero surface as ready entries with the
    /// aggregate error.
    pub(crate) fn complete(&mut self, key: OrderingKey, tx: TxId, error: Option<VfsError>) -> bool {
        let idx = match self.find(key) {
            Some(i) => i,
            None => return false,
        };
        let mut alloc = MmapAllocator::new();
        let mut compact_queue: SegmentedArray<LaneEntry> = SegmentedArray::new_empty();
        let mut compact_waiters: SegmentedArray<BarrierWaiter> = SegmentedArray::new_empty();
        let mut promoted: Option<TxId> = None;
        let mut local_ready: SegmentedArray<OrderingReady> = SegmentedArray::new_empty();

        let mut matched = false;
        let mut matched_head = false;

        if let Some(lane) = self.lanes.get_mut(idx) {
            if lane.head_tx == tx {
                matched = true;
                matched_head = true;
                lane.head_tx = TxId::INVALID;

                let total = lane.queue.len();
                for i in 0..total {
                    let entry = match lane.queue.get(i) {
                        Some(e) => *e,
                        None => continue,
                    };
                    if i == 0 {
                        promoted = Some(entry.tx);
                    } else {
                        unsafe {
                            let _ = compact_queue.push(entry, &mut alloc);
                        }
                    }
                }
            } else {
                let unordered_total = lane.unordered.len();
                let mut compact_unordered: SegmentedArray<LaneEntry> = SegmentedArray::new_empty();
                for i in 0..unordered_total {
                    let entry = match lane.unordered.get(i) {
                        Some(e) => *e,
                        None => continue,
                    };
                    if entry.tx == tx && !matched {
                        matched = true;
                    } else {
                        unsafe {
                            let _ = compact_unordered.push(entry, &mut alloc);
                        }
                    }
                }
                ::core::mem::swap(&mut lane.unordered, &mut compact_unordered);
            }

            if !matched {
                // Completion for an op that was not tracked by
                // this key. Leave the lane untouched; the caller
                // can fall back to its non-ordering completion path.
                return false;
            }

            let waiter_total = lane.waiters.len();
            for i in 0..waiter_total {
                let mut w = match lane.waiters.get(i) {
                    Some(w) => *w,
                    None => continue,
                };
                if w.remaining > 0 {
                    w.remaining -= 1;
                }
                if let Some(e) = error {
                    if w.aggregate_error.is_none() {
                        w.aggregate_error = Some(e);
                    }
                }
                if w.remaining == 0 {
                    unsafe {
                        let _ = local_ready.push(
                            OrderingReady {
                                key: lane.key,
                                tx: w.pending_tx,
                                error: w.aggregate_error,
                            },
                            &mut alloc,
                        );
                    }
                } else {
                    unsafe {
                        let _ = compact_waiters.push(w, &mut alloc);
                    }
                }
            }

            if let Some(next_tx) = promoted {
                lane.head_tx = next_tx;
            }
            if matched_head {
                ::core::mem::swap(&mut lane.queue, &mut compact_queue);
            }
            ::core::mem::swap(&mut lane.waiters, &mut compact_waiters);
        }

        if let Some(next_tx) = promoted {
            unsafe {
                let _ = self.pending_ready.push(
                    OrderingReady {
                        key,
                        tx: next_tx,
                        error,
                    },
                    &mut alloc,
                );
            }
        }
        let ready_n = local_ready.len();
        for j in 0..ready_n {
            if let Some(r) = local_ready.get(j) {
                unsafe {
                    let _ = self.pending_ready.push(*r, &mut alloc);
                }
            }
        }
        true
    }

    /// Register `succ_tx` as a barrier waiter on `key`. The gate
    /// snapshots the lane's current in-flight count
    /// (`head_tx + queue.len()`) and returns it; the caller
    /// uses the value to decide whether to issue the barrier
    /// RPC immediately (count == 0) or hold it on the gate
    /// until [`Self::take_ready_issues`] surfaces it.
    pub(crate) fn add_barrier(&mut self, key: OrderingKey, succ_tx: TxId) -> u32 {
        let idx = match self.find(key) {
            Some(i) => i,
            None => return 0,
        };
        let mut alloc = MmapAllocator::new();
        let lane = match self.lanes.get_mut(idx) {
            Some(l) => l,
            None => return 0,
        };
        let mut count = 0u32;
        if lane.head_tx.is_valid() {
            count += 1;
        }
        count += lane.queue.len();
        count += lane.unordered.len();
        if count == 0 {
            return 0;
        }
        let waiter = BarrierWaiter {
            pending_tx: succ_tx,
            remaining: count,
            aggregate_error: None,
        };
        unsafe {
            let _ = lane.waiters.push(waiter, &mut alloc);
        }
        count
    }

    /// Drain accumulated ready-to-issue entries the dispatcher
    /// should now act on. Called once per dispatch iteration so
    /// promoted lane heads and unblocked barriers surface as a
    /// single batch.
    pub(crate) fn take_ready_issues(&mut self, out: &mut SegmentedArray<OrderingReady>) {
        let mut alloc = MmapAllocator::new();
        let n = self.pending_ready.len();
        for i in 0..n {
            if let Some(entry) = self.pending_ready.get(i) {
                unsafe {
                    let _ = out.push(*entry, &mut alloc);
                }
            }
        }
        self.pending_ready.clear();
    }

    /// Put a ready entry back on the drain queue. Used when the
    /// owning backend has no credit at the moment a barrier opens;
    /// the next reactor iteration retries without losing the
    /// dependency result.
    pub(crate) fn requeue_ready(&mut self, ready: OrderingReady) {
        let mut alloc = MmapAllocator::new();
        unsafe {
            let _ = self.pending_ready.push(ready, &mut alloc);
        }
    }

    fn find(&self, key: OrderingKey) -> Option<u32> {
        let n = self.lanes.len();
        for i in 0..n {
            if let Some(lane) = self.lanes.get(i) {
                if lane.key == key {
                    return Some(i);
                }
            }
        }
        None
    }

    fn find_or_insert(&mut self, key: OrderingKey, alloc: &mut MmapAllocator) -> u32 {
        if let Some(i) = self.find(key) {
            return i;
        }
        unsafe {
            let _ = self.lanes.push(OrderingLane::empty(key), alloc);
        }
        self.lanes.len().saturating_sub(1)
    }
}
