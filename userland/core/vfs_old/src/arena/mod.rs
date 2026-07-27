// SPDX-License-Identifier: GPL-2.0-only
//! `Arena<T>` — non-moving, epoch-counted slab allocator.
//!
//! Memory is allocated in fixed-size segments from `server::mem::map_anon`.
//! Segments are never moved or freed during normal operation, so raw pointers
//! resolved from handles remain stable as long as the slot is not recycled.
//!
//! All mutating methods take `&mut self`, enforcing the single-owner invariant
//! at the type level. Workers receive resolved raw pointers or immutable
//! snapshots — they never touch the arena directly.

pub(crate) mod badge_map;
pub(crate) mod handle;

pub(crate) use badge_map::BadgeMap;
pub(crate) use handle::Handle;

// =========================================================================
// Slot metadata
// =========================================================================

/// Object lifecycle state, tracked per slot in parallel metadata.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum SlotState {
    /// Slot is on the free list and available for allocation.
    Free = 0,
    /// Slot holds a live object.
    Active = 1,
    /// Object logically dead but in-flight worker references exist.
    Retired = 2,
    /// All in-flight references drained; safe to reclaim on next sweep.
    Reclaimable = 3,
}

/// Per-slot metadata stored in a parallel array next to the data slots.
#[repr(C)]
#[derive(Clone, Copy)]
struct SlotMeta {
    /// Epoch counter. Starts at 1, incremented on each reclaim.
    /// A handle is valid only when its epoch matches this value.
    epoch: u32,
    /// Current lifecycle state.
    state: SlotState,
    _pad: [u8; 3],
    /// Next slot index in the free list (valid only when `state == Free`).
    next_free: u32,
}

const FREE_LIST_END: u32 = u32::MAX;

// =========================================================================
// Arena segment
// =========================================================================

const MAX_SEGMENTS: usize = 8;
const MAX_SEGMENT_CAP: u32 = 1 << 16; // 64K slots per segment

/// A contiguous block of slots allocated from mmsrv.
struct ArenaSegment<T> {
    data: *mut T,
    meta: *mut SlotMeta,
    cap: u32,
}

impl<T> ArenaSegment<T> {
    const EMPTY: Self = ArenaSegment {
        data: core::ptr::null_mut(),
        meta: core::ptr::null_mut(),
        cap: 0,
    };
}

impl<T> Clone for ArenaSegment<T> {
    fn clone(&self) -> Self {
        ArenaSegment {
            data: self.data,
            meta: self.meta,
            cap: self.cap,
        }
    }
}
impl<T> Copy for ArenaSegment<T> {}

// =========================================================================
// Arena
// =========================================================================

/// Non-moving, epoch-counted slab allocator.
///
/// # Safety contract
///
/// Only the owner thread (VFS main loop) may call any method. Workers
/// interact with arena-managed objects only through raw pointers resolved
/// by the owner and guarded by flight counting.
pub(crate) struct Arena<T> {
    segments: [ArenaSegment<T>; MAX_SEGMENTS],
    segment_count: u8,
    /// Total capacity across all segments.
    total_cap: u32,
    /// Head of the singly-linked free list (global slot index).
    free_head: u32,
    /// Number of free slots.
    free_count: u32,
    /// Capacity to use for the next segment allocation.
    next_segment_cap: u32,
}

impl<T> Arena<T> {
    /// Create a new arena with an initial segment of `initial_cap` slots.
    /// Returns `None` if the initial allocation fails.
    pub(crate) fn new(initial_cap: u32) -> Option<Self> {
        let mut arena = Arena {
            segments: [ArenaSegment::EMPTY; MAX_SEGMENTS],
            segment_count: 0,
            total_cap: 0,
            free_head: FREE_LIST_END,
            free_count: 0,
            next_segment_cap: initial_cap,
        };
        if arena.grow().is_err() {
            return None;
        }
        Some(arena)
    }

    /// Allocate a slot, returning its handle. Grows the arena if the free
    /// list is empty. Returns `None` if growth fails (all segments used or
    /// mmsrv allocation failure).
    pub(crate) fn alloc(&mut self) -> Option<Handle<T>> {
        if self.free_count == 0 {
            if self.grow().is_err() {
                return None;
            }
        }
        let slot = self.free_head;
        let (seg, local) = self.resolve_slot(slot)?;
        let meta = unsafe { &mut *self.segments[seg].meta.add(local as usize) };
        self.free_head = meta.next_free;
        self.free_count -= 1;
        meta.state = SlotState::Active;
        meta.next_free = FREE_LIST_END;

        // Zero-initialize the data slot.
        unsafe {
            core::ptr::write_bytes(self.segments[seg].data.add(local as usize), 0, 1);
        }

        Some(Handle::new(slot, meta.epoch))
    }

    /// Resolve a handle to a shared reference.
    /// Returns `None` on epoch mismatch or non-Active state.
    pub(crate) fn get(&self, h: Handle<T>) -> Option<&T> {
        if !h.is_valid() {
            return None;
        }
        let (seg, local) = self.resolve_slot(h.slot())?;
        let meta = unsafe { &*self.segments[seg].meta.add(local as usize) };
        if meta.epoch != h.epoch() || meta.state != SlotState::Active {
            return None;
        }
        Some(unsafe { &*self.segments[seg].data.add(local as usize) })
    }

    /// Resolve a handle to a mutable reference. Owner-thread only.
    /// Returns `None` on epoch mismatch or non-Active state.
    pub(crate) fn get_mut(&mut self, h: Handle<T>) -> Option<&mut T> {
        if !h.is_valid() {
            return None;
        }
        let (seg, local) = self.resolve_slot(h.slot())?;
        let meta = unsafe { &*self.segments[seg].meta.add(local as usize) };
        if meta.epoch != h.epoch() || meta.state != SlotState::Active {
            return None;
        }
        Some(unsafe { &mut *self.segments[seg].data.add(local as usize) })
    }

    /// Resolve a handle to a raw pointer.
    ///
    /// Valid for `Active` and `Retired` slots (workers may still hold a
    /// pointer to a retired slot guarded by flight counting).
    ///
    /// # Safety
    ///
    /// The pointer is valid only while the slot is not recycled (epoch
    /// unchanged). The caller must ensure flight counting prevents recycling.
    pub(crate) unsafe fn raw_ptr(&self, h: Handle<T>) -> Option<*mut T> {
        if !h.is_valid() {
            return None;
        }
        let (seg, local) = self.resolve_slot(h.slot())?;
        let meta = unsafe { &*self.segments[seg].meta.add(local as usize) };
        if meta.epoch != h.epoch() {
            return None;
        }
        match meta.state {
            SlotState::Active | SlotState::Retired => {
                Some(unsafe { self.segments[seg].data.add(local as usize) })
            }
            _ => None,
        }
    }

    /// Rebuild a live handle from a raw slot index.
    ///
    /// Returns `None` if the slot is out of range or currently free.
    pub(crate) fn handle_from_slot(&self, slot: u32) -> Option<Handle<T>> {
        let (seg, local) = self.resolve_slot(slot)?;
        let meta = unsafe { &*self.segments[seg].meta.add(local as usize) };
        match meta.state {
            SlotState::Active | SlotState::Retired => Some(Handle::new(slot, meta.epoch)),
            _ => None,
        }
    }

    /// Check if a handle refers to a live (Active) object.
    #[inline]
    pub(crate) fn is_alive(&self, h: Handle<T>) -> bool {
        if !h.is_valid() {
            return false;
        }
        match self.resolve_slot(h.slot()) {
            Some((seg, local)) => {
                let meta = unsafe { &*self.segments[seg].meta.add(local as usize) };
                meta.epoch == h.epoch() && meta.state == SlotState::Active
            }
            None => false,
        }
    }

    /// Transition an Active slot to Retired.
    ///
    /// Used when the object is logically dead but workers still reference it
    /// (flight_count > 0). Returns `false` on epoch mismatch or if the
    /// slot is not Active.
    pub(crate) fn retire(&mut self, h: Handle<T>) -> bool {
        if !h.is_valid() {
            return false;
        }
        let (seg, local) = match self.resolve_slot(h.slot()) {
            Some(v) => v,
            None => return false,
        };
        let meta = unsafe { &mut *self.segments[seg].meta.add(local as usize) };
        if meta.epoch != h.epoch() || meta.state != SlotState::Active {
            return false;
        }
        meta.state = SlotState::Retired;
        true
    }

    /// Transition a Retired slot to Reclaimable.
    ///
    /// Called when the last in-flight worker reference drains (flight_count
    /// drops to 0).
    pub(crate) fn mark_reclaimable(&mut self, h: Handle<T>) {
        if !h.is_valid() {
            return;
        }
        if let Some((seg, local)) = self.resolve_slot(h.slot()) {
            let meta = unsafe { &mut *self.segments[seg].meta.add(local as usize) };
            if meta.epoch == h.epoch() && meta.state == SlotState::Retired {
                meta.state = SlotState::Reclaimable;
            }
        }
    }

    /// Transition an Active slot directly to Reclaimable, bypassing Retired.
    ///
    /// Used when flight_count is already 0 at close time — no need for the
    /// intermediate Retired state.
    pub(crate) fn release(&mut self, h: Handle<T>) -> bool {
        if !h.is_valid() {
            return false;
        }
        let (seg, local) = match self.resolve_slot(h.slot()) {
            Some(v) => v,
            None => return false,
        };
        let meta = unsafe { &mut *self.segments[seg].meta.add(local as usize) };
        if meta.epoch != h.epoch() || meta.state != SlotState::Active {
            return false;
        }
        meta.state = SlotState::Reclaimable;
        true
    }

    /// Reclaim all Reclaimable slots: increment epoch, zero data, push
    /// to free list. Returns the number of slots reclaimed.
    ///
    /// Called periodically by the owner loop (every ~64 dispatch cycles or
    /// when free_count drops below a threshold).
    pub(crate) fn sweep(&mut self) -> u32 {
        self.sweep_with(|_| false)
    }

    /// Variant of `sweep` that consults a caller-supplied skip predicate
    /// on every Reclaimable slot. When the predicate returns `true` the
    /// slot is *left alone* (not reclaimed, not epoch-bumped) — used
    /// by the vnode arena to retain pinned structural entries whose
    /// identity must survive generic cache churn.
    pub(crate) fn sweep_with<F>(&mut self, mut skip: F) -> u32
    where
        F: FnMut(&T) -> bool,
    {
        let mut reclaimed = 0u32;
        let mut base = 0u32;
        for i in 0..self.segment_count as usize {
            let seg = &self.segments[i];
            let cap = seg.cap;
            for j in 0..cap {
                let meta = unsafe { &mut *seg.meta.add(j as usize) };
                if meta.state != SlotState::Reclaimable {
                    continue;
                }
                let data_ptr = unsafe { seg.data.add(j as usize) };
                if skip(unsafe { &*data_ptr }) {
                    continue;
                }
                // Advance epoch (skip 0).
                meta.epoch = meta.epoch.wrapping_add(1);
                if meta.epoch == 0 {
                    meta.epoch = 1;
                }
                meta.state = SlotState::Free;
                meta.next_free = self.free_head;
                self.free_head = base + j;
                self.free_count += 1;
                reclaimed += 1;
            }
            base += cap;
        }
        reclaimed
    }

    /// Number of free slots available without growth.
    #[inline]
    pub(crate) fn free_count(&self) -> u32 {
        self.free_count
    }

    /// Total capacity across all segments.
    #[inline]
    pub(crate) fn total_cap(&self) -> u32 {
        self.total_cap
    }

    /// Access the slot's lifecycle state (for reclaim decisions).
    pub(crate) fn slot_state(&self, h: Handle<T>) -> Option<SlotState> {
        if !h.is_valid() {
            return None;
        }
        let (seg, local) = self.resolve_slot(h.slot())?;
        let meta = unsafe { &*self.segments[seg].meta.add(local as usize) };
        if meta.epoch != h.epoch() {
            return None;
        }
        Some(meta.state)
    }

    // =====================================================================
    // Iteration
    // =====================================================================

    /// Call `f` for every Active slot, passing its handle and a shared
    /// reference. Stops early if `f` returns `false`.
    pub(crate) fn for_each_active<F>(&self, mut f: F)
    where
        F: FnMut(Handle<T>, &T) -> bool,
    {
        let mut base = 0u32;
        for i in 0..self.segment_count as usize {
            let seg = &self.segments[i];
            let cap = seg.cap;
            for j in 0..cap {
                let meta = unsafe { &*seg.meta.add(j as usize) };
                if meta.state == SlotState::Active {
                    let h = Handle::new(base + j, meta.epoch);
                    let data = unsafe { &*seg.data.add(j as usize) };
                    if !f(h, data) {
                        return;
                    }
                }
            }
            base += cap;
        }
    }

    /// Call `f` for every Active slot, passing its handle and an
    /// exclusive reference. Stops early if `f` returns `false`.
    /// Used by invalidation sweeps that mutate in-place; split-
    /// borrow compatible (callers may hold a `&` to an adjacent
    /// field of the containing struct while this is running).
    pub(crate) fn for_each_active_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(Handle<T>, &mut T) -> bool,
    {
        let mut base = 0u32;
        for i in 0..self.segment_count as usize {
            let seg = &self.segments[i];
            let cap = seg.cap;
            for j in 0..cap {
                let meta = unsafe { &*seg.meta.add(j as usize) };
                if meta.state == SlotState::Active {
                    let h = Handle::new(base + j, meta.epoch);
                    let data = unsafe { &mut *seg.data.add(j as usize) };
                    if !f(h, data) {
                        return;
                    }
                }
            }
            base += cap;
        }
    }

    // =====================================================================
    // Internal helpers
    // =====================================================================

    /// Map a global slot index to (segment_index, local_offset).
    fn resolve_slot(&self, slot: u32) -> Option<(usize, u32)> {
        let mut base = 0u32;
        for i in 0..self.segment_count as usize {
            let cap = self.segments[i].cap;
            if slot < base + cap {
                return Some((i, slot - base));
            }
            base += cap;
        }
        None
    }

    /// Allocate a new segment and append it to the arena.
    fn grow(&mut self) -> Result<(), ()> {
        if self.segment_count as usize >= MAX_SEGMENTS {
            return Err(());
        }

        let cap = self.next_segment_cap;
        let data_bytes = (cap as usize) * core::mem::size_of::<T>();
        let meta_bytes = (cap as usize) * core::mem::size_of::<SlotMeta>();

        let data_alloc = (data_bytes + 4095) & !4095; // page-align
        let meta_alloc = (meta_bytes + 4095) & !4095;

        let data_ptr = unsafe { crate::server::mem::map_anon(data_alloc as u64) };
        if data_ptr.is_null() || data_ptr == usize::MAX as *mut u8 {
            return Err(());
        }
        let meta_ptr = unsafe { crate::server::mem::map_anon(meta_alloc as u64) };
        if meta_ptr.is_null() || meta_ptr == usize::MAX as *mut u8 {
            unsafe {
                crate::server::mem::unmap(data_ptr, data_alloc as u64);
            }
            return Err(());
        }

        // Build free list for the new segment. New slots are prepended to
        // the existing free list so they are allocated first (warm cache).
        let base = self.total_cap;
        let meta = meta_ptr as *mut SlotMeta;
        for i in 0..cap {
            unsafe {
                let m = &mut *meta.add(i as usize);
                m.epoch = 1;
                m.state = SlotState::Free;
                m.next_free = if i + 1 < cap {
                    base + i + 1
                } else {
                    self.free_head
                };
            }
        }
        self.free_head = base;
        self.free_count += cap;

        let seg_idx = self.segment_count as usize;
        self.segments[seg_idx] = ArenaSegment {
            data: data_ptr as *mut T,
            meta,
            cap,
        };
        self.segment_count += 1;
        self.total_cap += cap;

        // Double for next growth, capped.
        self.next_segment_cap = core::cmp::min(cap.saturating_mul(2), MAX_SEGMENT_CAP);

        Ok(())
    }
}

// The arena is only accessed by the owner thread, but VfsState (which
// contains arenas) may be stored behind a raw pointer that the compiler
// considers potentially shared.
unsafe impl<T: Send> Send for Arena<T> {}
