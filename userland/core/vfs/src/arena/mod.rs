// SPDX-License-Identifier: GPL-2.0-only
//
//! `Arena<T>` — non-moving, epoch-counted slab allocator.
//!
//! Memory is allocated in fixed-size segments via
//! [`crate::server::mem::map_anon`]. Segments are never moved or freed
//! during normal operation, so raw pointers resolved from handles
//! remain stable as long as the slot is not recycled.
//!
//! There is no fixed cap on segment count or per-segment capacity.
//! The arena threads segments through an intrusive singly-linked
//! list; each grow allocates one new segment and appends it.
//! Per-segment capacity starts at `INITIAL_SEGMENT_CAP` and doubles
//! each grow, saturating only at `u32::MAX` slots — the natural
//! backstop is mmap allocation failure, surfaced as
//! [`crate::arena::segmented_array::SegError::OutOfMemory`].
//!
//! All mutating methods take `&mut self`, enforcing the single-owner
//! invariant at the type level. Deferred operations carry handles
//! or immutable snapshots and re-enter through the owner reactor.

pub(crate) mod badge_map;
pub(crate) mod handle;
pub(crate) mod segmented_array;
pub(crate) mod segmented_slot_table;

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
    /// Epoch counter. Starts at 1, incremented on each reclaim. A
    /// handle is valid only when its epoch matches this value.
    epoch: u32,
    /// Current lifecycle state.
    state: SlotState,
    _pad: [u8; 3],
    /// Next slot index in the free list (valid only when
    /// `state == Free`). `FREE_LIST_END` marks the tail.
    next_free: u32,
}

const FREE_LIST_END: u32 = u32::MAX;

// =========================================================================
// Arena segment
// =========================================================================

/// Initial per-segment capacity (slots). Picked so that even small
/// `T` (e.g. `OpenObjectHandle = 8 bytes`) requires only one frame
/// for the first segment.
const INITIAL_SEGMENT_CAP: u32 = 64;

/// A contiguous block of slots. Segments form an intrusive singly-
/// linked list anchored at `Arena::head`; grow appends at the tail.
#[repr(C)]
struct ArenaSegment<T> {
    next: *mut ArenaSegment<T>,
    data: *mut T,
    meta: *mut SlotMeta,
    cap: u32,
    /// Global slot index where this segment's slot 0 sits. Lets
    /// `resolve_slot` skip the per-segment running sum.
    base: u32,
    /// Total bytes the segment header + data + meta occupy in the
    /// underlying mmap. Drop unmaps both the header and the
    /// data/meta payloads.
    data_alloc_bytes: u64,
    meta_alloc_bytes: u64,
}

// =========================================================================
// Arena
// =========================================================================

/// Non-moving, epoch-counted slab allocator. See module docs.
pub(crate) struct Arena<T> {
    head: *mut ArenaSegment<T>,
    tail: *mut ArenaSegment<T>,
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
            head: ::core::ptr::null_mut(),
            tail: ::core::ptr::null_mut(),
            total_cap: 0,
            free_head: FREE_LIST_END,
            free_count: 0,
            next_segment_cap: if initial_cap == 0 {
                INITIAL_SEGMENT_CAP
            } else {
                initial_cap
            },
        };
        if arena.grow().is_err() {
            return None;
        }
        Some(arena)
    }

    /// Allocate a slot, returning its handle. Grows the arena if the
    /// free list is empty. Returns `None` if growth fails (mmsrv
    /// allocation failure).
    pub(crate) fn alloc(&mut self) -> Option<Handle<T>> {
        if self.free_count == 0 && self.grow().is_err() {
            return None;
        }
        let slot = self.free_head;
        let (seg_ptr, local) = self.resolve_slot(slot)?;
        let seg = unsafe { &*seg_ptr };
        let meta = unsafe { &mut *seg.meta.add(local as usize) };
        self.free_head = meta.next_free;
        self.free_count -= 1;
        meta.state = SlotState::Active;
        meta.next_free = FREE_LIST_END;
        unsafe {
            ::core::ptr::write_bytes(seg.data.add(local as usize), 0, 1);
        }
        Some(Handle::new(slot, meta.epoch))
    }

    /// Resolve a handle to a shared reference. `None` on epoch
    /// mismatch or non-Active state.
    pub(crate) fn get(&self, h: Handle<T>) -> Option<&T> {
        if !h.is_valid() {
            return None;
        }
        let (seg_ptr, local) = self.resolve_slot(h.slot())?;
        let seg = unsafe { &*seg_ptr };
        let meta = unsafe { &*seg.meta.add(local as usize) };
        if meta.epoch != h.epoch() || meta.state != SlotState::Active {
            return None;
        }
        Some(unsafe { &*seg.data.add(local as usize) })
    }

    /// Resolve a handle to a mutable reference (owner thread only).
    /// `None` on epoch mismatch or non-Active state.
    pub(crate) fn get_mut(&mut self, h: Handle<T>) -> Option<&mut T> {
        if !h.is_valid() {
            return None;
        }
        let (seg_ptr, local) = self.resolve_slot(h.slot())?;
        let seg = unsafe { &*seg_ptr };
        let meta = unsafe { &*seg.meta.add(local as usize) };
        if meta.epoch != h.epoch() || meta.state != SlotState::Active {
            return None;
        }
        Some(unsafe { &mut *seg.data.add(local as usize) })
    }

    /// Resolve a handle to a raw pointer. Valid for `Active` and
    /// `Retired` slots (deferred operations may still hold a pointer
    /// to a retired slot guarded by flight counting).
    ///
    /// # Safety
    ///
    /// Pointer is valid only while the slot is not recycled (epoch
    /// unchanged). Caller ensures flight counting prevents recycling.
    pub(crate) unsafe fn raw_ptr(&self, h: Handle<T>) -> Option<*mut T> {
        if !h.is_valid() {
            return None;
        }
        let (seg_ptr, local) = self.resolve_slot(h.slot())?;
        let seg = unsafe { &*seg_ptr };
        let meta = unsafe { &*seg.meta.add(local as usize) };
        if meta.epoch != h.epoch() {
            return None;
        }
        match meta.state {
            SlotState::Active | SlotState::Retired => Some(unsafe { seg.data.add(local as usize) }),
            _ => None,
        }
    }

    /// Rebuild a live handle from a raw slot index. `None` if the
    /// slot is out of range or currently free.
    pub(crate) fn handle_from_slot(&self, slot: u32) -> Option<Handle<T>> {
        let (seg_ptr, local) = self.resolve_slot(slot)?;
        let seg = unsafe { &*seg_ptr };
        let meta = unsafe { &*seg.meta.add(local as usize) };
        match meta.state {
            SlotState::Active | SlotState::Retired => Some(Handle::new(slot, meta.epoch)),
            _ => None,
        }
    }

    #[inline]
    pub(crate) fn is_alive(&self, h: Handle<T>) -> bool {
        if !h.is_valid() {
            return false;
        }
        match self.resolve_slot(h.slot()) {
            Some((seg_ptr, local)) => {
                let seg = unsafe { &*seg_ptr };
                let meta = unsafe { &*seg.meta.add(local as usize) };
                meta.epoch == h.epoch() && meta.state == SlotState::Active
            }
            None => false,
        }
    }

    /// Transition an Active slot to Retired. Used when the object is
    /// logically dead but deferred operations still reference it
    /// (flight_count > 0).
    pub(crate) fn retire(&mut self, h: Handle<T>) -> bool {
        if !h.is_valid() {
            return false;
        }
        let Some((seg_ptr, local)) = self.resolve_slot(h.slot()) else {
            return false;
        };
        let seg = unsafe { &*seg_ptr };
        let meta = unsafe { &mut *seg.meta.add(local as usize) };
        if meta.epoch != h.epoch() || meta.state != SlotState::Active {
            return false;
        }
        meta.state = SlotState::Retired;
        true
    }

    /// Transition a Retired slot to Reclaimable. Called when the last
    /// in-flight worker reference drains.
    pub(crate) fn mark_reclaimable(&mut self, h: Handle<T>) {
        if !h.is_valid() {
            return;
        }
        if let Some((seg_ptr, local)) = self.resolve_slot(h.slot()) {
            let seg = unsafe { &*seg_ptr };
            let meta = unsafe { &mut *seg.meta.add(local as usize) };
            if meta.epoch == h.epoch() && meta.state == SlotState::Retired {
                meta.state = SlotState::Reclaimable;
            }
        }
    }

    /// Transition an Active slot directly to Reclaimable, bypassing
    /// Retired. Used when flight_count is already 0 at close time.
    pub(crate) fn release(&mut self, h: Handle<T>) -> bool {
        if !h.is_valid() {
            return false;
        }
        let Some((seg_ptr, local)) = self.resolve_slot(h.slot()) else {
            return false;
        };
        let seg = unsafe { &*seg_ptr };
        let meta = unsafe { &mut *seg.meta.add(local as usize) };
        if meta.epoch != h.epoch() || meta.state != SlotState::Active {
            return false;
        }
        meta.state = SlotState::Reclaimable;
        true
    }

    /// Reclaim all Reclaimable slots: increment epoch, zero data,
    /// push to free list. Returns the number of slots reclaimed.
    pub(crate) fn sweep(&mut self) -> u32 {
        self.sweep_with(|_| false)
    }

    /// `sweep` variant that consults a caller-supplied skip predicate
    /// for every Reclaimable slot. When the predicate returns `true`
    /// the slot is left alone — used by the vnode arena to retain
    /// pinned structural entries.
    pub(crate) fn sweep_with<F>(&mut self, mut skip: F) -> u32
    where
        F: FnMut(&T) -> bool,
    {
        let mut reclaimed = 0u32;
        let mut cur = self.head;
        while !cur.is_null() {
            let seg = unsafe { &*cur };
            let cap = seg.cap;
            let base = seg.base;
            for j in 0..cap {
                let meta = unsafe { &mut *seg.meta.add(j as usize) };
                if meta.state != SlotState::Reclaimable {
                    continue;
                }
                let data_ptr = unsafe { seg.data.add(j as usize) };
                if skip(unsafe { &*data_ptr }) {
                    continue;
                }
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
            cur = seg.next;
        }
        reclaimed
    }

    #[inline]
    pub(crate) fn free_count(&self) -> u32 {
        self.free_count
    }

    #[inline]
    pub(crate) fn total_cap(&self) -> u32 {
        self.total_cap
    }

    pub(crate) fn slot_state(&self, h: Handle<T>) -> Option<SlotState> {
        if !h.is_valid() {
            return None;
        }
        let (seg_ptr, local) = self.resolve_slot(h.slot())?;
        let seg = unsafe { &*seg_ptr };
        let meta = unsafe { &*seg.meta.add(local as usize) };
        if meta.epoch != h.epoch() {
            return None;
        }
        Some(meta.state)
    }

    /// Iterate every Active slot, passing `(handle, &T)`. Stops early
    /// if `f` returns `false`.
    pub(crate) fn for_each_active<F>(&self, mut f: F)
    where
        F: FnMut(Handle<T>, &T) -> bool,
    {
        let mut cur = self.head;
        while !cur.is_null() {
            let seg = unsafe { &*cur };
            for j in 0..seg.cap {
                let meta = unsafe { &*seg.meta.add(j as usize) };
                if meta.state == SlotState::Active {
                    let h = Handle::new(seg.base + j, meta.epoch);
                    let data = unsafe { &*seg.data.add(j as usize) };
                    if !f(h, data) {
                        return;
                    }
                }
            }
            cur = seg.next;
        }
    }

    /// Mutable variant of `for_each_active`. Stops early on `false`.
    pub(crate) fn for_each_active_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(Handle<T>, &mut T) -> bool,
    {
        let mut cur = self.head;
        while !cur.is_null() {
            let seg = unsafe { &*cur };
            for j in 0..seg.cap {
                let meta = unsafe { &*seg.meta.add(j as usize) };
                if meta.state == SlotState::Active {
                    let h = Handle::new(seg.base + j, meta.epoch);
                    let data = unsafe { &mut *seg.data.add(j as usize) };
                    if !f(h, data) {
                        return;
                    }
                }
            }
            cur = seg.next;
        }
    }

    // =====================================================================
    // Internal helpers
    // =====================================================================

    /// Map a global slot index to (segment pointer, local offset).
    fn resolve_slot(&self, slot: u32) -> Option<(*const ArenaSegment<T>, u32)> {
        let mut cur = self.head;
        while !cur.is_null() {
            let seg = unsafe { &*cur };
            if slot >= seg.base && slot < seg.base + seg.cap {
                return Some((cur as *const ArenaSegment<T>, slot - seg.base));
            }
            cur = seg.next;
        }
        None
    }

    /// Allocate a new segment and append it to the linked list.
    fn grow(&mut self) -> Result<(), ()> {
        let cap = self.next_segment_cap;
        let data_bytes = (cap as usize)
            .checked_mul(::core::mem::size_of::<T>())
            .ok_or(())?;
        let meta_bytes = (cap as usize)
            .checked_mul(::core::mem::size_of::<SlotMeta>())
            .ok_or(())?;
        let data_alloc = ((data_bytes + 4095) & !4095) as u64;
        let meta_alloc = ((meta_bytes + 4095) & !4095) as u64;
        let header_alloc = ((::core::mem::size_of::<ArenaSegment<T>>() + 4095) & !4095) as u64;

        let header_ptr = unsafe { crate::server::mem::map_anon(header_alloc) };
        if header_ptr.is_null() || header_ptr == usize::MAX as *mut u8 {
            return Err(());
        }
        let data_ptr = unsafe { crate::server::mem::map_anon(data_alloc) };
        if data_ptr.is_null() || data_ptr == usize::MAX as *mut u8 {
            unsafe { crate::server::mem::unmap(header_ptr, header_alloc) };
            return Err(());
        }
        let meta_ptr = unsafe { crate::server::mem::map_anon(meta_alloc) };
        if meta_ptr.is_null() || meta_ptr == usize::MAX as *mut u8 {
            unsafe {
                crate::server::mem::unmap(data_ptr, data_alloc);
                crate::server::mem::unmap(header_ptr, header_alloc);
            }
            return Err(());
        }

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

        let seg_hdr = header_ptr as *mut ArenaSegment<T>;
        unsafe {
            ::core::ptr::write(
                seg_hdr,
                ArenaSegment {
                    next: ::core::ptr::null_mut(),
                    data: data_ptr as *mut T,
                    meta,
                    cap,
                    base,
                    data_alloc_bytes: data_alloc,
                    meta_alloc_bytes: meta_alloc,
                },
            );
        }

        if self.tail.is_null() {
            self.head = seg_hdr;
            self.tail = seg_hdr;
        } else {
            unsafe { (*self.tail).next = seg_hdr };
            self.tail = seg_hdr;
        }
        self.total_cap += cap;
        self.next_segment_cap = cap.saturating_mul(2);
        Ok(())
    }
}

// The arena is only accessed by the owner thread, but VfsState (which
// contains arenas) may be stored behind a raw pointer that the
// compiler considers potentially shared.
unsafe impl<T: Send> Send for Arena<T> {}
