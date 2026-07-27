// SPDX-License-Identifier: GPL-2.0-only
//
//! Dynamic fd-table for vfs `ClientState`.
//!
//! There is no fixed limit on file descriptors per client (no
//! `MAX_CLIENT_OBJECTS`, no `MAX_FD_SEGMENTS`). The table is a
//! chain of segments backed by anonymous mmsrv memory.
//! Segment 0 holds fds `[0..64)`, segment 1 holds `[64..192)` (cap 128),
//! and so on doubling up to a per-segment ceiling. The segment list
//! itself lives in a [`SegmentedArray`] so the segment chain also
//! grows without a fixed cap.
//!
//! Storage invariants:
//! - `handles` array stores `Handle<T>::INVALID` for empty slots and
//!   live `Handle<T>` for occupied slots.
//! - `free_next` array threads a singly-linked free list of empty
//!   slots, head = `free_list_head` (a global fd index, `u32::MAX`
//!   when the list is empty).
//! - `fd_high_water` tracks the highest fd ever populated; drives
//!   segment-extension on `ensure_grown_to` and bounds the search in
//!   `iter_active`.
//!
//! Storage stable: segment-relative pointers are never moved — the
//! `SegmentedArray<SlotTableSegment>` itself never reallocates because
//! [`trona_server::segmented_array::SegmentedArray`] preserves indices.

use core::marker::PhantomData;

use crate::arena::handle::Handle;
use crate::arena::segmented_array::{MmapAllocator, SegError, SegmentedArray};

/// Initial first-segment capacity. 64 fds × 8 byte handle = 512 bytes
/// — well under one frame so even sparse clients stay cheap.
const INITIAL_SEGMENT_CAP: u32 = 64;

/// Sentinel for "no next free slot". Distinct from `u32::MAX`-as-fd
/// to avoid spurious matches; reserved by `find_first_empty_from`.
const FREE_LIST_END: u32 = u32::MAX;

/// One row in [`SegmentedSlotTable::segments`]. `handles`,
/// `free_next` and `slot_flags` are each their own anonymous mmap;
/// tearing the table down releases all three back to mmsrv.
///
/// `slot_flags` is a personality-neutral per-slot byte. The
/// table itself does not assign meaning to any bit — POSIX
/// interprets bit 0 as `FD_CLOEXEC`, Win32 interprets it as
/// `HANDLE_FLAG_INHERIT`, and a future personality (e.g. starnite)
/// can stake its own claim. Each duplicate (via `dup`-class
/// operations or `set`) starts at `0` so personalities that need
/// per-duplicate flag isolation already get it for free.
#[repr(C)]
struct SlotTableSegment<T> {
    base_fd: u32,
    cap: u32,
    handles_bytes: u64,
    free_next_bytes: u64,
    slot_flags_bytes: u64,
    handles: *mut Handle<T>,
    free_next: *mut u32,
    slot_flags: *mut u8,
}

unsafe impl<T: Send> Send for SlotTableSegment<T> {}

/// Dynamic fd-indexed handle table.
pub(crate) struct SegmentedSlotTable<T> {
    segments: SegmentedArray<SlotTableSegment<T>>,
    allocator: MmapAllocator,
    fd_high_water: u32,
    free_list_head: u32,
    next_segment_cap: u32,
    /// Total fd capacity covered by `segments`. Equals `Σ segments[i].cap`.
    total_cap: u32,
    _marker: PhantomData<T>,
}

unsafe impl<T: Send> Send for SegmentedSlotTable<T> {}

impl<T> SegmentedSlotTable<T> {
    pub(crate) const fn new() -> Self {
        Self {
            segments: SegmentedArray::new_empty(),
            allocator: MmapAllocator::new(),
            fd_high_water: 0,
            free_list_head: FREE_LIST_END,
            next_segment_cap: INITIAL_SEGMENT_CAP,
            total_cap: 0,
            _marker: PhantomData,
        }
    }

    /// Total fd capacity currently covered by allocated segments.
    pub(crate) fn capacity(&self) -> u32 {
        self.total_cap
    }

    /// Lookup the handle stored at `fd`. Returns `None` if `fd` is
    /// past the high-water or maps to an empty slot.
    pub(crate) fn lookup(&self, fd: u32) -> Option<Handle<T>> {
        let (seg, local) = self.locate(fd)?;
        let h = unsafe { *seg.handles.add(local as usize) };
        if h.is_valid() { Some(h) } else { None }
    }

    /// Store `handle` at `fd`. Caller must have ensured the segment
    /// is allocated via `ensure_grown_to`. Storing `Handle::INVALID`
    /// is the same as `clear`. The slot's flag byte is reset to
    /// `0` — `set_slot_flags` adjusts it after the install.
    pub(crate) fn set(&mut self, fd: u32, handle: Handle<T>) -> Result<(), SegError> {
        if fd >= self.total_cap {
            self.ensure_grown_to(fd)?;
        }
        let (seg, local) = self.locate_mut(fd).ok_or(SegError::OutOfMemory)?;
        let prev = unsafe { *seg.handles.add(local as usize) };
        unsafe { *seg.handles.add(local as usize) = handle };
        unsafe { *seg.slot_flags.add(local as usize) = 0 };
        // If we just turned an empty slot into a populated one and it
        // sits on the free list, tearing it cleanly out is too
        // expensive (free list is singly-linked, no back-pointer);
        // we accept the stale entry and skip it the next time
        // `find_first_empty_from` walks. The walker checks the live
        // `handles` array, so a stale free-list entry is harmless.
        let _ = prev;
        if fd >= self.fd_high_water {
            self.fd_high_water = fd + 1;
        }
        Ok(())
    }

    /// Mark `fd` empty and push it onto the free list. Idempotent —
    /// clearing an already-empty slot is a no-op. Resets the
    /// per-slot flag byte so a future install starts from `0`.
    pub(crate) fn clear(&mut self, fd: u32) {
        let old_free_head = self.free_list_head;
        let Some((seg, local)) = self.locate_mut(fd) else {
            return;
        };
        let h_ptr = unsafe { seg.handles.add(local as usize) };
        if !unsafe { *h_ptr }.is_valid() {
            return;
        }
        unsafe { *h_ptr = Handle::<T>::INVALID };
        unsafe { *seg.slot_flags.add(local as usize) = 0 };
        unsafe { *seg.free_next.add(local as usize) = old_free_head };
        self.free_list_head = fd;
    }

    /// Read the personality-neutral flag byte for `fd`. Returns
    /// `0` for empty or out-of-range fds. Each personality
    /// assigns its own meaning to the bits.
    pub(crate) fn slot_flags(&self, fd: u32) -> u8 {
        match self.locate(fd) {
            Some((seg, local)) => unsafe { *seg.slot_flags.add(local as usize) },
            None => 0,
        }
    }

    /// Replace the personality-neutral flag byte for `fd`. No-op
    /// when the slot is empty.
    pub(crate) fn set_slot_flags(&mut self, fd: u32, flags: u8) {
        if let Some((seg, local)) = self.locate_mut(fd) {
            unsafe { *seg.slot_flags.add(local as usize) = flags };
        }
    }

    /// Toggle a single bit in the slot's flag byte without
    /// disturbing the other bits.
    pub(crate) fn set_slot_flag_bit(&mut self, fd: u32, mask: u8, on: bool) {
        if let Some((seg, local)) = self.locate_mut(fd) {
            let p = unsafe { seg.slot_flags.add(local as usize) };
            let cur = unsafe { *p };
            let new = if on { cur | mask } else { cur & !mask };
            unsafe { *p = new };
        }
    }

    /// Find the first empty fd ≥ `start`. Allocates a new segment if
    /// every existing segment is full. The returned fd is guaranteed
    /// to live inside an already-allocated segment; the caller can
    /// `set` it without an extra `ensure_grown_to`.
    pub(crate) fn find_first_empty_from(&mut self, start: u32) -> Result<u32, SegError> {
        // Free-list fast path is only taken when `start == 0` (the
        // overwhelmingly common case — `dup`, `open`, `socket`, etc.).
        // For `start > 0` (`fcntl(F_DUPFD, n)`) we fall through to
        // the linear scan: re-ordering the free list to skip entries
        // below `start` while keeping them visible to a later
        // `start = 0` call would require walking to unlink, which
        // costs the same as the linear scan would have.
        //
        // `set()` deliberately does NOT unlink an overwritten empty
        // slot from the free list (there is no back-pointer in a
        // singly-linked list — unlink would walk every entry).
        // Instead we drain stale entries on the consumer side here:
        // pop the head, verify the slot is still empty, return it
        // or skip. Each fd visits the list at most once per close
        // / dup cycle so the amortised cost stays O(1).
        if start == 0 {
            while self.free_list_head != FREE_LIST_END {
                let fd = self.free_list_head;
                let Some((next, occupied)) = self.take_free_list_entry(fd) else {
                    self.free_list_head = FREE_LIST_END;
                    break;
                };
                self.free_list_head = next;
                if !occupied {
                    return Ok(fd);
                }
                // Stale — `set()` overwrote this slot without
                // unlinking. Skip and try the next.
            }
        }
        // Linear scan inside the high-water region. Past the high-
        // water every slot is empty by construction, so we stop the
        // moment we reach it and grow if needed.
        let mut fd = start;
        while fd < self.fd_high_water {
            if self.lookup(fd).is_none() {
                return Ok(fd);
            }
            fd += 1;
        }
        if fd >= self.total_cap {
            self.ensure_grown_to(fd)?;
        }
        Ok(fd)
    }

    /// Iterate every (fd, handle) pair where the slot is occupied.
    /// `f` returns `false` to stop early.
    pub(crate) fn iter_active<F: FnMut(u32, Handle<T>) -> bool>(&self, mut f: F) {
        let segs = self.segments.len();
        for i in 0..segs {
            let Some(seg) = self.segments.get(i) else {
                continue;
            };
            let upper = ::core::cmp::min(seg.cap, self.fd_high_water.saturating_sub(seg.base_fd));
            for j in 0..upper {
                let h = unsafe { *seg.handles.add(j as usize) };
                if h.is_valid() && !f(seg.base_fd + j, h) {
                    return;
                }
            }
        }
    }

    /// Ensure segments cover at least `fd`. Grows by appending fresh
    /// segments (per-segment cap doubles each grow, saturating at
    /// `u32::MAX` slots) until `fd < self.total_cap`. There is no
    /// declared per-segment ceiling — the natural backstop is mmap
    /// allocation failure, surfaced as `SegError::OutOfMemory`.
    pub(crate) fn ensure_grown_to(&mut self, fd: u32) -> Result<(), SegError> {
        while fd >= self.total_cap {
            self.grow_one_segment()?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    fn locate(&self, fd: u32) -> Option<(&SlotTableSegment<T>, u32)> {
        if fd >= self.total_cap {
            return None;
        }
        let segs = self.segments.len();
        for i in 0..segs {
            let seg = self.segments.get(i)?;
            if fd >= seg.base_fd && fd < seg.base_fd + seg.cap {
                return Some((seg, fd - seg.base_fd));
            }
        }
        None
    }

    fn locate_mut(&mut self, fd: u32) -> Option<(&mut SlotTableSegment<T>, u32)> {
        let (idx, local) = self.locate_index(fd)?;
        let seg = self.segments.get_mut(idx)?;
        Some((seg, local))
    }

    fn locate_index(&self, fd: u32) -> Option<(u32, u32)> {
        if fd >= self.total_cap {
            return None;
        }
        let segs = self.segments.len();
        for i in 0..segs {
            let seg = self.segments.get(i)?;
            if fd >= seg.base_fd && fd < seg.base_fd + seg.cap {
                let local = fd - seg.base_fd;
                return Some((i, local));
            }
        }
        None
    }

    fn take_free_list_entry(&mut self, fd: u32) -> Option<(u32, bool)> {
        let (seg, local) = self.locate_mut(fd)?;
        let next = unsafe { *seg.free_next.add(local as usize) };
        unsafe { *seg.free_next.add(local as usize) = FREE_LIST_END };
        let handle = unsafe { *seg.handles.add(local as usize) };
        Some((next, handle.is_valid()))
    }

    fn grow_one_segment(&mut self) -> Result<(), SegError> {
        let cap = self.next_segment_cap;
        let handle_size = ::core::mem::size_of::<Handle<T>>();
        let handles_bytes = (cap as usize)
            .checked_mul(handle_size)
            .ok_or(SegError::Overflow)?;
        let free_next_bytes = (cap as usize)
            .checked_mul(::core::mem::size_of::<u32>())
            .ok_or(SegError::Overflow)?;
        let slot_flags_bytes = cap as usize;
        let handles_alloc = ((handles_bytes + 4095) & !4095) as u64;
        let free_next_alloc = ((free_next_bytes + 4095) & !4095) as u64;
        let slot_flags_alloc = ((slot_flags_bytes + 4095) & !4095) as u64;

        let handles_ptr = unsafe { crate::server::mem::map_anon(handles_alloc) };
        if handles_ptr.is_null() || handles_ptr == usize::MAX as *mut u8 {
            return Err(SegError::OutOfMemory);
        }
        let free_next_ptr = unsafe { crate::server::mem::map_anon(free_next_alloc) };
        if free_next_ptr.is_null() || free_next_ptr == usize::MAX as *mut u8 {
            unsafe { crate::server::mem::unmap(handles_ptr, handles_alloc) };
            return Err(SegError::OutOfMemory);
        }
        let slot_flags_ptr = unsafe { crate::server::mem::map_anon(slot_flags_alloc) };
        if slot_flags_ptr.is_null() || slot_flags_ptr == usize::MAX as *mut u8 {
            unsafe {
                crate::server::mem::unmap(handles_ptr, handles_alloc);
                crate::server::mem::unmap(free_next_ptr, free_next_alloc);
            }
            return Err(SegError::OutOfMemory);
        }

        let handles = handles_ptr as *mut Handle<T>;
        let free_next = free_next_ptr as *mut u32;
        let slot_flags = slot_flags_ptr as *mut u8;
        for i in 0..cap {
            unsafe {
                *handles.add(i as usize) = Handle::<T>::INVALID;
                *free_next.add(i as usize) = FREE_LIST_END;
                *slot_flags.add(i as usize) = 0;
            }
        }
        let base_fd = self.total_cap;
        unsafe {
            self.segments.push(
                SlotTableSegment {
                    base_fd,
                    cap,
                    handles_bytes: handles_alloc,
                    free_next_bytes: free_next_alloc,
                    slot_flags_bytes: slot_flags_alloc,
                    handles,
                    free_next,
                    slot_flags,
                },
                &mut self.allocator,
            )?;
        }
        self.total_cap = self.total_cap.saturating_add(cap);
        self.next_segment_cap = cap.saturating_mul(2);
        Ok(())
    }
}
