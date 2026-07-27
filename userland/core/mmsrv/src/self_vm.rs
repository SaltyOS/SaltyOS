// SPDX-License-Identifier: GPL-2.0-only
//
//! `SelfVm` — mmsrv's private page source for its `trona_server` slabs
//! ([`TrackedSlab`](trona_server::slab::TrackedSlab) /
//! [`BaseSortedIndex`](trona_server::slab::BaseSortedIndex)).
//!
//! mmsrv *is* the system frame allocator, so it cannot back its own
//! internal region / reservation tables through `MM_MMAP` — that call
//! would re-enter mmsrv's reactor and deadlock. `SelfVm` instead
//! retypes a MemoryObject straight out of mmsrv's untyped pool
//! ([`FrameAllocator`]), commits its pages from the kernel PMM, and
//! maps them into mmsrv's own VSpace at a dedicated scratch window. It
//! is the live rebuild of the retired `kernel_vm::tracked_alloc_pages`
//! path: same kernel calls, but driven by [`FrameAllocator::retype_child`]
//! instead of the removed `recycled_*` / `rsrcsrv_alloc_object` plumbing.
//!
//! # One MO per buffer
//!
//! Each [`TrackedBuffer`] is exactly one MemoryObject covering its
//! pages, so freeing tracks a single `(mo_cap_slot, source_chunk_idx)`
//! — the same single-chunk accounting [`crate::mo_registry`] uses for
//! client MOs. A per-frame scheme would need a variable-length cap
//! array per buffer, which a fixed `TrackedBuffer` cannot hold.
//!
//! # Re-entry safety
//!
//! `mo_commit(ut_cap = 0)` allocates from the kernel bitmap PMM, and
//! the eager `VSPACE_MAP_MO` (no `DEMAND` flag) installs present PTEs
//! over the committed pages — both are pure kernel syscalls with no
//! callback into mmsrv's reactor or fault dispatcher. Mapping eagerly
//! over already-committed pages is what keeps the self-fault path from
//! ever re-entering mmsrv.
//!
//! # VA window + free list
//!
//! Buffers map into [`MMSRV_SLAB_SCRATCH_BASE`]..[`MMSRV_SLAB_SCRATCH_END`],
//! disjoint from the cookie-table segment window
//! (`MMSRV_SEGMENT_SCRATCH_*`) and clear of the fault dispatcher stack.
//! Slabs grow by reallocating (allocate the doubled run, free the old),
//! so a bump-only cursor would exhaust the window after enough grows;
//! freed runs go to an exact-fit free list and are reused by later
//! same-size allocations. Free-list overflow falls back to leaking the
//! VA run — the MemoryObject is still freed, only the address range is
//! lost, and the window is sized far above the live footprint.

use trona_server::slab::{PageBacking, TrackedBuffer};
use uapi::{
    KERNITE_CAP_SELF_VSPACE, KERNITE_OBJ_MEMORY_OBJECT, KERNITE_PAGE_BYTES, KERNITE_PAGE_FLAG_USER,
    KERNITE_PAGE_FLAG_WRITABLE,
};

use trona_server::frame_alloc::FrameAllocator;

// mmsrv's private slab-backing VA window comes from the shared layout
// contract; `_END` is one past the window.
use trona_runtime::spawn::layout::{MMSRV_SLAB_SCRATCH_BASE, MMSRV_SLAB_SCRATCH_LEN};
const MMSRV_SLAB_SCRATCH_END: u64 = MMSRV_SLAB_SCRATCH_BASE + MMSRV_SLAB_SCRATCH_LEN;

const PAGE_BYTES: u64 = KERNITE_PAGE_BYTES as u64;

/// `VSPACE_MAP_MO` low flag bits: writable + user, eager (the `DEMAND`
/// bit is intentionally unset so committed pages map present). The
/// kernel decodes bit0 = writable, bit1 = user — matching
/// `KERNITE_PAGE_FLAG_WRITABLE` / `_USER`.
const MAP_FLAGS: u64 = (KERNITE_PAGE_FLAG_WRITABLE | KERNITE_PAGE_FLAG_USER) as u64;

/// Anonymous-MO retype selector — bare `KERNITE_OBJ_MEMORY_OBJECT`
/// (the anon kind nibble is zero), matching `MoRegistry`'s selector for
/// `MoKind::Anon`.
const MO_RETYPE_ANON: u64 = KERNITE_OBJ_MEMORY_OBJECT as u64;

/// Capacity of the VA free list. Each entry is a freed run awaiting
/// exact-fit reuse; overflow leaks the VA run (bounded, rare).
const FREE_LIST_CAP: usize = 256;

#[derive(Clone, Copy)]
struct FreeWindow {
    va: u64,
    pages: u32,
}

/// mmsrv's private page-backing allocator. Holds a raw pointer to the
/// running [`FrameAllocator`] (single-threaded dispatch makes the raw
/// deref sound, same contract as `MmsrvSegmentAllocator`), a bump
/// cursor into the scratch window, and an exact-fit VA free list.
pub struct SelfVm {
    frames: *mut FrameAllocator,
    next_va: u64,
    free_windows: [FreeWindow; FREE_LIST_CAP],
    free_count: usize,
}

impl SelfVm {
    /// Construct unbound. [`alloc_pages`](PageBacking::alloc_pages)
    /// fails until [`rebind`](Self::rebind) supplies the
    /// [`FrameAllocator`], so a premature slab grow fails loudly rather
    /// than producing garbage.
    pub const fn new() -> Self {
        Self {
            frames: core::ptr::null_mut(),
            next_va: MMSRV_SLAB_SCRATCH_BASE,
            free_windows: [FreeWindow { va: 0, pages: 0 }; FREE_LIST_CAP],
            free_count: 0,
        }
    }

    /// Bind to the running [`FrameAllocator`] once boot has adopted at
    /// least one untyped chunk. Mirrors `MmsrvSegmentAllocator::rebind`.
    pub fn rebind(&mut self, frames: *mut FrameAllocator) {
        self.frames = frames;
    }

    /// Take a VA run of exactly `pages` pages: reuse a freed run of the
    /// same size, else bump the cursor. Returns `None` when the window
    /// is exhausted.
    fn take_va(&mut self, pages: u32) -> Option<u64> {
        let mut i = 0;
        while i < self.free_count {
            if self.free_windows[i].pages == pages {
                let va = self.free_windows[i].va;
                self.free_count -= 1;
                self.free_windows[i] = self.free_windows[self.free_count];
                return Some(va);
            }
            i += 1;
        }
        let bytes = (pages as u64).checked_mul(PAGE_BYTES)?;
        let new_top = self.next_va.checked_add(bytes)?;
        if new_top > MMSRV_SLAB_SCRATCH_END {
            return None;
        }
        let va = self.next_va;
        self.next_va = new_top;
        Some(va)
    }

    /// Return a VA run to the free list, or leak it (cursor not
    /// reclaimed) when the free list is full. The backing MemoryObject
    /// has already been released by the caller — only the address range
    /// is recycled here.
    fn give_va(&mut self, va: u64, pages: u32) {
        if self.free_count < FREE_LIST_CAP {
            self.free_windows[self.free_count] = FreeWindow { va, pages };
            self.free_count += 1;
        }
    }
}

impl PageBacking for SelfVm {
    unsafe fn alloc_pages(&mut self, pages: usize) -> Option<TrackedBuffer> {
        unsafe {
            if pages == 0 || self.frames.is_null() {
                return None;
            }
            let n = pages as u64;
            let page_count = pages as u32;
            let size_bits = n.next_power_of_two().trailing_zeros() as u64;
            let va = self.take_va(page_count)?;

            // 1. Retype an anonymous MemoryObject out of the untyped pool.
            let Some(slot) = trona_runtime::core::slot_alloc::alloc_slot() else {
                self.give_va(va, page_count);
                return None;
            };
            let Some(chunk_idx) =
                (*self.frames).retype_child(MO_RETYPE_ANON, size_bits, slot.addr())
            else {
                // retype failed: `slot` is still empty — its OwnedSlot Drop frees it.
                self.give_va(va, page_count);
                return None;
            };
            // The retype landed an MO cap; adopt the slot as an OwnedCap so every
            // failure path tears it down on drop, and success hands it to the token.
            let mo = slot.assume_filled();

            // 2. Commit `n` pages from the kernel PMM (zero-filled kernel-side).
            let commit_err = crate::kernel_vm::commit_mo_pages(mo.as_raw(), 0, n);
            if commit_err != 0 {
                (*self.frames).release_child(mo.as_raw(), chunk_idx);
                self.give_va(va, page_count);
                return None;
            }

            // 3. Eager-map the committed pages present at `va`.
            let count_and_flags = (n << 32) | MAP_FLAGS;
            let (map_err, mapped) = crate::kernel_vm::vspace_map_mo_with_count(
                KERNITE_CAP_SELF_VSPACE as u64,
                mo.as_raw(),
                va,
                0,
                count_and_flags,
            );
            if map_err != 0 || mapped != n {
                for i in 0..mapped {
                    let _ = crate::kernel_vm::vspace_unmap(
                        KERNITE_CAP_SELF_VSPACE as u64,
                        va + i * PAGE_BYTES,
                    );
                }
                (*self.frames).release_child(mo.as_raw(), chunk_idx);
                self.give_va(va, page_count);
                return None;
            }

            Some(TrackedBuffer::new(
                va as *mut u8,
                page_count,
                [mo.into_raw(), chunk_idx as u64],
            ))
        }
    }

    unsafe fn free_pages(&mut self, buf: TrackedBuffer) {
        unsafe {
            if buf.is_empty() {
                return;
            }
            let token = buf.token();
            let mo_cap = token[0];
            let chunk_idx = token[1] as usize;
            let va = buf.ptr() as u64;
            let page_count = buf.pages();

            for i in 0..page_count as u64 {
                let _ = crate::kernel_vm::vspace_unmap(
                    KERNITE_CAP_SELF_VSPACE as u64,
                    va + i * PAGE_BYTES,
                );
            }
            if !self.frames.is_null() {
                (*self.frames).release_child(mo_cap, chunk_idx);
            }
            // SAFETY: in the normal path `release_child` above deleted the MO cap,
            // leaving this slot empty; the slot was allocated for this TrackedBuffer
            // and is reclaimed exactly once here. (The `frames`-null branch is a
            // degenerate teardown that matches the prior raw `slot_free`.)
            trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(mo_cap);
            self.give_va(va, page_count);
        }
    }
}
