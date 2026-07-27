// SPDX-License-Identifier: GPL-2.0-only
//
//! `InitSelfVm` — init's freeable page source for its `trona_server`
//! slabs (the PID table, lifecycle stream, and per-record extras
//! arenas).
//!
//! init runs before mmsrv exists, so its slab grows cannot route
//! through `MM_MMAP`. Like mmsrv's `SelfVm`, `InitSelfVm` retypes one
//! MemoryObject per buffer straight out of init's own untyped pool
//! ([`FrameAllocator`]) and maps it eagerly into init's VSpace at a
//! dedicated scratch window. Unlike mmsrv's `SelfVm`, it commits the
//! MO's pages from that same untyped chunk (`ut_cap = chunk cap`) rather
//! than the kernel PMM, so a freed buffer's pages return to init's
//! untyped pool — init owns and accounts for its own slab memory.
//!
//! # Reset isolation
//!
//! The [`FrameAllocator`] backing `InitSelfVm` adopts a dedicated
//! untyped chunk carved for slab use only — never the chunk
//! [`InitSegmentAllocator`](super::segment_alloc::InitSegmentAllocator)
//! retypes cookie-table FRAMEs from. `FrameAllocator::retype_child`
//! resets an exhausted chunk once its tracked children reach zero, and
//! that counter only sees `InitSelfVm`'s MOs. Sharing a chunk with the
//! segment allocator's untracked FRAMEs would let a reset on a
//! transiently-empty pool destroy live cookie tables.
//!
//! # One MO per buffer / re-entry / free list
//!
//! Identical accounting to mmsrv's `SelfVm`: each [`TrackedBuffer`] is
//! one MO tracked by `(mo_cap_slot, source_chunk_idx)`; the eager
//! `VSPACE_MAP_MO` over already-committed pages keeps the self-fault
//! path from re-entering anything; freed VA runs go to an exact-fit
//! free list, and reused runs keep the bump cursor from exhausting the
//! window across slab reallocations.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_server::frame_alloc::FrameAllocator;
use trona_server::slab::{PageBacking, TrackedBuffer};
use uapi::{
    KERNITE_CAP_SELF_VSPACE, KERNITE_OBJ_MEMORY_OBJECT, KERNITE_PAGE_BYTES, KERNITE_PAGE_FLAG_USER,
    KERNITE_PAGE_FLAG_WRITABLE,
};

// init's private slab-backing VA window comes from the shared layout
// contract; `_END` is one past the window.
use trona_runtime::spawn::layout::{INIT_SLAB_SCRATCH_BASE, INIT_SLAB_SCRATCH_LEN};
const INIT_SLAB_SCRATCH_END: u64 = INIT_SLAB_SCRATCH_BASE + INIT_SLAB_SCRATCH_LEN;

const PAGE_BYTES: u64 = KERNITE_PAGE_BYTES as u64;

/// `VSPACE_MAP_MO` low flag bits: writable + user, eager (the `DEMAND`
/// bit is intentionally unset so committed pages map present). The
/// kernel decodes bit0 = writable, bit1 = user.
const MAP_FLAGS: u64 = (KERNITE_PAGE_FLAG_WRITABLE | KERNITE_PAGE_FLAG_USER) as u64;

/// Anonymous-MO retype selector — bare `KERNITE_OBJ_MEMORY_OBJECT`
/// (the anon kind nibble is zero).
const MO_RETYPE_ANON: u64 = KERNITE_OBJ_MEMORY_OBJECT as u64;

/// Capacity of the VA free list. Each entry is a freed run awaiting
/// exact-fit reuse; overflow leaks the VA run (bounded, rare).
const FREE_LIST_CAP: usize = 128;

#[derive(Clone, Copy)]
struct FreeWindow {
    va: u64,
    pages: u32,
}

/// init's private page-backing allocator. Holds a raw pointer to the
/// running [`FrameAllocator`] (init's single owner thread makes the raw
/// deref sound, same contract as
/// [`InitSegmentAllocator`](super::segment_alloc::InitSegmentAllocator)),
/// a bump cursor into the scratch window, and an exact-fit VA free list.
pub struct InitSelfVm {
    frames: *mut FrameAllocator,
    next_va: u64,
    free_windows: [FreeWindow; FREE_LIST_CAP],
    free_count: usize,
}

impl InitSelfVm {
    /// Construct unbound. [`alloc_pages`](PageBacking::alloc_pages)
    /// fails until [`rebind`](Self::rebind) supplies the
    /// [`FrameAllocator`], so a premature slab grow fails loudly rather
    /// than producing garbage.
    pub const fn new() -> Self {
        Self {
            frames: core::ptr::null_mut(),
            next_va: INIT_SLAB_SCRATCH_BASE,
            free_windows: [FreeWindow { va: 0, pages: 0 }; FREE_LIST_CAP],
            free_count: 0,
        }
    }

    /// Bind to the running [`FrameAllocator`] once boot has carved and
    /// adopted init's dedicated slab untyped chunk.
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
        if new_top > INIT_SLAB_SCRATCH_END {
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

impl PageBacking for InitSelfVm {
    unsafe fn alloc_pages(&mut self, pages: usize) -> Option<TrackedBuffer> {
        unsafe {
            if pages == 0 || self.frames.is_null() {
                return None;
            }
            let n = pages as u64;
            let page_count = pages as u32;
            let size_bits = n.next_power_of_two().trailing_zeros() as u64;
            let va = self.take_va(page_count)?;

            // 1. Retype an anonymous MemoryObject out of the dedicated
            //    slab untyped chunk.
            let slot = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"init slab MO");
            let Some(chunk_idx) =
                (*self.frames).retype_child(MO_RETYPE_ANON, size_bits, slot.addr())
            else {
                // retype failed: `slot` is still empty — its OwnedSlot Drop frees it.
                self.give_va(va, page_count);
                return None;
            };
            // The retype landed an MO cap; adopt the slot as an OwnedCap so every
            // failure path below tears the cap down (delete + free) on
            // drop, and the success path hands it to the TrackedBuffer token.
            let mo = slot.assume_filled();

            // 2. Commit `n` pages from init's own untyped chunk so the
            //    pages return to init's pool when the MO is freed.
            let Some(ut_cap) = (*self.frames).chunk_cap(chunk_idx) else {
                (*self.frames).release_child(mo.as_raw(), chunk_idx);
                self.give_va(va, page_count);
                return None;
            };
            let commit_err = invoke::mo_commit(mo.borrow(), 0, n, ut_cap);
            if commit_err != 0 {
                (*self.frames).release_child(mo.as_raw(), chunk_idx);
                self.give_va(va, page_count);
                return None;
            }

            // 3. Eager-map the committed pages present at `va`.
            let count_and_flags = (n << 32) | MAP_FLAGS;
            let (map_err, mapped) = invoke::vspace_map_mo_with_count(
                CapRef::flat(KERNITE_CAP_SELF_VSPACE as u64),
                mo.as_raw(),
                va,
                0,
                count_and_flags,
            );
            if map_err != 0 || mapped != n {
                for i in 0..mapped {
                    let _ = invoke::vspace_unmap(
                        CapRef::flat(KERNITE_CAP_SELF_VSPACE as u64),
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
                let _ = invoke::vspace_unmap(
                    CapRef::flat(KERNITE_CAP_SELF_VSPACE as u64),
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
