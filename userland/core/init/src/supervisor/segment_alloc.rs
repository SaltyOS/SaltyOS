// SPDX-License-Identifier: GPL-2.0-only
//
//! `SegmentAllocator` impl backing init's reactor cookie table and
//! any other init-internal `SegmentedArray<T>`.
//!
//! init runs before mmsrv exists, so cookie-table grows during boot
//! cannot route through mmsrv's `MM_MMAP`. The allocator instead
//! retypes 4 KiB FRAMEs from a caller-provided untyped cap (init's
//! `state.untyped.init_private` chunk) and maps each frame
//! contiguously into init's own VSpace at the dedicated scratch
//! window [`INIT_SEGMENT_SCRATCH_BASE`].
//!
//! The mode survives past Stage E too — even after init self-registers
//! with mmsrv, dispatcher state mutation runs on the owner thread that
//! holds no mmsrv RPC in flight, so re-entering `MM_MMAP` is fine; the
//! direct-untyped path stays the simpler choice.
//!
//! # VA layout
//!
//! [`INIT_SEGMENT_SCRATCH_BASE`] sits clear of init's image, IPC
//! buffer, cap-table frame, scratch staging window, and every region
//! mmsrv hands back through `MM_MMAP` (those land on mmsrv-chosen
//! VAs starting from init's `mmap_base`).

use trona_kernel::invoke;
use trona_server::segmented_array::{SegError, SegmentAllocator};
use uapi::{
    KERNITE_CAP_SELF_VSPACE, KERNITE_OBJ_FRAME, KERNITE_PAGE_BYTES, KERNITE_PAGE_FLAG_USER,
    KERNITE_PAGE_FLAG_WRITABLE,
};

use trona_runtime::spawn::layout::{INIT_SEGMENT_SCRATCH_BASE, INIT_SEGMENT_SCRATCH_LEN};
const INIT_SEGMENT_SCRATCH_END: u64 = INIT_SEGMENT_SCRATCH_BASE + INIT_SEGMENT_SCRATCH_LEN;

pub struct InitSegmentAllocator {
    /// Untyped cap that backing FRAMEs are retyped from. Init binds
    /// this to `state.untyped.init_private` after Stage B splits the
    /// boot untyped. Pre-bind, [`alloc_zeroed`] surfaces
    /// `OutOfMemory` so any premature cookie-table grow fails loudly
    /// instead of silently producing zeroed garbage.
    untyped: u64,
    next_va: u64,
}

impl InitSegmentAllocator {
    pub const fn new() -> Self {
        Self {
            untyped: 0,
            next_va: INIT_SEGMENT_SCRATCH_BASE,
        }
    }

    /// Bind the allocator to a live untyped cap. Call once after
    /// Stage B has split the boot untyped, before any
    /// `state.cookie_table.arm` invocation.
    pub fn rebind(&mut self, untyped: u64) {
        self.untyped = untyped;
    }
}

impl SegmentAllocator for InitSegmentAllocator {
    unsafe fn alloc_zeroed(&mut self, bytes: usize, _align: usize) -> Result<*mut u8, SegError> {
        if self.untyped == 0 {
            return Err(SegError::OutOfMemory);
        }
        let page_size = KERNITE_PAGE_BYTES as usize;
        let pages = bytes.checked_add(page_size - 1).ok_or(SegError::Overflow)? / page_size;
        if pages == 0 {
            return Err(SegError::Overflow);
        }
        let total_bytes = pages.checked_mul(page_size).ok_or(SegError::Overflow)?;
        let new_top = self
            .next_va
            .checked_add(total_bytes as u64)
            .ok_or(SegError::Overflow)?;
        if new_top > INIT_SEGMENT_SCRATCH_END {
            return Err(SegError::OutOfMemory);
        }

        let result_va = self.next_va;
        for _ in 0..pages {
            // Allocate a fresh CSpace slot per page — same shape as
            // mmsrv's `MmsrvSegmentAllocator`. Retaining each frame
            // cap costs one slot per page but matches the kernel's
            // VSPACE_MAP contract: the frame stays referenced via
            // both its CSpace cap and the page-table entry, and the
            // SegmentedArray never frees the backing.
            let frame = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"init segment frame");
            let r = invoke::untyped_retype(
                trona_runtime::core::slot_alloc::resolved_cap_ref(self.untyped),
                KERNITE_OBJ_FRAME,
                0,
                frame.addr(),
            );
            if r != 0 {
                // retype failed: `frame` (OwnedSlot) Drop frees the empty slot.
                return Err(SegError::OutOfMemory);
            }
            let frame = frame.assume_filled();
            let map_flags = KERNITE_PAGE_FLAG_USER | KERNITE_PAGE_FLAG_WRITABLE;
            let r = invoke::vspace_map(
                trona_kernel::core_types::CapRef::flat(KERNITE_CAP_SELF_VSPACE),
                frame.borrow(),
                self.next_va,
                map_flags,
            );
            if r != 0 {
                // map failed: `frame` (OwnedCap) Drop deletes the cap and frees the slot.
                return Err(SegError::OutOfMemory);
            }
            // Success: the frame stays referenced for the process lifetime (CSpace
            // cap + PTE); intentionally retain the slot by forgetting the owner.
            core::mem::forget(frame);
            self.next_va += page_size as u64;
        }

        Ok(result_va as *mut u8)
    }
}
