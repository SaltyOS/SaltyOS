// SPDX-License-Identifier: GPL-2.0-only
//
//! `SegmentAllocator` impl backing mmsrv's reactor cookie tables
//! and any other mmsrv-internal `SegmentedArray<T>`.
//!
//! mmsrv is the system-wide frame allocator, so it cannot route
//! its own internal-table grows through `mm::mmap_anon` — that
//! call would re-enter mmsrv's reactor and deadlock. Instead the
//! allocator reaches directly into [`FrameAllocator`] via a raw
//! pointer to retype 4 KiB FRAME caps out of the buddy and maps
//! each one into mmsrv's own vspace at the reserved scratch
//! window.
//!
//! # VA layout
//!
//! [`MMSRV_SEGMENT_SCRATCH_BASE`] sits clear of mmsrv's image,
//! IPC buffer, cap-table, fault dispatcher's stack frame, and
//! every cluster of MO-mapped client pages (those land on
//! per-client VAs the client provided, never inside mmsrv's own
//! address space).

use trona_server::segmented_array::{SegError, SegmentAllocator};
use uapi::{
    KERNITE_CAP_SELF_VSPACE, KERNITE_PAGE_BYTES, KERNITE_PAGE_FLAG_USER, KERNITE_PAGE_FLAG_WRITABLE,
};

use trona_server::frame_alloc::FrameAllocator;

use trona_runtime::spawn::layout::{MMSRV_SEGMENT_SCRATCH_BASE, MMSRV_SEGMENT_SCRATCH_LEN};
const MMSRV_SEGMENT_SCRATCH_END: u64 = MMSRV_SEGMENT_SCRATCH_BASE + MMSRV_SEGMENT_SCRATCH_LEN;

pub struct MmsrvSegmentAllocator {
    /// Raw pointer to the running `FrameAllocator`. Single-thread
    /// dispatch (reactor + fault dispatcher TCB synchronise via
    /// `state_mut` already), so the raw pointer is sound.
    frames: *mut FrameAllocator,
    next_va: u64,
}

impl MmsrvSegmentAllocator {
    pub const fn new() -> Self {
        Self {
            frames: core::ptr::null_mut(),
            next_va: MMSRV_SEGMENT_SCRATCH_BASE,
        }
    }

    /// Bind the allocator to the running [`FrameAllocator`] once
    /// boot has adopted at least one untyped chunk. Pre-bind,
    /// [`alloc_zeroed`](Self::alloc_zeroed) surfaces
    /// `OutOfMemory` so any premature cookie-table grow fails
    /// loudly instead of silently producing zeroed garbage.
    pub fn rebind(&mut self, frames: *mut FrameAllocator) {
        self.frames = frames;
    }
}

impl SegmentAllocator for MmsrvSegmentAllocator {
    unsafe fn alloc_zeroed(&mut self, bytes: usize, _align: usize) -> Result<*mut u8, SegError> {
        if self.frames.is_null() {
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
        if new_top > MMSRV_SEGMENT_SCRATCH_END {
            return Err(SegError::OutOfMemory);
        }

        let result_va = self.next_va;
        for _ in 0..pages {
            let Some(frame) = trona_runtime::core::slot_alloc::alloc_slot() else {
                return Err(SegError::OutOfMemory);
            };
            let Some(backing) = (unsafe { (*self.frames).alloc_frame(frame.addr()) }) else {
                // alloc_frame failed: `frame` is still empty — OwnedSlot Drop frees it.
                return Err(SegError::OutOfMemory);
            };
            // The frame cap now occupies the slot; adopt it as an OwnedCap.
            let frame = frame.assume_filled();
            let map_err = crate::kernel_vm::vspace_map(
                KERNITE_CAP_SELF_VSPACE as u64,
                frame.as_raw(),
                self.next_va,
                (KERNITE_PAGE_FLAG_USER | KERNITE_PAGE_FLAG_WRITABLE) as u64,
            );
            if map_err != 0 {
                unsafe {
                    (*self.frames).release_child(frame.as_raw(), backing);
                }
                // `frame` (OwnedCap) Drop deletes the cap and frees the slot.
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
