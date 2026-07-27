// SPDX-License-Identifier: GPL-2.0-only
//
//! Segment allocator backing for namesrv's `EventLoop`
//! cookie table and any other namesrv-internal `SegmentedArray<T>`.
//!
//! Retypes 4 KiB frames out of the boot_untyped (delivered to
//! namesrv via `ROLE_NAMESRV_BOOT_UNTYPED` — a 1 MiB sub-untyped
//! split from `state.untyped.namesrv_quota` by init's
//! `boot_core::spawn_namesrv`) and maps each into a reserved
//! scratch region of namesrv's own vspace.
//!
//! Boot order is `init → namesrv → rsrcsrv → mmsrv`, so namesrv is
//! up before mmsrv and cannot use `mm::mmap_anon` to back its
//! internal tables. rsrcsrv's vending object set deliberately
//! excludes `OBJ_FRAME` (frame allocation is mmsrv's domain), so
//! namesrv's only path to a fresh frame is to retype out of an
//! untyped it owns.
//!
//! # VA layout
//!
//! [`NAMESRV_SEGMENT_SCRATCH_BASE`] sits clear of namesrv's PIE
//! image, the fixed startup IPC buffer page, the cap-table region,
//! and the stack (mapped near the high end of the user-half address
//! space). 1 MiB of VA spans the entire 1 MiB boot_untyped — every
//! frame the allocator can ever produce fits inside this window.

use trona_kernel::core_types::Cap;
use trona_kernel::invoke;
use trona_server::segmented_array::{SegError, SegmentAllocator};
use uapi::{
    KERNITE_CAP_SELF_VSPACE, KERNITE_OBJ_FRAME, KERNITE_PAGE_BYTES, KERNITE_PAGE_FLAG_USER,
    KERNITE_PAGE_FLAG_WRITABLE,
};

/// Start of the reserved scratch region used by
/// [`NamesrvSegmentAllocator`] to map retyped frames into namesrv's
/// vspace. Aligned to a page boundary; sized to cover the full
/// 1 MiB `boot_untyped` chunk.
pub const NAMESRV_SEGMENT_SCRATCH_BASE: u64 = 0x0000_0000_8000_0000;

/// One past the end of the scratch region. The allocator surfaces
/// `SegError::OutOfMemory` once `next_va` would advance past this.
pub const NAMESRV_SEGMENT_SCRATCH_END: u64 = 0x0000_0000_8010_0000;

/// `SegmentAllocator` impl that backs each segment with retyped
/// 4 KiB frames out of the namesrv boot_untyped. Single-threaded
/// — namesrv's reactor is one TCB, so no synchronisation on
/// `next_va`.
pub struct NamesrvSegmentAllocator {
    boot_untyped: Cap,
    next_va: u64,
}

impl NamesrvSegmentAllocator {
    /// Construct an allocator pinned to `boot_untyped`. The next
    /// allocation maps starting at [`NAMESRV_SEGMENT_SCRATCH_BASE`].
    pub const fn new(boot_untyped: Cap) -> Self {
        Self {
            boot_untyped,
            next_va: NAMESRV_SEGMENT_SCRATCH_BASE,
        }
    }

    /// Bind the allocator to `boot_untyped` after
    /// `read_startup_caps` populates `state.startup.boot_untyped` —
    /// the const constructor takes 0 so `ServerState` can be
    /// initialised statically before the cap table is walked.
    pub fn rebind_untyped(&mut self, boot_untyped: Cap) {
        self.boot_untyped = boot_untyped;
    }
}

impl SegmentAllocator for NamesrvSegmentAllocator {
    unsafe fn alloc_zeroed(&mut self, bytes: usize, _align: usize) -> Result<*mut u8, SegError> {
        if self.boot_untyped == 0 {
            return Err(SegError::OutOfMemory);
        }
        let page_size = KERNITE_PAGE_BYTES as usize;
        // Round up to whole pages — the underlying retype is
        // page-grained, and `SegmentedArray` headers + entries fit
        // comfortably inside one or two pages for any sane T.
        let pages = bytes.checked_add(page_size - 1).ok_or(SegError::Overflow)? / page_size;
        if pages == 0 {
            return Err(SegError::Overflow);
        }
        let total_bytes = pages.checked_mul(page_size).ok_or(SegError::Overflow)?;
        let new_top = self
            .next_va
            .checked_add(total_bytes as u64)
            .ok_or(SegError::Overflow)?;
        if new_top > NAMESRV_SEGMENT_SCRATCH_END {
            return Err(SegError::OutOfMemory);
        }

        let result_va = self.next_va;
        for _ in 0..pages {
            let frame_slot =
                trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"namesrv segment frame");
            let err = invoke::untyped_retype(
                trona_runtime::core::slot_alloc::resolved_cap_ref(self.boot_untyped),
                KERNITE_OBJ_FRAME as u64,
                12, // size_bits = 12 → 4 KiB
                frame_slot,
            );
            if err != 0 {
                return Err(SegError::OutOfMemory);
            }
            let map_err = invoke::vspace_map(
                trona_kernel::core_types::CapRef::flat(KERNITE_CAP_SELF_VSPACE as u64),
                trona_runtime::core::slot_alloc::resolved_cap_ref(frame_slot),
                self.next_va,
                (KERNITE_PAGE_FLAG_USER | KERNITE_PAGE_FLAG_WRITABLE) as u64,
            );
            if map_err != 0 {
                return Err(SegError::OutOfMemory);
            }
            self.next_va += page_size as u64;
        }

        Ok(result_va as *mut u8)
    }
}
