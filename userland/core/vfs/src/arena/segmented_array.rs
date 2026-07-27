// SPDX-License-Identifier: GPL-2.0-only
//
//! vfs-side wiring for [`trona_server::segmented_array::SegmentedArray`].
//!
//! Re-exports the substrate generic plus a concrete
//! [`MmapAllocator`] that backs every segment via mmsrv's
//! `MM_MMAP MAP_ANONYMOUS`. Core servers (mmsrv / rsrcsrv / init /
//! namesrv) cannot use this — they sit in the boot graph below
//! mmsrv and have to retype frames out of their own untyped pools.
//! Leaf services like vfs / future netsrv subsystems / future ext4
//! reuse `MmapAllocator` directly.

pub(crate) use trona_server::segmented_array::{SegError, SegmentAllocator, SegmentedArray};

/// `SegmentAllocator` impl that backs each segment with anonymous
/// memory mapped through [`crate::server::mem::map_anon`]. Stateless
/// — every instance hands out the same pages from mmsrv's anon pool.
#[derive(Clone, Copy, Default)]
pub(crate) struct MmapAllocator;

impl MmapAllocator {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl SegmentAllocator for MmapAllocator {
    unsafe fn alloc_zeroed(&mut self, bytes: usize, _align: usize) -> Result<*mut u8, SegError> {
        // mmsrv's MM_MMAP rounds up to page granularity and zero-fills
        // — both the alignment and the zero-init contract are met by
        // construction. The `_align` parameter is informational; the
        // returned pointer is page-aligned and `_align` is never
        // larger than that for any caller in this tree.
        let rounded = ((bytes + 4095) & !4095) as u64;
        let p = unsafe { crate::server::mem::map_anon(rounded) };
        if p.is_null() || p == usize::MAX as *mut u8 {
            Err(SegError::OutOfMemory)
        } else {
            Ok(p)
        }
    }
}
