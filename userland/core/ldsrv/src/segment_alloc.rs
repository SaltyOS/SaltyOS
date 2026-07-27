// SPDX-License-Identifier: GPL-2.0-only
//
//! `SegmentAllocator` backing ldsrv's reactor cookie table.
//!
//! ldsrv boots after mmsrv (Stage H), so unlike the core servers below mmsrv
//! it backs its internal `SegmentedArray<T>` storage with anonymous memory
//! mapped through `MM_MMAP MAP_ANONYMOUS` rather than retyping frames from its
//! own untyped. Mirrors vfs's `MmapAllocator`.

use trona_protocol::posix_abi::mm::{MAP_PRIVATE, PROT_READ, PROT_WRITE};
use trona_server::segmented_array::{SegError, SegmentAllocator};

/// Stateless allocator — every grow hands out fresh anonymous pages from
/// mmsrv's pool.
pub struct LdsrvSegmentAllocator;

impl LdsrvSegmentAllocator {
    pub const fn new() -> Self {
        Self
    }
}

impl SegmentAllocator for LdsrvSegmentAllocator {
    unsafe fn alloc_zeroed(&mut self, bytes: usize, _align: usize) -> Result<*mut u8, SegError> {
        // mmsrv rounds up to page granularity and zero-fills, satisfying both
        // the alignment and zero-init contracts. `_align` is informational;
        // the returned pointer is page-aligned, larger than any caller needs.
        let rounded = ((bytes + 4095) & !4095) as u64;
        let p = unsafe {
            trona_runtime::client::mm::mmap_anonymous(
                core::ptr::null_mut(),
                rounded,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE,
            )
        };
        match p {
            Ok(ptr) if !ptr.is_null() && ptr != usize::MAX as *mut u8 => Ok(ptr),
            _ => Err(SegError::OutOfMemory),
        }
    }
}
