// SPDX-License-Identifier: GPL-2.0-only
//
//! `SegmentAllocator` impl backing rsrcsrv's reactor cookie table
//! and any other rsrcsrv-internal `SegmentedArray<T>`.
//!
//! rsrcsrv cannot route its internal-table grows through `mm::mmap_anon`
//! because mmsrv hasn't been spawned yet at rsrcsrv startup time —
//! `mmsrv` is the next core service after rsrcsrv in init's boot
//! sequence. Instead the allocator wraps [`selfmem::map_one_page`]:
//! each grow request retypes one or more 4 KiB FRAMEs from rsrcsrv's
//! own untyped pool ([`ROLE_RSRCSRV_AUTHORITY_RAW`]) and maps them
//! contiguously into rsrcsrv's vspace at the dedicated self-storage
//! window.
//!
//! # VA layout
//!
//! [`selfmem::SELF_STORAGE_BASE`] (`0x0080_0000`) sits clear of
//! rsrcsrv's image and stack. The window is 64 MiB
//! ([`selfmem::SELF_STORAGE_LIMIT`]) — far more than the cookie
//! table needs.

use trona_server::segmented_array::{SegError, SegmentAllocator};
use uapi::KERNITE_PAGE_BYTES;

use crate::selfmem;

pub struct RsrcsrvSegmentAllocator;

impl RsrcsrvSegmentAllocator {
    pub const fn new() -> Self {
        Self
    }
}

impl SegmentAllocator for RsrcsrvSegmentAllocator {
    unsafe fn alloc_zeroed(&mut self, bytes: usize, _align: usize) -> Result<*mut u8, SegError> {
        let page_size = KERNITE_PAGE_BYTES as usize;
        let pages = bytes.checked_add(page_size - 1).ok_or(SegError::Overflow)? / page_size;
        if pages == 0 {
            return Err(SegError::Overflow);
        }

        let state = crate::main_loop::state_mut();
        let mut first_va: Option<u64> = None;
        let mut prev_va: Option<u64> = None;
        for _ in 0..pages {
            // Each `map_one_page` call appends another page at the
            // current high watermark — the watermark is monotonic,
            // so a sequence of N successful calls produces N
            // contiguous pages.
            let va = match selfmem::map_one_page(&mut state.untyped) {
                Some(v) => v,
                None => return Err(SegError::OutOfMemory),
            };
            if first_va.is_none() {
                first_va = Some(va);
            } else if let Some(prev) = prev_va {
                debug_assert_eq!(va, prev + page_size as u64);
            }
            prev_va = Some(va);
        }

        Ok(first_va.expect("pages > 0") as *mut u8)
    }
}
