//! Memory utility functions shared across loader and lifecycle modules.
//! SPDX-License-Identifier: GPL-2.0-only

use trona_protocol::posix_abi::mm::*;

/// Zero `len` bytes at `ptr` using u64-wide volatile writes for bulk throughput,
/// with byte-granular head/tail for alignment.
///
/// # Safety
/// `ptr..ptr+len` must be valid, writable, and non-overlapping with any live reference.
pub(crate) unsafe fn volatile_zero(ptr: *mut u8, len: usize) {
    unsafe {
        let align_off = ptr.align_offset(8).min(len);
        for i in 0..align_off {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
        let remaining = len - align_off;
        let qwords = remaining / 8;
        let p64 = ptr.add(align_off) as *mut u64;
        for i in 0..qwords {
            core::ptr::write_volatile(p64.add(i), 0u64);
        }
        let tail_start = align_off + qwords * 8;
        for i in tail_start..len {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
}

/// Copy `len` bytes from `src` to `dst` using u64-wide volatile writes,
/// with byte-granular head/tail for alignment.
///
/// # Safety
/// `dst..dst+len` and `src..src+len` must be valid and non-overlapping.
pub(crate) unsafe fn volatile_copy(dst: *mut u8, src: *const u8, len: usize) {
    unsafe {
        let align_off = dst.align_offset(8).min(len);
        for i in 0..align_off {
            core::ptr::write_volatile(dst.add(i), *src.add(i));
        }
        let remaining = len - align_off;
        let qwords = remaining / 8;
        if qwords > 0 {
            let d64 = dst.add(align_off) as *mut u64;
            let s8 = src.add(align_off);
            for i in 0..qwords {
                let val = core::ptr::read_unaligned(s8.add(i * 8) as *const u64);
                core::ptr::write_volatile(d64.add(i), val);
            }
        }
        let tail_start = align_off + qwords * 8;
        for i in tail_start..len {
            core::ptr::write_volatile(dst.add(i), *src.add(i));
        }
    }
}

pub(crate) unsafe fn alloc_staging_buffer(num_pages: usize) -> *mut u8 {
    unsafe {
        let len = match (num_pages as u64).checked_mul(4096) {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        match trona_runtime::client::mm::mmap(
            core::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ) {
            Ok(ptr) => ptr,
            Err(_) => core::ptr::null_mut(),
        }
    }
}

pub(crate) unsafe fn free_staging_buffer(ptr: *mut u8, num_pages: usize) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        let len = match (num_pages as u64).checked_mul(4096) {
            Some(v) => v,
            None => return,
        };
        let _ = trona_runtime::client::mm::munmap(ptr, len);
    }
}
