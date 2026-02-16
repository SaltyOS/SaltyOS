//! Memory functions (compiler intrinsics)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Byte-level implementations of `memcpy`, `memset`, `memmove`, `memcmp`,
//! `memchr`, `memrchr`, `memmem`, and `bzero`. These are required as
//! compiler intrinsics (`#[no_mangle]`) since Rust's codegen emits calls
//! to them for large copies and zeroing.
//!
//! When `saltyc_sse2` is enabled, the core operations delegate to SSE2-
//! accelerated implementations via the `Arch` trait.

use crate::arch::{Arch, ArchMem};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { <Arch as ArchMem>::memcpy(dest, src, n) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe { <Arch as ArchMem>::memset(s, c, n) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { <Arch as ArchMem>::memmove(dest, src, n) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe { <Arch as ArchMem>::memcmp(s1, s2, n) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mempcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        memcpy(dest, src, n);
        dest.add(n)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
    unsafe { <Arch as ArchMem>::memchr(s, c, n) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memrchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        let val = c as u8;
        let mut i = n;
        while i > 0 {
            i -= 1;
            if *s.add(i) == val {
                return s.add(i) as *mut u8;
            }
        }
        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bzero(s: *mut u8, n: usize) {
    unsafe {
        memset(s, 0, n);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcopy(src: *const u8, dest: *mut u8, n: usize) {
    unsafe {
        memmove(dest, src, n);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn explicit_bzero(s: *mut u8, n: usize) {
    unsafe {
        let mut i = 0;
        while i < n {
            core::ptr::write_volatile(s.add(i), 0);
            i += 1;
        }
    }
}
