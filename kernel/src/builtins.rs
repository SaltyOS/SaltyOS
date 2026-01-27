//! Compiler builtins for freestanding environment
//!
//! These functions are required by the Rust compiler for memory operations.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// memset implementation
///
/// # Safety
/// Caller must ensure dest points to valid memory of at least n bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let c = c as u8;
    // SAFETY: Caller guarantees dest is valid for n bytes
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = c;
            i += 1;
        }
    }
    dest
}

/// memcpy implementation
///
/// # Safety
/// Caller must ensure src and dest point to valid non-overlapping memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: Caller guarantees non-overlapping valid memory
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
    }
    dest
}

/// memmove implementation (handles overlapping regions)
///
/// # Safety
/// Caller must ensure src and dest point to valid memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: Caller guarantees valid memory, we handle overlap
    unsafe {
        if (dest as usize) < (src as usize) {
            // Copy forwards
            let mut i = 0;
            while i < n {
                *dest.add(i) = *src.add(i);
                i += 1;
            }
        } else {
            // Copy backwards
            let mut i = n;
            while i > 0 {
                i -= 1;
                *dest.add(i) = *src.add(i);
            }
        }
    }
    dest
}

/// memcmp implementation
///
/// # Safety
/// Caller must ensure s1 and s2 point to valid memory of at least n bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    // SAFETY: Caller guarantees valid memory
    unsafe {
        let mut i = 0;
        while i < n {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b {
                return (a as i32) - (b as i32);
            }
            i += 1;
        }
    }
    0
}

/// bcmp implementation (like memcmp but only returns 0 or non-zero)
///
/// # Safety
/// Caller must ensure s1 and s2 point to valid memory of at least n bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    // SAFETY: memcmp handles the safety requirements
    unsafe { memcmp(s1, s2, n) }
}

/// strlen implementation
///
/// # Safety
/// Caller must ensure s points to a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    // SAFETY: Caller guarantees null-terminated string
    unsafe {
        let mut len = 0;
        while *s.add(len) != 0 {
            len += 1;
        }
        len
    }
}
