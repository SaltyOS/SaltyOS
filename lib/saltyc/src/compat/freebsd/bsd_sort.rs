//! BSD sorting algorithms and version string comparison
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! mergesort (stable), heapsort (in-place), strverscmp, strtonum, vcmp.

use crate::errno;

unsafe extern "C" {
    safe fn malloc(size: usize) -> *mut u8;
    safe fn free(ptr: *mut u8);
}

type CmpFn = unsafe extern "C" fn(*const u8, *const u8) -> i32;

/// mergesort — stable sort (BSD extension).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mergesort(
    base: *mut u8,
    nmemb: usize,
    size: usize,
    cmp: CmpFn,
) -> i32 {
    unsafe {
        if nmemb <= 1 {
            return 0;
        }
        let total = nmemb * size;
        let tmp = malloc(total);
        if tmp.is_null() {
            errno::set_errno(errno::ENOMEM);
            return -1;
        }
        core::ptr::copy_nonoverlapping(base, tmp, total);
        mergesort_impl(tmp, base, nmemb, size, cmp);
        free(tmp);
        0
    }
}

unsafe fn mergesort_impl(
    src: *mut u8,
    dst: *mut u8,
    n: usize,
    size: usize,
    cmp: CmpFn,
) {
    unsafe {
        if n <= 1 {
            return;
        }
        let mid = n / 2;
        // Recurse with src/dst swapped so data ends in dst
        mergesort_impl(dst, src, mid, size, cmp);
        mergesort_impl(dst.add(mid * size), src.add(mid * size), n - mid, size, cmp);
        // Merge from src into dst
        let (mut i, mut j, mut k) = (0usize, mid, 0usize);
        while i < mid && j < n {
            if cmp(src.add(i * size), src.add(j * size)) <= 0 {
                core::ptr::copy_nonoverlapping(src.add(i * size), dst.add(k * size), size);
                i += 1;
            } else {
                core::ptr::copy_nonoverlapping(src.add(j * size), dst.add(k * size), size);
                j += 1;
            }
            k += 1;
        }
        while i < mid {
            core::ptr::copy_nonoverlapping(src.add(i * size), dst.add(k * size), size);
            i += 1;
            k += 1;
        }
        while j < n {
            core::ptr::copy_nonoverlapping(src.add(j * size), dst.add(k * size), size);
            j += 1;
            k += 1;
        }
    }
}

/// heapsort — in-place unstable sort (BSD extension).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heapsort(
    base: *mut u8,
    nmemb: usize,
    size: usize,
    cmp: CmpFn,
) -> i32 {
    unsafe {
        if nmemb <= 1 {
            return 0;
        }
        // Build max-heap
        let mut i = nmemb / 2;
        while i > 0 {
            i -= 1;
            sift_down(base, i, nmemb, size, cmp);
        }
        // Extract elements
        let mut end = nmemb - 1;
        while end > 0 {
            swap_elements(base, 0, end, size);
            sift_down(base, 0, end, size, cmp);
            end -= 1;
        }
        0
    }
}

unsafe fn swap_elements(base: *mut u8, a: usize, b: usize, size: usize) {
    unsafe {
        let pa = base.add(a * size);
        let pb = base.add(b * size);
        for i in 0..size {
            let tmp = *pa.add(i);
            *pa.add(i) = *pb.add(i);
            *pb.add(i) = tmp;
        }
    }
}

unsafe fn sift_down(base: *mut u8, start: usize, end: usize, size: usize, cmp: CmpFn) {
    unsafe {
        let mut root = start;
        loop {
            let mut child = 2 * root + 1;
            if child >= end {
                break;
            }
            if child + 1 < end && cmp(base.add(child * size), base.add((child + 1) * size)) < 0 {
                child += 1;
            }
            if cmp(base.add(root * size), base.add(child * size)) < 0 {
                swap_elements(base, root, child, size);
                root = child;
            } else {
                break;
            }
        }
    }
}

/// strverscmp — version comparison: compare strings with embedded numbers treated numerically.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strverscmp(s1: *const u8, s2: *const u8) -> i32 {
    unsafe {
        let mut i = 0usize;
        loop {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a == 0 && b == 0 {
                return 0;
            }
            // If both are digits, compare numerically
            if a >= b'0' && a <= b'9' && b >= b'0' && b <= b'9' {
                // Parse both numbers
                let mut na: u64 = 0;
                let mut j = i;
                while *s1.add(j) >= b'0' && *s1.add(j) <= b'9' {
                    na = na * 10 + (*s1.add(j) - b'0') as u64;
                    j += 1;
                }
                let mut nb: u64 = 0;
                let mut k = i;
                while *s2.add(k) >= b'0' && *s2.add(k) <= b'9' {
                    nb = nb * 10 + (*s2.add(k) - b'0') as u64;
                    k += 1;
                }
                if na != nb {
                    return if na < nb { -1 } else { 1 };
                }
                // Same number but different lengths (leading zeros)
                if j != k {
                    return if j < k { -1 } else { 1 };
                }
                i = j;
                continue;
            }
            if a != b {
                return (a as i32) - (b as i32);
            }
            i += 1;
        }
    }
}

/// strtonum — convert string to number with range checking (BSD extension).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtonum(
    numstr: *const u8,
    minval: i64,
    maxval: i64,
    errstrp: *mut *const u8,
) -> i64 {
    static TOO_SMALL: [u8; 10] = *b"too small\0";
    static TOO_LARGE: [u8; 10] = *b"too large\0";
    static INVALID: [u8; 8] = *b"invalid\0";

    unsafe {
        if numstr.is_null() || *numstr == 0 {
            if !errstrp.is_null() {
                *errstrp = INVALID.as_ptr();
            }
            return 0;
        }
        let mut endptr: *mut u8 = core::ptr::null_mut();
        let val = crate::stdlib_impl::strtoll(numstr, &raw mut endptr, 10);
        if !endptr.is_null() && *endptr != 0 {
            if !errstrp.is_null() {
                *errstrp = INVALID.as_ptr();
            }
            return 0;
        }
        if val < minval {
            if !errstrp.is_null() {
                *errstrp = TOO_SMALL.as_ptr();
            }
            return 0;
        }
        if val > maxval {
            if !errstrp.is_null() {
                *errstrp = TOO_LARGE.as_ptr();
            }
            return 0;
        }
        if !errstrp.is_null() {
            *errstrp = core::ptr::null();
        }
        val
    }
}

/// vcmp — compare version strings. Returns <0, 0, >0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vcmp(s1: *const u8, s2: *const u8) -> i32 {
    unsafe { strverscmp(s1, s2) }
}
