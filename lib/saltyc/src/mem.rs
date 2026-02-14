//! Memory functions (compiler intrinsics)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Byte-level implementations of `memcpy`, `memset`, `memmove`, `memcmp`,
//! `memchr`, `memrchr`, `memmem`, and `bzero`. These are required as
//! compiler intrinsics (`#[no_mangle]`) since Rust's codegen emits calls
//! to them for large copies and zeroing.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        let val = c as u8;
        let mut i = 0;
        while i < n {
            *s.add(i) = val;
            i += 1;
        }
        s
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if (dest as usize) < (src as usize) {
            let mut i = 0;
            while i < n {
                *dest.add(i) = *src.add(i);
                i += 1;
            }
        } else {
            let mut i = n;
            while i > 0 {
                i -= 1;
                *dest.add(i) = *src.add(i);
            }
        }
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe {
        let mut i = 0;
        while i < n {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
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
    unsafe {
        let val = c as u8;
        let mut i = 0;
        while i < n {
            if *s.add(i) == val {
                return s.add(i) as *mut u8;
            }
            i += 1;
        }
        core::ptr::null_mut()
    }
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
