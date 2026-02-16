//! x86_64 architecture implementations
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides `X86_64Arch` which implements `ArchMath`, `ArchMem`, and
//! `ArchString`. When `saltyc_sse2` is enabled (default on x86_64),
//! sqrt/sqrtf use SSE2 `sqrtsd`/`sqrtss`, memory operations use 128-bit
//! `movdqu`, and strlen uses `pcmpeqb`+`pmovmskb`. Transcendental math
//! always uses the x87 FPU (no SSE equivalent exists).

pub mod math_x87;
#[cfg(saltyc_sse2)]
pub mod math_sse2;
#[cfg(saltyc_sse2)]
pub mod mem_sse2;
#[cfg(saltyc_sse2)]
pub mod string_sse2;

pub struct X86_64Arch;

impl super::ArchMath for X86_64Arch {
    #[inline]
    fn sqrt(x: f64) -> f64 {
        #[cfg(saltyc_sse2)]
        { unsafe { math_sse2::sqrt_sse2(x) } }
        #[cfg(not(saltyc_sse2))]
        { math_x87::sqrt_x87(x) }
    }

    #[inline]
    fn sqrtf(x: f32) -> f32 {
        #[cfg(saltyc_sse2)]
        { unsafe { math_sse2::sqrtf_sse2(x) } }
        #[cfg(not(saltyc_sse2))]
        { math_x87::sqrt_x87(x as f64) as f32 }
    }

    #[inline]
    fn floor(x: f64) -> f64 { math_x87::floor_x87(x) }
    #[inline]
    fn ceil(x: f64) -> f64 { math_x87::ceil_x87(x) }
    #[inline]
    fn trunc(x: f64) -> f64 { math_x87::trunc_x87(x) }
    #[inline]
    fn rint(x: f64) -> f64 { math_x87::rint_x87(x) }
    #[inline]
    fn sin(x: f64) -> f64 { math_x87::sin_x87(x) }
    #[inline]
    fn cos(x: f64) -> f64 { math_x87::cos_x87(x) }
    #[inline]
    fn tan(x: f64) -> f64 { math_x87::tan_x87(x) }
    #[inline]
    fn atan2(y: f64, x: f64) -> f64 { math_x87::atan2_x87(y, x) }
    #[inline]
    fn log(x: f64) -> f64 { math_x87::log_x87(x) }
    #[inline]
    fn log2(x: f64) -> f64 { math_x87::log2_x87(x) }
    #[inline]
    fn log10(x: f64) -> f64 { math_x87::log10_x87(x) }
    #[inline]
    fn exp(x: f64) -> f64 { math_x87::exp_x87(x) }
    #[inline]
    fn exp2(x: f64) -> f64 { math_x87::exp2_x87(x) }
    #[inline]
    fn pow(x: f64, y: f64) -> f64 { math_x87::pow_x87(x, y) }
    #[inline]
    fn fmod(x: f64, y: f64) -> f64 { math_x87::fmod_x87(x, y) }
    #[inline]
    fn remainder(x: f64, y: f64) -> f64 { math_x87::remainder_x87(x, y) }
    #[inline]
    fn fma(x: f64, y: f64, z: f64) -> f64 { math_x87::fma_x87(x, y, z) }
    #[inline]
    fn scalbn(x: f64, n: i32) -> f64 { math_x87::scalbn_x87(x, n) }
}

impl super::ArchMem for X86_64Arch {
    #[inline]
    unsafe fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        #[cfg(saltyc_sse2)]
        { unsafe { mem_sse2::memcpy_sse2(dst, src, n) } }
        #[cfg(not(saltyc_sse2))]
        { unsafe { scalar_memcpy(dst, src, n) } }
    }

    #[inline]
    unsafe fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
        #[cfg(saltyc_sse2)]
        { unsafe { mem_sse2::memset_sse2(s, c, n) } }
        #[cfg(not(saltyc_sse2))]
        { unsafe { scalar_memset(s, c, n) } }
    }

    #[inline]
    unsafe fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        #[cfg(saltyc_sse2)]
        { unsafe { mem_sse2::memmove_sse2(dst, src, n) } }
        #[cfg(not(saltyc_sse2))]
        { unsafe { scalar_memmove(dst, src, n) } }
    }

    #[inline]
    unsafe fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
        #[cfg(saltyc_sse2)]
        { unsafe { mem_sse2::memcmp_sse2(s1, s2, n) } }
        #[cfg(not(saltyc_sse2))]
        { unsafe { scalar_memcmp(s1, s2, n) } }
    }

    #[inline]
    unsafe fn memchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
        #[cfg(saltyc_sse2)]
        { unsafe { mem_sse2::memchr_sse2(s, c, n) } }
        #[cfg(not(saltyc_sse2))]
        { unsafe { scalar_memchr(s, c, n) } }
    }
}

impl super::ArchString for X86_64Arch {
    #[inline]
    unsafe fn strlen(s: *const u8) -> usize {
        #[cfg(saltyc_sse2)]
        { unsafe { string_sse2::strlen_sse2(s) } }
        #[cfg(not(saltyc_sse2))]
        { unsafe { scalar_strlen(s) } }
    }
}

// ============================================================================
// Scalar fallbacks (used when saltyc_sse2 is disabled)
// ============================================================================

#[cfg(not(saltyc_sse2))]
unsafe fn scalar_memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        dst
    }
}

#[cfg(not(saltyc_sse2))]
unsafe fn scalar_memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
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

#[cfg(not(saltyc_sse2))]
unsafe fn scalar_memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if (dst as usize) < (src as usize) {
            let mut i = 0;
            while i < n {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else {
            let mut i = n;
            while i > 0 {
                i -= 1;
                *dst.add(i) = *src.add(i);
            }
        }
        dst
    }
}

#[cfg(not(saltyc_sse2))]
unsafe fn scalar_memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
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

#[cfg(not(saltyc_sse2))]
unsafe fn scalar_memchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
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

#[cfg(not(saltyc_sse2))]
unsafe fn scalar_strlen(s: *const u8) -> usize {
    unsafe {
        let mut len = 0;
        while *s.add(len) != 0 {
            len += 1;
        }
        len
    }
}
