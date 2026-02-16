//! SSE2 memory operations for x86_64
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! SIMD-accelerated memcpy, memset, memmove, memcmp, and memchr using
//! SSE2 128-bit `movdqu`/`movdqa`/`pcmpeqb`/`pmovmskb` instructions.
//! Falls back to byte-level operations for sizes below 16 bytes and for
//! alignment fixup regions.

use core::arch::asm;

/// SSE2-accelerated memcpy. Uses 16-byte `movdqu` loads/stores for the
/// bulk of the copy, with byte-level handling for the tail.
///
/// # Safety
/// `dst` and `src` must be valid for `n` bytes. Regions must not overlap
/// (use `memmove_sse2` for overlapping regions).
#[inline]
#[target_feature(enable = "sse,sse2")]
pub unsafe fn memcpy_sse2(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0usize;

        // 16-byte SSE2 loop
        while i + 16 <= n {
            // SAFETY: movdqu handles unaligned 128-bit loads/stores. SSE2 baseline.
            asm!(
                "movdqu {tmp}, xmmword ptr [{src}]",
                "movdqu xmmword ptr [{dst}], {tmp}",
                src = in(reg) src.add(i),
                dst = in(reg) dst.add(i),
                tmp = out(xmm_reg) _,
                options(nostack),
            );
            i += 16;
        }

        // 8-byte chunk
        if i + 8 <= n {
            *(dst.add(i) as *mut u64) = *(src.add(i) as *const u64);
            i += 8;
        }

        // Remaining bytes
        while i < n {
            *dst.add(i) = *src.add(i);
            i += 1;
        }

        dst
    }
}

/// SSE2-accelerated memset. Broadcasts the byte value to a 128-bit XMM
/// register and writes 16 bytes at a time.
///
/// # Safety
/// `s` must be valid for `n` bytes.
#[inline]
#[target_feature(enable = "sse,sse2")]
pub unsafe fn memset_sse2(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        let val = c as u8;
        let mut i = 0usize;

        // Build 64-bit fill pattern: 0x0101...01 * val
        let fill8 = 0x0101_0101_0101_0101u64.wrapping_mul(val as u64);

        // 16-byte SSE2 loop: broadcast + store in one asm block
        while i + 16 <= n {
            asm!(
                "movq {tmp}, [{fill}]",
                "punpcklqdq {tmp}, {tmp}",
                "movdqu xmmword ptr [{dst}], {tmp}",
                fill = in(reg) &fill8 as *const u64,
                dst = in(reg) s.add(i),
                tmp = out(xmm_reg) _,
                options(nostack),
            );
            i += 16;
        }

        // 8-byte chunk
        if i + 8 <= n {
            *(s.add(i) as *mut u64) = fill8;
            i += 8;
        }

        // Remaining bytes
        while i < n {
            *s.add(i) = val;
            i += 1;
        }

        s
    }
}

/// SSE2-accelerated memmove. Forward copy when dst < src (uses memcpy_sse2),
/// backward 16-byte copy otherwise.
///
/// # Safety
/// `dst` and `src` must be valid for `n` bytes. Regions may overlap.
#[inline]
#[target_feature(enable = "sse,sse2")]
pub unsafe fn memmove_sse2(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if (dst as usize) < (src as usize) || (dst as usize) >= (src as usize) + n {
            // Non-overlapping or forward-safe: use memcpy
            return memcpy_sse2(dst, src, n);
        }

        // Backward copy for overlapping dst > src
        let mut i = n;

        // 16-byte backward SSE2 loop
        while i >= 16 {
            i -= 16;
            asm!(
                "movdqu {tmp}, xmmword ptr [{src}]",
                "movdqu xmmword ptr [{dst}], {tmp}",
                src = in(reg) src.add(i),
                dst = in(reg) dst.add(i),
                tmp = out(xmm_reg) _,
                options(nostack),
            );
        }

        // Remaining bytes backward
        while i > 0 {
            i -= 1;
            *dst.add(i) = *src.add(i);
        }

        dst
    }
}

/// SSE2-accelerated memcmp. Compares 16 bytes at a time using `pcmpeqb`
/// + `pmovmskb`, falling back to byte comparison on mismatch.
///
/// # Safety
/// `s1` and `s2` must be valid for `n` bytes.
#[inline]
#[target_feature(enable = "sse,sse2")]
pub unsafe fn memcmp_sse2(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe {
        let mut i = 0usize;

        // 16-byte SSE2 comparison loop
        while i + 16 <= n {
            let mask: u32;
            asm!(
                "movdqu {a}, xmmword ptr [{s1}]",
                "movdqu {b}, xmmword ptr [{s2}]",
                "pcmpeqb {a}, {b}",
                "pmovmskb {mask:e}, {a}",
                s1 = in(reg) s1.add(i),
                s2 = in(reg) s2.add(i),
                a = out(xmm_reg) _,
                b = out(xmm_reg) _,
                mask = out(reg) mask,
                options(nostack),
            );
            if mask != 0xFFFF {
                // At least one byte differs — find first mismatch
                let diff_bit = (!mask) & 0xFFFF;
                let pos = diff_bit.trailing_zeros() as usize;
                let a = *s1.add(i + pos);
                let b = *s2.add(i + pos);
                return a as i32 - b as i32;
            }
            i += 16;
        }

        // Remaining bytes
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

/// SSE2-accelerated memchr. Broadcasts the search byte and uses `pcmpeqb`
/// + `pmovmskb` to scan 16 bytes at a time.
///
/// # Safety
/// `s` must be valid for `n` bytes.
#[inline]
#[target_feature(enable = "sse,sse2")]
pub unsafe fn memchr_sse2(s: *const u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        let val = c as u8;
        let mut i = 0usize;

        // Build 64-bit broadcast pattern
        let fill8 = 0x0101_0101_0101_0101u64.wrapping_mul(val as u64);

        // 16-byte SSE2 search loop: broadcast + compare in one asm block
        while i + 16 <= n {
            let mask: u32;
            asm!(
                "movq {needle}, [{fill}]",
                "punpcklqdq {needle}, {needle}",
                "movdqu {data}, xmmword ptr [{src}]",
                "pcmpeqb {data}, {needle}",
                "pmovmskb {mask:e}, {data}",
                fill = in(reg) &fill8 as *const u64,
                src = in(reg) s.add(i),
                needle = out(xmm_reg) _,
                data = out(xmm_reg) _,
                mask = out(reg) mask,
                options(nostack),
            );
            if mask != 0 {
                let pos = mask.trailing_zeros() as usize;
                return s.add(i + pos) as *mut u8;
            }
            i += 16;
        }

        // Remaining bytes
        while i < n {
            if *s.add(i) == val {
                return s.add(i) as *mut u8;
            }
            i += 1;
        }

        core::ptr::null_mut()
    }
}
