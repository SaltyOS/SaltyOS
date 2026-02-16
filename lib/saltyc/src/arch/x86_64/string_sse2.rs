//! SSE2 string operations for x86_64
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! SIMD-accelerated strlen using SSE2 `pcmpeqb` + `pmovmskb` to scan
//! 16 bytes at a time for the NUL terminator. Handles alignment carefully
//! to avoid crossing page boundaries.

use core::arch::asm;

/// SSE2-accelerated strlen. Aligns to 16-byte boundary then scans 16 bytes
/// at a time using `pxor`/`pcmpeqb`/`pmovmskb` to detect NUL bytes.
///
/// # Safety
/// `s` must point to a NUL-terminated string. The string must be readable
/// up to the next 16-byte aligned boundary past the NUL terminator (this
/// is guaranteed by `movdqa` operating within the same page after alignment).
#[inline]
#[target_feature(enable = "sse,sse2")]
pub unsafe fn strlen_sse2(s: *const u8) -> usize {
    unsafe {
        let start = s;

        // Handle unaligned prefix byte-by-byte until 16-byte aligned.
        // This ensures movdqa won't cross a page boundary.
        let mut p = s;
        let align_offset = (p as usize) & 0xF;
        if align_offset != 0 {
            let skip = 16 - align_offset;
            let mut i = 0usize;
            while i < skip {
                if *p == 0 {
                    return (p as usize) - (start as usize);
                }
                p = p.add(1);
                i += 1;
            }
        }

        // p is now 16-byte aligned — use movdqa for safe, fast scanning
        loop {
            let mask: u32;
            asm!(
                "pxor {zero}, {zero}",
                "movdqa {data}, xmmword ptr [{ptr}]",
                "pcmpeqb {data}, {zero}",
                "pmovmskb {mask:e}, {data}",
                ptr = in(reg) p,
                zero = out(xmm_reg) _,
                data = out(xmm_reg) _,
                mask = out(reg) mask,
                options(nostack, readonly),
            );
            if mask != 0 {
                let pos = mask.trailing_zeros() as usize;
                return (p as usize) - (start as usize) + pos;
            }
            p = p.add(16);
        }
    }
}
