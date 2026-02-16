//! SSE2 math implementations for x86_64
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! SSE2 replacements for basic math operations. Only includes functions
//! where SSE2 provides a direct instruction (sqrtsd/sqrtss). Transcendental
//! functions remain in math_x87.rs since SSE has no sin/cos/log equivalents.

use core::arch::asm;

/// Double-precision square root via `sqrtsd`.
///
/// # Safety
/// Caller must ensure SSE2 is available (guaranteed on all x86_64 CPUs).
#[inline]
#[target_feature(enable = "sse,sse2")]
pub unsafe fn sqrt_sse2(x: f64) -> f64 {
    let result: f64;
    // SAFETY: sqrtsd is an SSE2 baseline instruction. Uses XMM registers only.
    unsafe {
        asm!("sqrtsd {dst}, {src}",
            src = in(xmm_reg) x,
            dst = out(xmm_reg) result,
            options(pure, nomem, nostack));
    }
    result
}

/// Single-precision square root via `sqrtss`.
///
/// # Safety
/// Caller must ensure SSE2 is available (guaranteed on all x86_64 CPUs).
#[inline]
#[target_feature(enable = "sse,sse2")]
pub unsafe fn sqrtf_sse2(x: f32) -> f32 {
    let result: f32;
    // SAFETY: sqrtss is an SSE baseline instruction. Uses XMM registers only.
    unsafe {
        asm!("sqrtss {dst}, {src}",
            src = in(xmm_reg) x,
            dst = out(xmm_reg) result,
            options(pure, nomem, nostack));
    }
    result
}
