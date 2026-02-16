//! x87 FPU math implementations for x86_64
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All functions here use the x87 FPU via inline assembly (Intel syntax).
//! These are used for transcendental functions (sin, cos, log, exp, etc.)
//! that have no SSE2 equivalent, and for rounding functions that would
//! require SSE4.1 (roundsd).

use core::arch::asm;

// x87 control word rounding modes (bits 10-11)
const CW_ROUND_NEAREST: u16 = 0x0000;
const CW_ROUND_DOWN: u16 = 0x0400;
const CW_ROUND_UP: u16 = 0x0800;
const CW_ROUND_TRUNC: u16 = 0x0C00;
const CW_ROUND_MASK: u16 = 0x0C00;

/// x87 frndint with specific rounding mode.
pub(crate) fn x87_round_mode(x: f64, mode: u16) -> f64 {
    let mut cw_old: u16 = 0;
    let cw_new: u16;
    let mut result = x;
    // SAFETY: x87 FPU inline asm. The control word is saved, modified for the
    // desired rounding mode, used for one frndint, then restored. The FPU stack
    // is left clean (st(0) is consumed by fstp and declared as clobbered).
    unsafe {
        asm!(
            "fnstcw word ptr [{cw}]",
            cw = in(reg) &mut cw_old as *mut u16,
        );
        cw_new = (cw_old & !CW_ROUND_MASK) | mode;
        asm!(
            "fldcw word ptr [{cw}]",
            "fld qword ptr [{x}]",
            "frndint",
            "fstp qword ptr [{x}]",
            "fldcw word ptr [{old}]",
            cw = in(reg) &cw_new as *const u16,
            x = in(reg) &mut result as *mut f64,
            old = in(reg) &cw_old as *const u16,
            out("st(0)") _,
        );
    }
    result
}

// ============================================================================
// Rounding — x87 frndint with control word manipulation
// ============================================================================

#[inline]
pub fn floor_x87(x: f64) -> f64 {
    x87_round_mode(x, CW_ROUND_DOWN)
}

#[inline]
pub fn ceil_x87(x: f64) -> f64 {
    x87_round_mode(x, CW_ROUND_UP)
}

#[inline]
pub fn trunc_x87(x: f64) -> f64 {
    x87_round_mode(x, CW_ROUND_TRUNC)
}

#[inline]
pub fn rint_x87(x: f64) -> f64 {
    x87_round_mode(x, CW_ROUND_NEAREST)
}

// ============================================================================
// Square root — x87 fsqrt
// ============================================================================

#[inline]
pub fn sqrt_x87(x: f64) -> f64 {
    let mut result = x;
    // SAFETY: x87 FPU inline asm. Loads x onto the FPU stack, computes
    // square root, stores result back. FPU stack is left clean.
    unsafe {
        asm!(
            "fld qword ptr [{r}]",
            "fsqrt",
            "fstp qword ptr [{r}]",
            r = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

// ============================================================================
// Trigonometric — x87 FPU
// ============================================================================

#[inline]
pub fn sin_x87(x: f64) -> f64 {
    let mut result = x;
    // SAFETY: x87 FPU inline asm. fsin operates on st(0), result stored back.
    unsafe {
        asm!(
            "fld qword ptr [{r}]",
            "fsin",
            "fstp qword ptr [{r}]",
            r = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

#[inline]
pub fn cos_x87(x: f64) -> f64 {
    let mut result = x;
    // SAFETY: x87 FPU inline asm. fcos operates on st(0), result stored back.
    unsafe {
        asm!(
            "fld qword ptr [{r}]",
            "fcos",
            "fstp qword ptr [{r}]",
            r = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

#[inline]
pub fn tan_x87(x: f64) -> f64 {
    let mut result = x;
    // SAFETY: x87 FPU inline asm. fptan pushes 1.0 and tan(x) onto the FPU
    // stack; both are consumed (fstp st(0) pops the 1.0, fstp stores tan).
    unsafe {
        asm!(
            "fld qword ptr [{r}]",
            "fptan",
            "fstp st(0)",
            "fstp qword ptr [{r}]",
            r = in(reg) &mut result as *mut f64,
            out("st(0)") _,
            out("st(1)") _,
        );
    }
    result
}

#[inline]
pub fn atan2_x87(y: f64, x: f64) -> f64 {
    let mut result = y;
    unsafe {
        asm!(
            "fld qword ptr [{x}]",
            "fld qword ptr [{y}]",
            "fpatan",
            "fstp qword ptr [{y}]",
            x = in(reg) &x as *const f64,
            y = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

// ============================================================================
// Exponential / logarithmic — x87 FPU
// ============================================================================

#[inline]
pub fn log2_x87(x: f64) -> f64 {
    let one: f64 = 1.0;
    let mut result = x;
    unsafe {
        asm!(
            "fld qword ptr [{one}]",
            "fld qword ptr [{x}]",
            "fyl2x",
            "fstp qword ptr [{x}]",
            one = in(reg) &one as *const f64,
            x = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

#[inline]
pub fn log_x87(x: f64) -> f64 {
    let mut result = x;
    // SAFETY: x87 FPU inline asm. fldln2 pushes ln(2), fyl2x computes
    // ln(2) * log2(x) = ln(x). Both FPU stack slots are consumed.
    unsafe {
        asm!(
            "fldln2",
            "fld qword ptr [{x}]",
            "fyl2x",
            "fstp qword ptr [{x}]",
            x = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

#[inline]
pub fn log10_x87(x: f64) -> f64 {
    let mut result = x;
    unsafe {
        asm!(
            "fldlg2",
            "fld qword ptr [{x}]",
            "fyl2x",
            "fstp qword ptr [{x}]",
            x = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

#[inline]
pub fn exp2_x87(x: f64) -> f64 {
    let mut result = x;
    unsafe {
        asm!(
            "fld qword ptr [{x}]",
            "fld st(0)",
            "frndint",
            "fxch st(1)",
            "fsub st(0), st(1)",
            "f2xm1",
            "fld1",
            "faddp",
            "fscale",
            "fstp st(1)",
            "fstp qword ptr [{x}]",
            x = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

#[inline]
pub fn exp_x87(x: f64) -> f64 {
    let mut result = x;
    // SAFETY: x87 FPU inline asm. Computes 2^(x*log2(e)) using the identity
    // e^x = 2^(x*log2(e)). Splits into integer and fractional parts via
    // frndint, uses f2xm1 for the fractional part, then fscale for the
    // integer part. All FPU stack slots are properly consumed.
    unsafe {
        asm!(
            "fldl2e",
            "fmul qword ptr [{x}]",
            "fld st(0)",
            "frndint",
            "fxch st(1)",
            "fsub st(0), st(1)",
            "f2xm1",
            "fld1",
            "faddp",
            "fscale",
            "fstp st(1)",
            "fstp qword ptr [{x}]",
            x = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

// ============================================================================
// fmod / remainder / fma — x87 fprem / fprem1
// ============================================================================

#[inline]
pub fn fmod_x87(x: f64, y: f64) -> f64 {
    let mut result = x;
    // SAFETY: x87 FPU inline asm. Uses fprem in a loop (checking C2 status
    // bit) to compute the IEEE remainder. Both FPU stack slots are consumed.
    unsafe {
        asm!(
            "fld qword ptr [{y}]",
            "fld qword ptr [{x}]",
            "2:",
            "fprem",
            "fnstsw ax",
            "test ax, 0x0400",
            "jnz 2b",
            "fstp qword ptr [{x}]",
            "fstp st(0)",
            x = in(reg) &mut result as *mut f64,
            y = in(reg) &y as *const f64,
            out("ax") _,
            out("st(0)") _,
            out("st(1)") _,
        );
    }
    result
}

#[inline]
pub fn remainder_x87(x: f64, y: f64) -> f64 {
    let mut result = x;
    unsafe {
        asm!(
            "fld qword ptr [{y}]",
            "fld qword ptr [{x}]",
            "2:",
            "fprem1",
            "fnstsw ax",
            "test ax, 0x0400",
            "jnz 2b",
            "fstp qword ptr [{x}]",
            "fstp st(0)",
            x = in(reg) &mut result as *mut f64,
            y = in(reg) &y as *const f64,
            out("ax") _,
            out("st(0)") _,
            out("st(1)") _,
        );
    }
    result
}

#[inline]
pub fn fma_x87(x: f64, y: f64, z: f64) -> f64 {
    let mut result: f64 = 0.0;
    unsafe {
        asm!(
            "fld qword ptr [{x}]",
            "fmul qword ptr [{y}]",
            "fadd qword ptr [{z}]",
            "fstp qword ptr [{r}]",
            x = in(reg) &x as *const f64,
            y = in(reg) &y as *const f64,
            z = in(reg) &z as *const f64,
            r = in(reg) &mut result as *mut f64,
            out("st(0)") _,
        );
    }
    result
}

#[inline]
pub fn scalbn_x87(x: f64, n: i32) -> f64 {
    let mut result = x;
    let nf = n as f64;
    unsafe {
        asm!(
            "fld qword ptr [{n}]",
            "fld qword ptr [{x}]",
            "fscale",
            "fstp qword ptr [{x}]",
            "fstp st(0)",
            x = in(reg) &mut result as *mut f64,
            n = in(reg) &nf as *const f64,
            out("st(0)") _,
            out("st(1)") _,
        );
    }
    result
}

// ============================================================================
// pow — uses x87 log2 + exp2
// ============================================================================

#[inline]
pub fn pow_x87(x: f64, y: f64) -> f64 {
    if y == 0.0 {
        return 1.0;
    }
    if x == 1.0 {
        return 1.0;
    }
    if x == 0.0 {
        return if y > 0.0 { 0.0 } else { f64::INFINITY };
    }
    if x < 0.0 {
        let yi = y as i64;
        if y != yi as f64 {
            return f64::NAN;
        }
        let r = exp2_x87(y * log2_x87(-x));
        return if yi & 1 != 0 { -r } else { r };
    }
    exp2_x87(y * log2_x87(x))
}
