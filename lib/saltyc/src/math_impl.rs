//! Math library — pure x87 FPU implementations for x86_64 userland
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Target x86_64-unknown-none has no SSE feature, so all floating-point
//! operations use the x87 FPU via inline assembly (Intel syntax).

use core::arch::asm;

// ============================================================================
// IEEE 754 bit constants
// ============================================================================

const F64_SIGN_MASK: u64 = 0x8000_0000_0000_0000;
const F64_EXP_MASK: u64 = 0x7FF0_0000_0000_0000;
const F64_MANT_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;
const F64_EXP_BIAS: i64 = 1023;

// x87 control word rounding modes (bits 10-11)
const CW_ROUND_NEAREST: u16 = 0x0000;
const CW_ROUND_DOWN: u16 = 0x0400;
const CW_ROUND_UP: u16 = 0x0800;
const CW_ROUND_TRUNC: u16 = 0x0C00;
const CW_ROUND_MASK: u16 = 0x0C00;

// ============================================================================
// x87 helper: frndint with specific rounding mode
// ============================================================================

fn x87_round_mode(x: f64, mode: u16) -> f64 {
    let mut cw_old: u16 = 0;
    let cw_new: u16;
    let mut result = x;
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
// Absolute value / sign manipulation (pure bit ops)
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & !F64_SIGN_MASK)
}

#[unsafe(no_mangle)]
pub extern "C" fn fabsf(x: f32) -> f32 {
    f32::from_bits(x.to_bits() & !0x8000_0000)
}

#[unsafe(no_mangle)]
pub extern "C" fn copysign(x: f64, y: f64) -> f64 {
    f64::from_bits((x.to_bits() & !F64_SIGN_MASK) | (y.to_bits() & F64_SIGN_MASK))
}

#[unsafe(no_mangle)]
pub extern "C" fn copysignf(x: f32, y: f32) -> f32 {
    f32::from_bits((x.to_bits() & !0x8000_0000) | (y.to_bits() & 0x8000_0000))
}

// ============================================================================
// Classification (pure bit ops)
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn __fpclassify(x: f64) -> i32 {
    let bits = x.to_bits();
    let exp = (bits >> 52) & 0x7FF;
    let mant = bits & F64_MANT_MASK;
    match (exp, mant) {
        (0, 0) => 2,        // FP_ZERO
        (0, _) => 3,        // FP_SUBNORMAL
        (0x7FF, 0) => 1,    // FP_INFINITE
        (0x7FF, _) => 0,    // FP_NAN
        _ => 4,             // FP_NORMAL
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __fpclassifyf(x: f32) -> i32 {
    let bits = x.to_bits();
    let exp = (bits >> 23) & 0xFF;
    let mant = bits & 0x007F_FFFF;
    match (exp, mant) {
        (0, 0) => 2,
        (0, _) => 3,
        (0xFF, 0) => 1,
        (0xFF, _) => 0,
        _ => 4,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __isnan(x: f64) -> i32 {
    let bits = x.to_bits();
    let exp = (bits >> 52) & 0x7FF;
    let mant = bits & F64_MANT_MASK;
    (exp == 0x7FF && mant != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn __isnanf(x: f32) -> i32 {
    let bits = x.to_bits();
    let exp = (bits >> 23) & 0xFF;
    let mant = bits & 0x007F_FFFF;
    (exp == 0xFF && mant != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn __isinf(x: f64) -> i32 {
    let bits = x.to_bits();
    let exp = (bits >> 52) & 0x7FF;
    let mant = bits & F64_MANT_MASK;
    if exp == 0x7FF && mant == 0 {
        if bits & F64_SIGN_MASK != 0 { -1 } else { 1 }
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __isinff(x: f32) -> i32 {
    let bits = x.to_bits();
    let exp = (bits >> 23) & 0xFF;
    let mant = bits & 0x007F_FFFF;
    if exp == 0xFF && mant == 0 {
        if bits & 0x8000_0000 != 0 { -1 } else { 1 }
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __finite(x: f64) -> i32 {
    let exp = (x.to_bits() >> 52) & 0x7FF;
    (exp != 0x7FF) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn __finitef(x: f32) -> i32 {
    let exp = (x.to_bits() >> 23) & 0xFF;
    (exp != 0xFF) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn __signbit(x: f64) -> i32 {
    ((x.to_bits() >> 63) & 1) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn __signbitf(x: f32) -> i32 {
    ((x.to_bits() >> 31) & 1) as i32
}

// ============================================================================
// Square root — x87 fsqrt
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn sqrt(x: f64) -> f64 {
    let mut result = x;
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

#[unsafe(no_mangle)]
pub extern "C" fn sqrtf(x: f32) -> f32 {
    sqrt(x as f64) as f32
}

// ============================================================================
// Rounding — x87 frndint with control word manipulation
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn floor(x: f64) -> f64 {
    x87_round_mode(x, CW_ROUND_DOWN)
}

#[unsafe(no_mangle)]
pub extern "C" fn floorf(x: f32) -> f32 {
    floor(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn ceil(x: f64) -> f64 {
    x87_round_mode(x, CW_ROUND_UP)
}

#[unsafe(no_mangle)]
pub extern "C" fn ceilf(x: f32) -> f32 {
    ceil(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn trunc(x: f64) -> f64 {
    x87_round_mode(x, CW_ROUND_TRUNC)
}

#[unsafe(no_mangle)]
pub extern "C" fn truncf(x: f32) -> f32 {
    trunc(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn round(x: f64) -> f64 {
    let t = trunc(x);
    let d = fabs(x - t);
    if d >= 0.5 {
        t + copysign(1.0, x)
    } else {
        t
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn roundf(x: f32) -> f32 {
    round(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn rint(x: f64) -> f64 {
    x87_round_mode(x, CW_ROUND_NEAREST)
}

#[unsafe(no_mangle)]
pub extern "C" fn rintf(x: f32) -> f32 {
    rint(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn nearbyint(x: f64) -> f64 {
    rint(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn lrint(x: f64) -> i64 {
    rint(x) as i64
}

#[unsafe(no_mangle)]
pub extern "C" fn lround(x: f64) -> i64 {
    round(x) as i64
}

#[unsafe(no_mangle)]
pub extern "C" fn llrint(x: f64) -> i64 {
    rint(x) as i64
}

#[unsafe(no_mangle)]
pub extern "C" fn llround(x: f64) -> i64 {
    round(x) as i64
}

// ============================================================================
// fmod / remainder / fma — x87 fprem / fprem1
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn fmod(x: f64, y: f64) -> f64 {
    let mut result = x;
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

#[unsafe(no_mangle)]
pub extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    fmod(x as f64, y as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn remainder(x: f64, y: f64) -> f64 {
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

#[unsafe(no_mangle)]
pub extern "C" fn remainderf(x: f32, y: f32) -> f32 {
    remainder(x as f64, y as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
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

#[unsafe(no_mangle)]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    fma(x as f64, y as f64, z as f64) as f32
}

// ============================================================================
// frexp / ldexp / modf / scalbn / logb / ilogb
// ============================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn frexp(x: f64, exp: *mut i32) -> f64 {
    unsafe {
        let bits = x.to_bits();
        let e = ((bits >> 52) & 0x7FF) as i64;
        let mant = bits & F64_MANT_MASK;

        if e == 0 && mant == 0 {
            *exp = 0;
            return x;
        }
        if e == 0x7FF {
            *exp = 0;
            return x;
        }
        if e == 0 {
            let nx = x * (1u64 << 52) as f64;
            let nbits = nx.to_bits();
            let ne = ((nbits >> 52) & 0x7FF) as i64;
            *exp = (ne - F64_EXP_BIAS - 52 + 1) as i32;
            return f64::from_bits((nbits & !F64_EXP_MASK) | (0x3FE << 52));
        }

        *exp = (e - F64_EXP_BIAS + 1) as i32;
        f64::from_bits((bits & !F64_EXP_MASK) | (0x3FE << 52))
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ldexp(x: f64, n: i32) -> f64 {
    scalbn(x, n)
}

#[unsafe(no_mangle)]
pub extern "C" fn ldexpf(x: f32, n: i32) -> f32 {
    scalbnf(x, n)
}

#[unsafe(no_mangle)]
pub extern "C" fn scalbn(x: f64, n: i32) -> f64 {
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

#[unsafe(no_mangle)]
pub extern "C" fn scalbnf(x: f32, n: i32) -> f32 {
    scalbn(x as f64, n) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn scalbln(x: f64, n: i64) -> f64 {
    scalbn(x, n as i32)
}

#[unsafe(no_mangle)]
pub extern "C" fn scalblnf(x: f32, n: i64) -> f32 {
    scalbn(x as f64, n as i32) as f32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn modf(x: f64, iptr: *mut f64) -> f64 {
    unsafe {
        let t = trunc(x);
        *iptr = t;
        copysign(x - t, x)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn logb(x: f64) -> f64 {
    let bits = x.to_bits();
    let e = ((bits >> 52) & 0x7FF) as i64;
    if e == 0 {
        if bits & F64_MANT_MASK == 0 {
            return f64::NEG_INFINITY;
        }
        let nx = x * (1u64 << 52) as f64;
        let ne = ((nx.to_bits() >> 52) & 0x7FF) as i64;
        return (ne - F64_EXP_BIAS - 52) as f64;
    }
    if e == 0x7FF {
        return if bits & F64_MANT_MASK != 0 { x } else { f64::INFINITY };
    }
    (e - F64_EXP_BIAS) as f64
}

#[unsafe(no_mangle)]
pub extern "C" fn ilogb(x: f64) -> i32 {
    logb(x) as i32
}

// ============================================================================
// Trigonometric — x87 FPU
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn sin(x: f64) -> f64 {
    let mut result = x;
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

#[unsafe(no_mangle)]
pub extern "C" fn sinf(x: f32) -> f32 {
    sin(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn cos(x: f64) -> f64 {
    let mut result = x;
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

#[unsafe(no_mangle)]
pub extern "C" fn cosf(x: f32) -> f32 {
    cos(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn tan(x: f64) -> f64 {
    let mut result = x;
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

#[unsafe(no_mangle)]
pub extern "C" fn tanf(x: f32) -> f32 {
    tan(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn asin(x: f64) -> f64 {
    atan2(x, sqrt(1.0 - x * x))
}

#[unsafe(no_mangle)]
pub extern "C" fn asinf(x: f32) -> f32 {
    asin(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn acos(x: f64) -> f64 {
    atan2(sqrt(1.0 - x * x), x)
}

#[unsafe(no_mangle)]
pub extern "C" fn acosf(x: f32) -> f32 {
    acos(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn atan(x: f64) -> f64 {
    atan2(x, 1.0)
}

#[unsafe(no_mangle)]
pub extern "C" fn atanf(x: f32) -> f32 {
    atan(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn atan2(y: f64, x: f64) -> f64 {
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

#[unsafe(no_mangle)]
pub extern "C" fn atan2f(y: f32, x: f32) -> f32 {
    atan2(y as f64, x as f64) as f32
}

// ============================================================================
// Hyperbolic
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn sinh(x: f64) -> f64 {
    let ex = exp(x);
    (ex - 1.0 / ex) * 0.5
}

#[unsafe(no_mangle)]
pub extern "C" fn cosh(x: f64) -> f64 {
    let ex = exp(x);
    (ex + 1.0 / ex) * 0.5
}

#[unsafe(no_mangle)]
pub extern "C" fn tanh(x: f64) -> f64 {
    if x > 20.0 {
        return 1.0;
    }
    if x < -20.0 {
        return -1.0;
    }
    let e2x = exp(2.0 * x);
    (e2x - 1.0) / (e2x + 1.0)
}

// ============================================================================
// Exponential / logarithmic — x87 FPU
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn log2(x: f64) -> f64 {
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

#[unsafe(no_mangle)]
pub extern "C" fn log2f(x: f32) -> f32 {
    log2(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn log(x: f64) -> f64 {
    let mut result = x;
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

#[unsafe(no_mangle)]
pub extern "C" fn logf(x: f32) -> f32 {
    log(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn log10(x: f64) -> f64 {
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

#[unsafe(no_mangle)]
pub extern "C" fn log10f(x: f32) -> f32 {
    log10(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn log1p(x: f64) -> f64 {
    if fabs(x) < 1e-8 {
        x - x * x * 0.5
    } else {
        log(1.0 + x)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn log1pf(x: f32) -> f32 {
    log1p(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn exp2(x: f64) -> f64 {
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

#[unsafe(no_mangle)]
pub extern "C" fn exp2f(x: f32) -> f32 {
    exp2(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn exp(x: f64) -> f64 {
    let mut result = x;
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

#[unsafe(no_mangle)]
pub extern "C" fn expf(x: f32) -> f32 {
    exp(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn expm1(x: f64) -> f64 {
    if fabs(x) < 1e-8 {
        x + x * x * 0.5
    } else {
        exp(x) - 1.0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn expm1f(x: f32) -> f32 {
    expm1(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn pow(x: f64, y: f64) -> f64 {
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
        let r = exp2(y * log2(-x));
        return if yi & 1 != 0 { -r } else { r };
    }
    exp2(y * log2(x))
}

#[unsafe(no_mangle)]
pub extern "C" fn powf(x: f32, y: f32) -> f32 {
    pow(x as f64, y as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn cbrt(x: f64) -> f64 {
    if x == 0.0 {
        return x;
    }
    copysign(pow(fabs(x), 1.0 / 3.0), x)
}

#[unsafe(no_mangle)]
pub extern "C" fn cbrtf(x: f32) -> f32 {
    cbrt(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn hypot(x: f64, y: f64) -> f64 {
    sqrt(x * x + y * y)
}

#[unsafe(no_mangle)]
pub extern "C" fn hypotf(x: f32, y: f32) -> f32 {
    hypot(x as f64, y as f64) as f32
}

// ============================================================================
// Min / max / dim
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn fmin(x: f64, y: f64) -> f64 {
    if x != x { return y; }
    if y != y { return x; }
    if x < y { x } else { y }
}

#[unsafe(no_mangle)]
pub extern "C" fn fminf(x: f32, y: f32) -> f32 {
    if x != x { return y; }
    if y != y { return x; }
    if x < y { x } else { y }
}

#[unsafe(no_mangle)]
pub extern "C" fn fmax(x: f64, y: f64) -> f64 {
    if x != x { return y; }
    if y != y { return x; }
    if x > y { x } else { y }
}

#[unsafe(no_mangle)]
pub extern "C" fn fmaxf(x: f32, y: f32) -> f32 {
    if x != x { return y; }
    if y != y { return x; }
    if x > y { x } else { y }
}

#[unsafe(no_mangle)]
pub extern "C" fn fdim(x: f64, y: f64) -> f64 {
    if x > y { x - y } else { 0.0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn fdimf(x: f32, y: f32) -> f32 {
    if x > y { x - y } else { 0.0 }
}

// ============================================================================
// Error functions — Abramowitz & Stegun 7.1.26
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn erf(x: f64) -> f64 {
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let ax = fabs(x);
    let t = 1.0 / (1.0 + p * ax);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * exp(-ax * ax);
    sign * y
}

#[unsafe(no_mangle)]
pub extern "C" fn erfc(x: f64) -> f64 {
    1.0 - erf(x)
}

// ============================================================================
// Gamma — Stirling approximation
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn lgamma(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::INFINITY;
    }
    if x < 12.0 {
        let mut result = 0.0;
        let mut z = x;
        while z < 12.0 {
            result -= log(z);
            z += 1.0;
        }
        return result + lgamma(z);
    }
    let ln2pi_half = 0.9189385332046727;
    (x - 0.5) * log(x) - x + ln2pi_half
        + 1.0 / (12.0 * x)
        - 1.0 / (360.0 * x * x * x)
}

#[unsafe(no_mangle)]
pub extern "C" fn tgamma(x: f64) -> f64 {
    exp(lgamma(x))
}

// ============================================================================
// nan
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn nan(_tag: *const u8) -> f64 {
    f64::NAN
}

#[unsafe(no_mangle)]
pub extern "C" fn nanf(_tag: *const u8) -> f32 {
    f32::NAN
}
