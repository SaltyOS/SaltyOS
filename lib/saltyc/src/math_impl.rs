//! Math library — C ABI wrappers with architecture-dispatched implementations
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Public `#[no_mangle]` C ABI functions that delegate to the architecture-
//! specific backend via `Arch` trait dispatch. Architecture-independent
//! functions (IEEE 754 classification, copysign, pure bit-ops) remain here.

use crate::arch::{Arch, ArchMath};

// ============================================================================
// IEEE 754 bit constants
// ============================================================================

const F64_SIGN_MASK: u64 = 0x8000_0000_0000_0000;
const F64_EXP_MASK: u64 = 0x7FF0_0000_0000_0000;
const F64_MANT_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;
const F64_EXP_BIAS: i64 = 1023;

// ============================================================================
// Absolute value / sign manipulation (pure bit ops — arch-independent)
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
// Classification (pure bit ops — arch-independent)
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
// Square root — arch dispatch
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn sqrt(x: f64) -> f64 {
    <Arch as ArchMath>::sqrt(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn sqrtf(x: f32) -> f32 {
    <Arch as ArchMath>::sqrtf(x)
}

// ============================================================================
// Rounding — arch dispatch
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn floor(x: f64) -> f64 {
    <Arch as ArchMath>::floor(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn floorf(x: f32) -> f32 {
    floor(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn ceil(x: f64) -> f64 {
    <Arch as ArchMath>::ceil(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn ceilf(x: f32) -> f32 {
    ceil(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn trunc(x: f64) -> f64 {
    <Arch as ArchMath>::trunc(x)
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
    <Arch as ArchMath>::rint(x)
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
// fmod / remainder / fma — arch dispatch
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn fmod(x: f64, y: f64) -> f64 {
    <Arch as ArchMath>::fmod(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    fmod(x as f64, y as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn remainder(x: f64, y: f64) -> f64 {
    <Arch as ArchMath>::remainder(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn remainderf(x: f32, y: f32) -> f32 {
    remainder(x as f64, y as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    <Arch as ArchMath>::fma(x, y, z)
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
    <Arch as ArchMath>::scalbn(x, n)
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
// Trigonometric — arch dispatch
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn sin(x: f64) -> f64 {
    <Arch as ArchMath>::sin(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn sinf(x: f32) -> f32 {
    sin(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn cos(x: f64) -> f64 {
    <Arch as ArchMath>::cos(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn cosf(x: f32) -> f32 {
    cos(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn tan(x: f64) -> f64 {
    <Arch as ArchMath>::tan(x)
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
    <Arch as ArchMath>::atan2(y, x)
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
// Exponential / logarithmic — arch dispatch
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn log2(x: f64) -> f64 {
    <Arch as ArchMath>::log2(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn log2f(x: f32) -> f32 {
    log2(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn log(x: f64) -> f64 {
    <Arch as ArchMath>::log(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn logf(x: f32) -> f32 {
    log(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn log10(x: f64) -> f64 {
    <Arch as ArchMath>::log10(x)
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
    <Arch as ArchMath>::exp2(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn exp2f(x: f32) -> f32 {
    exp2(x as f64) as f32
}

#[unsafe(no_mangle)]
pub extern "C" fn exp(x: f64) -> f64 {
    <Arch as ArchMath>::exp(x)
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
    <Arch as ArchMath>::pow(x, y)
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
