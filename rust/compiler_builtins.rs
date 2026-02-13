//! Compiler builtins for freestanding environment
//!
//! Provides software floating-point intrinsics (IEEE 754) using pure integer
//! math for `x86_64-unknown-none` targets where SSE is disabled. Also stubs
//! out i128/u128 and f32 arithmetic intrinsics that are not needed.
//!
//! SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![allow(internal_features)]
#![feature(compiler_builtins)]
#![compiler_builtins]
#![no_builtins]

macro_rules! define_panicking_intrinsics(
    ($reason: tt, { $($ident: ident, )* }) => {
        $(
            #[doc(hidden)]
            #[unsafe(export_name = stringify!($ident))]
            pub extern "C" fn $ident() {
                panic!($reason);
            }
        )*
    }
);

// f32 arithmetic — not used in kernel or saltyc
define_panicking_intrinsics!("`f32` should not be used", {
    __addsf3,
    __eqsf2,
    __gesf2,
    __lesf2,
    __ltsf2,
    __mulsf3,
    __nesf2,
    __unordsf2,
});

define_panicking_intrinsics!("`i128` should not be used", {
    __ashrti3,
    __muloti4,
    __multi3,
});

define_panicking_intrinsics!("`u128` should not be used", {
    __ashlti3,
    __lshrti3,
    __udivmodti4,
    __udivti3,
    __umodti3,
});

// ---------------------------------------------------------------------------
// IEEE 754 double-precision (f64) soft-float intrinsics
//
// All operations use raw u64 bit manipulation. No FP instructions are emitted.
// ---------------------------------------------------------------------------

// IEEE 754 double-precision constants
const F64_SIGN_BIT: u64 = 1 << 63;
const F64_EXP_MASK: u64 = 0x7FF0_0000_0000_0000;
const F64_FRAC_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;
const F64_EXP_BIAS: i32 = 1023;
const F64_FRAC_BITS: u32 = 52;
const F64_IMPLICIT_BIT: u64 = 1 << F64_FRAC_BITS;

// IEEE 754 single-precision constants
const F32_EXP_BIAS: i32 = 127;
const F32_FRAC_BITS: u32 = 23;

#[inline(always)]
fn f64_sign(bits: u64) -> u64 {
    bits & F64_SIGN_BIT
}

#[inline(always)]
fn f64_exp(bits: u64) -> i32 {
    ((bits >> F64_FRAC_BITS) & 0x7FF) as i32
}

#[inline(always)]
fn f64_frac(bits: u64) -> u64 {
    bits & F64_FRAC_MASK
}

#[inline(always)]
fn f64_is_nan(bits: u64) -> bool {
    (bits & !F64_SIGN_BIT) > F64_EXP_MASK
}

#[inline(always)]
fn f64_pack(sign: u64, exp: i32, frac: u64) -> u64 {
    sign | ((exp as u64) << F64_FRAC_BITS) | frac
}

/// Normalize a subnormal f64: returns (exponent, significand with implicit bit)
#[inline(always)]
fn f64_normalize_subnormal(frac: u64) -> (i32, u64) {
    let shift = frac.leading_zeros() as i32 - 11; // 11 = 64 - 53
    (1 - shift, frac << shift)
}

// ---------------------------------------------------------------------------
// __adddf3: f64 + f64
// ---------------------------------------------------------------------------
#[unsafe(export_name = "__adddf3")]
pub extern "C" fn __adddf3(a: u64, b: u64) -> u64 {
    add_f64(a, b)
}

// ---------------------------------------------------------------------------
// __subdf3: f64 - f64
// ---------------------------------------------------------------------------
#[unsafe(export_name = "__subdf3")]
pub extern "C" fn __subdf3(a: u64, b: u64) -> u64 {
    add_f64(a, b ^ F64_SIGN_BIT)
}

/// Core addition routine used by both __adddf3 and __subdf3.
fn add_f64(a_bits: u64, b_bits: u64) -> u64 {
    let a_sign = f64_sign(a_bits);
    let mut a_exp = f64_exp(a_bits);
    let mut a_frac = f64_frac(a_bits);

    let b_sign = f64_sign(b_bits);
    let mut b_exp = f64_exp(b_bits);
    let mut b_frac = f64_frac(b_bits);

    // Handle NaN
    if f64_is_nan(a_bits) {
        return a_bits | 0x0008_0000_0000_0000; // quiet NaN
    }
    if f64_is_nan(b_bits) {
        return b_bits | 0x0008_0000_0000_0000;
    }

    // Handle infinity
    if a_exp == 0x7FF {
        if b_exp == 0x7FF && a_sign != b_sign {
            // inf + (-inf) = NaN
            return 0x7FF8_0000_0000_0000;
        }
        return a_bits;
    }
    if b_exp == 0x7FF {
        return b_bits;
    }

    // Handle zeros
    if a_exp == 0 && a_frac == 0 {
        if b_exp == 0 && b_frac == 0 {
            // -0 + -0 = -0, otherwise +0
            return a_sign & b_sign;
        }
        return b_bits;
    }
    if b_exp == 0 && b_frac == 0 {
        return a_bits;
    }

    // Add implicit bit for normals, normalize subnormals
    if a_exp == 0 {
        let (e, f) = f64_normalize_subnormal(a_frac);
        a_exp = e;
        a_frac = f;
    } else {
        a_frac |= F64_IMPLICIT_BIT;
    }

    if b_exp == 0 {
        let (e, f) = f64_normalize_subnormal(b_frac);
        b_exp = e;
        b_frac = f;
    } else {
        b_frac |= F64_IMPLICIT_BIT;
    }

    // Shift to 3 extra bits for rounding (guard, round, sticky)
    let mut a_sig = (a_frac as u128) << 3;
    let mut b_sig = (b_frac as u128) << 3;

    // Align exponents
    let exp_diff = a_exp - b_exp;
    let mut result_exp;
    if exp_diff > 0 {
        result_exp = a_exp;
        if exp_diff < 128 {
            let sticky = if (b_sig & ((1u128 << exp_diff) - 1)) != 0 { 1u128 } else { 0 };
            b_sig = (b_sig >> exp_diff) | sticky;
        } else {
            b_sig = 1; // sticky
        }
    } else if exp_diff < 0 {
        result_exp = b_exp;
        let shift = -exp_diff;
        if shift < 128 {
            let sticky = if (a_sig & ((1u128 << shift) - 1)) != 0 { 1u128 } else { 0 };
            a_sig = (a_sig >> shift) | sticky;
        } else {
            a_sig = 1;
        }
    } else {
        result_exp = a_exp;
    }

    // Add or subtract significands
    let result_sign;
    let mut result_sig;
    if a_sign == b_sign {
        result_sign = a_sign;
        result_sig = a_sig + b_sig;
    } else {
        if a_sig >= b_sig {
            result_sign = a_sign;
            result_sig = a_sig - b_sig;
        } else {
            result_sign = b_sign;
            result_sig = b_sig - a_sig;
        }
    }

    // Result is zero
    if result_sig == 0 {
        return result_sign & 0; // +0 (round-to-even gives +0 for exact zero)
    }

    // Normalize: shift left if needed
    // The implicit bit should be at position 55 (52 frac bits + 3 rounding bits)
    let target_bit = 55;
    let msb = 127 - result_sig.leading_zeros() as i32;
    if msb > target_bit {
        let shift = msb - target_bit;
        let sticky = if (result_sig & ((1u128 << shift) - 1)) != 0 { 1u128 } else { 0 };
        result_sig = (result_sig >> shift) | sticky;
        result_exp += shift;
    } else if msb < target_bit {
        let shift = target_bit - msb;
        result_sig <<= shift;
        result_exp -= shift;
    }

    // Round to nearest, ties to even
    let round_bits = (result_sig & 0x7) as u32; // guard, round, sticky
    let mut result_frac = (result_sig >> 3) as u64;

    if round_bits > 4 || (round_bits == 4 && (result_frac & 1) != 0) {
        result_frac += 1;
        // Check for carry into next exponent
        if result_frac == (F64_IMPLICIT_BIT << 1) {
            result_frac = F64_IMPLICIT_BIT;
            result_exp += 1;
        }
    }

    // Overflow → infinity
    if result_exp >= 0x7FF {
        return result_sign | F64_EXP_MASK;
    }

    // Underflow → subnormal or zero
    if result_exp <= 0 {
        let shift = 1 - result_exp;
        if shift >= 53 {
            return result_sign; // zero with sign
        }
        result_frac >>= shift;
        return result_sign | result_frac;
    }

    // Remove implicit bit and pack
    result_frac &= F64_FRAC_MASK;
    f64_pack(result_sign, result_exp, result_frac)
}

// ---------------------------------------------------------------------------
// __muldf3: f64 × f64
// ---------------------------------------------------------------------------
#[unsafe(export_name = "__muldf3")]
pub extern "C" fn __muldf3(a: u64, b: u64) -> u64 {
    let a_sign = f64_sign(a);
    let mut a_exp = f64_exp(a);
    let mut a_frac = f64_frac(a);

    let b_sign = f64_sign(b);
    let mut b_exp = f64_exp(b);
    let mut b_frac = f64_frac(b);

    let result_sign = a_sign ^ b_sign;

    // NaN
    if f64_is_nan(a) {
        return a | 0x0008_0000_0000_0000;
    }
    if f64_is_nan(b) {
        return b | 0x0008_0000_0000_0000;
    }

    // Infinity
    if a_exp == 0x7FF {
        if b_exp == 0 && b_frac == 0 {
            return 0x7FF8_0000_0000_0000; // inf * 0 = NaN
        }
        return result_sign | F64_EXP_MASK;
    }
    if b_exp == 0x7FF {
        if a_exp == 0 && a_frac == 0 {
            return 0x7FF8_0000_0000_0000;
        }
        return result_sign | F64_EXP_MASK;
    }

    // Zero
    if (a_exp == 0 && a_frac == 0) || (b_exp == 0 && b_frac == 0) {
        return result_sign; // signed zero
    }

    // Normalize subnormals
    if a_exp == 0 {
        let (e, f) = f64_normalize_subnormal(a_frac);
        a_exp = e;
        a_frac = f;
    } else {
        a_frac |= F64_IMPLICIT_BIT;
    }

    if b_exp == 0 {
        let (e, f) = f64_normalize_subnormal(b_frac);
        b_exp = e;
        b_frac = f;
    } else {
        b_frac |= F64_IMPLICIT_BIT;
    }

    // Multiply significands (53 × 53 = 106 bits, fits in u128)
    let product = (a_frac as u128) * (b_frac as u128);

    // Result exponent
    let mut result_exp = a_exp + b_exp - F64_EXP_BIAS;

    // The product has the implicit bit at position 104 (52+52) or 105
    // We need it at position 52. Shift right by ~52 with rounding.
    let msb = 127 - product.leading_zeros() as i32;
    let shift = msb - 52;
    let mut result_frac;
    if shift > 0 {
        let sticky = if (product & ((1u128 << (shift - 1)) - 1)) != 0 { 1u64 } else { 0 };
        let round_bit = ((product >> (shift - 1)) & 1) as u64;
        result_frac = (product >> shift) as u64;
        // Round to nearest, ties to even
        if round_bit != 0 && (sticky != 0 || (result_frac & 1) != 0) {
            result_frac += 1;
            if result_frac == (F64_IMPLICIT_BIT << 1) {
                result_frac = F64_IMPLICIT_BIT;
                result_exp += 1;
            }
        }
        result_exp += shift - 52; // adjust for extra shift beyond 52
    } else {
        result_frac = (product as u64) << (-shift);
    }

    // Overflow
    if result_exp >= 0x7FF {
        return result_sign | F64_EXP_MASK;
    }

    // Underflow
    if result_exp <= 0 {
        let s = 1 - result_exp;
        if s >= 53 {
            return result_sign;
        }
        result_frac >>= s;
        return result_sign | result_frac;
    }

    result_frac &= F64_FRAC_MASK;
    f64_pack(result_sign, result_exp, result_frac)
}

// ---------------------------------------------------------------------------
// __divdf3: f64 ÷ f64
// ---------------------------------------------------------------------------
#[unsafe(export_name = "__divdf3")]
pub extern "C" fn __divdf3(a: u64, b: u64) -> u64 {
    let a_sign = f64_sign(a);
    let mut a_exp = f64_exp(a);
    let mut a_frac = f64_frac(a);

    let b_sign = f64_sign(b);
    let mut b_exp = f64_exp(b);
    let mut b_frac = f64_frac(b);

    let result_sign = a_sign ^ b_sign;

    // NaN
    if f64_is_nan(a) {
        return a | 0x0008_0000_0000_0000;
    }
    if f64_is_nan(b) {
        return b | 0x0008_0000_0000_0000;
    }

    // Inf / Inf = NaN
    if a_exp == 0x7FF && b_exp == 0x7FF {
        return 0x7FF8_0000_0000_0000;
    }

    // Inf / x = Inf
    if a_exp == 0x7FF {
        return result_sign | F64_EXP_MASK;
    }

    // x / Inf = 0
    if b_exp == 0x7FF {
        return result_sign;
    }

    // 0 / 0 = NaN
    if (a_exp == 0 && a_frac == 0) && (b_exp == 0 && b_frac == 0) {
        return 0x7FF8_0000_0000_0000;
    }

    // 0 / x = 0
    if a_exp == 0 && a_frac == 0 {
        return result_sign;
    }

    // x / 0 = Inf
    if b_exp == 0 && b_frac == 0 {
        return result_sign | F64_EXP_MASK;
    }

    // Normalize subnormals
    if a_exp == 0 {
        let (e, f) = f64_normalize_subnormal(a_frac);
        a_exp = e;
        a_frac = f;
    } else {
        a_frac |= F64_IMPLICIT_BIT;
    }

    if b_exp == 0 {
        let (e, f) = f64_normalize_subnormal(b_frac);
        b_exp = e;
        b_frac = f;
    } else {
        b_frac |= F64_IMPLICIT_BIT;
    }

    // Division: shift numerator left to get enough precision
    // We need 53 bits of quotient + guard/round/sticky
    // Shift a_frac left by 55 bits and divide by b_frac
    let numerator = (a_frac as u128) << 55;
    let quotient = numerator / (b_frac as u128);
    let remainder = numerator % (b_frac as u128);

    let mut result_exp = a_exp - b_exp + F64_EXP_BIAS;

    // quotient has ~55 bits. We need 53 bits (52 frac + implicit).
    // Normalize the quotient
    let mut q = quotient as u64;
    let sticky = if remainder != 0 { 1u64 } else { 0 };

    // The quotient should be around 55 bits. Find MSB.
    if q == 0 {
        return result_sign; // zero
    }

    let msb = 63 - q.leading_zeros() as i32;
    if msb > 53 {
        let shift = msb - 53;
        let s = if (q & ((1u64 << shift) - 1)) != 0 || sticky != 0 { 1u64 } else { 0 };
        q = (q >> shift) | s;
        result_exp += shift - 2; // -2 because we shifted left by 55 but need 53
    } else if msb < 53 {
        let shift = 53 - msb;
        q = (q << shift) | sticky;
        result_exp -= shift + 2;
    } else {
        q |= sticky;
        result_exp -= 2;
    }

    // Round to nearest, ties to even
    let round_bit = (q >> 0) & 1;
    let mut result_frac = q >> 1;
    if round_bit != 0 && (sticky != 0 || (result_frac & 1) != 0) {
        result_frac += 1;
        if result_frac == (F64_IMPLICIT_BIT << 1) {
            result_frac = F64_IMPLICIT_BIT;
            result_exp += 1;
        }
    }

    // Overflow
    if result_exp >= 0x7FF {
        return result_sign | F64_EXP_MASK;
    }

    // Underflow
    if result_exp <= 0 {
        let s = 1 - result_exp;
        if s >= 53 {
            return result_sign;
        }
        result_frac >>= s;
        return result_sign | result_frac;
    }

    result_frac &= F64_FRAC_MASK;
    f64_pack(result_sign, result_exp, result_frac)
}

// ---------------------------------------------------------------------------
// __negdf2: negate f64
// ---------------------------------------------------------------------------
#[unsafe(export_name = "__negdf2")]
pub extern "C" fn __negdf2(a: u64) -> u64 {
    a ^ F64_SIGN_BIT
}

// ---------------------------------------------------------------------------
// Comparison intrinsics
//
// GCC/LLVM convention:
//   __ltdf2: returns negative if a < b, 0 if a == b, positive if a > b (or NaN → +1)
//   __ledf2: same
//   __gtdf2: returns negative if a < b, 0 if a == b, positive if a > b (or NaN → -1)
//   __gedf2: same
//   __eqdf2: returns 0 if a == b, nonzero otherwise
//   __unorddf2: returns nonzero if either operand is NaN
// ---------------------------------------------------------------------------

/// Compare two f64 values. Returns -1, 0, or 1.
/// `nan_result` is returned if either operand is NaN.
fn cmp_f64(a: u64, b: u64, nan_result: i32) -> i32 {
    if f64_is_nan(a) || f64_is_nan(b) {
        return nan_result;
    }

    let a_sign = f64_sign(a);
    let b_sign = f64_sign(b);

    // Both zero (positive or negative)
    if (a & !F64_SIGN_BIT) == 0 && (b & !F64_SIGN_BIT) == 0 {
        return 0;
    }

    // Different signs
    if a_sign != b_sign {
        return if a_sign != 0 { -1 } else { 1 };
    }

    // Same sign — compare magnitudes
    let a_mag = a & !F64_SIGN_BIT;
    let b_mag = b & !F64_SIGN_BIT;

    if a_mag == b_mag {
        return 0;
    }

    if a_sign != 0 {
        // Both negative: larger magnitude is smaller value
        if a_mag > b_mag { -1 } else { 1 }
    } else {
        // Both positive: larger magnitude is larger value
        if a_mag > b_mag { 1 } else { -1 }
    }
}

#[unsafe(export_name = "__ltdf2")]
pub extern "C" fn __ltdf2(a: u64, b: u64) -> i32 {
    cmp_f64(a, b, 1) // NaN → not less than
}

#[unsafe(export_name = "__ledf2")]
pub extern "C" fn __ledf2(a: u64, b: u64) -> i32 {
    cmp_f64(a, b, 1) // NaN → not less than or equal
}

#[unsafe(export_name = "__gtdf2")]
pub extern "C" fn __gtdf2(a: u64, b: u64) -> i32 {
    cmp_f64(a, b, -1) // NaN → not greater than
}

#[unsafe(export_name = "__gedf2")]
pub extern "C" fn __gedf2(a: u64, b: u64) -> i32 {
    cmp_f64(a, b, -1) // NaN → not greater than or equal
}

#[unsafe(export_name = "__eqdf2")]
pub extern "C" fn __eqdf2(a: u64, b: u64) -> i32 {
    cmp_f64(a, b, 1) // NaN → not equal
}

#[unsafe(export_name = "__unorddf2")]
pub extern "C" fn __unorddf2(a: u64, b: u64) -> i32 {
    if f64_is_nan(a) || f64_is_nan(b) { 1 } else { 0 }
}

// ---------------------------------------------------------------------------
// Integer → f64 conversions
// ---------------------------------------------------------------------------

/// __floatsidf: i32 → f64
#[unsafe(export_name = "__floatsidf")]
pub extern "C" fn __floatsidf(a: i32) -> u64 {
    if a == 0 {
        return 0;
    }

    let sign = if a < 0 { F64_SIGN_BIT } else { 0 };
    let mag = if a < 0 { (-(a as i64)) as u64 } else { a as u64 };

    // i32 fits exactly in f64 (53-bit significand >= 32 bits)
    let msb = 63 - mag.leading_zeros() as i32;
    let exp = msb + F64_EXP_BIAS;
    // Shift significand to position 52
    let frac = if msb > 52 {
        mag >> (msb - 52)
    } else {
        mag << (52 - msb)
    };

    f64_pack(sign, exp, frac & F64_FRAC_MASK)
}

/// __floatdidf: i64 → f64
#[unsafe(export_name = "__floatdidf")]
pub extern "C" fn __floatdidf(a: i64) -> u64 {
    if a == 0 {
        return 0;
    }

    let sign = if a < 0 { F64_SIGN_BIT } else { 0 };
    // Handle i64::MIN carefully
    let mag = if a == i64::MIN {
        (1u64) << 63
    } else if a < 0 {
        (-a) as u64
    } else {
        a as u64
    };

    if mag == 0 {
        return sign;
    }

    let msb = 63 - mag.leading_zeros() as i32;
    let exp = msb + F64_EXP_BIAS;

    let frac = if msb > 52 {
        let shift = msb - 52;
        // Round to nearest, ties to even
        let dropped = mag & ((1u64 << shift) - 1);
        let halfway = 1u64 << (shift - 1);
        let mut f = mag >> shift;
        if dropped > halfway || (dropped == halfway && (f & 1) != 0) {
            f += 1;
        }
        f
    } else {
        mag << (52 - msb)
    };

    if frac >= (F64_IMPLICIT_BIT << 1) {
        // Rounding caused carry
        f64_pack(sign, exp + 1, (frac >> 1) & F64_FRAC_MASK)
    } else {
        f64_pack(sign, exp, frac & F64_FRAC_MASK)
    }
}

// ---------------------------------------------------------------------------
// f64 ↔ f32 conversions
// ---------------------------------------------------------------------------

/// __truncdfsf2: f64 → f32
#[unsafe(export_name = "__truncdfsf2")]
pub extern "C" fn __truncdfsf2(a: u64) -> u32 {
    let sign = ((a >> 63) as u32) << 31;
    let exp = f64_exp(a);
    let frac = f64_frac(a);

    // NaN
    if exp == 0x7FF && frac != 0 {
        // Preserve NaN, quiet it
        return sign | 0x7FC0_0000;
    }

    // Infinity
    if exp == 0x7FF {
        return sign | 0x7F80_0000;
    }

    // Rebias exponent: f64 bias 1023, f32 bias 127
    let new_exp = exp - F64_EXP_BIAS as i32 + F32_EXP_BIAS;

    if exp == 0 && frac == 0 {
        // Zero
        return sign;
    }

    // Get the full significand
    let mut sig = frac;
    if exp != 0 {
        sig |= F64_IMPLICIT_BIT;
    } else {
        // Subnormal f64 — normalize first
        let (ne, nf) = f64_normalize_subnormal(frac);
        let adj_exp = ne - F64_EXP_BIAS as i32 + F32_EXP_BIAS;
        // Continue with normalized values
        return truncate_to_f32(sign, adj_exp, nf);
    }

    truncate_to_f32(sign, new_exp, sig)
}

fn truncate_to_f32(sign: u32, new_exp: i32, sig: u64) -> u32 {
    // sig has 53 bits (implicit + 52 fraction). f32 needs 24 bits (implicit + 23).
    // Shift right by 29 with rounding.
    let shift = 29;
    let dropped = sig & ((1u64 << shift) - 1);
    let halfway = 1u64 << (shift - 1);
    let mut f32_sig = (sig >> shift) as u32;

    // Round to nearest, ties to even
    if dropped > halfway || (dropped == halfway && (f32_sig & 1) != 0) {
        f32_sig += 1;
    }

    let mut result_exp = new_exp;

    // Handle carry from rounding
    if f32_sig >= (1u32 << 24) {
        f32_sig >>= 1;
        result_exp += 1;
    }

    // Overflow → infinity
    if result_exp >= 0xFF {
        return sign | 0x7F80_0000;
    }

    // Underflow → subnormal or zero
    if result_exp <= 0 {
        let s = 1 - result_exp;
        if s >= 24 {
            return sign;
        }
        f32_sig >>= s;
        return sign | f32_sig;
    }

    // Remove implicit bit
    f32_sig &= (1u32 << F32_FRAC_BITS) - 1;
    sign | ((result_exp as u32) << F32_FRAC_BITS) | f32_sig
}

/// __extendsfdf2: f32 → f64
#[unsafe(export_name = "__extendsfdf2")]
pub extern "C" fn __extendsfdf2(a: u32) -> u64 {
    let sign = ((a >> 31) as u64) << 63;
    let exp = ((a >> F32_FRAC_BITS) & 0xFF) as i32;
    let frac = (a & ((1u32 << F32_FRAC_BITS) - 1)) as u64;

    // NaN
    if exp == 0xFF && frac != 0 {
        return sign | F64_EXP_MASK | (frac << (F64_FRAC_BITS - F32_FRAC_BITS))
            | 0x0008_0000_0000_0000; // quiet NaN
    }

    // Infinity
    if exp == 0xFF {
        return sign | F64_EXP_MASK;
    }

    // Zero
    if exp == 0 && frac == 0 {
        return sign;
    }

    // Subnormal f32
    if exp == 0 {
        // Normalize
        let shift = frac.leading_zeros() as i32 - (64 - 23); // leading zeros beyond 23 bit width
        let normalized_frac = frac << shift;
        let new_exp = F64_EXP_BIAS - F32_EXP_BIAS - shift + 1;
        let f64_frac = (normalized_frac & ((1u64 << F32_FRAC_BITS) - 1))
            << (F64_FRAC_BITS - F32_FRAC_BITS);
        return f64_pack(sign, new_exp, f64_frac);
    }

    // Normal: rebias exponent, shift fraction
    let new_exp = exp - F32_EXP_BIAS + F64_EXP_BIAS;
    let f64_frac = frac << (F64_FRAC_BITS - F32_FRAC_BITS);
    f64_pack(sign, new_exp, f64_frac)
}

// ---------------------------------------------------------------------------
// Unsigned integer → f64 conversions
// ---------------------------------------------------------------------------

/// __floatunsidf: u32 → f64
#[unsafe(export_name = "__floatunsidf")]
pub extern "C" fn __floatunsidf(a: u32) -> u64 {
    if a == 0 {
        return 0;
    }
    let mag = a as u64;
    let msb = 63 - mag.leading_zeros() as i32;
    let exp = msb + F64_EXP_BIAS;
    let frac = if msb > 52 {
        mag >> (msb - 52)
    } else {
        mag << (52 - msb)
    };
    f64_pack(0, exp, frac & F64_FRAC_MASK)
}

/// __floatundidf: u64 → f64
#[unsafe(export_name = "__floatundidf")]
pub extern "C" fn __floatundidf(a: u64) -> u64 {
    if a == 0 {
        return 0;
    }
    let msb = 63 - a.leading_zeros() as i32;
    let exp = msb + F64_EXP_BIAS;
    let frac = if msb > 52 {
        let shift = msb - 52;
        let dropped = a & ((1u64 << shift) - 1);
        let halfway = 1u64 << (shift - 1);
        let mut f = a >> shift;
        if dropped > halfway || (dropped == halfway && (f & 1) != 0) {
            f += 1;
        }
        f
    } else {
        a << (52 - msb)
    };
    if frac >= (F64_IMPLICIT_BIT << 1) {
        f64_pack(0, exp + 1, (frac >> 1) & F64_FRAC_MASK)
    } else {
        f64_pack(0, exp, frac & F64_FRAC_MASK)
    }
}

// ---------------------------------------------------------------------------
// f64 → integer conversions
// ---------------------------------------------------------------------------

/// __fixdfsi: f64 → i32 (truncate toward zero)
#[unsafe(export_name = "__fixdfsi")]
pub extern "C" fn __fixdfsi(a: u64) -> i32 {
    let sign = f64_sign(a);
    let exp = f64_exp(a);
    let frac = f64_frac(a);

    if exp == 0x7FF || (exp == 0 && frac == 0) {
        return 0;
    }

    let unbiased = exp - F64_EXP_BIAS;
    if unbiased < 0 {
        return 0;
    }
    if unbiased >= 31 {
        return if sign != 0 { i32::MIN } else { i32::MAX };
    }

    let sig = frac | F64_IMPLICIT_BIT;
    let shift = F64_FRAC_BITS as i32 - unbiased;
    let mag = if shift > 0 { (sig >> shift) as u32 } else { (sig << (-shift)) as u32 };

    if sign != 0 {
        -(mag as i32)
    } else {
        mag as i32
    }
}

/// __fixdfdi: f64 → i64 (truncate toward zero)
#[unsafe(export_name = "__fixdfdi")]
pub extern "C" fn __fixdfdi(a: u64) -> i64 {
    let sign = f64_sign(a);
    let exp = f64_exp(a);
    let frac = f64_frac(a);

    if exp == 0x7FF || (exp == 0 && frac == 0) {
        return 0;
    }

    let unbiased = exp - F64_EXP_BIAS;
    if unbiased < 0 {
        return 0;
    }
    if unbiased >= 63 {
        return if sign != 0 { i64::MIN } else { i64::MAX };
    }

    let sig = frac | F64_IMPLICIT_BIT;
    let shift = F64_FRAC_BITS as i32 - unbiased;
    let mag = if shift > 0 { sig >> shift } else { sig << (-shift) };

    if sign != 0 {
        -(mag as i64)
    } else {
        mag as i64
    }
}

/// __fixunsdfsi: f64 → u32 (truncate toward zero, unsigned)
#[unsafe(export_name = "__fixunsdfsi")]
pub extern "C" fn __fixunsdfsi(a: u64) -> u32 {
    let sign = f64_sign(a);
    if sign != 0 {
        return 0; // negative → 0 for unsigned
    }
    let exp = f64_exp(a);
    let frac = f64_frac(a);

    if exp == 0x7FF || (exp == 0 && frac == 0) {
        return 0;
    }

    let unbiased = exp - F64_EXP_BIAS;
    if unbiased < 0 {
        return 0;
    }
    if unbiased >= 32 {
        return u32::MAX;
    }

    let sig = frac | F64_IMPLICIT_BIT;
    let shift = F64_FRAC_BITS as i32 - unbiased;
    if shift > 0 { (sig >> shift) as u32 } else { (sig << (-shift)) as u32 }
}

/// __fixunsdfdi: f64 → u64 (truncate toward zero, unsigned)
#[unsafe(export_name = "__fixunsdfdi")]
pub extern "C" fn __fixunsdfdi(a: u64) -> u64 {
    let sign = f64_sign(a);
    if sign != 0 {
        return 0;
    }
    let exp = f64_exp(a);
    let frac = f64_frac(a);

    if exp == 0x7FF || (exp == 0 && frac == 0) {
        return 0;
    }

    let unbiased = exp - F64_EXP_BIAS;
    if unbiased < 0 {
        return 0;
    }
    if unbiased >= 64 {
        return u64::MAX;
    }

    let sig = frac | F64_IMPLICIT_BIT;
    let shift = F64_FRAC_BITS as i32 - unbiased;
    if shift > 0 { sig >> shift } else { sig << (-shift) }
}
