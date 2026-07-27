//! Compiler builtins for freestanding environment
//!
//! Provides software floating-point intrinsics (IEEE 754) using pure integer
//! math for freestanding targets, plus the subset of i128/u128 helpers the
//! kernel and userland need without depending on a host runtime.
//!
//! SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![allow(internal_features)]
#![feature(compiler_builtins)]
#![compiler_builtins]
#![no_builtins]

use core::cmp::Ordering;

// ---------------------------------------------------------------------------
// C memory/string builtins
// ---------------------------------------------------------------------------

#[cfg(trona_mem_builtins)]

/// memset implementation
///
/// # Safety
/// Caller must ensure dest points to valid memory of at least n bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let c = c as u8;
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = c;
            i += 1;
        }
    }
    dest
}

#[cfg(trona_mem_builtins)]
/// memcpy implementation
///
/// # Safety
/// Caller must ensure src and dest point to valid non-overlapping memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
    }
    dest
}

#[cfg(trona_mem_builtins)]
/// memmove implementation (handles overlapping regions)
///
/// # Safety
/// Caller must ensure src and dest point to valid memory.
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
    }
    dest
}

#[cfg(trona_mem_builtins)]
/// memcmp implementation
///
/// # Safety
/// Caller must ensure s1 and s2 point to valid memory of at least n bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe {
        let mut i = 0;
        while i < n {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b {
                return (a as i32) - (b as i32);
            }
            i += 1;
        }
    }
    0
}

#[cfg(trona_mem_builtins)]
/// bcmp implementation (like memcmp but only returns 0 or non-zero)
///
/// # Safety
/// Caller must ensure s1 and s2 point to valid memory of at least n bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe { memcmp(s1, s2, n) }
}

#[cfg(trona_mem_builtins)]
/// strlen implementation
///
/// # Safety
/// Caller must ensure s points to a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    unsafe {
        let mut len = 0;
        while *s.add(len) != 0 {
            len += 1;
        }
        len
    }
}

// ---------------------------------------------------------------------------
// Integer helper types
// ---------------------------------------------------------------------------

#[cfg(target_endian = "little")]
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct U128Words {
    lo: u64,
    hi: u64,
}

#[cfg(target_endian = "big")]
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct U128Words {
    hi: u64,
    lo: u64,
}

#[repr(C)]
union U128Repr {
    value: u128,
    words: U128Words,
}

impl U128Words {
    const ZERO: Self = Self { lo: 0, hi: 0 };
    const ONE: Self = Self { lo: 1, hi: 0 };
    const I128_MAX: Self = Self {
        lo: u64::MAX,
        hi: 0x7fff_ffff_ffff_ffff,
    };
    const I128_MIN_ABS: Self = Self {
        lo: 0,
        hi: 0x8000_0000_0000_0000,
    };

    #[inline(always)]
    fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    #[inline(always)]
    fn is_negative(self) -> bool {
        (self.hi >> 63) != 0
    }

    #[inline(always)]
    fn cmp_unsigned(self, other: Self) -> Ordering {
        match self.hi.cmp(&other.hi) {
            Ordering::Equal => self.lo.cmp(&other.lo),
            ord => ord,
        }
    }

    #[inline(always)]
    fn bit(self, bit: u32) -> u64 {
        if bit < 64 {
            (self.lo >> bit) & 1
        } else {
            (self.hi >> (bit - 64)) & 1
        }
    }

    #[inline(always)]
    fn set_bit(&mut self, bit: u32) {
        if bit < 64 {
            self.lo |= 1u64 << bit;
        } else {
            self.hi |= 1u64 << (bit - 64);
        }
    }

    #[inline(always)]
    fn shl1(self) -> Self {
        Self {
            lo: self.lo << 1,
            hi: (self.hi << 1) | (self.lo >> 63),
        }
    }

    #[inline(always)]
    fn not(self) -> Self {
        Self {
            lo: !self.lo,
            hi: !self.hi,
        }
    }

    #[inline(always)]
    fn wrapping_add(self, other: Self) -> Self {
        let (lo, carry) = self.lo.overflowing_add(other.lo);
        Self {
            lo,
            hi: self.hi.wrapping_add(other.hi).wrapping_add(carry as u64),
        }
    }

    #[inline(always)]
    fn wrapping_sub(self, other: Self) -> Self {
        let (lo, borrow) = self.lo.overflowing_sub(other.lo);
        Self {
            lo,
            hi: self.hi.wrapping_sub(other.hi).wrapping_sub(borrow as u64),
        }
    }

    #[inline(always)]
    fn wrapping_neg(self) -> Self {
        self.not().wrapping_add(Self::ONE)
    }
}

#[inline(always)]
fn u128_to_words(value: u128) -> U128Words {
    unsafe { U128Repr { value }.words }
}

#[inline(always)]
fn i128_to_words(value: i128) -> U128Words {
    u128_to_words(value as u128)
}

#[inline(always)]
fn words_to_u128(words: U128Words) -> u128 {
    unsafe { U128Repr { words }.value }
}

#[inline(always)]
fn words_to_i128(words: U128Words) -> i128 {
    words_to_u128(words) as i128
}

#[inline(always)]
fn shl_words(value: U128Words, shift: u32) -> U128Words {
    match shift {
        0 => value,
        1..=63 => U128Words {
            lo: value.lo << shift,
            hi: (value.hi << shift) | (value.lo >> (64 - shift)),
        },
        64..=127 => U128Words {
            lo: 0,
            hi: value.lo << (shift - 64),
        },
        _ => U128Words::ZERO,
    }
}

#[inline(always)]
fn lshr_words(value: U128Words, shift: u32) -> U128Words {
    match shift {
        0 => value,
        1..=63 => U128Words {
            lo: (value.lo >> shift) | (value.hi << (64 - shift)),
            hi: value.hi >> shift,
        },
        64..=127 => U128Words {
            lo: value.hi >> (shift - 64),
            hi: 0,
        },
        _ => U128Words::ZERO,
    }
}

#[inline(always)]
fn ashr_words(value: U128Words, shift: u32) -> U128Words {
    let fill = if value.is_negative() { u64::MAX } else { 0 };
    match shift {
        0 => value,
        1..=63 => U128Words {
            lo: (value.lo >> shift) | (value.hi << (64 - shift)),
            hi: ((value.hi as i64) >> shift) as u64,
        },
        64..=127 => U128Words {
            lo: ((value.hi as i64) >> (shift - 64)) as u64,
            hi: fill,
        },
        _ => U128Words { lo: fill, hi: fill },
    }
}

#[inline(always)]
fn mul_u64_wide(a: u64, b: u64) -> U128Words {
    const LOWER_MASK: u64 = 0xffff_ffff;

    let mut lo = (a & LOWER_MASK).wrapping_mul(b & LOWER_MASK);
    let mut t = lo >> 32;
    lo &= LOWER_MASK;

    t = t.wrapping_add((a >> 32).wrapping_mul(b & LOWER_MASK));
    lo = lo.wrapping_add((t & LOWER_MASK) << 32);
    let mut hi = t >> 32;

    t = lo >> 32;
    lo &= LOWER_MASK;
    t = t.wrapping_add((b >> 32).wrapping_mul(a & LOWER_MASK));
    lo = lo.wrapping_add((t & LOWER_MASK) << 32);
    hi = hi
        .wrapping_add(t >> 32)
        .wrapping_add((a >> 32).wrapping_mul(b >> 32));

    U128Words { lo, hi }
}

#[inline(always)]
fn mul_words(a: U128Words, b: U128Words) -> U128Words {
    let product = mul_u64_wide(a.lo, b.lo);
    U128Words {
        lo: product.lo,
        hi: product
            .hi
            .wrapping_add(a.hi.wrapping_mul(b.lo))
            .wrapping_add(a.lo.wrapping_mul(b.hi)),
    }
}

#[inline(always)]
fn udivmod_words(numerator: U128Words, divisor: U128Words) -> (U128Words, U128Words) {
    if divisor.is_zero() {
        panic!("128-bit division by zero");
    }
    if numerator.cmp_unsigned(divisor) == Ordering::Less {
        return (U128Words::ZERO, numerator);
    }

    let mut quotient = U128Words::ZERO;
    let mut remainder = U128Words::ZERO;
    let mut bit = 128u32;

    while bit != 0 {
        bit -= 1;
        remainder = remainder.shl1();
        remainder.lo |= numerator.bit(bit);
        if remainder.cmp_unsigned(divisor) != Ordering::Less {
            remainder = remainder.wrapping_sub(divisor);
            quotient.set_bit(bit);
        }
    }

    (quotient, remainder)
}

#[inline(always)]
fn abs_i128_words(value: i128) -> U128Words {
    let bits = i128_to_words(value);
    if bits.is_negative() {
        bits.wrapping_neg()
    } else {
        bits
    }
}

#[inline(always)]
fn signed_mul_overflow(a: i128, b: i128) -> (i128, bool) {
    let a_neg = a < 0;
    let b_neg = b < 0;
    let result_neg = a_neg ^ b_neg;
    let a_abs = abs_i128_words(a);
    let b_abs = abs_i128_words(b);
    let product = mul_words(a_abs, b_abs);

    let overflow = if a_abs.is_zero() || b_abs.is_zero() {
        false
    } else {
        let limit = if result_neg {
            U128Words::I128_MIN_ABS
        } else {
            U128Words::I128_MAX
        };
        let (max_factor, _) = udivmod_words(limit, a_abs);
        b_abs.cmp_unsigned(max_factor) == Ordering::Greater
    };

    let signed = if result_neg {
        product.wrapping_neg()
    } else {
        product
    };
    (words_to_i128(signed), overflow)
}

// ---------------------------------------------------------------------------
// i128/u128 intrinsics
// ---------------------------------------------------------------------------

#[unsafe(export_name = "__ashlti3")]
pub extern "C" fn __ashlti3(a: u128, b: u32) -> u128 {
    words_to_u128(shl_words(u128_to_words(a), b))
}

#[unsafe(export_name = "__lshrti3")]
pub extern "C" fn __lshrti3(a: u128, b: u32) -> u128 {
    words_to_u128(lshr_words(u128_to_words(a), b))
}

#[unsafe(export_name = "__ashrti3")]
pub extern "C" fn __ashrti3(a: i128, b: u32) -> i128 {
    words_to_i128(ashr_words(i128_to_words(a), b))
}

#[unsafe(export_name = "__multi3")]
pub extern "C" fn __multi3(a: i128, b: i128) -> i128 {
    words_to_i128(mul_words(i128_to_words(a), i128_to_words(b)))
}

#[unsafe(export_name = "__muloti4")]
pub extern "C" fn __muloti4(a: i128, b: i128, overflow: &mut i32) -> i128 {
    let (result, did_overflow) = signed_mul_overflow(a, b);
    *overflow = did_overflow as i32;
    result
}

#[unsafe(export_name = "__udivmodti4")]
pub extern "C" fn __udivmodti4(n: u128, d: u128, rem: *mut u128) -> u128 {
    let (quotient, remainder) = udivmod_words(u128_to_words(n), u128_to_words(d));
    if !rem.is_null() {
        // SAFETY: `rem` comes from the compiler builtin ABI. When non-null it
        // points to writable storage for the remainder result.
        unsafe {
            *rem = words_to_u128(remainder);
        }
    }
    words_to_u128(quotient)
}

#[unsafe(export_name = "__udivti3")]
pub extern "C" fn __udivti3(n: u128, d: u128) -> u128 {
    __udivmodti4(n, d, core::ptr::null_mut())
}

#[unsafe(export_name = "__umodti3")]
pub extern "C" fn __umodti3(n: u128, d: u128) -> u128 {
    let mut rem = 0u128;
    __udivmodti4(n, d, &mut rem);
    rem
}

#[unsafe(export_name = "__divmodti4")]
pub extern "C" fn __divmodti4(a: i128, b: i128, rem: *mut i128) -> i128 {
    let a_neg = a < 0;
    let b_neg = b < 0;
    let (quotient, remainder) = udivmod_words(abs_i128_words(a), abs_i128_words(b));

    if !rem.is_null() {
        let signed_remainder = words_to_i128(if a_neg {
            remainder.wrapping_neg()
        } else {
            remainder
        });
        // SAFETY: `rem` follows the compiler builtin ABI and, when non-null,
        // points to writable storage for the remainder output.
        unsafe {
            *rem = signed_remainder;
        }
    }

    words_to_i128(if a_neg != b_neg {
        quotient.wrapping_neg()
    } else {
        quotient
    })
}

#[unsafe(export_name = "__divti3")]
pub extern "C" fn __divti3(a: i128, b: i128) -> i128 {
    let a_neg = a < 0;
    let b_neg = b < 0;
    let quotient = __udivti3(
        words_to_u128(abs_i128_words(a)),
        words_to_u128(abs_i128_words(b)),
    );
    let quotient = u128_to_words(quotient);
    words_to_i128(if a_neg != b_neg {
        quotient.wrapping_neg()
    } else {
        quotient
    })
}

#[unsafe(export_name = "__modti3")]
pub extern "C" fn __modti3(a: i128, b: i128) -> i128 {
    let remainder = u128_to_words(__umodti3(
        words_to_u128(abs_i128_words(a)),
        words_to_u128(abs_i128_words(b)),
    ));
    words_to_i128(if a < 0 {
        remainder.wrapping_neg()
    } else {
        remainder
    })
}

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
const F32_SIGN_BIT: u32 = 1 << 31;
const F32_EXP_MASK: u32 = 0x7F80_0000;
const F32_FRAC_MASK: u32 = 0x007F_FFFF;
const F32_EXP_BIAS: i32 = 127;
const F32_FRAC_BITS: u32 = 23;

#[inline(always)]
fn f32_sign(bits: u32) -> u32 {
    bits & F32_SIGN_BIT
}

#[inline(always)]
fn f32_is_nan(bits: u32) -> bool {
    (bits & F32_EXP_MASK) == F32_EXP_MASK && (bits & F32_FRAC_MASK) != 0
}

// ---------------------------------------------------------------------------
// f32 arithmetic intrinsics implemented via f64 soft-float helpers
// ---------------------------------------------------------------------------

#[unsafe(export_name = "__addsf3")]
pub extern "C" fn __addsf3(a: u32, b: u32) -> u32 {
    __truncdfsf2(__adddf3(__extendsfdf2(a), __extendsfdf2(b)))
}

#[unsafe(export_name = "__subsf3")]
pub extern "C" fn __subsf3(a: u32, b: u32) -> u32 {
    __truncdfsf2(__subdf3(__extendsfdf2(a), __extendsfdf2(b)))
}

#[unsafe(export_name = "__mulsf3")]
pub extern "C" fn __mulsf3(a: u32, b: u32) -> u32 {
    __truncdfsf2(__muldf3(__extendsfdf2(a), __extendsfdf2(b)))
}

#[unsafe(export_name = "__divsf3")]
pub extern "C" fn __divsf3(a: u32, b: u32) -> u32 {
    __truncdfsf2(__divdf3(__extendsfdf2(a), __extendsfdf2(b)))
}

// ---------------------------------------------------------------------------
// f32 comparison intrinsics
// ---------------------------------------------------------------------------

/// Compare two f32 values. Returns -1, 0, or 1.
/// `nan_result` is returned if either operand is NaN.
fn cmp_f32(a: u32, b: u32, nan_result: i32) -> i32 {
    if f32_is_nan(a) || f32_is_nan(b) {
        return nan_result;
    }

    let a_sign = f32_sign(a);
    let b_sign = f32_sign(b);

    // Both zero (positive or negative)
    if (a & !F32_SIGN_BIT) == 0 && (b & !F32_SIGN_BIT) == 0 {
        return 0;
    }

    // Different signs
    if a_sign != b_sign {
        return if a_sign != 0 { -1 } else { 1 };
    }

    // Same sign — compare magnitudes
    let a_mag = a & !F32_SIGN_BIT;
    let b_mag = b & !F32_SIGN_BIT;

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

#[unsafe(export_name = "__ltsf2")]
pub extern "C" fn __ltsf2(a: u32, b: u32) -> i32 {
    cmp_f32(a, b, 1) // NaN -> not less than
}

#[unsafe(export_name = "__lesf2")]
pub extern "C" fn __lesf2(a: u32, b: u32) -> i32 {
    cmp_f32(a, b, 1) // NaN -> not less than or equal
}

#[unsafe(export_name = "__gtsf2")]
pub extern "C" fn __gtsf2(a: u32, b: u32) -> i32 {
    cmp_f32(a, b, -1) // NaN -> not greater than
}

#[unsafe(export_name = "__gesf2")]
pub extern "C" fn __gesf2(a: u32, b: u32) -> i32 {
    cmp_f32(a, b, -1) // NaN -> not greater than or equal
}

#[unsafe(export_name = "__eqsf2")]
pub extern "C" fn __eqsf2(a: u32, b: u32) -> i32 {
    cmp_f32(a, b, 1) // NaN -> not equal
}

#[unsafe(export_name = "__nesf2")]
pub extern "C" fn __nesf2(a: u32, b: u32) -> i32 {
    cmp_f32(a, b, 1) // NaN -> not equal
}

#[unsafe(export_name = "__unordsf2")]
pub extern "C" fn __unordsf2(a: u32, b: u32) -> i32 {
    if f32_is_nan(a) || f32_is_nan(b) { 1 } else { 0 }
}

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
            let sticky = if (b_sig & ((1u128 << exp_diff) - 1)) != 0 {
                1u128
            } else {
                0
            };
            b_sig = (b_sig >> exp_diff) | sticky;
        } else {
            b_sig = 1; // sticky
        }
    } else if exp_diff < 0 {
        result_exp = b_exp;
        let shift = -exp_diff;
        if shift < 128 {
            let sticky = if (a_sig & ((1u128 << shift) - 1)) != 0 {
                1u128
            } else {
                0
            };
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
        let sticky = if (result_sig & ((1u128 << shift) - 1)) != 0 {
            1u128
        } else {
            0
        };
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
        let sticky = if (product & ((1u128 << (shift - 1)) - 1)) != 0 {
            1u64
        } else {
            0
        };
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
        let s = if (q & ((1u64 << shift) - 1)) != 0 || sticky != 0 {
            1u64
        } else {
            0
        };
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

#[unsafe(export_name = "__nedf2")]
pub extern "C" fn __nedf2(a: u64, b: u64) -> i32 {
    cmp_f64(a, b, 1) // NaN → not equal (same semantics as __eqdf2)
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
    let mag = if a < 0 {
        (-(a as i64)) as u64
    } else {
        a as u64
    };

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
        return sign
            | F64_EXP_MASK
            | (frac << (F64_FRAC_BITS - F32_FRAC_BITS))
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
        let f64_frac =
            (normalized_frac & ((1u64 << F32_FRAC_BITS) - 1)) << (F64_FRAC_BITS - F32_FRAC_BITS);
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
    let mag = if shift > 0 {
        (sig >> shift) as u32
    } else {
        (sig << (-shift)) as u32
    };

    if sign != 0 { -(mag as i32) } else { mag as i32 }
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
    let mag = if shift > 0 {
        sig >> shift
    } else {
        sig << (-shift)
    };

    if sign != 0 { -(mag as i64) } else { mag as i64 }
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
    if shift > 0 {
        (sig >> shift) as u32
    } else {
        (sig << (-shift)) as u32
    }
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
    if shift > 0 {
        sig >> shift
    } else {
        sig << (-shift)
    }
}

// ---------------------------------------------------------------------------
// f128 (quad precision) intrinsics — needed on aarch64 where long double is
// IEEE 754 binary128 (1 sign + 15 exponent + 112 fraction bits).
// ---------------------------------------------------------------------------

const F128_SIGN_BIT: u128 = 1u128 << 127;
const F128_EXP_BITS: u32 = 15;
const F128_FRAC_BITS: u32 = 112;
const F128_EXP_MASK: u128 = ((1u128 << F128_EXP_BITS) - 1) << F128_FRAC_BITS;
const F128_FRAC_MASK: u128 = (1u128 << F128_FRAC_BITS) - 1;
const F128_IMPLICIT_BIT: u128 = 1u128 << F128_FRAC_BITS;
const F128_EXP_BIAS: i32 = 16383;

#[inline(always)]
fn f128_sign(a: u128) -> u128 {
    a >> 127
}

#[inline(always)]
fn f128_exp(a: u128) -> i32 {
    ((a >> F128_FRAC_BITS) & ((1u128 << F128_EXP_BITS) - 1)) as i32
}

#[inline(always)]
fn f128_frac(a: u128) -> u128 {
    a & F128_FRAC_MASK
}

#[inline(always)]
fn f128_is_nan(a: u128) -> bool {
    (a & F128_EXP_MASK) == F128_EXP_MASK && (a & F128_FRAC_MASK) != 0
}

/// Compare two f128 values. Returns -1, 0, or 1.
/// `nan_result` is returned if either operand is NaN.
fn cmp_f128(a: u128, b: u128, nan_result: i32) -> i32 {
    if f128_is_nan(a) || f128_is_nan(b) {
        return nan_result;
    }

    let a_sign = f128_sign(a);
    let b_sign = f128_sign(b);

    // Both zero (positive or negative)
    if (a & !F128_SIGN_BIT) == 0 && (b & !F128_SIGN_BIT) == 0 {
        return 0;
    }

    // Different signs
    if a_sign != b_sign {
        return if a_sign != 0 { -1 } else { 1 };
    }

    // Same sign — compare magnitudes
    let a_mag = a & !F128_SIGN_BIT;
    let b_mag = b & !F128_SIGN_BIT;

    if a_mag == b_mag {
        return 0;
    }

    if a_sign != 0 {
        if a_mag > b_mag { -1 } else { 1 }
    } else {
        if a_mag > b_mag { 1 } else { -1 }
    }
}

/// __lttf2: f128 less-than comparison (returns negative if a < b)
#[unsafe(export_name = "__lttf2")]
pub extern "C" fn __lttf2(a: u128, b: u128) -> i32 {
    cmp_f128(a, b, 1) // NaN → not less than
}

/// __letf2: f128 less-than-or-equal comparison
#[unsafe(export_name = "__letf2")]
pub extern "C" fn __letf2(a: u128, b: u128) -> i32 {
    cmp_f128(a, b, 1)
}

/// __gttf2: f128 greater-than comparison
#[unsafe(export_name = "__gttf2")]
pub extern "C" fn __gttf2(a: u128, b: u128) -> i32 {
    cmp_f128(a, b, -1)
}

/// __getf2: f128 greater-than-or-equal comparison
#[unsafe(export_name = "__getf2")]
pub extern "C" fn __getf2(a: u128, b: u128) -> i32 {
    cmp_f128(a, b, -1)
}

/// __eqtf2: f128 equality comparison
#[unsafe(export_name = "__eqtf2")]
pub extern "C" fn __eqtf2(a: u128, b: u128) -> i32 {
    cmp_f128(a, b, 1)
}

/// __netf2: f128 inequality comparison
#[unsafe(export_name = "__netf2")]
pub extern "C" fn __netf2(a: u128, b: u128) -> i32 {
    cmp_f128(a, b, 1)
}

/// __unordtf2: f128 unordered comparison (returns nonzero if either is NaN)
#[unsafe(export_name = "__unordtf2")]
pub extern "C" fn __unordtf2(a: u128, b: u128) -> i32 {
    if f128_is_nan(a) || f128_is_nan(b) {
        1
    } else {
        0
    }
}

/// __trunctfdf2: f128 → f64
#[unsafe(export_name = "__trunctfdf2")]
pub extern "C" fn __trunctfdf2(a: u128) -> u64 {
    let sign = ((a >> 127) as u64) << 63;
    let exp = f128_exp(a);
    let frac = f128_frac(a);

    // NaN
    if exp == 0x7FFF && frac != 0 {
        return sign | 0x7FF8_0000_0000_0000; // quiet NaN
    }

    // Infinity
    if exp == 0x7FFF {
        return sign | 0x7FF0_0000_0000_0000;
    }

    // Zero
    if exp == 0 && frac == 0 {
        return sign;
    }

    // Get full significand with implicit bit
    let mut sig = frac;
    let mut src_exp = exp;
    if exp != 0 {
        sig |= F128_IMPLICIT_BIT;
    } else {
        // Subnormal f128 — normalize
        let shift = sig.leading_zeros() - (128 - F128_FRAC_BITS - 1);
        sig <<= shift;
        src_exp = 1 - shift as i32;
    }

    // Rebias exponent: f128 bias 16383, f64 bias 1023
    let new_exp = src_exp - F128_EXP_BIAS + F64_EXP_BIAS as i32;

    // sig has 113 bits (implicit + 112 fraction). f64 needs 53 bits (implicit + 52).
    // Shift right by 60 with rounding.
    let shift = (F128_FRAC_BITS - F64_FRAC_BITS as u32) as u128;
    let dropped = sig & ((1u128 << shift) - 1);
    let halfway = 1u128 << (shift - 1);
    let mut f64_sig = (sig >> shift) as u64;

    // Round to nearest, ties to even
    if dropped > halfway || (dropped == halfway && (f64_sig & 1) != 0) {
        f64_sig += 1;
    }

    let mut result_exp = new_exp;

    // Handle carry from rounding
    if f64_sig >= (1u64 << (F64_FRAC_BITS as u32 + 1)) {
        f64_sig >>= 1;
        result_exp += 1;
    }

    // Overflow → infinity
    if result_exp >= 0x7FF {
        return sign | 0x7FF0_0000_0000_0000;
    }

    // Underflow → subnormal or zero
    if result_exp <= 0 {
        let s = 1 - result_exp;
        if s >= 53 {
            return sign;
        }
        f64_sig >>= s;
        return sign | f64_sig;
    }

    // Remove implicit bit
    f64_sig &= F64_FRAC_MASK;
    sign | ((result_exp as u64) << F64_FRAC_BITS as u32) | f64_sig
}
