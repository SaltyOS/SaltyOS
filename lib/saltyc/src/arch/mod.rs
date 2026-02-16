//! Architecture-specific implementations
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Defines traits for architecture-dependent operations (math, memory, string).
//! Each target architecture provides a concrete type implementing these traits.
//! The `Arch` type alias resolves to the current target at compile time, giving
//! zero-cost dispatch (monomorphized, inlineable).

/// Architecture-dependent math operations.
///
/// Functions that require platform-specific instructions (x87 FPU, SSE, NEON)
/// are grouped here. Pure bit-manipulation functions (fpclassify, copysign,
/// fabs) remain in `math_impl.rs` as they are architecture-independent.
pub trait ArchMath {
    fn sqrt(x: f64) -> f64;
    fn sqrtf(x: f32) -> f32;
    fn floor(x: f64) -> f64;
    fn ceil(x: f64) -> f64;
    fn trunc(x: f64) -> f64;
    fn rint(x: f64) -> f64;
    fn sin(x: f64) -> f64;
    fn cos(x: f64) -> f64;
    fn tan(x: f64) -> f64;
    fn atan2(y: f64, x: f64) -> f64;
    fn log(x: f64) -> f64;
    fn log2(x: f64) -> f64;
    fn log10(x: f64) -> f64;
    fn exp(x: f64) -> f64;
    fn exp2(x: f64) -> f64;
    fn pow(x: f64, y: f64) -> f64;
    fn fmod(x: f64, y: f64) -> f64;
    fn remainder(x: f64, y: f64) -> f64;
    fn fma(x: f64, y: f64, z: f64) -> f64;
    fn scalbn(x: f64, n: i32) -> f64;
}

/// Architecture-dependent memory operations.
///
/// Hot-path memory functions that benefit from SIMD acceleration.
/// Fallback scalar implementations exist for architectures without SIMD
/// or when SSE2 is disabled via build configuration.
pub trait ArchMem {
    /// # Safety
    /// `dst` and `src` must be valid for `n` bytes. Regions must not overlap.
    unsafe fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
    /// # Safety
    /// `s` must be valid for `n` bytes.
    unsafe fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8;
    /// # Safety
    /// `dst` and `src` must be valid for `n` bytes. Regions may overlap.
    unsafe fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
    /// # Safety
    /// `s1` and `s2` must be valid for `n` bytes.
    unsafe fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32;
    /// # Safety
    /// `s` must be valid for `n` bytes.
    unsafe fn memchr(s: *const u8, c: i32, n: usize) -> *mut u8;
}

/// Architecture-dependent string operations.
///
/// Only includes functions that benefit significantly from SIMD.
pub trait ArchString {
    /// # Safety
    /// `s` must point to a NUL-terminated string.
    unsafe fn strlen(s: *const u8) -> usize;
}

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub type Arch = x86_64::X86_64Arch;
