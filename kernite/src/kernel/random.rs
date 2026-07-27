//! Kernel hardware random number generator (RDRAND / RDSEED / RNDR)
//!
//! Provides kernel-internal entropy sourced from the CPU's hardware RNG.
//! Used for ASLR, stack canary seeds, and the `KernelRng` `RNG_READ`
//! capability invocation.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Maximum retry count for RDRAND/RDSEED/RNDR (Intel recommendation: 10).
const MAX_RETRIES: u32 = 10;

/// Generate a 64-bit random value using hardware RNG.
///
/// On x86_64, uses RDRAND. On aarch64, uses RNDR (ARMv8.5 FEAT_RNG).
///
/// Returns `None` if the CPU does not support the hardware RNG or if all
/// retries fail.
pub fn rdrand64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if !crate::arch::cpuid::has_hw_rng() {
            return None;
        }
        for _ in 0..MAX_RETRIES {
            if let Some(val) = crate::arch::random::rdrand64_once() {
                return Some(val);
            }
        }
        None
    }
    #[cfg(target_arch = "aarch64")]
    {
        // FEAT_RNG is optional. If it is absent, touching RNDR itself
        // faults, so gate the instruction on the architectural ID bit.
        if !crate::arch::cpuid::has_hw_rng() {
            return None;
        }
        for _ in 0..MAX_RETRIES {
            if let Some(val) = crate::arch::random::rdrand64_once() {
                return Some(val);
            }
        }
        None
    }
}

/// Generate a 64-bit seed value using hardware RNG.
///
/// On x86_64, uses RDSEED (falling back to RDRAND). On aarch64, delegates
/// to `rdrand64()` since there is no separate seed instruction.
pub fn rdseed64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::arch::cpuid::has_hw_seed() {
            for _ in 0..MAX_RETRIES {
                if let Some(val) = crate::arch::random::rdseed64_once() {
                    return Some(val);
                }
            }
        }
        // Fallback to RDRAND
        rdrand64()
    }
    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 RNDR is the only hardware RNG; no separate seed instruction
        for _ in 0..MAX_RETRIES {
            if let Some(val) = crate::arch::random::rdseed64_once() {
                return Some(val);
            }
        }
        None
    }
}

/// Generate a random u64 in the range [0, max).
///
/// Uses rejection sampling to avoid modulo bias.
/// Returns `None` if the hardware RNG is unavailable.
pub fn random_range(max: u64) -> Option<u64> {
    if max <= 1 {
        return Some(0);
    }
    // Rejection sampling: reject values >= threshold to avoid bias.
    // threshold = u64::MAX - (u64::MAX % max) - 1 + 1, i.e. round down to
    // the largest multiple of `max` that fits in u64.
    let threshold = u64::MAX - (u64::MAX % max);
    for _ in 0..64 {
        if let Some(val) = rdrand64() {
            if val < threshold {
                return Some(val % max);
            }
        } else {
            return None;
        }
    }
    // Extreme fallback: just use modulo (very unlikely to reach here)
    rdrand64().map(|v| v % max)
}

/// Generate a page-aligned random offset (in bytes).
///
/// Returns an offset in [0, max_pages * 4096) that is 4K-aligned.
/// Returns `None` if the hardware RNG is unavailable or `max_pages` is 0.
pub fn random_page_offset(max_pages: usize) -> Option<u64> {
    if max_pages == 0 {
        return Some(0);
    }
    random_range(max_pages as u64).map(|pages| pages * 4096)
}
