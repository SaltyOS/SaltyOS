//! AArch64 hardware random instruction wrappers.
//!
//! SPDX-License-Identifier: GPL-2.0-only

unsafe extern "C" {
    fn aarch64_random_rndr64_once(out: *mut u64) -> u32;
}

#[inline]
pub fn rdrand64_once() -> Option<u64> {
    let mut value = 0;
    let ok = unsafe { aarch64_random_rndr64_once(&mut value) };
    (ok != 0).then_some(value)
}

#[inline]
pub fn rdseed64_once() -> Option<u64> {
    rdrand64_once()
}
