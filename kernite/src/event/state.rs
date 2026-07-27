// SPDX-License-Identifier: GPL-2.0-only
//! State-flag word helpers.
//!
//! Watchable kernel objects expose a `state_flags: AtomicU64` whose bits
//! match the `KERNITE_STATE_*` constants in `kernite/include/uapi/event.h`. The helpers
//! here are the common asserts / clears used by the IPC and event planes
//! before notifying any registered `Watch`.

use core::sync::atomic::{AtomicU64, Ordering};

#[inline]
pub fn assert_bits(state: &AtomicU64, bits: u64) -> u64 {
    state.fetch_or(bits, Ordering::AcqRel)
}

#[inline]
pub fn clear_bits(state: &AtomicU64, bits: u64) -> u64 {
    state.fetch_and(!bits, Ordering::AcqRel)
}

#[inline]
pub fn read(state: &AtomicU64) -> u64 {
    state.load(Ordering::Acquire)
}
