// SPDX-License-Identifier: GPL-2.0-only
//! Kernel time anchors.

use core::sync::atomic::AtomicU64;

/// Kernel boot-time anchor in nanoseconds.
///
/// Captured very early in `init::main::kmain` from `arch::now_ns()`.
/// CLOCK_REALTIME currently reports monotonic time plus this anchor; SaltyOS
/// has no RTC plumbing yet, so this starts as the kernel's early monotonic
/// reference and can become a wall-clock epoch later.
pub(crate) static BOOT_TIME_NS: AtomicU64 = AtomicU64::new(0);
