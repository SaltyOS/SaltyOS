// SPDX-License-Identifier: GPL-2.0-only
//! RT FIFO scheduling class.
//!
//! Static-priority real-time class: higher `rt_priority` value runs
//! first within the class. Ties resolve FIFO — once a higher-priority
//! peer arrives, the running RT thread is preempted; among equal-
//! priority peers, the running thread keeps the CPU until it blocks
//! or yields.

use super::SCHED_CLASS_SHIFT;

/// Maximum RT FIFO priority. Values are clamped to
/// `[1, RT_FIFO_MAX_PRIORITY]` at admission — `0` is reserved as the
/// "no priority configured" sentinel and is rejected by
/// `task::control::set_priority_locked`.
pub const RT_FIFO_MAX_PRIORITY: u8 = 99;

/// In-class key base for the RT FIFO discriminant (encoded in the
/// scheduler key's class stamp).
pub const RT_FIFO_KEY_BASE: u64 = 1u64 << SCHED_CLASS_SHIFT;

// The class-priority encoder lives on `Tcb::encode_rt_fifo_priority`
// (`sched/thread.rs`). It clamps `priority == 0` to 1 to honour the
// "0 = invalid" admission rule that `task::control::set_priority_locked`
// enforces, then maps higher `priority` values to smaller keys via
// `RT_FIFO_KEY_BASE + (RT_FIFO_MAX_PRIORITY - clamped)`.
