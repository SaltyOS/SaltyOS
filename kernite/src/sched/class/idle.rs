// SPDX-License-Identifier: GPL-2.0-only
//! Idle scheduling class.
//!
//! Threads in this class run only when no Deadline / RT / Fair
//! thread is eligible. The per-CPU idle TCB sits permanently in this
//! class and serves as the fallback when the scheduler has nothing
//! else to dispatch.

use super::SCHED_CLASS_SHIFT;

/// In-class key base for the Idle discriminant. The largest stamp,
/// so any other-class thread preempts an Idle-class one.
pub const IDLE_KEY_BASE: u64 = 3u64 << SCHED_CLASS_SHIFT;

// The class-priority encoder lives on `Tcb::encode_idle_priority`
// (`sched/thread.rs`). It returns `IDLE_KEY_BASE | CLASS_KEY_MASK`
// — every idle thread shares the largest possible key inside the
// class so the dispatcher treats them as interchangeable fallbacks.
