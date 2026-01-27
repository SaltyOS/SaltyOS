//! Scheduler
//!
//! EDF (Earliest Deadline First) with budget enforcement.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod scheduler;
mod thread;

// Re-exports for future use
pub use thread::Tcb;

/// Initialize scheduler
pub fn init() {
    // Initialize scheduler structures
}

/// Yield current thread
pub fn yield_now() {
    // TODO: Trigger reschedule
}

/// Get current thread
pub fn current() -> Option<&'static mut Tcb> {
    // TODO: Return current TCB
    None
}
