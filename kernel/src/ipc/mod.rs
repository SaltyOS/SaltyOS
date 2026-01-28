//! IPC Subsystem
//!
//! Synchronous endpoints and asynchronous notifications.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod endpoint;
mod notification;
mod queue;

pub use queue::WaitQueue;

/// IPC message (register-based for fastpath)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Message {
    /// Message label/tag
    pub label: u64,
    /// Message registers
    pub regs: [u64; 4],
}

impl Message {
    pub const fn empty() -> Self {
        Self {
            label: 0,
            regs: [0; 4],
        }
    }
}

/// Initialize IPC subsystem
pub fn init() {
    // Initialize IPC structures
}

use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

use crate::sched::scheduler::scheduler as get_scheduler;

/// Block the current thread on an IPC operation
///
/// This function:
/// 1. Sets thread state to Blocked/Waiting
/// 2. Stores blocked reason
/// 3. Triggers reschedule
///
/// # Safety
/// Must be called from current thread context with interrupts disabled
pub unsafe fn block_current_thread(tcb: *mut Tcb, reason: BlockedReason) {
    (*tcb).blocked_reason = Some(reason);
    (*tcb).state = ThreadState::Blocked;

    // Do NOT enqueue - thread is in endpoint/notification queue, not ready queue
    get_scheduler().reschedule();
}

/// Wake a blocked thread
///
/// This function:
/// 1. Clears blocked reason
/// 2. Sets thread state to Ready
/// 3. Enqueues in ready queue
///
/// # Safety
/// Must be called with interrupts disabled
pub unsafe fn wake_thread(tcb: *mut Tcb) {
    (*tcb).blocked_reason = None;
    (*tcb).blocked_notification = core::ptr::null_mut();
    get_scheduler().enqueue(tcb);
}
