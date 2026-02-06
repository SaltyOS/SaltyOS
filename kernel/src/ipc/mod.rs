//! IPC Subsystem
//!
//! Synchronous endpoints and asynchronous notifications.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod endpoint;
pub mod irq;
mod notification;
mod queue;

pub use endpoint::{Endpoint, EndpointState};
pub use irq::IrqHandler;
pub use notification::Notification;
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

/// Fault types for user-mode exception delivery
#[repr(u64)]
#[derive(Clone, Copy)]
pub enum FaultType {
    NullFault = 0,
    CapFault = 1,
    VMFault = 2,
    UnknownSyscall = 3,
    UserException = 4,
}

/// Build a VMFault message
///
/// Layout:
///   label = FaultType::VMFault (2)
///   regs[0] = fault address (CR2)
///   regs[1] = error code (PF error bits)
///   regs[2] = faulting RIP
///   regs[3] = is_instruction_fault (1 if I/D bit set)
pub fn vm_fault_message(address: u64, error_code: u64, rip: u64, is_instr: bool) -> Message {
    Message {
        label: FaultType::VMFault as u64,
        regs: [address, error_code, rip, is_instr as u64],
    }
}

/// Build a UserException message
///
/// Layout:
///   label = FaultType::UserException (4)
///   regs[0] = exception vector
///   regs[1] = error code
///   regs[2] = faulting RIP
///   regs[3] = faulting RSP
pub fn user_exception_message(vector: u64, error_code: u64, rip: u64, rsp: u64) -> Message {
    Message {
        label: FaultType::UserException as u64,
        regs: [vector, error_code, rip, rsp],
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
    unsafe {
        (*tcb).blocked_reason = Some(reason);
        (*tcb).state = ThreadState::Blocked;
    }

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
    unsafe {
        (*tcb).blocked_reason = None;
        (*tcb).blocked_notification = core::ptr::null_mut();
    }
    get_scheduler().enqueue(tcb);
}
