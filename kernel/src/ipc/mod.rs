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
    /// Message label (extracted from msg_info bits 51:12)
    pub label: u64,
    /// Number of valid message registers (extracted from msg_info bits 6:0)
    pub length: usize,
    /// Number of capabilities to transfer (extracted from msg_info bits 11:7)
    pub extra_caps: usize,
    /// Message registers (inline fastpath: 4 in registers, overflow via IPC buffer)
    pub regs: [u64; 4],
}

impl Message {
    pub const fn empty() -> Self {
        Self {
            label: 0,
            length: 0,
            extra_caps: 0,
            regs: [0; 4],
        }
    }
}

/// IPC Buffer layout (mapped into user VSpace, shared between kernel and user)
///
/// The msg[] array is overlaid by userland as `struct salty_msg`:
///   msg[0] = label, msg[1] = length, msg[2..21] = regs[0..19]
/// So 22 slots = 2 header + 20 message registers.
///
/// Total size: 4096 bytes (one page)
#[repr(C)]
pub struct IpcBuffer {
    /// salty_msg overlay: [label, length, regs[0..19]]
    pub msg: [u64; 22],         // 0x000: 176 bytes
    /// Badge received from sender
    pub badge: u64,             // 0x0B0: 8 bytes
    /// Capability slots to transfer (sender-side: indices into sender's CNode)
    pub caps: [u64; 4],         // 0x0B8: 32 bytes
    /// CNode for receiving transferred capabilities
    pub receive_cnode: u64,     // 0x0D8: 8 bytes
    /// Starting slot index in receive CNode
    pub receive_index: u64,     // 0x0E0: 8 bytes
    /// CNode depth for receive
    pub receive_depth: u64,     // 0x0E8: 8 bytes
    /// Reserved for future use
    pub reserved: [u64; 478],   // 0x0F0: 3824 bytes
}

// Compile-time assertion: IpcBuffer fits in one page
const _: () = assert!(core::mem::size_of::<IpcBuffer>() <= 4096);

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
        length: 4,
        extra_caps: 0,
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
        length: 4,
        extra_caps: 0,
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
