//! Thread Control Block
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::CNode;
use crate::mm::VSpace;

/// Thread state
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Inactive,
    Ready,
    Running,
    Blocked,
    Waiting,
}

/// Reason why a thread is blocked
#[derive(Clone, Copy)]
pub enum BlockedReason {
    /// Blocked on send - waiting for receiver
    SendBlocked {
        /// Message to send
        msg: super::super::ipc::Message,
        /// Badge (sender identity)
        badge: u64,
    },
    /// Blocked on receive - waiting for sender
    RecvBlocked,
    /// Blocked on notification wait
    NotificationWait,
}

/// Thread Control Block
#[repr(C)]
pub struct Tcb {
    /// Thread state
    pub state: ThreadState,
    /// Priority (for EDF: deadline)
    pub priority: u64,
    /// Saved registers
    pub context: ThreadContext,
    /// Virtual address space
    pub vspace: *mut VSpace,
    /// Capability space root
    pub cspace: *mut CNode,
    /// IPC buffer address
    pub ipc_buffer: u64,
    /// Scheduling context
    pub sched_context: *mut SchedContext,
    /// Next thread in queue
    pub next: *mut Tcb,
    /// Why this thread is blocked (valid when state == Blocked/Waiting)
    pub blocked_reason: Option<BlockedReason>,
    /// Saved caller badge (for reply_recv)
    pub saved_caller_badge: u64,
    /// Saved caller message (for reply_recv)
    pub saved_caller_msg: super::super::ipc::Message,
    /// Notification pointer if blocked on notification
    pub blocked_notification: *mut u8,
}

/// Saved thread context
#[repr(C)]
pub struct ThreadContext {
    // General purpose registers
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Instruction pointer
    pub rip: u64,
    // Flags
    pub rflags: u64,
    // Segments
    pub cs: u64,
    pub ss: u64,
}

impl ThreadContext {
    pub const fn empty() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            cs: 0,
            ss: 0,
        }
    }
}

/// Scheduling context (EDF parameters)
#[repr(C)]
pub struct SchedContext {
    /// Budget per period (time units)
    pub budget: u64,
    /// Remaining budget
    pub remaining: u64,
    /// Period length
    pub period: u64,
    /// Absolute deadline
    pub deadline: u64,
    /// Bound TCB
    pub bound_tcb: *mut Tcb,
}

impl Tcb {
    pub const fn new() -> Self {
        Self {
            state: ThreadState::Inactive,
            priority: 0,
            context: ThreadContext::empty(),
            vspace: core::ptr::null_mut(),
            cspace: core::ptr::null_mut(),
            ipc_buffer: 0,
            sched_context: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            blocked_reason: None,
            saved_caller_badge: 0,
            saved_caller_msg: super::super::ipc::Message::empty(),
            blocked_notification: core::ptr::null_mut(),
        }
    }
}
