//! Thread Control Block
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::{KernelObject, ObjectType};
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
    /// Blocked on VSpace teardown - waiting for VSpace to become inactive
    VSpaceWait,
    /// Blocked waiting for reply from server (after call())
    ReplyWait {
        /// Message to send
        msg: super::super::ipc::Message,
        /// Badge (sender identity)
        badge: u64,
    },
    /// Blocked on fault delivery (waiting for fault handler to reply)
    FaultBlocked {
        /// Fault message (label = FaultType, regs = fault details)
        msg: super::super::ipc::Message,
        /// Badge
        badge: u64,
    },
    /// Blocked on call() send phase - waiting for receiver to pick up
    /// When recv() pops this, the sender stays blocked (transitions to ReplyWait)
    CallSendBlocked {
        /// Message to send
        msg: super::super::ipc::Message,
        /// Badge (sender identity)
        badge: u64,
    },
}

/// Thread Control Block
#[repr(C)]
pub struct Tcb {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Thread state
    pub state: ThreadState,
    /// Priority (for EDF: deadline)
    pub priority: u64,
    /// Saved registers
    pub context: ThreadContext,
    /// Virtual address space root
    pub vspace_root: *mut VSpace,
    /// Capability space root
    pub cspace_root: *mut CNode,
    /// IPC buffer address
    pub ipc_buffer: u64,
    /// Cached receive CNode slot for incoming cap transfers
    pub ipc_receive_cnode: u64,
    /// Cached receive index for incoming cap transfers
    pub ipc_receive_index: u64,
    /// Cached receive depth for incoming cap transfers
    pub ipc_receive_depth: u64,
    /// Scheduling context
    pub sched_context: *mut SchedContext,
    /// CPU affinity (0xFFFF_FFFF = any CPU, otherwise specific CPU ID)
    pub cpu_affinity: u32,
    /// Next thread in queue
    pub next: *mut Tcb,
    /// Why this thread is blocked (valid when state == Blocked/Waiting)
    pub blocked_reason: Option<BlockedReason>,
    /// Saved caller badge (for reply_recv)
    pub saved_caller_badge: u64,
    /// Saved caller message (for reply_recv)
    pub saved_caller_msg: super::super::ipc::Message,
    /// Endpoint pointer if blocked on endpoint send/recv queue
    pub blocked_endpoint: *mut u8,
    /// Notification pointer if blocked on notification
    pub blocked_notification: *mut u8,
    /// VSpace tracking pointer (for VSpaceWait)
    pub blocked_vspace_tracking: *mut crate::mm::VSpaceTracking,
    /// Next pointer for VSpace wait queue (intrusive)
    pub vspace_wait_next: *mut Tcb,
    /// Reply capability: pointer to caller's TCB (for reply_recv)
    pub reply_tcb: *mut Tcb,
    /// Can the caller grant capabilities in the reply?
    pub reply_can_grant: bool,
    /// Fault handler endpoint (for delivering faults to userspace handler)
    pub fault_handler: *mut u8,
    /// Bound notification for combined IPC wait
    pub bound_notification: *mut u8,
    /// Kernel stack top for syscall entry (per-thread kernel stack)
    pub kernel_stack_top: u64,
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
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
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
    /// Cumulative consumed time (ticks)
    pub consumed: u64,
}

impl Tcb {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Tcb, 0),
            state: ThreadState::Inactive,
            priority: 0,
            context: ThreadContext::empty(),
            vspace_root: core::ptr::null_mut(),
            cspace_root: core::ptr::null_mut(),
            ipc_buffer: 0,
            ipc_receive_cnode: 0,
            ipc_receive_index: 0,
            ipc_receive_depth: 0,
            sched_context: core::ptr::null_mut(),
            cpu_affinity: 0xFFFF_FFFF,
            next: core::ptr::null_mut(),
            blocked_reason: None,
            saved_caller_badge: 0,
            saved_caller_msg: super::super::ipc::Message::empty(),
            blocked_endpoint: core::ptr::null_mut(),
            blocked_notification: core::ptr::null_mut(),
            blocked_vspace_tracking: core::ptr::null_mut(),
            vspace_wait_next: core::ptr::null_mut(),
            reply_tcb: core::ptr::null_mut(),
            reply_can_grant: false,
            fault_handler: core::ptr::null_mut(),
            bound_notification: core::ptr::null_mut(),
            kernel_stack_top: 0,
        }
    }

    /// Cleanup when TCB is destroyed
    ///
    /// Note: This does not wake the thread if blocked or remove it from scheduler queues.
    /// Those operations should be handled by the caller before calling cleanup.
    ///
    /// However, this DOES wake any caller waiting for a reply via reply_tcb.
    pub fn cleanup(&mut self) {
        self.state = ThreadState::Inactive;
        self.blocked_reason = None;
        self.blocked_endpoint = core::ptr::null_mut();
        self.blocked_notification = core::ptr::null_mut();
        self.blocked_vspace_tracking = core::ptr::null_mut();
        self.vspace_wait_next = core::ptr::null_mut();

        // If we have a reply capability, wake the blocked caller
        // This handles the case where a server dies before replying
        if !self.reply_tcb.is_null() {
            unsafe {
                let caller = self.reply_tcb;
                // Wake the caller - it will receive an error or empty reply
                (*caller).state = ThreadState::Ready;
                (*caller).blocked_reason = None;
                crate::sched::scheduler::scheduler().enqueue(caller);
            }
        }
        self.reply_tcb = core::ptr::null_mut();
        self.reply_can_grant = false;
        self.fault_handler = core::ptr::null_mut();
        self.bound_notification = core::ptr::null_mut();
    }
}

impl SchedContext {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::SchedContext, 0),
            budget: 0,
            remaining: 0,
            period: 0,
            deadline: 0,
            bound_tcb: core::ptr::null_mut(),
            consumed: 0,
        }
    }

    /// Cleanup when scheduling context is destroyed
    pub fn cleanup(&mut self) {
        self.bound_tcb = core::ptr::null_mut();
    }
}
