//! System Call Handler
//!
//! Capability invocation dispatch.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::{CapError, CapRights, Capability, CNode, FrameObject, ObjectType, UntypedMemory};
use crate::ipc::{Endpoint, EndpointState, Message, Notification};
use crate::mm::vspace::{PageFlags, VSpace, VSpaceError};
use crate::sched::thread::{SchedContext, Tcb, ThreadState};

/// System call numbers
#[repr(u64)]
pub enum Syscall {
    Send = 0,
    Recv = 1,
    Call = 2,
    ReplyRecv = 3,
    NBSend = 4,
    Signal = 5,
    Wait = 6,
    Poll = 7,
    Yield = 8,
    Invoke = 9,
}

impl TryFrom<u64> for Syscall {
    type Error = SyscallError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Syscall::Send),
            1 => Ok(Syscall::Recv),
            2 => Ok(Syscall::Call),
            3 => Ok(Syscall::ReplyRecv),
            4 => Ok(Syscall::NBSend),
            5 => Ok(Syscall::Signal),
            6 => Ok(Syscall::Wait),
            7 => Ok(Syscall::Poll),
            8 => Ok(Syscall::Yield),
            9 => Ok(Syscall::Invoke),
            _ => Err(SyscallError::InvalidOperation),
        }
    }
}

/// Message info word helpers
///
/// Format: [63:12 Reserved | 11:8 ExtraCaps | 7:4 CapsUnwr | 3:0 Length]
mod msg_info {
    const LENGTH_MASK: u64 = 0xF;
    const CAPS_UNWR_SHIFT: u64 = 4;
    const CAPS_UNWR_MASK: u64 = 0xF << CAPS_UNWR_SHIFT;
    const EXTRACAPS_SHIFT: u64 = 8;
    const EXTRACAPS_MASK: u64 = 0xF << EXTRACAPS_SHIFT;

    /// Extract message length (number of words)
    pub fn get_length(msg_info: u64) -> usize {
        ((msg_info & LENGTH_MASK) as usize).min(4) // Max 4 for now
    }

    /// Extract number of capabilities to unwrap
    pub fn get_caps_unwr(msg_info: u64) -> usize {
        ((msg_info & CAPS_UNWR_MASK) >> CAPS_UNWR_SHIFT) as usize
    }

    /// Extract number of extra capabilities
    pub fn get_extra_caps(msg_info: u64) -> usize {
        ((msg_info & EXTRACAPS_MASK) >> EXTRACAPS_SHIFT) as usize
    }

    /// Create message info word
    #[allow(dead_code)]
    pub fn make(length: u64, caps_unwr: u64, extra_caps: u64) -> u64 {
        length | (caps_unwr << 4) | (extra_caps << 8)
    }
}

/// System call result (FFI-safe)
///
/// Under System V AMD64 ABI:
/// - `error` is returned in %rax
/// - `value` is returned in %rdx
#[repr(C)]
pub struct SyscallResult {
    pub error: u64,
    pub value: u64,
}

impl SyscallResult {
    pub const fn ok(value: u64) -> Self {
        Self { error: 0, value }
    }

    pub const fn err(error: SyscallError) -> Self {
        Self {
            error: error as u64,
            value: 0,
        }
    }
}

/// System call errors
#[repr(u64)]
pub enum SyscallError {
    None = 0,
    InvalidCapability = 1,
    InvalidOperation = 2,
    InsufficientRights = 3,
    InvalidArgument = 4,
    OutOfMemory = 5,
    WouldBlock = 9,
}

/// Look up capability from current thread's CSpace
///
/// This is the primary capability lookup function used by all syscall handlers.
/// It retrieves a capability from the current thread's CNode (capability space).
///
/// # Arguments
/// * `cap_ptr` - Capability slot index in the thread's CSpace
///
/// # Returns
/// * `Ok(&Capability)` - Reference to the capability
/// * `Err(SyscallError::InvalidCapability)` - Slot is empty or CSpace is null
fn lookup_capability(cap_ptr: u64) -> Result<&'static Capability, SyscallError> {
    unsafe {
        // Get current thread's TCB
        let scheduler = crate::sched::scheduler::scheduler();
        let current_tcb = scheduler.current();

        if current_tcb.is_null() {
            return Err(SyscallError::InvalidOperation);
        }

        // Get thread's CSpace (CNode)
        let cspace = &*(*current_tcb).cspace;

        // Look up capability in CSpace
        // CNode::get() returns Option<&Capability>
        cspace.get(cap_ptr as usize).ok_or(SyscallError::InvalidCapability)
    }
}

/// Validate capability has required type and rights
///
/// Helper function to check that a capability meets the requirements
/// for a specific operation. Used by syscall handlers to validate
/// capabilities before performing operations.
///
/// # Arguments
/// * `cap` - Capability to validate
/// * `expected_type` - Required object type (ObjectType::Null matches any)
/// * `required_rights` - Required access rights
///
/// # Returns
/// * `Ok(())` - Capability is valid
/// * `Err(SyscallError::InvalidOperation)` - Wrong object type
/// * `Err(SyscallError::InsufficientRights)` - Missing required rights
fn validate_capability(
    cap: &Capability,
    expected_type: ObjectType,
    required_rights: CapRights,
) -> Result<(), SyscallError> {
    // Check if capability is null
    if cap.is_null() {
        return Err(SyscallError::InvalidCapability);
    }

    // Check object type (ObjectType::Null is a wildcard)
    if expected_type != ObjectType::Null && cap.obj_type != expected_type {
        return Err(SyscallError::InvalidOperation);
    }

    // Check capability has required rights
    if !cap.has_right(required_rights) {
        return Err(SyscallError::InsufficientRights);
    }

    Ok(())
}

/// Validate endpoint capability with required rights
///
/// Convenience wrapper for validate_capability specific to endpoints.
/// Checks that the capability is an Endpoint and has the specified rights.
///
/// # Arguments
/// * `cap` - Capability to validate
/// * `required_rights` - Required IPC rights (SEND, RECV, CALL, etc.)
///
/// # Returns
/// * `Ok(())` - Valid endpoint capability
/// * `Err(SyscallError::InvalidCapability)` - Null capability
/// * `Err(SyscallError::InvalidOperation)` - Not an endpoint
/// * `Err(SyscallError::InsufficientRights)` - Missing required rights
fn validate_endpoint_cap(
    cap: &Capability,
    required_rights: CapRights,
) -> Result<(), SyscallError> {
    validate_capability(cap, ObjectType::Endpoint, required_rights)
}

/// Validate notification capability with required rights
///
/// Convenience wrapper for validate_capability specific to notifications.
/// Checks that the capability is a Notification and has the specified rights.
///
/// # Arguments
/// * `cap` - Capability to validate
/// * `required_rights` - Required rights (READ, WRITE)
///
/// # Returns
/// * `Ok(())` - Valid notification capability
/// * `Err(SyscallError::InvalidCapability)` - Null capability
/// * `Err(SyscallError::InvalidOperation)` - Not a notification
/// * `Err(SyscallError::InsufficientRights)` - Missing required rights
fn validate_notification_cap(
    cap: &Capability,
    required_rights: CapRights,
) -> Result<(), SyscallError> {
    validate_capability(cap, ObjectType::Notification, required_rights)
}

/// Construct Message from syscall arguments
///
/// Arguments:
/// - msg_info: Message info word (length, caps counts)
/// - mr0-mr3: Message registers
fn construct_message(
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> Message {
    let length = msg_info::get_length(msg_info);
    let mut regs = [0u64; 4];

    // Copy registers based on length
    regs[0] = mr0;
    if length > 1 { regs[1] = mr1; }
    if length > 2 { regs[2] = mr2; }
    if length > 3 { regs[3] = mr3; }

    Message { label: msg_info, regs }
}

/// Send message to endpoint (blocks until receiver ready)
fn syscall_send(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(cap, CapRights::SEND) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    let msg = construct_message(msg_info, mr0, mr1, mr2, mr3);

    unsafe {
        let endpoint = &mut *(cap.object as *mut Endpoint);
        endpoint.send(&msg, cap.badge);
    }

    SyscallResult::ok(0)
}

/// Receive message from endpoint (blocks until sender ready)
fn syscall_recv(cap_ptr: u64) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(cap, CapRights::RECV) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    unsafe {
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let (_msg, badge) = endpoint.recv();
        SyscallResult::ok(badge)
    }
}

/// Call endpoint (send + wait for reply atomically)
fn syscall_call(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(cap, CapRights::CALL) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    let msg = construct_message(msg_info, mr0, mr1, mr2, mr3);

    unsafe {
        let endpoint = &mut *(cap.object as *mut Endpoint);
        endpoint.call(&msg, cap.badge);
    }

    SyscallResult::ok(0)
}

/// Reply to caller and receive next message (server pattern)
fn syscall_reply_recv(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(cap, CapRights::RECV) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    let reply = construct_message(msg_info, mr0, mr1, mr2, mr3);

    unsafe {
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let (_msg, badge) = endpoint.reply_recv(&reply);
        SyscallResult::ok(badge)
    }
}

/// Non-blocking send to endpoint
fn syscall_nbsend(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(cap, CapRights::SEND) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    let msg = construct_message(msg_info, mr0, mr1, mr2, 0);

    unsafe {
        let endpoint = &mut *(cap.object as *mut Endpoint);
        if endpoint.state() == EndpointState::RecvBlocked {
            endpoint.send(&msg, cap.badge);
            SyscallResult::ok(0)
        } else {
            SyscallResult::err(SyscallError::WouldBlock)
        }
    }
}

/// Signal a notification
fn syscall_signal(cap_ptr: u64, bits: u64) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_notification_cap(cap, CapRights::WRITE) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    unsafe {
        let notification = &mut *(cap.object as *mut Notification);
        notification.signal(bits);
    }

    SyscallResult::ok(0)
}

/// Wait on a notification
fn syscall_wait(cap_ptr: u64) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_notification_cap(cap, CapRights::READ) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    let bits = unsafe {
        let notification = &mut *(cap.object as *mut Notification);
        notification.wait()
    };

    SyscallResult::ok(bits)
}

/// Poll notification without blocking
fn syscall_poll(cap_ptr: u64) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_notification_cap(cap, CapRights::READ) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    unsafe {
        let notification = &mut *(cap.object as *mut Notification);
        match notification.poll() {
            Some(bits) => SyscallResult::ok(bits),
            None => SyscallResult::err(SyscallError::WouldBlock),
        }
    }
}

/// Invoke capability operation
fn syscall_invoke(
    cap_ptr: u64,
    label: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    _arg3: u64, // Reserved for future use
) -> SyscallResult {
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };

    match (cap.obj_type, label) {
        (ObjectType::CNode, 0x10) => {
            // CNode_Copy
            let dest_cnode = match lookup_capability(arg0) {
                Ok(c) => c,
                Err(e) => return SyscallResult::err(e),
            };
            let src_cnode = match lookup_capability(arg2) {
                Ok(c) => c,
                Err(e) => return SyscallResult::err(e),
            };
            let rights = CapRights::from_bits(arg1 as u32);

            unsafe {
                let dest = &mut *(dest_cnode.object as *mut CNode);
                let src = &*(src_cnode.object as *const CNode);
                match dest.copy_slot(arg0 as usize, src, arg2 as usize, rights) {
                    Ok(()) => {}
                    Err(e) => return SyscallResult::err(syscall_error_from_cap_error(e)),
                }
            }
            SyscallResult::ok(0)
        }
        (ObjectType::CNode, 0x14) => {
            // CNode_Delete
            unsafe {
                let cnode = &mut *(cap.object as *mut CNode);
                match cnode.delete(arg0 as usize) {
                    Ok(()) => {}
                    Err(e) => return SyscallResult::err(syscall_error_from_cap_error(e)),
                }
            }
            SyscallResult::ok(0)
        }
        (ObjectType::CNode, 0x15) => {
            // CNode_Revoke
            unsafe {
                let cnode = &mut *(cap.object as *mut CNode);
                match cnode.revoke(arg0 as usize) {
                    Ok(()) => {}
                    Err(e) => return SyscallResult::err(syscall_error_from_cap_error(e)),
                }
            }
            SyscallResult::ok(0)
        }
        // Untyped operations
        (ObjectType::Untyped, 0x20) => {
            // UNTYPED_RETYPE: arg0 = new_type, arg1 = size_bits, arg2 = dest_offset
            syscall_untyped_retype(cap, cap_ptr, arg0, arg1, arg2)
        }

        // TCB operations
        (ObjectType::Tcb, 0x40) => {
            // TCB_CONFIGURE: arg0 = entry_rip, arg1 = entry_rsp, arg2 = ipc_buffer_addr
            syscall_tcb_configure(cap, arg0, arg1, arg2)
        }
        (ObjectType::Tcb, 0x41) => {
            // TCB_RESUME
            syscall_tcb_resume(cap)
        }
        (ObjectType::Tcb, 0x42) => {
            // TCB_SUSPEND
            syscall_tcb_suspend(cap)
        }
        (ObjectType::Tcb, 0x43) => {
            // TCB_SET_SPACE: arg0 = cspace_cap_ptr, arg1 = vspace_cap_ptr
            syscall_tcb_set_space(cap, arg0, arg1)
        }
        (ObjectType::Tcb, 0x44) => {
            // TCB_SET_AFFINITY: arg0 = cpu_id
            syscall_tcb_set_affinity(cap, arg0)
        }

        // VSpace operations
        (ObjectType::VSpace, 0x50) => {
            // VSPACE_MAP: arg0 = frame_cap_ptr, arg1 = virt_addr, arg2 = flags_bits
            syscall_vspace_map(cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x51) => {
            // VSPACE_UNMAP: arg0 = virt_addr
            syscall_vspace_unmap(cap, arg0)
        }

        // SchedContext operations
        (ObjectType::SchedContext, 0x30) => {
            // SC_CONFIGURE: arg0 = budget (microseconds), arg1 = period (microseconds)
            syscall_sc_configure(cap, arg0, arg1)
        }
        (ObjectType::SchedContext, 0x31) => {
            // SC_BIND: arg0 = tcb_cap_ptr
            syscall_sc_bind(cap, arg0)
        }
        (ObjectType::SchedContext, 0x32) => {
            // SC_UNBIND
            syscall_sc_unbind(cap)
        }
        (ObjectType::SchedContext, 0x33) => {
            // SC_YIELD_TO: arg0 = target_sc_cap_ptr
            syscall_sc_yield_to(cap, arg0)
        }

        _ => SyscallResult::err(SyscallError::InvalidOperation),
    }
}

/// SC_CONFIGURE: Configure scheduling context parameters
///
/// Args:
/// - budget_us: Budget per period in microseconds (must be > 0)
/// - period_us: Period in microseconds (0 = sporadic, otherwise >= budget)
fn syscall_sc_configure(cap: &Capability, budget_us: u64, period_us: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    if budget_us == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // For periodic tasks, period must be >= budget
    if period_us != 0 && period_us < budget_us {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Convert microseconds to ticks (1 tick = 1ms = 1000us)
    let budget_ticks = budget_us / 1000;
    let period_ticks = period_us / 1000;

    if budget_ticks == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let sc = &mut *(cap.object as *mut SchedContext);
        sc.budget = budget_ticks;
        sc.period = period_ticks;
        sc.remaining = budget_ticks;

        if period_ticks > 0 {
            // Periodic: deadline = now + period
            let now = crate::arch::get_ticks() as u64;
            sc.deadline = now + period_ticks;
        } else {
            // Sporadic: infinite deadline (lowest priority in EDF)
            sc.deadline = u64::MAX;
        }
    }

    SyscallResult::ok(0)
}

/// SC_BIND: Bind a scheduling context to a TCB
///
/// Args:
/// - tcb_cap_ptr: Capability pointer to the target TCB
fn syscall_sc_bind(cap: &Capability, tcb_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Look up and validate the TCB capability
    let tcb_cap = match lookup_capability(tcb_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(tcb_cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let sc = &mut *(cap.object as *mut SchedContext);
        let tcb = &mut *(tcb_cap.object as *mut Tcb);

        // Check SC is not already bound
        if !sc.bound_tcb.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        // Check TCB does not already have a scheduling context
        if !tcb.sched_context.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        // Bind SC to TCB
        sc.bound_tcb = tcb as *mut Tcb;
        tcb.sched_context = sc as *mut SchedContext;
        tcb.priority = sc.deadline;

        // If TCB is Ready, re-enqueue with updated priority
        if tcb.state == ThreadState::Ready {
            // Remove and re-insert to maintain deadline ordering
            crate::sched::scheduler::scheduler().enqueue(tcb as *mut Tcb);
        }
    }

    SyscallResult::ok(0)
}

/// SC_UNBIND: Unbind a scheduling context from its TCB
fn syscall_sc_unbind(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let sc = &mut *(cap.object as *mut SchedContext);

        // Check SC is bound
        if sc.bound_tcb.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let tcb = &mut *sc.bound_tcb;

        // Cannot unbind from a Running or Ready thread
        if tcb.state == ThreadState::Running || tcb.state == ThreadState::Ready {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        // Clear the binding
        tcb.sched_context = core::ptr::null_mut();
        sc.bound_tcb = core::ptr::null_mut();
    }

    SyscallResult::ok(0)
}

/// SC_YIELD_TO: Transfer remaining budget to target scheduling context
///
/// Args:
/// - target_sc_cap_ptr: Capability pointer to the target SchedContext
fn syscall_sc_yield_to(cap: &Capability, target_sc_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Look up and validate the target SC capability
    let target_cap = match lookup_capability(target_sc_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(target_cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let current_sc = &mut *(cap.object as *mut SchedContext);
        let target_sc = &mut *(target_cap.object as *mut SchedContext);

        // Transfer remaining budget to target
        target_sc.remaining += current_sc.remaining;
        current_sc.remaining = 0;

        // Block the current thread and reschedule
        let scheduler = crate::sched::scheduler::scheduler();
        let current_tcb = scheduler.current();
        if !current_tcb.is_null() {
            (*current_tcb).state = ThreadState::Blocked;
            scheduler.reschedule();
        }
    }

    SyscallResult::ok(0)
}

/// TCB_CONFIGURE: Set thread entry point, stack, and IPC buffer
///
/// Args:
/// - entry_rip: Entry instruction pointer
/// - entry_rsp: Entry stack pointer
/// - ipc_buffer: IPC buffer virtual address
fn syscall_tcb_configure(
    cap: &Capability,
    entry_rip: u64,
    entry_rsp: u64,
    ipc_buffer: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.context.rip = entry_rip;
        tcb.context.rsp = entry_rsp;
        tcb.context.rflags = 0x202; // IF=1
        tcb.context.cs = 0x1B; // User code segment (selector 0x18 | RPL 3)
        tcb.context.ss = 0x23; // User data segment (selector 0x20 | RPL 3)
        tcb.ipc_buffer = ipc_buffer;
    }

    SyscallResult::ok(0)
}

/// TCB_RESUME: Make a thread runnable
fn syscall_tcb_resume(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::RESUME) {
        return SyscallResult::err(e);
    }

    unsafe {
        let tcb = &mut *(cap.object as *mut Tcb);
        match tcb.state {
            ThreadState::Running | ThreadState::Ready => {
                // Already runnable, no-op
            }
            ThreadState::Inactive | ThreadState::Blocked => {
                let scheduler = crate::sched::scheduler::scheduler();
                scheduler.enqueue(tcb as *mut Tcb);
            }
            ThreadState::Waiting => {
                let scheduler = crate::sched::scheduler::scheduler();
                scheduler.enqueue(tcb as *mut Tcb);
            }
        }
    }

    SyscallResult::ok(0)
}

/// TCB_SUSPEND: Stop a thread
fn syscall_tcb_suspend(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::SUSPEND) {
        return SyscallResult::err(e);
    }

    unsafe {
        let tcb = &mut *(cap.object as *mut Tcb);
        let scheduler = crate::sched::scheduler::scheduler();

        match tcb.state {
            ThreadState::Running => {
                tcb.state = ThreadState::Inactive;
                scheduler.reschedule();
            }
            ThreadState::Ready => {
                scheduler.remove_from_ready_queue(tcb as *mut Tcb);
                tcb.state = ThreadState::Inactive;
            }
            ThreadState::Blocked => {
                tcb.state = ThreadState::Inactive;
                tcb.blocked_reason = None;
            }
            ThreadState::Waiting => {
                tcb.state = ThreadState::Inactive;
            }
            ThreadState::Inactive => {
                // Already inactive, no-op
            }
        }
    }

    SyscallResult::ok(0)
}

/// TCB_SET_SPACE: Set thread's CSpace and VSpace
///
/// Args:
/// - cspace_cap_ptr: Capability pointer to a CNode
/// - vspace_cap_ptr: Capability pointer to a VSpace
fn syscall_tcb_set_space(
    cap: &Capability,
    cspace_cap_ptr: u64,
    vspace_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Look up and validate CSpace capability
    let cspace_cap = match lookup_capability(cspace_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(cspace_cap, ObjectType::CNode, CapRights::READ) {
        return SyscallResult::err(e);
    }

    // Look up and validate VSpace capability
    let vspace_cap = match lookup_capability(vspace_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(vspace_cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.cspace = cspace_cap.object as *mut CNode;
        tcb.vspace = vspace_cap.object as *mut VSpace;
    }

    SyscallResult::ok(0)
}

/// TCB_SET_AFFINITY: Set CPU affinity for a thread
///
/// Args:
/// - cpu_id: Target CPU ID (0xFFFF_FFFF = any CPU)
fn syscall_tcb_set_affinity(cap: &Capability, cpu_id: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let affinity = cpu_id as u32;
    if affinity != 0xFFFF_FFFF && (affinity as usize) >= crate::arch::MAX_CPUS {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.cpu_affinity = affinity;
    }

    SyscallResult::ok(0)
}

/// UNTYPED_RETYPE: Create typed kernel objects from untyped memory
///
/// Args:
/// - new_type_raw: ObjectType as u64 (must be 1..=10, not 0/Null)
/// - size_bits: Size in bits (for variable-size objects)
/// - dest_offset: Destination offset in current thread's CSpace
fn syscall_untyped_retype(
    cap: &Capability,
    cap_ptr: u64,
    new_type_raw: u64,
    size_bits: u64,
    dest_offset: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Untyped, CapRights::RETYPE) {
        return SyscallResult::err(e);
    }

    // Validate object type (1..=10, not 0/Null)
    let new_type = match new_type_raw {
        1 => ObjectType::Untyped,
        2 => ObjectType::Endpoint,
        3 => ObjectType::Notification,
        4 => ObjectType::Tcb,
        5 => ObjectType::CNode,
        6 => ObjectType::VSpace,
        7 => ObjectType::Frame,
        8 => ObjectType::IrqHandler,
        9 => ObjectType::IoPort,
        10 => ObjectType::SchedContext,
        _ => return SyscallResult::err(SyscallError::InvalidArgument),
    };

    unsafe {
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let cspace = &mut *(*current_tcb).cspace;

        // Get the untyped's CapSlot for CDT tracking
        let cap_ref = match cspace.get_ref(cap_ptr as usize) {
            Some(r) => r,
            None => return SyscallResult::err(SyscallError::InvalidCapability),
        };
        let untyped_slot = cap_ref.slot;

        let untyped = &mut *(cap.object as *mut UntypedMemory);
        match untyped.retype(
            untyped_slot,
            new_type,
            size_bits as u8,
            1,
            cspace,
            dest_offset as usize,
        ) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
        }
    }
}

/// VSPACE_MAP: Map a physical frame into a virtual address space
///
/// Args:
/// - frame_cap_ptr: Capability pointer to the frame
/// - virt_addr: Virtual address to map at
/// - flags_bits: Mapping flags (bit 0=writable, bit 1=user, bit 2=executable)
fn syscall_vspace_map(
    cap: &Capability,
    frame_cap_ptr: u64,
    virt_addr: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    // Look up and validate frame capability
    let frame_cap = match lookup_capability(frame_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(frame_cap, ObjectType::Frame, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let frame = &*(frame_cap.object as *const FrameObject);
        let vspace = &mut *(cap.object as *mut VSpace);

        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
        };

        match vspace.map(virt_addr, frame.phys_addr, flags) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_UNMAP: Unmap a page from a virtual address space
///
/// Args:
/// - virt_addr: Virtual address to unmap
fn syscall_vspace_unmap(cap: &Capability, virt_addr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::UNMAP) {
        return SyscallResult::err(e);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        match vspace.unmap(virt_addr) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// Convert VSpaceError to syscall error
fn syscall_error_from_vspace_error(err: VSpaceError) -> SyscallError {
    match err {
        VSpaceError::Alignment => SyscallError::InvalidArgument,
        VSpaceError::AlreadyMapped => SyscallError::InvalidArgument,
        VSpaceError::NotMapped => SyscallError::InvalidArgument,
        VSpaceError::OutOfMemory => SyscallError::OutOfMemory,
    }
}

/// Convert CNode error to syscall error
fn syscall_error_from_cap_error(err: CapError) -> SyscallError {
    match err {
        CapError::InvalidSlot | CapError::SlotEmpty => SyscallError::InvalidArgument,
        CapError::InsufficientRights => SyscallError::InsufficientRights,
        CapError::InsufficientMemory | CapError::OutOfSlots => SyscallError::OutOfMemory,
        CapError::SlotOccupied => SyscallError::InvalidArgument,
        CapError::HasChildren => SyscallError::InvalidOperation,
        _ => SyscallError::InvalidOperation,
    }
}

/// Handle system call logic
pub fn handle(
    syscall: u64,
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
) -> SyscallResult {
    let syscall_num = match Syscall::try_from(syscall) {
        Ok(s) => s,
        Err(e) => return SyscallResult::err(e),
    };

    match syscall_num {
        Syscall::Send => syscall_send(cap_ptr, msg_info, mr0, mr1, mr2, 0),
        Syscall::Recv => syscall_recv(cap_ptr),
        Syscall::Call => syscall_call(cap_ptr, msg_info, mr0, mr1, mr2, 0),
        Syscall::ReplyRecv => syscall_reply_recv(cap_ptr, msg_info, mr0, mr1, mr2, 0),
        Syscall::NBSend => syscall_nbsend(cap_ptr, msg_info, mr0, mr1, mr2),
        Syscall::Signal => syscall_signal(cap_ptr, mr0),
        Syscall::Wait => syscall_wait(cap_ptr),
        Syscall::Poll => syscall_poll(cap_ptr),
        Syscall::Yield => {
            crate::sched::yield_now();
            SyscallResult::ok(0)
        }
        Syscall::Invoke => syscall_invoke(cap_ptr, msg_info, mr0, mr1, mr2, 0),
    }
}

/// Syscall handler wrapper called from assembly
///
/// # ABI Note
/// Returns struct { u64, u64 }.
/// - Rust/C ABI places the first u64 in **RAX**.
/// - Rust/C ABI places the second u64 in **RDX**.
///
/// The assembly entry point MUST read the value from RDX, not RBX.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_handle_rust(
    syscall: u64, // RDI
    cap_ptr: u64, // RSI
    arg0: u64,    // RDX
    arg1: u64,    // RCX
    arg2: u64,    // R8
    arg3: u64,    // R9
) -> SyscallResult {
    handle(syscall, cap_ptr, arg0, arg1, arg2, arg3)
}