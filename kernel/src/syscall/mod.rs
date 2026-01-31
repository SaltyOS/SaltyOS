//! System Call Handler
//!
//! Capability invocation dispatch.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::{CapError, CapRights, Capability, CNode, ObjectType};
use crate::ipc::{Endpoint, EndpointState, Message, Notification};

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
    _arg3: u64,
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
        _ => SyscallResult::err(SyscallError::InvalidOperation),
    }
}

/// Convert CNode error to syscall error
fn syscall_error_from_cap_error(err: CapError) -> SyscallError {
    match err {
        CapError::InvalidSlot | CapError::SlotEmpty => SyscallError::InvalidArgument,
        CapError::InsufficientRights => SyscallError::InsufficientRights,
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