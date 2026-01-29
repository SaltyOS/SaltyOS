//! System Call Handler
//!
//! Capability invocation dispatch.
//!
//! SPDX-License-Identifier: GPL-2.0-only

#[allow(unused_imports)]
use crate::cap::{CapRights, Capability, ObjectType};

/// System call numbers
#[repr(u64)]
pub enum Syscall {
    Send = 0,
    Recv = 1,
    Call = 2,
    ReplyRecv = 3,
    Signal = 4,
    Wait = 5,
    Yield = 6,
    Invoke = 7,
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
}

/// Handle system call logic
pub fn handle(
    syscall: u64,
    _cap_ptr: u64,
    _arg0: u64,
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
) -> SyscallResult {
    // Convert raw u64 to Enum safely
    let syscall_num = match syscall {
        0 => Syscall::Send,
        1 => Syscall::Recv,
        2 => Syscall::Call,
        3 => Syscall::ReplyRecv,
        4 => Syscall::Signal,
        5 => Syscall::Wait,
        6 => Syscall::Yield,
        7 => Syscall::Invoke,
        _ => return SyscallResult::err(SyscallError::InvalidOperation),
    };

    match syscall_num {
        Syscall::Yield => {
            crate::sched::yield_now();
            SyscallResult::ok(0)
        }
        _ => {
            // TODO: Implement other syscalls
            SyscallResult::err(SyscallError::InvalidOperation)
        }
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