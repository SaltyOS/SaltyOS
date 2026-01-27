//! System Call Handler
//!
//! Capability invocation dispatch.
//!
//! SPDX-License-Identifier: GPL-2.0-only

// Will be used when syscalls are implemented
#[allow(unused_imports)]
use crate::cap::{Capability, ObjectType, Rights};

/// System call numbers
#[repr(u64)]
pub enum Syscall {
    /// Send message to endpoint
    Send = 0,
    /// Receive message from endpoint
    Recv = 1,
    /// Call (send + recv)
    Call = 2,
    /// Reply and receive
    ReplyRecv = 3,
    /// Signal notification
    Signal = 4,
    /// Wait on notification
    Wait = 5,
    /// Yield to scheduler
    Yield = 6,
    /// Invoke capability
    Invoke = 7,
}

/// System call result
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

/// Handle system call
pub fn handle(
    syscall: u64,
    _cap_ptr: u64,
    _arg0: u64,
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
) -> SyscallResult {
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
