//! SSABI syscall handler
//!
//! This is the main syscall entry point called from assembly trampoline.

#![no_std]

use saltyos_ssabi::{
    numbers::*,
    KernelError,
};

/// Syscall handler entry point
///
/// This function is called from the assembly syscall entry point.
/// Arguments are passed according to System V AMD64 ABI:
/// - rdi: syscall number
/// - rsi, rdx, rcx, r8, r9: arguments (a1-a5)
///
/// Return value in rax: i64 (0 = success, negative = error code)
#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn syscall_handler(
    num: u64,
    _a1: u64,
    _a2: u64,
    _a3: u64,
    _a4: u64,
    _a5: u64,
) -> i64 {
    match num {
        // Debug syscall - print a character
        // a1 = character to print
        SYS_DEBUG_PRINT => {
            if let Some(c) = core::char::from_u32(_a1 as u32) {
                crate::print_char(c as u8);
            }
            0 // Success
        }

        // Thread management syscalls
        SYS_THREAD_CREATE => KernelError::Unsupported as i64,
        SYS_THREAD_BLOCK => KernelError::Unsupported as i64,
        SYS_THREAD_UNBLOCK => KernelError::Unsupported as i64,
        SYS_THREAD_EXIT => KernelError::Unsupported as i64,

        // Virtual memory syscalls
        SYS_VM_MAP => KernelError::Unsupported as i64,
        SYS_VM_UNMAP => KernelError::Unsupported as i64,
        SYS_PAGER_REGISTER => KernelError::Unsupported as i64,

        // Address space syscalls
        SYS_ADDRESS_SPACE_CREATE => KernelError::Unsupported as i64,
        SYS_ADDRESS_SPACE_SWITCH => KernelError::Unsupported as i64,

        // Capability syscalls
        SYS_CAP_DUP => KernelError::Unsupported as i64,
        SYS_CAP_REVOKE => KernelError::Unsupported as i64,
        SYS_CAP_TYPE => KernelError::Unsupported as i64,
        SYS_CAP_INFO => KernelError::Unsupported as i64,

        // IPC syscalls
        SYS_IPC_SEND => KernelError::Unsupported as i64,
        SYS_IPC_RECV => KernelError::Unsupported as i64,
        SYS_IPC_CALL => KernelError::Unsupported as i64,

        // Unknown syscall
        _ => KernelError::NotFound as i64,
    }
}

/// Initialize syscall handling
pub fn init() {
    // The syscall instruction is already available
    // We just need to make sure the syscall entry point is linked
}
