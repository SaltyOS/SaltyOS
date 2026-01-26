//! SSABI syscall numbers

#![no_std]

/// Thread management syscalls
pub const SYS_THREAD_CREATE: u64 = 0x01;
pub const SYS_THREAD_BLOCK: u64 = 0x02;
pub const SYS_THREAD_UNBLOCK: u64 = 0x03;
pub const SYS_THREAD_EXIT: u64 = 0x04;

/// Virtual memory syscalls
pub const SYS_VM_MAP: u64 = 0x10;
pub const SYS_VM_UNMAP: u64 = 0x11;
pub const SYS_PAGER_REGISTER: u64 = 0x12;

/// Address space syscalls
pub const SYS_ADDRESS_SPACE_CREATE: u64 = 0x20;
pub const SYS_ADDRESS_SPACE_SWITCH: u64 = 0x21;

/// Capability syscalls
pub const SYS_CAP_DUP: u64 = 0x30;
pub const SYS_CAP_REVOKE: u64 = 0x31;
pub const SYS_CAP_TYPE: u64 = 0x32;
pub const SYS_CAP_INFO: u64 = 0x33;

/// IPC syscalls
pub const SYS_IPC_SEND: u64 = 0x40;
pub const SYS_IPC_RECV: u64 = 0x41;
pub const SYS_IPC_CALL: u64 = 0x42;

/// Debug syscall (for testing)
pub const SYS_DEBUG_PRINT: u64 = 0xFF;
