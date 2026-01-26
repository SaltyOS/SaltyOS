//! SaltySys ABI (SSABI) - Minimal kernel primitives
//!
//! SSABI provides only machine-level primitives that depend on
//! architecture/trap mechanism.
//!
//! This includes:
//! - Thread management (create, block, unblock, exit)
//! - Virtual memory (map, unmap, pager registration)
//! - Address space management (create, switch)
//! - Capability operations (dup, revoke, type, info)
//! - IPC (send, recv, call)
//!
//! SSABI does NOT provide:
//! - POSIX syscalls (fork, exec, wait, open, read, write) - those are in userspace via SSIP
//! - File operations - handled by filesystem server via SSIP
//! - Signal handling - userspace emulation
//! - ioctl - device-specific SSIP protocols

#![no_std]

pub mod numbers;
pub mod types;
pub mod error;

pub use numbers::*;
pub use types::*;
pub use error::*;

/// SSABI version
pub const SSABI_VERSION: u32 = 0x0001;
