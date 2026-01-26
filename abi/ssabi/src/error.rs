//! SSABI error codes

#![no_std]

use core::fmt;

/// Kernel error codes
///
/// These are returned as negative i64 values from syscalls.
/// Success is represented as 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum KernelError {
    // ===== Success =====
    Success = 0,

    // ===== General errors =====
    /// Invalid argument passed to syscall
    InvalidArgument = -1,
    /// Resource not found
    NotFound = -2,
    /// Permission denied
    PermissionDenied = -3,
    /// Resource already exists
    AlreadyExists = -4,

    // ===== Memory errors =====
    /// Out of memory
    OutOfMemory = -10,
    /// Invalid address
    InvalidAddress = -11,
    /// Access violation (page fault, etc.)
    AccessViolation = -12,

    // ===== Capability errors =====
    /// Invalid capability
    InvalidCapability = -20,
    /// Insufficient rights for operation
    InsufficientRights = -21,

    // ===== IPC errors =====
    /// Operation would block
    WouldBlock = -30,
    /// Operation interrupted
    Interrupted = -31,

    // ===== Thread errors =====
    /// Invalid thread ID
    InvalidThread = -40,
    /// Thread has exited
    ThreadExited = -41,

    // ===== Unsupported =====
    /// Operation not supported
    Unsupported = -100,
}

impl KernelError {
    /// Convert from i64 (as returned from syscall)
    pub const fn from_i64(val: i64) -> Option<Self> {
        match val {
            0 => Some(Self::Success),
            -1 => Some(Self::InvalidArgument),
            -2 => Some(Self::NotFound),
            -3 => Some(Self::PermissionDenied),
            -4 => Some(Self::AlreadyExists),
            -10 => Some(Self::OutOfMemory),
            -11 => Some(Self::InvalidAddress),
            -12 => Some(Self::AccessViolation),
            -20 => Some(Self::InvalidCapability),
            -21 => Some(Self::InsufficientRights),
            -30 => Some(Self::WouldBlock),
            -31 => Some(Self::Interrupted),
            -40 => Some(Self::InvalidThread),
            -41 => Some(Self::ThreadExited),
            -100 => Some(Self::Unsupported),
            _ => None,
        }
    }

    /// Convert to i64 (for syscall return)
    pub const fn as_i64(self) -> i64 {
        self as i64
    }

    /// Check if this represents success
    pub const fn is_success(self) -> bool {
        self as i64 == 0
    }

    /// Check if this represents an error
    pub const fn is_error(self) -> bool {
        (self as i64) < 0
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::InvalidArgument => write!(f, "Invalid argument"),
            Self::NotFound => write!(f, "Not found"),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::AlreadyExists => write!(f, "Already exists"),
            Self::OutOfMemory => write!(f, "Out of memory"),
            Self::InvalidAddress => write!(f, "Invalid address"),
            Self::AccessViolation => write!(f, "Access violation"),
            Self::InvalidCapability => write!(f, "Invalid capability"),
            Self::InsufficientRights => write!(f, "Insufficient rights"),
            Self::WouldBlock => write!(f, "Would block"),
            Self::Interrupted => write!(f, "Interrupted"),
            Self::InvalidThread => write!(f, "Invalid thread"),
            Self::ThreadExited => write!(f, "Thread exited"),
            Self::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// Result type for SSABI operations
pub type Result<T> = core::result::Result<T, KernelError>;
