// SPDX-License-Identifier: GPL-2.0-only
//! Shared syscall ABI types and message-info helpers.

#[repr(u64)]
pub enum Syscall {
    Invoke = 0,
}

impl TryFrom<u64> for Syscall {
    type Error = SyscallError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Syscall::Invoke),
            _ => Err(SyscallError::InvalidOperation),
        }
    }
}

pub mod msg_info {
    const LENGTH_BITS: u64 = 7;
    const LENGTH_MASK: u64 = (1 << LENGTH_BITS) - 1;
    const EXTRACAPS_SHIFT: u64 = 7;
    const EXTRACAPS_BITS: u64 = 5;
    const EXTRACAPS_MASK: u64 = ((1 << EXTRACAPS_BITS) - 1) << EXTRACAPS_SHIFT;
    const LABEL_SHIFT: u64 = 12;
    const LABEL_MASK: u64 = 0xFF_FFFF_FFFF;

    pub fn get_label(msg_info: u64) -> u64 {
        (msg_info >> LABEL_SHIFT) & LABEL_MASK
    }

    pub fn get_length(msg_info: u64) -> usize {
        (msg_info & LENGTH_MASK) as usize
    }

    pub fn get_extra_caps(msg_info: u64) -> usize {
        ((msg_info & EXTRACAPS_MASK) >> EXTRACAPS_SHIFT) as usize
    }

    pub fn make(label: u64, length: usize, extra_caps: usize) -> u64 {
        ((label & LABEL_MASK) << LABEL_SHIFT)
            | ((extra_caps as u64 & 0x1F) << EXTRACAPS_SHIFT)
            | (length as u64 & LENGTH_MASK)
    }
}

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

/// Syscall error codes — discriminants pinned to `KERNITE_ERR_*` from
/// the kernite UAPI so the kernel-internal enum and the wire-visible
/// error register share a single integer.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallError {
    None = 0,
    InvalidCapability = uapi::KERNITE_ERR_INVALID_CAPABILITY as u64,
    InvalidOperation = uapi::KERNITE_ERR_INVALID_OPERATION as u64,
    InsufficientRights = uapi::KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
    InvalidArgument = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64,
    OutOfMemory = uapi::KERNITE_ERR_OUT_OF_MEMORY as u64,
    NotFound = uapi::KERNITE_ERR_NOT_FOUND as u64,
    Busy = uapi::KERNITE_ERR_BUSY as u64,
    AlreadyExists = uapi::KERNITE_ERR_ALREADY_EXISTS as u64,
    WouldBlock = uapi::KERNITE_ERR_WOULD_BLOCK as u64,
    BadAddress = uapi::KERNITE_ERR_BAD_ADDRESS as u64,
    OutOfRange = uapi::KERNITE_ERR_OUT_OF_RANGE as u64,
    Cancelled = uapi::KERNITE_ERR_CANCELLED as u64,
    Restart = uapi::KERNITE_ERR_RESTART as u64,
    Deadlock = uapi::KERNITE_ERR_DEADLOCK as u64,
    Interrupted = uapi::KERNITE_ERR_INTERRUPTED as u64,
    TooLarge = uapi::KERNITE_ERR_TOO_LARGE as u64,
    NotSupported = uapi::KERNITE_ERR_NOT_SUPPORTED as u64,
    Readonly = uapi::KERNITE_ERR_READONLY as u64,
    SlotOccupied = uapi::KERNITE_ERR_SLOT_OCCUPIED as u64,
    AlreadyMapped = uapi::KERNITE_ERR_ALREADY_MAPPED as u64,
    PeerClosed = uapi::KERNITE_ERR_PEER_CLOSED as u64,
    QueueOverflow = uapi::KERNITE_ERR_QUEUE_OVERFLOW as u64,
    WatchCancelled = uapi::KERNITE_ERR_WATCH_CANCELLED as u64,
    AbiMismatch = uapi::KERNITE_ERR_ABI_MISMATCH as u64,
    IoError = uapi::KERNITE_ERR_IO_ERROR as u64,
    TimedOut = uapi::KERNITE_ERR_TIMED_OUT as u64,
    Pending = uapi::KERNITE_ERR_PENDING as u64,
    InsufficientResources = uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as u64,
}
