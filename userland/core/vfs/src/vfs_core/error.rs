// SPDX-License-Identifier: GPL-2.0-only
//! VFS core error type and TRONA_* mapping.
//!
//! Personality-neutral error codes returned by VopVector operations and
//! internal VFS helpers. Each personality layer (`personality/posix/errno.rs`,
//! `personality/win32/errno.rs`) converts these into the error code shape
//! expected by its callers (POSIX errno, Win32 NTSTATUS/ERROR_*).
//!
//! The mapping to `TRONA_*` wire labels lives in `ipc/reply.rs`. VFS op
//! functions themselves never touch `TronaMsg` — they return `Result<_, VfsError>`
//! and the IPC boundary layer performs the conversion.

use trona::consts::kernel::*;

/// VFS core error code — personality-neutral.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VfsError {
    /// Path component or object not found.
    NotFound = 1,
    /// Expected a directory, got a non-directory.
    NotDir = 2,
    /// Expected a non-directory, got a directory.
    IsDir = 3,
    /// Symbolic link loop exceeded depth limit.
    Loop = 4,
    /// Backend I/O failure (IPC, device, etc.).
    Io = 5,
    /// Operation not supported by this filesystem.
    NotSupported = 6,
    /// Permission denied (credential check failed).
    Perm = 7,
    /// Out of space (storage, inode pool, etc.).
    NoSpace = 8,
    /// Path component already exists (O_CREAT | O_EXCL).
    Exists = 9,
    /// Name or path too long.
    NameTooLong = 10,
    /// Invalid argument (malformed path, bad flags, etc.).
    Inval = 11,
    /// Resource busy (mount has live references, etc.).
    Busy = 12,
    /// Directory entry references a stale inode.
    NoEntry = 13,
    /// Open would violate an existing share-mode restriction.
    SharingViolation = 14,
    /// Vnode has delete-pending flag; new opens rejected.
    DeletePending = 15,
    /// Mount is read-only and this op would mutate.
    ReadOnly = 16,
    /// Value too large (e.g. xattr inline limit exceeded).
    TooLarge = 17,
    /// Bad handle (FD, vnode reference, etc.).
    BadHandle = 18,
    /// Operation would block — used by saltyfs cache-miss to signal the
    /// dispatch layer to defer to a worker thread.
    WouldBlock = 19,
}

impl VfsError {
    /// Convert to a TRONA_* error code for IPC reply.
    #[inline]
    pub(crate) fn to_trona(self) -> u64 {
        match self {
            VfsError::NotFound => TRONA_NOT_FOUND,
            VfsError::NotDir => TRONA_NOT_DIRECTORY,
            VfsError::IsDir => TRONA_IS_DIRECTORY,
            VfsError::Loop => TRONA_LOOP,
            VfsError::Io => TRONA_IO_ERROR,
            VfsError::NotSupported => TRONA_NOT_SUPPORTED,
            VfsError::Perm => TRONA_INSUFFICIENT_RIGHTS,
            VfsError::NoSpace => TRONA_OUT_OF_MEMORY,
            VfsError::Exists => TRONA_ALREADY_EXISTS,
            VfsError::NameTooLong => TRONA_INVALID_ARGUMENT,
            VfsError::Inval => TRONA_INVALID_ARGUMENT,
            VfsError::Busy => TRONA_BUSY,
            VfsError::NoEntry => TRONA_NOT_FOUND,
            VfsError::SharingViolation => TRONA_BUSY,
            VfsError::DeletePending => TRONA_NOT_FOUND,
            VfsError::ReadOnly => TRONA_READONLY,
            VfsError::TooLarge => TRONA_TOO_LARGE,
            VfsError::BadHandle => TRONA_INVALID_ARGUMENT,
            VfsError::WouldBlock => TRONA_BUSY,
        }
    }
}

/// Convenience alias for Results returned by VopVector operations.
pub(crate) type VfsResult<T> = core::result::Result<T, VfsError>;
