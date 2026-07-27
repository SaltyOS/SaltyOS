// SPDX-License-Identifier: GPL-2.0-only
//
//! Win32 NT wire constants — `ACCESS_MASK` bits, `FILE_*` create
//! disposition / share / attribute flags, and `STATUS_*` NTSTATUS
//! values that vfs's Win32 entry point projects onto the
//! personality-neutral vnode operations.
//!
//! Personality-neutral code never imports from this module — it
//! is only loaded by the Win32 wire surface in
//! `personality::win32::dispatch`.
#![allow(dead_code)]

// =========================================================================
// ACCESS_MASK — desired access bits
// =========================================================================

pub(crate) const GENERIC_READ: u32 = 0x8000_0000;
pub(crate) const GENERIC_WRITE: u32 = 0x4000_0000;
pub(crate) const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub(crate) const GENERIC_ALL: u32 = 0x1000_0000;

pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;
pub(crate) const DELETE: u32 = 0x0001_0000;
pub(crate) const READ_CONTROL: u32 = 0x0002_0000;
pub(crate) const WRITE_DAC: u32 = 0x0004_0000;
pub(crate) const WRITE_OWNER: u32 = 0x0008_0000;

pub(crate) const FILE_READ_DATA: u32 = 0x0001;
pub(crate) const FILE_WRITE_DATA: u32 = 0x0002;
pub(crate) const FILE_APPEND_DATA: u32 = 0x0004;
pub(crate) const FILE_READ_EA: u32 = 0x0008;
pub(crate) const FILE_WRITE_EA: u32 = 0x0010;
pub(crate) const FILE_EXECUTE: u32 = 0x0020;
pub(crate) const FILE_DELETE_CHILD: u32 = 0x0040;
pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub(crate) const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;

// =========================================================================
// FILE_SHARE_* — share-mode bits
// =========================================================================

pub(crate) const FILE_SHARE_READ: u32 = 0x0000_0001;
pub(crate) const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub(crate) const FILE_SHARE_DELETE: u32 = 0x0000_0004;

// =========================================================================
// CreateDisposition — what to do if the target exists
// =========================================================================

pub(crate) const FILE_SUPERSEDE: u32 = 0;
pub(crate) const FILE_OPEN: u32 = 1;
pub(crate) const FILE_CREATE: u32 = 2;
pub(crate) const FILE_OPEN_IF: u32 = 3;
pub(crate) const FILE_OVERWRITE: u32 = 4;
pub(crate) const FILE_OVERWRITE_IF: u32 = 5;

// =========================================================================
// CreateOptions — flags passed to NtCreateFile
// =========================================================================

pub(crate) const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub(crate) const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
pub(crate) const FILE_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
pub(crate) const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
pub(crate) const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
pub(crate) const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
pub(crate) const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub(crate) const FILE_RANDOM_ACCESS: u32 = 0x0000_0800;
pub(crate) const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
pub(crate) const FILE_OPEN_BY_FILE_ID: u32 = 0x0000_2000;
pub(crate) const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
pub(crate) const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

// =========================================================================
// FILE_ATTRIBUTE_* — file metadata bits returned in NtQueryInformationFile
// =========================================================================

pub(crate) const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub(crate) const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub(crate) const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub(crate) const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub(crate) const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub(crate) const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub(crate) const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
pub(crate) const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

// =========================================================================
// HANDLE_FLAG_* — handle inheritance / protection bits
// =========================================================================

/// Win32 equivalent of POSIX `FD_CLOEXEC`. When set on a handle,
/// the handle is *not* inherited by child processes spawned via
/// CreateProcess. Stored in the slot table's `slot_flags` byte at
/// the same bit position as `POSIX_FD_CLOEXEC` so the underlying
/// raw-byte API stays personality-neutral.
pub(crate) const WIN32_HANDLE_FLAG_INHERIT: u8 = 0x01;

/// Protect the handle from closure via `CloseHandle`. Caller must
/// reset before close. Tracked separately from inherit because the
/// semantics differ — CLOEXEC on POSIX is purely about exec
/// inheritance, not about close protection.
pub(crate) const WIN32_HANDLE_FLAG_PROTECT_FROM_CLOSE: u8 = 0x02;

// =========================================================================
// STATUS_* — NTSTATUS values vfs's Win32 entry returns
// =========================================================================

pub(crate) const STATUS_SUCCESS: u32 = 0x0000_0000;
pub(crate) const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub(crate) const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub(crate) const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub(crate) const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
pub(crate) const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub(crate) const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
pub(crate) const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub(crate) const STATUS_DISK_FULL: u32 = 0xC000_007F;
pub(crate) const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub(crate) const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub(crate) const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
pub(crate) const STATUS_END_OF_FILE: u32 = 0xC000_0011;
pub(crate) const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
pub(crate) const STATUS_IO_DEVICE_ERROR: u32 = 0xC000_0185;
pub(crate) const STATUS_TOO_MANY_OPENED_FILES: u32 = 0xC000_011F;
pub(crate) const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_023F;
pub(crate) const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub(crate) const STATUS_RETRY: u32 = 0xC000_022D;
pub(crate) const STATUS_CANCELLED: u32 = 0xC000_0120;
pub(crate) const STATUS_PIPE_BROKEN: u32 = 0xC000_014B;
pub(crate) const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub(crate) const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
pub(crate) const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
pub(crate) const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
pub(crate) const STATUS_NOT_SAME_DEVICE: u32 = 0xC000_00D4;
pub(crate) const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_00DD;
pub(crate) const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
pub(crate) const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
pub(crate) const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub(crate) const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

/// Translate a personality-neutral [`VfsError`] into the matching
/// `STATUS_*` NTSTATUS value the Win32 entry surface returns.
/// Mirrors the POSIX errno encoder used by `vfs_error_to_public_reply`
/// — every variant resolves explicitly so a future error addition
/// triggers a non-exhaustive-match warning rather than collapsing
/// silently to `STATUS_IO_DEVICE_ERROR`.
///
/// [`VfsError`]: crate::core::error::VfsError
pub(crate) const fn vfs_error_to_ntstatus(err: crate::core::error::VfsError) -> u32 {
    use crate::core::error::VfsError;
    match err {
        VfsError::BadF => STATUS_INVALID_PARAMETER,
        VfsError::Acces => STATUS_ACCESS_DENIED,
        VfsError::Busy => STATUS_SHARING_VIOLATION,
        VfsError::Exist => STATUS_OBJECT_NAME_COLLISION,
        VfsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        VfsError::XDev => STATUS_NOT_SAME_DEVICE,
        VfsError::Io => STATUS_IO_DEVICE_ERROR,
        VfsError::IsDir => STATUS_FILE_IS_A_DIRECTORY,
        VfsError::NotDir => STATUS_NOT_A_DIRECTORY,
        VfsError::NoMem => STATUS_NO_MEMORY,
        VfsError::Inval => STATUS_INVALID_PARAMETER,
        VfsError::NoEnt => STATUS_OBJECT_NAME_NOT_FOUND,
        VfsError::Loop => STATUS_OBJECT_PATH_SYNTAX_BAD,
        VfsError::NotSup => STATUS_NOT_SUPPORTED,
        VfsError::NameTooLong => STATUS_NAME_TOO_LONG,
        VfsError::RoFs => STATUS_MEDIA_WRITE_PROTECTED,
        VfsError::Again => STATUS_RETRY,
        VfsError::Intr => STATUS_CANCELLED,
        VfsError::SessionTornDown => STATUS_PIPE_BROKEN,
        VfsError::PredecessorFailed => STATUS_IO_DEVICE_ERROR,
        VfsError::StaleIncarnation => STATUS_PIPE_BROKEN,
        VfsError::Quota => STATUS_QUOTA_EXCEEDED,
        VfsError::TimedOut => STATUS_TIMEOUT,
        VfsError::NotTty => STATUS_INVALID_DEVICE_REQUEST,
        VfsError::Range => STATUS_BUFFER_TOO_SMALL,
    }
}

// =========================================================================
// Path syntax limits
// =========================================================================

/// Maximum path length without the `\\?\` extended-length prefix.
/// Mirrors the documented Win32 `MAX_PATH = 260` cap, kept as a
/// hint for personality-aware lookup that wants to refuse long
/// paths early.
pub(crate) const WIN32_MAX_PATH: usize = 260;

/// Maximum path length including the `\\?\` prefix. NT object
/// manager namespace permits up to 32767 wide chars.
pub(crate) const WIN32_EXTENDED_MAX_PATH: usize = 32767;
