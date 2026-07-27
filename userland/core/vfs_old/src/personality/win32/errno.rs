// SPDX-License-Identifier: GPL-2.0-only
//! VfsError to Win32/NTSTATUS error code mapping.
//!
//! Win32 exposes two parallel error code systems:
//!
//! - **NTSTATUS** — used by NT kernel APIs (`NtCreateFile`, etc.). These
//!   are the canonical error codes returned by the subsystem internals.
//! - **Win32 ERROR_*** — used by the higher-level Win32 API surface
//!   (`CreateFile`, `GetLastError`). Typically derived from NTSTATUS via
//!   `RtlNtStatusToDosError`.
//!
//! This module provides both conversions so the Win32 personality dispatch
//! layer can return whichever form the IPC protocol expects.

use crate::vfs_core::error::VfsError;

// =========================================================================
// NTSTATUS constants
// =========================================================================

pub(crate) const STATUS_SUCCESS: u32 = 0x0000_0000;
pub(crate) const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub(crate) const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub(crate) const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub(crate) const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub(crate) const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
pub(crate) const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub(crate) const STATUS_TOO_MANY_LINKS: u32 = 0xC000_0265; // symlink loop
pub(crate) const STATUS_UNEXPECTED_IO_ERROR: u32 = 0xC000_016A;
pub(crate) const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
pub(crate) const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub(crate) const STATUS_DISK_FULL: u32 = 0xC000_007F;
pub(crate) const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub(crate) const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;
pub(crate) const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
pub(crate) const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
pub(crate) const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
pub(crate) const STATUS_SECTION_TOO_BIG: u32 = 0xC000_0040;
pub(crate) const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub(crate) const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
/// Rename / link crosses a mount boundary.
pub(crate) const STATUS_NOT_SAME_DEVICE: u32 = 0xC000_00D4;
/// Backend session was torn down mid-operation.
pub(crate) const STATUS_DEVICE_NOT_CONNECTED: u32 = 0xC000_00C9;

// =========================================================================
// Win32 ERROR_* constants
// =========================================================================

pub(crate) const ERROR_SUCCESS: u32 = 0;
pub(crate) const ERROR_FILE_NOT_FOUND: u32 = 2;
pub(crate) const ERROR_PATH_NOT_FOUND: u32 = 3;
pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
pub(crate) const ERROR_INVALID_HANDLE: u32 = 6;
pub(crate) const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub(crate) const ERROR_WRITE_PROTECT: u32 = 19;
pub(crate) const ERROR_SHARING_VIOLATION: u32 = 32;
pub(crate) const ERROR_FILE_EXISTS: u32 = 80;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const ERROR_DISK_FULL: u32 = 112;
pub(crate) const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
pub(crate) const ERROR_INVALID_NAME: u32 = 123;
pub(crate) const ERROR_DIRECTORY: u32 = 267;
pub(crate) const ERROR_NOT_A_REPARSE_POINT: u32 = 4390;
pub(crate) const ERROR_BUSY: u32 = 170;
pub(crate) const ERROR_DELETE_PENDING: u32 = 303;
/// Rename / link crosses a volume (mapped from `STATUS_NOT_SAME_DEVICE`).
pub(crate) const ERROR_NOT_SAME_DEVICE: u32 = 17;
/// Backend went away.
pub(crate) const ERROR_DEVICE_NOT_CONNECTED: u32 = 1167;
/// Generic I/O failure — used as the default for `VfsError::Io`,
/// `DataCorrupt`, `IntegrityFailure`. `ERROR_NOT_ENOUGH_MEMORY` was
/// incorrect (the NT → DOS table does not map I/O failures that way).
pub(crate) const ERROR_GEN_FAILURE: u32 = 31;
/// Data read/written with bad CRC (integrity-class failures).
pub(crate) const ERROR_CRC: u32 = 23;
/// Output buffer too small — maps `TooLarge` so callers can re-size
/// and retry.
pub(crate) const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// Stale NFS-like file handle — maps `VfsError::Stale`.
pub(crate) const ERROR_STALE_LINK: u32 = 1206;
pub(crate) const STATUS_INVALID_HANDLE_SURVIVES_STALE: u32 = 0xC000_0127; // STATUS_STALE_HANDLE

// =========================================================================
// VfsError → NTSTATUS
// =========================================================================

/// Convert a VFS core error to its closest NTSTATUS equivalent.
pub(crate) fn vfs_error_to_ntstatus(e: VfsError) -> u32 {
    match e {
        VfsError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        VfsError::NotDir => STATUS_NOT_A_DIRECTORY,
        VfsError::IsDir => STATUS_FILE_IS_A_DIRECTORY,
        VfsError::Loop => STATUS_TOO_MANY_LINKS,
        VfsError::Io => STATUS_UNEXPECTED_IO_ERROR,
        VfsError::NotSupported => STATUS_NOT_IMPLEMENTED,
        VfsError::Perm => STATUS_ACCESS_DENIED,
        VfsError::NoSpace => STATUS_DISK_FULL,
        VfsError::Exists => STATUS_OBJECT_NAME_COLLISION,
        VfsError::NameTooLong => STATUS_OBJECT_NAME_INVALID,
        VfsError::Inval => STATUS_INVALID_PARAMETER,
        VfsError::Busy => STATUS_DEVICE_BUSY,
        VfsError::WouldBlock => STATUS_DEVICE_BUSY,
        VfsError::NoEntry => STATUS_OBJECT_PATH_NOT_FOUND,
        VfsError::SharingViolation => STATUS_SHARING_VIOLATION,
        VfsError::DeletePending => STATUS_DELETE_PENDING,
        VfsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        VfsError::TooLarge => STATUS_SECTION_TOO_BIG,
        VfsError::BadHandle => STATUS_INVALID_HANDLE,
        VfsError::CrossDevice => STATUS_NOT_SAME_DEVICE,
        VfsError::SessionTornDown => STATUS_DEVICE_NOT_CONNECTED,
        VfsError::DataCorrupt { .. } => STATUS_UNEXPECTED_IO_ERROR,
        VfsError::IntegrityFailure { .. } => STATUS_UNEXPECTED_IO_ERROR,
        VfsError::Stale => STATUS_INVALID_HANDLE_SURVIVES_STALE,
    }
}

// =========================================================================
// VfsError → Win32 ERROR_*
// =========================================================================

/// Convert a VFS core error to its closest Win32 `ERROR_*` equivalent.
///
/// This mirrors the `RtlNtStatusToDosError` mapping for the subset of
/// NTSTATUS codes VFS produces.
pub(crate) fn vfs_error_to_win32(e: VfsError) -> u32 {
    match e {
        VfsError::NotFound => ERROR_FILE_NOT_FOUND,
        VfsError::NotDir => ERROR_DIRECTORY,
        VfsError::IsDir => ERROR_ACCESS_DENIED,
        VfsError::Loop => ERROR_NOT_A_REPARSE_POINT,
        VfsError::Io => ERROR_GEN_FAILURE,
        VfsError::NotSupported => ERROR_CALL_NOT_IMPLEMENTED,
        VfsError::Perm => ERROR_ACCESS_DENIED,
        VfsError::NoSpace => ERROR_DISK_FULL,
        VfsError::Exists => ERROR_FILE_EXISTS,
        VfsError::NameTooLong => ERROR_INVALID_NAME,
        VfsError::Inval => ERROR_INVALID_PARAMETER,
        VfsError::Busy => ERROR_BUSY,
        VfsError::WouldBlock => ERROR_BUSY,
        VfsError::NoEntry => ERROR_PATH_NOT_FOUND,
        VfsError::SharingViolation => ERROR_SHARING_VIOLATION,
        VfsError::DeletePending => ERROR_DELETE_PENDING,
        VfsError::ReadOnly => ERROR_WRITE_PROTECT,
        VfsError::TooLarge => ERROR_INSUFFICIENT_BUFFER,
        VfsError::BadHandle => ERROR_INVALID_HANDLE,
        VfsError::CrossDevice => ERROR_NOT_SAME_DEVICE,
        VfsError::SessionTornDown => ERROR_DEVICE_NOT_CONNECTED,
        VfsError::DataCorrupt { .. } => ERROR_CRC,
        VfsError::IntegrityFailure { .. } => ERROR_CRC,
        VfsError::Stale => ERROR_STALE_LINK,
    }
}
