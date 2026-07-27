// SPDX-License-Identifier: GPL-2.0-only
//! Win32 open arbitration policy.
//!
//! Maps Win32 `CreateFile(dwDesiredAccess, dwShareMode, ...)` into the
//! personality-neutral `(access, deny)` pair consumed by
//! `vfs_core::arbitration::check_open`.
//!
//! Win32 semantics: the share mode specifies which access modes OTHER
//! openers are *allowed* to use. The deny set is the inverse — any mode
//! NOT in `dwShareMode` is denied to future openers.
//!
//! ## Mapping
//!
//! | Win32 `dwDesiredAccess` | access bit |
//! |-------------------------|------------|
//! | `GENERIC_READ`          | `ACCESS_READ` |
//! | `GENERIC_WRITE`         | `ACCESS_WRITE` |
//! | `GENERIC_EXECUTE`       | `ACCESS_EXEC` |
//! | `DELETE`                | `ACCESS_UNLINK_NAME` |
//!
//! | Win32 `dwShareMode` absent | deny bit |
//! |-----------------------------|----------|
//! | `FILE_SHARE_READ` absent    | `ACCESS_READ` |
//! | `FILE_SHARE_WRITE` absent   | `ACCESS_WRITE` |
//! | `FILE_SHARE_DELETE` absent  | `ACCESS_UNLINK_NAME` |

use crate::fileops::open::OpenRequest;
use crate::personality::posix::consts::S_IFREG_L;
use crate::server::client::object_open_flags;
use crate::vfs_core::arbitration::{ACCESS_EXEC, ACCESS_READ, ACCESS_UNLINK_NAME, ACCESS_WRITE};

// =========================================================================
// Win32 access mode constants (from Win32 SDK)
// =========================================================================

pub(crate) const GENERIC_READ: u32 = 0x8000_0000;
pub(crate) const GENERIC_WRITE: u32 = 0x4000_0000;
pub(crate) const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub(crate) const GENERIC_ALL: u32 = 0x1000_0000;
pub(crate) const DELETE: u32 = 0x0001_0000;

// =========================================================================
// Win32 share mode constants
// =========================================================================

pub(crate) const FILE_SHARE_READ: u32 = 0x0000_0001;
pub(crate) const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub(crate) const FILE_SHARE_DELETE: u32 = 0x0000_0004;

// =========================================================================
// Win32 creation disposition / flags
// =========================================================================

pub(crate) const CREATE_NEW: u32 = 1;
pub(crate) const CREATE_ALWAYS: u32 = 2;
pub(crate) const OPEN_EXISTING: u32 = 3;
pub(crate) const OPEN_ALWAYS: u32 = 4;
pub(crate) const TRUNCATE_EXISTING: u32 = 5;

pub(crate) const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;

// =========================================================================
// Arbitration mapping
// =========================================================================

/// Convert Win32 `CreateFile` access and share parameters into the
/// unified `(access, deny)` pair for the arbitration layer.
///
/// `desired_access` is `dwDesiredAccess` — a bitmask of `GENERIC_*` and
/// specific access rights.
///
/// `share_mode` is `dwShareMode` — a bitmask of `FILE_SHARE_*` flags
/// indicating which access modes other openers are permitted to hold.
pub(crate) fn win32_create_arbitration(desired_access: u32, share_mode: u32) -> (u8, u8) {
    // --- Access bits ---

    let mut access: u8 = 0;

    if (desired_access & GENERIC_ALL) != 0 {
        access = ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC | ACCESS_UNLINK_NAME;
    } else {
        if (desired_access & GENERIC_READ) != 0 {
            access |= ACCESS_READ;
        }
        if (desired_access & GENERIC_WRITE) != 0 {
            access |= ACCESS_WRITE;
        }
        if (desired_access & GENERIC_EXECUTE) != 0 {
            access |= ACCESS_EXEC;
        }
        if (desired_access & DELETE) != 0 {
            access |= ACCESS_UNLINK_NAME;
        }
    }

    // --- Deny bits (inverse of share mode) ---

    let mut deny: u8 = 0;

    if (share_mode & FILE_SHARE_READ) == 0 {
        deny |= ACCESS_READ;
    }
    if (share_mode & FILE_SHARE_WRITE) == 0 {
        deny |= ACCESS_WRITE;
    }
    if (share_mode & FILE_SHARE_DELETE) == 0 {
        deny |= ACCESS_UNLINK_NAME;
    }

    (access, deny)
}

fn win32_object_flags(desired_access: u32) -> u32 {
    let can_read = (desired_access & (GENERIC_READ | GENERIC_EXECUTE)) != 0;
    let can_write = (desired_access & GENERIC_WRITE) != 0;

    let posix_like = match (can_read, can_write) {
        (false, true) => trona_posix::consts::O_WRONLY,
        (true, true) => trona_posix::consts::O_RDWR,
        _ => trona_posix::consts::O_RDONLY,
    };

    object_open_flags(posix_like)
}

pub(crate) fn win32_open_request(
    desired_access: u32,
    share_mode: u32,
    creation_disposition: u32,
    flags_and_attributes: u32,
) -> Option<OpenRequest> {
    let (access, deny) = win32_create_arbitration(desired_access, share_mode);
    let object_flags = win32_object_flags(desired_access);

    let (create_if_missing, fail_if_exists, truncate_existing) = match creation_disposition {
        CREATE_NEW => (true, true, false),
        CREATE_ALWAYS => (true, false, true),
        OPEN_EXISTING => (false, false, false),
        OPEN_ALWAYS => (true, false, false),
        TRUNCATE_EXISTING => (false, false, true),
        _ => return None,
    };

    let can_write = (desired_access & GENERIC_WRITE) != 0;

    Some(OpenRequest {
        backend_open_flags: object_flags
            | if truncate_existing {
                trona_posix::consts::O_TRUNC
            } else {
                0
            },
        object_flags,
        create_mode: S_IFREG_L | 0o666,
        win32_desired_access: desired_access,
        access,
        deny,
        append_on_write: false,
        nonblocking: false,
        create_if_missing,
        fail_if_exists,
        truncate_existing,
        mutating_data: can_write || truncate_existing,
        cloexec: false,
        delete_on_close: (flags_and_attributes & FILE_FLAG_DELETE_ON_CLOSE) != 0,
    })
}
