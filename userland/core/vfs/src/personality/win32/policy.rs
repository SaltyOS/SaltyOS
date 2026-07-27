// SPDX-License-Identifier: GPL-2.0-only
//!
//! Win32/NT open policy projection.
//!
//! The Win32 entry surface owns `ACCESS_MASK`, `ShareAccess`,
//! `CreateDisposition`, and `CreateOptions` numerics. This module
//! projects those wire bits onto the personality-neutral `ops`
//! shapes; the shared vnode/open logic never imports NT constants.

use crate::ops::{OpenAccess, OpenOptions, SharePolicy};

/// Collapse NT desired access bits onto the data-access portion of
/// `VfsOpenSpec`.
pub(crate) fn access_from_desired(desired_access: u32) -> Option<OpenAccess> {
    let has_read = (desired_access
        & (super::consts::GENERIC_READ
            | super::consts::GENERIC_EXECUTE
            | super::consts::FILE_READ_DATA
            | super::consts::FILE_EXECUTE))
        != 0;
    let has_write = (desired_access
        & (super::consts::GENERIC_WRITE
            | super::consts::FILE_WRITE_DATA
            | super::consts::FILE_APPEND_DATA))
        != 0;
    let has_all = (desired_access & super::consts::GENERIC_ALL) != 0;
    let has_attr = (desired_access
        & (super::consts::FILE_READ_ATTRIBUTES | super::consts::FILE_WRITE_ATTRIBUTES))
        != 0;

    if has_all || (has_read && has_write) {
        Some(OpenAccess::ReadWrite)
    } else if has_write {
        Some(OpenAccess::Write)
    } else if has_read {
        Some(OpenAccess::Read)
    } else if has_attr || delete_access_from_desired(desired_access) {
        Some(OpenAccess::AttributesOnly)
    } else {
        None
    }
}

/// Whether the handle requests NT delete/name-removal access.
pub(crate) const fn delete_access_from_desired(desired_access: u32) -> bool {
    (desired_access & (super::consts::GENERIC_ALL | super::consts::DELETE)) != 0
}

/// Map NT `ShareAccess` onto the cross-open share policy enforced
/// by `ops::open`.
pub(crate) fn share_from_access(share_access: u32) -> SharePolicy {
    let mut share_bits = 0u32;
    if (share_access & super::consts::FILE_SHARE_READ) != 0 {
        share_bits |= SharePolicy::SHARE_READ;
    }
    if (share_access & super::consts::FILE_SHARE_WRITE) != 0 {
        share_bits |= SharePolicy::SHARE_WRITE;
    }
    if (share_access & super::consts::FILE_SHARE_DELETE) != 0 {
        share_bits |= SharePolicy::SHARE_DELETE;
    }
    SharePolicy::from_bits(share_bits)
}

/// Project NT `CreateOptions` plus append desired-access into the
/// personality-neutral open option bitmap.
pub(crate) fn options_from_nt(desired_access: u32, options: u32) -> OpenOptions {
    let mut opts = OpenOptions::empty();
    if (options & super::consts::FILE_DIRECTORY_FILE) != 0 {
        opts = opts.with(OpenOptions::DIRECTORY);
    }
    if (options & super::consts::FILE_OPEN_REPARSE_POINT) != 0 {
        opts = opts.with(OpenOptions::NO_FOLLOW_LEAF);
    }
    if (options & super::consts::FILE_WRITE_THROUGH) != 0
        || (options
            & (super::consts::FILE_SYNCHRONOUS_IO_ALERT
                | super::consts::FILE_SYNCHRONOUS_IO_NONALERT))
            != 0
    {
        opts = opts.with(OpenOptions::SYNC_WRITES);
    }
    if (options & super::consts::FILE_SEQUENTIAL_ONLY) != 0 {
        opts = opts.with(OpenOptions::SEQUENTIAL_HINT);
    }
    if (options & super::consts::FILE_RANDOM_ACCESS) != 0 {
        opts = opts.with(OpenOptions::RANDOM_HINT);
    }
    if (options & super::consts::FILE_NO_INTERMEDIATE_BUFFERING) != 0 {
        opts = opts.with(OpenOptions::DIRECT);
    }
    if (desired_access & super::consts::FILE_APPEND_DATA) != 0 {
        opts = opts.with(OpenOptions::APPEND);
    }
    opts
}
