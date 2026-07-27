// SPDX-License-Identifier: GPL-2.0-only
//! Win32 `CreateFile` → neutral open-flag mapping.

use trona_posix::consts::*;

pub(crate) const GENERIC_READ: u32 = 0x8000_0000;
pub(crate) const GENERIC_WRITE: u32 = 0x4000_0000;
pub(crate) const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub(crate) const GENERIC_ALL: u32 = 0x1000_0000;

pub(crate) const CREATE_NEW: u32 = 1;
pub(crate) const CREATE_ALWAYS: u32 = 2;
pub(crate) const OPEN_EXISTING: u32 = 3;
pub(crate) const OPEN_ALWAYS: u32 = 4;
pub(crate) const TRUNCATE_EXISTING: u32 = 5;

pub(crate) struct Win32OpenPlan {
    pub(crate) flags: u32,
    pub(crate) mode: u32,
}

pub(crate) fn win32_open_plan(
    desired_access: u32,
    _share_mode: u32,
    creation_disposition: u32,
    _flags_and_attributes: u32,
) -> Option<Win32OpenPlan> {
    let can_read = (desired_access & (GENERIC_READ | GENERIC_EXECUTE | GENERIC_ALL)) != 0;
    let can_write = (desired_access & (GENERIC_WRITE | GENERIC_ALL)) != 0;

    let mut flags = match (can_read, can_write) {
        (false, true) => O_WRONLY,
        (true, true) => O_RDWR,
        _ => O_RDONLY,
    };

    match creation_disposition {
        CREATE_NEW => flags |= O_CREAT | O_EXCL,
        CREATE_ALWAYS => flags |= O_CREAT | O_TRUNC,
        OPEN_EXISTING => {}
        OPEN_ALWAYS => flags |= O_CREAT,
        TRUNCATE_EXISTING => flags |= O_TRUNC,
        _ => return None,
    }

    Some(Win32OpenPlan {
        flags,
        mode: (S_IFREG as u32) | 0o666,
    })
}
