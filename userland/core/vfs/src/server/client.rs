// SPDX-License-Identifier: GPL-2.0-only
//! Client helper utilities — IPC path extraction, flag checks.
//!
//! Per-client state management (allocation, fd operations, cleanup) has
//! moved to `owner/dispatch.rs` which uses `VfsState` + `Arena<ClientState>`
//! + `BadgeMap`. This module retains only pure utility functions that
//! don't touch VFS state.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::ipc;
use trona::types::core::*;

use crate::server::consts::*;
use crate::ipc_ctx;

// =========================================================================
// IPC path extraction
// =========================================================================

pub(crate) unsafe fn extract_path(msg: *const TronaMsg, reg_offset: usize, path: *mut u8) -> u8 {
    unsafe {
        let mut path_len = (*msg).regs[reg_offset] as u8;
        if (path_len as usize) > MAX_PATH_LEN {
            path_len = MAX_PATH_LEN as u8;
        }
        let raw = &(*msg).regs[reg_offset + 1] as *const u64 as *const u8;
        for i in 0..path_len as usize {
            *path.add(i) = *raw.add(i);
        }
        path_len
    }
}

/// Extract two packed paths from an IPC message with bounds validation.
pub(crate) unsafe fn extract_dual_paths(
    msg: *const TronaMsg,
    hdr_regs: usize,
    old_path: *mut u8,
    new_path: *mut u8,
    reply: *mut TronaMsg,
) -> Option<(u8, u8)> {
    unsafe {
        let old_len = (*msg).regs[hdr_regs] as u8;
        let new_len = (*msg).regs[hdr_regs + 1] as u8;
        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return None;
        }
        if (old_len as usize) > MAX_PATH_LEN || (new_len as usize) > MAX_PATH_LEN {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return None;
        }
        let data_start = hdr_regs + 2;
        let old_regs = ((old_len as usize) + 7) / 8;
        let new_regs = ((new_len as usize) + 7) / 8;
        let required = data_start + old_regs + new_regs;
        if required > 20 || required as u64 > (*msg).length {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return None;
        }
        let old_raw = &(*msg).regs[data_start] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            *old_path.add(i) = *old_raw.add(i);
        }
        let new_raw = &(*msg).regs[data_start + old_regs] as *const u64 as *const u8;
        for i in 0..new_len as usize {
            *new_path.add(i) = *new_raw.add(i);
        }
        Some((old_len, new_len))
    }
}

// =========================================================================
// Flag utilities
// =========================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenAccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

pub(crate) fn flags_nonblocking(flags: u32) -> bool {
    (flags & O_NONBLOCK) != 0
}

pub(crate) fn flags_append_writes(flags: u32) -> bool {
    (flags & O_APPEND) != 0
}

pub(crate) fn flags_allow_read(flags: u32) -> bool {
    let accmode = flags & O_ACCMODE;
    accmode == O_RDONLY || accmode == O_RDWR
}

pub(crate) fn open_access_mode(flags: u32) -> OpenAccessMode {
    match flags & O_ACCMODE {
        O_WRONLY => OpenAccessMode::WriteOnly,
        O_RDWR => OpenAccessMode::ReadWrite,
        _ => OpenAccessMode::ReadOnly,
    }
}

pub(crate) fn flags_close_on_exec(flags: u32) -> bool {
    (flags & O_CLOEXEC) != 0
}

pub(crate) fn object_status_flags(flags: u32) -> u32 {
    flags & !(OBJ_FLAG_CLOEXEC | O_CLOEXEC)
}

pub(crate) fn object_open_flags(flags: u32) -> u32 {
    let mut object_flags = object_status_flags(flags);
    if (flags & O_CLOEXEC) != 0 {
        object_flags |= OBJ_FLAG_CLOEXEC;
    }
    object_flags
}

pub(crate) fn pipe_end_open_flags(request_flags: u32, access: OpenAccessMode) -> u32 {
    let mut flags = match access {
        OpenAccessMode::ReadOnly => 0,
        OpenAccessMode::WriteOnly => O_WRONLY,
        OpenAccessMode::ReadWrite => O_RDWR,
    };
    if flags_nonblocking(request_flags) {
        flags |= O_NONBLOCK;
    }
    if flags_close_on_exec(request_flags) {
        flags |= O_CLOEXEC;
    }
    object_open_flags(flags)
}

// =========================================================================
// IPC helpers
// =========================================================================

/// Send an error reply to a saved caller cap (used during client exit
/// cleanup to wake deferred waiters).
pub(crate) unsafe fn send_client_exit_error(reply_slot: u64) {
    unsafe {
        if reply_slot == 0 {
            return;
        }
        let mut wake = TronaMsg::zeroed();
        wake.label = TRONA_INVALID_OPERATION;
        ipc::send_ctx(ipc_ctx(), reply_slot, &raw const wake);
    }
}
