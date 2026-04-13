// SPDX-License-Identifier: GPL-2.0-only
//! Win32 personality dispatch — routes Win32-specific VFS IPC labels and
//! provides object-type-aware I/O dispatch for Win32 clients.

use trona::protocol::vfs::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::fileops::pipe;
use super::policy;

/// Dispatch a Win32-specific VFS label.
///
/// Returns `Some(skip_reply)` if the label was handled, `None` if unrecognised.
pub(crate) unsafe fn dispatch(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> Option<bool> {
    unsafe {
        match (*msg).label {
            VFS_WIN32_OPEN => {
                let desired_access = (*msg).regs[0] as u32;
                let share_mode = (*msg).regs[1] as u32;
                let creation_disposition = (*msg).regs[2] as u32;
                let flags_and_attributes = (*msg).regs[3] as u32;
                let mut path = [0u8; MAX_PATH_LEN];
                let raw_len = extract_path(msg, 4, path.as_mut_ptr());
                let Some(request) = policy::win32_open_request(
                    desired_access,
                    share_mode,
                    creation_disposition,
                    flags_and_attributes,
                ) else {
                    (*reply).label = trona::consts::kernel::TRONA_INVALID_ARGUMENT;
                    return Some(false);
                };
                crate::fileops::open::open_path_owned(
                    state,
                    cli_handle,
                    path.as_ptr(),
                    raw_len,
                    &request,
                    reply,
                );
                Some(false)
            }
            _ => None,
        }
    }
}

/// Win32 read dispatch: Win32 clients can hold pipe objects (via pipefs).
/// All other types use the neutral read path.
pub(crate) unsafe fn dispatch_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        unsafe { crate::fileops::rw::handle_read_owned(state, cli_handle, msg, reply) }
    } else {
        let kind = match state.clients.get(cli_handle) {
            Some(cli) => {
                let slot = &cli.objects[fd as usize];
                if !slot.is_live() { ObjectKind::None } else { slot.kind() }
            }
            None => ObjectKind::None,
        };

        match kind {
            ObjectKind::Pipe => unsafe {
                pipe::handle_pipe_read(state, cli_handle, fd, msg, reply)
            },
            _ => {
                unsafe { crate::fileops::rw::handle_read_owned(state, cli_handle, msg, reply) }
            }
        }
    }
}

/// Win32 write dispatch.
pub(crate) unsafe fn dispatch_write(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        unsafe { crate::fileops::rw::handle_write_owned(state, cli_handle, msg, reply) }
    } else {
        let kind = match state.clients.get(cli_handle) {
            Some(cli) => {
                let slot = &cli.objects[fd as usize];
                if !slot.is_live() { ObjectKind::None } else { slot.kind() }
            }
            None => ObjectKind::None,
        };

        match kind {
            ObjectKind::Pipe => unsafe {
                pipe::handle_pipe_write(state, cli_handle, fd, msg, reply)
            },
            _ => {
                unsafe { crate::fileops::rw::handle_write_owned(state, cli_handle, msg, reply) }
            }
        }
    }
}

/// Win32 close pre-cleanup: release pipe resources before generic close.
pub(crate) unsafe fn pre_close(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return;
    }

    let kind = match state.clients.get(cli_handle) {
        Some(cli) => {
            let slot = &cli.objects[fd as usize];
            if !slot.is_live() { return; }
            slot.kind()
        }
        None => return,
    };

    if kind == ObjectKind::Pipe {
        unsafe { pipe::close_pipe(state, cli_handle, fd); }
    }
}

/// Win32 client exit cleanup.
pub(crate) unsafe fn cleanup_client_objects(
    state: &mut VfsState,
    cli_handle: ClientHandle,
) {
    let mut pipe_fds = [0i32; MAX_CLIENT_OBJECTS];
    let mut pipe_count = 0usize;
    if let Some(cli) = state.clients.get(cli_handle) {
        for i in 0..MAX_CLIENT_OBJECTS {
            if cli.objects[i].is_live() && cli.objects[i].kind() == ObjectKind::Pipe {
                pipe_fds[pipe_count] = i as i32;
                pipe_count += 1;
            }
        }
    } else {
        return;
    }

    for idx in 0..pipe_count {
        unsafe { pipe::close_pipe(state, cli_handle, pipe_fds[idx]); }
    }
}
