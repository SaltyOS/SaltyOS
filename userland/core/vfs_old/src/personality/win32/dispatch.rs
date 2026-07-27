// SPDX-License-Identifier: GPL-2.0-only
//! Win32 personality dispatch — routes Win32-specific VFS IPC labels and
//! provides object-type-aware I/O dispatch for Win32 clients.

use trona_kernel::core_types::*;
use trona_protocol::posix::vfs::*;

use super::policy;
use crate::fileops::pipe;
use crate::owner::VfsState;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;

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
                    (*reply).label = uapi::TRONA_INVALID_ARGUMENT;
                    return Some(false);
                };
                Some(crate::fileops::open::open_path_owned(
                    state,
                    cli_handle,
                    path.as_ptr(),
                    raw_len,
                    &request,
                    reply,
                ))
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
        let kind = state
            .open_object_at(cli_handle, fd as usize)
            .map(|obj| obj.kind())
            .unwrap_or(ObjectKind::None);

        match kind {
            ObjectKind::Pipe => unsafe {
                pipe::handle_pipe_read(state, cli_handle, fd, msg, reply)
            },
            _ => unsafe { crate::fileops::rw::handle_read_owned(state, cli_handle, msg, reply) },
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
        let kind = state
            .open_object_at(cli_handle, fd as usize)
            .map(|obj| obj.kind())
            .unwrap_or(ObjectKind::None);

        match kind {
            ObjectKind::Pipe => unsafe {
                pipe::handle_pipe_write(state, cli_handle, fd, msg, reply)
            },
            _ => unsafe { crate::fileops::rw::handle_write_owned(state, cli_handle, msg, reply) },
        }
    }
}

/// Win32 client exit cleanup: route every live object slot through the
/// neutral `close_open_object` so the shared refcount + `release_backing`
/// dispatch fires just like an in-session close. `badge` is the exiting
/// client's badge threaded in from `dispatch_client_exit`.
pub(crate) unsafe fn cleanup_client_objects(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    badge: u64,
) {
    if state.clients.get(cli_handle).is_none() {
        return;
    }
    for i in 0..MAX_CLIENT_OBJECTS {
        if state.open_object_at(cli_handle, i).is_some() {
            unsafe {
                let _ = state.close_open_object(cli_handle, i, badge);
            }
        }
    }
}
