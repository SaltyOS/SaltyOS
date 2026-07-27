// SPDX-License-Identifier: GPL-2.0-only
//! Win32 request dispatch.

use trona_kernel::core_types::*;
use trona_protocol::posix::vfs::*;

use crate::owner::VfsState;
use crate::server::client::{MAX_PATH_LEN, extract_path};

/// Try to dispatch a Win32 request.
pub(crate) fn dispatch_request(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        match (*msg).label {
            VFS_WIN32_OPEN => {
                let Some(cli_handle) = super::win32_client_or_oom(state, badge, reply) else {
                    return true;
                };

                let desired_access = (*msg).regs[0] as u32;
                let share_mode = (*msg).regs[1] as u32;
                let creation_disposition = (*msg).regs[2] as u32;
                let flags_and_attributes = (*msg).regs[3] as u32;
                let Some(plan) = super::policy::win32_open_plan(
                    desired_access,
                    share_mode,
                    creation_disposition,
                    flags_and_attributes,
                ) else {
                    (*reply).label = uapi::TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return true;
                };

                let mut raw_path = [0u8; MAX_PATH_LEN];
                let mut abs_path = [0u8; MAX_PATH_LEN];
                let raw_len = extract_path(msg, 4, raw_path.as_mut_ptr());
                let path_len = match super::path::normalize_path_owned(
                    state,
                    cli_handle,
                    raw_path.as_ptr(),
                    raw_len,
                    abs_path.as_mut_ptr(),
                ) {
                    Ok(len) => len,
                    Err(err) => {
                        (*reply).label = err;
                        (*reply).length = 0;
                        return true;
                    }
                };

                crate::fileops::open::open_abs_path_as_slot(
                    state,
                    cli_handle,
                    false,
                    plan.flags,
                    plan.mode,
                    &abs_path[..path_len],
                    reply,
                );
                true
            }
            _ => false,
        }
    }
}
