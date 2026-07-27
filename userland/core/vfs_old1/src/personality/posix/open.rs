// SPDX-License-Identifier: GPL-2.0-only
//! POSIX open and directory dispatch.

use trona_kernel::core_types::*;
use trona_protocol::posix::vfs::*;

use crate::owner::VfsState;

pub(super) fn dispatch_request(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        match (*msg).label {
            VFS_POSIX_OPEN => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::open::handle_open_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_OPENAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::open::handle_openat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_OPENDIR => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::open::handle_opendir_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_READDIR => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::dir::handle_readdir_owned(state, cli_handle, msg, reply);
            }
            VFS_CLOSE => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::open::handle_close_owned(state, cli_handle, msg, reply);
            }
            _ => return false,
        }
    }
    true
}
