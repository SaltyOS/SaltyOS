// SPDX-License-Identifier: GPL-2.0-only
//! POSIX descriptor-control dispatch.

use trona_kernel::core_types::*;
use trona_protocol::posix::posix::*;
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
            VFS_POSIX_ISATTY => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_isatty_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCNTL => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_fcntl_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_DUP => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_dup_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_DUP2 => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_dup2_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_DUP3 => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_dup3_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_CLONE_FDS => crate::fileops::fd::handle_clone_fds_owned(state, msg, reply),
            VFS_POSIX_IOCTL => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_ioctl_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_TCGETATTR => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_tcgetattr_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_TCSETATTR => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_tcsetattr_owned(state, cli_handle, msg, reply);
            }
            VFS_FSYNC => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::fd::handle_fsync_owned(state, cli_handle, msg, reply);
            }
            VFS_CLIENT_EXEC => crate::fileops::fd::handle_client_exec_owned(state, msg, reply),
            _ => return false,
        }
    }
    true
}
