// SPDX-License-Identifier: GPL-2.0-only
//! POSIX path, stat, and cwd dispatch.

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
            VFS_POSIX_CANON_PATH => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::stat::handle_canon_path_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_STAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::stat::handle_stat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_LSTAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::stat::handle_lstat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_STAT_FOR_EXEC => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::stat::handle_stat_for_exec_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FSTAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::stat::handle_fstat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FSTATAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::stat::handle_fstatat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_READLINKAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::stat::handle_readlinkat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_CHDIR => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::misc::handle_chdir_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_GETCWD => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::misc::handle_getcwd_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_ACCESS => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::misc::handle_access_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FACCESSAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::misc::handle_faccessat_owned(state, cli_handle, msg, reply);
            }
            _ => return false,
        }
    }
    true
}
