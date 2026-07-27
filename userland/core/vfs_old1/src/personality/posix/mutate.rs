// SPDX-License-Identifier: GPL-2.0-only
//! POSIX metadata and namespace mutation dispatch.

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
            VFS_POSIX_FCHMODAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::attr::handle_fchmodat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCHOWNAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::attr::handle_fchownat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_UTIMENSAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::attr::handle_utimensat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCHMOD => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::attr::handle_fchmod_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCHOWN => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::attr::handle_fchown_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_MKFIFO => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_mkfifo_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_MKDIR => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_mkdir_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_MKDIRAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_mkdirat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_UNLINK => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_unlink_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_RENAME => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_rename_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_UNLINKAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_unlinkat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_RENAMEAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_renameat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_LINKAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_linkat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_RMDIR => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_rmdir_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SYMLINKAT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::mutate::handle_symlinkat_owned(state, cli_handle, msg, reply);
            }
            _ => return false,
        }
    }
    true
}
