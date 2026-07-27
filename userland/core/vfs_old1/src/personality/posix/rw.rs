// SPDX-License-Identifier: GPL-2.0-only
//! POSIX read/write, poll, and shm dispatch.

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
            VFS_READ => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::rw::handle_read_owned(state, cli_handle, msg, reply);
            }
            VFS_PREAD => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::rw::handle_pread_owned(state, cli_handle, msg, reply);
            }
            VFS_WRITE => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::rw::handle_write_owned(state, cli_handle, msg, reply);
            }
            VFS_PWRITE => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::rw::handle_pwrite_owned(state, cli_handle, msg, reply);
            }
            VFS_LSEEK => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::rw::handle_lseek_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FTRUNCATE => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::rw::handle_ftruncate_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_POLL => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::poll::handle_poll_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_EPOLL_CREATE => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::poll::handle_epoll_create_owned(state, cli_handle, reply);
            }
            VFS_POSIX_EPOLL_CTL => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::poll::handle_epoll_ctl_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_EPOLL_WAIT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::poll::handle_epoll_wait_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SHM_OPEN => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::shm::handle_shm_open_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SHM_UNLINK => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::shm::handle_shm_unlink_owned(state, cli_handle, msg, reply);
            }
            _ => return false,
        }
    }
    true
}
