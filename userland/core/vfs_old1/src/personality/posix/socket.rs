// SPDX-License-Identifier: GPL-2.0-only
//! POSIX socket and pipe dispatch.

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
            VFS_POSIX_PIPE => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::pipe::handle_pipe_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SOCKET => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_socket_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_BIND => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_bind_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_LISTEN => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_listen_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_ACCEPT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_accept_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_CONNECT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_connect_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SENDMSG => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_sendmsg_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_RECVMSG => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_recvmsg_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SOCKPAIR => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_sockpair_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SHUTDOWN => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_shutdown_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_GETSOCKNAME => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_getsockname_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_GETPEERNAME => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_getpeername_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SETSOCKOPT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_setsockopt_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_GETSOCKOPT => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::socket::handle_getsockopt_owned(state, cli_handle, msg, reply);
            }
            _ => return false,
        }
    }
    true
}
