// SPDX-License-Identifier: GPL-2.0-only
//! POSIX bulk SHM file-transfer dispatch.

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
            VFS_BULK_SETUP => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::bulk::handle_bulk_setup_owned(state, cli_handle, msg, reply);
            }
            VFS_BULK_READ => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::bulk::handle_bulk_read_owned(state, cli_handle, msg, reply);
            }
            VFS_BULK_PWRITE => {
                let Some(cli_handle) = super::posix_client_or_oom(state, badge, reply) else {
                    return true;
                };
                crate::fileops::bulk::handle_bulk_pwrite_owned(state, cli_handle, msg, reply);
            }
            _ => return false,
        }
    }
    true
}
