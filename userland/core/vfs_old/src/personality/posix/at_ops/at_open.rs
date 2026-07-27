// SPDX-License-Identifier: GPL-2.0-only
//! openat — handle-based dispatch.

use trona_kernel::core_types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{cwd_vnode_for, root_vnode_for};
use crate::personality::posix::consts::AT_FDCWD_VAL;
use crate::personality::posix::policy::posix_open_request;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::vnode::VnodeHandle;

/// Resolve the start vnode for an *at() call given dirfd.
pub(super) fn resolve_dirfd_vnode(
    state: &VfsState,
    cli_handle: ClientHandle,
    dirfd: i32,
) -> VnodeHandle {
    if dirfd == AT_FDCWD_VAL {
        return cwd_vnode_for(state, cli_handle);
    }
    if dirfd < 0 || dirfd as usize >= MAX_CLIENT_OBJECTS {
        return VnodeHandle::INVALID;
    }
    if let Some(obj) = state.open_object_at(cli_handle, dirfd as usize) {
        if obj.vnode_handle().is_valid() {
            return obj.vnode_handle();
        }
    }
    VnodeHandle::INVALID
}

/// openat(dirfd, path, flags, mode)
///
/// Returns `true` when the reply is deferred on any async walk or
/// terminal open/create boundary; `false` when the reply is already
/// populated synchronously.
pub(crate) unsafe fn handle_openat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let flags = (*msg).regs[1] as u32;
        let mode = (*msg).regs[2] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let start = resolve_dirfd_vnode(state, cli_handle, dirfd);
        if !start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let root = root_vnode_for(state, cli_handle);
        let request = posix_open_request(flags, mode);
        crate::fileops::open::open_path_from_start_owned(
            state,
            cli_handle,
            start,
            root,
            path.as_ptr(),
            path_len,
            &request,
            reply,
        )
    }
}
