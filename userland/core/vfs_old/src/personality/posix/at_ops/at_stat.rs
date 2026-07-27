// SPDX-License-Identifier: GPL-2.0-only
//! fstatat, faccessat, lstat — handle-based dispatch.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{cwd_vnode_for, root_vnode_for};
use crate::personality::posix::consts::*;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::namei_common::{NAMEI_FOLLOW, NAMEI_NOFOLLOW_FINAL};

use super::at_open::resolve_dirfd_vnode;

/// fstatat(dirfd, path, statbuf, flags)
pub(crate) unsafe fn handle_fstatat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        // AT_EMPTY_PATH: stat the fd itself
        if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 {
            if dirfd < 0 || dirfd as usize >= MAX_CLIENT_OBJECTS {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
            let vh = match state.open_object_at(cli_handle, dirfd as usize) {
                Some(obj) if obj.vnode_handle().is_valid() => obj.vnode_handle(),
                _ => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
            };
            return crate::fileops::stat::fill_stat_reply_handle(state, cli_handle, reply, vh);
        }

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
        let namei_flags = if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
            NAMEI_NOFOLLOW_FINAL
        } else {
            NAMEI_FOLLOW
        };
        // `fstatat` only picks the dirfd-relative anchor and final
        // follow policy; the shared async stat walker owns the path
        // semantics and park/resume contract.
        crate::fileops::stat::stat_path_from_start_owned(
            state,
            cli_handle,
            start,
            root,
            path.as_ptr(),
            path_len,
            namei_flags,
            reply,
        )
    }
}

/// faccessat(dirfd, path, mode, flags)
pub(crate) unsafe fn handle_faccessat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let amode = (*msg).regs[1] as u32;
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
        crate::fileops::stat::access_path_from_start_owned(
            state,
            cli_handle,
            start,
            root,
            path.as_ptr(),
            path_len,
            amode,
            reply,
        )
    }
}

/// lstat: stat without following final symlink
pub(crate) unsafe fn handle_lstat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 0, path.as_mut_ptr());
        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let root = root_vnode_for(state, cli_handle);
        let start = cwd_vnode_for(state, cli_handle);
        // `lstat` is the same shared stat walk with a no-follow-final
        // terminal policy and cwd/root anchors.
        crate::fileops::stat::stat_path_from_start_owned(
            state,
            cli_handle,
            start,
            root,
            path.as_ptr(),
            path_len,
            NAMEI_NOFOLLOW_FINAL,
            reply,
        )
    }
}
