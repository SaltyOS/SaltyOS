// SPDX-License-Identifier: GPL-2.0-only
//! fstatat, faccessat, lstat — handle-based dispatch.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, client_cred, root_vnode_for, cwd_vnode_for, resolve_fd};
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NameiArgs, NAMEI_FOLLOW, NAMEI_NOFOLLOW_FINAL};
use crate::vfs_core::vnode::VnodeHandle;

use super::at_open::resolve_dirfd_vnode;

/// Fill IPC reply with stat data from a VnodeHandle.
unsafe fn fill_stat_reply(
    state: &mut VfsState,
    reply: *mut TronaMsg,
    vh: VnodeHandle,
) {
    unsafe {
        let ctx = match mount_ctl::build_vop_context(state, vh) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let vnode = &*ctx.vnode;
        let ops = vnode.ops;
        if ops.is_null() {
            mount_ctl::clear_trampolines();
            (*reply).label = TRONA_IO_ERROR;
            return;
        }
        let mut attr = VAttr::zeroed();
        match ((*ops).meta.getattr)(&ctx, &raw mut attr) {
            Ok(()) => {
                (*reply).label = TRONA_OK;
                (*reply).length = 9;
                (*reply).regs[0] = vnode.id;
                (*reply).regs[1] = attr.mode as u64;
                (*reply).regs[2] = attr.nlink as u64;
                (*reply).regs[3] = attr.uid as u64;
                (*reply).regs[4] = attr.gid as u64;
                (*reply).regs[5] = attr.size;
                (*reply).regs[6] = attr.blocks;
                (*reply).regs[7] = attr.mtime;
                (*reply).regs[8] = attr.rdev as u64;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
        mount_ctl::clear_trampolines();
    }
}

/// fstatat(dirfd, path, statbuf, flags)
pub(crate) unsafe fn handle_fstatat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        // AT_EMPTY_PATH: stat the fd itself
        if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 {
            if dirfd < 0 || dirfd as usize >= MAX_CLIENT_OBJECTS {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            let vh = match state.clients.get(cli_handle) {
                Some(cli) => {
                    let slot = &cli.objects[dirfd as usize];
                    if !slot.is_live() || !slot.vnode_handle().is_valid() {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                    slot.vnode_handle()
                }
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            };
            fill_stat_reply(state, reply, vh);
            return;
        }

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let start = resolve_dirfd_vnode(state, cli_handle, dirfd);
        if !start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        let namei_flags = if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
            NAMEI_NOFOLLOW_FINAL
        } else {
            NAMEI_FOLLOW
        };

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: path.as_ptr(),
            path_len: path_len as u16,
            flags: namei_flags,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if !ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        fill_stat_reply(state, reply, ni.vp);
    }
}

/// faccessat(dirfd, path, mode, flags)
pub(crate) unsafe fn handle_faccessat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let start = resolve_dirfd_vnode(state, cli_handle, dirfd);
        if !start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: path.as_ptr(),
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };

        match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(ni) => {
                mount_ctl::clear_trampolines();
                if ni.vp.is_valid() {
                    (*reply).label = TRONA_OK;
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                }
            }
            Err(_) => {
                mount_ctl::clear_trampolines();
                (*reply).label = TRONA_NOT_FOUND;
            }
        }
    }
}

/// lstat: stat without following final symlink
pub(crate) unsafe fn handle_lstat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 0, path.as_mut_ptr());
        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);
        let start = cwd_vnode_for(state, cli_handle);

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: path.as_ptr(),
            path_len: path_len as u16,
            flags: NAMEI_NOFOLLOW_FINAL,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if !ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        fill_stat_reply(state, reply, ni.vp);
    }
}
