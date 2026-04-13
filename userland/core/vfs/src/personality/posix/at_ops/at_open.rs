// SPDX-License-Identifier: GPL-2.0-only
//! openat — handle-based dispatch.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, client_cred, root_vnode_for, cwd_vnode_for, resolve_fd};
use crate::personality::posix::policy::posix_open_request;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NameiArgs, NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_WANTPARENT};
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
    if let Some(cli) = state.clients.get(cli_handle) {
        let slot = &cli.objects[dirfd as usize];
        if slot.is_live() && slot.vnode_handle().is_valid() {
            return slot.vnode_handle();
        }
    }
    VnodeHandle::INVALID
}

/// openat(dirfd, path, flags, mode)
pub(crate) unsafe fn handle_openat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let flags = (*msg).regs[1] as u32;
        let mode = (*msg).regs[2] as u32;
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
        let request = posix_open_request(flags, mode);

        let mut namei_flags = NAMEI_FOLLOW;
        if request.create_if_missing {
            namei_flags |= NAMEI_CREATE | NAMEI_WANTPARENT;
        }

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

        // Target found.
        if ni.vp.is_valid() {
            if request.fail_if_exists && request.create_if_missing {
                (*reply).label = TRONA_ALREADY_EXISTS;
                return;
            }
            crate::fileops::open::open_vnode_owned(state, cli_handle, ni.vp, &request, reply);
            return;
        }

        // Target not found, O_CREAT requested.
        if request.create_if_missing && ni.dvp.is_valid() {
            let ctx = match mount_ctl::build_vop_context(state, ni.dvp) {
                Some(c) => c,
                None => { (*reply).label = TRONA_IO_ERROR; return; }
            };
            let ops = &*(*ctx.vnode).ops;
            let new_vh = match (ops.meta.create)(
                &ctx,
                ni.last_name,
                ni.last_name_len,
                request.create_mode,
                &raw const cred,
            ) {
                Ok(vh) => vh,
                Err(e) => {
                    mount_ctl::clear_trampolines();
                    (*reply).label = e.to_trona();
                    return;
                }
            };
            mount_ctl::clear_trampolines();

            if !new_vh.is_valid() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }

            crate::fileops::open::open_vnode_owned(state, cli_handle, new_vh, &request, reply);
            return;
        }

        (*reply).label = TRONA_NOT_FOUND;
    }
}
