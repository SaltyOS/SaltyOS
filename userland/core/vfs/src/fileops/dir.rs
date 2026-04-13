// SPDX-License-Identifier: GPL-2.0-only
//! Directory open and readdir — VopMetaOps/VopDataOps dispatch.

use trona::consts::kernel::*;
use trona::types::core::*;

use crate::owner::dispatch::{build_data_ctx, resolve_fd, resolve_fd_mut};
use crate::owner::VfsState;
use crate::server::consts::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::vnode::VT_DIR;

use crate::server::types::{ClientHandle, ObjectKind};

/// opendir — owner-loop version.
///
/// Resolves path via handle-based namei, allocates fd for directory.
pub(crate) unsafe fn handle_opendir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = crate::fileops::open::normalize_path_owned(
            state,
            cli_handle,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);
        let args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: crate::vfs_core::namei_common::NAMEI_FOLLOW,
            cred,
            root,
        };

        let vh = match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(result) => {
                if !result.vp.is_valid() {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
                result.vp
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        // Cross mount coverage.
        let dir_vh = match crate::vfs_core::mount_ctl::covering_mount_for_vnode(state, vh) {
            Some(covering_mh) => match state.mounts.get(covering_mh) {
                Some(covering_mp) if covering_mp.root_vnode.is_valid() => covering_mp.root_vnode,
                _ => vh,
            },
            None => vh,
        };

        // Verify directory type.
        let vtype = match state.vnodes.get(dir_vh) {
            Some(v) => v.vtype,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if vtype != VT_DIR {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // MetaOps::open for the directory.
        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, dir_vh) {
            let ops = (*ctx.vnode).ops;
            if !ops.is_null() {
                let _ = ((*ops).meta.open)(&ctx, 0);
            }
            crate::vfs_core::mount_ctl::clear_trampolines();
        }

        // Install arbitration.
        if let Some(vnode) = state.vnodes.get_mut(dir_vh) {
            crate::vfs_core::arbitration::install_open(vnode, 0, 0);
        }

        // Allocate fd.
        let fd = match crate::fileops::open::reserve_fd_owned(state, cli_handle) {
            Some(fd) => fd,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let vnode_id = state.vnodes.get(dir_vh).map(|v| v.id).unwrap_or(0);
        if let Some(cli) = state.clients.get_mut(cli_handle) {
            let slot = &mut cli.objects[fd as usize];
            slot.rights = OBJ_RIGHT_READ;
            slot.offset = 0;
            slot.flags = 0;
            slot.set_directory(dir_vh, vnode_id as u32);
            slot.dir_cursor = 0;
            slot.held_access = 0;
            slot.held_deny = 0;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

/// readdir — owner-loop version.
///
/// Reads one directory entry via VopDataOps::readdir. Updates dir_cursor
/// in the ObjectSlot.
pub(crate) unsafe fn handle_readdir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;

        let (vnode_h, cookie) = {
            match resolve_fd(state, cli_handle, fd) {
                Some(s) if s.kind() == ObjectKind::Directory && s.vnode_handle().is_valid() => {
                    (s.vnode_handle(), s.dir_cursor as u64)
                }
                _ => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            }
        };

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let vnode = match state.vnodes.get(vnode_h) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let ops = vnode.ops;
        if ops.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mut cookie_mut = cookie;
        let mut got_entry = false;

        let emit_fn =
            &mut |ino: u64, name: *const u8, name_len: u8, d_type: u8, _attr: &VAttr| -> bool {
                (*reply).label = TRONA_OK;
                (*reply).length = 5 + ((name_len as u64 + 7) / 8);
                (*reply).regs[0] = name_len as u64;
                (*reply).regs[1] = 0;
                (*reply).regs[2] = ino;
                (*reply).regs[3] = d_type as u64;
                for j in 4..20 {
                    (*reply).regs[j] = 0;
                }
                let dst = &raw mut (*reply).regs[4] as *mut u8;
                for j in 0..name_len as usize {
                    *dst.add(j) = *name.add(j);
                }
                got_entry = true;
                false
            };

        match ((*ops).data.readdir)(&data_ctx, &raw mut cookie_mut, emit_fn) {
            Ok(()) => {
                if let Some(slot) = resolve_fd_mut(state, cli_handle, fd) {
                    slot.dir_cursor = cookie_mut as u32;
                }
                if !got_entry {
                    (*reply).label = TRONA_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                }
            }
            Err(e) => {
                if !got_entry {
                    (*reply).label = e.to_trona();
                }
            }
        }
    }
}
