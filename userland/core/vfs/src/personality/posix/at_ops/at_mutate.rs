// SPDX-License-Identifier: GPL-2.0-only
//! unlinkat, renameat, mkdirat, linkat

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, client_cred, root_vnode_for, cwd_vnode_for};
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{
    NameiArgs, NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_WANTPARENT,
};
use crate::vfs_core::vnode::{VnodeHandle, VT_DIR};

use super::at_open::resolve_dirfd_vnode;

/// unlinkat(dirfd, path, flags)
pub(crate) unsafe fn handle_unlinkat(
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

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let is_rmdir = (at_flags & AT_REMOVEDIR_VAL) != 0;

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
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
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

        if !ni.vp.is_valid() || !ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Check type: unlinkat without AT_REMOVEDIR must not target a dir,
        // with AT_REMOVEDIR must target a dir.
        if let Some(vnode) = state.vnodes.get(ni.vp) {
            if is_rmdir && vnode.vtype != VT_DIR {
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            if !is_rmdir && vnode.vtype == VT_DIR {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
        }

        let ctx = match mount_ctl::build_vop_context(state, ni.dvp) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let ops = &*(*ctx.vnode).ops;
        let result = if is_rmdir {
            (ops.meta.rmdir)(&ctx, ni.last_name, ni.last_name_len)
        } else {
            (ops.meta.unlink)(&ctx, ni.last_name, ni.last_name_len)
        };
        mount_ctl::clear_trampolines();

        match result {
            Ok(()) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
    }
}

/// renameat(olddirfd, oldpath, newdirfd, newpath)
pub(crate) unsafe fn handle_renameat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let old_len = (*msg).regs[2] as u8;
        let new_len = (*msg).regs[3] as u8;

        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let raw = &(*msg).regs[4] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }

        let old_start = resolve_dirfd_vnode(state, cli_handle, old_dirfd);
        let new_start = resolve_dirfd_vnode(state, cli_handle, new_dirfd);
        if !old_start.is_valid() || !new_start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        // Resolve old path
        let namei_ctx = build_namei_ctx(state);
        let old_args = NameiArgs {
            start: old_start,
            path: old_path.as_ptr(),
            path_len: old_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let old_ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &old_args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if !old_ni.vp.is_valid() || !old_ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Resolve new path parent
        let namei_ctx2 = build_namei_ctx(state);
        let new_args = NameiArgs {
            start: new_start,
            path: new_path.as_ptr(),
            path_len: new_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let new_ni = match crate::personality::posix::namei::namei_posix(&namei_ctx2, &new_args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if !new_ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Call rename via VopMetaOps on old parent
        let old_ctx = match mount_ctl::build_vop_context(state, old_ni.dvp) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        // Build new parent context (for cross-directory rename)
        let new_ctx = match mount_ctl::build_vop_context(state, new_ni.dvp) {
            Some(c) => c,
            None => {
                mount_ctl::clear_trampolines();
                (*reply).label = TRONA_IO_ERROR;
                return;
            }
        };
        let ops = &*(*old_ctx.vnode).ops;
        match (ops.meta.rename)(
            &old_ctx,
            old_ni.last_name,
            old_ni.last_name_len,
            &new_ctx,
            new_ni.last_name,
            new_ni.last_name_len,
        ) {
            Ok(()) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
        mount_ctl::clear_trampolines();
    }
}

/// mkdirat(dirfd, path, mode)
pub(crate) unsafe fn handle_mkdirat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

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
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
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

        if ni.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }
        if !ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let ctx = match mount_ctl::build_vop_context(state, ni.dvp) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let ops = &*(*ctx.vnode).ops;
        match (ops.meta.mkdir)(
            &ctx,
            ni.last_name,
            ni.last_name_len,
            S_IFDIR_L | (mode & 0o777),
            &raw const cred,
        ) {
            Ok(_) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
        mount_ctl::clear_trampolines();
    }
}

/// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
pub(crate) unsafe fn handle_linkat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let at_flags = (*msg).regs[2] as i32;
        let old_len = (*msg).regs[3] as u8;
        let new_len = (*msg).regs[4] as u8;

        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let raw = &(*msg).regs[5] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }

        let old_start = resolve_dirfd_vnode(state, cli_handle, old_dirfd);
        let new_start = resolve_dirfd_vnode(state, cli_handle, new_dirfd);
        if !old_start.is_valid() || !new_start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        // Resolve old path (the source)
        let namei_ctx = build_namei_ctx(state);
        let old_args = NameiArgs {
            start: old_start,
            path: old_path.as_ptr(),
            path_len: old_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };
        let old_ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &old_args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if !old_ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Resolve new path parent
        let namei_ctx2 = build_namei_ctx(state);
        let new_args = NameiArgs {
            start: new_start,
            path: new_path.as_ptr(),
            path_len: new_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let new_ni = match crate::personality::posix::namei::namei_posix(&namei_ctx2, &new_args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if new_ni.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }
        if !new_ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // link(new_parent, new_name, old_vnode)
        let ctx = match mount_ctl::build_vop_context(state, new_ni.dvp) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let ops = &*(*ctx.vnode).ops;
        match (ops.meta.link)(
            &ctx,
            new_ni.last_name,
            new_ni.last_name_len,
            old_ni.vp,
        ) {
            Ok(()) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
        mount_ctl::clear_trampolines();
    }
}
