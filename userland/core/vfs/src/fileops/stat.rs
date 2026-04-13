// SPDX-License-Identifier: GPL-2.0-only
//! Stat and access operations — VopMetaOps dispatch.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{resolve_fd, build_data_ctx};
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::vnode::VnodeHandle;

use crate::server::types::ClientHandle;

/// Fill stat reply from a VnodeHandle via MetaOps::getattr.
unsafe fn fill_stat_reply_handle(
    state: &mut VfsState,
    reply: *mut TronaMsg,
    vh: VnodeHandle,
) {
    unsafe {
        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vh) {
            let vnode = &*ctx.vnode;
            let ops = vnode.ops;
            if ops.is_null() {
                crate::vfs_core::mount_ctl::clear_trampolines();
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            let mut attr = VAttr::zeroed();
            match ((*ops).meta.getattr)(&ctx, &raw mut attr) {
                Ok(()) => {
                    (*reply).label = TRONA_OK;
                    (*reply).length = 8;
                    (*reply).regs[0] = vnode.id;
                    (*reply).regs[1] = attr.mode as u64;
                    (*reply).regs[2] = attr.nlink as u64;
                    (*reply).regs[3] = attr.size;
                    (*reply).regs[4] = attr.uid as u64;
                    (*reply).regs[5] = attr.gid as u64;
                    (*reply).regs[6] = attr.mtime / 1_000_000_000;
                    (*reply).regs[7] = vnode.vtype as u64;
                }
                Err(e) => {
                    (*reply).label = e.to_trona();
                }
            }
            crate::vfs_core::mount_ctl::clear_trampolines();
        } else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
        }
    }
}

/// fstat — owner-loop version.
pub(crate) unsafe fn handle_fstat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let vh = match resolve_fd(state, cli_handle, fd) {
            Some(s) if s.vnode_handle().is_valid() => s.vnode_handle(),
            _ => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        fill_stat_reply_handle(state, reply, vh);
    }
}

/// stat — owner-loop version. Path-based stat via handle-based namei.
pub(crate) unsafe fn handle_stat_owned(
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
        let Some((path_ptr, path_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
            )
        else {
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

        match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(result) => {
                if result.vp.is_valid() {
                    fill_stat_reply_handle(state, reply, result.vp);
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                }
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

/// stat_for_exec — owner-loop version.
pub(crate) unsafe fn handle_stat_for_exec_owned(
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
        let Some((path_ptr, path_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
            )
        else {
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
            cred: cred.clone(),
            root,
        };

        match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(result) => {
                if !result.vp.is_valid() {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }

                // X_OK permission check via MetaOps::access.
                if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, result.vp) {
                    let ops = (*ctx.vnode).ops;
                    if ops.is_null() {
                        crate::vfs_core::mount_ctl::clear_trampolines();
                        (*reply).label = TRONA_NOT_FOUND;
                        return;
                    }
                    if let Err(_) = ((*ops).meta.access)(&ctx, X_OK as u32, &raw const cred) {
                        crate::vfs_core::mount_ctl::clear_trampolines();
                        (*reply).label = TRONA_INSUFFICIENT_RIGHTS;
                        return;
                    }
                    let mut attr = VAttr::zeroed();
                    match ((*ops).meta.getattr)(&ctx, &raw mut attr) {
                        Ok(()) => {
                            (*reply).label = TRONA_OK;
                            (*reply).length = 4;
                            (*reply).regs[0] = attr.mode as u64;
                            (*reply).regs[1] = attr.uid as u64;
                            (*reply).regs[2] = attr.gid as u64;
                            (*reply).regs[3] = attr.size;
                        }
                        Err(e) => {
                            (*reply).label = e.to_trona();
                        }
                    }
                    crate::vfs_core::mount_ctl::clear_trampolines();
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                }
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

/// canon_path — owner-loop version. Pure path canonicalization, no VOP calls.
pub(crate) unsafe fn handle_canon_path_owned(
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
        let Some((path_ptr, path_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
            )
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        (*reply).label = TRONA_OK;
        (*reply).regs[0] = path_len as u64;
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path_ptr.add(i);
        }
        (*reply).length = 1 + ((path_len as u64 + 7) / 8);
    }
}

/// access — owner-loop version.
pub(crate) unsafe fn handle_access_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
            )
        else {
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
            cred: cred.clone(),
            root,
        };

        match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(result) => {
                if !result.vp.is_valid() {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
                let amode = (*msg).regs[0] as u32;
                if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, result.vp) {
                    let ops = (*ctx.vnode).ops;
                    if !ops.is_null() {
                        match ((*ops).meta.access)(&ctx, amode, &raw const cred) {
                            Ok(()) => { (*reply).label = TRONA_OK; }
                            Err(e) => { (*reply).label = e.to_trona(); }
                        }
                    } else {
                        (*reply).label = TRONA_OK;
                    }
                    crate::vfs_core::mount_ctl::clear_trampolines();
                } else {
                    (*reply).label = TRONA_OK;
                }
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}
