// SPDX-License-Identifier: GPL-2.0-only
//! Mutating file operations — VopMetaOps dispatch: close, lseek, unlink,
//! rename, mkdir, mkfifo, rmdir.

use trona_kernel::core_types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::resume::fs::FinalOpKind;
use crate::personality::posix::consts::{S_IFDIR_L, S_IFREG_L};
use crate::server::consts::*;
use crate::server::types::{ClientHandle, MAX_CLIENT_OBJECTS, ObjectKind};
use crate::vfs_core::file::VAttr;
use crate::vfs_core::identity::VnodeKey;
use crate::vfs_core::namei_common::{NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_WANTPARENT};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::{VT_DIR, VT_FIFO};

/// Resume entry for parked compound mutations that materialise a new
/// child vnode on the parent (`create`, `mkdir`, `symlink`).
///
/// The backend's completion router is responsible for parsing its
/// own reply payload, materialising the new child vnode into the
/// arena (so `new_vh` points at a live slot with its `VnodeKey`
/// installed in the resolve cache), translating any backend-level
/// failure into a `VfsError`, and invoking this helper with pre-
/// extracted generic data. This function stays backend-neutral:
/// it inspects `parse_err` / `new_vh` / `open_request` only.
///
/// * On `parse_err` set, emits an error reply translated from the
///   core `VfsError`.
/// * Otherwise, if `open_request` is present: runs
///   `open_vnode_owned` on the freshly-materialised child vnode
///   using the deferred request and forwards the resulting fd reply
///   to the waiting client.
/// * Otherwise (mkdirat / symlinkat / non-openat create), emits a
///   bare `TRONA_OK` ack.
pub(crate) unsafe fn resume_fill_final_op_child_reply(
    state: &mut VfsState,
    client: ClientHandle,
    parent_vkey: VnodeKey,
    _kind_hint: FinalOpKind,
    reply_slot: u64,
    _reply_msg: &TronaMsg,
    new_vh: Option<crate::vfs_core::vnode::VnodeHandle>,
    open_request: Option<crate::fileops::open::OpenRequest>,
    parse_err: Option<crate::vfs_core::error::VfsError>,
) {
    unsafe {
        // Parent vnode cache invalidation: a new child was added to
        // the directory, so (a) the parent's own resolve-cache entry
        // is forced to re-resolve on the next lookup and (b) every
        // open fd that has a `readdir_batch` snapshot of the parent
        // is cleared so subsequent `readdir` calls refetch instead
        // of draining stale records.
        state.invalidate_parent_dir_caches(parent_vkey);

        let mut out = TronaMsg::zeroed();
        if let Some(e) = parse_err {
            out.label = e.to_trona();
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        let Some(vh) = new_vh else {
            out.label = TRONA_OUT_OF_MEMORY;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        if let Some(request) = open_request {
            // Replay the deferred open on the freshly materialised
            // child. Reply shape matches the synchronous open path.
            crate::fileops::open::open_vnode_owned(state, client, vh, &request, &raw mut out);
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        // mkdirat / symlinkat / mkfifoat — bare TRONA_OK ack.
        out.label = TRONA_OK;
        out.length = 0;
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Emit the POSIX plain-ack reply for a completed compound mutation
/// (`unlink` / `rmdir` / `link` / `rename` / `truncate`). The backend
/// completion router has already performed any per-kind cache
/// invalidation / mmsrv-notify work before calling this helper; all
/// that remains is forwarding the `TRONA_*` label to the waiting
/// client.
pub(crate) unsafe fn resume_fill_final_op_ack_reply(
    state: &mut VfsState,
    reply_slot: u64,
    reply_msg: &TronaMsg,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();
        out.label = if reply_msg.label == TRONA_OK {
            TRONA_OK
        } else {
            reply_msg.label
        };
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Close an fd — owner-loop entry point.
///
/// Decrements the shared `OpenObject` refcount via
/// [`VfsState::close_open_object`]. The actual per-backing teardown
/// fires only when the last reference is gone and runs inside
/// `server::release::release_backing`.
pub(crate) unsafe fn handle_close_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        if state.clients.get(cli_handle).is_none() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        match state.close_open_object(cli_handle, fd as usize, badge) {
            Ok(()) => (*reply).label = TRONA_OK,
            Err(()) => (*reply).label = TRONA_INVALID_ARGUMENT,
        }
    }
}

/// unlink — owner-loop version.
///
/// No retry loop, no locks, no vrele — single-owner model.
pub(crate) unsafe fn handle_unlink_owned(
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
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        if !result.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Target must not be a directory.
        let target_vtype = state.vnodes.get(result.vp).map(|v| v.vtype).unwrap_or(0);
        if target_vtype == VT_DIR {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        // Call MetaOps::unlink on the parent directory.
        if let Some(mut ctx) =
            crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, result.dvp)
        {
            let ops = (*ctx.vnode).ops;
            if ops.is_null() {
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
            match ((*ops).meta.unlink)(&mut ctx, result.last_name, result.last_name_len) {
                Ok(Ready(())) => {
                    (*reply).label = TRONA_OK;
                }
                Ok(Parked(_)) => {
                    (*reply).label = TRONA_BUSY;
                }
                Err(e) => {
                    (*reply).label = e.to_trona();
                }
            }
        } else {
            (*reply).label = TRONA_NOT_SUPPORTED;
        }
    }
}

/// rename — owner-loop version.
pub(crate) unsafe fn handle_rename_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut old_len = (*msg).regs[0] as u8;
        let mut new_len = (*msg).regs[1] as u8;
        if (old_len as usize) > MAX_PATH_LEN {
            old_len = MAX_PATH_LEN as u8;
        }
        if (new_len as usize) > MAX_PATH_LEN {
            new_len = MAX_PATH_LEN as u8;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let mut old_abs = [0u8; MAX_PATH_LEN];
        let mut new_abs = [0u8; MAX_PATH_LEN];
        let raw = &(*msg).regs[2] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }
        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some((old_ptr, old_norm_len)) = crate::fileops::open::normalize_path_owned(
            state,
            cli_handle,
            old_path.as_ptr(),
            old_len,
            old_abs.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };
        let Some((new_ptr, new_norm_len)) = crate::fileops::open::normalize_path_owned(
            state,
            cli_handle,
            new_path.as_ptr(),
            new_len,
            new_abs.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);

        // Resolve old path parent.
        let old_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: old_ptr,
            path_len: old_norm_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let old_result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &old_args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !old_result.dvp.is_valid() || !old_result.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Resolve new path parent.
        let new_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: new_ptr,
            path_len: new_norm_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let new_result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &new_args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !new_result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Reject cross-mount rename early (EXDEV) — backend handles same-mount only.
        let old_mount_h = state
            .resolve_vnode_mount(old_result.dvp)
            .unwrap_or(crate::vfs_core::mount::MountHandle::INVALID);
        let new_mount_h = state
            .resolve_vnode_mount(new_result.dvp)
            .unwrap_or(crate::vfs_core::mount::MountHandle::INVALID);
        if old_mount_h != new_mount_h {
            (*reply).label = TRONA_CROSS_DEVICE;
            return;
        }

        let mut ctx =
            match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, old_result.dvp) {
                Some(c) => c,
                None => {
                    (*reply).label = TRONA_NOT_SUPPORTED;
                    return;
                }
            };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            (*reply).label = TRONA_NOT_SUPPORTED;
            return;
        }

        match ((*ops).meta.rename)(
            &mut ctx,
            old_result.last_name,
            old_result.last_name_len,
            new_result.dvp,
            new_result.last_name,
            new_result.last_name_len,
        ) {
            Ok(Ready(())) => {
                (*reply).label = TRONA_OK;
            }
            Ok(Parked(_)) => {
                (*reply).label = TRONA_BUSY;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

/// mkdir — owner-loop version.
pub(crate) unsafe fn handle_mkdir_owned(
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

        // Check if target already exists.
        let check_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };
        if let Ok(result) = crate::owner::dispatch::resolve_namei(state, cli_handle, &check_args) {
            if result.vp.is_valid() {
                (*reply).label = TRONA_ALREADY_EXISTS;
                return;
            }
        }

        // Resolve parent.
        let parent_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &parent_args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        if result.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        let mode = (*msg).regs[0] as u32 & 0o777;
        if let Some(mut ctx) =
            crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, result.dvp)
        {
            let ops = (*ctx.vnode).ops;
            if ops.is_null() {
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
            let create_mode = S_IFDIR_L | mode;
            match ((*ops).meta.mkdir)(
                &mut ctx,
                result.last_name,
                result.last_name_len,
                create_mode,
                &raw const cred,
            ) {
                Ok(_new_vh) => {
                    (*reply).label = TRONA_OK;
                }
                Err(e) => {
                    (*reply).label = e.to_trona();
                }
            }
        } else {
            (*reply).label = TRONA_NOT_SUPPORTED;
        }
    }
}

/// mkfifo — owner-loop version.
pub(crate) unsafe fn handle_mkfifo_owned(
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

        // Check if target already exists.
        let check_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };
        if let Ok(result) = crate::owner::dispatch::resolve_namei(state, cli_handle, &check_args) {
            if result.vp.is_valid() {
                (*reply).label = TRONA_ALREADY_EXISTS;
                return;
            }
        }

        // Allocate a pipe via VfsState arena.
        let pipe_handle = match crate::fileops::pipe::alloc_pipe(state) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        // Resolve parent directory.
        let parent_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &parent_args) {
            Ok(r) => r,
            Err(e) => {
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !result.dvp.is_valid() {
            crate::fileops::pipe::release_pipe(state, pipe_handle);
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        if result.vp.is_valid() {
            crate::fileops::pipe::release_pipe(state, pipe_handle);
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        let mode = (*msg).regs[0] as u32 & 0o777;
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, result.dvp)
        {
            Some(c) => c,
            None => {
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            crate::fileops::pipe::release_pipe(state, pipe_handle);
            (*reply).label = TRONA_NOT_SUPPORTED;
            return;
        }

        let create_mode = S_IFREG_L | mode;
        let new_vh = match ((*ops).meta.create)(
            &mut ctx,
            result.last_name,
            result.last_name_len,
            create_mode,
            &raw const cred,
        ) {
            Ok(Ready(vh)) => vh,
            Ok(Parked(_)) => {
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = TRONA_BUSY;
                return;
            }
            Err(_) => {
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        // Set FIFO metadata on the new vnode.
        if let Some(vnode) = state.vnodes.get_mut(new_vh) {
            vnode.vtype = VT_FIFO;
            if vnode.ops == &raw const crate::fs::ramfs::RAMFS_VOPS {
                let vd = vnode.data as *mut crate::fs::ramfs::RamfsVnodeData;
                (*vd).ftype = VT_FIFO;
                (*vd).fifo_pipe = pipe_handle;
            } else if vnode.ops == &raw const crate::fs::tmpfs::TMPFS_VOPS {
                let vd = vnode.data as *mut crate::fs::tmpfs::TmpfsVnodeData;
                (*vd).ftype = VT_FIFO;
                (*vd).fifo_pipe = pipe_handle;
            } else {
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
        }

        (*reply).label = TRONA_OK;
    }
}

/// rmdir — owner-loop version.
pub(crate) unsafe fn handle_rmdir_owned(
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
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        if !result.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Target must be a directory.
        let target_vtype = state.vnodes.get(result.vp).map(|v| v.vtype).unwrap_or(0);
        if target_vtype != VT_DIR {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Must not be a mount point.
        let is_covered = state
            .vnodes
            .get(result.vp)
            .map(|v| v.covered_by.id().is_valid())
            .unwrap_or(false);
        if is_covered {
            (*reply).label = TRONA_BUSY;
            return;
        }

        if let Some(mut ctx) =
            crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, result.dvp)
        {
            let ops = (*ctx.vnode).ops;
            if ops.is_null() {
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
            match ((*ops).meta.rmdir)(&mut ctx, result.last_name, result.last_name_len) {
                Ok(Ready(())) => {
                    (*reply).label = TRONA_OK;
                }
                Ok(Parked(_)) => {
                    (*reply).label = TRONA_BUSY;
                }
                Err(e) => {
                    (*reply).label = e.to_trona();
                }
            }
        } else {
            (*reply).label = TRONA_NOT_SUPPORTED;
        }
    }
}

/// Lseek — owner-loop version.
pub(crate) unsafe fn handle_lseek_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let offset = (*msg).regs[1] as i64;
        let whence = (*msg).regs[2] as i32;

        let (kind, vnode_handle, current_offset) = {
            match crate::owner::dispatch::resolve_fd(state, cli_handle, fd) {
                Some(s) => (s.kind(), s.vnode_handle(), s.offset),
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            }
        };

        if kind != ObjectKind::File {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let file_size: u64 = if vnode_handle.is_valid() {
            if let Some(mut ctx) =
                crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vnode_handle)
            {
                let ops = (*ctx.vnode).ops;
                let sz = if !ops.is_null() {
                    let mut attr = VAttr::zeroed();
                    let _ = ((*ops).meta.getattr)(&mut ctx, &raw mut attr);
                    attr.size
                } else {
                    0
                };
                sz
            } else {
                0
            }
        } else {
            0
        };

        let new_offset: i64 = match whence {
            0 => offset,
            1 => current_offset as i64 + offset,
            2 => file_size as i64 + offset,
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        if new_offset < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if let Some(slot_mut) = crate::owner::dispatch::resolve_fd_mut(state, cli_handle, fd) {
            slot_mut.offset = new_offset as u64;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_offset as u64;
    }
}
