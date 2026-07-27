// SPDX-License-Identifier: GPL-2.0-only
//! unlinkat, renameat, mkdirat, linkat

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, client_cred, cwd_vnode_for, root_vnode_for};
use crate::owner::resume::{
    Resume,
    fs::{FinalOpKind, FsResume},
};
use crate::personality::posix::consts::*;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_WANTPARENT, NameiArgs};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::{VT_DIR, VnodeHandle};

/// Stamp a `FsResume::FinalOpChild` continuation on a parked mutation
/// that materialises a new child vnode (`mkdirat` / `symlinkat`).
/// `open_request = None` because these dispatch paths do not open an
/// fd — the completion router emits a bare `TRONA_OK` ack.
pub(crate) unsafe fn finalise_final_op_child_parked(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    parent_vkey: crate::vfs_core::identity::VnodeKey,
    kind_hint: FinalOpKind,
    handle: crate::owner::pending::PendingOpHandle,
    reply: *mut TronaMsg,
    uid: u32,
    gid: u32,
) -> bool {
    unsafe {
        finalise_with_resume(
            state,
            cli_handle,
            handle,
            reply,
            Resume::Fs(FsResume::FinalOpChild {
                client: cli_handle,
                parent_vkey,
                kind_hint,
                open_request: None,
                creds_uid: uid,
                creds_gid: gid,
            }),
        )
    }
}

/// Stamp a `FsResume` continuation on a parked op. Shared boilerplate
/// for every async dispatch path: allocate a reply slot, save the
/// client's caller cap, and stamp the resume context. Returns `true`
/// on successful deferral; on failure the error label is written to
/// `reply` and the pending op is cancelled.
pub(crate) unsafe fn finalise_with_resume(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    handle: crate::owner::pending::PendingOpHandle,
    reply: *mut TronaMsg,
    resume: Resume,
) -> bool {
    unsafe {
        if let Err(err) = state.arm_pending_fs_reply_for_client(handle, cli_handle, resume) {
            (*reply).label = err.to_trona();
            return false;
        }
        true
    }
}

use super::at_open::resolve_dirfd_vnode;

/// unlinkat(dirfd, path, flags). Returns `true` when the reply was
/// deferred (saltyfs parked the mutation); `false` when `reply` was
/// populated synchronously.
pub(crate) unsafe fn handle_unlinkat(
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

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let is_rmdir = (at_flags & AT_REMOVEDIR_VAL) != 0;

        let start = resolve_dirfd_vnode(state, cli_handle, dirfd);
        if !start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        let mut namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: path.as_ptr(),
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                (*reply).label = e.to_trona();
                return false;
            }
        };

        if !ni.vp.is_valid() || !ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Check type: unlinkat without AT_REMOVEDIR must not target a dir,
        // with AT_REMOVEDIR must target a dir.
        if let Some(vnode) = state.vnodes.get(ni.vp) {
            if is_rmdir && vnode.vtype != VT_DIR {
                (*reply).label = TRONA_NOT_FOUND;
                return false;
            }
            if !is_rmdir && vnode.vtype == VT_DIR {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
        }

        let removed_child_vkey = state
            .vnodes
            .get(ni.vp)
            .map(|v| v.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, ni.dvp) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_IO_ERROR;
                return false;
            }
        };
        let parent_vkey = (*ctx.vnode).vnode_key();
        let ops = &*(*ctx.vnode).ops;
        let result = if is_rmdir {
            (ops.meta.rmdir)(&mut ctx, ni.last_name, ni.last_name_len)
        } else {
            (ops.meta.unlink)(&mut ctx, ni.last_name, ni.last_name_len)
        };

        match result {
            Ok(Ready(())) => {
                // Sync success: invalidate the removed child's
                // resolve-cache entry and clear any open fd's
                // readdir_batch snapshot of the parent directory so
                // concurrent readers don't keep draining stale
                // entries.
                if removed_child_vkey.is_valid() {
                    state.invalidate_resolve_cache_for(removed_child_vkey);
                }
                state.invalidate_parent_dir_caches(parent_vkey);
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => {
                let kind = if is_rmdir {
                    crate::owner::resume::fs::FinalOpRemovalKind::Rmdir
                } else {
                    crate::owner::resume::fs::FinalOpRemovalKind::Unlink
                };
                finalise_with_resume(
                    state,
                    cli_handle,
                    handle,
                    reply,
                    Resume::Fs(FsResume::FinalOpAckRemoval {
                        client: cli_handle,
                        parent_vkey,
                        removed_child_vkey,
                        kind,
                    }),
                )
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// renameat(olddirfd, oldpath, newdirfd, newpath)
///
/// Returns `true` when the reply is deferred (saltyfs parked the
/// rename RPC); `false` when the reply is already populated.
pub(crate) unsafe fn handle_renameat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let old_len = (*msg).regs[2] as u8;
        let new_len = (*msg).regs[3] as u8;

        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
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
            return false;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        // Resolve old path
        let mut namei_ctx = build_namei_ctx(state);
        let old_args = NameiArgs {
            start: old_start,
            path: old_path.as_ptr(),
            path_len: old_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let old_ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &old_args)
        {
            Ok(ni) => ni,
            Err(e) => {
                (*reply).label = e.to_trona();
                return false;
            }
        };

        if !old_ni.vp.is_valid() || !old_ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Resolve new path parent
        let mut namei_ctx2 = build_namei_ctx(state);
        let new_args = NameiArgs {
            start: new_start,
            path: new_path.as_ptr(),
            path_len: new_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let new_ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx2, &new_args)
        {
            Ok(ni) => ni,
            Err(e) => {
                (*reply).label = e.to_trona();
                return false;
            }
        };

        if !new_ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Reject cross-mount rename pre-issue. The backend's rename VOP
        // reinterprets `VopContext.data` as its own vnode-data struct;
        // letting a foreign-backend new-parent vnode reach that cast is
        // undefined behaviour (arbitrary bytes read as saltyfs/ramfs
        // layout). POSIX returns EXDEV for this case.
        let (old_fs_id, new_fs_id) =
            match (state.vnodes.get(old_ni.dvp), state.vnodes.get(new_ni.dvp)) {
                (Some(ovp), Some(nvp)) => (ovp.fs_instance_id, nvp.fs_instance_id),
                _ => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
            };
        if old_fs_id != new_fs_id {
            (*reply).label = TRONA_CROSS_DEVICE;
            return false;
        }

        // Call rename via VopMetaOps on old parent
        let new_parent_vkey = state
            .vnodes
            .get(new_ni.dvp)
            .map(|v| v.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        let old_parent_vkey = state
            .vnodes
            .get(old_ni.dvp)
            .map(|v| v.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        let mut old_ctx =
            match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, old_ni.dvp) {
                Some(c) => c,
                None => {
                    (*reply).label = TRONA_IO_ERROR;
                    return false;
                }
            };
        let ops = &*(*old_ctx.vnode).ops;
        let rename_result = (ops.meta.rename)(
            &mut old_ctx,
            old_ni.last_name,
            old_ni.last_name_len,
            new_ni.dvp,
            new_ni.last_name,
            new_ni.last_name_len,
        );
        match rename_result {
            Ok(Ready(())) => {
                // Cross-directory rename affects two parents; intra-
                // directory rename's old_parent == new_parent so the
                // second call is a cheap no-op cache lookup.
                state.invalidate_parent_dir_caches(new_parent_vkey);
                if old_parent_vkey != new_parent_vkey {
                    state.invalidate_parent_dir_caches(old_parent_vkey);
                }
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => finalise_with_resume(
                state,
                cli_handle,
                handle,
                reply,
                Resume::Fs(FsResume::FinalOpAckRename {
                    client: cli_handle,
                    new_parent_vkey,
                    old_parent_vkey,
                }),
            ),
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// mkdirat(dirfd, path, mode)
///
/// Returns `true` when the reply is deferred (saltyfs parked the
/// mkdir RPC); `false` when the reply is already populated.
pub(crate) unsafe fn handle_mkdirat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let start = resolve_dirfd_vnode(state, cli_handle, dirfd);
        if !start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        let mut namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: path.as_ptr(),
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                (*reply).label = e.to_trona();
                return false;
            }
        };

        if ni.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return false;
        }
        if !ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        let parent_vkey = state
            .vnodes
            .get(ni.dvp)
            .map(|v| v.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, ni.dvp) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_IO_ERROR;
                return false;
            }
        };
        let ops = &*(*ctx.vnode).ops;
        let result = (ops.meta.mkdir)(
            &mut ctx,
            ni.last_name,
            ni.last_name_len,
            S_IFDIR_L | (mode & 0o777),
            &raw const cred,
        );
        match result {
            Ok(Ready(_)) => {
                state.invalidate_parent_dir_caches(parent_vkey);
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => finalise_final_op_child_parked(
                state,
                cli_handle,
                parent_vkey,
                FinalOpKind::Mkdir,
                handle,
                reply,
                cred.euid,
                cred.egid,
            ),
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
///
/// Returns `true` when the reply is deferred (saltyfs parked the
/// link RPC); `false` when the reply is already populated.
pub(crate) unsafe fn handle_linkat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let at_flags = (*msg).regs[2] as i32;
        let old_len = (*msg).regs[3] as u8;
        let new_len = (*msg).regs[4] as u8;

        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
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
            return false;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        // Resolve old path (the source)
        let mut namei_ctx = build_namei_ctx(state);
        let old_args = NameiArgs {
            start: old_start,
            path: old_path.as_ptr(),
            path_len: old_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };
        let old_ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &old_args)
        {
            Ok(ni) => ni,
            Err(e) => {
                (*reply).label = e.to_trona();
                return false;
            }
        };

        if !old_ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Resolve new path parent
        let mut namei_ctx2 = build_namei_ctx(state);
        let new_args = NameiArgs {
            start: new_start,
            path: new_path.as_ptr(),
            path_len: new_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let new_ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx2, &new_args)
        {
            Ok(ni) => ni,
            Err(e) => {
                (*reply).label = e.to_trona();
                return false;
            }
        };

        if new_ni.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return false;
        }
        if !new_ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Cross-mount link is forbidden (POSIX EXDEV). Same rationale
        // as `handle_renameat`: the target backend's `link` VOP
        // reinterprets the source vnode's `data` as its own struct
        // layout, which is UB for foreign backends.
        let (src_fs_id, dst_fs_id) =
            match (state.vnodes.get(old_ni.vp), state.vnodes.get(new_ni.dvp)) {
                (Some(ovp), Some(nvp)) => (ovp.fs_instance_id, nvp.fs_instance_id),
                _ => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
            };
        if src_fs_id != dst_fs_id {
            (*reply).label = TRONA_CROSS_DEVICE;
            return false;
        }

        // link(new_parent, new_name, old_vnode)
        let new_parent_vkey = state
            .vnodes
            .get(new_ni.dvp)
            .map(|v| v.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, new_ni.dvp)
        {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_IO_ERROR;
                return false;
            }
        };
        let ops = &*(*ctx.vnode).ops;
        let result = (ops.meta.link)(&mut ctx, new_ni.last_name, new_ni.last_name_len, old_ni.vp);
        let _ = at_flags;
        match result {
            Ok(Ready(())) => {
                state.invalidate_parent_dir_caches(new_parent_vkey);
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => finalise_with_resume(
                state,
                cli_handle,
                handle,
                reply,
                Resume::Fs(FsResume::FinalOpAckLink {
                    client: cli_handle,
                    new_parent_vkey,
                }),
            ),
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}
