// SPDX-License-Identifier: GPL-2.0-only
//! fchmodat, fchownat, fchmod, fchown, utimensat, symlinkat, readlinkat

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{
    build_namei_ctx, client_cred, cwd_vnode_for, resolve_fd, root_vnode_for,
};
use crate::owner::resume::{Resume, fs::FsResume};
use crate::personality::posix::consts::*;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{
    NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_NOFOLLOW_FINAL, NAMEI_WANTPARENT, NameiArgs,
};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::VnodeHandle;

use super::at_open::resolve_dirfd_vnode;

/// Finalise a parked `setattr` RPC: allocate a deferred reply slot,
/// save the caller cap, and stamp `FsResume::AckMutation` so the
/// completion router can emit the client's ack. Returns `true` on
/// successful stamp (caller keeps `skip_reply = true`); `false` on
/// any failure (caller writes the emitted error label into `reply`).
unsafe fn finalise_setattr_parked(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    vkey: crate::vfs_core::identity::VnodeKey,
    handle: crate::owner::pending::PendingOpHandle,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if let Err(err) = state.arm_pending_fs_reply_for_client(
            handle,
            cli_handle,
            Resume::Fs(FsResume::AckMutation {
                client: cli_handle,
                vkey,
            }),
        ) {
            (*reply).label = err.to_trona();
            return false;
        }
        true
    }
}

/// Common pattern: resolve path via namei from dirfd, then call a VopMetaOps
/// callback. Returns `true` when the reply was deferred via `AckMutation`.
unsafe fn resolve_and_setattr(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    dirfd: i32,
    path: &[u8],
    path_len: u8,
    namei_flags: u32,
    attr: &VAttr,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
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
            flags: namei_flags,
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

        if !ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, ni.vp) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_IO_ERROR;
                return false;
            }
        };
        let vkey = (*ctx.vnode).vnode_key();
        let ops = &*(*ctx.vnode).ops;
        let result = (ops.meta.setattr)(&mut ctx, &raw const *attr);
        match result {
            Ok(Ready(())) => {
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => finalise_setattr_parked(state, cli_handle, vkey, handle, reply),
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// Invoke `meta.setattr` on a resolved `VnodeHandle` (fd-based
/// variants of chmod/chown/utimensat). Returns `true` when the reply
/// is deferred via `AckMutation`.
unsafe fn setattr_on_vh(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    vh: VnodeHandle,
    attr: &VAttr,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_IO_ERROR;
                return false;
            }
        };
        let vkey = (*ctx.vnode).vnode_key();
        let ops = &*(*ctx.vnode).ops;
        let result = (ops.meta.setattr)(&mut ctx, &raw const *attr);
        match result {
            Ok(Ready(())) => {
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => finalise_setattr_parked(state, cli_handle, vkey, handle, reply),
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// fchmodat(dirfd, path, mode, flags)
pub(crate) unsafe fn handle_fchmodat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        let mut attr = VAttr::zeroed();
        attr.mode = mode;
        resolve_and_setattr(
            state,
            cli_handle,
            dirfd,
            &path,
            path_len,
            NAMEI_FOLLOW,
            &attr,
            reply,
        )
    }
}

/// fchownat(dirfd, path, uid, gid, flags)
pub(crate) unsafe fn handle_fchownat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let uid = (*msg).regs[1] as u32;
        let gid = (*msg).regs[2] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 4, path.as_mut_ptr());

        let at_flags = (*msg).regs[3] as i32;
        let namei_flags = if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
            NAMEI_NOFOLLOW_FINAL
        } else {
            NAMEI_FOLLOW
        };

        let mut attr = VAttr::zeroed();
        attr.uid = uid;
        attr.gid = gid;
        resolve_and_setattr(
            state,
            cli_handle,
            dirfd,
            &path,
            path_len,
            namei_flags,
            &attr,
            reply,
        )
    }
}

/// fchmod(fd, mode)
pub(crate) unsafe fn handle_fchmod(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let vh = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.vnode_handle().is_valid() => obj.vnode_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let mut attr = VAttr::zeroed();
        attr.mode = mode;
        setattr_on_vh(state, cli_handle, vh, &attr, reply)
    }
}

/// fchown(fd, uid, gid)
pub(crate) unsafe fn handle_fchown(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let uid = (*msg).regs[1] as u32;
        let gid = (*msg).regs[2] as u32;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let vh = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.vnode_handle().is_valid() => obj.vnode_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let mut attr = VAttr::zeroed();
        attr.uid = uid;
        attr.gid = gid;
        setattr_on_vh(state, cli_handle, vh, &attr, reply)
    }
}

/// utimensat(dirfd, path, times, flags)
pub(crate) unsafe fn handle_utimensat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let atime_ns = (*msg).regs[4];
        let mtime_ns = (*msg).regs[5];
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        // fd-based utimensat (AT_EMPTY_PATH with fd)
        if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 && dirfd >= 0 {
            if dirfd as usize >= MAX_CLIENT_OBJECTS {
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
            let mut attr = VAttr::zeroed();
            attr.atime = atime_ns;
            attr.mtime = mtime_ns;
            return setattr_on_vh(state, cli_handle, vh, &attr, reply);
        }

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let namei_flags = if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
            NAMEI_NOFOLLOW_FINAL
        } else {
            NAMEI_FOLLOW
        };

        let mut attr = VAttr::zeroed();
        attr.atime = atime_ns;
        attr.mtime = mtime_ns;
        resolve_and_setattr(
            state,
            cli_handle,
            dirfd,
            &path,
            path_len,
            namei_flags,
            &attr,
            reply,
        )
    }
}

/// symlinkat(target, dirfd, linkpath)
///
/// Returns `true` when the reply is deferred; `false` otherwise.
pub(crate) unsafe fn handle_symlinkat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let target_len = (*msg).regs[0] as u8;
        let dirfd = (*msg).regs[1] as i32;
        let mut link_path = [0u8; MAX_PATH_LEN];
        let link_len = extract_path(msg, 2, link_path.as_mut_ptr());

        if target_len == 0 || link_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        // Extract target string from msg after link path.
        let mut target = [0u8; MAX_PATH_LEN];
        let target_src = &(*msg).regs[3 + ((link_len as usize + 7) / 8)] as *const u64 as *const u8;
        for i in 0..target_len as usize {
            target[i] = *target_src.add(i);
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
            path: link_path.as_ptr(),
            path_len: link_len as u16,
            flags: NAMEI_CREATE | NAMEI_WANTPARENT,
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
        let result = (ops.meta.symlink)(
            &mut ctx,
            ni.last_name,
            ni.last_name_len,
            target.as_ptr(),
            target_len,
            &raw const cred,
        );
        match result {
            Ok(Ready(_)) => {
                state.invalidate_parent_dir_caches(parent_vkey);
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => {
                crate::personality::posix::at_ops::at_mutate::finalise_final_op_child_parked(
                    state,
                    cli_handle,
                    parent_vkey,
                    crate::owner::resume::fs::FinalOpKind::Symlink,
                    handle,
                    reply,
                    cred.euid,
                    cred.egid,
                )
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// readlinkat(dirfd, path, buf, bufsiz)
///
/// Returns `true` when the reply is deferred (the backend parked the RPC);
/// `false` when `reply` was populated synchronously.
pub(crate) unsafe fn handle_readlinkat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 1, path.as_mut_ptr());

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
        // `readlinkat` contributes only the dirfd/root anchors; the
        // shared helper now owns async path walk and terminal readlink.
        crate::fileops::attr::readlink_path_from_start_owned(
            state,
            cli_handle,
            start,
            root,
            path.as_ptr(),
            path_len,
            reply,
        )
    }
}
