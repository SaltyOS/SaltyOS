// SPDX-License-Identifier: GPL-2.0-only
//! CWD and access helpers.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::client::{
    MAX_PATH_LEN, extract_path, normalize_path_at_owned, normalize_path_owned,
    write_inline_path_reply,
};
use crate::server::types::{ClientHandle, PERS_WIN32};
use crate::vfs_core::vnode::VT_DIR;

unsafe fn chdir_continuation_adopt(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    explicit_drive: Option<usize>,
    reply: *mut TronaMsg,
) {
    let body = crate::owner::namei::ChdirContBody {
        explicit_drive: explicit_drive.map(|idx| idx as i8).unwrap_or(-1),
        _pad0: [0; 7],
        _reserved: [0; 88],
    };
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_CHDIR_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_CHDIR,
            crate::owner::namei::namei_aux_chdir(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_chdir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let Some(path_len) = normalize_path_owned(
            state,
            cli_handle,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        let is_win32 = state
            .clients
            .get(cli_handle)
            .map(|client| client.personality == PERS_WIN32)
            .unwrap_or(false);
        let explicit_drive = if is_win32 {
            crate::personality::win32::path::explicit_drive_index(path.as_ptr(), raw_len)
        } else {
            None
        };

        let vh =
            match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], false) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                    (*reply).label = TRONA_NOT_FOUND;
                    (*reply).length = 0;
                    return;
                }
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                    chdir_continuation_adopt(
                        state,
                        cli_handle,
                        op_id,
                        &abs_path[..path_len],
                        explicit_drive,
                        reply,
                    );
                    return;
                }
                Err(err) => {
                    (*reply).label = err;
                    (*reply).length = 0;
                    return;
                }
            };
        let Some(vnode) = state.vnodes.get(vh) else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };
        if vnode.vtype != VT_DIR {
            (*reply).label = TRONA_NOT_DIRECTORY;
            (*reply).length = 0;
            return;
        }

        let Some(cwd_anchor) = state.anchor_for_vnode(vh) else {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        };
        let Some(client) = state.clients.get_mut(cli_handle) else {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        };
        client.cwd_anchor = cwd_anchor;
        if is_win32 {
            if let Some(drive_index) = explicit_drive {
                state.update_win32_client_cwd_for_drive(cli_handle, drive_index, vh);
            } else {
                state.update_win32_client_cwd(cli_handle, vh);
            }
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_getcwd_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let size = (*msg).regs[0] as usize;
        let Some(client) = state.clients.get(cli_handle) else {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        };
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = if client.personality == PERS_WIN32 {
            let cwd_anchor = if client.cwd_anchor.is_valid() {
                client.cwd_anchor
            } else {
                match state.root_vnode().and_then(|vh| state.anchor_for_vnode(vh)) {
                    Some(anchor) => anchor,
                    None => {
                        (*reply).label = TRONA_INVALID_OPERATION;
                        (*reply).length = 0;
                        return;
                    }
                }
            };
            match crate::personality::win32::path::render_anchor_path_owned(
                state,
                cli_handle,
                cwd_anchor,
                path.as_mut_ptr(),
            ) {
                Ok(len) => len,
                Err(err) => {
                    (*reply).label = err;
                    (*reply).length = 0;
                    return;
                }
            }
        } else {
            let base_anchor = if client.cwd_anchor.is_valid() {
                Some(client.cwd_anchor)
            } else {
                state.root_vnode().and_then(|vh| state.anchor_for_vnode(vh))
            };
            let Some(base_anchor) = base_anchor else {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return;
            };
            let Some(path_len) = state.render_anchor_path(base_anchor, &mut path) else {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return;
            };
            path_len
        };
        if size == 0 || path_len + 1 > size {
            (*reply).label = TRONA_OUT_OF_RANGE;
            (*reply).length = 0;
            return;
        }
        write_inline_path_reply(reply, path.as_ptr(), path_len);
    }
}

fn access_reply_for_vnode(
    state: &VfsState,
    vh: crate::vfs_core::vnode::VnodeHandle,
    mode: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let Some(vnode) = state.vnodes.get(vh) else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };

        let perms = vnode.mode & 0o777;
        let readable = (perms & 0o444) != 0;
        let writable = (perms & 0o222) != 0;
        let executable = (perms & 0o111) != 0;
        let ok = (mode == F_OK)
            || ((mode & R_OK) == 0 || readable)
                && ((mode & W_OK) == 0 || writable)
                && ((mode & X_OK) == 0 || executable);

        (*reply).label = if ok {
            TRONA_OK
        } else {
            TRONA_INSUFFICIENT_RIGHTS
        };
        (*reply).length = 0;
    }
}

/// Shared helper: adopt a deferred-mid-walk PendingOp for an
/// access-family continuation.
unsafe fn access_continuation_adopt(
    state: &mut crate::owner::VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    mode: u32,
    flags: u32,
    reply: *mut TronaMsg,
) {
    let body = crate::owner::namei::AccessContBody {
        mode,
        flags,
        dirfd_packed: 0,
        _reserved: [0; 80],
    };
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_ACCESS_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_ACCESS,
            crate::owner::namei::namei_aux_access(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_access_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mode = (*msg).regs[0];
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let Some(path_len) = normalize_path_owned(
            state,
            cli_handle,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let vh =
            match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], false) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                    (*reply).label = TRONA_NOT_FOUND;
                    (*reply).length = 0;
                    return;
                }
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                    access_continuation_adopt(
                        state,
                        cli_handle,
                        op_id,
                        &abs_path[..path_len],
                        mode as u32,
                        0,
                        reply,
                    );
                    return;
                }
                Err(err) => {
                    (*reply).label = err;
                    (*reply).length = 0;
                    return;
                }
            };
        access_reply_for_vnode(state, vh, mode, reply);
    }
}

pub(crate) unsafe fn handle_faccessat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1];
        let at_flags = (*msg).regs[2] as i32;
        if (at_flags & !AT_SYMLINK_NOFOLLOW) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 3, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let Some(path_len) = normalize_path_at_owned(
            state,
            cli_handle,
            dirfd,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let no_follow = (at_flags & AT_SYMLINK_NOFOLLOW) != 0;
        let vh = match state.lookup_path_dynamic_for_client(
            cli_handle,
            &abs_path[..path_len],
            no_follow,
        ) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                access_continuation_adopt(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    mode as u32,
                    at_flags as u32,
                    reply,
                );
                return;
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        access_reply_for_vnode(state, vh, mode, reply);
    }
}

/// Owner-side completion handler for `access`/`faccessat`. The sync
/// tail re-uses `access_reply_for_vnode` with the requested permission
/// `mode` carried in `saved.aux.access`.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn complete_access_continuation(
    state: &mut crate::owner::VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.access;
        let vh = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
            saved.current_packed as u32,
            (saved.current_packed >> 32) as u32,
        );
        let mut reply = TronaMsg::zeroed();
        access_reply_for_vnode(state, vh, body.mode as u64, &raw mut reply);
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}
