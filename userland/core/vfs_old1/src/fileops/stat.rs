// SPDX-License-Identifier: GPL-2.0-only
//! Metadata and canonical-path operations.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::client::{
    MAX_PATH_LEN, extract_path, normalize_path_at_owned, normalize_path_owned,
    write_inline_path_reply,
};
use crate::server::types::ClientHandle;
use crate::server::types::{OBJ_PIPE, OBJ_SOCKET, PERS_WIN32};

const INLINE_READLINK_MAX: usize = 152;

fn stat_reply_for_vnode(
    state: &VfsState,
    vh: crate::vfs_core::vnode::VnodeHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let Some(vnode) = state.vnodes.get(vh) else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 8;
        (*reply).regs[0] = vnode.id;
        (*reply).regs[1] = vnode.mode as u64;
        (*reply).regs[2] = vnode.nlink as u64;
        (*reply).regs[3] = vnode.size;
        (*reply).regs[4] = vnode.uid as u64;
        (*reply).regs[5] = vnode.gid as u64;
        (*reply).regs[6] = vnode.mtime_ns / 1_000_000_000;
        (*reply).regs[7] = vnode.vtype as u64;
    }
}

fn stat_reply_for_pipe(
    state: &VfsState,
    pipe: crate::server::pipe_object::PipeHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let Some((read_refs, write_refs)) = state.pipe_refcounts(pipe) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let size = state.pipe_buffer_len(pipe).unwrap_or(0) as u64;
        let nlink = if read_refs != 0 || write_refs != 0 {
            1
        } else {
            0
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 8;
        (*reply).regs[0] = ((pipe.slot() as u64) << 32) | pipe.epoch() as u64;
        (*reply).regs[1] = (S_IFIFO as u32 | 0o600) as u64;
        (*reply).regs[2] = nlink;
        (*reply).regs[3] = size;
        (*reply).regs[4] = 0;
        (*reply).regs[5] = 0;
        (*reply).regs[6] = 0;
        (*reply).regs[7] = crate::vfs_core::vnode::VT_FIFO as u64;
    }
}

fn stat_reply_for_fifo_vnode(
    state: &VfsState,
    vnode: crate::vfs_core::vnode::VnodeHandle,
    pipe: crate::server::pipe_object::PipeHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let Some(vn) = state.vnodes.get(vnode) else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 8;
        (*reply).regs[0] = vn.id;
        (*reply).regs[1] = vn.mode as u64;
        (*reply).regs[2] = vn.nlink as u64;
        (*reply).regs[3] = state.pipe_buffer_len(pipe).unwrap_or(0) as u64;
        (*reply).regs[4] = vn.uid as u64;
        (*reply).regs[5] = vn.gid as u64;
        (*reply).regs[6] = vn.mtime_ns / 1_000_000_000;
        (*reply).regs[7] = vn.vtype as u64;
    }
}

fn stat_reply_for_socket_id(socket_id: u64, reply: *mut TronaMsg) {
    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).length = 8;
        (*reply).regs[0] = socket_id;
        (*reply).regs[1] = (S_IFSOCK | 0o666) as u64;
        (*reply).regs[2] = 1;
        (*reply).regs[3] = 0;
        (*reply).regs[4] = 0;
        (*reply).regs[5] = 0;
        (*reply).regs[6] = 0;
        (*reply).regs[7] = crate::vfs_core::vnode::VT_SOCK as u64;
    }
}

pub(crate) unsafe fn handle_canon_path_owned(
    state: &VfsState,
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

        if state.client_personality(cli_handle) == PERS_WIN32 {
            let mut win32_path = [0u8; MAX_PATH_LEN];
            let rendered_len = match crate::personality::win32::path::render_absolute_path_owned(
                state,
                cli_handle,
                &abs_path[..path_len],
                win32_path.as_mut_ptr(),
            ) {
                Ok(len) => len,
                Err(err) => {
                    (*reply).label = err;
                    (*reply).length = 0;
                    return;
                }
            };
            write_inline_path_reply(reply, win32_path.as_ptr(), rendered_len);
            return;
        }

        write_inline_path_reply(reply, abs_path.as_ptr(), path_len);
    }
}

/// Shared helper: adopt a deferred-mid-walk PendingOp for a stat-family
/// continuation. `follow_symlink` distinguishes `stat`/`fstatat` (1)
/// from `lstat`/`fstatat(AT_SYMLINK_NOFOLLOW)` (0). `for_exec` selects
/// the 4-reg ABI used by `stat_for_exec` (mode/uid/gid/size) over the
/// 8-reg full-stat ABI; the deferred completion routes through the
/// matching reply helper so the wire format matches the sync path.
unsafe fn stat_continuation_adopt(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    follow_symlink: u8,
    for_exec: u8,
    reply: *mut TronaMsg,
) {
    let body = crate::owner::namei::StatContBody {
        follow_symlink,
        for_exec,
        _pad0: [0; 6],
        dirfd_packed: 0,
        _reserved: [0; 80],
    };
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_STAT_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_STAT,
            crate::owner::namei::namei_aux_stat(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

unsafe fn readlink_continuation_adopt(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    reply: *mut TronaMsg,
) {
    let body = crate::owner::namei::ReadlinkContBody { _reserved: [0; 96] };
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_READLINK_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_READLINK,
            crate::owner::namei::namei_aux_readlink(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_stat_owned(
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

        let vh =
            match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], false) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                    (*reply).label = TRONA_NOT_FOUND;
                    (*reply).length = 0;
                    return;
                }
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                    stat_continuation_adopt(
                        state,
                        cli_handle,
                        op_id,
                        &abs_path[..path_len],
                        1,
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

        stat_reply_for_vnode(state, vh, reply);
    }
}

pub(crate) unsafe fn handle_lstat_owned(
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

        let vh = match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], true)
        {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                stat_continuation_adopt(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    0,
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

        stat_reply_for_vnode(state, vh, reply);
    }
}

pub(crate) unsafe fn handle_stat_for_exec_owned(
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

        let vh =
            match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], false) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                    (*reply).label = TRONA_NOT_FOUND;
                    (*reply).length = 0;
                    return;
                }
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                    stat_continuation_adopt(
                        state,
                        cli_handle,
                        op_id,
                        &abs_path[..path_len],
                        1,
                        1,
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

        (*reply).label = TRONA_OK;
        (*reply).length = 4;
        (*reply).regs[0] = vnode.mode as u64;
        (*reply).regs[1] = vnode.uid as u64;
        (*reply).regs[2] = vnode.gid as u64;
        (*reply).regs[3] = vnode.size;
    }
}

pub(crate) unsafe fn handle_fstat_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let Some(of) = state.client_open_file(cli_handle, fd as usize) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        if of.kind == OBJ_PIPE {
            if of.vnode.is_valid()
                && matches!(
                    state.vnodes.get(of.vnode),
                    Some(vnode) if vnode.vtype == crate::vfs_core::vnode::VT_FIFO
                )
            {
                stat_reply_for_fifo_vnode(state, of.vnode, of.pipe, reply);
                return;
            }
            stat_reply_for_pipe(state, of.pipe, reply);
            return;
        }
        if of.kind == OBJ_SOCKET {
            let socket_id = if of.unix_socket.is_valid() {
                ((of.unix_socket.slot() as u64) << 32) | of.unix_socket.epoch() as u64
            } else {
                of.socket_conn_id as u64
            };
            stat_reply_for_socket_id(socket_id, reply);
            return;
        }
        if !of.vnode.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        stat_reply_for_vnode(state, of.vnode, reply);
    }
}

pub(crate) unsafe fn handle_fstatat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        if (at_flags & !AT_SYMLINK_NOFOLLOW) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 2, path.as_mut_ptr());
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
                let follow = if no_follow { 0u8 } else { 1u8 };
                stat_continuation_adopt(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    follow,
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
        stat_reply_for_vnode(state, vh, reply);
    }
}

pub(crate) unsafe fn handle_readlinkat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
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

        let vh = match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], true)
        {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                readlink_continuation_adopt(state, cli_handle, op_id, &abs_path[..path_len], reply);
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
        if vnode.vtype != crate::vfs_core::vnode::VT_LNK {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let needs_materialize = vnode.data.is_null();

        // procfs PidExe readlink: defer to a worker so the owner does
        // not block on init's INIT_GET_EXE_PATH RPC inside dispatch.
        if vnode.backend_kind == crate::vfs_core::vnode::VNODE_BACKEND_PROCFS {
            if let Some((kind, pid)) = crate::fs::procfs::proc_read_kind(state, vh) {
                if crate::fs::procfs::proc_readlink_needs_deferred(kind) {
                    if crate::fs::procfs::defer_procfs_readlink(state, cli_handle, vh, pid, reply) {
                        return;
                    }
                }
            }
        }

        let actual = if let Some(result) = crate::vfs_core::vops::readlink_inline(
            state,
            Some(cli_handle),
            vh,
            &raw mut (*reply).regs[1] as *mut u8,
            INLINE_READLINK_MAX,
        ) {
            match crate::vfs_core::vops::into_value_or_label(result) {
                Ok(actual) => actual,
                Err(err) => {
                    (*reply).label = err;
                    (*reply).length = 0;
                    return;
                }
            }
        } else {
            let materialized = match crate::vfs_core::vops::ensure_symlink_target(state, vh) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(b)) => b,
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                    readlink_continuation_adopt(
                        state,
                        cli_handle,
                        op_id,
                        &abs_path[..path_len],
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
            if needs_materialize && !materialized {
                (*reply).label = TRONA_IO_ERROR;
                (*reply).length = 0;
                return;
            }
            let Some(vnode) = state.vnodes.get(vh) else {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            };
            let actual = core::cmp::min(vnode.size as usize, INLINE_READLINK_MAX);
            let src = vnode.data as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for idx in 0..actual {
                *dst.add(idx) = *src.add(idx);
            }
            actual
        };
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = actual as u64;
        (*reply).length = 1 + ((actual as u64 + 7) / 8);
    }
}

/// 4-reg stat ABI used by `stat_for_exec` (mode/uid/gid/size only).
/// Mirrors the inline reply construction in `handle_stat_for_exec_owned`
/// so the deferred-completion path returns the same wire shape.
fn stat_for_exec_reply_for_vnode(
    state: &VfsState,
    vh: crate::vfs_core::vnode::VnodeHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let Some(vnode) = state.vnodes.get(vh) else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 4;
        (*reply).regs[0] = vnode.mode as u64;
        (*reply).regs[1] = vnode.uid as u64;
        (*reply).regs[2] = vnode.gid as u64;
        (*reply).regs[3] = vnode.size;
    }
}

/// Owner-side completion handler for `stat`/`lstat`/`fstatat`/`stat_for_exec`.
/// `saved.current_packed` holds the resolved vnode (the namei walk
/// already followed-or-not symlinks per `saved.aux.stat.follow_symlink`).
/// `saved.aux.stat.for_exec` selects the 4-reg ABI used by
/// `stat_for_exec` over the 8-reg full-stat ABI so the deferred reply
/// matches the sync path's wire format.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn complete_stat_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.stat;
        let vh = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
            saved.current_packed as u32,
            (saved.current_packed >> 32) as u32,
        );
        let mut reply = TronaMsg::zeroed();
        if body.for_exec != 0 {
            stat_for_exec_reply_for_vnode(state, vh, &raw mut reply);
        } else {
            stat_reply_for_vnode(state, vh, &raw mut reply);
        }
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}
