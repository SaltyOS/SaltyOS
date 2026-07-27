// SPDX-License-Identifier: GPL-2.0-only
//! Synchronous vnode metadata mutation helpers.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::client::{MAX_PATH_LEN, extract_path, normalize_path_at_owned};
use crate::server::types::ClientHandle;

unsafe fn populate_direct_deferred(
    state: &VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    reply: *mut TronaMsg,
) {
    unsafe {
        if !crate::owner::continuation::populate_alloced_op_for_caller(
            state, op_id, cli_handle, reply,
        ) {
            crate::owner::pending_ops::free(op_id);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

unsafe fn transition_or_fail(
    old_op_id: crate::owner::pending_ops::PendingOpId,
    new_op_id: crate::owner::pending_ops::PendingOpId,
    new_kind: crate::owner::pending_ops::PendingOpKind,
    aux_kind: u8,
    aux: crate::owner::namei::NameiResumeAux,
) {
    unsafe {
        if !crate::owner::continuation::transition_to_chained_op_with_aux(
            old_op_id, new_op_id, new_kind, aux_kind, aux,
        ) {
            crate::owner::continuation::fail_continuation(old_op_id, TRONA_INVALID_OPERATION);
        }
    }
}

fn current_realtime_ns() -> Option<u64> {
    let res =
        trona_kernel::syscall::syscall(SYS_CLOCK_GETTIME, CLOCK_REALTIME as u64, 0, 0, 0, 0, 0);
    if res.error != 0 {
        return None;
    }
    Some(res.value)
}

fn decode_utimens_component(sec: i64, nsec: i64, current: u64, now: u64) -> Option<Option<u64>> {
    if nsec == UTIME_OMIT {
        return Some(None);
    }
    if nsec == UTIME_NOW {
        return Some(Some(now));
    }
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return None;
    }
    let value = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64);
    Some(Some(if value == current { current } else { value }))
}

pub(crate) unsafe fn handle_fchmod_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let mode = (*msg).regs[1] as u32;
        let Some(of) = state.client_open_file(cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        match crate::vfs_core::vops::set_mode(state, of.vnode, mode) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => (*reply).label = TRONA_OK,
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                populate_direct_deferred(state, cli_handle, op_id, reply);
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_fchmodat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
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
        match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], no_follow) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => {
                match crate::vfs_core::vops::set_mode(state, vh, mode) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        let body = crate::owner::namei::ChmodContBody {
                            mode,
                            _pad: [0; 92],
                        };
                        let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                        if !crate::owner::continuation::adopt_deferred_op_for_continuation(
                            op_id,
                            crate::owner::pending_ops::PO_KIND_CHMOD_CONT,
                            badge,
                            cli_handle,
                            reply,
                            &abs_path[..path_len],
                            crate::owner::namei::NAMEI_AUX_CHMOD,
                            crate::owner::namei::namei_aux_chmod(body),
                        ) {
                            (*reply).label = TRONA_OUT_OF_MEMORY;
                        }
                    }
                    Err(err) => (*reply).label = err,
                }
                (*reply).length = 0;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                let body = crate::owner::namei::ChmodContBody {
                    mode,
                    _pad: [0; 92],
                };
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                let ok = crate::owner::continuation::adopt_deferred_op_for_continuation(
                    op_id,
                    crate::owner::pending_ops::PO_KIND_CHMOD_CONT,
                    badge,
                    cli_handle,
                    reply,
                    &abs_path[..path_len],
                    crate::owner::namei::NAMEI_AUX_CHMOD,
                    crate::owner::namei::namei_aux_chmod(body),
                );
                if !ok {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                }
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
            }
        }
    }
}

pub(crate) unsafe fn handle_fchown_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let uid = (*msg).regs[1] as u32;
        let gid = (*msg).regs[2] as u32;
        let Some(of) = state.client_open_file(cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        match crate::vfs_core::vops::set_owner(state, of.vnode, uid, gid) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => (*reply).label = TRONA_OK,
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                populate_direct_deferred(state, cli_handle, op_id, reply);
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_fchownat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let uid = (*msg).regs[1] as u32;
        let gid = (*msg).regs[2] as u32;
        let at_flags = (*msg).regs[3] as i32;
        if (at_flags & !AT_SYMLINK_NOFOLLOW) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 4, path.as_mut_ptr());
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
        match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], no_follow) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => {
                match crate::vfs_core::vops::set_owner(state, vh, uid, gid) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        let body = crate::owner::namei::ChownContBody {
                            uid,
                            gid,
                            _pad: [0; 88],
                        };
                        let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                        if !crate::owner::continuation::adopt_deferred_op_for_continuation(
                            op_id,
                            crate::owner::pending_ops::PO_KIND_CHOWN_CONT,
                            badge,
                            cli_handle,
                            reply,
                            &abs_path[..path_len],
                            crate::owner::namei::NAMEI_AUX_CHOWN,
                            crate::owner::namei::namei_aux_chown(body),
                        ) {
                            (*reply).label = TRONA_OUT_OF_MEMORY;
                        }
                    }
                    Err(err) => (*reply).label = err,
                }
                (*reply).length = 0;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                let body = crate::owner::namei::ChownContBody {
                    uid,
                    gid,
                    _pad: [0; 88],
                };
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                let ok = crate::owner::continuation::adopt_deferred_op_for_continuation(
                    op_id,
                    crate::owner::pending_ops::PO_KIND_CHOWN_CONT,
                    badge,
                    cli_handle,
                    reply,
                    &abs_path[..path_len],
                    crate::owner::namei::NAMEI_AUX_CHOWN,
                    crate::owner::namei::namei_aux_chown(body),
                );
                if !ok {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                }
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
            }
        }
    }
}

pub(crate) unsafe fn handle_utimensat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let atime_sec = (*msg).regs[2] as i64;
        let atime_nsec = (*msg).regs[3] as i64;
        let mtime_sec = (*msg).regs[4] as i64;
        let mtime_nsec = (*msg).regs[5] as i64;
        if (at_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let now_ns = match current_realtime_ns() {
            Some(now_ns) => now_ns,
            None => {
                (*reply).label = TRONA_IO_ERROR;
                (*reply).length = 0;
                return;
            }
        };

        let mut path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 6, path.as_mut_ptr());
        if raw_len == 0 && (at_flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
            let Some(of) = state.client_open_file(cli_handle, dirfd as usize) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            let Some(vn) = state.vnodes.get(of.vnode) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            let Some(atime) = decode_utimens_component(atime_sec, atime_nsec, vn.atime_ns, now_ns)
            else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            let Some(mtime) = decode_utimens_component(mtime_sec, mtime_nsec, vn.mtime_ns, now_ns)
            else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            match crate::vfs_core::vops::set_times(state, of.vnode, atime, mtime) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => (*reply).label = TRONA_OK,
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                    populate_direct_deferred(state, cli_handle, op_id, reply);
                }
                Err(err) => (*reply).label = err,
            }
            (*reply).length = 0;
            return;
        }
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut abs_path = [0u8; MAX_PATH_LEN];
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
        match state.lookup_path_dynamic_for_client(cli_handle, &abs_path[..path_len], no_follow) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => {
                let Some(vn) = state.vnodes.get(vh) else {
                    (*reply).label = TRONA_NOT_FOUND;
                    (*reply).length = 0;
                    return;
                };
                let Some(atime) =
                    decode_utimens_component(atime_sec, atime_nsec, vn.atime_ns, now_ns)
                else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                let Some(mtime) =
                    decode_utimens_component(mtime_sec, mtime_nsec, vn.mtime_ns, now_ns)
                else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                match crate::vfs_core::vops::set_times(state, vh, atime, mtime) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        let encode_opt = |sec: i64, nsec: i64, ns: u64| -> (u8, u64) {
                            if nsec == UTIME_OMIT {
                                (crate::owner::namei::UTIMENS_OPT_OMIT, 0)
                            } else if nsec == UTIME_NOW {
                                (crate::owner::namei::UTIMENS_OPT_NOW, now_ns)
                            } else {
                                let v = (sec as u64)
                                    .saturating_mul(1_000_000_000)
                                    .saturating_add(nsec as u64);
                                (
                                    crate::owner::namei::UTIMENS_OPT_NORMAL,
                                    if v == ns { ns } else { v },
                                )
                            }
                        };
                        let (atime_opt, atime_ns) =
                            encode_opt(atime_sec, atime_nsec, atime.unwrap_or(0));
                        let (mtime_opt, mtime_ns) =
                            encode_opt(mtime_sec, mtime_nsec, mtime.unwrap_or(0));
                        let body = crate::owner::namei::UtimesContBody {
                            atime_opt,
                            mtime_opt,
                            _pad0: [0; 6],
                            atime_ns,
                            mtime_ns,
                            dirfd_packed: 0,
                            flags: at_flags as u32,
                            _pad1: [0; 4],
                            _reserved: [0; 56],
                        };
                        let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                        if !crate::owner::continuation::adopt_deferred_op_for_continuation(
                            op_id,
                            crate::owner::pending_ops::PO_KIND_UTIMES_CONT,
                            badge,
                            cli_handle,
                            reply,
                            &abs_path[..path_len],
                            crate::owner::namei::NAMEI_AUX_UTIMES,
                            crate::owner::namei::namei_aux_utimes(body),
                        ) {
                            (*reply).label = TRONA_OUT_OF_MEMORY;
                        }
                    }
                    Err(err) => (*reply).label = err,
                }
                (*reply).length = 0;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                let encode_opt = |sec: i64, nsec: i64, ns: u64| -> (u8, u64) {
                    if nsec == UTIME_OMIT {
                        (crate::owner::namei::UTIMENS_OPT_OMIT, 0)
                    } else if nsec == UTIME_NOW {
                        (crate::owner::namei::UTIMENS_OPT_NOW, now_ns)
                    } else {
                        let v = (sec as u64)
                            .saturating_mul(1_000_000_000)
                            .saturating_add(nsec as u64);
                        (
                            crate::owner::namei::UTIMENS_OPT_NORMAL,
                            if v == ns { ns } else { v },
                        )
                    }
                };
                let (atime_opt, atime_ns) = encode_opt(atime_sec, atime_nsec, 0);
                let (mtime_opt, mtime_ns) = encode_opt(mtime_sec, mtime_nsec, 0);
                let body = crate::owner::namei::UtimesContBody {
                    atime_opt,
                    mtime_opt,
                    _pad0: [0; 6],
                    atime_ns,
                    mtime_ns,
                    dirfd_packed: 0,
                    flags: at_flags as u32,
                    _pad1: [0; 4],
                    _reserved: [0; 56],
                };
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                let ok = crate::owner::continuation::adopt_deferred_op_for_continuation(
                    op_id,
                    crate::owner::pending_ops::PO_KIND_UTIMES_CONT,
                    badge,
                    cli_handle,
                    reply,
                    &abs_path[..path_len],
                    crate::owner::namei::NAMEI_AUX_UTIMES,
                    crate::owner::namei::namei_aux_utimes(body),
                );
                if !ok {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                }
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
            }
        }
    }
}

pub(crate) unsafe fn complete_chmod_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.chmod;
        let mut reply = TronaMsg::zeroed();
        if saved.current_packed == u32::MAX as u64 {
            reply.label = TRONA_NOT_FOUND;
            reply.length = 0;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        }
        let vh = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
            saved.current_packed as u32,
            (saved.current_packed >> 32) as u32,
        );
        if state.vnodes.get(vh).is_none() {
            reply.label = TRONA_NOT_FOUND;
        } else {
            match crate::vfs_core::vops::set_mode(state, vh, body.mode) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => reply.label = TRONA_OK,
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                    transition_or_fail(
                        op_id,
                        new_op_id,
                        crate::owner::pending_ops::PO_KIND_CHMOD_CONT,
                        crate::owner::namei::NAMEI_AUX_CHMOD,
                        crate::owner::namei::namei_aux_chmod(body),
                    );
                    return true;
                }
                Err(err) => reply.label = err,
            }
        }
        reply.length = 0;
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}

pub(crate) unsafe fn complete_chown_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.chown;
        let mut reply = TronaMsg::zeroed();
        if saved.current_packed == u32::MAX as u64 {
            reply.label = TRONA_NOT_FOUND;
            reply.length = 0;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        }
        let vh = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
            saved.current_packed as u32,
            (saved.current_packed >> 32) as u32,
        );
        if state.vnodes.get(vh).is_none() {
            reply.label = TRONA_NOT_FOUND;
        } else {
            match crate::vfs_core::vops::set_owner(state, vh, body.uid, body.gid) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => reply.label = TRONA_OK,
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                    transition_or_fail(
                        op_id,
                        new_op_id,
                        crate::owner::pending_ops::PO_KIND_CHOWN_CONT,
                        crate::owner::namei::NAMEI_AUX_CHOWN,
                        crate::owner::namei::namei_aux_chown(body),
                    );
                    return true;
                }
                Err(err) => reply.label = err,
            }
        }
        reply.length = 0;
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}

pub(crate) unsafe fn complete_utimes_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.utimes;
        let mut reply = TronaMsg::zeroed();
        if saved.current_packed == u32::MAX as u64 {
            reply.label = TRONA_NOT_FOUND;
            reply.length = 0;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        }
        let vh = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
            saved.current_packed as u32,
            (saved.current_packed >> 32) as u32,
        );
        if state.vnodes.get(vh).is_none() {
            reply.label = TRONA_NOT_FOUND;
            reply.length = 0;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        }
        let decode = |opt: u8, ns: u64| -> Option<Option<u64>> {
            match opt {
                crate::owner::namei::UTIMENS_OPT_OMIT => Some(None),
                crate::owner::namei::UTIMENS_OPT_NOW => Some(Some(ns)),
                crate::owner::namei::UTIMENS_OPT_NORMAL => Some(Some(ns)),
                _ => None,
            }
        };
        let Some(atime) = decode(body.atime_opt, body.atime_ns) else {
            reply.label = TRONA_INVALID_ARGUMENT;
            reply.length = 0;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        };
        let Some(mtime) = decode(body.mtime_opt, body.mtime_ns) else {
            reply.label = TRONA_INVALID_ARGUMENT;
            reply.length = 0;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        };
        match crate::vfs_core::vops::set_times(state, vh, atime, mtime) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => reply.label = TRONA_OK,
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                transition_or_fail(
                    op_id,
                    new_op_id,
                    crate::owner::pending_ops::PO_KIND_UTIMES_CONT,
                    crate::owner::namei::NAMEI_AUX_UTIMES,
                    crate::owner::namei::namei_aux_utimes(body),
                );
                return true;
            }
            Err(err) => reply.label = err,
        }
        reply.length = 0;
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}

pub(crate) unsafe fn complete_truncate_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.truncate;
        let mut reply = TronaMsg::zeroed();
        if saved.current_packed == u32::MAX as u64 {
            reply.label = TRONA_NOT_FOUND;
            reply.length = 0;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        }
        let vh = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
            saved.current_packed as u32,
            (saved.current_packed >> 32) as u32,
        );
        if state.vnodes.get(vh).is_none() {
            reply.label = TRONA_NOT_FOUND;
        } else {
            match crate::vfs_core::vops::truncate(state, vh, body.length) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => reply.label = TRONA_OK,
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                    transition_or_fail(
                        op_id,
                        new_op_id,
                        crate::owner::pending_ops::PO_KIND_TRUNCATE_CONT,
                        crate::owner::namei::NAMEI_AUX_TRUNCATE,
                        crate::owner::namei::namei_aux_truncate(body),
                    );
                    return true;
                }
                Err(err) => reply.label = err,
            }
        }
        reply.length = 0;
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}
