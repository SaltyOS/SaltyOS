// SPDX-License-Identifier: GPL-2.0-only
//! mmap backing resolution and pager callbacks.

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_posix::consts::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::client::extract_path;
use crate::server::types::{ClientHandle, OBJ_FILE, OBJ_SHM};
use crate::vfs_core::identity::FsInstanceId;
use crate::vfs_core::vnode::{VT_LNK, VT_REG, VnodeHandle};

const VFS_FILE_MMAP_SCRATCH_VADDR: u64 = 0x0000_0000_7000_0000;
const INLINE_READLINK_MAX: usize = 152;

fn unpack_saved_vnode(saved: &crate::owner::namei::NameiResumeState) -> Option<VnodeHandle> {
    if saved.current_packed == u32::MAX as u64 {
        return None;
    }
    Some(VnodeHandle::new(
        saved.current_packed as u32,
        (saved.current_packed >> 32) as u32,
    ))
}

fn client_handle_for_op(op_id: crate::owner::pending_ops::PendingOpId) -> ClientHandle {
    unsafe {
        crate::owner::pending_ops::unpack_client_handle(
            crate::owner::pending_ops::get(op_id)
                .map(|op| op.client_handle_raw)
                .unwrap_or(0),
        )
    }
}

fn log_resolve_backing_failure(
    stage: &'static [u8],
    target_badge: u64,
    fd: usize,
    vnode: crate::vfs_core::vnode::VnodeHandle,
    label: u64,
) {
    trona_runtime::uwarn!(|_lb| {
        _lb.str(b"[VFS] mmap backing failed component=vfs op=RESOLVE_BACKING stage=");
        _lb.bytes(stage);
        _lb.str(b" badge=");
        _lb.hex(target_badge);
        _lb.str(b" fd=");
        _lb.dec(fd as u64);
        _lb.str(b" vnode=");
        if vnode.is_valid() {
            _lb.dec(vnode.slot() as u64);
            _lb.str(b":");
            _lb.dec(vnode.epoch() as u64);
        } else {
            _lb.str(b"invalid");
        }
        _lb.str(b" label=");
        _lb.hex(label);
        _lb.str(b"\n");
    });
}

fn fill_resolve_reply(
    reply: *mut TronaMsg,
    backing_kind: u64,
    id0: u64,
    id1: u64,
    file_size: u64,
    flags: u64,
) {
    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).length = 5;
        (*reply).regs[0] = backing_kind;
        (*reply).regs[1] = id0;
        (*reply).regs[2] = id1;
        (*reply).regs[3] = file_size;
        (*reply).regs[4] = flags;
    }
}

fn with_recv_mo_page(recv_slot: Cap, mo_page_idx: u64, func: impl FnOnce(*mut u8) -> bool) -> bool {
    let count_and_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
    let (err, mapped) = invoke::vspace_map_mo_with_count(
        CAP_SELF_VSPACE,
        recv_slot,
        VFS_FILE_MMAP_SCRATCH_VADDR,
        mo_page_idx,
        count_and_flags,
    );
    if err != 0 || mapped != 1 {
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
        return false;
    }

    let result = func(VFS_FILE_MMAP_SCRATCH_VADDR as *mut u8);
    let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
    let _ = invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
    result
}

pub(crate) unsafe fn handle_resolve_backing_owned(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let target_badge = (*msg).regs[1];
        let Some(cli_handle) = state.lookup_client(target_badge) else {
            log_resolve_backing_failure(
                b"client_lookup",
                target_badge,
                fd,
                crate::vfs_core::vnode::VnodeHandle::INVALID,
                TRONA_INVALID_ARGUMENT,
            );
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        // Copy every field we need out of the OpenFile up front so the
        // immutable borrow on `state` ends before any backend callback
        // takes `state` mutably below.
        let (of_kind, of_vnode, of_shm, of_status_flags) =
            match state.client_open_file(cli_handle, fd) {
                Some(of) => (of.kind, of.vnode, of.shm, of.status_flags),
                None => {
                    log_resolve_backing_failure(
                        b"fd_lookup",
                        target_badge,
                        fd,
                        crate::vfs_core::vnode::VnodeHandle::INVALID,
                        TRONA_INVALID_ARGUMENT,
                    );
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                }
            };

        let mut resolve_flags = 0u64;
        if (of_status_flags & O_ACCMODE) != O_RDONLY {
            resolve_flags |= 1;
        }

        if of_kind == OBJ_SHM {
            let Some(shm) = state.shm_state(of_shm) else {
                log_resolve_backing_failure(
                    b"shm_lookup",
                    target_badge,
                    fd,
                    of_vnode,
                    TRONA_INVALID_ARGUMENT,
                );
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            let file_size = state.vnodes.get(of_vnode).map(|vn| vn.size).unwrap_or(0);
            fill_resolve_reply(reply, MMAP_BACKING_SHM, shm.id, 0, file_size, resolve_flags);
            return;
        }

        if of_kind == OBJ_FILE {
            let (fs_id, ino, size, mode) = match state.vnodes.get(of_vnode) {
                Some(vn) => (vn.fs_instance_id.0, vn.id, vn.size, vn.mode),
                None => {
                    log_resolve_backing_failure(
                        b"vnode_lookup",
                        target_badge,
                        fd,
                        of_vnode,
                        TRONA_INVALID_ARGUMENT,
                    );
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                }
            };
            if (mode & 0o222) == 0 {
                resolve_flags |= 2;
            }

            // Backend-specific resolve_backing first — backends that
            // hand out a transferrable MO cap (tmpfs today; future
            // first-class fs) reply directly. Generic file cache
            // routing only fires when no backend claims the vnode.
            let resolve_cb = crate::vfs_core::vfsops::vfsops_for_vnode(state, of_vnode)
                .and_then(|ops| ops.resolve_backing);
            if let Some(resolve_cb) = resolve_cb {
                match resolve_cb(state, of_vnode) {
                    Ok(Some(resolution)) => {
                        trona_kernel::ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, resolution.mo_cap);
                        fill_resolve_reply(reply, resolution.kind, fs_id, ino, size, resolve_flags);
                        return;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        log_resolve_backing_failure(
                            b"backend_resolve",
                            target_badge,
                            fd,
                            of_vnode,
                            err,
                        );
                        (*reply).label = err;
                        (*reply).length = 0;
                        return;
                    }
                }
            }

            if !crate::fileops::regular::supports_pager_backing(state, of_vnode) {
                log_resolve_backing_failure(
                    b"unsupported",
                    target_badge,
                    fd,
                    of_vnode,
                    TRONA_INVALID_ARGUMENT,
                );
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
            fill_resolve_reply(reply, MMAP_BACKING_FILE, fs_id, ino, size, resolve_flags);
            return;
        }

        log_resolve_backing_failure(b"kind", target_badge, fd, of_vnode, TRONA_INVALID_ARGUMENT);
        fill_resolve_reply(reply, MMAP_BACKING_NONE, 0, 0, 0, 0);
    }
}

pub(crate) unsafe fn handle_resolve_path_backing_owned(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let path_len = (*msg).regs[0] as usize;
        if path_len == 0 || path_len > 248 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let mut path = [0u8; 256];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr()) as usize;
        if raw_len != path_len {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let path = &path[..path_len];
        if path.first().copied() != Some(b'/') {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let vh = match state.lookup_path_dynamic_absolute(path, false) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                let ok = crate::owner::continuation::adopt_deferred_op_for_continuation(
                    op_id,
                    crate::owner::pending_ops::PO_KIND_RESOLVE_PATH_BACKING_CONT,
                    badge,
                    ClientHandle::INVALID,
                    reply,
                    path,
                    crate::owner::namei::NAMEI_AUX_NONE,
                    crate::owner::namei::namei_aux_none(),
                );
                if !ok {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                }
                return;
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        emit_resolve_path_backing_for_vnode(state, vh, reply);
    }
}

unsafe fn emit_resolve_path_backing_for_vnode(
    state: &mut VfsState,
    vh: VnodeHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let (fs_id, ino, size, mode, vtype) = match state.vnodes.get(vh) {
            Some(vn) => (vn.fs_instance_id.0, vn.id, vn.size, vn.mode, vn.vtype),
            None => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
        };
        if vtype != VT_REG {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        if state.shm_by_vnode(vh).is_some() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let mut resolve_flags = 0u64;
        if (mode & 0o222) == 0 {
            resolve_flags |= 2;
        }

        if let Some(ops) = crate::vfs_core::vfsops::vfsops_for_vnode(state, vh) {
            if let Some(resolve_cb) = ops.resolve_backing {
                match resolve_cb(state, vh) {
                    Ok(Some(resolution)) => {
                        trona_kernel::ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, resolution.mo_cap);
                        fill_resolve_reply(reply, resolution.kind, fs_id, ino, size, resolve_flags);
                        return;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        (*reply).label = err;
                        (*reply).length = 0;
                        return;
                    }
                }
            }
        }

        if !crate::fileops::regular::supports_pager_backing(state, vh) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        fill_resolve_reply(reply, MMAP_BACKING_FILE, fs_id, ino, size, resolve_flags);
    }
}

pub(crate) unsafe fn handle_pager_read_owned(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let backing_kind = (*msg).regs[0];
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let file_offset = (*msg).regs[3];
        let mo_page_idx = (*msg).regs[4];
        let bytes = core::cmp::min((*msg).regs[5] as usize, 4096);
        if backing_kind != MMAP_BACKING_FILE {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let Some(vh) =
            state.vnode_by_fs_instance_and_inode_id(FsInstanceId::new(backing_id0), backing_id1)
        else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };
        let recv_slot = state.owner_recv_slot;
        if recv_slot == 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        let mut actual = 0usize;
        let mut read_err = TRONA_OK;
        let ok = with_recv_mo_page(recv_slot, mo_page_idx, |page| {
            core::ptr::write_bytes(page, 0, 4096);
            match crate::fileops::regular::read_into(state, None, vh, file_offset, page, bytes) {
                Ok(read) => {
                    actual = read;
                    true
                }
                Err(err) => {
                    read_err = err;
                    false
                }
            }
        });
        if !ok {
            (*reply).label = if read_err != TRONA_OK {
                read_err
            } else {
                TRONA_IO_ERROR
            };
            (*reply).length = 0;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual as u64;
    }
}

pub(crate) unsafe fn handle_pager_write_owned(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let backing_kind = (*msg).regs[0];
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let file_offset = (*msg).regs[3];
        let mo_page_idx = (*msg).regs[4];
        let bytes = core::cmp::min((*msg).regs[5] as usize, 4096);
        if backing_kind != MMAP_BACKING_FILE {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let Some(vh) =
            state.vnode_by_fs_instance_and_inode_id(FsInstanceId::new(backing_id0), backing_id1)
        else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };
        let recv_slot = state.owner_recv_slot;
        if recv_slot == 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        let mut written = 0usize;
        let mut write_err = TRONA_OK;
        let ok = with_recv_mo_page(recv_slot, mo_page_idx, |page| {
            match crate::fileops::regular::write_from(
                state,
                vh,
                file_offset,
                page as *const u8,
                bytes,
            ) {
                Ok(actual) => {
                    written = actual as usize;
                    written == bytes
                }
                Err(err) => {
                    write_err = err;
                    false
                }
            }
        });
        if !ok {
            (*reply).label = if write_err != TRONA_OK {
                write_err
            } else {
                TRONA_INVALID_OPERATION
            };
            (*reply).length = 0;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
    }
}

/// Path-syscall continuation routing for `readlink` / `readlinkat`.
/// Lands here once the saltyfs vertical slice wires the deferred
/// `readlink_sync` / `ensure_symlink_target` RPC.
pub(crate) unsafe fn complete_readlink_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let Some(vh) = unpack_saved_vnode(saved) else {
            let mut reply = TronaMsg::zeroed();
            reply.label = TRONA_NOT_FOUND;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        };
        let mut reply = TronaMsg::zeroed();
        let Some(vnode) = state.vnodes.get(vh) else {
            reply.label = TRONA_NOT_FOUND;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        };
        if vnode.vtype != VT_LNK {
            reply.label = TRONA_INVALID_ARGUMENT;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        }

        let cli_handle = client_handle_for_op(op_id);
        let needs_materialize = vnode.data.is_null();
        let actual = if let Some(result) = crate::vfs_core::vops::readlink_inline(
            state,
            Some(cli_handle),
            vh,
            &raw mut reply.regs[1] as *mut u8,
            INLINE_READLINK_MAX,
        ) {
            match result {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(actual)) => actual,
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                    let body = crate::owner::namei::ReadlinkContBody { _reserved: [0; 96] };
                    if !crate::owner::continuation::transition_to_chained_op_with_aux(
                        op_id,
                        new_op_id,
                        crate::owner::pending_ops::PO_KIND_READLINK_CONT,
                        crate::owner::namei::NAMEI_AUX_READLINK,
                        crate::owner::namei::namei_aux_readlink(body),
                    ) {
                        crate::owner::continuation::fail_continuation(
                            op_id,
                            TRONA_INVALID_OPERATION,
                        );
                    }
                    return true;
                }
                Err(err) => {
                    reply.label = err;
                    crate::owner::continuation::finish_continuation(op_id, reply);
                    return true;
                }
            }
        } else {
            let materialized = match crate::vfs_core::vops::ensure_symlink_target(state, vh) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(b)) => b,
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                    let body = crate::owner::namei::ReadlinkContBody { _reserved: [0; 96] };
                    if !crate::owner::continuation::transition_to_chained_op_with_aux(
                        op_id,
                        new_op_id,
                        crate::owner::pending_ops::PO_KIND_READLINK_CONT,
                        crate::owner::namei::NAMEI_AUX_READLINK,
                        crate::owner::namei::namei_aux_readlink(body),
                    ) {
                        crate::owner::continuation::fail_continuation(
                            op_id,
                            TRONA_INVALID_OPERATION,
                        );
                    }
                    return true;
                }
                Err(err) => {
                    reply.label = err;
                    crate::owner::continuation::finish_continuation(op_id, reply);
                    return true;
                }
            };
            if needs_materialize && !materialized {
                reply.label = TRONA_IO_ERROR;
                crate::owner::continuation::finish_continuation(op_id, reply);
                return true;
            }
            let Some(vnode) = state.vnodes.get(vh) else {
                reply.label = TRONA_NOT_FOUND;
                crate::owner::continuation::finish_continuation(op_id, reply);
                return true;
            };
            let actual = core::cmp::min(vnode.size as usize, INLINE_READLINK_MAX);
            let src = vnode.data as *const u8;
            let dst = &raw mut reply.regs[1] as *mut u8;
            for idx in 0..actual {
                *dst.add(idx) = *src.add(idx);
            }
            actual
        };
        reply.label = TRONA_OK;
        reply.regs[0] = actual as u64;
        reply.length = 1 + ((actual as u64 + 7) / 8);
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}

/// Path-syscall continuation routing for `chdir`. Lands here once the
/// saltyfs vertical slice wires the deferred lookup-walk for the
/// target directory.
pub(crate) unsafe fn complete_chdir_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let Some(vh) = unpack_saved_vnode(saved) else {
            let mut reply = TronaMsg::zeroed();
            reply.label = TRONA_NOT_FOUND;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        };
        let mut reply = TronaMsg::zeroed();
        let Some(vnode) = state.vnodes.get(vh) else {
            reply.label = TRONA_NOT_FOUND;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        };
        if vnode.vtype != crate::vfs_core::vnode::VT_DIR {
            reply.label = TRONA_NOT_DIRECTORY;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        }
        let Some(cwd_anchor) = state.anchor_for_vnode(vh) else {
            reply.label = TRONA_INVALID_OPERATION;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        };
        let cli_handle = client_handle_for_op(op_id);
        let Some(client) = state.clients.get_mut(cli_handle) else {
            reply.label = TRONA_INVALID_OPERATION;
            crate::owner::continuation::finish_continuation(op_id, reply);
            return true;
        };
        let is_win32 = client.personality == crate::server::types::PERS_WIN32;
        client.cwd_anchor = cwd_anchor;
        if is_win32 {
            let drive = saved.aux.chdir.explicit_drive;
            if drive >= 0 {
                state.update_win32_client_cwd_for_drive(cli_handle, drive as usize, vh);
            } else {
                state.update_win32_client_cwd(cli_handle, vh);
            }
        }
        reply.label = TRONA_OK;
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}

/// Path-syscall continuation routing for `statvfs` / `fstatvfs`.
/// Lands here once the saltyfs vertical slice wires the deferred
/// `statfs` RPC against the resolved mount.
pub(crate) unsafe fn complete_statvfs_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let mut reply = TronaMsg::zeroed();
        match unpack_saved_vnode(saved) {
            Some(vh) => crate::ipc::statfs_ipc::emit_statfs_for_vnode(state, vh, &raw mut reply),
            None => {
                reply.label = TRONA_NOT_FOUND;
                reply.length = 0;
            }
        }
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}

/// Backend path-backed mmap continuation. The path lookup may yield on
/// SaltyFS; once namei resolves, finish with the same reply shape as the
/// synchronous resolver.
pub(crate) unsafe fn complete_resolve_path_backing_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let mut reply = TronaMsg::zeroed();
        match unpack_saved_vnode(saved) {
            Some(vh) => emit_resolve_path_backing_for_vnode(state, vh, &raw mut reply),
            None => {
                reply.label = TRONA_NOT_FOUND;
                reply.length = 0;
            }
        }
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
    true
}

/// Path-syscall continuation routing for `mount`. Lands here once the
/// saltyfs vertical slice wires the deferred mount-table mutation
/// against the resolved target vnode.
pub(crate) unsafe fn complete_mount_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = (state, saved, completion);
    unsafe {
        crate::owner::continuation::fail_continuation(op_id, TRONA_NOT_SUPPORTED);
    }
    true
}

/// Path-syscall continuation routing for `umount`. Lands here once
/// the saltyfs vertical slice wires the deferred mount-table mutation
/// against the resolved mountpoint vnode.
pub(crate) unsafe fn complete_umount_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = (state, saved, completion);
    unsafe {
        crate::owner::continuation::fail_continuation(op_id, TRONA_NOT_SUPPORTED);
    }
    true
}
