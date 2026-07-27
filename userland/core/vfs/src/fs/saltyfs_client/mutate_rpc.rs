// SPDX-License-Identifier: GPL-2.0-only
//
//! Mutating SaltyFS IPC helpers — create / mkdir / symlink /
//! unlink / rmdir / link / rename / setattr / truncate / write.
//!
//! Every entry in this file is the async issue side of a backend
//! mutation RPC: reserve credit + a `PendingOp`, pack the wire
//! shape, stamp the correlation header, fire `mp_write_ctx`. The
//! completion router (`super::completion::saltyfs_completion`)
//! routes replies through the matching `FsResume::*` resume arm.
//!
//! Wire payload conventions:
//!
//! * Names ride packed as bytes after the metadata regs. The
//!   `name_len` register tells the backend how many bytes to
//!   read. `SALTYFS_NAME_MAX = 144` caps any single component.
//! * Bulk WRITE bytes ride through the per-mount-instance SHM
//!   ring (`TransferDescriptor::shm`); no inline-regs path.

use trona_kernel::core_types::TronaMsg;
use trona_runtime::core::slot_alloc;

use crate::core::error::VfsError;
use crate::core::file::{VATTR_ATIME, VATTR_GID, VATTR_MODE, VATTR_MTIME, VATTR_UID, VAttr};
use crate::core::identity::{BackendNodeId, FsInstanceId, VnodeKey};
use crate::ipc::protocol::backend::{
    BACKEND_CREATE, BACKEND_LINK, BACKEND_MKDIR, BACKEND_RENAME, BACKEND_RMDIR,
    BACKEND_RW_REQ_DESCRIPTOR_REG, BACKEND_SETATTR, BACKEND_SYMLINK, BACKEND_TRUNCATE,
    BACKEND_UNLINK, BACKEND_WRITE, SETATTR_MASK_ATIME, SETATTR_MASK_GID, SETATTR_MASK_MODE,
    SETATTR_MASK_MTIME, SETATTR_MASK_UID, TransferDescriptor, VFS_BACKEND_REPLY_OK,
};
use crate::owner::op::{OpKind, OpState};
use crate::owner::ordering::{OrderingDecision, OrderingKey};
use crate::owner::pending::{PendingOpHandle, WALK_NAME_MAX, WALK_SYMLINK_TARGET_MAX};

use super::op_kind::SaltyfsOpKind;
use super::rpc::{ipc_ctx, stamp_saltyfs_async_request};
use super::types::{SALTYFS_NAME_MAX, SaltyfsMountData};

/// Convert the personality-neutral `VAttr.valid` bits into the
/// SaltyFS backend wire mask. Keep this explicit even while the
/// current numeric values line up; protocol masks and core VAttr
/// masks are separate ABI surfaces.
#[inline]
pub(crate) fn setattr_mask_from_vattr(valid: u32) -> u32 {
    let mut mask = 0u32;
    if (valid & VATTR_MODE) != 0 {
        mask |= SETATTR_MASK_MODE;
    }
    if (valid & VATTR_UID) != 0 {
        mask |= SETATTR_MASK_UID;
    }
    if (valid & VATTR_GID) != 0 {
        mask |= SETATTR_MASK_GID;
    }
    if (valid & VATTR_ATIME) != 0 {
        mask |= SETATTR_MASK_ATIME;
    }
    if (valid & VATTR_MTIME) != 0 {
        mask |= SETATTR_MASK_MTIME;
    }
    mask
}

#[inline]
fn saltyfs_name_fits(name_len: u8) -> bool {
    let len = name_len as usize;
    len <= SALTYFS_NAME_MAX && len <= WALK_NAME_MAX
}

#[inline]
fn stamp_mutation_core(
    state: &mut crate::owner::VfsState,
    handle: PendingOpHandle,
    op_kind: OpKind,
    fs_instance_id: FsInstanceId,
    node_id: u64,
    node_seq: u32,
) {
    if let Some(op) = state.pending_ops.get_mut(handle) {
        op.core.kind = op_kind;
        op.core.vnode_key = VnodeKey::new(fs_instance_id, BackendNodeId::new(node_id, node_seq));
    }
}

// ---------------------------------------------------------------------------
// Pack helper — write a name buffer into consecutive register
// bytes, eight per word.
// ---------------------------------------------------------------------------

#[inline]
unsafe fn pack_name_at(req: &mut TronaMsg, reg_base: usize, name: *const u8, name_len: u8) {
    unsafe {
        let dst = (&raw mut req.regs[reg_base]) as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
    }
}

#[inline]
fn name_word_count(name_len: u8) -> u64 {
    ((name_len as u64) + 7) / 8
}

// ---------------------------------------------------------------------------
// BACKEND_CREATE
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_create_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    parent_seq: u32,
    name: *const u8,
    name_len: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if !saltyfs_name_fits(name_len) {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let kind = SaltyfsOpKind::Create {
            parent_ino,
            name: name_buf,
            name_len,
            mode,
            uid,
            gid,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        stamp_mutation_core(
            state,
            handle,
            OpKind::DirMutate,
            fs_instance_id,
            parent_ino,
            parent_seq,
        );
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_CREATE;
        req.regs[0] = parent_ino;
        req.regs[1] = mode as u64;
        req.regs[2] = uid as u64;
        req.regs[3] = gid as u64;
        req.regs[4] = name_len as u64;
        pack_name_at(&mut req, 5, name, name_len);
        req.length = 5 + name_word_count(name_len);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_CREATE, tx_id, parent_seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// BACKEND_MKDIR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_mkdir_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    parent_seq: u32,
    name: *const u8,
    name_len: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if !saltyfs_name_fits(name_len) {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let kind = SaltyfsOpKind::Mkdir {
            parent_ino,
            name: name_buf,
            name_len,
            mode,
            uid,
            gid,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        stamp_mutation_core(
            state,
            handle,
            OpKind::DirMutate,
            fs_instance_id,
            parent_ino,
            parent_seq,
        );
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_MKDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = mode as u64;
        req.regs[2] = uid as u64;
        req.regs[3] = gid as u64;
        req.regs[4] = name_len as u64;
        pack_name_at(&mut req, 5, name, name_len);
        req.length = 5 + name_word_count(name_len);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_MKDIR, tx_id, parent_seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// BACKEND_SYMLINK
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_symlink_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    parent_seq: u32,
    name: *const u8,
    name_len: u8,
    target: *const u8,
    target_len: u8,
    uid: u32,
    gid: u32,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        // SaltyfsOpKind::Symlink stores the target inline in a
        // 64-byte buffer — large targets are rejected at issue
        // time so the deferred-issue drain can rebuild both
        // payloads without an SHM dependency.
        if !saltyfs_name_fits(name_len) || target_len as usize > 64 {
            return None;
        }
        let _ = WALK_SYMLINK_TARGET_MAX; // wire upper bound; vops
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let mut target_buf = [0u8; 64];
        for i in 0..target_len as usize {
            target_buf[i] = *target.add(i);
        }
        let kind = SaltyfsOpKind::Symlink {
            parent_ino,
            name: name_buf,
            target: target_buf,
            name_len,
            target_len,
            uid,
            gid,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        stamp_mutation_core(
            state,
            handle,
            OpKind::DirMutate,
            fs_instance_id,
            parent_ino,
            parent_seq,
        );
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_SYMLINK;
        req.regs[0] = parent_ino;
        req.regs[1] = uid as u64;
        req.regs[2] = gid as u64;
        req.regs[3] = name_len as u64;
        req.regs[4] = target_len as u64;
        pack_name_at(&mut req, 5, name, name_len);
        let target_reg_base = 5 + name_word_count(name_len) as usize;
        pack_name_at(&mut req, target_reg_base, target, target_len);
        req.length = (target_reg_base as u64) + ((target_len as u64 + 7) / 8);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_SYMLINK, tx_id, parent_seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// BACKEND_UNLINK
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_unlink_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    parent_seq: u32,
    name: *const u8,
    name_len: u8,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if !saltyfs_name_fits(name_len) {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let kind = SaltyfsOpKind::Unlink {
            parent_ino,
            name: name_buf,
            name_len,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        stamp_mutation_core(
            state,
            handle,
            OpKind::DirMutate,
            fs_instance_id,
            parent_ino,
            parent_seq,
        );
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_UNLINK;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        pack_name_at(&mut req, 2, name, name_len);
        req.length = 2 + name_word_count(name_len);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_UNLINK, tx_id, parent_seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// BACKEND_RMDIR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_rmdir_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    parent_seq: u32,
    name: *const u8,
    name_len: u8,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if !saltyfs_name_fits(name_len) {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let kind = SaltyfsOpKind::Rmdir {
            parent_ino,
            name: name_buf,
            name_len,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        stamp_mutation_core(
            state,
            handle,
            OpKind::DirMutate,
            fs_instance_id,
            parent_ino,
            parent_seq,
        );
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_RMDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        pack_name_at(&mut req, 2, name, name_len);
        req.length = 2 + name_word_count(name_len);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_RMDIR, tx_id, parent_seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// BACKEND_LINK
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_link_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    parent_seq: u32,
    target_ino: u64,
    target_seq: u32,
    name: *const u8,
    name_len: u8,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if !saltyfs_name_fits(name_len) {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let kind = SaltyfsOpKind::Link {
            parent_ino,
            target_ino,
            name: name_buf,
            name_len,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        stamp_mutation_core(
            state,
            handle,
            OpKind::DirMutate,
            fs_instance_id,
            parent_ino,
            parent_seq,
        );
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_LINK;
        req.regs[0] = parent_ino;
        req.regs[1] = target_ino;
        req.regs[2] = name_len as u64;
        pack_name_at(&mut req, 3, name, name_len);
        req.length = 3 + name_word_count(name_len);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_LINK, tx_id, parent_seq, target_seq);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// BACKEND_RENAME
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_rename_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    old_parent_ino: u64,
    old_parent_seq: u32,
    old_name: *const u8,
    old_len: u8,
    new_parent_ino: u64,
    new_parent_seq: u32,
    new_name: *const u8,
    new_len: u8,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if !saltyfs_name_fits(old_len) || !saltyfs_name_fits(new_len) {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut old_buf = [0u8; WALK_NAME_MAX];
        let mut new_buf = [0u8; WALK_NAME_MAX];
        for i in 0..old_len as usize {
            old_buf[i] = *old_name.add(i);
        }
        for i in 0..new_len as usize {
            new_buf[i] = *new_name.add(i);
        }
        let kind = SaltyfsOpKind::Rename {
            old_parent_ino,
            new_parent_ino,
            old_name: old_buf,
            new_name: new_buf,
            old_name_len: old_len,
            new_name_len: new_len,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        stamp_mutation_core(
            state,
            handle,
            OpKind::DirMutate,
            fs_instance_id,
            old_parent_ino,
            old_parent_seq,
        );
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_RENAME;
        req.regs[0] = old_parent_ino;
        req.regs[1] = new_parent_ino;
        req.regs[2] = old_len as u64;
        req.regs[3] = new_len as u64;
        pack_name_at(&mut req, 4, old_name, old_len);
        let new_reg_base = 4 + name_word_count(old_len) as usize;
        pack_name_at(&mut req, new_reg_base, new_name, new_len);
        req.length = (new_reg_base as u64) + name_word_count(new_len);
        stamp_saltyfs_async_request(
            md,
            &mut req,
            BACKEND_RENAME,
            tx_id,
            old_parent_seq,
            new_parent_seq,
        );
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// BACKEND_SETATTR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_setattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    mask: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    atime: u64,
    mtime: u64,
    size: u64,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        let kind = SaltyfsOpKind::SetAttr {
            ino,
            mask,
            mode,
            uid,
            gid,
            atime,
            mtime,
            size,
        };
        let (handle, tx_id) = state.reserve_fs_pending(fs_instance_id, kind.pack())?;
        stamp_mutation_core(state, handle, OpKind::AttrMutate, fs_instance_id, ino, seq);
        let key =
            OrderingKey::VnodeMutate(VnodeKey::new(fs_instance_id, BackendNodeId::new(ino, seq)));
        match state.ordering.try_issue(key, tx_id) {
            OrderingDecision::Queued => Some(handle),
            OrderingDecision::Issue => {
                match issue_reserved_attr_mutation_with_cap(
                    state,
                    handle,
                    (*md).fs_cap,
                    (*md).session_id,
                ) {
                    Ok(()) => Some(handle),
                    Err(err) => {
                        let _ = state.ordering.complete(key, tx_id, Some(err));
                        let _ = state.pending_ops.release(handle);
                        None
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BACKEND_TRUNCATE
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_truncate_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    new_size: u64,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        // old_size is captured by the posix resume context
        // (`FsResume::FinalOpAckTruncate { old_size, .. }`) at
        // stamp time — the kind payload does not need to carry
        // it.
        let kind = SaltyfsOpKind::Truncate { ino, new_size };
        let (handle, tx_id) = state.reserve_fs_pending(fs_instance_id, kind.pack())?;
        stamp_mutation_core(state, handle, OpKind::AttrMutate, fs_instance_id, ino, seq);
        let key =
            OrderingKey::VnodeMutate(VnodeKey::new(fs_instance_id, BackendNodeId::new(ino, seq)));
        match state.ordering.try_issue(key, tx_id) {
            OrderingDecision::Queued => Some(handle),
            OrderingDecision::Issue => {
                match issue_reserved_attr_mutation_with_cap(
                    state,
                    handle,
                    (*md).fs_cap,
                    (*md).session_id,
                ) {
                    Ok(()) => Some(handle),
                    Err(err) => {
                        let _ = state.ordering.complete(key, tx_id, Some(err));
                        let _ = state.pending_ops.release(handle);
                        None
                    }
                }
            }
        }
    }
}

/// Issue a dependency-held metadata mutation once the ordering
/// gate promotes its transaction to lane head. Supports the
/// `SaltyfsOpKind` variants whose request can be reconstructed
/// exactly from the pending payload plus `OpCore.vnode_key`.
pub(crate) fn issue_parked_attr_mutation(
    state: &mut crate::owner::VfsState,
    handle: PendingOpHandle,
) -> Result<(), VfsError> {
    let (session_idx, session_gen) = {
        let op = state
            .pending_ops
            .get(handle)
            .ok_or(VfsError::StaleIncarnation)?;
        (op.core.backend_session_idx, op.core.backend_session_gen)
    };
    let session_h = state
        .backend_sessions
        .handle_from_slot(session_idx)
        .ok_or(VfsError::SessionTornDown)?;
    let (send_cap, session_id) = {
        let session = state
            .backend_sessions
            .get(session_h)
            .ok_or(VfsError::SessionTornDown)?;
        if session.live_gen != session_gen || session.is_empty() {
            return Err(VfsError::SessionTornDown);
        }
        (session.send_cap.as_raw(), session.session_id)
    };
    issue_reserved_attr_mutation_with_cap(state, handle, send_cap, session_id)
}

fn issue_reserved_attr_mutation_with_cap(
    state: &mut crate::owner::VfsState,
    handle: PendingOpHandle,
    send_cap: u64,
    session_id: u32,
) -> Result<(), VfsError> {
    let (tx_id, session_idx, kind_payload, request_seq) = {
        let op = state
            .pending_ops
            .get(handle)
            .ok_or(VfsError::StaleIncarnation)?;
        (
            op.core.tx_id,
            op.core.backend_session_idx,
            op.kind_payload,
            op.core.vnode_key.backend_id.seq,
        )
    };
    let kind = unsafe { SaltyfsOpKind::unpack(&kind_payload) };
    if !kind.validate_completion_envelope() {
        return Err(VfsError::Inval);
    }
    let session_h = state
        .backend_sessions
        .handle_from_slot(session_idx)
        .ok_or(VfsError::SessionTornDown)?;
    if !state.backend_credit_reserve_for_session(session_h) {
        return Err(VfsError::Busy);
    }

    let mut req = TronaMsg::zeroed();
    let opcode = match kind {
        SaltyfsOpKind::SetAttr {
            ino,
            mask,
            mode,
            uid,
            gid,
            atime,
            mtime,
            size,
        } => {
            req.label = BACKEND_SETATTR;
            req.regs[0] = ino;
            req.regs[1] = mask as u64;
            req.regs[2] = mode as u64;
            req.regs[3] = uid as u64;
            req.regs[4] = gid as u64;
            req.regs[5] = atime;
            req.regs[6] = mtime;
            req.regs[7] = size;
            req.length = 8;
            BACKEND_SETATTR
        }
        SaltyfsOpKind::Truncate { ino, new_size } => {
            req.label = BACKEND_TRUNCATE;
            req.regs[0] = ino;
            req.regs[1] = new_size;
            req.length = 2;
            BACKEND_TRUNCATE
        }
        _ => {
            state.backend_credit_release_for_session(session_h);
            return Err(VfsError::Inval);
        }
    };
    stamp_saltyfs_async_request_from_session(session_id, &mut req, opcode, tx_id, request_seq, 0);
    let send_err = unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx(), send_cap, &raw const req) };
    if send_err != 0 {
        state.backend_credit_release_for_session(session_h);
        return Err(VfsError::Io);
    }
    if let Some(op) = state.pending_ops.get_mut(handle) {
        op.core.state = OpState::Running;
        op.core.credit_held = true;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BACKEND_FSYNC
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_fsync_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    flags: u32,
    fs_instance_id: FsInstanceId,
    vnode_key: VnodeKey,
) -> Option<PendingOpHandle> {
    unsafe {
        let kind = SaltyfsOpKind::Fsync { ino, seq, flags };
        let (handle, _tx_id) = state.reserve_fs_pending(fs_instance_id, kind.pack())?;
        if let Some(op) = state.pending_ops.get_mut(handle) {
            op.core.kind = OpKind::Sync;
            op.core.vnode_key = vnode_key;
        }
        let tx_id = state
            .pending_ops
            .get(handle)
            .map(|op| op.core.tx_id)
            .unwrap_or(crate::owner::pending::TxId::INVALID);
        let waiting_on = state.ordering.add_barrier(
            crate::owner::ordering::OrderingKey::VnodeMutate(vnode_key),
            tx_id,
        );
        if waiting_on != 0 {
            return Some(handle);
        }
        if issue_reserved_fsync_with_cap(state, handle, (*md).fs_cap, (*md).session_id).is_err() {
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

/// Issue a dependency-held `BACKEND_FSYNC` once all predecessor
/// writes have completed. The pending op must already be stamped
/// as `OpKind::Sync`; this helper only reserves backend credit,
/// rebuilds the wire request from `SaltyfsOpKind::Fsync`, sends it,
/// and flips the op to `Running`.
pub(crate) fn issue_parked_fsync(
    state: &mut crate::owner::VfsState,
    handle: PendingOpHandle,
) -> Result<(), VfsError> {
    let (session_idx, session_gen) = {
        let op = state
            .pending_ops
            .get(handle)
            .ok_or(VfsError::StaleIncarnation)?;
        (op.core.backend_session_idx, op.core.backend_session_gen)
    };
    let session_h = state
        .backend_sessions
        .handle_from_slot(session_idx)
        .ok_or(VfsError::SessionTornDown)?;
    let (send_cap, session_id) = {
        let session = state
            .backend_sessions
            .get(session_h)
            .ok_or(VfsError::SessionTornDown)?;
        if session.live_gen != session_gen || session.is_empty() {
            return Err(VfsError::SessionTornDown);
        }
        (session.send_cap.as_raw(), session.session_id)
    };
    issue_reserved_fsync_with_cap(state, handle, send_cap, session_id)
}

fn issue_reserved_fsync_with_cap(
    state: &mut crate::owner::VfsState,
    handle: PendingOpHandle,
    send_cap: u64,
    session_id: u32,
) -> Result<(), VfsError> {
    let (tx_id, session_idx, kind_payload) = {
        let op = state
            .pending_ops
            .get(handle)
            .ok_or(VfsError::StaleIncarnation)?;
        (op.core.tx_id, op.core.backend_session_idx, op.kind_payload)
    };
    let kind = unsafe { SaltyfsOpKind::unpack(&kind_payload) };
    let SaltyfsOpKind::Fsync { ino, seq, flags } = kind else {
        return Err(VfsError::Inval);
    };
    let session_h = state
        .backend_sessions
        .handle_from_slot(session_idx)
        .ok_or(VfsError::SessionTornDown)?;
    if !state.backend_credit_reserve_for_session(session_h) {
        return Err(VfsError::Busy);
    }

    let mut req = TronaMsg::zeroed();
    req.label = crate::ipc::protocol::backend::BACKEND_FSYNC;
    req.regs[0] = ino;
    req.regs[1] = flags as u64;
    req.length = 2;
    stamp_saltyfs_async_request_from_session(
        session_id,
        &mut req,
        crate::ipc::protocol::backend::BACKEND_FSYNC,
        tx_id,
        seq,
        0,
    );
    let send_err = unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx(), send_cap, &raw const req) };
    if send_err != 0 {
        state.backend_credit_release_for_session(session_h);
        return Err(VfsError::Io);
    }
    if let Some(op) = state.pending_ops.get_mut(handle) {
        op.core.state = OpState::Running;
        op.core.credit_held = true;
    }
    Ok(())
}

fn stamp_saltyfs_async_request_from_session(
    session_id: u32,
    req: &mut TronaMsg,
    opcode: u64,
    tx_id: crate::owner::pending::TxId,
    request_seq: u32,
    request_seq_secondary: u32,
) {
    use crate::ipc::protocol::correlation::{
        CORRELATION_BACKEND_SALTYFS, CORRELATION_CLASS_FS, CORRELATION_HEADER_REG_START,
        CORRELATION_KIND_REQUEST, CorrelationHeader, ensure_correlation_wire_length,
    };

    let words = CorrelationHeader {
        class: CORRELATION_CLASS_FS,
        backend: CORRELATION_BACKEND_SALTYFS,
        kind: CORRELATION_KIND_REQUEST,
        flags: 0,
        session: session_id,
        opcode: opcode as u16,
        _reserved0: 0,
        token: tx_id.raw(),
        request_seq,
        request_seq_secondary,
    }
    .encode_words();
    req.regs[CORRELATION_HEADER_REG_START] = words[0];
    req.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    req.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    req.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    ensure_correlation_wire_length(&mut req.length);
}

// ---------------------------------------------------------------------------
// BACKEND_WRITE
// ---------------------------------------------------------------------------

/// Issue an asynchronous `BACKEND_WRITE`. Hybrid-1 dispatch:
///
/// * `transfer.kind == TRANSFER_KIND_INLINE` — `inline_payload` carries
///   exactly `transfer.length` bytes (≤ `INLINE_TRANSFER_WIRE_MAX`).
///   They are packed into `regs[BACKEND_WRITE_INLINE_PAYLOAD_REG..]`
///   and ride in the IPC buffer; no SHM ring slot is consumed.
/// * `transfer.kind == TRANSFER_KIND_SHM` — caller has copied the
///   payload into the per-session SHM ring at `transfer.offset`
///   already; only the descriptor rides in regs.
/// * `transfer.kind == TRANSFER_KIND_MO` — caller has retyped a
///   transient MO via `MM_MO_CREATE`, copied the payload through
///   their own short-lived `MM_MMAP` of that MO, and passes the
///   MO cap as `mo_cap`. It is staged into `caps[0]` so the
///   daemon can map it into its staging window.
///
/// `inline_payload` must be `null` for the SHM and MO kinds; `mo_cap`
/// must be 0 for the INLINE and SHM kinds. Mixing yields a malformed
/// request.
pub(crate) unsafe fn saltyfs_ipc_write_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    file_offset: u64,
    transfer: TransferDescriptor,
    inline_payload: *const u8,
    mo_cap: u64,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let kind = SaltyfsOpKind::Write {
            ino,
            file_offset,
            transfer,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_WRITE;
        req.regs[0] = ino;
        req.regs[1] = file_offset;
        // Pack all four descriptor words `(kind, flags, offset, length)`.
        let desc = transfer.encode_regs();
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG] = desc[0];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 1] = desc[1];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 2] = desc[2];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 3] = desc[3];

        // INLINE: copy payload bytes into the regs[8..28] window.
        // Reach into a `*mut u8` view of the regs array so a
        // sub-word `length` does not require word-aligned packing.
        let mut wire_len =
            (BACKEND_RW_REQ_DESCRIPTOR_REG as u64) + u64::from(TransferDescriptor::REG_COUNT);
        if transfer.kind == trona_protocol::vfs::backend::TRANSFER_KIND_INLINE
            && transfer.length > 0
        {
            let copy_len = ::core::cmp::min(
                transfer.length,
                trona_protocol::vfs::backend::INLINE_TRANSFER_WIRE_MAX,
            ) as usize;
            let dst = &raw mut req.regs
                [trona_protocol::vfs::backend::BACKEND_WRITE_INLINE_PAYLOAD_REG]
                as *mut u8;
            ::core::ptr::copy_nonoverlapping(inline_payload, dst, copy_len);
            // Advance the wire length up to (and including) the
            // last partially-filled register so the receiver sees
            // every byte we packed. Round bytes up to whole regs.
            let inline_regs = ((copy_len + 7) / 8) as u64;
            wire_len = (trona_protocol::vfs::backend::BACKEND_WRITE_INLINE_PAYLOAD_REG as u64)
                + inline_regs;
        }
        req.length = wire_len;
        stamp_saltyfs_async_request(md, &mut req, BACKEND_WRITE, tx_id, seq, 0);

        // MO: stage the cap into caps[0] before the send. INLINE /
        // SHM clear send_cap_count to keep the wire shape clean.
        let ctx = ipc_ctx();
        if transfer.kind == trona_protocol::vfs::backend::TRANSFER_KIND_MO {
            trona_kernel::ipc::set_send_cap_ctx(ctx, 0, mo_cap);
        } else {
            trona_kernel::ipc::clear_send_caps_ctx(ctx);
        }

        let send_err = trona_kernel::ipc::mp_write_ctx(ctx, (*md).fs_cap, &raw const req);

        // Per-RPC MO cap teardown happens inline. The kernel
        // `cnode_copy`'d the cap into the daemon's receive slot at
        // send time, so the sender's slot is now redundant on
        // success — drop it. On failure the daemon never saw the
        // cap, so the sender still needs to release it. Either
        // way the slot is recycled before this function returns,
        // and the completion router has no MO bookkeeping to do.
        if transfer.kind == trona_protocol::vfs::backend::TRANSFER_KIND_MO && mo_cap != 0 {
            slot_alloc::delete_and_free(mo_cap);
        }

        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

// ---------------------------------------------------------------------------
// Reply parsers — used by completion.rs to harvest mutation reply
// shapes without re-issuing.
// ---------------------------------------------------------------------------

/// Parse a `BACKEND_SETATTR` reply into the post-commit
/// attribute snapshot. The backend echoes the fields the
/// caller mutated plus the resulting `mtime` so the cache can
/// refresh without a follow-up stat. `None` on backend
/// failure / malformed reply.
pub(crate) fn saltyfs_ipc_setattr_parse(reply: &TronaMsg) -> Option<VAttr> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return None;
    }
    let mut attr = VAttr::zeroed();
    attr.mode = reply.regs[0] as u32;
    attr.uid = reply.regs[1] as u32;
    attr.gid = reply.regs[2] as u32;
    attr.size = reply.regs[3];
    attr.nlink = reply.regs[4] as u32;
    attr.mtime = reply.regs[5];
    Some(attr)
}

/// Parse a compound-mutation child reply (`BACKEND_CREATE` /
/// `BACKEND_MKDIR` / `BACKEND_SYMLINK`) into the new node's ino.
/// The completion router synthesises the rest of the attrs from
/// the request side rather than chaining a follow-up stat. Error
/// labels propagate to the caller via the `Err(label)` arm.
pub(crate) fn saltyfs_ipc_child_reply_parse(reply: &TronaMsg) -> Result<u64, u64> {
    if reply.label == VFS_BACKEND_REPLY_OK {
        Ok(reply.regs[0])
    } else {
        Err(reply.label)
    }
}
