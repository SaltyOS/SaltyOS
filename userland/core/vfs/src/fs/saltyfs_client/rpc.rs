// SPDX-License-Identifier: GPL-2.0-only
//
//! Read-only SaltyFS IPC helpers — lookup / stat / read / readlink /
//! readdir. Async issue helpers reserve a `PendingOp` and stamp
//! the correlation header; parse helpers let the completion router
//! harvest replies without re-issuing. Mount-level synchronous
//! calls live in `vfsops.rs`, where `VfsOps::{vget, statfs, sync}`
//! need immediate return values.
//!
//! Mutation calls (`BACKEND_CREATE` / `BACKEND_MKDIR` / etc.) live
//! in the sibling `mutate_rpc` module; xattr calls live in
//! `xattr_rpc`. Splitting by op-class keeps each file under a
//! reading-budget threshold.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::identity::FsInstanceId;
use crate::ipc::protocol::backend::{
    BACKEND_LOOKUP, BACKEND_READ, BACKEND_READDIR, BACKEND_READLINK, BACKEND_RW_REQ_DESCRIPTOR_REG,
    BACKEND_STAT, TransferDescriptor, VFS_BACKEND_REPLY_NOT_FOUND, VFS_BACKEND_REPLY_OK,
};
use crate::ipc::protocol::correlation::{
    CORRELATION_BACKEND_SALTYFS, CORRELATION_CLASS_FS, CORRELATION_F_LOOKUP_PARENT,
    CORRELATION_HEADER_REG_START, CORRELATION_KIND_REQUEST, CorrelationHeader,
    ensure_correlation_wire_length,
};
use crate::owner::pending::{PendingOpHandle, TxId, WALK_NAME_MAX, WALK_SYMLINK_TARGET_MAX};

use super::op_kind::SaltyfsOpKind;
use super::types::SaltyfsMountData;

#[inline]
pub(super) fn ipc_ctx() -> *mut trona_kernel::core_types::IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

/// Stamp the correlation header onto a saltyfs request and ensure
/// the kernel-side length copy will carry the trailing header
/// words. Every async issue helper calls this immediately before
/// firing the IPC.
#[inline]
pub(crate) unsafe fn stamp_saltyfs_async_request(
    md: *mut SaltyfsMountData,
    req: &mut TronaMsg,
    opcode: u64,
    tx_id: TxId,
    request_seq: u32,
    request_seq_secondary: u32,
) {
    let words = CorrelationHeader {
        class: CORRELATION_CLASS_FS,
        backend: CORRELATION_BACKEND_SALTYFS,
        kind: CORRELATION_KIND_REQUEST,
        flags: 0,
        session: unsafe { (*md).session_id },
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

// =========================================================================
// BACKEND_LOOKUP
// =========================================================================

/// Walk the live `pending_ops` arena looking for an active saltyfs
/// `Lookup` op against the same `(fs_instance_id, parent_ino,
/// name)` triple. Used by `saltyfs_ipc_lookup_issue` to coalesce
/// concurrent walks of the same path component onto a single
/// in-flight RPC.
fn lookup_primary_tx(
    state: &crate::owner::VfsState,
    fs_instance_id: FsInstanceId,
    parent_ino: u64,
    name: &[u8],
) -> Option<TxId> {
    let mut found = TxId::INVALID;
    state.pending_ops.for_each_active(|_, op| {
        if !op.core.tx_id.is_valid() || op.core.cancelled || op.core.coalesce_primary_tx.is_valid()
        {
            return true;
        }
        if op.core.vnode_key.fs_instance_id != fs_instance_id {
            return true;
        }
        let kind = unsafe { SaltyfsOpKind::unpack(&op.kind_payload) };
        if let SaltyfsOpKind::Lookup {
            parent_ino: op_parent,
            name: op_name,
            name_len,
        } = kind
        {
            if op_parent == parent_ino
                && (name_len as usize) == name.len()
                && op_name[..name_len as usize] == *name
            {
                found = op.core.tx_id;
                return false;
            }
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

/// Issue an asynchronous `BACKEND_LOOKUP`. Reserves a `PendingOp`
/// tagged with `SaltyfsOpKind::Lookup`, stamps the correlation
/// header, fires `mp_write_ctx`, and returns the handle so the
/// posix layer can attach a `Resume` continuation.
///
/// Coalesces against an existing in-flight lookup of the same
/// `(parent_ino, name)` — the secondary's reply slot is satisfied
/// from the primary's reply at completion time.
pub(super) unsafe fn saltyfs_ipc_lookup_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    parent_seq: u32,
    name: *const u8,
    name_len: u8,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    if name_len as usize > WALK_NAME_MAX {
        return None;
    }
    let mut name_bytes = [0u8; WALK_NAME_MAX];
    for i in 0..name_len as usize {
        name_bytes[i] = unsafe { *name.add(i) };
    }
    let (handle, tx_id) = state.reserve_fs_pending(
        fs_instance_id,
        SaltyfsOpKind::Lookup {
            parent_ino,
            name: name_bytes,
            name_len,
        }
        .pack(),
    )?;
    let name_slice = &name_bytes[..name_len as usize];
    if let Some(primary_tx) = lookup_primary_tx(state, fs_instance_id, parent_ino, name_slice) {
        if state.mark_lookup_coalesced_secondary(handle, primary_tx) {
            return Some(handle);
        }
        let _ = state.pending_ops.release(handle);
        return None;
    }

    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_LOOKUP;
    req.regs[0] = parent_ino;
    req.regs[1] = name_len as u64;
    let dst = &raw mut req.regs[2] as *mut u8;
    for i in 0..name_len as usize {
        unsafe { *dst.add(i) = *name.add(i) };
    }
    req.length = 2 + ((name_len as u64) + 7) / 8;
    unsafe { stamp_saltyfs_async_request(md, &mut req, BACKEND_LOOKUP, tx_id, parent_seq, 0) };
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req) };
    if state.observe_backend_send(fs_instance_id, send_err) != 0 {
        let _ = state.pending_ops.release(handle);
        return None;
    }
    Some(handle)
}

/// Issue a `BACKEND_LOOKUP` with `CORRELATION_F_LOOKUP_PARENT` —
/// the server treats `regs[0]` as the *child* inode and replies
/// with the parent's stat-merged record. Replaces the legacy
/// `getparent + stat` pair on the dotdot-walk path.
pub(crate) unsafe fn saltyfs_ipc_lookup_parent_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    child_ino: u64,
    child_seq: u32,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    let mut name_bytes = [0u8; WALK_NAME_MAX];
    name_bytes[0] = b'.';
    name_bytes[1] = b'.';

    let (handle, tx_id) = state.reserve_fs_pending(
        fs_instance_id,
        SaltyfsOpKind::Lookup {
            parent_ino: child_ino,
            name: name_bytes,
            name_len: 2,
        }
        .pack(),
    )?;

    let name_slice = &name_bytes[..2];
    if let Some(primary_tx) = lookup_primary_tx(state, fs_instance_id, child_ino, name_slice) {
        if state.mark_lookup_coalesced_secondary(handle, primary_tx) {
            return Some(handle);
        }
        let _ = state.pending_ops.release(handle);
        return None;
    }

    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_LOOKUP;
    req.regs[0] = child_ino;
    req.regs[1] = 2;
    let dst = &raw mut req.regs[2] as *mut u8;
    unsafe {
        *dst = b'.';
        *dst.add(1) = b'.';
    }

    // Manual encode path — flag bit must ride in the header. The
    // helper `stamp_saltyfs_async_request` always sends `flags=0`,
    // so we encode the header by hand here.
    let words = CorrelationHeader {
        class: CORRELATION_CLASS_FS,
        backend: CORRELATION_BACKEND_SALTYFS,
        kind: CORRELATION_KIND_REQUEST,
        flags: CORRELATION_F_LOOKUP_PARENT,
        session: unsafe { (*md).session_id },
        opcode: BACKEND_LOOKUP as u16,
        _reserved0: 0,
        token: tx_id.raw(),
        request_seq: child_seq,
        request_seq_secondary: 0,
    }
    .encode_words();
    req.regs[CORRELATION_HEADER_REG_START] = words[0];
    req.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    req.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    req.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    req.length = 3;
    ensure_correlation_wire_length(&mut req.length);

    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req) };
    if state.observe_backend_send(fs_instance_id, send_err) != 0 {
        let _ = state.pending_ops.release(handle);
        return None;
    }
    Some(handle)
}

/// Parse a `BACKEND_LOOKUP` completion. `Ok(Some(tuple))` =
/// success. `Ok(None)` = clean ENOENT. `Err(VfsError)` = backend
/// error / malformed reply.
pub(crate) fn saltyfs_ipc_lookup_parse(
    reply: &TronaMsg,
) -> Result<Option<(u64, u32, u32, u64, u32, u64, u32, u32, u8, u64)>, VfsError> {
    match reply.label {
        VFS_BACKEND_REPLY_OK => Ok(Some((
            reply.regs[0],
            reply.regs[1] as u32,
            reply.regs[2] as u32,
            reply.regs[3],
            reply.regs[4] as u32,
            reply.regs[5],
            reply.regs[6] as u32,
            reply.regs[7] as u32,
            reply.regs[8] as u8,
            reply.regs[9],
        ))),
        VFS_BACKEND_REPLY_NOT_FOUND => Ok(None),
        other => Err(VfsError::from_backend_reply(other)),
    }
}

// =========================================================================
// BACKEND_STAT
// =========================================================================

/// Issue an asynchronous `BACKEND_STAT`. Reserves a `PendingOp`,
/// stamps the correlation header, fires `mp_write_ctx`. The
/// caller installs a `Resume` continuation before returning to
/// the owner loop.
pub(super) unsafe fn saltyfs_ipc_stat_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    let (handle, tx_id) =
        state.reserve_fs_pending(fs_instance_id, SaltyfsOpKind::Stat { ino }.pack())?;
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_STAT;
    req.regs[0] = ino;
    req.length = 1;
    unsafe { stamp_saltyfs_async_request(md, &mut req, BACKEND_STAT, tx_id, seq, 0) };
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req) };
    if state.observe_backend_send(fs_instance_id, send_err) != 0 {
        let _ = state.pending_ops.release(handle);
        return None;
    }
    Some(handle)
}

/// Parse a `BACKEND_STAT` completion. `None` on backend failure.
/// Tuple shape: `(size, mode, nlink, mtime, blocks, uid, gid, dir_type)`.
pub(crate) fn saltyfs_ipc_stat_parse(
    reply: &TronaMsg,
) -> Option<(u64, u32, u32, u64, u64, u32, u32, u32)> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return None;
    }
    Some((
        reply.regs[1],
        reply.regs[2] as u32,
        reply.regs[3] as u32,
        reply.regs[4],
        reply.regs[5],
        reply.regs[6] as u32,
        reply.regs[7] as u32,
        reply.regs[8] as u32,
    ))
}

// =========================================================================
// BACKEND_READLINK
// =========================================================================

/// Issue an asynchronous `BACKEND_READLINK`.
pub(crate) unsafe fn saltyfs_ipc_readlink_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    let (handle, tx_id) =
        state.reserve_fs_pending(fs_instance_id, SaltyfsOpKind::Readlink { ino }.pack())?;
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_READLINK;
    req.regs[0] = ino;
    req.length = 1;
    unsafe { stamp_saltyfs_async_request(md, &mut req, BACKEND_READLINK, tx_id, seq, 0) };
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req) };
    if state.observe_backend_send(fs_instance_id, send_err) != 0 {
        let _ = state.pending_ops.release(handle);
        return None;
    }
    Some(handle)
}

/// Parse a `BACKEND_READLINK` reply. Returns the target as an
/// inline byte buffer + length, or `None` on backend failure.
pub(crate) fn saltyfs_ipc_readlink_parse(
    reply: &TronaMsg,
) -> Option<([u8; WALK_SYMLINK_TARGET_MAX], usize)> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return None;
    }
    let target_len = reply.regs[0] as usize;
    if target_len == 0 || target_len > WALK_SYMLINK_TARGET_MAX {
        return None;
    }
    let mut buf = [0u8; WALK_SYMLINK_TARGET_MAX];
    let src = &reply.regs[1] as *const u64 as *const u8;
    for i in 0..target_len {
        buf[i] = unsafe { *src.add(i) };
    }
    Some((buf, target_len))
}

// =========================================================================
// BACKEND_READ
// =========================================================================

/// Issue an asynchronous `BACKEND_READ`. Reserves one inflight
/// credit, reserves a `PendingOp` tagged with
/// `SaltyfsOpKind::Read`, stamps the correlation header, fires
/// `mp_write_ctx`. The `transfer` descriptor names the per-mount-
/// instance SHM ring slot (offset, count) where the backend writes
/// the bytes; the resume handler reads from there before releasing
/// credit. There is no inline-regs fast path — every backend READ
/// rides through SHM, matching the Zircon-VMO single-mechanism
/// model.
pub(crate) unsafe fn saltyfs_ipc_read_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    file_offset: u64,
    transfer: TransferDescriptor,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    if !state.backend_credit_reserve(fs_instance_id) {
        return None;
    }
    let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
        fs_instance_id,
        SaltyfsOpKind::Read {
            ino,
            file_offset,
            transfer,
        }
        .pack(),
    ) else {
        state.backend_credit_release(fs_instance_id);
        return None;
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_READ;
    req.regs[0] = ino;
    req.regs[1] = file_offset;
    // Pack all four descriptor words `(kind, flags, offset, length)`.
    // The previous 2-reg layout truncated to `(kind, flags)` and
    // dropped the offset / length, so the daemon decoded a zero-byte
    // payload window — silent corruption.
    let desc = transfer.encode_regs();
    req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG] = desc[0];
    req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 1] = desc[1];
    req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 2] = desc[2];
    req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 3] = desc[3];
    req.length = (BACKEND_RW_REQ_DESCRIPTOR_REG as u64) + u64::from(TransferDescriptor::REG_COUNT);
    unsafe { stamp_saltyfs_async_request(md, &mut req, BACKEND_READ, tx_id, seq, 0) };
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req) };
    if state.observe_backend_send(fs_instance_id, send_err) != 0 {
        let _ = state.pending_ops.release(handle);
        state.backend_credit_release(fs_instance_id);
        return None;
    }
    Some(handle)
}

/// Parse a `BACKEND_READ` completion into the delivered byte
/// count. `None` on backend failure / malformed reply.
pub(crate) fn saltyfs_ipc_read_parse(reply: &TronaMsg) -> Option<u64> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return None;
    }
    Some(reply.regs[0])
}

// =========================================================================
// BACKEND_READDIR
// =========================================================================

/// Issue an asynchronous `BACKEND_READDIR`. Reserves one inflight
/// credit, claims the per-mount-instance SHM ring (via
/// `super::deferred::acquire_readdir_shm`), reserves a
/// `PendingOp`, stamps the correlation header, fires
/// `mp_write_ctx`. On reply, the resume handler pops 96-byte
/// records out of SHM into the client's readdir reply path.
pub(crate) unsafe fn saltyfs_ipc_readdir_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    dir_ino: u64,
    dir_seq: u32,
    cookie: u64,
    shm_offset: u64,
    buf_bytes: u64,
    fs_instance_id: FsInstanceId,
    open_handle: crate::server::types::OpenObjectHandle,
) -> Option<PendingOpHandle> {
    // SAFETY: `md` is the live mount-private SaltyFS state pointer carried by
    // the caller's VOP context; this issue path only borrows it long enough to
    // claim the per-mount readdir SHM window.
    if !unsafe { super::deferred::acquire_readdir_shm(state, md, open_handle) } {
        return None;
    }
    if !state.backend_credit_reserve(fs_instance_id) {
        return None;
    }
    let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
        fs_instance_id,
        SaltyfsOpKind::Readdir {
            dir_ino,
            cookie,
            shm_offset,
            buf_bytes,
        }
        .pack(),
    ) else {
        state.backend_credit_release(fs_instance_id);
        return None;
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_READDIR;
    req.regs[0] = dir_ino;
    req.regs[1] = cookie;
    req.regs[2] = shm_offset;
    req.regs[3] = buf_bytes;
    req.length = 4;
    unsafe { stamp_saltyfs_async_request(md, &mut req, BACKEND_READDIR, tx_id, dir_seq, 0) };
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req) };
    if state.observe_backend_send(fs_instance_id, send_err) != 0 {
        let _ = state.pending_ops.release(handle);
        state.backend_credit_release(fs_instance_id);
        return None;
    }
    Some(handle)
}

/// Parse a `BACKEND_READDIR` completion.
/// Returns `(next_cursor, entries_written, bytes_written)` on
/// success. `next_cursor == 0` signals EOF.
pub(crate) fn saltyfs_ipc_readdir_parse(reply: &TronaMsg) -> Option<(u64, u64, u64)> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return None;
    }
    Some((reply.regs[0], reply.regs[1], reply.regs[2]))
}
