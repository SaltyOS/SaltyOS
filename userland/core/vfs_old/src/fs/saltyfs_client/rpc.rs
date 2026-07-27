// SPDX-License-Identifier: GPL-2.0-only
//! Read-only SaltyFS IPC helpers — lookup, stat, read, readlink, getparent.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::server::consts::*;

use super::types::SaltyfsMountData;

// =========================================================================
// IPC context accessor
// =========================================================================

#[inline]
pub(super) fn ipc_ctx() -> *mut trona_kernel::core_types::core::IpcContext {
    crate::ipc_ctx()
}

#[inline]
pub(crate) unsafe fn stamp_saltyfs_async_request(
    md: *mut SaltyfsMountData,
    req: &mut TronaMsg,
    opcode: u64,
    tx_id: crate::owner::pending::TxId,
    request_seq: u32,
    request_seq_secondary: u32,
) {
    unsafe {
        let words = CorrelationHeader {
            class: CORRELATION_CLASS_FS,
            backend: CORRELATION_BACKEND_SALTYFS,
            session: (*md).session_id,
            opcode: opcode as u16,
            kind: CORRELATION_KIND_REQUEST,
            flags: 0,
            token: tx_id.raw(),
            request_seq,
            request_seq_secondary,
        }
        .encode_words();
        req.regs[CORRELATION_HEADER_REG_START] = words[0];
        req.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
        req.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
        req.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
        // Kernel IPC copies only `msg.length` registers. Callers typically
        // set `req.length` *before* invoking this helper (so this raise
        // catches the final length), but the defence-in-depth rule is:
        // every code path that stamps a correlation header must leave
        // `msg.length >= CORRELATION_WIRE_LENGTH` on the wire. Any caller
        // that sets `req.length` again *after* this helper runs MUST
        // either do so with a value already `>= CORRELATION_WIRE_LENGTH`
        // or call `ensure_correlation_wire_length(&mut req.length)` explicitly
        // after the final length assignment.
        ensure_correlation_wire_length(&mut req.length);
    }
}

// =========================================================================
// BACKEND_LOOKUP — single-component lookup with stat-merged reply
// =========================================================================

fn lookup_primary_tx(
    state: &crate::owner::VfsState,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
    parent_ino: u64,
    name: &[u8],
) -> Option<crate::owner::pending::TxId> {
    let mut found = crate::owner::pending::TxId::INVALID;
    state.pending_ops.for_each_active(|_, op| {
        if !op.tx_id.is_valid() || op.cancelled != 0 || op.coalesce_primary_tx.is_valid() {
            return true;
        }
        let crate::owner::pending::PendingOpState::Fs {
            fs_instance_id: op_fs,
            kind,
            ..
        } = op.op_state
        else {
            return true;
        };
        if op_fs != fs_instance_id {
            return true;
        }
        let super::op_kind::SaltyfsOpKind::Lookup {
            parent_ino: op_parent,
            name: op_name,
            name_len,
        } = (unsafe { super::op_kind::SaltyfsOpKind::unpack(&kind) })
        else {
            return true;
        };
        if op_parent == parent_ino && &op_name[..name_len as usize] == name {
            found = op.tx_id;
            return false;
        }
        true
    });
    found.is_valid().then_some(found)
}

/// Lookup a single directory component on the remote SaltyFS.
///
/// Returns `Ok(Some(...))` on success, `Ok(None)` when the entry does not
/// exist, and `Err(reply_label)` when the backend reports a real failure.
pub(super) unsafe fn saltyfs_ipc_lookup(
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
) -> Result<Option<(u64, u32, u32, u64, u32, u64, u32, u32, u8, u64)>, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_LOOKUP;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + ((name_len as u64) + 7) / 8;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }

        match reply.label {
            TRONA_OK => Ok(Some((
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
            TRONA_NOT_FOUND => Ok(None),
            other => Err(other),
        }
    }
}

/// Issue an asynchronous `BACKEND_LOOKUP`. Mirror of
/// [`saltyfs_ipc_stat_issue`] — reserves a `PendingOp` slot
/// tagged with `SaltyfsOpKind::Lookup { parent_ino, name, name_len }`,
/// stamps the shared correlation header into MR28..=MR31, and fires `send_ctx` to the
/// saltyfs server so the owner loop can continue while disk I/O
/// is in flight.
///
/// Returns the reserved `PendingOpHandle` on success so the
/// caller (the `saltyfs_lookup` VOP, which bubbles up as
/// `Ok(VopOutcome::Parked(handle))`) can propagate to the fileops
/// stamp site; `None` on arena exhaustion or oversized name. The
/// saltyfs server-side async allowlist must include `BACKEND_LOOKUP`
/// so the completion can be pushed back over VFS's shared backend
/// callback endpoint.
pub(super) unsafe fn saltyfs_ipc_lookup_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    parent_seq: u32,
    name: *const u8,
    name_len: u8,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        if name_len as usize > crate::owner::pending::WALK_NAME_MAX {
            return None;
        }

        let mut name_bytes = [0u8; crate::owner::pending::WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_bytes[i] = *name.add(i);
        }

        let (handle, tx_id) = state.reserve_fs_pending(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Lookup {
                parent_ino,
                name: name_bytes,
                name_len,
            }
            .pack(),
        )?;

        // Concurrent-fetch coalescing: if another walk is already
        // parked on the same (fs_id, parent_ino, name) triple, attach
        // this handle as a waiter and skip the RPC. The primary's
        // completion broadcast (in `apply_lookup_reply`) will drive
        // this handle's resume with the same reply body. Falls back
        // to an independent RPC when no primary exists OR the waiter
        // slot is full.
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
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + ((name_len as u64) + 7) / 8;
        stamp_saltyfs_async_request(md, &mut req, BACKEND_LOOKUP, tx_id, parent_seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

/// Issue an asynchronous `BACKEND_LOOKUP` with `CORRELATION_F_LOOKUP_PARENT`
/// set. The server interprets `regs[0]` as the **child** inode and returns
/// the parent's stat-merged lookup reply. The reply format is identical to
/// a regular lookup, so `apply_lookup_reply` handles it unchanged.
///
/// Used by the `saltyfs_lookup` dotdot path to replace the blocking
/// `saltyfs_ipc_getparent` + `saltyfs_ipc_stat` pair with a single
/// async round-trip.
pub(crate) unsafe fn saltyfs_ipc_lookup_parent_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    child_ino: u64,
    child_seq: u32,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        // Record parent_ino=0 + a synthetic ".." name in the Lookup kind so
        // the pending-op layer can log it coherently. The actual parent
        // resolution happens server-side, driven by the flag bit.
        let mut name_bytes = [0u8; crate::owner::pending::WALK_NAME_MAX];
        name_bytes[0] = b'.';
        name_bytes[1] = b'.';

        let (handle, tx_id) = state.reserve_fs_pending(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Lookup {
                parent_ino: child_ino,
                name: name_bytes,
                name_len: 2,
            }
            .pack(),
        )?;

        // Concurrent-fetch coalescing for dotdot walks. Keys are the
        // same shape as regular lookup coalescing; the
        // `LOOKUP_PARENT` flag semantically inverts `parent_ino` to a
        // child-ino, but from the coalescer's perspective the triple
        // `(fs_id, child_ino, "..")` is unique and stable across
        // concurrent callers. Two dotdot walks against the same child
        // share a single `BACKEND_LOOKUP` RPC with the flag set.
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
        // name_len and name bytes are ignored by the server when the
        // LOOKUP_PARENT flag is set, but populate them for protocol
        // consistency.
        req.regs[1] = 2;
        let dst = &raw mut req.regs[2] as *mut u8;
        *dst = b'.';
        *dst.add(1) = b'.';

        // Stamp the async header with the LOOKUP_PARENT flag.
        let words = CorrelationHeader {
            class: CORRELATION_CLASS_FS,
            backend: CORRELATION_BACKEND_SALTYFS,
            session: (*md).session_id,
            opcode: BACKEND_LOOKUP as u16,
            kind: CORRELATION_KIND_REQUEST,
            flags: CORRELATION_F_LOOKUP_PARENT,
            token: tx_id.raw(),
            request_seq: child_seq,
            request_seq_secondary: 0,
        }
        .encode_words();
        req.regs[CORRELATION_HEADER_REG_START] = words[0];
        req.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
        req.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
        req.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
        req.length = 2 + 1; // regs[0..2] + one word for ".."
        // Manual encode path — `stamp_saltyfs_async_request`'s internal
        // length raise does not run here, so ensure the header survives
        // the kernel's length-bounded register copy explicitly.
        ensure_correlation_wire_length(&mut req.length);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

/// Parse a `BACKEND_LOOKUP` reply payload
/// into the same tuple shape [`saltyfs_ipc_lookup`] returns
/// (`child_ino`, `child_seq`, `mode`, `size`, `nlink`, `mtime`,
/// `uid`, `gid`, `dir_type`, `blocks`). Used by `dispatch_pending_reply` on
/// the resume side to harvest the async result without re-issuing.
///
/// `Ok(Some(tuple))` — success. `Ok(None)` — clean `TRONA_NOT_FOUND`
/// (ENOENT). `Err(VfsError)` — backend error label or malformed
/// reply (unknown label / missing fields).
pub(crate) fn saltyfs_ipc_lookup_parse(
    reply: &TronaMsg,
) -> crate::vfs_core::error::VfsResult<Option<(u64, u32, u32, u64, u32, u64, u32, u32, u8, u64)>> {
    // Sync and async completion paths share the same payload layout.
    // The async path is distinguished by the correlation header on the
    // backend callback endpoint, not by a special outer label. Clean
    // ENOENT arrives as `TRONA_NOT_FOUND`. Any other label is a real
    // backend error and is translated through
    // `crate::trona_to_vfs_error`.
    match reply.label {
        TRONA_OK => Ok(Some((
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
        TRONA_NOT_FOUND => Ok(None),
        other => Err(super::vops::trona_to_vfs_error(other)),
    }
}

// =========================================================================
// BACKEND_STAT
// =========================================================================

/// Synchronous stat of a remote inode. Used by compound VOPs inside
/// saltyfs_client (lookup/create/mkdir/symlink post-creation stat,
/// vget population) where the caller cannot propagate a `Pending`
/// continuation up through the VOP boundary.
///
/// Returns `Some((size, mode, nlink, mtime, blocks, uid, gid, seq))` on
/// success, `None` on failure. Blocks the owner loop for the duration
/// of the RPC — acceptable at these call sites because they run
/// inside already-issued VOPs whose fileops callers have no state
/// machine shape to park against. A future iteration may revisit whether
/// these compound paths can be restructured to park further up the
/// call chain.
pub(super) unsafe fn saltyfs_ipc_stat_sync(
    md: *mut SaltyfsMountData,
    ino: u64,
) -> Option<(u64, u32, u32, u64, u64, u32, u32, u32)> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_STAT;
        req.regs[0] = ino;
        req.length = 1;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        Some((
            reply.regs[1],        // size
            reply.regs[2] as u32, // mode
            reply.regs[3] as u32, // nlink
            reply.regs[4],        // mtime
            reply.regs[5],        // blocks
            reply.regs[6] as u32, // uid
            reply.regs[7] as u32, // gid
            reply.regs[8] as u32, // seq
        ))
    }
}

/// Synchronous alias preserved for callers that have not yet been
/// migrated to the issue/parse split. Delegates to
/// [`saltyfs_ipc_stat_sync`]; deprecated in favour of the explicit
/// `_sync` / issue-parse naming and kept only to minimise blast
/// radius during the async migration.
#[inline]
pub(super) unsafe fn saltyfs_ipc_stat(
    md: *mut SaltyfsMountData,
    ino: u64,
) -> Option<(u64, u32, u32, u64, u64, u32, u32, u32)> {
    unsafe { saltyfs_ipc_stat_sync(md, ino) }
}

/// Issue an asynchronous `BACKEND_STAT`. Reserves a `PendingOp` slot,
/// stamps the shared correlation header into MR28..=MR31, and fires `send_ctx` to the
/// saltyfs server so the owner loop can return to `recv_any` without
/// waiting on disk I/O. Returns the reserved handle so the fileops
/// layer can overwrite the `Placeholder` `Resume` with its own
/// continuation before returning control.
///
/// `fs_instance_id` is snapshotted into the `PendingOp` so the
/// dispatcher can detect mount teardown while the RPC is in flight.
pub(super) unsafe fn saltyfs_ipc_stat_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        let (handle, tx_id) = state.reserve_fs_pending(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Stat { ino }.pack(),
        )?;

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_STAT;
        req.regs[0] = ino;
        req.length = 1;
        stamp_saltyfs_async_request(md, &mut req, BACKEND_STAT, tx_id, seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a `BACKEND_STAT` reply payload into the
/// same tuple shape `saltyfs_ipc_stat_sync` returns. Used by
/// `dispatch_pending_reply` on the resume side to harvest the
/// async result without re-issuing the RPC.
pub(crate) fn saltyfs_ipc_stat_parse(
    reply: &TronaMsg,
) -> Option<(u64, u32, u32, u64, u64, u32, u32, u32)> {
    // The sync reply layout reserves `regs[0]` for the inode id echo
    // (unused by the client) and packs fields into `regs[1..=8]`.
    // Async completions reuse the same reply layout; the distinction
    // lives in the correlation header, not the label.
    if reply.label != TRONA_OK {
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

/// Read a symlink target into `buf`. Returns the number of bytes read (0 on failure).
pub(super) unsafe fn saltyfs_ipc_readlink_sync(
    md: *mut SaltyfsMountData,
    ino: u64,
    buf: *mut u8,
    buf_cap: usize,
) -> usize {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_READLINK;
        req.regs[0] = ino;
        req.length = 1;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let target_len = reply.regs[0] as usize;
        if target_len == 0 || target_len > buf_cap {
            return 0;
        }
        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..target_len {
            *buf.add(i) = *src.add(i);
        }
        target_len
    }
}

/// Delegating alias. Preserved for callers that have not yet been migrated
/// to the `_sync` / `_issue` / `_parse` split.
#[inline]
pub(super) unsafe fn saltyfs_ipc_readlink(
    md: *mut SaltyfsMountData,
    ino: u64,
    buf: *mut u8,
    buf_cap: usize,
) -> usize {
    unsafe { saltyfs_ipc_readlink_sync(md, ino, buf, buf_cap) }
}

/// Issue an asynchronous [`BACKEND_READ`]. Reserves one inflight credit
/// against the owning session, reserves a `PendingOp` slot tagged with
/// [`SaltyfsOpKind::Read`], stamps the correlation header, and fires
/// `send_ctx` so the owner loop can return to `recv_any_ctx` without
/// blocking on backend disk I/O.
///
/// `transfer` selects the wire transport. Callers pick
/// [`TRANSFER_KIND_INLINE`] for payloads ≤ [`INLINE_TRANSFER_THRESHOLD`]
/// (reply rides in the response registers) and [`TRANSFER_KIND_SHM`]
/// otherwise (reply's payload lands in VFS↔saltyfs SHM at
/// `transfer.offset`). The resume handler inspects the parked
/// descriptor to choose the matching delivery path.
///
/// Returns `None` when credit is exhausted or the pending arena is
/// full; the caller surfaces a synchronous `Busy` error so the client
/// sees `TRONA_BUSY` instead of hanging.
pub(crate) unsafe fn saltyfs_ipc_read_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    file_offset: u64,
    transfer: TransferDescriptor,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Read {
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
        let desc = transfer.encode_regs();
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG] = desc[0];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 1] = desc[1];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 2] = desc[2];
        req.length = (BACKEND_RW_REQ_DESCRIPTOR_REG + TransferDescriptor::REG_COUNT) as u64;
        stamp_saltyfs_async_request(md, &mut req, BACKEND_READ, tx_id, seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a [`BACKEND_READ`] completion into the delivered byte count.
/// Returns `None` when the backend reported a failure label or the
/// reply is malformed; returns `Some(bytes_read)` otherwise.
///
/// The caller is responsible for delivering the payload to the final
/// sink: for [`TRANSFER_KIND_INLINE`] the bytes live in the reply
/// registers starting at [`BACKEND_READ_INLINE_PAYLOAD_REG`]; for
/// [`TRANSFER_KIND_SHM`] the bytes already reside in VFS↔saltyfs SHM
/// at the parked descriptor's `offset`. The wire layout matches the
/// sync read path this replaces.
pub(crate) fn saltyfs_ipc_read_parse(reply: &TronaMsg) -> Option<u64> {
    if reply.label != TRONA_OK {
        return None;
    }
    Some(reply.regs[0])
}

/// Issue an asynchronous [`BACKEND_READDIR`]. Reserves one inflight
/// credit against the owning session, reserves a `PendingOp` slot
/// tagged with [`SaltyfsOpKind::Readdir`], stamps the correlation
/// header, and fires `send_ctx` so the owner loop can service other
/// clients while the backend iterates the directory B-tree and
/// writes fixed 96-byte records into VFS↔saltyfs SHM at
/// `shm_offset`.
///
/// `buf_bytes` bounds the maximum number of bytes the backend may
/// write into SHM (the caller's policy). On reply, the completion
/// header carries `next_cursor`, `entries_written`, and
/// `bytes_written`; the resume handler pops entries from SHM into
/// the client's readdir reply path.
///
/// Returns `None` on credit exhaustion or pending-arena overflow.
pub(crate) unsafe fn saltyfs_ipc_readdir_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    dir_ino: u64,
    dir_seq: u32,
    cookie: u64,
    shm_offset: u64,
    buf_bytes: u64,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
    open_handle: crate::server::open_object::OpenObjectHandle,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        // Serialise against the per-mount VFS↔saltyfs SHM region.
        // `super::deferred::acquire_readdir_shm` returns `true` when
        // the SHM is idle or the prior owner has been reclaimed (in
        // which case we take over cleanly); returns `false` when a
        // live owner is mid-drain and caller must park instead of
        // stomping the other reader's cached records.
        if !super::deferred::acquire_readdir_shm(state, md, open_handle) {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            // Nothing irrecoverable happens if we don't release the
            // SHM ownership here — the flag points at us, and the
            // VOP's next call (which sees our own open_h) will pass
            // the acquire check or reclaim on stale handle.
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Readdir {
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
        stamp_saltyfs_async_request(md, &mut req, BACKEND_READDIR, tx_id, dir_seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a [`BACKEND_READDIR`] completion.
///
/// Returns `(next_cursor, entries_written, bytes_written)` on success,
/// `None` on backend failure. `next_cursor == 0` signals EOF.
pub(crate) fn saltyfs_ipc_readdir_parse(reply: &TronaMsg) -> Option<(u64, u64, u64)> {
    if reply.label != TRONA_OK {
        return None;
    }
    Some((reply.regs[0], reply.regs[1], reply.regs[2]))
}

/// Issue an asynchronous `BACKEND_READLINK`. Reserves a `PendingOp` slot
/// tagged with `SaltyfsOpKind::Readlink { ino }`, stamps the shared
/// correlation header into MR28..=MR31, and fires `send_ctx` so the owner loop can continue while
/// the backend services the request. The reply carries the symlink target
/// bytes in the same inline layout as the sync path (`regs[0]` = byte
/// count, `regs[1..]` = target bytes).
pub(crate) unsafe fn saltyfs_ipc_readlink_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        let (handle, tx_id) = state.reserve_fs_pending(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Readlink { ino }.pack(),
        )?;

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_READLINK;
        req.regs[0] = ino;
        req.length = 1;
        stamp_saltyfs_async_request(md, &mut req, BACKEND_READLINK, tx_id, seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a `BACKEND_READLINK` reply. Returns the
/// symlink target as an inline byte array and its length on success.
/// `None` on malformed or error reply.
pub(crate) fn saltyfs_ipc_readlink_parse(
    reply: &TronaMsg,
) -> Option<([u8; crate::owner::pending::WALK_SYMLINK_TARGET_MAX], usize)> {
    if reply.label != TRONA_OK {
        return None;
    }
    let target_len = reply.regs[0] as usize;
    if target_len == 0 || target_len > crate::owner::pending::WALK_SYMLINK_TARGET_MAX {
        return None;
    }
    let mut buf = [0u8; crate::owner::pending::WALK_SYMLINK_TARGET_MAX];
    let src = &reply.regs[1] as *const u64 as *const u8;
    for i in 0..target_len {
        buf[i] = unsafe { *src.add(i) };
    }
    Some((buf, target_len))
}

// =========================================================================
// BACKEND_GETINFO — filesystem statistics
// =========================================================================

/// Synchronous filesystem-level info query. Used at bootstrap /
/// mount-validation sites where the owner loop has not started yet,
/// so the async issue/parse pair cannot run. See
/// `saltyfs_ipc_getinfo_issue` for the park-capable variant.
pub(super) unsafe fn saltyfs_ipc_getinfo_sync(
    md: *mut SaltyfsMountData,
) -> Option<(u64, u64, u64)> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_GETINFO;
        req.length = 0;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        Some((
            reply.regs[0], // total_blocks
            reply.regs[1], // used_blocks
            reply.regs[2], // block_size
        ))
    }
}

/// Delegating alias. Preserved so call sites that predate the
/// `_sync` / `_issue` / `_parse` split continue to compile without
/// per-caller refactoring — see the matching `saltyfs_ipc_stat`
/// alias for the equivalent pattern on BACKEND_STAT.
#[inline]
pub(super) unsafe fn saltyfs_ipc_getinfo(md: *mut SaltyfsMountData) -> Option<(u64, u64, u64)> {
    unsafe { saltyfs_ipc_getinfo_sync(md) }
}

/// Issue an asynchronous `BACKEND_GETINFO`. Reserves a `PendingOp`
/// slot with `SaltyfsOpKind::GetInfo`, stamps the shared correlation
/// header into MR28..=MR31, and fires `send_ctx`. Caller must overwrite the
/// placeholder `Resume` with its own continuation before
/// returning control to the owner loop.
#[allow(dead_code)]
pub(crate) unsafe fn saltyfs_ipc_getinfo_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        let (handle, tx_id) = state.reserve_fs_pending(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::GetInfo.pack(),
        )?;

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_GETINFO;
        req.length = 0;
        stamp_saltyfs_async_request(md, &mut req, BACKEND_GETINFO, tx_id, 0, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a `BACKEND_GETINFO` reply into
/// `(total_blocks, used_blocks, block_size)`.
pub(crate) fn saltyfs_ipc_getinfo_parse(reply: &TronaMsg) -> Option<(u64, u64, u64)> {
    if reply.label != TRONA_OK {
        return None;
    }
    Some((reply.regs[0], reply.regs[1], reply.regs[2]))
}
