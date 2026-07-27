// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS xattr IPC helpers — getxattr, setxattr, removexattr, listxattr.
//!
//! GETXATTR, SETXATTR, and LISTXATTR require SHM transport (name and/or value
//! are exchanged via the VFS-SaltyFS shared memory region). REMOVEXATTR uses
//! inline IPC registers for the name (up to 144 bytes).

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use super::rpc::ipc_ctx;
use super::types::SaltyfsMountData;

// =========================================================================
// BACKEND_GETXATTR (23) — requires SHM
// =========================================================================

/// Get an extended attribute value (synchronous).
///
/// The caller places the attribute name at `shm_vaddr + shm_offset` before
/// calling. On success, the value is written at the same SHM offset.
///
/// Returns `Ok(value_len)` on success, `Err(label)` on failure.
/// When `buf_bytes == 0`, this is a size-query: returns the value length
/// without writing any data.
pub(super) unsafe fn saltyfs_ipc_getxattr_sync(
    md: *mut SaltyfsMountData,
    ino: u64,
    shm_offset: u64,
    buf_bytes: u64,
    name_len: usize,
) -> Result<usize, u64> {
    unsafe {
        if !(*md).shm_active {
            return Err(TRONA_INVALID_OPERATION);
        }
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_GETXATTR;
        req.regs[0] = ino;
        req.regs[1] = shm_offset;
        req.regs[2] = buf_bytes;
        req.regs[3] = name_len as u64;
        req.length = 4;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }

        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0] as usize)
    }
}

/// Outcome of a claim-gated async xattr issue. `Issued` means the
/// backend request went out on the wire and the caller can park on
/// the returned `PendingOpHandle`. `ShmBusy` means the VFS↔saltyfs
/// SHM region is currently held by another live xattr / readdir op —
/// caller should surface `VfsError::WouldBlock` so the dispatch layer
/// parks via the session's deferred-issue ring. `Failed` covers
/// credit exhaustion and arena overflow; the dispatch layer surfaces
/// `TRONA_BUSY` (matching the existing behaviour of the other issue
/// helpers).
pub(crate) enum XattrIssueOutcome {
    Issued(crate::owner::pending::PendingOpHandle),
    ShmBusy,
    Failed,
}

/// Issue an asynchronous `BACKEND_GETXATTR`. Reserves a `PendingOp`,
/// tries to claim the per-mount VFS↔saltyfs SHM region via
/// [`super::deferred::acquire_xattr_shm`], writes the attribute name
/// to SHM at offset 0, stamps the correlation header into MR28..=MR31,
/// and fires `send_ctx`. On reply, the value bytes land in SHM and
/// `regs[0]` carries `value_len`.
///
/// The caller passes the name bytes directly — this function is
/// responsible for copying them into SHM only after the claim
/// succeeds. That ordering matters: the claim gate stamps ownership
/// with the fresh `TxId`, and a prior xattr op's replay (via the
/// drain path) must not race the memcpy into SHM while the other op
/// still has its data staged.
///
/// Returns [`XattrIssueOutcome::ShmBusy`] when the SHM claim fails;
/// the VOP surfaces `VfsError::WouldBlock` in that case and the
/// dispatch layer parks the op via
/// [`crate::owner::DeferArgs::XattrGet`].
pub(crate) unsafe fn saltyfs_ipc_getxattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    name: *const u8,
    name_len: u8,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> XattrIssueOutcome {
    unsafe {
        if !(*md).shm_active {
            return XattrIssueOutcome::Failed;
        }
        if (name_len as usize) > crate::owner::pending::WALK_NAME_MAX {
            return XattrIssueOutcome::Failed;
        }
        let mut name_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return XattrIssueOutcome::Failed;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::XattrGet {
                ino,
                name: name_buf,
                name_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return XattrIssueOutcome::Failed;
        };
        if !super::deferred::acquire_xattr_shm(state, md, tx_id) {
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release(fs_instance_id);
            return XattrIssueOutcome::ShmBusy;
        }

        // Claim held — safe to stage name bytes into SHM.
        let shm_base = (*md).shm_vaddr as *mut u8;
        for i in 0..name_len as usize {
            *shm_base.add(i) = name_buf[i];
        }

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_GETXATTR;
        req.regs[0] = ino;
        req.regs[1] = 0; // shm_offset
        req.regs[2] = 31 * 8; // buf_bytes = inline reply capacity
        req.regs[3] = name_len as u64;
        req.length = 4;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_GETXATTR, tx_id, seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        XattrIssueOutcome::Issued(handle)
    }
}

/// Parse a `BACKEND_GETXATTR` reply. Returns
/// `Some(value_len)` on success; the value bytes themselves are in the
/// VFS-saltyfs SHM buffer and are accessed by the resume helper via
/// the mount's `shm_vaddr`. Returns `None` on error labels.
pub(crate) fn saltyfs_ipc_xattr_get_parse(reply: &TronaMsg) -> Option<usize> {
    match reply.label {
        TRONA_OK => Some(reply.regs[0] as usize),
        _ => None,
    }
}

// =========================================================================
// BACKEND_SETXATTR (24) — requires SHM
// =========================================================================

/// Set an extended attribute.
///
/// The caller places `name || value` at `shm_vaddr + shm_offset` before calling.
///
/// `flags`: 0 = create or replace, XATTR_CREATE = fail if exists,
///          XATTR_REPLACE = fail if not exists.
pub(super) unsafe fn saltyfs_ipc_setxattr(
    md: *mut SaltyfsMountData,
    ino: u64,
    shm_offset: u64,
    value_len: u64,
    name_len: usize,
    flags: u32,
) -> u64 {
    unsafe {
        if !(*md).shm_active {
            return TRONA_INVALID_OPERATION;
        }
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_SETXATTR;
        req.regs[0] = ino;
        req.regs[1] = flags as u64;
        req.regs[2] = shm_offset;
        req.regs[3] = value_len;
        req.regs[4] = name_len as u64;
        req.length = 5;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

/// Issue an asynchronous `BACKEND_SETXATTR`. Reserves a `PendingOp`,
/// claims the VFS↔saltyfs SHM region, writes `name || value` to SHM at
/// offset 0, stamps the correlation header, and fires `send_ctx`. The
/// completion is a plain ack (no attribute snapshot) parsed via
/// [`saltyfs_ipc_setxattr_parse`].
///
/// Both `name` and `value` bytes are cached inline on the parked op-
/// kind so the deferred-issue drain can replay the memcpy into SHM
/// when the claim frees. See [`XattrIssueOutcome`].
pub(crate) unsafe fn saltyfs_ipc_setxattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    name: *const u8,
    name_len: u8,
    value: *const u8,
    value_len: u16,
    flags: u32,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> XattrIssueOutcome {
    unsafe {
        if !(*md).shm_active {
            return XattrIssueOutcome::Failed;
        }
        if (name_len as usize) > crate::owner::pending::WALK_NAME_MAX
            || (value_len as usize) > crate::owner::pending::WALK_NAME_MAX
        {
            return XattrIssueOutcome::Failed;
        }
        let mut name_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        let mut value_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        for i in 0..value_len as usize {
            value_buf[i] = *value.add(i);
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return XattrIssueOutcome::Failed;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::SetXattr {
                ino,
                name: name_buf,
                value: value_buf,
                name_len,
                value_len,
                flags,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return XattrIssueOutcome::Failed;
        };
        if !super::deferred::acquire_xattr_shm(state, md, tx_id) {
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release(fs_instance_id);
            return XattrIssueOutcome::ShmBusy;
        }

        let shm_base = (*md).shm_vaddr as *mut u8;
        for i in 0..name_len as usize {
            *shm_base.add(i) = name_buf[i];
        }
        for i in 0..value_len as usize {
            *shm_base.add(name_len as usize + i) = value_buf[i];
        }

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_SETXATTR;
        req.regs[0] = ino;
        req.regs[1] = flags as u64;
        req.regs[2] = 0; // shm_offset
        req.regs[3] = value_len as u64;
        req.regs[4] = name_len as u64;
        req.length = 5;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_SETXATTR, tx_id, seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        XattrIssueOutcome::Issued(handle)
    }
}

/// Parse a `BACKEND_SETXATTR` completion. Returns `Ok(())` on
/// success and the raw `TRONA_*` label on failure so the caller can
/// map it to the appropriate `VfsError`.
pub(crate) fn saltyfs_ipc_setxattr_parse(reply: &TronaMsg) -> Result<(), u64> {
    if reply.label == TRONA_OK {
        Ok(())
    } else {
        Err(reply.label)
    }
}

// =========================================================================
// BACKEND_REMOVEXATTR (25) — inline name
// =========================================================================

/// Issue an asynchronous `BACKEND_REMOVEXATTR`. The name is copied
/// inline into the parked `SaltyfsOpKind::RemoveXattr` payload so
/// the deferred-issue drain can replay the request without
/// reconstructing the buffer from SHM. The completion is a plain
/// ack parsed via [`saltyfs_ipc_removexattr_parse`].
pub(crate) unsafe fn saltyfs_ipc_removexattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
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
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::RemoveXattr {
                ino,
                name: name_bytes,
                name_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_REMOVEXATTR;
        req.regs[0] = ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + ((name_len as u64) + 7) / 8;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_REMOVEXATTR, tx_id, seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a `BACKEND_REMOVEXATTR` completion.
pub(crate) fn saltyfs_ipc_removexattr_parse(reply: &TronaMsg) -> Result<(), u64> {
    if reply.label == TRONA_OK {
        Ok(())
    } else {
        Err(reply.label)
    }
}

/// Remove an extended attribute. Name is sent inline via IPC registers (up to 144 bytes).
pub(super) unsafe fn saltyfs_ipc_removexattr(
    md: *mut SaltyfsMountData,
    ino: u64,
    name: *const u8,
    name_len: u8,
) -> u64 {
    unsafe {
        if name_len as usize > 144 {
            return TRONA_INVALID_ARGUMENT;
        }
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_REMOVEXATTR;
        req.regs[0] = ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + ((name_len as u64) + 7) / 8;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

// =========================================================================
// BACKEND_LISTXATTR (26) — requires SHM
// =========================================================================

/// Issue an asynchronous `BACKEND_LISTXATTR`. Reserves a `PendingOp`,
/// claims the VFS↔saltyfs SHM region, stamps the shared correlation
/// header into MR28..=MR31, and fires `send_ctx`. On reply the NUL-
/// separated name list lands in SHM; `regs[0]` carries `bytes_needed`
/// and `regs[1]` carries `bytes_written`.
pub(crate) unsafe fn saltyfs_ipc_listxattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    buf_bytes: u64,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> XattrIssueOutcome {
    unsafe {
        if !(*md).shm_active {
            return XattrIssueOutcome::Failed;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return XattrIssueOutcome::Failed;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::ListXattr { ino }.pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return XattrIssueOutcome::Failed;
        };
        if !super::deferred::acquire_xattr_shm(state, md, tx_id) {
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release(fs_instance_id);
            return XattrIssueOutcome::ShmBusy;
        }

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_LISTXATTR;
        req.regs[0] = ino;
        req.regs[1] = 0; // shm_offset
        req.regs[2] = buf_bytes;
        req.length = 3;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_LISTXATTR, tx_id, seq, 0);

        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        XattrIssueOutcome::Issued(handle)
    }
}

/// Parse a `BACKEND_LISTXATTR` reply. Returns `Some((bytes_needed,
/// bytes_written))` on success; the name data itself is in the
/// VFS-saltyfs SHM buffer. Returns `None` on error labels.
pub(crate) fn saltyfs_ipc_listxattr_parse(reply: &TronaMsg) -> Option<(usize, usize)> {
    match reply.label {
        TRONA_OK | TRONA_OUT_OF_RANGE => Some((reply.regs[0] as usize, reply.regs[1] as usize)),
        _ => None,
    }
}

/// List extended attribute names.
///
/// On success, NUL-separated names are written to `shm_vaddr + shm_offset`.
///
/// Returns `Ok((bytes_needed, bytes_written))` on success.
/// When `buf_bytes == 0`, only `bytes_needed` is meaningful (size query).
pub(super) unsafe fn saltyfs_ipc_listxattr(
    md: *mut SaltyfsMountData,
    ino: u64,
    shm_offset: u64,
    buf_bytes: u64,
) -> Result<(usize, usize), u64> {
    unsafe {
        if !(*md).shm_active {
            return Err(TRONA_INVALID_OPERATION);
        }
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_LISTXATTR;
        req.regs[0] = ino;
        req.regs[1] = shm_offset;
        req.regs[2] = buf_bytes;
        req.length = 3;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }

        if reply.label != TRONA_OK && reply.label != TRONA_OUT_OF_RANGE {
            return Err(reply.label);
        }
        Ok((reply.regs[0] as usize, reply.regs[1] as usize))
    }
}
