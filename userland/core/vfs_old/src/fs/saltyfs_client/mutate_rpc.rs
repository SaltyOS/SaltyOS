// SPDX-License-Identifier: GPL-2.0-only
//! Mutating SaltyFS IPC helpers — create, mkdir, symlink, unlink, rmdir, rename,
//! link, truncate, write, chmod, chown.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use super::rpc::ipc_ctx;
use super::types::SaltyfsMountData;

/// V2 protocol sentinel — bit 63 on parent_ino signals uid/gid fields present.
const SALTYFS_PROTO_V2: u64 = 1u64 << 63;

// =========================================================================
// BACKEND_CREATE (V1 + V2)
// =========================================================================

/// Create a regular file on the remote SaltyFS.
///
/// Uses V2 protocol when `uid`/`gid` are provided (non-zero or mount supports V2).
/// Returns the new inode number, or 0 on failure.
pub(super) unsafe fn saltyfs_ipc_create(
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    use_v2: bool,
) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_CREATE;

        if use_v2 {
            if name_len as usize > 120 {
                return 0;
            }
            req.regs[0] = parent_ino | SALTYFS_PROTO_V2;
            req.regs[1] = mode as u64;
            req.regs[2] = uid as u64;
            req.regs[3] = gid as u64;
            req.regs[4] = name_len as u64;
            let dst = &raw mut req.regs[5] as *mut u8;
            for i in 0..name_len as usize {
                *dst.add(i) = *name.add(i);
            }
            req.length = 5 + ((name_len as u64) + 7) / 8;
        } else {
            if name_len as usize > 136 {
                return 0;
            }
            req.regs[0] = parent_ino;
            req.regs[1] = mode as u64;
            req.regs[2] = name_len as u64;
            let dst = &raw mut req.regs[3] as *mut u8;
            for i in 0..name_len as usize {
                *dst.add(i) = *name.add(i);
            }
            req.length = 3 + ((name_len as u64) + 7) / 8;
        }

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        reply.regs[0]
    }
}

// =========================================================================
// BACKEND_MKDIR (V1 + V2)
// =========================================================================

/// Create a directory on the remote SaltyFS.
/// Returns `(reply_label, new_ino)` where `new_ino` is valid on success.
pub(super) unsafe fn saltyfs_ipc_mkdir(
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    use_v2: bool,
) -> (u64, u64) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_MKDIR;

        if use_v2 {
            if name_len as usize > 120 {
                return (TRONA_INVALID_ARGUMENT, 0);
            }
            req.regs[0] = parent_ino | SALTYFS_PROTO_V2;
            req.regs[1] = mode as u64;
            req.regs[2] = uid as u64;
            req.regs[3] = gid as u64;
            req.regs[4] = name_len as u64;
            let dst = &raw mut req.regs[5] as *mut u8;
            for i in 0..name_len as usize {
                *dst.add(i) = *name.add(i);
            }
            req.length = 5 + ((name_len as u64) + 7) / 8;
        } else {
            if name_len as usize > 136 {
                return (TRONA_INVALID_ARGUMENT, 0);
            }
            req.regs[0] = parent_ino;
            req.regs[1] = mode as u64;
            req.regs[2] = name_len as u64;
            let dst = &raw mut req.regs[3] as *mut u8;
            for i in 0..name_len as usize {
                *dst.add(i) = *name.add(i);
            }
            req.length = 3 + ((name_len as u64) + 7) / 8;
        }

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return (TRONA_IO_ERROR, 0);
        }
        (reply.label, reply.regs[0])
    }
}

// =========================================================================
// BACKEND_SYMLINK (V1 + V2)
// =========================================================================

/// Create a symlink on the remote SaltyFS.
/// Returns the new inode number, or 0 on failure. `result_label` is set to the reply label.
pub(super) unsafe fn saltyfs_ipc_symlink(
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
    target: *const u8,
    target_len: u8,
    uid: u32,
    gid: u32,
    use_v2: bool,
) -> (u64, u64) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_SYMLINK;

        if use_v2 {
            if name_len as usize > 56 || target_len as usize > 64 {
                return (TRONA_INVALID_ARGUMENT, 0);
            }
            req.regs[0] = parent_ino | SALTYFS_PROTO_V2;
            req.regs[1] = uid as u64;
            req.regs[2] = gid as u64;
            req.regs[3] = name_len as u64;
            req.regs[4] = target_len as u64;
            let dst_name = &raw mut req.regs[5] as *mut u8;
            for i in 0..name_len as usize {
                *dst_name.add(i) = *name.add(i);
            }
            let dst_target = &raw mut req.regs[12] as *mut u8;
            for i in 0..target_len as usize {
                *dst_target.add(i) = *target.add(i);
            }
            req.length = 20;
        } else {
            if name_len as usize > 72 || target_len as usize > 64 {
                return (TRONA_INVALID_ARGUMENT, 0);
            }
            req.regs[0] = parent_ino;
            req.regs[1] = name_len as u64;
            req.regs[2] = target_len as u64;
            let dst_name = &raw mut req.regs[3] as *mut u8;
            for i in 0..name_len as usize {
                *dst_name.add(i) = *name.add(i);
            }
            let dst_target = &raw mut req.regs[12] as *mut u8;
            for i in 0..target_len as usize {
                *dst_target.add(i) = *target.add(i);
            }
            req.length = 20;
        }

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 {
            return (TRONA_IO_ERROR, 0);
        }

        let new_ino = if reply.label == TRONA_OK {
            reply.regs[0]
        } else {
            0
        };
        (reply.label, new_ino)
    }
}

// =========================================================================
// BACKEND_UNLINK
// =========================================================================

/// Unlink a name from a directory. Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_unlink(
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_UNLINK;
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
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

// =========================================================================
// BACKEND_RMDIR
// =========================================================================

/// Remove a directory. Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_rmdir(
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_RMDIR;
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
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

// =========================================================================
// BACKEND_RENAME
// =========================================================================

/// Rename a directory entry. Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_rename(
    md: *mut SaltyfsMountData,
    old_parent_ino: u64,
    old_name: *const u8,
    old_name_len: u8,
    new_parent_ino: u64,
    new_name: *const u8,
    new_name_len: u8,
) -> u64 {
    unsafe {
        if old_name_len as usize > 64 || new_name_len as usize > 64 {
            return TRONA_INVALID_ARGUMENT;
        }
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_RENAME;
        req.regs[0] = old_parent_ino;
        req.regs[1] = old_name_len as u64;
        req.regs[2] = new_parent_ino;
        req.regs[3] = new_name_len as u64;
        let dst = &raw mut req.regs[4] as *mut u8;
        for i in 0..old_name_len as usize {
            *dst.add(i) = *old_name.add(i);
        }
        let dst2 = &raw mut req.regs[12] as *mut u8;
        for i in 0..new_name_len as usize {
            *dst2.add(i) = *new_name.add(i);
        }
        req.length = 20;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

// =========================================================================
// BACKEND_LINK
// =========================================================================

/// Create a hard link. Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_link(
    md: *mut SaltyfsMountData,
    existing_ino: u64,
    new_parent_ino: u64,
    name: *const u8,
    name_len: u8,
) -> u64 {
    unsafe {
        if name_len as usize > 136 {
            return TRONA_INVALID_ARGUMENT;
        }
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_LINK;
        req.regs[0] = existing_ino;
        req.regs[1] = new_parent_ino;
        req.regs[2] = name_len as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 3 + ((name_len as u64) + 7) / 8;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

// =========================================================================
// BACKEND_TRUNCATE
// =========================================================================

/// Truncate a file. Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_truncate(
    md: *mut SaltyfsMountData,
    ino: u64,
    new_size: u64,
) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_TRUNCATE;
        req.regs[0] = ino;
        req.regs[1] = new_size;
        req.length = 2;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

// =========================================================================
// BACKEND_WRITE — synchronous write via inline payload or SHM.
// =========================================================================

/// Issue a synchronous [`BACKEND_WRITE`] carrying a [`TransferDescriptor`]
/// selecting inline vs SHM transport.
///
/// For [`TRANSFER_KIND_INLINE`]: `inline_payload` must point at `descriptor.length`
/// readable bytes; they are copied into the request registers. Length must be
/// ≤ [`INLINE_TRANSFER_WIRE_MAX`].
///
/// For [`TRANSFER_KIND_SHM`]: `inline_payload` is ignored; caller must have
/// already populated the SHM region at `descriptor.offset`.
///
/// Returns `(label, bytes_written)`.
pub(super) unsafe fn saltyfs_ipc_write(
    md: *mut SaltyfsMountData,
    ino: u64,
    file_offset: u64,
    descriptor: TransferDescriptor,
    inline_payload: *const u8,
) -> (u64, u64) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_WRITE;
        req.regs[0] = ino;
        req.regs[1] = file_offset;
        let desc = descriptor.encode_regs();
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG] = desc[0];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 1] = desc[1];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 2] = desc[2];

        let length = descriptor.length;
        req.length = if descriptor.is_inline() {
            if length > INLINE_TRANSFER_WIRE_MAX {
                return (TRONA_INVALID_ARGUMENT, 0);
            }
            let dst = &raw mut req.regs[BACKEND_WRITE_INLINE_PAYLOAD_REG] as *mut u8;
            for i in 0..length as usize {
                *dst.add(i) = *inline_payload.add(i);
            }
            (BACKEND_WRITE_INLINE_PAYLOAD_REG as u64) + (length + 7) / 8
        } else {
            (BACKEND_RW_REQ_DESCRIPTOR_REG as u64) + TransferDescriptor::REG_COUNT as u64
        };

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 {
            return (TRONA_IO_ERROR, 0);
        }
        if reply.label != TRONA_OK {
            return (reply.label, 0);
        }
        (TRONA_OK, reply.regs[0])
    }
}

// =========================================================================
// BACKEND_CHMOD
// =========================================================================

/// Change permission bits. Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_chmod(md: *mut SaltyfsMountData, ino: u64, new_perm: u32) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_CHMOD;
        req.regs[0] = ino;
        req.regs[1] = new_perm as u64;
        req.length = 2;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

// =========================================================================
// BACKEND_CHOWN
// =========================================================================

/// Change owner/group. `u32::MAX` means "no change". Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_chown(
    md: *mut SaltyfsMountData,
    ino: u64,
    new_uid: u32,
    new_gid: u32,
) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_CHOWN;
        req.regs[0] = ino;
        req.regs[1] = new_uid as u64;
        req.regs[2] = new_gid as u64;
        req.length = 3;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return TRONA_IO_ERROR;
        }
        reply.label
    }
}

// =========================================================================
// BACKEND_SETATTR (bundled)
// =========================================================================

/// Issue an asynchronous bundled [`BACKEND_SETATTR`]. Reserves a
/// `PendingOp` slot tagged with [`SaltyfsOpKind::SetAttr`], stamps the
/// shared correlation header into MR28..=MR31, and fires `send_ctx`.
///
/// The server applies every field selected by `mask` atomically and
/// replies with a post-commit attribute snapshot — the completion
/// router (`saltyfs_completion`) parses it back via
/// [`saltyfs_ipc_setattr_parse`] and hands the refreshed [`VAttr`] to
/// `fileops::mutate::resume_fill_ack_mutation_reply` so VFS can
/// update its cached attrs without a follow-up `BACKEND_STAT`.
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
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::SetAttr {
                ino,
                mask,
                mode,
                uid,
                gid,
                atime,
                mtime,
                size,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_SETATTR;
        req.regs[0] = ino;
        req.regs[1] = mask as u64;
        req.regs[2] = mode as u64;
        req.regs[3] = (uid as u64) | ((gid as u64) << 32);
        req.regs[4] = atime;
        req.regs[5] = mtime;
        req.regs[6] = size;
        req.length = BACKEND_SETATTR_REG_COUNT as u64;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_SETATTR, tx_id, seq, 0);

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a [`BACKEND_SETATTR`] reply into a refreshed [`VAttr`]
/// snapshot. Returns `None` on a non-`TRONA_OK` label so the caller
/// can surface the backend's error verbatim.
pub(crate) fn saltyfs_ipc_setattr_parse(reply: &TronaMsg) -> Option<crate::vfs_core::file::VAttr> {
    if reply.label != TRONA_OK {
        return None;
    }
    let mut attr = crate::vfs_core::file::VAttr::zeroed();
    attr.mode = reply.regs[0] as u32;
    attr.uid = reply.regs[1] as u32;
    attr.gid = reply.regs[2] as u32;
    attr.size = reply.regs[3];
    attr.nlink = reply.regs[4] as u32;
    attr.atime = reply.regs[5];
    attr.mtime = reply.regs[6];
    Some(attr)
}

// =========================================================================
// BACKEND_TRUNCATE (async)
// =========================================================================

/// Issue an asynchronous [`BACKEND_TRUNCATE`]. Reserves a
/// `PendingOp` slot tagged with [`SaltyfsOpKind::Truncate`], stamps
/// the correlation header, and fires `send_ctx`. Completion is a
/// plain ack parsed via [`saltyfs_ipc_truncate_parse`].
pub(crate) unsafe fn saltyfs_ipc_truncate_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    new_size: u64,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Truncate { ino, new_size }.pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_TRUNCATE;
        req.regs[0] = ino;
        req.regs[1] = new_size;
        req.length = 2;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_TRUNCATE, tx_id, seq, 0);

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a `BACKEND_TRUNCATE` completion.
pub(crate) fn saltyfs_ipc_truncate_parse(reply: &TronaMsg) -> Result<(), u64> {
    if reply.label == TRONA_OK {
        Ok(())
    } else {
        Err(reply.label)
    }
}

// =========================================================================
// BACKEND_UNLINK / BACKEND_RMDIR (async)
// =========================================================================

/// Issue an asynchronous [`BACKEND_UNLINK`].
pub(crate) unsafe fn saltyfs_ipc_unlink_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
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
            super::op_kind::SaltyfsOpKind::Unlink {
                parent_ino,
                name: name_bytes,
                name_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_UNLINK;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + (name_len as u64 + 7) / 8;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_UNLINK, tx_id, seq, 0);

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Issue an asynchronous [`BACKEND_RMDIR`]. Same contract as
/// [`saltyfs_ipc_unlink_issue`] but tagged with
/// [`SaltyfsOpKind::Rmdir`] so the deferred-issue drain fires the
/// correct opcode on replay.
pub(crate) unsafe fn saltyfs_ipc_rmdir_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
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
            super::op_kind::SaltyfsOpKind::Rmdir {
                parent_ino,
                name: name_bytes,
                name_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_RMDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + (name_len as u64 + 7) / 8;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_RMDIR, tx_id, seq, 0);

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a plain-ack compound mutation completion (unlink / rmdir /
/// link / rename / truncate share the same reply shape).
pub(crate) fn saltyfs_ipc_mutation_ack_parse(reply: &TronaMsg) -> Result<(), u64> {
    if reply.label == TRONA_OK {
        Ok(())
    } else {
        Err(reply.label)
    }
}

// =========================================================================
// BACKEND_CREATE / MKDIR / SYMLINK — async issue helpers
// =========================================================================

/// Issue an asynchronous `BACKEND_CREATE` (V2). Reserves credit,
/// reserves a `PendingOp` tagged with [`SaltyfsOpKind::Create`]
/// (carries the inline name for deferred replay), and fires
/// `send_ctx`. Wire layout mirrors the sync V2 helper: `regs[0] =
/// parent_ino | V2_BIT, regs[1] = mode, regs[2] = uid, regs[3] =
/// gid, regs[4] = name_len, regs[5..] = name`.
///
/// Completion reply carries `reply.regs[0] = new_ino`; the completion
/// router synthesises stat attrs (size=0, nlink=1, blocks=0, mtime=
/// server-assigned-approximation) from the client-known request
/// parameters and the server-returned ino — no follow-up STAT round-
/// trip is needed, matching the pragmatic compound-mutation scope. A
/// subsequent client-facing `getattr` will refresh the cache via the
/// existing `BACKEND_STAT` path if authoritative attrs are required.
pub(crate) unsafe fn saltyfs_ipc_create_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    seq: u32,
    name: *const u8,
    name_len: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        if (name_len as usize) > crate::owner::pending::WALK_NAME_MAX || (name_len as usize) > 120 {
            return None;
        }
        let mut name_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Create {
                parent_ino,
                mode,
                uid,
                gid,
                name: name_buf,
                name_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_CREATE;
        req.regs[0] = parent_ino | SALTYFS_PROTO_V2;
        req.regs[1] = mode as u64;
        req.regs[2] = uid as u64;
        req.regs[3] = gid as u64;
        req.regs[4] = name_len as u64;
        let dst = &raw mut req.regs[5] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 5 + ((name_len as u64) + 7) / 8;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_CREATE, tx_id, seq, 0);

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Parse a child-returning mutation reply
/// (`BACKEND_CREATE` / `BACKEND_MKDIR` / `BACKEND_SYMLINK`).
/// Returns `Ok(new_ino)` on success, `Err(label)` on failure.
pub(crate) fn saltyfs_ipc_child_reply_parse(reply: &TronaMsg) -> Result<u64, u64> {
    if reply.label == TRONA_OK {
        Ok(reply.regs[0])
    } else {
        Err(reply.label)
    }
}

/// Issue an asynchronous `BACKEND_MKDIR` (V2). See
/// [`saltyfs_ipc_create_issue`] for the contract shape; the only
/// difference is the wire label and the fact that the resulting
/// vnode's type is directory.
pub(crate) unsafe fn saltyfs_ipc_mkdir_issue_async(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    seq: u32,
    name: *const u8,
    name_len: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        if (name_len as usize) > crate::owner::pending::WALK_NAME_MAX || (name_len as usize) > 120 {
            return None;
        }
        let mut name_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Mkdir {
                parent_ino,
                mode,
                uid,
                gid,
                name: name_buf,
                name_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_MKDIR;
        req.regs[0] = parent_ino | SALTYFS_PROTO_V2;
        req.regs[1] = mode as u64;
        req.regs[2] = uid as u64;
        req.regs[3] = gid as u64;
        req.regs[4] = name_len as u64;
        let dst = &raw mut req.regs[5] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 5 + ((name_len as u64) + 7) / 8;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_MKDIR, tx_id, seq, 0);

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Issue an asynchronous `BACKEND_SYMLINK` (V2). Wire layout mirrors
/// the sync helper: name at fixed slot `regs[5..12]` (56 bytes),
/// target at fixed slot `regs[12..20]` (64 bytes), length 20 words.
pub(crate) unsafe fn saltyfs_ipc_symlink_issue_async(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    seq: u32,
    name: *const u8,
    name_len: u8,
    target: *const u8,
    target_len: u8,
    uid: u32,
    gid: u32,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        // Sync V2 caps name at 56 bytes; target at 64 bytes (fixed
        // slot). Match exactly or the backend handler rejects.
        if (name_len as usize) > 56 || (target_len as usize) > 64 {
            return None;
        }
        let mut name_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        let mut target_buf = [0u8; 64];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        for i in 0..target_len as usize {
            target_buf[i] = *target.add(i);
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Symlink {
                parent_ino,
                uid,
                gid,
                name: name_buf,
                target: target_buf,
                name_len,
                target_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_SYMLINK;
        req.regs[0] = parent_ino | SALTYFS_PROTO_V2;
        req.regs[1] = uid as u64;
        req.regs[2] = gid as u64;
        req.regs[3] = name_len as u64;
        req.regs[4] = target_len as u64;
        let dst_name = &raw mut req.regs[5] as *mut u8;
        for i in 0..name_len as usize {
            *dst_name.add(i) = *name.add(i);
        }
        let dst_target = &raw mut req.regs[12] as *mut u8;
        for i in 0..target_len as usize {
            *dst_target.add(i) = *target.add(i);
        }
        req.length = 20;
        super::rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_SYMLINK, tx_id, seq, 0);

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

// =========================================================================
// BACKEND_LINK / RENAME — async issue helpers (plain-ack completion)
// =========================================================================

/// Issue an asynchronous `BACKEND_LINK`. Reserves credit + pending,
/// sends `regs[0]=existing_ino, regs[1]=new_parent_ino,
/// regs[2]=name_len, regs[3..]=name`. Completion is a plain ack.
pub(crate) unsafe fn saltyfs_ipc_link_issue_async(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    existing_ino: u64,
    existing_seq: u32,
    new_parent_ino: u64,
    new_parent_seq: u32,
    name: *const u8,
    name_len: u8,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        // Sync caps name at 136 bytes; match.
        if (name_len as usize) > 136 || (name_len as usize) > crate::owner::pending::WALK_NAME_MAX {
            return None;
        }
        let mut name_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Link {
                target_ino: existing_ino,
                parent_ino: new_parent_ino,
                name: name_buf,
                name_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_LINK;
        req.regs[0] = existing_ino;
        req.regs[1] = new_parent_ino;
        req.regs[2] = name_len as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 3 + ((name_len as u64) + 7) / 8;
        super::rpc::stamp_saltyfs_async_request(
            md,
            &mut req,
            BACKEND_LINK,
            tx_id,
            existing_seq,
            new_parent_seq,
        );

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}

/// Issue an asynchronous `BACKEND_RENAME`. Wire layout mirrors the
/// sync helper: `regs[0]=old_parent, regs[1]=old_name_len,
/// regs[2]=new_parent, regs[3]=new_name_len, regs[4..12]=old_name,
/// regs[12..20]=new_name`. Length = 20.
pub(crate) unsafe fn saltyfs_ipc_rename_issue_async(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    old_parent_ino: u64,
    old_parent_seq: u32,
    old_name: *const u8,
    old_name_len: u8,
    new_parent_ino: u64,
    new_parent_seq: u32,
    new_name: *const u8,
    new_name_len: u8,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
) -> Option<crate::owner::pending::PendingOpHandle> {
    unsafe {
        // Sync caps both names at 64 bytes (fixed-slot layout).
        if (old_name_len as usize) > 64 || (new_name_len as usize) > 64 {
            return None;
        }
        let mut old_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        let mut new_buf = [0u8; crate::owner::pending::WALK_NAME_MAX];
        for i in 0..old_name_len as usize {
            old_buf[i] = *old_name.add(i);
        }
        for i in 0..new_name_len as usize {
            new_buf[i] = *new_name.add(i);
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let Some((handle, tx_id)) = state.reserve_fs_pending_credited(
            fs_instance_id,
            super::op_kind::SaltyfsOpKind::Rename {
                old_parent_ino,
                new_parent_ino,
                old_name: old_buf,
                new_name: new_buf,
                old_name_len,
                new_name_len,
            }
            .pack(),
        ) else {
            state.backend_credit_release(fs_instance_id);
            return None;
        };

        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_RENAME;
        req.regs[0] = old_parent_ino;
        req.regs[1] = old_name_len as u64;
        req.regs[2] = new_parent_ino;
        req.regs[3] = new_name_len as u64;
        let dst_old = &raw mut req.regs[4] as *mut u8;
        for i in 0..old_name_len as usize {
            *dst_old.add(i) = *old_name.add(i);
        }
        let dst_new = &raw mut req.regs[12] as *mut u8;
        for i in 0..new_name_len as usize {
            *dst_new.add(i) = *new_name.add(i);
        }
        req.length = 20;
        super::rpc::stamp_saltyfs_async_request(
            md,
            &mut req,
            BACKEND_RENAME,
            tx_id,
            old_parent_seq,
            new_parent_seq,
        );

        let send_err = ipc::send_ctx(super::rpc::ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_instance_id, send_err);
        Some(handle)
    }
}
