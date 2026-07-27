// SPDX-License-Identifier: GPL-2.0-only
//
//! Extended-attribute SaltyFS IPC helpers — getxattr / setxattr /
//! listxattr / removexattr.
//!
//! Each of the four operations rides through the per-mount-instance
//! SHM ring on the read side: `BACKEND_GETXATTR` / `_SETXATTR` /
//! `_LISTXATTR` writes the value bytes into the SHM region, and the
//! completion router copies them out before releasing credit. The
//! single-mechanism approach mirrors the BACKEND_READ path (Zircon-
//! VMO model) — there is no inline-regs fast path.

use trona_kernel::core_types::TronaMsg;

use crate::core::identity::FsInstanceId;
use crate::ipc::protocol::backend::{
    BACKEND_GETXATTR, BACKEND_LISTXATTR, BACKEND_REMOVEXATTR, BACKEND_SETXATTR,
    VFS_BACKEND_REPLY_OK,
};
use crate::owner::pending::{PendingOpHandle, WALK_NAME_MAX};

use super::op_kind::SaltyfsOpKind;
use super::rpc::{ipc_ctx, stamp_saltyfs_async_request};
use super::types::SaltyfsMountData;

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
// BACKEND_GETXATTR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_getxattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    name: *const u8,
    name_len: u8,
    buf_len: usize,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if name_len as usize > WALK_NAME_MAX {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let kind = SaltyfsOpKind::XattrGet {
            ino,
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
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_GETXATTR;
        req.regs[0] = ino;
        req.regs[1] = name_len as u64;
        req.regs[2] = buf_len as u64;
        pack_name_at(&mut req, 3, name, name_len);
        req.length = 3 + name_word_count(name_len);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_GETXATTR, tx_id, seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

/// Parse a `BACKEND_GETXATTR` reply into the value byte length.
/// `None` on backend failure / malformed reply. `Some(0)` is a
/// legitimate "attribute exists, value empty" reply.
pub(crate) fn saltyfs_ipc_xattr_get_parse(reply: &TronaMsg) -> Option<usize> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return None;
    }
    Some(reply.regs[0] as usize)
}

// ---------------------------------------------------------------------------
// BACKEND_SETXATTR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_setxattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    name: *const u8,
    name_len: u8,
    value: *const u8,
    value_len: usize,
    flags: u32,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        const KNOWN_XATTR_FLAGS: u32 =
            crate::core::vop::XATTR_CREATE | crate::core::vop::XATTR_REPLACE;
        if name_len as usize > WALK_NAME_MAX {
            return None;
        }
        if (flags & !KNOWN_XATTR_FLAGS) != 0 || (flags & KNOWN_XATTR_FLAGS) == KNOWN_XATTR_FLAGS {
            return None;
        }
        if value_len > WALK_NAME_MAX {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        // SHM-only payload transfer. The caller must have copied
        // the value bytes into the mount's SHM region before
        // calling this function; the wire passes (offset, count)
        // pointing at the slot.
        let shm_dst = (*md).shm_vaddr as *mut u8;
        if shm_dst.is_null() || value_len > (*md).shm_size as usize {
            state.backend_credit_release(fs_instance_id);
            return None;
        }
        let copy_len = value_len;
        for i in 0..copy_len {
            *shm_dst.add(i) = *value.add(i);
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let mut value_buf = [0u8; WALK_NAME_MAX];
        for i in 0..copy_len {
            value_buf[i] = *value.add(i);
        }
        let kind = SaltyfsOpKind::SetXattr {
            ino,
            name: name_buf,
            value: value_buf,
            name_len,
            value_len: copy_len as u16,
            flags,
        };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_SETXATTR;
        req.regs[0] = ino;
        req.regs[1] = name_len as u64;
        req.regs[2] = copy_len as u64;
        req.regs[3] = flags as u64;
        pack_name_at(&mut req, 4, name, name_len);
        req.length = 4 + name_word_count(name_len);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_SETXATTR, tx_id, seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

/// Parse a `BACKEND_SETXATTR` reply. `Ok(())` on success; the
/// label of any error reply propagates as `Err(label)` so the
/// caller can map via `VfsError::from_backend_reply`.
pub(crate) fn saltyfs_ipc_setxattr_parse(reply: &TronaMsg) -> Result<(), u64> {
    if reply.label == VFS_BACKEND_REPLY_OK {
        Ok(())
    } else {
        Err(reply.label)
    }
}

// ---------------------------------------------------------------------------
// BACKEND_LISTXATTR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_listxattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    buf_len: usize,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let kind = SaltyfsOpKind::ListXattr { ino };
        let (handle, tx_id) = match state.reserve_fs_pending_credited(fs_instance_id, kind.pack()) {
            Some(p) => p,
            None => {
                state.backend_credit_release(fs_instance_id);
                return None;
            }
        };
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_LISTXATTR;
        req.regs[0] = ino;
        req.regs[1] = buf_len as u64;
        req.length = 2;
        stamp_saltyfs_async_request(md, &mut req, BACKEND_LISTXATTR, tx_id, seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

/// Parse a `BACKEND_LISTXATTR` reply into `(bytes_needed,
/// bytes_written)`. `bytes_needed` reflects the total size of
/// the available list — callers that received a short buffer
/// reissue with the wider request. `None` on malformed reply.
pub(crate) fn saltyfs_ipc_listxattr_parse(reply: &TronaMsg) -> Option<(usize, usize)> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return None;
    }
    Some((reply.regs[0] as usize, reply.regs[1] as usize))
}

// ---------------------------------------------------------------------------
// BACKEND_REMOVEXATTR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn saltyfs_ipc_removexattr_issue(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    ino: u64,
    seq: u32,
    name: *const u8,
    name_len: u8,
    fs_instance_id: FsInstanceId,
) -> Option<PendingOpHandle> {
    unsafe {
        if name_len as usize > WALK_NAME_MAX {
            return None;
        }
        if !state.backend_credit_reserve(fs_instance_id) {
            return None;
        }
        let mut name_buf = [0u8; WALK_NAME_MAX];
        for i in 0..name_len as usize {
            name_buf[i] = *name.add(i);
        }
        let kind = SaltyfsOpKind::RemoveXattr {
            ino,
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
        let mut req = TronaMsg::zeroed();
        req.label = BACKEND_REMOVEXATTR;
        req.regs[0] = ino;
        req.regs[1] = name_len as u64;
        pack_name_at(&mut req, 2, name, name_len);
        req.length = 2 + name_word_count(name_len);
        stamp_saltyfs_async_request(md, &mut req, BACKEND_REMOVEXATTR, tx_id, seq, 0);
        let send_err = trona_kernel::ipc::mp_write_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        if state.observe_backend_send(fs_instance_id, send_err) != 0 {
            state.backend_credit_release(fs_instance_id);
            let _ = state.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }
}

/// Parse a `BACKEND_REMOVEXATTR` reply. Same shape as
/// [`saltyfs_ipc_setxattr_parse`].
pub(crate) fn saltyfs_ipc_removexattr_parse(reply: &TronaMsg) -> Result<(), u64> {
    if reply.label == VFS_BACKEND_REPLY_OK {
        Ok(())
    } else {
        Err(reply.label)
    }
}
