// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS xattr IPC helpers — getxattr, setxattr, removexattr, listxattr.
//!
//! GETXATTR, SETXATTR, and LISTXATTR require SHM transport (name and/or value
//! are exchanged via the VFS-SaltyFS shared memory region). REMOVEXATTR uses
//! inline IPC registers for the name (up to 144 bytes).

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use super::rpc::ipc_ctx;
use super::types::SaltyfsMountData;

// =========================================================================
// SALTYFS_GETXATTR (23) — requires SHM
// =========================================================================

/// Get an extended attribute value.
///
/// The caller places the attribute name (NUL-terminated not required) at
/// `shm_vaddr + shm_offset` before calling. On success, the value is written
/// at the same SHM offset (overwriting the name).
///
/// Returns `Ok(value_len)` on success, `Err(label)` on failure.
/// When `buf_bytes == 0`, this is a size-query: returns the value length
/// without writing any data.
pub(super) unsafe fn saltyfs_ipc_getxattr(
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
        req.label = SALTYFS_GETXATTR;
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

// =========================================================================
// SALTYFS_SETXATTR (24) — requires SHM
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
        req.label = SALTYFS_SETXATTR;
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

// =========================================================================
// SALTYFS_REMOVEXATTR (25) — inline name
// =========================================================================

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
        req.label = SALTYFS_REMOVEXATTR;
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
// SALTYFS_LISTXATTR (26) — requires SHM
// =========================================================================

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
        req.label = SALTYFS_LISTXATTR;
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
