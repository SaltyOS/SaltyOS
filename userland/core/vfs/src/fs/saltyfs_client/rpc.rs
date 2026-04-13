// SPDX-License-Identifier: GPL-2.0-only
//! Read-only SaltyFS IPC helpers — lookup, stat, read, readlink, getparent.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::server::consts::*;

use super::types::SaltyfsMountData;

// =========================================================================
// IPC context accessor
// =========================================================================

#[inline]
pub(super) fn ipc_ctx() -> *mut trona::types::core::IpcContext {
    crate::ipc_ctx()
}

// =========================================================================
// SALTYFS_LOOKUP — single-component lookup with stat-merged reply
// =========================================================================

/// Lookup a single directory component on the remote SaltyFS.
///
/// Returns `Ok(Some(...))` on success, `Ok(None)` when the entry does not
/// exist, and `Err(reply_label)` when the backend reports a real failure.
pub(super) unsafe fn saltyfs_ipc_lookup(
    md: *mut SaltyfsMountData,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
) -> Result<Option<(u64, u32, u64, u32, u64, u32, u32, u8, u64)>, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_LOOKUP;
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
                reply.regs[2],
                reply.regs[3] as u32,
                reply.regs[4],
                reply.regs[5] as u32,
                reply.regs[6] as u32,
                reply.regs[7] as u8,
                reply.regs[8],
            ))),
            TRONA_NOT_FOUND => Ok(None),
            other => Err(other),
        }
    }
}

// =========================================================================
// SALTYFS_STAT
// =========================================================================

/// Stat a remote inode.
///
/// Returns `Some((size, mode, nlink, mtime, blocks, uid, gid))` on success.
pub(super) unsafe fn saltyfs_ipc_stat(
    md: *mut SaltyfsMountData,
    ino: u64,
) -> Option<(u64, u32, u32, u64, u64, u32, u32)> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_STAT;
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
        ))
    }
}

// =========================================================================
// SALTYFS_READ_INLINE — small reads via IPC registers
// =========================================================================

/// Read up to 152 bytes from a remote inode via inline IPC registers.
///
/// Returns `Some(bytes_read)` on success. Transport/backend failures return
/// `None` so callers do not misinterpret them as EOF.
pub(super) unsafe fn saltyfs_ipc_read_inline(
    md: *mut SaltyfsMountData,
    ino: u64,
    offset: u64,
    dst: *mut u8,
    count: u64,
) -> Option<u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READ_INLINE;
        req.regs[0] = ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.length = 3;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 || reply.label != TRONA_OK {
            return None;
        }

        let bytes_read = reply.regs[0];
        if bytes_read > 0 {
            let src = &reply.regs[1] as *const u64 as *const u8;
            for i in 0..bytes_read as usize {
                *dst.add(i) = *src.add(i);
            }
        }
        Some(bytes_read)
    }
}

// =========================================================================
// SALTYFS_READ — SHM bulk read
// =========================================================================

/// Read from a remote inode via SHM bulk transport.
///
/// Data lands at `shm_vaddr + shm_offset`. Returns `Some(bytes_read)` on
/// success and `None` on transport/backend failure.
pub(super) unsafe fn saltyfs_ipc_read_shm(
    md: *mut SaltyfsMountData,
    ino: u64,
    offset: u64,
    count: u64,
    shm_offset: u64,
) -> Option<u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READ;
        req.regs[0] = ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.regs[3] = shm_offset;
        req.length = 4;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 || reply.label != TRONA_OK {
            return None;
        }
        Some(reply.regs[0])
    }
}

// =========================================================================
// SALTYFS_READLINK
// =========================================================================

/// Read a symlink target into `buf`. Returns the number of bytes read (0 on failure).
pub(super) unsafe fn saltyfs_ipc_readlink(
    md: *mut SaltyfsMountData,
    ino: u64,
    buf: *mut u8,
    buf_cap: usize,
) -> usize {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READLINK;
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

// =========================================================================
// SALTYFS_GETPARENT
// =========================================================================

/// Ask SaltyFS for the parent inode of a given inode.
///
/// Returns the parent inode number on success.
/// Returns 0 if the inode has no INODE_REF (root or orphan).
/// Returns `u64::MAX` on IPC or structural errors.
pub(super) unsafe fn saltyfs_ipc_getparent(md: *mut SaltyfsMountData, child_ino: u64) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_GETPARENT;
        req.regs[0] = child_ino;
        req.length = 1;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 {
            u64::MAX
        } else if reply.label == TRONA_OK {
            reply.regs[0]
        } else if reply.label == TRONA_NOT_FOUND {
            0
        } else {
            u64::MAX
        }
    }
}

// =========================================================================
// SALTYFS_GETINFO — filesystem statistics
// =========================================================================

/// Query filesystem-level info (total_blocks, used_blocks, block_size, label).
pub(super) unsafe fn saltyfs_ipc_getinfo(md: *mut SaltyfsMountData) -> Option<(u64, u64, u64)> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_GETINFO;
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
