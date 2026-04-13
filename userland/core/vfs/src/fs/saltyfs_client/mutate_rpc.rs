// SPDX-License-Identifier: GPL-2.0-only
//! Mutating SaltyFS IPC helpers — create, mkdir, symlink, unlink, rmdir, rename,
//! link, truncate, write, chmod, chown.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use super::rpc::ipc_ctx;
use super::types::SaltyfsMountData;

/// V2 protocol sentinel — bit 63 on parent_ino signals uid/gid fields present.
const SALTYFS_PROTO_V2: u64 = 1u64 << 63;

// =========================================================================
// SALTYFS_CREATE (V1 + V2)
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
        req.label = SALTYFS_CREATE;

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
// SALTYFS_MKDIR (V1 + V2)
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
        req.label = SALTYFS_MKDIR;

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
// SALTYFS_SYMLINK (V1 + V2)
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
        req.label = SALTYFS_SYMLINK;

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
// SALTYFS_UNLINK
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
        req.label = SALTYFS_UNLINK;
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
// SALTYFS_RMDIR
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
        req.label = SALTYFS_RMDIR;
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
// SALTYFS_RENAME
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
        req.label = SALTYFS_RENAME;
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
// SALTYFS_LINK
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
        req.label = SALTYFS_LINK;
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
// SALTYFS_TRUNCATE
// =========================================================================

/// Truncate a file. Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_truncate(
    md: *mut SaltyfsMountData,
    ino: u64,
    new_size: u64,
) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_TRUNCATE;
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
// SALTYFS_WRITE_INLINE — small writes via IPC registers
// =========================================================================

/// Write up to 136 bytes to a remote inode via inline IPC registers.
/// Returns (label, bytes_written).
pub(super) unsafe fn saltyfs_ipc_write_inline(
    md: *mut SaltyfsMountData,
    ino: u64,
    offset: u64,
    data: *const u8,
    count: u64,
) -> (u64, u64) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_WRITE_INLINE;
        req.regs[0] = ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..count as usize {
            *dst.add(i) = *data.add(i);
        }
        req.length = 3 + (count + 7) / 8;

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
// SALTYFS_WRITE — SHM bulk write
// =========================================================================

/// Write to a remote inode via SHM bulk transport.
/// Data must already be at `shm_vaddr + shm_offset`. Returns (label, bytes_written).
pub(super) unsafe fn saltyfs_ipc_write_shm(
    md: *mut SaltyfsMountData,
    ino: u64,
    offset: u64,
    count: u64,
    shm_offset: u64,
) -> (u64, u64) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_WRITE;
        req.regs[0] = ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.regs[3] = shm_offset;
        req.length = 4;

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
// SALTYFS_CHMOD
// =========================================================================

/// Change permission bits. Returns the TRONA_* reply label.
pub(super) unsafe fn saltyfs_ipc_chmod(md: *mut SaltyfsMountData, ino: u64, new_perm: u32) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_CHMOD;
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
// SALTYFS_CHOWN
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
        req.label = SALTYFS_CHOWN;
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
