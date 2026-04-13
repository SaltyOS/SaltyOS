// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS client VopVector implementation — vnode-level operations.
//!
//! Each function maps to a `VopMetaOps` or `VopDataOps` slot and issues the
//! corresponding SaltyFS IPC call via the `rpc` / `mutate_rpc` / `xattr_rpc`
//! helpers.

use trona::consts::kernel::*;
use trona::types::core::TronaMsg;

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::vnode::{VnodeHandle, VT_DIR, VT_LNK, VT_REG};
use crate::vfs_core::vop::ReaddirEmit;
use crate::vfs_core::vop_context::{VopContext, VopDataContext};

use super::mutate_rpc;
use super::pool;
use super::readdir;
use super::rpc;
use super::types::{SaltyfsMountData, SaltyfsVnodeData};
use super::xattr_rpc;

// =========================================================================
// Helpers
// =========================================================================

#[inline]
unsafe fn vdata(ctx: &VopContext) -> *mut SaltyfsVnodeData {
    ctx.data as *mut SaltyfsVnodeData
}

#[inline]
unsafe fn mdata(ctx: &VopContext) -> *mut SaltyfsMountData {
    ctx.mount_data as *mut SaltyfsMountData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataContext) -> *mut SaltyfsVnodeData {
    ctx.data as *mut SaltyfsVnodeData
}

#[inline]
unsafe fn mdata_d(ctx: &VopDataContext) -> *mut SaltyfsMountData {
    ctx.mount_data as *mut SaltyfsMountData
}

#[inline]
fn mode_to_vtype(mode: u32) -> u8 {
    match mode & S_IFMT_L {
        S_IFDIR_L => VT_DIR,
        S_IFLNK_L => VT_LNK,
        _ => VT_REG,
    }
}

#[inline]
fn dir_type_to_vtype(dir_type: u8) -> u8 {
    match dir_type {
        1 => VT_REG,
        4 => VT_DIR,
        7 => VT_LNK,
        _ => VT_REG,
    }
}

/// Map a TRONA_* IPC error label to a VfsError.
#[inline]
fn trona_to_vfs_error(label: u64) -> VfsError {
    match label {
        TRONA_NOT_FOUND => VfsError::NotFound,
        TRONA_NOT_DIRECTORY => VfsError::NotDir,
        TRONA_IS_DIRECTORY => VfsError::IsDir,
        TRONA_ALREADY_EXISTS => VfsError::Exists,
        TRONA_INVALID_ARGUMENT => VfsError::Inval,
        TRONA_INSUFFICIENT_RIGHTS => VfsError::Perm,
        TRONA_OUT_OF_MEMORY => VfsError::NoSpace,
        TRONA_BUSY => VfsError::Busy,
        TRONA_READONLY => VfsError::ReadOnly,
        TRONA_TOO_LARGE => VfsError::TooLarge,
        _ => VfsError::Io,
    }
}

/// Allocate a vnode from the arena and populate it from stat data.
///
/// First checks if a vdata already exists for the remote inode (cache hit).
/// If so, updates cached attributes and allocates a new arena vnode pointing
/// to the existing vdata. Otherwise allocates both vdata and arena vnode.
unsafe fn alloc_saltyfs_vnode(
    ctx: &VopContext,
    remote_ino: u64,
    mode: u32,
    size: u64,
    nlink: u32,
    mtime: u64,
    uid: u32,
    gid: u32,
    dir_type: u8,
    blocks: u64,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = mdata(ctx);

        // Check if vdata already cached for this remote inode
        let existing_vd = pool::find_vdata_by_ino(md, remote_ino);
        if !existing_vd.is_null() {
            // Update cached attributes
            (*existing_vd).mode = mode;
            (*existing_vd).size = size;
            (*existing_vd).nlink = nlink;
            (*existing_vd).mtime = mtime;
            (*existing_vd).uid = uid;
            (*existing_vd).gid = gid;
            (*existing_vd).blocks = blocks;

            if (*existing_vd).vnode_handle.is_valid()
                && (ctx.resolve_vnode)((*existing_vd).vnode_handle).is_some()
            {
                return Ok((*existing_vd).vnode_handle);
            }

            let (vh, vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
            (*vp).id = remote_ino;
            (*vp).vtype = (*existing_vd).ftype;
            (*vp).data = existing_vd as *mut u8;
            (*vp).nlink = nlink;
            (*vp).mount = ctx.mount_handle;
            (*vp).ops = (*ctx.vnode).ops;
            (*existing_vd).vnode_handle = vh;
            return Ok(vh);
        }

        // Allocate new vdata
        let vd = pool::alloc_vdata(md);
        if vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        let ftype = if dir_type != 0 {
            dir_type_to_vtype(dir_type)
        } else {
            mode_to_vtype(mode)
        };
        (*vd).active = 1;
        (*vd).ftype = ftype;
        (*vd).mode = mode;
        (*vd).remote_ino = remote_ino;
        (*vd).size = size;
        (*vd).nlink = nlink;
        (*vd).uid = uid;
        (*vd).gid = gid;
        (*vd).mtime = mtime;
        (*vd).blocks = blocks;

        // Allocate arena vnode
        let (vh, vp) = match (ctx.alloc)() {
            Some(pair) => pair,
            None => {
                (*vd).active = 0;
                return Err(VfsError::NoSpace);
            }
        };
        (*vp).id = remote_ino;
        (*vp).vtype = ftype;
        (*vp).data = vd as *mut u8;
        (*vp).nlink = nlink;
        (*vp).mount = ctx.mount_handle;
        (*vp).ops = (*ctx.vnode).ops;
        (*vd).vnode_handle = vh;

        Ok(vh)
    }
}

// =========================================================================
// MetaOps — owner-thread metadata operations
// =========================================================================

pub(super) unsafe fn saltyfs_lookup(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }

        let md = mdata(ctx);

        // Handle "."
        if name_len == 1 && *name == b'.' {
            return Ok(ctx.handle);
        }

        // Handle ".."
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            let parent = rpc::saltyfs_ipc_getparent(md, (*dvd).remote_ino);
            if parent == 0 || parent == u64::MAX {
                return Ok(ctx.handle);
            }
            match rpc::saltyfs_ipc_stat(md, parent) {
                Some((size, mode, nlink, mtime, blocks, uid, gid)) => {
                    alloc_saltyfs_vnode(ctx, parent, mode, size, nlink, mtime, uid, gid, 0, blocks)
                }
                None => Ok(VnodeHandle::INVALID),
            }
        } else {
            match rpc::saltyfs_ipc_lookup(md, (*dvd).remote_ino, name, name_len) {
                Ok(Some((child_ino, mode, size, nlink, mtime, uid, gid, dir_type, blocks))) => {
                    alloc_saltyfs_vnode(
                        ctx, child_ino, mode, size, nlink, mtime, uid, gid, dir_type, blocks,
                    )
                }
                Ok(None) => Ok(VnodeHandle::INVALID),
                Err(label) => Err(trona_to_vfs_error(label)),
            }
        }
    }
}

pub(super) unsafe fn saltyfs_create(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
    mode: u32,
    cred: *const VfsCred,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = if !cred.is_null() {
            ((*cred).euid, (*cred).egid)
        } else {
            (0, 0)
        };
        let new_ino = mutate_rpc::saltyfs_ipc_create(
            md,
            (*dvd).remote_ino,
            name,
            name_len,
            mode,
            uid,
            gid,
            (*md).v2_protocol,
        );
        if new_ino == 0 {
            return Err(VfsError::Io);
        }
        match rpc::saltyfs_ipc_stat(md, new_ino) {
            Some((size, mode, nlink, mtime, blocks, uid, gid)) => {
                alloc_saltyfs_vnode(ctx, new_ino, mode, size, nlink, mtime, uid, gid, 0, blocks)
            }
            None => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_mkdir(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
    mode: u32,
    cred: *const VfsCred,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = if !cred.is_null() {
            ((*cred).euid, (*cred).egid)
        } else {
            (0, 0)
        };
        let (label, new_ino) = mutate_rpc::saltyfs_ipc_mkdir(
            md,
            (*dvd).remote_ino,
            name,
            name_len,
            mode,
            uid,
            gid,
            (*md).v2_protocol,
        );
        if label == TRONA_ALREADY_EXISTS {
            return match rpc::saltyfs_ipc_lookup(md, (*dvd).remote_ino, name, name_len) {
                Ok(Some((child_ino, mode, size, nlink, mtime, uid, gid, dir_type, blocks))) => {
                    alloc_saltyfs_vnode(
                        ctx, child_ino, mode, size, nlink, mtime, uid, gid, dir_type, blocks,
                    )
                }
                Ok(None) => Err(VfsError::Io),
                Err(lookup_label) => Err(trona_to_vfs_error(lookup_label)),
            };
        }
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        if new_ino == 0 {
            return Err(VfsError::Io);
        }
        match rpc::saltyfs_ipc_stat(md, new_ino) {
            Some((size, mode, nlink, mtime, blocks, uid, gid)) => {
                alloc_saltyfs_vnode(ctx, new_ino, mode, size, nlink, mtime, uid, gid, 0, blocks)
            }
            None => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_symlink(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
    target: *const u8,
    target_len: u8,
    cred: *const VfsCred,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = if !cred.is_null() {
            ((*cred).euid, (*cred).egid)
        } else {
            (0, 0)
        };
        let (label, new_ino) = mutate_rpc::saltyfs_ipc_symlink(
            md,
            (*dvd).remote_ino,
            name,
            name_len,
            target,
            target_len,
            uid,
            gid,
            (*md).v2_protocol,
        );
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        if new_ino == 0 {
            return Err(VfsError::Io);
        }
        match rpc::saltyfs_ipc_stat(md, new_ino) {
            Some((size, mode, nlink, mtime, blocks, uid, gid)) => {
                alloc_saltyfs_vnode(ctx, new_ino, mode, size, nlink, mtime, uid, gid, 0, blocks)
            }
            None => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_unlink(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let label = mutate_rpc::saltyfs_ipc_unlink(md, (*dvd).remote_ino, name, name_len);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_rmdir(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let label = mutate_rpc::saltyfs_ipc_rmdir(md, (*dvd).remote_ino, name, name_len);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_link(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
    target: VnodeHandle,
) -> VfsResult<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let target_vp = (ctx.resolve_vnode)(target).ok_or(VfsError::Inval)?;
        let tvd = (*target_vp).data as *mut SaltyfsVnodeData;
        if tvd.is_null() {
            return Err(VfsError::Inval);
        }
        let md = mdata(ctx);
        let label =
            mutate_rpc::saltyfs_ipc_link(md, (*tvd).remote_ino, (*dvd).remote_ino, name, name_len);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_rename(
    old_ctx: &VopContext,
    old_name: *const u8,
    old_len: u8,
    new_ctx: &VopContext,
    new_name: *const u8,
    new_len: u8,
) -> VfsResult<()> {
    unsafe {
        let old_dvd = old_ctx.data as *mut SaltyfsVnodeData;
        let new_dvd = new_ctx.data as *mut SaltyfsVnodeData;
        if old_dvd.is_null() || new_dvd.is_null() {
            return Err(VfsError::Inval);
        }
        let md = mdata(old_ctx);
        let label = mutate_rpc::saltyfs_ipc_rename(
            md,
            (*old_dvd).remote_ino,
            old_name,
            old_len,
            (*new_dvd).remote_ino,
            new_name,
            new_len,
        );
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_open(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

pub(super) unsafe fn saltyfs_close(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

pub(super) unsafe fn saltyfs_getattr(ctx: &VopContext, attr: *mut VAttr) -> VfsResult<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);

        match rpc::saltyfs_ipc_stat(md, (*vd).remote_ino) {
            Some((size, mode, nlink, mtime, blocks, uid, gid)) => {
                (*vd).size = size;
                (*vd).mode = mode;
                (*vd).nlink = nlink;
                (*vd).mtime = mtime;
                (*vd).blocks = blocks;
                (*vd).uid = uid;
                (*vd).gid = gid;

                (*attr).size = size;
                (*attr).blocks = blocks;
                (*attr).mode = mode;
                (*attr).uid = uid;
                (*attr).gid = gid;
                (*attr).nlink = nlink;
                (*attr).mtime = mtime;
                (*attr).atime = 0;
                (*attr).ctime = 0;
                (*attr).btime = 0;
                (*attr).dev_id = 0;
                (*attr).rdev = 0;
                Ok(())
            }
            None => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_setattr(ctx: &VopContext, attr: *const VAttr) -> VfsResult<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);

        if (*attr).mode != 0 {
            let label = mutate_rpc::saltyfs_ipc_chmod(md, (*vd).remote_ino, (*attr).mode & 0o7777);
            if label != TRONA_OK {
                return Err(trona_to_vfs_error(label));
            }
            (*vd).mode = ((*vd).mode & S_IFMT_L) | ((*attr).mode & 0o7777);
        }

        let chown_uid = if (*attr).uid != u32::MAX {
            (*attr).uid
        } else {
            u32::MAX
        };
        let chown_gid = if (*attr).gid != u32::MAX {
            (*attr).gid
        } else {
            u32::MAX
        };
        if chown_uid != u32::MAX || chown_gid != u32::MAX {
            let label = mutate_rpc::saltyfs_ipc_chown(md, (*vd).remote_ino, chown_uid, chown_gid);
            if label != TRONA_OK {
                return Err(trona_to_vfs_error(label));
            }
            if chown_uid != u32::MAX {
                (*vd).uid = chown_uid;
            }
            if chown_gid != u32::MAX {
                (*vd).gid = chown_gid;
            }
        }

        Ok(())
    }
}

pub(super) unsafe fn saltyfs_access(
    ctx: &VopContext,
    mode: u32,
    cred: *const VfsCred,
) -> VfsResult<()> {
    unsafe {
        if cred.is_null() {
            return Ok(());
        }
        if (*cred).euid == 0 {
            return Ok(());
        }
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }

        let file_mode = (*vd).mode;
        let uid = (*vd).uid;
        let gid = (*vd).gid;

        let shift = if (*cred).euid == uid {
            6
        } else if (*cred).in_group(gid) {
            3
        } else {
            0
        };

        let perm = (file_mode >> shift) & 0o7;

        if (mode & 1) != 0 && (perm & 4) == 0 {
            return Err(VfsError::Perm);
        }
        if (mode & 2) != 0 && (perm & 2) == 0 {
            return Err(VfsError::Perm);
        }
        if (mode & 4) != 0 && (perm & 1) == 0 {
            return Err(VfsError::Perm);
        }
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_readlink(
    ctx: &VopContext,
    buf: *mut u8,
    buf_len: usize,
    _cred: *const VfsCred,
) -> VfsResult<usize> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype != VT_LNK {
            return Err(VfsError::Inval);
        }
        let md = mdata(ctx);
        let len = rpc::saltyfs_ipc_readlink(md, (*vd).remote_ino, buf, buf_len);
        if len == 0 {
            return Err(VfsError::Io);
        }
        Ok(len)
    }
}

pub(super) unsafe fn saltyfs_truncate(ctx: &VopContext, new_size: u64) -> VfsResult<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);
        let label = mutate_rpc::saltyfs_ipc_truncate(md, (*vd).remote_ino, new_size);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        (*vd).size = new_size;
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_inactive(ctx: &VopContext) {
    unsafe {
        let vd = vdata(ctx);
        if !vd.is_null() {
            // Keep the per-inode cache entry alive across close/reopen cycles.
            // Only the arena vnode is being reclaimed here; the cached remote
            // inode metadata remains the canonical lookup/vget record.
            (*vd).vnode_handle = VnodeHandle::INVALID;
        }
        (*ctx.vnode).data = core::ptr::null_mut();
    }
}

// =========================================================================
// DataOps — async-capable data operations
// =========================================================================

pub(super) unsafe fn saltyfs_read(
    ctx: &VopDataContext,
    offset: u64,
    dst: *mut u8,
    len: u64,
) -> VfsResult<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }

        let md = mdata_d(ctx);

        if (*md).shm_active && len > 152 {
            let shm_limit = (*md).shm_size;
            let read_count = if len > shm_limit { shm_limit } else { len };
            match rpc::saltyfs_ipc_read_shm(md, (*vd).remote_ino, offset, read_count, 0) {
                Some(bytes_read) => {
                    if bytes_read > 0 {
                        let src = (*md).shm_vaddr as *const u8;
                        core::ptr::copy_nonoverlapping(src, dst, bytes_read as usize);
                    }
                    return Ok(bytes_read);
                }
                None => {
                    return Err(VfsError::Io);
                }
            }
        }

        let read_count = if len > 152 { 152 } else { len };
        match rpc::saltyfs_ipc_read_inline(md, (*vd).remote_ino, offset, dst, read_count) {
            Some(bytes_read) => Ok(bytes_read),
            None => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_write(
    ctx: &VopDataContext,
    offset: u64,
    src: *const u8,
    len: u64,
) -> VfsResult<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }

        let md = mdata_d(ctx);

        if (*md).shm_active && len > 136 {
            let shm_limit = (*md).shm_size;
            let write_count = if len > shm_limit { shm_limit } else { len };
            let dst_shm = (*md).shm_vaddr as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst_shm, write_count as usize);
            let (label, written) =
                mutate_rpc::saltyfs_ipc_write_shm(md, (*vd).remote_ino, offset, write_count, 0);
            if label != TRONA_OK {
                return Err(trona_to_vfs_error(label));
            }
            let end = offset + written;
            if end > (*vd).size {
                (*vd).size = end;
            }
            return Ok(written);
        }

        let write_count = if len > 136 { 136 } else { len };
        let (label, written) =
            mutate_rpc::saltyfs_ipc_write_inline(md, (*vd).remote_ino, offset, src, write_count);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        let end = offset + written;
        if end > (*vd).size {
            (*vd).size = end;
        }
        Ok(written)
    }
}

pub(super) unsafe fn saltyfs_fsync(_ctx: &VopDataContext) -> VfsResult<()> {
    Ok(())
}

pub(super) unsafe fn saltyfs_readdir(
    ctx: &VopDataContext,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VfsResult<()> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() || (*vd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata_d(ctx);

        let start = *cookie;
        let attr = VAttr::zeroed();
        if start == 0 {
            if !emit((*vd).remote_ino, b".".as_ptr(), 1, 4, &attr) {
                *cookie = 1;
                return Ok(());
            }
        }
        if start <= 1 {
            let parent_ino = rpc::saltyfs_ipc_getparent(md, (*vd).remote_ino);
            let parent = if parent_ino == 0 || parent_ino == u64::MAX {
                (*vd).remote_ino
            } else {
                parent_ino
            };
            if !emit(parent, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = 2;
                return Ok(());
            }
        }

        let mut server_cookie = if start <= 1 { 0u64 } else { start - 2 };

        readdir::saltyfs_readdir_shm(md, (*vd).remote_ino, &raw mut server_cookie, emit)?;

        *cookie = if server_cookie == 0 {
            0
        } else {
            server_cookie + 2
        };
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_getxattr(
    ctx: &VopDataContext,
    name: *const u8,
    name_len: u8,
    buf: *mut u8,
    buf_len: usize,
) -> VfsResult<usize> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        if !(*md).shm_active {
            return Err(VfsError::NotSupported);
        }

        let shm_base = (*md).shm_vaddr as *mut u8;
        for i in 0..name_len as usize {
            *shm_base.add(i) = *name.add(i);
        }

        match xattr_rpc::saltyfs_ipc_getxattr(
            md,
            (*vd).remote_ino,
            0,
            buf_len as u64,
            name_len as usize,
        ) {
            Ok(value_len) => {
                if buf_len > 0 && value_len > 0 {
                    let copy = if value_len < buf_len {
                        value_len
                    } else {
                        buf_len
                    };
                    let src = shm_base;
                    for i in 0..copy {
                        *buf.add(i) = *src.add(i);
                    }
                }
                Ok(value_len)
            }
            Err(TRONA_NOT_FOUND) => Err(VfsError::NotFound),
            Err(TRONA_OUT_OF_RANGE) => Err(VfsError::TooLarge),
            Err(_) => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_setxattr(
    ctx: &VopDataContext,
    name: *const u8,
    name_len: u8,
    value: *const u8,
    value_len: usize,
    flags: u32,
) -> VfsResult<()> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        if !(*md).shm_active {
            return Err(VfsError::NotSupported);
        }

        let shm_base = (*md).shm_vaddr as *mut u8;
        for i in 0..name_len as usize {
            *shm_base.add(i) = *name.add(i);
        }
        for i in 0..value_len {
            *shm_base.add(name_len as usize + i) = *value.add(i);
        }

        let label = xattr_rpc::saltyfs_ipc_setxattr(
            md,
            (*vd).remote_ino,
            0,
            value_len as u64,
            name_len as usize,
            flags,
        );
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_listxattr(
    ctx: &VopDataContext,
    buf: *mut u8,
    buf_len: usize,
) -> VfsResult<usize> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        if !(*md).shm_active {
            return Err(VfsError::NotSupported);
        }

        match xattr_rpc::saltyfs_ipc_listxattr(md, (*vd).remote_ino, 0, buf_len as u64) {
            Ok((bytes_needed, bytes_written)) => {
                if buf_len > 0 && bytes_written > 0 {
                    let src = (*md).shm_vaddr as *const u8;
                    let copy = if bytes_written < buf_len {
                        bytes_written
                    } else {
                        buf_len
                    };
                    for i in 0..copy {
                        *buf.add(i) = *src.add(i);
                    }
                }
                Ok(bytes_needed)
            }
            Err(TRONA_NOT_FOUND) => Ok(0),
            Err(_) => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_removexattr(
    ctx: &VopDataContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<()> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        let label = xattr_rpc::saltyfs_ipc_removexattr(md, (*vd).remote_ino, name, name_len);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(())
    }
}

pub(super) unsafe fn saltyfs_statfs(ctx: &VopDataContext, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = mdata_d(ctx);
        match rpc::saltyfs_ipc_getinfo(md) {
            Some((total_blocks, used_blocks, block_size)) => {
                (*out).bsize = block_size;
                (*out).blocks = total_blocks;
                (*out).bfree = total_blocks.saturating_sub(used_blocks);
                (*out).bavail = (*out).bfree;
                (*out).files = 0;
                (*out).ffree = 0;
                let ft = &mut (*out).fs_type;
                ft[..7].copy_from_slice(b"saltyfs");
                (*out).flags = 0;
                (*out).name_max = 255;
                Ok(())
            }
            None => Err(VfsError::Io),
        }
    }
}
