// SPDX-License-Identifier: GPL-2.0-only
//! Tmpfs VopVector implementation — vnode-level operations.
//!
//! Independent from ramfs — reimplements all operations with tmpfs-specific
//! size/inode accounting (used_bytes, used_inodes enforcement).

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::vnode::{Vnode, VnodeHandle, VT_CHR, VT_DIR, VT_LNK, VT_REG};
use crate::vfs_core::vop::ReaddirEmit;
use crate::vfs_core::vop_context::{VopContext, VopDataContext};

use super::pool;
use super::types::TmpfsVnodeData;

use trona::types::core::TronaMsg;

// =========================================================================
// Helpers
// =========================================================================

/// Get the `TmpfsMountData` from a VopContext's mount_data pointer.
#[inline]
unsafe fn mdata(ctx: &VopContext) -> *mut super::types::TmpfsMountData {
    ctx.mount_data as *mut super::types::TmpfsMountData
}

/// Get the `TmpfsMountData` from a VopDataContext's mount_data pointer.
#[inline]
unsafe fn mdata_d(ctx: &VopDataContext) -> *mut super::types::TmpfsMountData {
    ctx.mount_data as *mut super::types::TmpfsMountData
}

/// Get the `TmpfsVnodeData` from a VopContext's data pointer.
#[inline]
unsafe fn vdata(ctx: &VopContext) -> *mut TmpfsVnodeData {
    ctx.data as *mut TmpfsVnodeData
}

/// Get the `TmpfsVnodeData` from a VopDataContext's data pointer.
#[inline]
unsafe fn vdata_d(ctx: &VopDataContext) -> *mut TmpfsVnodeData {
    ctx.data as *mut TmpfsVnodeData
}

/// Map VT_* vnode type to DT_* dirent type for readdir.
#[inline]
fn vtype_to_dtype(vtype: u8) -> u8 {
    match vtype {
        VT_REG => 8,  // DT_REG
        VT_DIR => 4,  // DT_DIR
        VT_LNK => 10, // DT_LNK
        VT_CHR => 2,  // DT_CHR
        _ => 0,       // DT_UNKNOWN
    }
}

/// Create a new vnode + vdata pair, add to parent directory, and return
/// a VnodeHandle to the new vnode (allocated via ctx.alloc).
///
/// Enforces inode limit before allocation.
unsafe fn create_child(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
    mode: u32,
    ftype: u8,
    cred: *const VfsCred,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = mdata(ctx);
        let parent_vd = vdata(ctx);
        let parent_id = (*ctx.vnode).id;

        // Check inode limit
        if !pool::check_inodes(md) {
            return Err(VfsError::NoSpace);
        }

        // Allocate vnode data
        let vd = pool::alloc_vdata(md);
        if vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        let id = pool::next_id(md);
        (*vd).id = id;
        (*vd).parent_id = parent_id;
        (*vd).ftype = ftype;
        (*vd).mode = mode;
        (*vd).nlink = if ftype == VT_DIR { 2 } else { 1 };
        (*vd).size = 0;
        if !cred.is_null() {
            (*vd).uid = (*cred).euid;
            (*vd).gid = (*cred).egid;
        }

        // Allocate dirents for directories
        if ftype == VT_DIR {
            let dirents = crate::vfs_alloc_array::<super::types::Dirent>(INITIAL_DIRENTS);
            if dirents.is_null() {
                (*vd).active = 0;
                return Err(VfsError::NoSpace);
            }
            (*vd).dirents = dirents;
            (*vd).dirents_cap = INITIAL_DIRENTS as u16;
        }

        // Allocate vnode via arena callback
        let (child_vh, child_vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
        (*child_vp).id = id;
        (*child_vp).vtype = ftype;
        (*child_vp).data = vd as *mut u8;
        (*child_vp).nlink = (*vd).nlink;
        (*child_vp).mount = ctx.mount_handle;
        (*child_vp).ops = (*ctx.vnode).ops;
        (*vd).vnode_handle = child_vh;

        // Add dirent to parent
        if pool::dir_add_entry(parent_vd, name, name_len, id) != 0 {
            (*vd).active = 0;
            return Err(VfsError::NoSpace);
        }

        // Bump parent nlink for subdirectory ".."
        if ftype == VT_DIR {
            (*parent_vd).nlink += 1;
            (*ctx.vnode).nlink = (*parent_vd).nlink;
        }

        // Account for new inode
        pool::account_inode_add(md);

        Ok(child_vh)
    }
}

// =========================================================================
// MetaOps function implementations
// =========================================================================

pub(super) unsafe fn tmpfs_lookup(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }

        // Handle "."
        if name_len == 1 && *name == b'.' {
            return Ok(ctx.handle);
        }

        // Handle ".."
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            let parent_id = (*dvd).parent_id;
            if parent_id == 0 {
                return Ok(ctx.handle);
            }
            let md = mdata(ctx);
            let parent_vd = pool::find_vdata(md, parent_id);
            if parent_vd.is_null() {
                return Ok(VnodeHandle::INVALID);
            }
            if (*parent_vd).vnode_handle.is_valid()
                && (ctx.resolve_vnode)((*parent_vd).vnode_handle).is_some()
            {
                return Ok((*parent_vd).vnode_handle);
            }
            let (vh, vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
            (*vp).id = parent_id;
            (*vp).vtype = (*parent_vd).ftype;
            (*vp).data = parent_vd as *mut u8;
            (*vp).nlink = (*parent_vd).nlink;
            (*vp).mount = ctx.mount_handle;
            (*vp).ops = (*ctx.vnode).ops;
            (*parent_vd).vnode_handle = vh;
            return Ok(vh);
        }

        // Normal component lookup
        let ent = pool::dir_find_entry(dvd, name, name_len);
        if ent.is_null() {
            return Ok(VnodeHandle::INVALID);
        }

        let child_id = (*ent).ino as u64;
        let md = mdata(ctx);

        let child_vd = pool::find_vdata(md, child_id);
        if child_vd.is_null() {
            return Ok(VnodeHandle::INVALID);
        }
        if (*child_vd).vnode_handle.is_valid()
            && (ctx.resolve_vnode)((*child_vd).vnode_handle).is_some()
        {
            return Ok((*child_vd).vnode_handle);
        }

        let (vh, vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
        (*vp).id = child_id;
        (*vp).vtype = (*child_vd).ftype;
        (*vp).data = child_vd as *mut u8;
        (*vp).nlink = (*child_vd).nlink;
        (*vp).mount = ctx.mount_handle;
        (*vp).ops = (*ctx.vnode).ops;
        (*child_vd).vnode_handle = vh;
        Ok(vh)
    }
}

pub(super) unsafe fn tmpfs_create(
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
        let existing = pool::dir_find_entry(dvd, name, name_len);
        if !existing.is_null() {
            return Err(VfsError::Exists);
        }
        create_child(ctx, name, name_len, mode, VT_REG, cred)
    }
}

pub(super) unsafe fn tmpfs_mkdir(
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
        let existing = pool::dir_find_entry(dvd, name, name_len);
        if !existing.is_null() {
            return Err(VfsError::Exists);
        }
        create_child(ctx, name, name_len, mode, VT_DIR, cred)
    }
}

pub(super) unsafe fn tmpfs_symlink(
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
        let existing = pool::dir_find_entry(dvd, name, name_len);
        if !existing.is_null() {
            return Err(VfsError::Exists);
        }
        let mode = S_IFLNK_L | 0o777;
        let child_vh = create_child(ctx, name, name_len, mode, VT_LNK, cred)?;

        // Resolve the newly created child to set symlink data.
        let child_vp = (ctx.resolve_vnode)(child_vh).ok_or(VfsError::Io)? as *mut Vnode;
        let child_vd = (*child_vp).data as *mut TmpfsVnodeData;
        let md = mdata(ctx);
        let sym_ptr = pool::alloc_symlink(md, target, target_len);
        if sym_ptr.is_null() {
            (*child_vd).active = 0;
            pool::dir_remove_entry(dvd, name, name_len);
            pool::account_inode_sub(md);
            return Err(VfsError::NoSpace);
        }
        (*child_vd).symlink_data = sym_ptr;
        (*child_vd).size = target_len as u64;
        Ok(child_vh)
    }
}

pub(super) unsafe fn tmpfs_unlink(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let ent = pool::dir_find_entry(dvd, name, name_len);
        if ent.is_null() {
            return Err(VfsError::NotFound);
        }
        let child_id = (*ent).ino as u64;
        let md = mdata(ctx);

        let child_vd = pool::find_vdata(md, child_id);
        if !child_vd.is_null() {
            if (*child_vd).ftype == VT_DIR {
                return Err(VfsError::IsDir);
            }
            if (*child_vd).nlink > 0 {
                (*child_vd).nlink -= 1;
            }
            if (*child_vd).nlink == 0 {
                free_vdata_storage(md, child_vd);
                pool::account_inode_sub(md);
            }
        }

        pool::dir_remove_entry(dvd, name, name_len);
        Ok(())
    }
}

pub(super) unsafe fn tmpfs_rmdir(ctx: &VopContext, name: *const u8, name_len: u8) -> VfsResult<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let ent = pool::dir_find_entry(dvd, name, name_len);
        if ent.is_null() {
            return Err(VfsError::NotFound);
        }
        let child_id = (*ent).ino as u64;
        let md = mdata(ctx);
        let child_vd = pool::find_vdata(md, child_id);
        if child_vd.is_null() {
            return Err(VfsError::NotFound);
        }
        if (*child_vd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if !dir_is_empty(child_vd) {
            return Err(VfsError::Busy);
        }

        pool::dir_remove_entry(dvd, name, name_len);

        // Decrement parent nlink
        if (*dvd).nlink > 0 {
            (*dvd).nlink -= 1;
            (*ctx.vnode).nlink = (*dvd).nlink;
        }

        // Free the child directory
        (*child_vd).nlink = 0;
        free_vdata_storage(md, child_vd);
        pool::account_inode_sub(md);
        Ok(())
    }
}

pub(super) unsafe fn tmpfs_link(
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
        let target_vp = (ctx.resolve_vnode)(target).ok_or(VfsError::Inval)? as *mut Vnode;
        let tvd = (*target_vp).data as *mut TmpfsVnodeData;
        if tvd.is_null() {
            return Err(VfsError::Inval);
        }
        if (*tvd).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        let existing = pool::dir_find_entry(dvd, name, name_len);
        if !existing.is_null() {
            return Err(VfsError::Exists);
        }
        if pool::dir_add_entry(dvd, name, name_len, (*tvd).id) != 0 {
            return Err(VfsError::NoSpace);
        }
        (*tvd).nlink += 1;
        (*target_vp).nlink = (*tvd).nlink;
        Ok(())
    }
}

pub(super) unsafe fn tmpfs_rename(
    old_ctx: &VopContext,
    old_name: *const u8,
    old_len: u8,
    new_ctx: &VopContext,
    new_name: *const u8,
    new_len: u8,
) -> VfsResult<()> {
    unsafe {
        let old_dvd = vdata(old_ctx);
        let new_dvd = vdata(new_ctx);
        if old_dvd.is_null() || new_dvd.is_null() {
            return Err(VfsError::Inval);
        }

        // Find source entry
        let src_ent = pool::dir_find_entry(old_dvd, old_name, old_len);
        if src_ent.is_null() {
            return Err(VfsError::NotFound);
        }
        let child_id = (*src_ent).ino as u64;

        // Check if target name already exists — remove it
        let dst_ent = pool::dir_find_entry(new_dvd, new_name, new_len);
        if !dst_ent.is_null() {
            let md = mdata(old_ctx);
            let dst_id = (*dst_ent).ino as u64;
            let dst_vd = pool::find_vdata(md, dst_id);
            if !dst_vd.is_null() {
                if (*dst_vd).ftype == VT_DIR && !dir_is_empty(dst_vd) {
                    return Err(VfsError::Busy);
                }
                if (*dst_vd).nlink > 0 {
                    (*dst_vd).nlink -= 1;
                }
                if (*dst_vd).nlink == 0 {
                    free_vdata_storage(md, dst_vd);
                    pool::account_inode_sub(md);
                }
            }
            pool::dir_remove_entry(new_dvd, new_name, new_len);
        }

        // Remove from old parent
        pool::dir_remove_entry(old_dvd, old_name, old_len);

        // Add to new parent
        if pool::dir_add_entry(new_dvd, new_name, new_len, child_id) != 0 {
            // Try to restore — best effort
            let _ = pool::dir_add_entry(old_dvd, old_name, old_len, child_id);
            return Err(VfsError::NoSpace);
        }

        // Update parent_id if moved to a different directory
        let md = mdata(old_ctx);
        let child_vd = pool::find_vdata(md, child_id);
        if !child_vd.is_null() && (*old_ctx.vnode).id != (*new_ctx.vnode).id {
            (*child_vd).parent_id = (*new_ctx.vnode).id;
            if (*child_vd).ftype == VT_DIR {
                if (*old_dvd).nlink > 0 {
                    (*old_dvd).nlink -= 1;
                    (*old_ctx.vnode).nlink = (*old_dvd).nlink;
                }
                (*new_dvd).nlink += 1;
                (*new_ctx.vnode).nlink = (*new_dvd).nlink;
            }
        }

        Ok(())
    }
}

pub(super) unsafe fn tmpfs_open(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

pub(super) unsafe fn tmpfs_close(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

pub(super) unsafe fn tmpfs_getattr(ctx: &VopContext, attr: *mut VAttr) -> VfsResult<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        (*attr).size = (*vd).size;
        (*attr).blocks = ((*vd).size + 511) / 512;
        (*attr).mode = (*vd).mode;
        (*attr).uid = (*vd).uid;
        (*attr).gid = (*vd).gid;
        (*attr).nlink = (*vd).nlink;
        (*attr).atime = (*vd).atime;
        (*attr).mtime = (*vd).mtime;
        (*attr).ctime = (*vd).ctime;
        (*attr).btime = (*vd).btime;
        (*attr).dev_id = 0;
        (*attr).rdev = 0;
        Ok(())
    }
}

pub(super) unsafe fn tmpfs_setattr(ctx: &VopContext, attr: *const VAttr) -> VfsResult<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*attr).mode != 0 {
            (*vd).mode = (*attr).mode;
        }
        if (*attr).uid != u32::MAX {
            (*vd).uid = (*attr).uid;
        }
        if (*attr).gid != u32::MAX {
            (*vd).gid = (*attr).gid;
        }
        if (*attr).atime != 0 {
            (*vd).atime = (*attr).atime;
        }
        if (*attr).mtime != 0 {
            (*vd).mtime = (*attr).mtime;
        }
        if (*attr).ctime != 0 {
            (*vd).ctime = (*attr).ctime;
        }
        Ok(())
    }
}

pub(super) unsafe fn tmpfs_access(
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

pub(super) unsafe fn tmpfs_readlink(
    ctx: &VopContext,
    buf: *mut u8,
    buf_len: usize,
    _cred: *const crate::vfs_core::cred::VfsCred,
) -> VfsResult<usize> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype != VT_LNK {
            return Err(VfsError::Inval);
        }

        if !(*vd).symlink_data.is_null() {
            let len = (*vd).size as usize;
            let copy_len = if len < buf_len { len } else { buf_len };
            core::ptr::copy_nonoverlapping((*vd).symlink_data, buf, copy_len);
            return Ok(copy_len);
        }

        Err(VfsError::Io)
    }
}

pub(super) unsafe fn tmpfs_truncate(ctx: &VopContext, new_size: u64) -> VfsResult<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }

        let md = mdata(ctx);
        let old_size = (*vd).size;

        if new_size < old_size {
            // Shrinking — free blocks and account bytes
            if (*vd).writable_head != INVALID_WRITABLE_SLOT {
                pool::chain_truncate(md, (*vd).writable_head, new_size);
            }
            pool::account_bytes_sub(md, old_size - new_size);
        } else if new_size > old_size {
            // Extending — check size limit
            let growth = new_size - old_size;
            if !pool::check_bytes(md, growth) {
                return Err(VfsError::NoSpace);
            }
            if (*vd).writable_head == INVALID_WRITABLE_SLOT {
                let slot = pool::alloc_writable(md);
                if slot == INVALID_WRITABLE_SLOT {
                    return Err(VfsError::NoSpace);
                }
                (*vd).writable_head = slot;
            }
            pool::account_bytes_add(md, growth);
        }

        (*vd).size = new_size;
        Ok(())
    }
}

pub(super) unsafe fn tmpfs_inactive(ctx: &VopContext) {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return;
        }
        if (*vd).nlink == 0 {
            let md = mdata(ctx);
            free_vdata_storage(md, vd);
            pool::account_inode_sub(md);
        }
        (*ctx.vnode).data = core::ptr::null_mut();
    }
}

// =========================================================================
// DataOps function implementations
// =========================================================================

pub(super) unsafe fn tmpfs_read(
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

        let size = (*vd).size;
        if offset >= size {
            return Ok(0);
        }
        let avail = size - offset;
        let count = if len < avail { len } else { avail };

        let md = mdata_d(ctx);
        let read = pool::chain_read(md, (*vd).writable_head, offset, dst, count);
        Ok(read)
    }
}

pub(super) unsafe fn tmpfs_write(
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

        // Check size limit
        let old_size = (*vd).size;
        let end = offset + len;
        if end > old_size {
            let growth = end - old_size;
            if !pool::check_bytes(md, growth) {
                return Err(VfsError::NoSpace);
            }
        }

        if (*vd).writable_head == INVALID_WRITABLE_SLOT {
            let slot = pool::alloc_writable(md);
            if slot == INVALID_WRITABLE_SLOT {
                return Err(VfsError::NoSpace);
            }
            (*vd).writable_head = slot;
        }

        let written = pool::chain_write(md, (*vd).writable_head, offset, src, len);
        if written == 0 && len > 0 {
            return Err(VfsError::NoSpace);
        }

        let new_end = offset + written;
        if new_end > old_size {
            let growth = new_end - old_size;
            pool::account_bytes_add(md, growth);
            (*vd).size = new_end;
        }

        Ok(written)
    }
}

pub(super) unsafe fn tmpfs_fsync(_ctx: &VopDataContext) -> VfsResult<()> {
    Ok(())
}

pub(super) unsafe fn tmpfs_readdir(
    ctx: &VopDataContext,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VfsResult<()> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() || (*vd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }

        let start = *cookie as usize;
        let attr = VAttr::zeroed();
        let md = mdata_d(ctx);

        // Emit "." and ".."
        if start == 0 {
            if !emit((*vd).id, b".".as_ptr(), 1, 4, &attr) {
                *cookie = 1;
                return Ok(());
            }
        }
        if start <= 1 {
            let parent_id = if (*vd).parent_id != 0 {
                (*vd).parent_id
            } else {
                (*vd).id
            };
            if !emit(parent_id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = 2;
                return Ok(());
            }
        }

        // Real entries start at cookie index 2
        let real_start = if start > 2 { start - 2 } else { 0 };
        let mut idx = 0usize;
        for i in 0..(*vd).dirents_cap as usize {
            let ent = (*vd).dirents.add(i);
            if (*ent).active == 0 {
                continue;
            }
            if idx < real_start {
                idx += 1;
                continue;
            }
            let child_id = (*ent).ino as u64;
            let child_vd = pool::find_vdata(md, child_id);
            let dtype = if !child_vd.is_null() {
                vtype_to_dtype((*child_vd).ftype)
            } else {
                0
            };
            if !emit(
                child_id,
                (*ent).name.as_ptr(),
                (*ent).name_len,
                dtype,
                &attr,
            ) {
                *cookie = (idx + 3) as u64;
                return Ok(());
            }
            idx += 1;
        }

        *cookie = (idx + 2) as u64;
        Ok(())
    }
}

pub(super) unsafe fn tmpfs_statfs(ctx: &VopDataContext, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = mdata_d(ctx);

        (*out).bsize = WRITABLE_SIZE as u64;
        (*out).name_max = MAX_NAME_LEN as u32;
        let ft = &mut (*out).fs_type;
        ft[..5].copy_from_slice(b"tmpfs");
        (*out).flags = 0;

        (*out).files = (*md).used_inodes as u64;
        if (*md).max_inodes > 0 {
            (*out).ffree = ((*md).max_inodes - (*md).used_inodes) as u64;
        } else {
            (*out).ffree = (*md).vdata_cap as u64 - (*md).used_inodes as u64;
        }

        if (*md).max_bytes > 0 {
            (*out).blocks = (*md).max_bytes / WRITABLE_SIZE as u64;
            let used_blocks = (*md).used_bytes / WRITABLE_SIZE as u64;
            (*out).bfree = (*out).blocks - used_blocks;
            (*out).bavail = (*out).bfree;
        } else {
            let mut used_blocks: u64 = 0;
            for i in 0..(*md).writable_cap {
                if *(*md).writable_used_ptr.add(i) != 0 {
                    used_blocks += 1;
                }
            }
            (*out).blocks = (*md).writable_cap as u64;
            (*out).bfree = (*md).writable_cap as u64 - used_blocks;
            (*out).bavail = (*out).bfree;
        }

        Ok(())
    }
}

// =========================================================================
// Internal helpers
// =========================================================================

/// Check whether a directory has any active entries.
unsafe fn dir_is_empty(vd: *mut TmpfsVnodeData) -> bool {
    unsafe {
        for i in 0..(*vd).dirents_cap as usize {
            if (*(*vd).dirents.add(i)).active != 0 {
                return false;
            }
        }
        true
    }
}

/// Free storage associated with a vnode-data entry (chain, symlink, etc.).
unsafe fn free_vdata_storage(md: *mut super::types::TmpfsMountData, vd: *mut TmpfsVnodeData) {
    unsafe {
        let old_size = (*vd).size;

        if (*vd).ftype == VT_LNK {
            pool::free_symlink(md, (*vd).symlink_data);
            (*vd).symlink_data = core::ptr::null_mut();
        } else {
            pool::free_chain(md, (*vd).writable_head);
            (*vd).writable_head = INVALID_WRITABLE_SLOT;
        }

        // Account for freed bytes
        if old_size > 0 && (*vd).ftype != VT_LNK {
            pool::account_bytes_sub(md, old_size);
        }

        (*vd).size = 0;
        (*vd).active = 0;
    }
}
