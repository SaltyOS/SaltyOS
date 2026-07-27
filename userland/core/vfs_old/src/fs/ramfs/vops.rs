// SPDX-License-Identifier: GPL-2.0-only
//! Ramfs VopVector implementation — vnode-level operations.

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::outcome::{Parked, Ready, VopOutcome};
use crate::vfs_core::vnode::{VT_CHR, VT_DIR, VT_LNK, VT_REG, Vnode, VnodeHandle};
use crate::vfs_core::vop::ReaddirEmit;
use crate::vfs_core::vop_context::{OwnerVopCtx, WorkerIoCtx};

use super::pool;
use super::types::RamfsMountData;

use trona_kernel::core_types::TronaMsg;

// =========================================================================
// Helpers
// =========================================================================

/// Get the `RamfsMountData` from a VopContext's mount_data pointer.
#[inline]
unsafe fn mdata(ctx: &OwnerVopCtx<'_>) -> *mut RamfsMountData {
    ctx.mount_data as *mut RamfsMountData
}

/// Get the `RamfsMountData` from a WorkerIoCtx's mount_data pointer.
#[inline]
unsafe fn mdata_d(ctx: &WorkerIoCtx) -> *mut RamfsMountData {
    ctx.mount_data as *mut RamfsMountData
}

/// Get the `super::types::RamfsVnodeData` from a VopContext's data pointer.
#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut super::types::RamfsVnodeData {
    ctx.data as *mut super::types::RamfsVnodeData
}

/// Get the `super::types::RamfsVnodeData` from a WorkerIoCtx's data pointer.
#[inline]
unsafe fn vdata_d(ctx: &WorkerIoCtx) -> *mut super::types::RamfsVnodeData {
    ctx.data as *mut super::types::RamfsVnodeData
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
unsafe fn create_child(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    mode: u32,
    ftype: u8,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let md = mdata(ctx);
        let parent_vd = vdata(ctx);
        let parent_id = (*ctx.vnode).id;

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
        let (child_vh, child_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        (*child_vp).id = id;
        (*child_vp).vtype = ftype;
        (*child_vp).data = vd as *mut u8;
        (*child_vp).nlink = (*vd).nlink;
        (*child_vp)
            .mount
            .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
        (*child_vp).fs_instance_id = (*ctx.mount).fs_instance_id;
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

        Ok(Ready(child_vh))
    }
}

// =========================================================================
// MetaOps function implementations
// =========================================================================

pub(super) unsafe fn ramfs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }

        // Handle "."
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }

        // Handle ".."
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            let parent_id = (*dvd).parent_id;
            if parent_id == 0 {
                // Root — ".." is self
                return Ok(Ready(ctx.handle));
            }
            let md = mdata(ctx);
            let parent_vd = pool::find_vdata(md, parent_id);
            if parent_vd.is_null() {
                return Ok(Ready(VnodeHandle::INVALID));
            }
            if (*parent_vd).vnode_handle.is_valid()
                && ctx.resolve_vnode((*parent_vd).vnode_handle).is_some()
            {
                return Ok(Ready((*parent_vd).vnode_handle));
            }
            // The parent vnode must be found via the arena — we search by id.
            // The dispatch layer maps VnodeHandle back to the vnode; we need
            // to find the handle for parent_id. Use vget-style allocation.
            let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
            (*vp).id = parent_id;
            (*vp).vtype = (*parent_vd).ftype;
            (*vp).data = parent_vd as *mut u8;
            (*vp).nlink = (*parent_vd).nlink;
            (*vp)
                .mount
                .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
            (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
            (*vp).ops = (*ctx.vnode).ops;
            (*parent_vd).vnode_handle = vh;
            return Ok(Ready(vh));
        }

        // Normal component lookup
        let ent = pool::dir_find_entry(dvd, name, name_len);
        if ent.is_null() {
            return Ok(Ready(VnodeHandle::INVALID));
        }

        let child_id = (*ent).ino as u64;
        let md = mdata(ctx);

        // Find the vnode data
        let child_vd = pool::find_vdata(md, child_id);
        if child_vd.is_null() {
            return Ok(Ready(VnodeHandle::INVALID));
        }

        if (*child_vd).vnode_handle.is_valid()
            && ctx.resolve_vnode((*child_vd).vnode_handle).is_some()
        {
            return Ok(Ready((*child_vd).vnode_handle));
        }

        // Allocate a vnode from the arena
        let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        (*vp).id = child_id;
        (*vp).vtype = (*child_vd).ftype;
        (*vp).data = child_vd as *mut u8;
        (*vp).nlink = (*child_vd).nlink;
        (*vp)
            .mount
            .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
        (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vp).ops = (*ctx.vnode).ops;
        (*child_vd).vnode_handle = vh;
        Ok(Ready(vh))
    }
}

pub(super) unsafe fn ramfs_create(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if (*dvd).readonly != 0 {
            return Err(VfsError::ReadOnly);
        }
        // Check for existing entry
        let existing = pool::dir_find_entry(dvd, name, name_len);
        if !existing.is_null() {
            return Err(VfsError::Exists);
        }
        create_child(ctx, name, name_len, mode, VT_REG, cred)
    }
}

pub(super) unsafe fn ramfs_mkdir(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if (*dvd).readonly != 0 {
            return Err(VfsError::ReadOnly);
        }
        let existing = pool::dir_find_entry(dvd, name, name_len);
        if !existing.is_null() {
            return Err(VfsError::Exists);
        }
        create_child(ctx, name, name_len, mode, VT_DIR, cred)
    }
}

pub(super) unsafe fn ramfs_symlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    target: *const u8,
    target_len: u8,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if (*dvd).readonly != 0 {
            return Err(VfsError::ReadOnly);
        }
        let existing = pool::dir_find_entry(dvd, name, name_len);
        if !existing.is_null() {
            return Err(VfsError::Exists);
        }
        let mode = S_IFLNK_L | 0o777;
        let child_vh = create_child(ctx, name, name_len, mode, VT_LNK, cred)?;

        // Resolve the child's vdata to store the symlink target.
        // create_child incremented next_id, so the child's id is next_id - 1.
        let md = mdata(ctx);
        let child_id = (*md).next_id - 1;
        let child_vd = pool::find_vdata(md, child_id);
        if child_vd.is_null() {
            return Err(VfsError::Io);
        }

        let sym_ptr = pool::alloc_symlink(md, target, target_len);
        if sym_ptr.is_null() {
            // Roll back
            (*child_vd).active = 0;
            pool::dir_remove_entry(dvd, name, name_len);
            return Err(VfsError::NoSpace);
        }
        (*child_vd).symlink_data = sym_ptr;
        (*child_vd).size = target_len as u64;
        Ok(child_vh)
    }
}

pub(super) unsafe fn ramfs_unlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if (*dvd).readonly != 0 {
            return Err(VfsError::ReadOnly);
        }
        let ent = pool::dir_find_entry(dvd, name, name_len);
        if ent.is_null() {
            return Err(VfsError::NotFound);
        }
        let child_id = (*ent).ino as u64;
        let md = mdata(ctx);

        // Find child vdata to check type and decrement nlink
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
            }
        }

        pool::dir_remove_entry(dvd, name, name_len);
        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_rmdir(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if (*dvd).readonly != 0 {
            return Err(VfsError::ReadOnly);
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
        // Check directory is empty
        if !dir_is_empty(child_vd) {
            return Err(VfsError::Busy);
        }

        pool::dir_remove_entry(dvd, name, name_len);

        // Decrement parent nlink
        let parent_vd = vdata(ctx);
        if (*parent_vd).nlink > 0 {
            (*parent_vd).nlink -= 1;
            (*ctx.vnode).nlink = (*parent_vd).nlink;
        }

        // Free the child directory
        (*child_vd).nlink = 0;
        free_vdata_storage(md, child_vd);
        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_link(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    target: VnodeHandle,
) -> VopOutcome<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if (*dvd).readonly != 0 {
            return Err(VfsError::ReadOnly);
        }

        // Resolve target vnode via the context's resolve callback.
        let target_vp = ctx.resolve_vnode(target).ok_or(VfsError::Inval)? as *mut Vnode;
        let target_id = (*target_vp).id;

        let md = mdata(ctx);
        let tvd = pool::find_vdata(md, target_id);
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
        if pool::dir_add_entry(dvd, name, name_len, target_id) != 0 {
            return Err(VfsError::NoSpace);
        }
        (*tvd).nlink += 1;
        (*target_vp).nlink = (*tvd).nlink;
        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_rename(
    ctx: &mut OwnerVopCtx<'_>,
    old_name: *const u8,
    old_len: u8,
    new_dir: VnodeHandle,
    new_name: *const u8,
    new_len: u8,
) -> VopOutcome<()> {
    unsafe {
        // Cross-mount rename is rejected before this entry fires, so the
        // new parent lives on the same mount as `ctx` and shares
        // `ctx.mount_data`.
        let new_vnode = ctx.resolve_vnode(new_dir).ok_or(VfsError::Inval)? as *mut Vnode;
        let new_dvd = (*new_vnode).data as *mut super::types::RamfsVnodeData;

        let old_dvd = vdata(ctx);
        if old_dvd.is_null() || new_dvd.is_null() {
            return Err(VfsError::Inval);
        }
        if (*old_dvd).readonly != 0 || (*new_dvd).readonly != 0 {
            return Err(VfsError::ReadOnly);
        }

        let src_ent = pool::dir_find_entry(old_dvd, old_name, old_len);
        if src_ent.is_null() {
            return Err(VfsError::NotFound);
        }
        let child_id = (*src_ent).ino as u64;

        let dst_ent = pool::dir_find_entry(new_dvd, new_name, new_len);
        if !dst_ent.is_null() {
            let md = mdata(ctx);
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
                }
            }
            pool::dir_remove_entry(new_dvd, new_name, new_len);
        }

        pool::dir_remove_entry(old_dvd, old_name, old_len);

        if pool::dir_add_entry(new_dvd, new_name, new_len, child_id) != 0 {
            let _ = pool::dir_add_entry(old_dvd, old_name, old_len, child_id);
            return Err(VfsError::NoSpace);
        }

        let md = mdata(ctx);
        let old_id = (*ctx.vnode).id;
        let new_id = (*new_vnode).id;
        let child_vd = pool::find_vdata(md, child_id);
        if !child_vd.is_null() && old_id != new_id {
            (*child_vd).parent_id = new_id;
            if (*child_vd).ftype == VT_DIR {
                if (*old_dvd).nlink > 0 {
                    (*old_dvd).nlink -= 1;
                    (*ctx.vnode).nlink = (*old_dvd).nlink;
                }
                (*new_dvd).nlink += 1;
                (*new_vnode).nlink = (*new_dvd).nlink;
            }
        }

        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_open(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(super) unsafe fn ramfs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(super) unsafe fn ramfs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
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
        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_setattr(
    ctx: &mut OwnerVopCtx<'_>,
    attr: *const VAttr,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        // Only update non-zero fields (sparse update pattern)
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
        // Size changes go through truncate, not setattr
        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_access(
    ctx: &mut OwnerVopCtx<'_>,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<()> {
    unsafe {
        if cred.is_null() {
            return Ok(Ready(()));
        }
        // Root bypasses permission checks
        if (*cred).euid == 0 {
            return Ok(Ready(()));
        }
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }

        let file_mode = (*vd).mode;
        let uid = (*vd).uid;
        let gid = (*vd).gid;

        // Determine which permission bits to check (owner/group/other)
        let shift = if (*cred).euid == uid {
            6 // owner
        } else if (*cred).in_group(gid) {
            3 // group
        } else {
            0 // other
        };

        let perm = (file_mode >> shift) & 0o7;

        // ACCESS_READ = 1, ACCESS_WRITE = 2, ACCESS_EXEC = 4
        if (mode & 1) != 0 && (perm & 4) == 0 {
            return Err(VfsError::Perm);
        }
        if (mode & 2) != 0 && (perm & 2) == 0 {
            return Err(VfsError::Perm);
        }
        if (mode & 4) != 0 && (perm & 1) == 0 {
            return Err(VfsError::Perm);
        }

        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_readlink(
    ctx: &mut OwnerVopCtx<'_>,
    buf: *mut u8,
    buf_len: usize,
    _cred: *const VfsCred,
) -> VopOutcome<usize> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype != VT_LNK {
            return Err(VfsError::Inval);
        }

        // Try symlink_data first (writable symlinks)
        if !(*vd).symlink_data.is_null() {
            let len = (*vd).size as usize;
            let copy_len = if len < buf_len { len } else { buf_len };
            core::ptr::copy_nonoverlapping((*vd).symlink_data, buf, copy_len);
            return Ok(Ready(copy_len));
        }

        // Fall back to ro_data (initrd symlinks)
        if !(*vd).ro_data.is_null() {
            let len = (*vd).ro_len as usize;
            let copy_len = if len < buf_len { len } else { buf_len };
            core::ptr::copy_nonoverlapping((*vd).ro_data, buf, copy_len);
            return Ok(Ready(copy_len));
        }

        Err(VfsError::Io)
    }
}

pub(super) unsafe fn ramfs_truncate(ctx: &mut OwnerVopCtx<'_>, new_size: u64) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).readonly != 0 {
            let md = mdata(ctx);
            match cow_promote(md, vd)? {
                Ready(true) => {}
                Ready(false) => return Err(VfsError::NoSpace),
                Parked(h) => return Ok(Parked(h)),
            }
        }

        let md = mdata(ctx);
        if new_size < (*vd).size && (*vd).writable_head != INVALID_WRITABLE_SLOT {
            pool::chain_truncate(md, (*vd).writable_head, new_size);
        } else if new_size > (*vd).size {
            // Extending — ensure chain exists
            if (*vd).writable_head == INVALID_WRITABLE_SLOT {
                let slot = pool::alloc_writable(md);
                if slot == INVALID_WRITABLE_SLOT {
                    return Err(VfsError::NoSpace);
                }
                (*vd).writable_head = slot;
            }
        }

        (*vd).size = new_size;
        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Ok(Ready(()));
        }
        // If nlink == 0, free the backing storage
        if (*vd).nlink == 0 {
            let md = mdata(ctx);
            free_vdata_storage(md, vd);
        }
        // Detach data pointer
        (*ctx.vnode).data = core::ptr::null_mut();
        Ok(Ready(()))
    }
}

// =========================================================================
// DataOps function implementations
// =========================================================================

pub(super) unsafe fn ramfs_read(
    ctx: &WorkerIoCtx,
    offset: u64,
    dst: *mut u8,
    len: u64,
) -> VopOutcome<u64> {
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
            return Ok(Ready(0));
        }
        let avail = size - offset;
        let count = if len < avail { len } else { avail };

        // Read-only data (initrd zero-copy)
        if !(*vd).ro_data.is_null() && (*vd).writable_head == INVALID_WRITABLE_SLOT {
            if offset + count > (*vd).ro_len {
                return Ok(Ready(0));
            }
            core::ptr::copy_nonoverlapping((*vd).ro_data.add(offset as usize), dst, count as usize);
            return Ok(Ready(count));
        }

        // Writable chain
        let md = mdata_d(ctx);
        let read = pool::chain_read(md, (*vd).writable_head, offset, dst, count);
        Ok(Ready(read))
    }
}

pub(super) unsafe fn ramfs_write(
    ctx: &WorkerIoCtx,
    offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        if (*vd).readonly != 0 {
            let md = mdata_d(ctx);
            match cow_promote(md, vd)? {
                Ready(true) => {}
                Ready(false) => return Err(VfsError::NoSpace),
                Parked(h) => return Ok(Parked(h)),
            }
        }

        let md = mdata_d(ctx);
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

        let end = offset + written;
        if end > (*vd).size {
            (*vd).size = end;
        }

        Ok(Ready(written))
    }
}

pub(super) unsafe fn ramfs_fsync(_ctx: &WorkerIoCtx) -> VopOutcome<()> {
    // In-memory — nothing to sync.
    Ok(Ready(()))
}

pub(super) unsafe fn ramfs_readdir(
    ctx: &WorkerIoCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() || (*vd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }

        let start = *cookie as usize;
        let attr = VAttr::zeroed();
        let md = mdata_d(ctx);
        let mut emitted = 0usize;

        // Emit "." and ".."
        if start == 0 {
            if !emit((*vd).id, b".".as_ptr(), 1, 4, &attr) {
                *cookie = 1;
                return Ok(Ready(()));
            }
            emitted += 1;
        }
        if start <= 1 {
            let parent_id = if (*vd).parent_id != 0 {
                (*vd).parent_id
            } else {
                (*vd).id
            };
            if !emit(parent_id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = 2;
                return Ok(Ready(()));
            }
            emitted += 1;
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
            // Look up child vdata to get dtype
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
                return Ok(Ready(()));
            }
            idx += 1;
        }

        *cookie = (idx + 2) as u64;
        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_statfs(ctx: &WorkerIoCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        (*out).bsize = WRITABLE_SIZE as u64;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = 0;
        (*out).ffree = 0;
        let ft = &mut (*out).fs_type;
        ft[..5].copy_from_slice(b"ramfs");
        (*out).flags = 0;
        (*out).name_max = MAX_NAME_LEN as u32;

        // Count active vnodes and writable blocks
        let md = mdata_d(ctx);
        let mut files: u64 = 0;
        for i in 0..(*md).vdata_cap {
            if (*(*md).vdata_ptr.add(i)).active != 0 {
                files += 1;
            }
        }
        let mut used_blocks: u64 = 0;
        for i in 0..(*md).writable_cap {
            if *(*md).writable_used_ptr.add(i) != 0 {
                used_blocks += 1;
            }
        }
        (*out).files = files;
        (*out).blocks = (*md).writable_cap as u64;
        (*out).bfree = (*md).writable_cap as u64 - used_blocks;
        (*out).bavail = (*out).bfree;
        Ok(Ready(()))
    }
}

// =========================================================================
// Internal helpers
// =========================================================================

/// Check whether a directory has any active entries.
unsafe fn dir_is_empty(vd: *mut super::types::RamfsVnodeData) -> bool {
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
unsafe fn free_vdata_storage(md: *mut RamfsMountData, vd: *mut super::types::RamfsVnodeData) {
    unsafe {
        if (*vd).ftype == VT_LNK {
            pool::free_symlink(md, (*vd).symlink_data);
            (*vd).symlink_data = core::ptr::null_mut();
        } else {
            pool::free_chain(md, (*vd).writable_head);
            (*vd).writable_head = INVALID_WRITABLE_SLOT;
        }
        (*vd).ro_data = core::ptr::null();
        (*vd).ro_len = 0;
        (*vd).active = 0;
    }
}

/// Copy-on-write promotion: convert a read-only file (ro_data) to a
/// writable block chain. Returns `Ok(Ready(true))` if promotion succeeded or
/// was unnecessary, `Ok(Ready(false))` if allocation failed.
unsafe fn cow_promote(
    md: *mut RamfsMountData,
    vd: *mut super::types::RamfsVnodeData,
) -> VopOutcome<bool> {
    unsafe {
        if (*vd).readonly == 0 {
            return Ok(Ready(true));
        }

        (*vd).readonly = 0;

        if (*vd).ro_data.is_null() || (*vd).ro_len == 0 {
            (*vd).ro_data = core::ptr::null();
            (*vd).ro_len = 0;
            return Ok(Ready(true));
        }

        // Allocate writable chain and copy ro_data
        let first_slot = pool::alloc_writable(md);
        if first_slot == INVALID_WRITABLE_SLOT {
            (*vd).readonly = 1;
            return Ok(Ready(false));
        }
        (*vd).writable_head = first_slot;

        let written = pool::chain_write(md, first_slot, 0, (*vd).ro_data, (*vd).ro_len);
        if written < (*vd).ro_len {
            // Partial write — keep what we have, update size
            (*vd).size = written;
        }

        (*vd).ro_data = core::ptr::null();
        (*vd).ro_len = 0;
        Ok(Ready(true))
    }
}
