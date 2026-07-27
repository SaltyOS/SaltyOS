// SPDX-License-Identifier: GPL-2.0-only
//
//! Tmpfs `VopVector` — vnode-level operations.
//!
//! Same shape as ramfs but with quota accounting on every mutation
//! (`pool::check_inodes` / `pool::account_inode_*` / `check_bytes` /
//! `account_bytes_*`). Truncate / write extend account for the
//! delta against `used_bytes`; unlink / rmdir / inactive return the
//! freed bytes to the pool.

use crate::core::cred::VfsCred;
use crate::core::error::VfsError;
use crate::core::file::{MODE_TYPE_DIR, MODE_TYPE_LNK, MODE_TYPE_REG};
use crate::core::file::{VAttr, VStatfs};
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::outcome::{Parked, Ready, VopOutcome};
use crate::core::vnode::{VT_CHR, VT_DIR, VT_LNK, VT_REG, Vnode, VnodeHandle, vtype_to_kind};
use crate::core::vop::ReaddirEmit;
use crate::core::vop_context::{OwnerVopCtx, VopDataCtx};
use crate::server::alloc::vfs_alloc_array;
use crate::server::consts::{INITIAL_DIRENTS, INVALID_WRITABLE_SLOT, MAX_NAME_LEN, WRITABLE_SIZE};

use super::pool;
use super::types::{Dirent, TmpfsMountData, TmpfsVnodeData};

#[inline]
unsafe fn mdata(ctx: &OwnerVopCtx<'_>) -> *mut TmpfsMountData {
    ctx.mount_data as *mut TmpfsMountData
}

#[inline]
unsafe fn mdata_d(ctx: &VopDataCtx) -> *mut TmpfsMountData {
    ctx.mount_data as *mut TmpfsMountData
}

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut TmpfsVnodeData {
    ctx.data as *mut TmpfsVnodeData
}

#[inline]
unsafe fn casefold_enabled(ctx: &OwnerVopCtx<'_>) -> bool {
    unsafe {
        !ctx.mount.is_null()
            && matches!(
                (*ctx.mount).case_fold,
                crate::ops::CaseFoldPolicy::InsensitivePreserving
            )
    }
}

#[inline]
unsafe fn dir_find_entry_for_mount(
    ctx: &OwnerVopCtx<'_>,
    dir_vdata: *mut TmpfsVnodeData,
    name: *const u8,
    name_len: u8,
) -> *mut Dirent {
    unsafe {
        if casefold_enabled(ctx) {
            pool::dir_find_entry_ci(dir_vdata, name, name_len)
        } else {
            pool::dir_find_entry(dir_vdata, name, name_len)
        }
    }
}

/// Cached file size in bytes for the tmpfs vnode (`(*vdata).size`).
/// Owner-thread synchronous; updated on `tmpfs_create`,
/// `tmpfs_truncate`, `tmpfs_write`, and `tmpfs_setattr`.
pub(crate) unsafe fn tmpfs_data_size(ctx: &mut OwnerVopCtx<'_>) -> u64 {
    let vd = unsafe { vdata(&*ctx) };
    if vd.is_null() {
        0
    } else {
        unsafe { (*vd).size }
    }
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataCtx) -> *mut TmpfsVnodeData {
    ctx.data as *mut TmpfsVnodeData
}

#[inline]
fn vtype_to_dtype_local(vtype: u8) -> u8 {
    match vtype {
        x if x == VT_REG => 8,
        x if x == VT_DIR => 4,
        x if x == VT_LNK => 10,
        x if x == VT_CHR => 2,
        _ => 0,
    }
}

#[inline]
fn mode_type_for_vtype(vtype: u8) -> u32 {
    match vtype {
        x if x == VT_REG => MODE_TYPE_REG,
        x if x == VT_DIR => MODE_TYPE_DIR,
        x if x == VT_LNK => MODE_TYPE_LNK,
        _ => 0,
    }
}

/// Allocate a fresh vnode + vdata pair, register the dirent on the
/// parent, and add an inode to the quota counter. Used by `create`
/// / `mkdir` / `symlink`.
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
        let parent_id = (*ctx.vnode).id();

        if !pool::check_inodes(md) {
            return Err(VfsError::NoMem);
        }

        let vdata = pool::alloc_vdata(md);
        if vdata.is_null() {
            return Err(VfsError::NoMem);
        }
        let id = pool::next_id(md);
        (*vdata).id = id;
        (*vdata).parent_id = parent_id;
        (*vdata).ftype = ftype;
        (*vdata).mode = mode_type_for_vtype(ftype) | (mode & 0o7777);
        (*vdata).nlink = if ftype == VT_DIR { 2 } else { 1 };
        (*vdata).size = 0;
        if !cred.is_null() {
            (*vdata).uid = (*cred).euid;
            (*vdata).gid = (*cred).egid;
        }

        if ftype == VT_DIR {
            let dirents = vfs_alloc_array::<Dirent>(INITIAL_DIRENTS);
            if dirents.is_null() {
                (*vdata).active = 0;
                return Err(VfsError::NoMem);
            }
            (*vdata).dirents = dirents;
            (*vdata).dirents_cap = INITIAL_DIRENTS as u16;
        }

        let (child_vh, child_vp) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let fs_id = (*ctx.mount).fs_instance_id;
        (*child_vp).kind = vtype_to_kind(ftype);
        (*child_vp).key = VnodeKey {
            fs_instance_id: fs_id,
            backend_id: BackendNodeId::new(id, 0),
        };
        (*child_vp).backend_seq = 0;
        (*child_vp).data = vdata as *mut u8;
        (*child_vp).nlink = (*vdata).nlink;
        (*child_vp).mount = ctx.mount_handle;
        (*child_vp).fs_instance_id = fs_id;
        (*child_vp).ops = (*ctx.vnode).ops;
        (*vdata).vnode_handle = child_vh;

        if pool::dir_add_entry(parent_vd, name, name_len, id) != 0 {
            (*vdata).active = 0;
            return Err(VfsError::NoMem);
        }

        if ftype == VT_DIR {
            (*parent_vd).nlink += 1;
            (*ctx.vnode).nlink = (*parent_vd).nlink;
        }

        pool::account_inode_add(md);
        Ok(Ready(child_vh))
    }
}

unsafe fn dir_is_empty(vdata: *mut TmpfsVnodeData) -> bool {
    unsafe {
        for i in 0..(*vdata).dirents_cap as usize {
            if (*(*vdata).dirents.add(i)).active != 0 {
                return false;
            }
        }
        true
    }
}

/// Tear down per-vnode storage on link-count-zero release. Tracks
/// the freed bytes against the mount's `used_bytes` counter.
unsafe fn free_vdata_storage(md: *mut TmpfsMountData, vdata: *mut TmpfsVnodeData) {
    unsafe {
        let old_size = (*vdata).size;
        if (*vdata).ftype == VT_LNK {
            pool::free_symlink(md, (*vdata).symlink_data);
            (*vdata).symlink_data = ::core::ptr::null_mut();
        } else {
            pool::free_chain(md, (*vdata).writable_head);
            (*vdata).writable_head = INVALID_WRITABLE_SLOT;
        }
        if old_size > 0 && (*vdata).ftype != VT_LNK {
            pool::account_bytes_sub(md, old_size);
        }
        (*vdata).size = 0;
        (*vdata).active = 0;
    }
}

unsafe fn intern_vnode(ctx: &mut OwnerVopCtx<'_>, child_id: u64) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let md = mdata(ctx);
        let child_vd = pool::find_vdata(md, child_id);
        if child_vd.is_null() {
            return Ok(VnodeHandle::INVALID);
        }
        // Active-only liveness: a Retired slot (closed but not yet reclaimed)
        // must NOT be reused here — its open_refcount can no longer be bumped
        // (get_mut is Active-only), so a reclaim sweep would free it under an
        // open fd. `raw_ptr`/`resolve_vnode` accept Retired, so use `get`.
        if (*child_vd).vnode_handle.is_valid()
            && ctx.state.vnodes.get((*child_vd).vnode_handle).is_some()
        {
            return Ok((*child_vd).vnode_handle);
        }
        let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let fs_id = (*ctx.mount).fs_instance_id;
        (*vnode_ptr).kind = vtype_to_kind((*child_vd).ftype);
        (*vnode_ptr).key = VnodeKey {
            fs_instance_id: fs_id,
            backend_id: BackendNodeId::new(child_id, 0),
        };
        (*vnode_ptr).backend_seq = 0;
        (*vnode_ptr).data = child_vd as *mut u8;
        (*vnode_ptr).nlink = (*child_vd).nlink;
        (*vnode_ptr).mount = ctx.mount_handle;
        (*vnode_ptr).fs_instance_id = fs_id;
        (*vnode_ptr).ops = (*ctx.vnode).ops;
        (*child_vd).vnode_handle = vnode_h;
        Ok(vnode_h)
    }
}

// =========================================================================
// MetaOps
// =========================================================================

pub(crate) unsafe fn tmpfs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            let parent_id = (*dir_vdata).parent_id;
            if parent_id == 0 {
                return Ok(Ready(ctx.handle));
            }
            return Ok(Ready(intern_vnode(ctx, parent_id)?));
        }
        let ent = pool::dir_find_entry(dir_vdata, name, name_len);
        if ent.is_null() {
            return Ok(Ready(VnodeHandle::INVALID));
        }
        let child_id = (*ent).ino as u64;
        Ok(Ready(intern_vnode(ctx, child_id)?))
    }
}

pub(crate) unsafe fn tmpfs_lookup_ci(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            let parent_id = (*dir_vdata).parent_id;
            if parent_id == 0 {
                return Ok(Ready(ctx.handle));
            }
            return Ok(Ready(intern_vnode(ctx, parent_id)?));
        }
        let ent = pool::dir_find_entry_ci(dir_vdata, name, name_len);
        if ent.is_null() {
            return Ok(Ready(VnodeHandle::INVALID));
        }
        let child_id = (*ent).ino as u64;
        Ok(Ready(intern_vnode(ctx, child_id)?))
    }
}

pub(crate) unsafe fn tmpfs_create(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if !dir_find_entry_for_mount(ctx, dir_vdata, name, name_len).is_null() {
            return Err(VfsError::Exist);
        }
        create_child(ctx, name, name_len, mode, VT_REG, cred)
    }
}

pub(crate) unsafe fn tmpfs_mkdir(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if !dir_find_entry_for_mount(ctx, dir_vdata, name, name_len).is_null() {
            return Err(VfsError::Exist);
        }
        create_child(ctx, name, name_len, mode, VT_DIR, cred)
    }
}

pub(crate) unsafe fn tmpfs_symlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    target: *const u8,
    target_len: u8,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if !dir_find_entry_for_mount(ctx, dir_vdata, name, name_len).is_null() {
            return Err(VfsError::Exist);
        }
        let mode = MODE_TYPE_LNK | 0o777;
        let child_outcome = create_child(ctx, name, name_len, mode, VT_LNK, cred)?;
        let child_vh = match child_outcome {
            Ready(vnode_h) => vnode_h,
            Parked(p) => return Ok(Parked(p)),
        };

        let child_vp = ctx.resolve_vnode(child_vh).ok_or(VfsError::Io)? as *mut Vnode;
        let child_vd = (*child_vp).data as *mut TmpfsVnodeData;
        let md = mdata(ctx);
        let sym_ptr = pool::alloc_symlink(md, target, target_len);
        if sym_ptr.is_null() {
            (*child_vd).active = 0;
            pool::dir_remove_entry(dir_vdata, name, name_len);
            pool::account_inode_sub(md);
            return Err(VfsError::NoMem);
        }
        (*child_vd).symlink_data = sym_ptr;
        (*child_vd).size = target_len as u64;
        Ok(Ready(child_vh))
    }
}

pub(crate) unsafe fn tmpfs_unlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let ent = dir_find_entry_for_mount(ctx, dir_vdata, name, name_len);
        if ent.is_null() {
            return Err(VfsError::NoEnt);
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
        *ent = Dirent::zeroed();
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn tmpfs_rmdir(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let ent = dir_find_entry_for_mount(ctx, dir_vdata, name, name_len);
        if ent.is_null() {
            return Err(VfsError::NoEnt);
        }
        let child_id = (*ent).ino as u64;
        let md = mdata(ctx);
        let child_vd = pool::find_vdata(md, child_id);
        if child_vd.is_null() {
            return Err(VfsError::NoEnt);
        }
        if (*child_vd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        if !dir_is_empty(child_vd) {
            return Err(VfsError::NotEmpty);
        }
        *ent = Dirent::zeroed();
        if (*dir_vdata).nlink > 0 {
            (*dir_vdata).nlink -= 1;
            (*ctx.vnode).nlink = (*dir_vdata).nlink;
        }
        (*child_vd).nlink = 0;
        free_vdata_storage(md, child_vd);
        pool::account_inode_sub(md);
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn tmpfs_link(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    target: VnodeHandle,
) -> VopOutcome<()> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let target_vp = ctx.resolve_vnode(target).ok_or(VfsError::Inval)? as *mut Vnode;
        let tvd = (*target_vp).data as *mut TmpfsVnodeData;
        if tvd.is_null() {
            return Err(VfsError::Inval);
        }
        if (*tvd).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        if !dir_find_entry_for_mount(ctx, dir_vdata, name, name_len).is_null() {
            return Err(VfsError::Exist);
        }
        if pool::dir_add_entry(dir_vdata, name, name_len, (*tvd).id) != 0 {
            return Err(VfsError::NoMem);
        }
        (*tvd).nlink += 1;
        (*target_vp).nlink = (*tvd).nlink;
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn tmpfs_rename(
    ctx: &mut OwnerVopCtx<'_>,
    old_name: *const u8,
    old_len: u8,
    new_dir: VnodeHandle,
    new_name: *const u8,
    new_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let new_vnode = ctx.resolve_vnode(new_dir).ok_or(VfsError::Inval)? as *mut Vnode;
        let new_dvd = (*new_vnode).data as *mut TmpfsVnodeData;
        let old_dvd = vdata(ctx);
        if old_dvd.is_null() || new_dvd.is_null() {
            return Err(VfsError::Inval);
        }
        let src_ent = dir_find_entry_for_mount(ctx, old_dvd, old_name, old_len);
        if src_ent.is_null() {
            return Err(VfsError::NoEnt);
        }
        let child_id = (*src_ent).ino as u64;
        let md = mdata(ctx);

        let dst_ent = dir_find_entry_for_mount(ctx, new_dvd, new_name, new_len);
        if !dst_ent.is_null() {
            let dst_id = (*dst_ent).ino as u64;
            let dst_vd = pool::find_vdata(md, dst_id);
            if !dst_vd.is_null() {
                if (*dst_vd).ftype == VT_DIR && !dir_is_empty(dst_vd) {
                    return Err(VfsError::NotEmpty);
                }
                if (*dst_vd).nlink > 0 {
                    (*dst_vd).nlink -= 1;
                }
                if (*dst_vd).nlink == 0 {
                    free_vdata_storage(md, dst_vd);
                    pool::account_inode_sub(md);
                }
            }
            *dst_ent = Dirent::zeroed();
        }

        *src_ent = Dirent::zeroed();

        if pool::dir_add_entry(new_dvd, new_name, new_len, child_id) != 0 {
            let _ = pool::dir_add_entry(old_dvd, old_name, old_len, child_id);
            return Err(VfsError::NoMem);
        }

        let child_vd = pool::find_vdata(md, child_id);
        if !child_vd.is_null() && (*ctx.vnode).id() != (*new_vnode).id() {
            (*child_vd).parent_id = (*new_vnode).id();
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

pub(crate) unsafe fn tmpfs_open(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(crate) unsafe fn tmpfs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(crate) unsafe fn tmpfs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let fs_id = (*ctx.mount).fs_instance_id;
        (*attr).fs_instance_id = fs_id;
        (*attr).backend_node_id = (*vdata).id;
        (*attr).backend_seq = 0;
        (*attr).kind = vtype_to_kind((*vdata).ftype);
        (*attr).mode = (*vdata).mode;
        (*attr).uid = (*vdata).uid;
        (*attr).gid = (*vdata).gid;
        (*attr).nlink = (*vdata).nlink;
        (*attr).size = (*vdata).size;
        (*attr).blocks = ((*vdata).size + 511) / 512;
        (*attr).atime = (*vdata).atime;
        (*attr).mtime = (*vdata).mtime;
        (*attr).ctime = (*vdata).ctime;
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn tmpfs_setattr(
    ctx: &mut OwnerVopCtx<'_>,
    attr: *const VAttr,
) -> VopOutcome<()> {
    use crate::core::file::{
        VATTR_ATIME, VATTR_CTIME, VATTR_GID, VATTR_MODE, VATTR_MTIME, VATTR_UID,
    };
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let valid = (*attr).valid;
        if (valid & VATTR_MODE) != 0 {
            (*vdata).mode = (*attr).mode;
        }
        if (valid & VATTR_UID) != 0 {
            (*vdata).uid = (*attr).uid;
        }
        if (valid & VATTR_GID) != 0 {
            (*vdata).gid = (*attr).gid;
        }
        if (valid & VATTR_ATIME) != 0 {
            (*vdata).atime = (*attr).atime;
        }
        if (valid & VATTR_MTIME) != 0 {
            (*vdata).mtime = (*attr).mtime;
        }
        if (valid & VATTR_CTIME) != 0 {
            (*vdata).ctime = (*attr).ctime;
        }
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn tmpfs_access(
    ctx: &mut OwnerVopCtx<'_>,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<()> {
    unsafe {
        if cred.is_null() {
            return Ok(Ready(()));
        }
        if (*cred).is_root() {
            return Ok(Ready(()));
        }
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let file_mode = (*vdata).mode;
        let uid = (*vdata).uid;
        let gid = (*vdata).gid;
        let shift = if (*cred).euid == uid {
            6
        } else if (*cred).in_group(gid) {
            3
        } else {
            0
        };
        let perm = (file_mode >> shift) & 0o7;
        if (mode & 1) != 0 && (perm & 4) == 0 {
            return Err(VfsError::Acces);
        }
        if (mode & 2) != 0 && (perm & 2) == 0 {
            return Err(VfsError::Acces);
        }
        if (mode & 4) != 0 && (perm & 1) == 0 {
            return Err(VfsError::Acces);
        }
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn tmpfs_readlink(
    ctx: &mut OwnerVopCtx<'_>,
    buf: *mut u8,
    buf_len: usize,
    _cred: *const VfsCred,
) -> VopOutcome<usize> {
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        if (*vdata).ftype != VT_LNK {
            return Err(VfsError::Inval);
        }
        if !(*vdata).symlink_data.is_null() {
            let len = (*vdata).size as usize;
            let copy_len = if len < buf_len { len } else { buf_len };
            ::core::ptr::copy_nonoverlapping((*vdata).symlink_data, buf, copy_len);
            return Ok(Ready(copy_len));
        }
        Err(VfsError::Io)
    }
}

pub(crate) unsafe fn tmpfs_truncate(ctx: &mut OwnerVopCtx<'_>, new_size: u64) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);
        let old_size = (*vdata).size;
        if new_size < old_size {
            if (*vdata).writable_head != INVALID_WRITABLE_SLOT {
                pool::chain_truncate(md, (*vdata).writable_head, new_size);
            }
            pool::account_bytes_sub(md, old_size - new_size);
        } else if new_size > old_size {
            let growth = new_size - old_size;
            if !pool::check_bytes(md, growth) {
                return Err(VfsError::NoMem);
            }
            if (*vdata).writable_head == INVALID_WRITABLE_SLOT {
                let slot = pool::alloc_writable(md);
                if slot == INVALID_WRITABLE_SLOT {
                    return Err(VfsError::NoMem);
                }
                (*vdata).writable_head = slot;
            }
            pool::account_bytes_add(md, growth);
        }
        (*vdata).size = new_size;
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn tmpfs_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        crate::owner::pager_rpc::release_mo_binding_for_vnode(ctx.state, ctx.handle);
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Ok(Ready(()));
        }
        if (*vdata).nlink == 0 {
            let md = mdata(ctx);
            free_vdata_storage(md, vdata);
            pool::account_inode_sub(md);
        }
        // The vnode is being detached from this vdata. Clear the
        // vdata->vnode backlink as well, so a later vget / intern_vnode
        // re-allocates a fresh vnode and rebinds `data` instead of
        // handing back this now-detached (data == null) vnode from the
        // cache fast-path while the inode still exists (nlink > 0).
        (*vdata).vnode_handle = VnodeHandle::INVALID;
        (*ctx.vnode).data = ::core::ptr::null_mut();
        Ok(Ready(()))
    }
}

// =========================================================================
// DataOps
// =========================================================================

pub(crate) unsafe fn tmpfs_read(
    ctx: &VopDataCtx,
    offset: u64,
    dst: *mut u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        if (*vdata).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        let size = (*vdata).size;
        if offset >= size {
            return Ok(Ready(0));
        }
        let avail = size - offset;
        let count = if len < avail { len } else { avail };
        let md = mdata_d(ctx);
        let read = pool::chain_read(md, (*vdata).writable_head, offset, dst, count);
        Ok(Ready(read))
    }
}

pub(crate) unsafe fn tmpfs_write(
    ctx: &VopDataCtx,
    offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        if (*vdata).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        let md = mdata_d(ctx);
        let old_size = (*vdata).size;
        let end = offset + len;
        if end > old_size {
            let growth = end - old_size;
            if !pool::check_bytes(md, growth) {
                return Err(VfsError::NoMem);
            }
        }
        if (*vdata).writable_head == INVALID_WRITABLE_SLOT {
            let slot = pool::alloc_writable(md);
            if slot == INVALID_WRITABLE_SLOT {
                return Err(VfsError::NoMem);
            }
            (*vdata).writable_head = slot;
        }
        let written = pool::chain_write(md, (*vdata).writable_head, offset, src, len);
        if written == 0 && len > 0 {
            return Err(VfsError::NoMem);
        }
        let new_end = offset + written;
        if new_end > old_size {
            let growth = new_end - old_size;
            pool::account_bytes_add(md, growth);
            (*vdata).size = new_end;
        }
        Ok(Ready(written))
    }
}

pub(crate) unsafe fn tmpfs_fsync(_ctx: &VopDataCtx) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(crate) unsafe fn tmpfs_readdir(
    ctx: &VopDataCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() || (*vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let start = *cookie as usize;
        let attr = VAttr::zeroed();
        let md = mdata_d(ctx);

        if start == 0 {
            if !emit((*vdata).id, b".".as_ptr(), 1, 4, &attr) {
                *cookie = 1;
                return Ok(Ready(()));
            }
        }
        if start <= 1 {
            let parent_id = if (*vdata).parent_id != 0 {
                (*vdata).parent_id
            } else {
                (*vdata).id
            };
            if !emit(parent_id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = 2;
                return Ok(Ready(()));
            }
        }

        let real_start = if start > 2 { start - 2 } else { 0 };
        let mut idx = 0usize;
        for i in 0..(*vdata).dirents_cap as usize {
            let ent = (*vdata).dirents.add(i);
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
                vtype_to_dtype_local((*child_vd).ftype)
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

pub(crate) unsafe fn tmpfs_statfs(ctx: &VopDataCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        let md = mdata_d(ctx);
        (*out).bsize = WRITABLE_SIZE as u32;
        (*out).frsize = WRITABLE_SIZE as u32;
        (*out).flag = 0;
        (*out).namemax = MAX_NAME_LEN as u32;
        (*out).fsid = ctx.fs_instance_id.0;
        (*out).set_fs_name(b"tmpfs");

        (*out).files = (*md).used_inodes as u64;
        if (*md).max_inodes > 0 {
            (*out).ffree = ((*md).max_inodes - (*md).used_inodes) as u64;
        } else {
            (*out).ffree = (*md).vdata_cap as u64 - (*md).used_inodes as u64;
        }
        (*out).favail = (*out).ffree;

        if (*md).max_bytes > 0 {
            (*out).blocks = (*md).max_bytes / WRITABLE_SIZE as u64;
            let used_blocks = (*md).used_bytes / WRITABLE_SIZE as u64;
            (*out).bfree = (*out).blocks - used_blocks;
            (*out).bavail = (*out).bfree;
        } else {
            let used_blocks = pool::allocated_file_slot_count(md);
            (*out).blocks = (*md).writable_cap as u64;
            (*out).bfree = (*md).writable_cap as u64 - used_blocks;
            (*out).bavail = (*out).bfree;
        }
        Ok(Ready(()))
    }
}
