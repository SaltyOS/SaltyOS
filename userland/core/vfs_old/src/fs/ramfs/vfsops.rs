// SPDX-License-Identifier: GPL-2.0-only
//! Ramfs VfsOps implementation — filesystem-level operations.

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_alloc_array;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::outcome::{VopControl::Ready, VopOutcome};
use crate::vfs_core::vnode::{VN_ROOT, VT_DIR, VnodeHandle};
use crate::vfs_core::vop_context::OwnerMountCtx;

use super::pool;
use super::types::RamfsMountData;

// =========================================================================
// VfsOps function implementations
// =========================================================================

pub(super) unsafe fn ramfs_mount(
    ctx: &mut OwnerMountCtx<'_>,
    _source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
    _can_park: bool,
) -> VopOutcome<()> {
    unsafe {
        let md: *mut RamfsMountData = vfs_alloc_array::<RamfsMountData>(1);
        if md.is_null() {
            return Err(VfsError::NoSpace);
        }
        *md = RamfsMountData::zeroed();
        (*ctx.mount).data = md as *mut u8;

        if pool::init_pools(md) != 0 {
            return Err(VfsError::NoSpace);
        }

        let root_vd = pool::alloc_vdata(md);
        if root_vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        let root_id = pool::next_id(md);
        (*root_vd).id = root_id;
        (*root_vd).parent_id = 0;
        (*root_vd).ftype = VT_DIR;
        (*root_vd).mode = S_IFDIR_L | 0o755;
        (*root_vd).nlink = 2;

        let dirents = vfs_alloc_array::<super::types::Dirent>(INITIAL_DIRENTS);
        if dirents.is_null() {
            (*root_vd).active = 0;
            return Err(VfsError::NoSpace);
        }
        (*root_vd).dirents = dirents;
        (*root_vd).dirents_cap = INITIAL_DIRENTS as u16;

        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*root_vp).id = root_id;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).flags = VN_ROOT;
        (*root_vp).data = root_vd as *mut u8;
        (*root_vp).nlink = 2;
        (*root_vp).mount.set(fs_instance_id, mount_handle);
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::RAMFS_VOPS;
        (*root_vd).vnode_handle = root_vh;

        (*ctx.mount).root_vnode = root_vh;
        Ok(Ready(()))
    }
}

pub(super) unsafe fn ramfs_unmount(ctx: &mut OwnerMountCtx<'_>, _force: bool) -> VfsResult<()> {
    unsafe {
        (*ctx.mount).root_vnode = VnodeHandle::INVALID;
        (*ctx.mount).data = core::ptr::null_mut();
        Ok(())
    }
}

pub(super) unsafe fn ramfs_root(ctx: &OwnerMountCtx<'_>) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*ctx.mount).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

pub(super) unsafe fn ramfs_vget(ctx: &mut OwnerMountCtx<'_>, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*ctx.mount).data as *mut RamfsMountData;

        let vd = pool::find_vdata(md, id);
        if vd.is_null() {
            return Err(VfsError::NotFound);
        }

        if (*vd).vnode_handle.is_valid() && ctx.state.vnodes.raw_ptr((*vd).vnode_handle).is_some() {
            return Ok((*vd).vnode_handle);
        }

        let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vp).id = id;
        (*vp).vtype = (*vd).ftype;
        (*vp).data = vd as *mut u8;
        (*vp).nlink = (*vd).nlink;
        (*vp).mount.set(fs_instance_id, mount_handle);
        (*vp).fs_instance_id = fs_instance_id;
        (*vp).ops = &raw const super::RAMFS_VOPS;
        (*vd).vnode_handle = vh;
        Ok(vh)
    }
}

pub(super) unsafe fn ramfs_statfs(ctx: &OwnerMountCtx<'_>, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*ctx.mount).data as *mut RamfsMountData;
        (*out).bsize = WRITABLE_SIZE as u64;
        (*out).name_max = MAX_NAME_LEN as u32;
        let ft = &mut (*out).fs_type;
        ft[..5].copy_from_slice(b"ramfs");
        (*out).flags = (*ctx.mount).flags;

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
        (*out).ffree = (*md).vdata_cap as u64 - files;
        (*out).blocks = (*md).writable_cap as u64;
        (*out).bfree = (*md).writable_cap as u64 - used_blocks;
        (*out).bavail = (*out).bfree;
        Ok(())
    }
}

pub(super) unsafe fn ramfs_sync(_ctx: &OwnerMountCtx<'_>) -> VfsResult<()> {
    Ok(())
}
