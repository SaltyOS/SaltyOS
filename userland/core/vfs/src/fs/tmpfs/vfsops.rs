// SPDX-License-Identifier: GPL-2.0-only
//
//! Tmpfs `VfsOps` — `mount`, `unmount`, `root`, `vget`, `statfs`,
//! `sync`. Same general shape as ramfs, with quota fields seeded
//! from the mount-time `size=` / `nr_inodes=` options.
//!
//! Today the new `VfsOps::mount` signature does not carry the
//! mount-time options vector — it lands together with the
//! mount-control wire in §M-late. Until then mounts come up with
//! `max_bytes = 0` (unlimited) and rely on the global mmsrv quota
//! to bound runaway growth.

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::file::MODE_TYPE_DIR;
use crate::core::file::VStatfs;
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::vnode::{VN_ROOT, VT_DIR, VnodeHandle, VnodeKind};
use crate::core::vop_context::OwnerMountCtx;
use crate::server::alloc::vfs_alloc_array;
use crate::server::consts::{INITIAL_DIRENTS, MAX_NAME_LEN, WRITABLE_SIZE};

use super::pool;
use super::types::{Dirent, TmpfsMountData};

pub(crate) unsafe fn tmpfs_mount(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let md: *mut TmpfsMountData = vfs_alloc_array::<TmpfsMountData>(1);
        if md.is_null() {
            return Err(VfsError::NoMem);
        }
        *md = TmpfsMountData::zeroed();
        (*ctx.mount).data = md as *mut u8;

        if pool::init_pools(md) != 0 {
            return Err(VfsError::NoMem);
        }

        let root_vd = pool::alloc_vdata(md);
        if root_vd.is_null() {
            return Err(VfsError::NoMem);
        }
        let root_id = pool::next_id(md);
        (*root_vd).id = root_id;
        (*root_vd).parent_id = 0;
        (*root_vd).ftype = VT_DIR;
        // Sticky bit (1777) — POSIX `/tmp` convention.
        (*root_vd).mode = MODE_TYPE_DIR | 0o1777;
        (*root_vd).nlink = 2;

        let dirents = vfs_alloc_array::<Dirent>(INITIAL_DIRENTS);
        if dirents.is_null() {
            (*root_vd).active = 0;
            return Err(VfsError::NoMem);
        }
        (*root_vd).dirents = dirents;
        (*root_vd).dirents_cap = INITIAL_DIRENTS as u16;

        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;

        (*root_vp).kind = VnodeKind::Directory;
        (*root_vp).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(root_id, 0),
        };
        (*root_vp).backend_seq = 0;
        (*root_vp).flags = VN_ROOT;
        (*root_vp).data = root_vd as *mut u8;
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::TMPFS_VOPS;
        (*root_vd).vnode_handle = root_vh;

        (*md).used_inodes = 1;

        Ok(root_vh)
    }
}

pub(crate) unsafe fn tmpfs_unmount(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    unsafe {
        (*ctx.mount).root = Handle::INVALID;
        (*ctx.mount).data = ::core::ptr::null_mut();
        Ok(())
    }
}

pub(crate) unsafe fn tmpfs_root(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let root = (*ctx.mount).root;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

pub(crate) unsafe fn tmpfs_vget(
    ctx: &mut OwnerMountCtx<'_>,
    ino: u64,
) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *mut TmpfsMountData;
        let vdata = pool::find_vdata(md, ino);
        if vdata.is_null() {
            return Err(VfsError::NoEnt);
        }
        if (*vdata).vnode_handle.is_valid() && ctx.state.vnodes.get((*vdata).vnode_handle).is_some()
        {
            return Ok((*vdata).vnode_handle);
        }
        let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;

        (*vnode_ptr).kind = crate::core::vnode::vtype_to_kind((*vdata).ftype);
        (*vnode_ptr).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(ino, 0),
        };
        (*vnode_ptr).backend_seq = 0;
        (*vnode_ptr).data = vdata as *mut u8;
        (*vnode_ptr).nlink = (*vdata).nlink;
        (*vnode_ptr).mount = mount_handle;
        (*vnode_ptr).fs_instance_id = fs_instance_id;
        (*vnode_ptr).ops = &raw const super::TMPFS_VOPS;
        (*vdata).vnode_handle = vnode_h;
        Ok(vnode_h)
    }
}

pub(crate) unsafe fn tmpfs_statfs(
    ctx: &mut OwnerMountCtx<'_>,
    out: *mut VStatfs,
) -> Result<(), VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *mut TmpfsMountData;

        (*out).bsize = WRITABLE_SIZE as u32;
        (*out).frsize = WRITABLE_SIZE as u32;
        (*out).flag = 0;
        (*out).namemax = MAX_NAME_LEN as u32;
        (*out).fsid = (*ctx.mount).fs_instance_id.0;
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
        Ok(())
    }
}

pub(crate) unsafe fn tmpfs_sync(_ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    Ok(())
}
