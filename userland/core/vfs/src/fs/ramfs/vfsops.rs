// SPDX-License-Identifier: GPL-2.0-only
//
//! Ramfs `VfsOps` — `mount`, `unmount`, `root`, `vget`, `statfs`,
//! `sync`. Synthetic in-memory filesystem; no backend session.
//!
//! `mount` allocates `RamfsMountData`, initialises the three pools,
//! seeds the root directory vnode, and returns the root handle for
//! the mount-control layer to record on `Mount.root`. The mount
//! itself never blocks — every entry returns synchronously.

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
use super::types::{Dirent, RamfsMountData};

// =========================================================================
// VfsOps function implementations
// =========================================================================

/// Allocate the per-mount state and seed the root directory.
/// Returns the root vnode handle to the mount-control layer.
pub(crate) unsafe fn ramfs_mount(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let md: *mut RamfsMountData = vfs_alloc_array::<RamfsMountData>(1);
        if md.is_null() {
            return Err(VfsError::NoMem);
        }
        *md = RamfsMountData::zeroed();
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
        (*root_vd).mode = MODE_TYPE_DIR | 0o755;
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
        (*root_vp).key = VnodeKey::new_ino(fs_instance_id, root_id);
        (*root_vp).backend_seq = 0;
        (*root_vp).flags = VN_ROOT;
        (*root_vp).data = root_vd as *mut u8;
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::RAMFS_VOPS;
        (*root_vd).vnode_handle = root_vh;

        Ok(root_vh)
    }
}

/// Tear down the mount. The arena reclaim sweep drops every vnode
/// referencing this mount before this entry fires (see
/// `Mount.vnode_refcount`); ramfs only needs to drop the per-mount
/// pools. The pool buffers are intentionally leaked to mmsrv on
/// unmount today — a future page-cache sweep will pair every
/// `map_anon` here with a matching `unmap`.
pub(crate) unsafe fn ramfs_unmount(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    unsafe {
        (*ctx.mount).root = Handle::INVALID;
        (*ctx.mount).data = ::core::ptr::null_mut();
        Ok(())
    }
}

/// Return the cached root handle. The arena keeps the slot pinned
/// while `Mount.vnode_refcount > 0`.
pub(crate) unsafe fn ramfs_root(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let root = (*ctx.mount).root;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

/// Look up a vnode by inode number, allocating a fresh `Vnode` slot
/// when the cached handle is stale (the previous arena slot was
/// reclaimed).
pub(crate) unsafe fn ramfs_vget(
    ctx: &mut OwnerMountCtx<'_>,
    ino: u64,
) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *mut RamfsMountData;
        let vdata = pool::find_vdata(md, ino);
        if vdata.is_null() {
            return Err(VfsError::NoEnt);
        }
        if (*vdata).vnode_handle.is_valid()
            && ctx.state.vnodes.raw_ptr((*vdata).vnode_handle).is_some()
        {
            return Ok((*vdata).vnode_handle);
        }

        let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;

        let kind = match (*vdata).ftype {
            x if x == crate::core::vnode::VT_DIR => VnodeKind::Directory,
            x if x == crate::core::vnode::VT_REG => VnodeKind::Regular,
            x if x == crate::core::vnode::VT_LNK => VnodeKind::Symlink,
            x if x == crate::core::vnode::VT_FIFO => VnodeKind::Fifo,
            x if x == crate::core::vnode::VT_CHR => VnodeKind::CharDev,
            x if x == crate::core::vnode::VT_BLK => VnodeKind::BlockDev,
            x if x == crate::core::vnode::VT_SOCK => VnodeKind::Socket,
            _ => VnodeKind::Empty,
        };

        (*vnode_ptr).kind = kind;
        (*vnode_ptr).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(ino, 0),
        };
        (*vnode_ptr).backend_seq = 0;
        (*vnode_ptr).data = vdata as *mut u8;
        (*vnode_ptr).nlink = (*vdata).nlink;
        (*vnode_ptr).mount = mount_handle;
        (*vnode_ptr).fs_instance_id = fs_instance_id;
        (*vnode_ptr).ops = &raw const super::RAMFS_VOPS;
        (*vdata).vnode_handle = vnode_h;
        Ok(vnode_h)
    }
}

/// Fill the `VStatfs` snapshot. Block / inode counts are scanned
/// from the live pool state.
pub(crate) unsafe fn ramfs_statfs(
    ctx: &mut OwnerMountCtx<'_>,
    out: *mut VStatfs,
) -> Result<(), VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *mut RamfsMountData;

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

        (*out).bsize = WRITABLE_SIZE as u32;
        (*out).frsize = WRITABLE_SIZE as u32;
        (*out).blocks = (*md).writable_cap as u64;
        (*out).bfree = (*md).writable_cap as u64 - used_blocks;
        (*out).bavail = (*out).bfree;
        (*out).files = files;
        (*out).ffree = (*md).vdata_cap as u64 - files;
        (*out).favail = (*out).ffree;
        (*out).fsid = (*ctx.mount).fs_instance_id.0;
        (*out).flag = 0;
        (*out).namemax = MAX_NAME_LEN as u32;
        (*out).set_fs_name(b"ramfs");
        Ok(())
    }
}

/// In-memory ramfs has no backing store to flush — `sync` is a
/// no-op.
pub(crate) unsafe fn ramfs_sync(_ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    Ok(())
}
