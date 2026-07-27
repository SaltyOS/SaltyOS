// SPDX-License-Identifier: GPL-2.0-only
//
//! devfs `VfsOps`. Mount allocates a `DevfsMountData` page, seeds
//! the root directory plus all entries from `DEVFS_REGISTRATIONS`,
//! and adds the synthetic `pts/` directory. Subsequent PTY slave
//! lookups extend the parallel arrays at runtime.

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::file::VStatfs;
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::vnode::{VN_ROOT, VnodeHandle, VnodeKind};
use crate::core::vop_context::OwnerMountCtx;

use super::{
    DEVFS_REGISTRATIONS, DevKind, DevfsMountData, MAX_DEVFS_VNODES, alloc_vdata, record_vnode,
};

pub(crate) unsafe fn devfs_mount(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let bytes = ::core::mem::size_of::<DevfsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoMem);
        }
        ::core::ptr::write_bytes(ptr, 0, pages * 4096);
        (*ctx.mount).data = ptr;

        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;

        // id 0: root directory.
        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        (*root_vp).kind = VnodeKind::Directory;
        (*root_vp).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(0, 0),
        };
        (*root_vp).backend_seq = 0;
        (*root_vp).flags |= VN_ROOT;
        (*root_vp).nlink = 3;
        (*root_vp).mount = mount_handle;
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::DEVFS_VOPS;

        let vdata = alloc_vdata(ptr);
        if vdata.is_null() {
            return Err(VfsError::NoMem);
        }
        // Root carries a placeholder `Console` kind — the
        // `is_root` discriminator is the directory's mode bits;
        // dispatch never matches the root against the device
        // routing table.
        (*vdata).kind = DevKind::Console;
        (*vdata).sub_id = 0;
        (*vdata).mode = 0o040755;
        (*vdata).generation = 0;
        (*root_vp).data = vdata as *mut u8;
        // devfs nodes are mount-lifetime singletons: pin them so the
        // reclaim sweep never frees a cached vnode out from under
        // vnode_handles[]. devfs_lookup / devfs_vget hand those cached
        // handles back without a liveness check, so an unpinned devfs
        // vnode that hits open_refcount==0 gets reclaimed and the cache
        // is left dangling (breaks the next open of e.g. /dev/console).
        (*root_vp).pin();
        record_vnode(ptr, root_vh, 0);

        let mut id: u64 = 1;
        for reg in DEVFS_REGISTRATIONS {
            let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
            (*vnode_ptr).kind = VnodeKind::CharDev;
            (*vnode_ptr).key = VnodeKey {
                fs_instance_id,
                backend_id: BackendNodeId::new(id, 0),
            };
            (*vnode_ptr).backend_seq = 0;
            (*vnode_ptr).nlink = 1;
            (*vnode_ptr).mount = mount_handle;
            (*vnode_ptr).fs_instance_id = fs_instance_id;
            (*vnode_ptr).ops = &raw const super::DEVFS_VOPS;

            let vdata = alloc_vdata(ptr);
            if vdata.is_null() {
                return Err(VfsError::NoMem);
            }
            (*vdata).kind = reg.kind;
            (*vdata).sub_id = 0;
            (*vdata).mode = reg.mode;
            (*vdata).generation = 0;
            (*vnode_ptr).data = vdata as *mut u8;
            (*vnode_ptr).pin(); // singleton device node — see root pin above
            record_vnode(ptr, vnode_h, id);

            id += 1;
        }

        // Synthetic /dev/pts directory.
        let (pts_vh, pts_vp) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        (*pts_vp).kind = VnodeKind::Directory;
        (*pts_vp).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(id, 0),
        };
        (*pts_vp).backend_seq = 0;
        (*pts_vp).nlink = 2;
        (*pts_vp).mount = mount_handle;
        (*pts_vp).fs_instance_id = fs_instance_id;
        (*pts_vp).ops = &raw const super::DEVFS_VOPS;

        let vdata = alloc_vdata(ptr);
        if vdata.is_null() {
            return Err(VfsError::NoMem);
        }
        (*vdata).kind = DevKind::PtsDir;
        (*vdata).sub_id = 0;
        (*vdata).mode = 0o040755;
        (*vdata).generation = 0;
        (*pts_vp).data = vdata as *mut u8;
        (*pts_vp).pin(); // singleton device node — see root pin above
        record_vnode(ptr, pts_vh, id);

        // PTY 0 is the console PTY, activated by posix_ttysrv at
        // boot and never torn down. Seed `/dev/pts/0` so callers
        // that receive pty id 0 can resolve the slave side through
        // normal VFS namei rather than a side-channel.
        id += 1;
        let (pty0_vh, pty0_vp) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        (*pty0_vp).kind = VnodeKind::CharDev;
        (*pty0_vp).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(id, 0),
        };
        (*pty0_vp).backend_seq = 0;
        (*pty0_vp).nlink = 1;
        (*pty0_vp).mount = mount_handle;
        (*pty0_vp).fs_instance_id = fs_instance_id;
        (*pty0_vp).ops = &raw const super::DEVFS_VOPS;

        let vdata = alloc_vdata(ptr);
        if vdata.is_null() {
            return Err(VfsError::NoMem);
        }
        (*vdata).kind = DevKind::PtySlave;
        (*vdata).sub_id = 0;
        (*vdata).mode = 0o020620;
        (*vdata).generation = 0;
        (*pty0_vp).data = vdata as *mut u8;
        (*pty0_vp).pin(); // singleton device node — see root pin above
        record_vnode(ptr, pty0_vh, id);

        Ok(root_vh)
    }
}

pub(crate) unsafe fn devfs_unmount(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    unsafe {
        let data = (*ctx.mount).data;
        if !data.is_null() {
            let bytes = ::core::mem::size_of::<DevfsMountData>();
            let pages = (bytes + 4095) / 4096;
            crate::server::mem::unmap(data, (pages * 4096) as u64);
            (*ctx.mount).data = ::core::ptr::null_mut();
        }
        (*ctx.mount).root = Handle::INVALID;
        Ok(())
    }
}

pub(crate) unsafe fn devfs_root(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let root = (*ctx.mount).root;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

pub(crate) unsafe fn devfs_vget(
    ctx: &mut OwnerMountCtx<'_>,
    id: u64,
) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *const DevfsMountData;
        for i in 0..(*md).count {
            if (*md).vnode_ids[i] == id {
                return Ok((*md).vnode_handles[i]);
            }
        }
        Err(VfsError::NoEnt)
    }
}

pub(crate) unsafe fn devfs_statfs(
    ctx: &mut OwnerMountCtx<'_>,
    out: *mut VStatfs,
) -> Result<(), VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *const DevfsMountData;
        (*out).bsize = 4096;
        (*out).frsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = (*md).count as u64;
        (*out).ffree = (MAX_DEVFS_VNODES - (*md).count) as u64;
        (*out).favail = (*out).ffree;
        (*out).fsid = (*ctx.mount).fs_instance_id.0;
        (*out).flag = 0;
        (*out).namemax = 255;
        (*out).set_fs_name(b"devfs");
        Ok(())
    }
}

pub(crate) unsafe fn devfs_sync(_ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    Ok(())
}
