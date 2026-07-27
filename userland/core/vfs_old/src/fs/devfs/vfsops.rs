// SPDX-License-Identifier: GPL-2.0-only
//! devfs `VfsOps` — mount, unmount, root, vget, statfs, sync.

use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::outcome::{VopControl::Ready, VopOutcome};
use crate::vfs_core::vfs::VfsOps;
use crate::vfs_core::vnode::{VN_ROOT, VT_CHR, VT_DIR, VnodeHandle};
use crate::vfs_core::vop_context::OwnerMountCtx;

use super::{
    DEVFS_REGISTRATIONS, DevKind, DevfsMountData, MAX_DEVFS_VNODES, alloc_vdata, record_vnode,
};

// =========================================================================
// VfsOps function implementations
// =========================================================================

unsafe fn devfs_mount(
    ctx: &mut OwnerMountCtx<'_>,
    _source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
    _can_park: bool,
) -> VopOutcome<()> {
    unsafe {
        let bytes = core::mem::size_of::<DevfsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoSpace);
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        (*ctx.mount).data = ptr;

        let mount_handle_h = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;

        // id 0: root directory vnode.
        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).id = 0;
        (*root_vp).flags |= VN_ROOT;
        (*root_vp).nlink = 3;
        (*root_vp).mount.set(fs_instance_id, mount_handle_h);
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::DEVFS_VOPS;

        let vd = alloc_vdata(ptr);
        if vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        (*vd).kind = DevKind::Console;
        (*vd).sub_id = 0;
        (*vd).mode = 0o040755;
        (*root_vp).data = vd as *mut u8;
        record_vnode(ptr, root_vh, 0);

        (*ctx.mount).root_vnode = root_vh;

        let mut id: u64 = 1;
        for reg in DEVFS_REGISTRATIONS {
            let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
            (*vp).vtype = VT_CHR;
            (*vp).id = id;
            (*vp).nlink = 1;
            (*vp).mount.set(fs_instance_id, mount_handle_h);
            (*vp).fs_instance_id = fs_instance_id;
            (*vp).ops = &raw const super::DEVFS_VOPS;

            let vd = alloc_vdata(ptr);
            if vd.is_null() {
                return Err(VfsError::NoSpace);
            }
            (*vd).kind = reg.kind;
            (*vd).sub_id = 0;
            (*vd).mode = reg.mode;
            (*vp).data = vd as *mut u8;
            record_vnode(ptr, vh, id);

            id += 1;
        }

        // Synthetic `pts/` directory vnode.
        let (pts_vh, pts_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        (*pts_vp).vtype = VT_DIR;
        (*pts_vp).id = id;
        (*pts_vp).nlink = 2;
        (*pts_vp).mount.set(fs_instance_id, mount_handle_h);
        (*pts_vp).fs_instance_id = fs_instance_id;
        (*pts_vp).ops = &raw const super::DEVFS_VOPS;

        let vd = alloc_vdata(ptr);
        if vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        (*vd).kind = DevKind::PtsDir;
        (*vd).sub_id = 0;
        (*vd).mode = 0o040755;
        (*pts_vp).data = vd as *mut u8;
        record_vnode(ptr, pts_vh, id);

        Ok(Ready(()))
    }
}

unsafe fn devfs_unmount(ctx: &mut OwnerMountCtx<'_>, _force: bool) -> VfsResult<()> {
    unsafe {
        let data = (*ctx.mount).data;
        if !data.is_null() {
            let bytes = core::mem::size_of::<DevfsMountData>();
            let pages = (bytes + 4095) / 4096;
            crate::server::mem::unmap(data, (pages * 4096) as u64);
            (*ctx.mount).data = core::ptr::null_mut();
        }
        (*ctx.mount).root_vnode = VnodeHandle::INVALID;
        Ok(())
    }
}

unsafe fn devfs_root(ctx: &OwnerMountCtx<'_>) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*ctx.mount).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

unsafe fn devfs_vget(ctx: &mut OwnerMountCtx<'_>, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*ctx.mount).data as *const DevfsMountData;
        for i in 0..(*md).count {
            if (*md).vnode_ids[i] == id {
                return Ok((*md).vnode_handles[i]);
            }
        }
        Err(VfsError::NotFound)
    }
}

unsafe fn devfs_statfs(ctx: &OwnerMountCtx<'_>, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*ctx.mount).data as *const DevfsMountData;
        (*out).bsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = (*md).count as u64;
        (*out).ffree = (MAX_DEVFS_VNODES - (*md).count) as u64;
        (*out).fs_type = [0; 16];
        let ft = &mut (*out).fs_type;
        ft[..5].copy_from_slice(b"devfs");
        (*out).flags = 0;
        (*out).name_max = 255;
        Ok(())
    }
}

unsafe fn devfs_sync(_ctx: &OwnerMountCtx<'_>) -> VfsResult<()> {
    Ok(())
}

// =========================================================================
// Static dispatch table
// =========================================================================

pub(super) static DEVFS_VFSOPS: VfsOps = VfsOps {
    mount: devfs_mount,
    unmount: devfs_unmount,
    root: devfs_root,
    vget: devfs_vget,
    statfs: devfs_statfs,
    sync: devfs_sync,
};
