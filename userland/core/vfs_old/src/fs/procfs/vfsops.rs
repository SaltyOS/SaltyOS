// SPDX-License-Identifier: GPL-2.0-only
//! procfs `VfsOps` — mount, unmount, root, vget, statfs, sync.

use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::outcome::{VopControl::Ready, VopOutcome};
use crate::vfs_core::vfs::VfsOps;
use crate::vfs_core::vnode::{VN_ROOT, VT_DIR, VnodeHandle};
use crate::vfs_core::vop_context::OwnerMountCtx;

use super::{ProcfsKind, ProcfsMountData, encode_id};

unsafe fn procfs_mount(
    ctx: &mut OwnerMountCtx<'_>,
    _source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
    _can_park: bool,
) -> VopOutcome<()> {
    unsafe {
        let bytes = core::mem::size_of::<ProcfsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoSpace);
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        (*ctx.mount).data = ptr;

        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).id = encode_id(ProcfsKind::Root, 0);
        (*root_vp).flags |= VN_ROOT;
        (*root_vp).nlink = 2;
        (*root_vp).mount.set(fs_instance_id, mount_handle);
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::PROCFS_VOPS;

        let md = ptr as *mut ProcfsMountData;
        let vd = &raw mut (*md).vdata[0];
        (*vd).kind = ProcfsKind::Root;
        (*vd).pid = 0;
        (*vd).sys_ptr = core::ptr::null();
        (*root_vp).data = vd as *mut u8;
        (*md).count = 1;

        (*ctx.mount).root_vnode = root_vh;

        Ok(Ready(()))
    }
}

unsafe fn procfs_unmount(ctx: &mut OwnerMountCtx<'_>, _force: bool) -> VfsResult<()> {
    unsafe {
        let data = (*ctx.mount).data;
        if !data.is_null() {
            let bytes = core::mem::size_of::<ProcfsMountData>();
            let pages = (bytes + 4095) / 4096;
            crate::server::mem::unmap(data, (pages * 4096) as u64);
            (*ctx.mount).data = core::ptr::null_mut();
        }
        (*ctx.mount).root_vnode = VnodeHandle::INVALID;
        Ok(())
    }
}

unsafe fn procfs_root(ctx: &OwnerMountCtx<'_>) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*ctx.mount).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

unsafe fn procfs_vget(_ctx: &mut OwnerMountCtx<'_>, _id: u64) -> VfsResult<VnodeHandle> {
    Err(VfsError::NotFound)
}

unsafe fn procfs_statfs(_ctx: &OwnerMountCtx<'_>, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        (*out).bsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = 0;
        (*out).ffree = 0;
        (*out).fs_type = [0; 16];
        let ft = &mut (*out).fs_type;
        ft[..6].copy_from_slice(b"procfs");
        (*out).flags = 0;
        (*out).name_max = 255;
        Ok(())
    }
}

unsafe fn procfs_sync(_ctx: &OwnerMountCtx<'_>) -> VfsResult<()> {
    Ok(())
}

// =========================================================================
// Static dispatch table
// =========================================================================

pub(super) static PROCFS_VFSOPS: VfsOps = VfsOps {
    mount: procfs_mount,
    unmount: procfs_unmount,
    root: procfs_root,
    vget: procfs_vget,
    statfs: procfs_statfs,
    sync: procfs_sync,
};
