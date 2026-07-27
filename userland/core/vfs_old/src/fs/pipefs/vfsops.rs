// SPDX-License-Identifier: GPL-2.0-only
//! pipefs `VfsOps` — mount, unmount, root, vget, statfs, sync.

use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::outcome::{VopControl::Ready, VopOutcome};
use crate::vfs_core::vfs::VfsOps;
use crate::vfs_core::vnode::{VN_ROOT, VT_DIR, VnodeHandle};
use crate::vfs_core::vop_context::OwnerMountCtx;

use super::{MAX_PIPEFS_VNODES, PipefsMountData};

unsafe fn pipefs_mount(
    ctx: &mut OwnerMountCtx<'_>,
    _source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
    _can_park: bool,
) -> VopOutcome<()> {
    unsafe {
        let bytes = core::mem::size_of::<PipefsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoSpace);
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        (*ctx.mount).data = ptr;

        let md = ptr as *mut PipefsMountData;
        (*md).next_id = 1;

        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).id = 0;
        (*root_vp).flags |= VN_ROOT;
        (*root_vp).nlink = 2;
        (*root_vp).mount.set(fs_instance_id, mount_handle);
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::PIPEFS_VOPS;

        let vd = &raw mut (*md).vdata[0];
        (*vd).slot_idx = u32::MAX;
        (*vd).is_root = 1;
        (*root_vp).data = vd as *mut u8;
        (*md).count = 1;

        (*md).vnode_handles[0] = root_vh;
        (*md).vnode_ids[0] = 0;

        (*ctx.mount).root_vnode = root_vh;
        (*ctx.mount).flags |= crate::vfs_core::mount::MNT_WIN32_ONLY;

        Ok(Ready(()))
    }
}

unsafe fn pipefs_unmount(ctx: &mut OwnerMountCtx<'_>, _force: bool) -> VfsResult<()> {
    unsafe {
        let data = (*ctx.mount).data;
        if !data.is_null() {
            let bytes = core::mem::size_of::<PipefsMountData>();
            let pages = (bytes + 4095) / 4096;
            crate::server::mem::unmap(data, (pages * 4096) as u64);
            (*ctx.mount).data = core::ptr::null_mut();
        }
        (*ctx.mount).root_vnode = VnodeHandle::INVALID;
        Ok(())
    }
}

unsafe fn pipefs_root(ctx: &OwnerMountCtx<'_>) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*ctx.mount).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

unsafe fn pipefs_vget(ctx: &mut OwnerMountCtx<'_>, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*ctx.mount).data as *mut PipefsMountData;
        for i in 0..(*md).count {
            if (*md).vnode_ids[i] == id && (*md).vnode_handles[i].is_valid() {
                return Ok((*md).vnode_handles[i]);
            }
        }
        Err(VfsError::NotFound)
    }
}

unsafe fn pipefs_statfs(ctx: &OwnerMountCtx<'_>, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*ctx.mount).data as *const PipefsMountData;
        (*out).bsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = (*md).count as u64;
        (*out).ffree = (MAX_PIPEFS_VNODES - (*md).count) as u64;
        (*out).fs_type = [0; 16];
        let ft = &mut (*out).fs_type;
        ft[..6].copy_from_slice(b"pipefs");
        (*out).flags = 0;
        (*out).name_max = 128;
        Ok(())
    }
}

unsafe fn pipefs_sync(_ctx: &OwnerMountCtx<'_>) -> VfsResult<()> {
    Ok(())
}

// =========================================================================
// Static dispatch table
// =========================================================================

pub(super) static PIPEFS_VFSOPS: VfsOps = VfsOps {
    mount: pipefs_mount,
    unmount: pipefs_unmount,
    root: pipefs_root,
    vget: pipefs_vget,
    statfs: pipefs_statfs,
    sync: pipefs_sync,
};
