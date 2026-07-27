// SPDX-License-Identifier: GPL-2.0-only
//
//! procfs `VfsOps` — synthetic filesystem with no persistent
//! storage. Mount allocates the per-mount vdata pool and seeds the
//! root directory; everything else is generated on demand by the
//! `vops` layer.

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::file::VStatfs;
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::vnode::{VN_ROOT, VnodeHandle, VnodeKind};
use crate::core::vop_context::OwnerMountCtx;

use super::{ProcfsKind, ProcfsMountData, encode_id};

pub(crate) unsafe fn procfs_mount(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let bytes = ::core::mem::size_of::<ProcfsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoMem);
        }
        ::core::ptr::write(ptr as *mut ProcfsMountData, ProcfsMountData::zeroed());
        (*ctx.mount).data = ptr;

        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*root_vp).kind = VnodeKind::Directory;
        (*root_vp).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(encode_id(ProcfsKind::Root, 0), 0),
        };
        (*root_vp).backend_seq = 0;
        (*root_vp).flags |= VN_ROOT;
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::PROCFS_VOPS;

        let md = ptr as *mut ProcfsMountData;
        let vdata = &raw mut (*md).vdata[0];
        (*vdata).kind = ProcfsKind::Root;
        (*vdata).pid = 0;
        (*vdata).sys_ptr = ::core::ptr::null();
        (*root_vp).data = vdata as *mut u8;
        (*md).count = 1;

        Ok(root_vh)
    }
}

pub(crate) unsafe fn procfs_unmount(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    unsafe {
        let data = (*ctx.mount).data;
        if !data.is_null() {
            let bytes = ::core::mem::size_of::<ProcfsMountData>();
            let pages = (bytes + 4095) / 4096;
            crate::server::mem::unmap(data, (pages * 4096) as u64);
            (*ctx.mount).data = ::core::ptr::null_mut();
        }
        (*ctx.mount).root = Handle::INVALID;
        Ok(())
    }
}

pub(crate) unsafe fn procfs_root(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let root = (*ctx.mount).root;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

pub(crate) unsafe fn procfs_vget(
    _ctx: &mut OwnerMountCtx<'_>,
    _id: u64,
) -> Result<VnodeHandle, VfsError> {
    // procfs vnodes are constructed on lookup (every node carries
    // `VN_NOCACHE` so they reach `inactive` right after the last
    // close); a vget revisit by id has no cached state to find.
    Err(VfsError::NoEnt)
}

pub(crate) unsafe fn procfs_statfs(
    ctx: &mut OwnerMountCtx<'_>,
    out: *mut VStatfs,
) -> Result<(), VfsError> {
    unsafe {
        (*out).bsize = 4096;
        (*out).frsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = 0;
        (*out).ffree = 0;
        (*out).favail = 0;
        (*out).fsid = (*ctx.mount).fs_instance_id.0;
        (*out).flag = 0;
        (*out).namemax = 255;
        (*out).set_fs_name(b"procfs");
        Ok(())
    }
}

pub(crate) unsafe fn procfs_sync(_ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    Ok(())
}
