// SPDX-License-Identifier: GPL-2.0-only
//
//! pipefs `VfsOps` — `mount`, `unmount`, `root`, `vget`, `statfs`,
//! `sync`. Synthetic Win32-only namespace; mount data is a single
//! page-aligned `PipefsMountData` blob with parallel arrays of
//! handles, ids, and slot pool entries.

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::file::VStatfs;
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::vnode::{VN_ROOT, VnodeHandle, VnodeKind};
use crate::core::vop_context::OwnerMountCtx;

use super::types::{MAX_NAMED_PIPES, NamedPipeSlot};
use super::{MAX_PIPEFS_VNODES, PipefsMountData, PipefsVnodeData};

pub(crate) unsafe fn pipefs_mount(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let bytes = ::core::mem::size_of::<PipefsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoMem);
        }
        ::core::ptr::write_bytes(ptr, 0, pages * 4096);
        (*ctx.mount).data = ptr;

        let md = ptr as *mut PipefsMountData;
        (*md).next_id = 1;
        for i in 0..MAX_PIPEFS_VNODES {
            (*md).vdata[i] = PipefsVnodeData::zeroed();
        }
        for i in 0..MAX_NAMED_PIPES {
            (*md).slots[i] = NamedPipeSlot::zeroed();
        }

        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;

        (*root_vp).kind = VnodeKind::Directory;
        (*root_vp).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(0, 0),
        };
        (*root_vp).backend_seq = 0;
        (*root_vp).flags |= VN_ROOT;
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::PIPEFS_VOPS;

        let vdata = &raw mut (*md).vdata[0];
        *vdata = PipefsVnodeData::zeroed();
        (*vdata).slot_idx = u32::MAX;
        (*vdata).is_root = 1;
        (*root_vp).data = vdata as *mut u8;
        (*md).count = 1;
        (*md).vnode_handles[0] = root_vh;
        (*md).vnode_ids[0] = 0;

        Ok(root_vh)
    }
}

pub(crate) unsafe fn pipefs_unmount(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    unsafe {
        let data = (*ctx.mount).data;
        if !data.is_null() {
            let bytes = ::core::mem::size_of::<PipefsMountData>();
            let pages = (bytes + 4095) / 4096;
            crate::server::mem::unmap(data, (pages * 4096) as u64);
            (*ctx.mount).data = ::core::ptr::null_mut();
        }
        (*ctx.mount).root = Handle::INVALID;
        Ok(())
    }
}

pub(crate) unsafe fn pipefs_root(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let root = (*ctx.mount).root;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

pub(crate) unsafe fn pipefs_vget(
    ctx: &mut OwnerMountCtx<'_>,
    id: u64,
) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *mut PipefsMountData;
        for i in 0..(*md).count {
            if (*md).vnode_ids[i] == id && (*md).vnode_handles[i].is_valid() {
                return Ok((*md).vnode_handles[i]);
            }
        }
        Err(VfsError::NoEnt)
    }
}

pub(crate) unsafe fn pipefs_statfs(
    ctx: &mut OwnerMountCtx<'_>,
    out: *mut VStatfs,
) -> Result<(), VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *const PipefsMountData;
        (*out).bsize = 4096;
        (*out).frsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = (*md).count as u64;
        (*out).ffree = (MAX_PIPEFS_VNODES - (*md).count) as u64;
        (*out).favail = (*out).ffree;
        (*out).fsid = (*ctx.mount).fs_instance_id.0;
        (*out).flag = 0;
        (*out).namemax = 128;
        (*out).set_fs_name(b"pipefs");
        Ok(())
    }
}

pub(crate) unsafe fn pipefs_sync(_ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    Ok(())
}
