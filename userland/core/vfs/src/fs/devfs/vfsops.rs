// SPDX-License-Identifier: GPL-2.0-only
//! devfs `VfsOps` — mount, unmount, root, vget, statfs, sync.

use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::mount::Mount;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::vfs::VfsOps;
use crate::vfs_core::vnode::{VnodeHandle, VN_ROOT, VT_CHR, VT_DIR};

use super::{
    alloc_vdata, record_vnode, DevKind, DevfsMountData, DEVFS_REGISTRATIONS,
    MAX_DEVFS_VNODES,
};

// =========================================================================
// VfsOps function implementations
// =========================================================================

/// Mount a new devfs instance.
///
/// Allocates `DevfsMountData`, populates the root directory vnode and one
/// vnode per static registration entry, plus the synthetic `pts/` directory.
/// All vnodes are allocated from the global arena via trampolines.
///
/// # Safety
///
/// `mp` must be a valid, freshly-allocated `Mount` slot. Arena trampolines
/// must be active.
unsafe fn devfs_mount(
    mp: *mut Mount,
    _source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
) -> VfsResult<()> {
    unsafe {
        let bytes = core::mem::size_of::<DevfsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoSpace);
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        (*mp).data = ptr;

        let mount_handle = (*mp).id as u32;

        // id 0: root directory vnode.
        let (root_vh, root_vp) = mount_ctl::trampoline_alloc_vnode()
            .ok_or(VfsError::NoSpace)?;
        let mount_handle_h = mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32)
            .ok_or(VfsError::Io)?;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).id = 0;
        (*root_vp).flags |= VN_ROOT;
        // Root has nlink = 2 (self + ".") by convention; "pts" subdir adds +1.
        (*root_vp).nlink = 3;
        (*root_vp).mount = mount_handle_h;
        (*root_vp).ops = &raw const super::DEVFS_VOPS;

        let vd = alloc_vdata(ptr);
        if vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        (*vd).kind = DevKind::Console; // Root reuses Console kind slot; kind unused for dirs.
        (*vd).sub_id = 0;
        (*vd).mode = 0o040755;
        (*root_vp).data = vd as *mut u8;
        record_vnode(ptr, root_vh, 0);

        (*mp).root_vnode = root_vh;

        // Populate one vnode per static device entry.
        let mut id: u64 = 1;
        for reg in DEVFS_REGISTRATIONS {
            let (vh, vp) = mount_ctl::trampoline_alloc_vnode()
                .ok_or(VfsError::NoSpace)?;
            (*vp).vtype = VT_CHR;
            (*vp).id = id;
            (*vp).nlink = 1;
            (*vp).mount = mount_handle_h;
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
        let (pts_vh, pts_vp) = mount_ctl::trampoline_alloc_vnode()
            .ok_or(VfsError::NoSpace)?;
        (*pts_vp).vtype = VT_DIR;
        (*pts_vp).id = id;
        (*pts_vp).nlink = 2;
        (*pts_vp).mount = mount_handle_h;
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

        Ok(())
    }
}

/// Unmount devfs. Releases mount-private data.
///
/// # Safety
///
/// `mp` must be a valid pointer to an active devfs mount.
unsafe fn devfs_unmount(mp: *mut Mount, _force: bool) -> VfsResult<()> {
    unsafe {
        let data = (*mp).data;
        if !data.is_null() {
            let bytes = core::mem::size_of::<DevfsMountData>();
            let pages = (bytes + 4095) / 4096;
            crate::server::mem::unmap(data, (pages * 4096) as u64);
            (*mp).data = core::ptr::null_mut();
        }
        (*mp).root_vnode = VnodeHandle::INVALID;
        Ok(())
    }
}

/// Return the root vnode handle.
///
/// # Safety
///
/// `mp` must be a valid pointer to an active devfs mount.
unsafe fn devfs_root(mp: *mut Mount) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*mp).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

/// Look up a vnode by its backend-specific id.
///
/// Searches the parallel arrays for a matching id.
///
/// # Safety
///
/// `mp` must be a valid pointer to an active devfs mount.
unsafe fn devfs_vget(mp: *mut Mount, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*mp).data as *const DevfsMountData;
        for i in 0..(*md).count {
            if (*md).vnode_ids[i] == id {
                return Ok((*md).vnode_handles[i]);
            }
        }
        Err(VfsError::NotFound)
    }
}

/// Fill filesystem statistics for devfs.
unsafe fn devfs_statfs(mp: *mut Mount, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*mp).data as *const DevfsMountData;
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

/// Sync — no-op for devfs (no persistent backing store).
unsafe fn devfs_sync(_mp: *mut Mount) -> VfsResult<()> {
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
