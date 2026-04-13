// SPDX-License-Identifier: GPL-2.0-only
//! pipefs `VfsOps` — mount, unmount, root, vget, statfs, sync.

use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::mount::Mount;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::vfs::VfsOps;
use crate::vfs_core::vnode::{VnodeHandle, VN_ROOT, VT_DIR};

use super::{PipefsMountData, MAX_PIPEFS_VNODES};

// =========================================================================
// VfsOps function implementations
// =========================================================================

/// Mount a new pipefs instance.
///
/// Allocates `PipefsMountData`, creates the root directory vnode via the
/// arena trampoline, and stores its handle in `mp.root_vnode`.
///
/// # Safety
///
/// `mp` must be a valid, freshly-allocated `Mount` slot with generic
/// fields already populated by the VFS layer. Arena trampolines must be
/// active (`mount_ctl::set_trampolines` called by `do_mount_with_ops`).
unsafe fn pipefs_mount(
    mp: *mut Mount,
    _source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
) -> VfsResult<()> {
    unsafe {
        let bytes = core::mem::size_of::<PipefsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoSpace);
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        (*mp).data = ptr;

        let md = ptr as *mut PipefsMountData;
        (*md).next_id = 1;

        // Allocate the root directory vnode from the global arena.
        let (root_vh, root_vp) = mount_ctl::trampoline_alloc_vnode()
            .ok_or(VfsError::NoSpace)?;
        let mount_handle = mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32)
            .ok_or(VfsError::Io)?;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).id = 0;
        (*root_vp).flags |= VN_ROOT;
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).ops = &raw const super::PIPEFS_VOPS;

        // Set up root vnode data.
        let vd = &raw mut (*md).vdata[0];
        (*vd).slot_idx = u32::MAX;
        (*vd).is_root = 1;
        (*root_vp).data = vd as *mut u8;
        (*md).count = 1;

        // Record the handle.
        (*md).vnode_handles[0] = root_vh;
        (*md).vnode_ids[0] = 0;

        (*mp).root_vnode = root_vh;
        (*mp).flags |= crate::vfs_core::mount::MNT_WIN32_ONLY;

        Ok(())
    }
}

/// Unmount pipefs. Releases mount-private data.
///
/// # Safety
///
/// `mp` must be a valid pointer to an active pipefs mount.
unsafe fn pipefs_unmount(mp: *mut Mount, _force: bool) -> VfsResult<()> {
    unsafe {
        let data = (*mp).data;
        if !data.is_null() {
            let bytes = core::mem::size_of::<PipefsMountData>();
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
/// `mp` must be a valid pointer to an active pipefs mount.
unsafe fn pipefs_root(mp: *mut Mount) -> VfsResult<VnodeHandle> {
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
/// # Safety
///
/// `mp` must be a valid pointer to an active pipefs mount.
unsafe fn pipefs_vget(mp: *mut Mount, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*mp).data as *mut PipefsMountData;
        for i in 0..(*md).count {
            if (*md).vnode_ids[i] == id && (*md).vnode_handles[i].is_valid() {
                return Ok((*md).vnode_handles[i]);
            }
        }
        Err(VfsError::NotFound)
    }
}

/// Fill filesystem statistics for pipefs.
unsafe fn pipefs_statfs(mp: *mut Mount, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*mp).data as *const PipefsMountData;
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

/// Sync — no-op for pipefs (no persistent backing store).
unsafe fn pipefs_sync(_mp: *mut Mount) -> VfsResult<()> {
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
