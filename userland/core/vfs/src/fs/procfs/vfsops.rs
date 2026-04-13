// SPDX-License-Identifier: GPL-2.0-only
//! procfs `VfsOps` — mount, unmount, root, vget, statfs, sync.

use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::mount::Mount;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::vfs::VfsOps;
use crate::vfs_core::vnode::{VnodeHandle, VN_ROOT, VT_DIR};

use super::{encode_id, ProcfsKind, ProcfsMountData};

// =========================================================================
// VfsOps function implementations
// =========================================================================

/// Mount a new procfs instance.
///
/// Allocates `ProcfsMountData` and creates the root directory vnode
/// via the arena trampoline.
///
/// # Safety
///
/// `mp` must be a valid, freshly-allocated `Mount` slot. Arena trampolines
/// must be active.
unsafe fn procfs_mount(
    mp: *mut Mount,
    _source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
) -> VfsResult<()> {
    unsafe {
        let bytes = core::mem::size_of::<ProcfsMountData>();
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return Err(VfsError::NoSpace);
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        (*mp).data = ptr;

        // Root directory vnode — allocated from the global arena.
        let (root_vh, root_vp) = mount_ctl::trampoline_alloc_vnode()
            .ok_or(VfsError::NoSpace)?;
        let mount_handle = mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32)
            .ok_or(VfsError::Io)?;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).id = encode_id(ProcfsKind::Root, 0);
        (*root_vp).flags |= VN_ROOT;
        // Root does NOT get VN_NOCACHE — persists for mount lifetime.
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).ops = &raw const super::PROCFS_VOPS;

        // Set up root vnode data.
        let md = ptr as *mut ProcfsMountData;
        let vd = &raw mut (*md).vdata[0];
        (*vd).kind = ProcfsKind::Root;
        (*vd).pid = 0;
        (*vd).sys_ptr = core::ptr::null();
        (*root_vp).data = vd as *mut u8;
        (*md).count = 1;

        (*mp).root_vnode = root_vh;

        Ok(())
    }
}

/// Unmount procfs. Releases mount-private data.
///
/// # Safety
///
/// `mp` must be a valid pointer to an active procfs mount.
unsafe fn procfs_unmount(mp: *mut Mount, _force: bool) -> VfsResult<()> {
    unsafe {
        let data = (*mp).data;
        if !data.is_null() {
            let bytes = core::mem::size_of::<ProcfsMountData>();
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
/// `mp` must be a valid pointer to an active procfs mount.
unsafe fn procfs_root(mp: *mut Mount) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*mp).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

/// Look up a vnode by id — not meaningful for procfs since vnodes are
/// ephemeral. Always returns NotFound.
unsafe fn procfs_vget(_mp: *mut Mount, _id: u64) -> VfsResult<VnodeHandle> {
    Err(VfsError::NotFound)
}

/// Fill filesystem statistics for procfs.
///
/// procfs is a pseudo-filesystem with no real backing storage.
unsafe fn procfs_statfs(_mp: *mut Mount, out: *mut VStatfs) -> VfsResult<()> {
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

/// Sync — no-op for procfs (no persistent backing store).
unsafe fn procfs_sync(_mp: *mut Mount) -> VfsResult<()> {
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
