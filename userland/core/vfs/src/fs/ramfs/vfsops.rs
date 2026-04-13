// SPDX-License-Identifier: GPL-2.0-only
//! Ramfs VfsOps implementation — filesystem-level operations.

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_alloc_array;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::mount::Mount;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::vnode::{VnodeHandle, VN_ROOT, VT_DIR};

use super::pool;
use super::types::RamfsMountData;

// =========================================================================
// VfsOps function implementations
// =========================================================================

/// Initialize a fresh ramfs mount.
///
/// Allocates all pools, creates the root vnode (via arena trampoline),
/// and sets `mp.root_vnode`.
pub(super) unsafe fn ramfs_mount(
    mp: *mut Mount,
    _source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
) -> VfsResult<()> {
    unsafe {
        // Allocate mount-private data
        let md: *mut RamfsMountData = vfs_alloc_array::<RamfsMountData>(1);
        if md.is_null() {
            return Err(VfsError::NoSpace);
        }
        *md = RamfsMountData::zeroed();
        (*mp).data = md as *mut u8;

        // Initialize pools
        if pool::init_pools(md) != 0 {
            return Err(VfsError::NoSpace);
        }

        // Create root vnode data
        let root_vd = pool::alloc_vdata(md);
        if root_vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        let root_id = pool::next_id(md);
        (*root_vd).id = root_id;
        (*root_vd).parent_id = 0;
        (*root_vd).ftype = VT_DIR;
        (*root_vd).mode = S_IFDIR_L | 0o755;
        (*root_vd).nlink = 2;

        // Allocate dirents for root
        let dirents = vfs_alloc_array::<super::types::Dirent>(INITIAL_DIRENTS);
        if dirents.is_null() {
            (*root_vd).active = 0;
            return Err(VfsError::NoSpace);
        }
        (*root_vd).dirents = dirents;
        (*root_vd).dirents_cap = INITIAL_DIRENTS as u16;

        // Allocate root vnode from the central arena via trampoline.
        // The caller (do_mount_with_ops) sets up the trampoline before
        // calling VfsOps::mount.
        let (root_vh, root_vp) = mount_ctl::trampoline_alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle =
            mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32).ok_or(VfsError::Io)?;
        (*root_vp).id = root_id;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).flags = VN_ROOT;
        (*root_vp).data = root_vd as *mut u8;
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).ops = &raw const super::RAMFS_VOPS;
        (*root_vd).vnode_handle = root_vh;

        (*mp).root_vnode = root_vh;
        Ok(())
    }
}

/// Tear down all ramfs state.
pub(super) unsafe fn ramfs_unmount(mp: *mut Mount, _force: bool) -> VfsResult<()> {
    unsafe {
        (*mp).root_vnode = VnodeHandle::INVALID;
        (*mp).data = core::ptr::null_mut();
        Ok(())
    }
}

/// Return the root vnode handle of this mount.
pub(super) unsafe fn ramfs_root(mp: *mut Mount) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*mp).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

/// Look up a vnode by its backend id, allocating a cache slot if needed.
pub(super) unsafe fn ramfs_vget(mp: *mut Mount, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*mp).data as *mut RamfsMountData;

        // Find the vnode data
        let vd = pool::find_vdata(md, id);
        if vd.is_null() {
            return Err(VfsError::NotFound);
        }

        if (*vd).vnode_handle.is_valid()
            && crate::vfs_core::mount_ctl::vnode_resolve_trampoline((*vd).vnode_handle).is_some()
        {
            return Ok((*vd).vnode_handle);
        }

        // Allocate a new vnode from the arena via trampoline.
        let (vh, vp) = mount_ctl::trampoline_alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle =
            mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32).ok_or(VfsError::Io)?;
        (*vp).id = id;
        (*vp).vtype = (*vd).ftype;
        (*vp).data = vd as *mut u8;
        (*vp).nlink = (*vd).nlink;
        (*vp).mount = mount_handle;
        (*vp).ops = &raw const super::RAMFS_VOPS;
        (*vd).vnode_handle = vh;
        Ok(vh)
    }
}

/// Fill filesystem-level statistics.
pub(super) unsafe fn ramfs_statfs(mp: *mut Mount, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*mp).data as *mut RamfsMountData;
        (*out).bsize = WRITABLE_SIZE as u64;
        (*out).name_max = MAX_NAME_LEN as u32;
        let ft = &mut (*out).fs_type;
        ft[..5].copy_from_slice(b"ramfs");
        (*out).flags = (*mp).flags;

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
        (*out).files = files;
        (*out).ffree = (*md).vdata_cap as u64 - files;
        (*out).blocks = (*md).writable_cap as u64;
        (*out).bfree = (*md).writable_cap as u64 - used_blocks;
        (*out).bavail = (*out).bfree;
        Ok(())
    }
}

/// Sync — no-op for in-memory filesystem.
pub(super) unsafe fn ramfs_sync(_mp: *mut Mount) -> VfsResult<()> {
    Ok(())
}
