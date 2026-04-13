// SPDX-License-Identifier: GPL-2.0-only
//! Tmpfs VfsOps implementation — filesystem-level operations.

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_alloc_array;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::mount::Mount;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::vnode::{VnodeHandle, VN_ROOT, VT_DIR};

use super::pool;
use super::types::{TmpfsMountData, TmpfsVnodeData};

// =========================================================================
// Mount option parsing
// =========================================================================

/// Parse a single "key=value" pair from mount options.
/// Returns the value as u64 if the key matches, None otherwise.
unsafe fn parse_opt_u64(opts: *const u8, opts_len: u8, key: &[u8]) -> Option<u64> {
    if opts.is_null() || opts_len == 0 {
        return None;
    }
    let len = opts_len as usize;
    // Scan for "key=" prefix
    let key_eq_len = key.len() + 1; // "key="
    if len < key_eq_len + 1 {
        return None;
    }

    let mut pos = 0usize;
    while pos < len {
        // Find start of this option (skip commas)
        while pos < len && unsafe { *opts.add(pos) } == b',' {
            pos += 1;
        }
        if pos >= len {
            break;
        }

        // Check if this option starts with "key="
        let remaining = len - pos;
        if remaining >= key_eq_len {
            let mut matches = true;
            for i in 0..key.len() {
                if unsafe { *opts.add(pos + i) } != key[i] {
                    matches = false;
                    break;
                }
            }
            if matches && unsafe { *opts.add(pos + key.len()) } == b'=' {
                // Parse the value
                let val_start = pos + key_eq_len;
                let mut val_end = val_start;
                while val_end < len && unsafe { *opts.add(val_end) } != b',' {
                    val_end += 1;
                }
                return unsafe { parse_decimal(opts, val_start, val_end) };
            }
        }

        // Skip to next comma or end
        while pos < len && unsafe { *opts.add(pos) } != b',' {
            pos += 1;
        }
    }

    None
}

/// Parse a decimal number from raw bytes at [start..end).
unsafe fn parse_decimal(buf: *const u8, start: usize, end: usize) -> Option<u64> {
    if start >= end {
        return None;
    }
    let mut val: u64 = 0;
    for i in start..end {
        let c = unsafe { *buf.add(i) };
        if c < b'0' || c > b'9' {
            return None;
        }
        val = val.wrapping_mul(10).wrapping_add((c - b'0') as u64);
    }
    Some(val)
}

// =========================================================================
// VfsOps function implementations
// =========================================================================

/// Initialize a fresh tmpfs mount.
///
/// Allocates all pools, parses mount options (size=, nr_inodes=),
/// creates the root vnode (via arena trampoline), and sets `mp.root_vnode`.
pub(super) unsafe fn tmpfs_mount(
    mp: *mut Mount,
    _source: u64,
    opts_ptr: *const u8,
    opts_len: u8,
) -> VfsResult<()> {
    unsafe {
        // Allocate mount-private data
        let md: *mut TmpfsMountData = vfs_alloc_array::<TmpfsMountData>(1);
        if md.is_null() {
            return Err(VfsError::NoSpace);
        }
        *md = TmpfsMountData::zeroed();
        (*mp).data = md as *mut u8;

        // Parse mount options
        if let Some(sz) = parse_opt_u64(opts_ptr, opts_len, b"size") {
            (*md).max_bytes = sz;
        }
        if let Some(nr) = parse_opt_u64(opts_ptr, opts_len, b"nr_inodes") {
            (*md).max_inodes = nr as u32;
        }

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
        // tmpfs root is sticky (mode 1777) like /tmp
        (*root_vd).mode = S_IFDIR_L | 0o1777;
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
        let (root_vh, root_vp) = mount_ctl::trampoline_alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle =
            mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32).ok_or(VfsError::Io)?;
        (*root_vp).id = root_id;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).flags = VN_ROOT;
        (*root_vp).data = root_vd as *mut u8;
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).ops = &raw const super::TMPFS_VOPS;
        (*root_vd).vnode_handle = root_vh;

        (*mp).root_vnode = root_vh;

        // Account for root inode
        (*md).used_inodes = 1;

        Ok(())
    }
}

/// Tear down all tmpfs state.
pub(super) unsafe fn tmpfs_unmount(mp: *mut Mount, _force: bool) -> VfsResult<()> {
    unsafe {
        (*mp).root_vnode = VnodeHandle::INVALID;
        (*mp).data = core::ptr::null_mut();
        Ok(())
    }
}

/// Return the root vnode handle of this mount.
pub(super) unsafe fn tmpfs_root(mp: *mut Mount) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*mp).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

/// Look up a vnode by its backend id, allocating a cache slot if needed.
pub(super) unsafe fn tmpfs_vget(mp: *mut Mount, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*mp).data as *mut TmpfsMountData;

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
        (*vp).ops = &raw const super::TMPFS_VOPS;
        (*vd).vnode_handle = vh;
        Ok(vh)
    }
}

/// Fill filesystem-level statistics.
pub(super) unsafe fn tmpfs_statfs(mp: *mut Mount, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*mp).data as *mut TmpfsMountData;
        (*out).bsize = WRITABLE_SIZE as u64;
        (*out).name_max = MAX_NAME_LEN as u32;
        let ft = &mut (*out).fs_type;
        ft[..5].copy_from_slice(b"tmpfs");
        (*out).flags = (*mp).flags;

        (*out).files = (*md).used_inodes as u64;
        if (*md).max_inodes > 0 {
            (*out).ffree = ((*md).max_inodes - (*md).used_inodes) as u64;
        } else {
            (*out).ffree = (*md).vdata_cap as u64 - (*md).used_inodes as u64;
        }

        if (*md).max_bytes > 0 {
            (*out).blocks = (*md).max_bytes / WRITABLE_SIZE as u64;
            let used_blocks = (*md).used_bytes / WRITABLE_SIZE as u64;
            (*out).bfree = (*out).blocks - used_blocks;
            (*out).bavail = (*out).bfree;
        } else {
            // Count actual writable pool usage
            let mut used_blocks: u64 = 0;
            for i in 0..(*md).writable_cap {
                if *(*md).writable_used_ptr.add(i) != 0 {
                    used_blocks += 1;
                }
            }
            (*out).blocks = (*md).writable_cap as u64;
            (*out).bfree = (*md).writable_cap as u64 - used_blocks;
            (*out).bavail = (*out).bfree;
        }

        Ok(())
    }
}

/// Sync — no-op for in-memory filesystem.
pub(super) unsafe fn tmpfs_sync(_mp: *mut Mount) -> VfsResult<()> {
    Ok(())
}
