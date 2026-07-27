// SPDX-License-Identifier: GPL-2.0-only
//! Tmpfs VfsOps implementation — filesystem-level operations.

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_alloc_array;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::outcome::{VopControl::Ready, VopOutcome};
use crate::vfs_core::vnode::{VN_ROOT, VT_DIR, VnodeHandle};
use crate::vfs_core::vop_context::OwnerMountCtx;

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
    ctx: &mut OwnerMountCtx<'_>,
    _source: u64,
    opts_ptr: *const u8,
    opts_len: u8,
    _can_park: bool,
) -> VopOutcome<()> {
    unsafe {
        let md: *mut TmpfsMountData = vfs_alloc_array::<TmpfsMountData>(1);
        if md.is_null() {
            return Err(VfsError::NoSpace);
        }
        *md = TmpfsMountData::zeroed();
        (*ctx.mount).data = md as *mut u8;

        if let Some(sz) = parse_opt_u64(opts_ptr, opts_len, b"size") {
            (*md).max_bytes = sz;
        }
        if let Some(nr) = parse_opt_u64(opts_ptr, opts_len, b"nr_inodes") {
            (*md).max_inodes = nr as u32;
        }

        if pool::init_pools(md) != 0 {
            return Err(VfsError::NoSpace);
        }

        let root_vd = pool::alloc_vdata(md);
        if root_vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        let root_id = pool::next_id(md);
        (*root_vd).id = root_id;
        (*root_vd).parent_id = 0;
        (*root_vd).ftype = VT_DIR;
        (*root_vd).mode = S_IFDIR_L | 0o1777;
        (*root_vd).nlink = 2;

        let dirents = vfs_alloc_array::<super::types::Dirent>(INITIAL_DIRENTS);
        if dirents.is_null() {
            (*root_vd).active = 0;
            return Err(VfsError::NoSpace);
        }
        (*root_vd).dirents = dirents;
        (*root_vd).dirents_cap = INITIAL_DIRENTS as u16;

        let (root_vh, root_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*root_vp).id = root_id;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).flags = VN_ROOT;
        (*root_vp).data = root_vd as *mut u8;
        (*root_vp).nlink = 2;
        (*root_vp).mount.set(fs_instance_id, mount_handle);
        (*root_vp).fs_instance_id = fs_instance_id;
        (*root_vp).ops = &raw const super::TMPFS_VOPS;
        (*root_vd).vnode_handle = root_vh;

        (*ctx.mount).root_vnode = root_vh;
        (*md).used_inodes = 1;

        Ok(Ready(()))
    }
}

pub(super) unsafe fn tmpfs_unmount(ctx: &mut OwnerMountCtx<'_>, _force: bool) -> VfsResult<()> {
    unsafe {
        (*ctx.mount).root_vnode = VnodeHandle::INVALID;
        (*ctx.mount).data = core::ptr::null_mut();
        Ok(())
    }
}

pub(super) unsafe fn tmpfs_root(ctx: &OwnerMountCtx<'_>) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*ctx.mount).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

pub(super) unsafe fn tmpfs_vget(ctx: &mut OwnerMountCtx<'_>, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*ctx.mount).data as *mut TmpfsMountData;

        let vd = pool::find_vdata(md, id);
        if vd.is_null() {
            return Err(VfsError::NotFound);
        }

        if (*vd).vnode_handle.is_valid() && ctx.state.vnodes.raw_ptr((*vd).vnode_handle).is_some() {
            return Ok((*vd).vnode_handle);
        }

        let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vp).id = id;
        (*vp).vtype = (*vd).ftype;
        (*vp).data = vd as *mut u8;
        (*vp).nlink = (*vd).nlink;
        (*vp).mount.set(fs_instance_id, mount_handle);
        (*vp).fs_instance_id = fs_instance_id;
        (*vp).ops = &raw const super::TMPFS_VOPS;
        (*vd).vnode_handle = vh;
        Ok(vh)
    }
}

pub(super) unsafe fn tmpfs_statfs(ctx: &OwnerMountCtx<'_>, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*ctx.mount).data as *mut TmpfsMountData;
        (*out).bsize = WRITABLE_SIZE as u64;
        (*out).name_max = MAX_NAME_LEN as u32;
        let ft = &mut (*out).fs_type;
        ft[..5].copy_from_slice(b"tmpfs");
        (*out).flags = (*ctx.mount).flags;

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

pub(super) unsafe fn tmpfs_sync(_ctx: &OwnerMountCtx<'_>) -> VfsResult<()> {
    Ok(())
}
