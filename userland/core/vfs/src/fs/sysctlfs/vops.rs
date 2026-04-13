// SPDX-License-Identifier: GPL-2.0-only
//! sysctlfs `VopVector` — per-vnode operations for the sysctl virtual filesystem.
//!
//! Node vnodes (directories) dispatch to `SysctlNode` children; leaf vnodes
//! (regular files) invoke provider callbacks for read/write.
//! All non-root vnodes carry `VN_NOCACHE` and are reclaimed by the arena
//! after last close.

use crate::personality::posix::consts::{S_IFDIR_L, S_IFREG_L};
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::vnode::{VnodeHandle, VN_NOCACHE, VT_DIR, VT_REG};
use crate::vfs_core::vop::{
    ReaddirEmit, VopDataOps, VopMetaOps, VopVector, DATA_OPS_DEFAULT, META_OPS_DEFAULT,
};
use crate::vfs_core::vop_context::{VopContext, VopDataContext};

use super::tree::{SysctlLeaf, SysctlNode, MIB_ROOT, CTLFLAG_WR};
use super::{encode_id, SysctlfsKind, SysctlfsVnodeData};

/// Content generation buffer size for leaf reads.
const SYSCTL_BUF_SIZE: usize = 512;

// =========================================================================
// Helpers
// =========================================================================

#[inline]
unsafe fn vdata(ctx: &VopContext) -> *mut SysctlfsVnodeData {
    ctx.data as *mut SysctlfsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataContext) -> *mut SysctlfsVnodeData {
    ctx.data as *mut SysctlfsVnodeData
}

#[inline]
fn name_eq(a: *const u8, a_len: u8, b: &[u8]) -> bool {
    if a_len as usize != b.len() {
        return false;
    }
    for i in 0..b.len() {
        if unsafe { *a.add(i) } != b[i] {
            return false;
        }
    }
    true
}

// =========================================================================
// MetaOps
// =========================================================================

/// Look up a child by name in a sysctlfs directory vnode.
///
/// Allocates a fresh ephemeral vnode (VN_NOCACHE) for each successful
/// lookup via `ctx.alloc`.
unsafe fn sysctlfs_lookup(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);

        // "." — self reference.
        if name_len == 1 && *name == b'.' {
            return Ok(ctx.handle);
        }

        // ".." — parent is root for all subdirs; root's parent is itself.
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            // Resolve the root vnode handle from the mount.
            if !ctx.mount.is_null() {
                let root_vh = (*ctx.mount).root_vnode;
                if root_vh.is_valid() {
                    return Ok(root_vh);
                }
            }
            return Ok(ctx.handle);
        }

        // Resolve which SysctlNode we are looking inside.
        let node_ptr = match (*dvd).kind {
            SysctlfsKind::Root => &raw const MIB_ROOT as *const SysctlNode,
            SysctlfsKind::Node => (*dvd).node,
            SysctlfsKind::Leaf => return Err(VfsError::NotDir),
        };
        if node_ptr.is_null() {
            return Err(VfsError::Io);
        }
        let node = &*node_ptr;

        let name_slice = core::slice::from_raw_parts(name, name_len as usize);

        // Check child nodes first (directories).
        if let Some(child) = node.find_child_node(name_slice) {
            let child_ptr = child as *const SysctlNode;
            let (vh, vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
            (*vp).vtype = VT_DIR;
            (*vp).flags = VN_NOCACHE;
            (*vp).id = encode_id(SysctlfsKind::Node, child_ptr);
            (*vp).mount = ctx.mount_handle;
            (*vp).ops = (*ctx.vnode).ops;
            (*vp).nlink = 2;

            // Allocate vnode data from mount-private pool.
            let vd = super::alloc_vdata(ctx.mount_data);
            if vd.is_null() {
                return Err(VfsError::NoSpace);
            }
            (*vd).kind = SysctlfsKind::Node;
            (*vd).node = child_ptr;
            (*vp).data = vd as *mut u8;

            return Ok(vh);
        }

        // Check leaves (regular files).
        if let Some(leaf) = node.find_leaf(name_slice) {
            let leaf_ptr = leaf as *const SysctlLeaf as *const SysctlNode;
            let (vh, vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
            (*vp).vtype = VT_REG;
            (*vp).flags = VN_NOCACHE;
            (*vp).id = encode_id(SysctlfsKind::Leaf, leaf_ptr);
            (*vp).mount = ctx.mount_handle;
            (*vp).ops = (*ctx.vnode).ops;
            (*vp).nlink = 1;

            let vd = super::alloc_vdata(ctx.mount_data);
            if vd.is_null() {
                return Err(VfsError::NoSpace);
            }
            (*vd).kind = SysctlfsKind::Leaf;
            (*vd).node = leaf_ptr;
            (*vp).data = vd as *mut u8;

            return Ok(vh);
        }

        // Not found.
        Ok(VnodeHandle::INVALID)
    }
}

unsafe fn sysctlfs_getattr(ctx: &VopContext, attr: *mut VAttr) -> VfsResult<()> {
    unsafe {
        let vd = vdata(ctx);

        (*attr).uid = 0;
        (*attr).gid = 0;
        (*attr).nlink = (*ctx.vnode).nlink;
        (*attr).atime = 0;
        (*attr).mtime = 0;
        (*attr).ctime = 0;
        (*attr).btime = 0;
        (*attr).blocks = 0;
        (*attr).dev_id = 0;
        (*attr).rdev = 0;
        (*attr).size = 0;

        match (*vd).kind {
            SysctlfsKind::Root | SysctlfsKind::Node => {
                (*attr).mode = S_IFDIR_L | 0o555;
                (*attr).nlink = 2;
            }
            SysctlfsKind::Leaf => {
                let leaf = (*vd).node as *const SysctlLeaf;
                let writable = if !leaf.is_null() {
                    (*leaf).flags & CTLFLAG_WR != 0
                } else {
                    false
                };
                if writable {
                    (*attr).mode = S_IFREG_L | 0o644;
                } else {
                    (*attr).mode = S_IFREG_L | 0o444;
                }
            }
        }

        Ok(())
    }
}

unsafe fn sysctlfs_access(
    _ctx: &VopContext,
    _mode: u32,
    _cred: *const VfsCred,
) -> VfsResult<()> {
    Ok(())
}

unsafe fn sysctlfs_open(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

unsafe fn sysctlfs_close(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

unsafe fn sysctlfs_inactive(_ctx: &VopContext) {}

// =========================================================================
// DataOps
// =========================================================================

unsafe fn sysctlfs_readdir(
    ctx: &VopDataContext,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VfsResult<()> {
    unsafe {
        let vd = vdata_d(ctx);
        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        let node_ptr = match (*vd).kind {
            SysctlfsKind::Root => &raw const MIB_ROOT as *const SysctlNode,
            SysctlfsKind::Node => (*vd).node,
            _ => return Err(VfsError::NotDir),
        };
        if node_ptr.is_null() {
            return Err(VfsError::Io);
        }
        let node = &*node_ptr;

        // "."
        if pos == 0 {
            if !emit(ctx.id, b".".as_ptr(), 1, 4 /* DT_DIR */, &attr) {
                *cookie = pos + 1;
                return Ok(());
            }
            pos += 1;
        }

        // ".." — root id is encode_id(Root, null) = 0.
        if pos == 1 {
            let parent_id = encode_id(SysctlfsKind::Root, core::ptr::null());
            if !emit(parent_id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = pos + 1;
                return Ok(());
            }
            pos += 1;
        }

        // Child nodes (directories).
        let child_base = 2u64;
        let child_count = node.child_node_count;
        let child_start = if pos >= child_base {
            (pos - child_base) as usize
        } else {
            0
        };
        for i in child_start..child_count {
            let entry_pos = child_base + i as u64;
            if pos > entry_pos {
                continue;
            }
            let child = &*node.child_nodes.add(i);
            if !emit(
                0,
                child.name.as_ptr(),
                child.name_len,
                4, // DT_DIR
                &attr,
            ) {
                *cookie = entry_pos + 1;
                return Ok(());
            }
            pos = entry_pos + 1;
        }

        // Leaves (regular files).
        let leaf_base = child_base + child_count as u64;
        let leaf_start = if pos >= leaf_base {
            (pos - leaf_base) as usize
        } else {
            0
        };
        for i in leaf_start..node.leaf_count {
            let entry_pos = leaf_base + i as u64;
            if pos > entry_pos {
                continue;
            }
            let leaf = &node.leaves[i];
            if !emit(
                0,
                leaf.name.as_ptr(),
                leaf.name_len,
                8, // DT_REG
                &attr,
            ) {
                *cookie = entry_pos + 1;
                return Ok(());
            }
            pos = entry_pos + 1;
        }

        *cookie = pos;
        Ok(())
    }
}

unsafe fn sysctlfs_read(
    ctx: &VopDataContext,
    offset: u64,
    dst: *mut u8,
    len: u64,
) -> VfsResult<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if (*vd).kind != SysctlfsKind::Leaf {
            return Err(VfsError::IsDir);
        }

        let leaf = (*vd).node as *const SysctlLeaf;
        if leaf.is_null() {
            return Err(VfsError::Io);
        }
        let read_fn = match (*leaf).read_fn {
            Some(f) => f,
            None => return Err(VfsError::NotSupported),
        };

        let mut content = [0u8; SYSCTL_BUF_SIZE];
        let content_len = read_fn(content.as_mut_ptr(), SYSCTL_BUF_SIZE);

        if offset as usize >= content_len {
            return Ok(0);
        }

        let available = content_len - offset as usize;
        let to_copy = if (len as usize) < available {
            len as usize
        } else {
            available
        };

        core::ptr::copy_nonoverlapping(
            content.as_ptr().add(offset as usize),
            dst,
            to_copy,
        );
        Ok(to_copy as u64)
    }
}

unsafe fn sysctlfs_write(
    ctx: &VopDataContext,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VfsResult<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if (*vd).kind != SysctlfsKind::Leaf {
            return Err(VfsError::IsDir);
        }

        let leaf = (*vd).node as *const SysctlLeaf;
        if leaf.is_null() {
            return Err(VfsError::Io);
        }
        if (*leaf).flags & CTLFLAG_WR == 0 {
            return Err(VfsError::Perm);
        }
        let write_fn = match (*leaf).write_fn {
            Some(f) => f,
            None => return Err(VfsError::NotSupported),
        };

        let result = write_fn(src, len as usize);
        if result != 0 {
            return Err(VfsError::Inval);
        }
        Ok(len)
    }
}

unsafe fn sysctlfs_statfs(_ctx: &VopDataContext, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        (*out).bsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = 0;
        (*out).ffree = 0;
        (*out).fs_type = [0; 16];
        (&mut (*out).fs_type)[..8].copy_from_slice(b"sysctlfs");
        (*out).flags = 0;
        (*out).name_max = 255;
        Ok(())
    }
}

// =========================================================================
// Static dispatch table
// =========================================================================

pub(super) static SYSCTLFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: sysctlfs_lookup,
        getattr: sysctlfs_getattr,
        access: sysctlfs_access,
        open: sysctlfs_open,
        close: sysctlfs_close,
        inactive: sysctlfs_inactive,
        ..META_OPS_DEFAULT
    },
    data: VopDataOps {
        readdir: sysctlfs_readdir,
        read: sysctlfs_read,
        write: sysctlfs_write,
        statfs: sysctlfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
