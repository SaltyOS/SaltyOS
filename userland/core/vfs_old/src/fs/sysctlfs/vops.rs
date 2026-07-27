// SPDX-License-Identifier: GPL-2.0-only
//! sysctlfs `VopVector` — per-vnode operations for the sysctl virtual filesystem.
//!
//! Node vnodes (directories) dispatch to `SysctlNode` children; leaf vnodes
//! (regular files) invoke provider callbacks for read/write.
//! All non-root vnodes carry `VN_NOCACHE` and are reclaimed by the arena
//! after last close.

use crate::personality::posix::consts::{S_IFDIR_L, S_IFREG_L};
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::outcome::{Ready, VopOutcome};
use crate::vfs_core::vnode::{VN_NOCACHE, VT_DIR, VT_REG, VnodeHandle};
use crate::vfs_core::vop::{
    DATA_OPS_DEFAULT, DataExecMode, META_OPS_DEFAULT, ReaddirEmit, VopDataOps, VopMetaOps,
    VopVector,
};
use crate::vfs_core::vop_context::{OwnerVopCtx, WorkerIoCtx};

use super::tree::{CTLFLAG_WR, DynamicDir, MIB_ROOT, SysctlLeaf, SysctlNode};
use super::{SysctlfsKind, SysctlfsVnodeData, encode_dynleaf_id, encode_id};

/// Content generation buffer size for leaf reads.
/// Must be large enough for kern.proc.all (N × 128-byte KinfoProc).
const SYSCTL_BUF_SIZE: usize = 4096;

// =========================================================================
// Helpers
// =========================================================================

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut SysctlfsVnodeData {
    ctx.data as *mut SysctlfsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &WorkerIoCtx) -> *mut SysctlfsVnodeData {
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
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);

        // "." — self reference.
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }

        // ".." — parent is root for all subdirs; root's parent is itself.
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            // Resolve the root vnode handle from the mount.
            if !ctx.mount.is_null() {
                let root_vh = (*ctx.mount).root_vnode;
                if root_vh.is_valid() {
                    return Ok(Ready(root_vh));
                }
            }
            return Ok(Ready(ctx.handle));
        }

        // Resolve which SysctlNode we are looking inside.
        // DynDir lookups go through the DynamicDir path below.
        let node_ptr = match (*dvd).kind {
            SysctlfsKind::Root => &raw const MIB_ROOT as *const SysctlNode,
            SysctlfsKind::Node => (*dvd).node,
            SysctlfsKind::Leaf | SysctlfsKind::DynLeaf => return Err(VfsError::NotDir),
            SysctlfsKind::DynDir => {
                // Delegate to the DynamicDir lookup function.
                let dyn_ptr = (*dvd).node as *const DynamicDir;
                if dyn_ptr.is_null() {
                    return Err(VfsError::Io);
                }
                let dyn_dir = &*dyn_ptr;
                let mut buf = [0u8; SYSCTL_BUF_SIZE];
                let n =
                    (dyn_dir.lookup)(name, name_len as usize, buf.as_mut_ptr(), SYSCTL_BUF_SIZE);
                return match n {
                    None => Ok(Ready(VnodeHandle::INVALID)),
                    Some(content_len) => {
                        let name_slice = core::slice::from_raw_parts(name, name_len as usize);
                        let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
                        (*vp).vtype = VT_REG;
                        (*vp).flags = VN_NOCACHE;
                        (*vp).id = encode_dynleaf_id(dyn_ptr, name_slice);
                        (*vp)
                            .mount
                            .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
                        (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
                        (*vp).ops = (*ctx.vnode).ops;
                        (*vp).nlink = 1;
                        let vd = super::alloc_vdata(ctx.mount_data);
                        if vd.is_null() {
                            return Err(VfsError::NoSpace);
                        }
                        (*vd).kind = SysctlfsKind::DynLeaf;
                        (*vd).node = dyn_ptr as *const SysctlNode;
                        let copy_len = name_len.min(32);
                        core::ptr::copy_nonoverlapping(
                            name,
                            (*vd).dyn_name.as_mut_ptr(),
                            copy_len as usize,
                        );
                        (*vd).dyn_name_len = copy_len;
                        let _ = content_len; // content is not cached; re-fetched at read time
                        (*vp).data = vd as *mut u8;
                        Ok(Ready(vh))
                    }
                };
            }
        };
        if node_ptr.is_null() {
            return Err(VfsError::Io);
        }
        let node = &*node_ptr;

        let name_slice = core::slice::from_raw_parts(name, name_len as usize);

        // Check child nodes first (directories).
        if let Some(child) = node.find_child_node(name_slice) {
            let child_ptr = child as *const SysctlNode;
            let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
            (*vp).vtype = VT_DIR;
            (*vp).flags = VN_NOCACHE;
            (*vp).id = encode_id(SysctlfsKind::Node, child_ptr as *const u8);
            (*vp)
                .mount
                .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
            (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
            (*vp).ops = (*ctx.vnode).ops;
            (*vp).nlink = 2;

            let vd = super::alloc_vdata(ctx.mount_data);
            if vd.is_null() {
                return Err(VfsError::NoSpace);
            }
            (*vd).kind = SysctlfsKind::Node;
            (*vd).node = child_ptr;
            (*vp).data = vd as *mut u8;

            return Ok(Ready(vh));
        }

        // Check leaves (regular files).
        if let Some(leaf) = node.find_leaf(name_slice) {
            let leaf_ptr = leaf as *const SysctlLeaf as *const SysctlNode;
            let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
            (*vp).vtype = VT_REG;
            (*vp).flags = VN_NOCACHE;
            (*vp).id = encode_id(SysctlfsKind::Leaf, leaf_ptr as *const u8);
            (*vp)
                .mount
                .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
            (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
            (*vp).ops = (*ctx.vnode).ops;
            (*vp).nlink = 1;

            let vd = super::alloc_vdata(ctx.mount_data);
            if vd.is_null() {
                return Err(VfsError::NoSpace);
            }
            (*vd).kind = SysctlfsKind::Leaf;
            (*vd).node = leaf_ptr;
            (*vp).data = vd as *mut u8;

            return Ok(Ready(vh));
        }

        // Check Dynamic directories.
        if let Some(dyn_dir) = node.find_dynamic(name_slice) {
            let dyn_ptr = dyn_dir as *const DynamicDir;
            let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
            (*vp).vtype = VT_DIR;
            (*vp).flags = VN_NOCACHE;
            (*vp).id = encode_id(SysctlfsKind::DynDir, dyn_ptr as *const u8);
            (*vp)
                .mount
                .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
            (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
            (*vp).ops = (*ctx.vnode).ops;
            (*vp).nlink = 2;

            let vd = super::alloc_vdata(ctx.mount_data);
            if vd.is_null() {
                return Err(VfsError::NoSpace);
            }
            (*vd).kind = SysctlfsKind::DynDir;
            (*vd).node = dyn_ptr as *const SysctlNode;
            (*vp).data = vd as *mut u8;

            return Ok(Ready(vh));
        }

        // Not found.
        Ok(Ready(VnodeHandle::INVALID))
    }
}

unsafe fn sysctlfs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
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
            SysctlfsKind::Root | SysctlfsKind::Node | SysctlfsKind::DynDir => {
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
            SysctlfsKind::DynLeaf => {
                (*attr).mode = S_IFREG_L | 0o444;
            }
        }

        Ok(Ready(()))
    }
}

unsafe fn sysctlfs_access(
    _ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn sysctlfs_open(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn sysctlfs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn sysctlfs_inactive(_ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    Ok(Ready(()))
}

// =========================================================================
// DataOps
// =========================================================================

unsafe fn sysctlfs_readdir(
    ctx: &WorkerIoCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata_d(ctx);
        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        // DynDir readdir: list entries from the DynamicDir callback.
        if (*vd).kind == SysctlfsKind::DynDir {
            let dyn_ptr = (*vd).node as *const DynamicDir;
            if dyn_ptr.is_null() {
                return Err(VfsError::Io);
            }
            let dyn_dir = &*dyn_ptr;

            // Collect all entries upfront (max 64).
            const MAX_DYN: usize = 64;
            let mut names = [super::tree::DynamicName {
                bytes: [0; 32],
                len: 0,
            }; MAX_DYN];
            let count = (dyn_dir.list)(names.as_mut_ptr(), MAX_DYN);

            if pos == 0 {
                if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                    *cookie = 1;
                    return Ok(Ready(()));
                }
                pos += 1;
            }
            if pos == 1 {
                let parent_id = encode_id(SysctlfsKind::Root, core::ptr::null());
                if !emit(parent_id, b"..".as_ptr(), 2, 4, &attr) {
                    *cookie = 2;
                    return Ok(Ready(()));
                }
                pos += 1;
            }
            let base = 2u64;
            for i in 0..count {
                let entry_pos = base + i as u64;
                if pos > entry_pos {
                    continue;
                }
                let n = &names[i];
                if !emit(0, n.bytes.as_ptr(), n.len, 8 /* DT_REG */, &attr) {
                    *cookie = entry_pos + 1;
                    return Ok(Ready(()));
                }
                pos = entry_pos + 1;
            }
            *cookie = pos;
            return Ok(Ready(()));
        }

        let node_ptr = match (*vd).kind {
            SysctlfsKind::Root => &raw const MIB_ROOT as *const SysctlNode,
            SysctlfsKind::Node => (*vd).node,
            _ => return Err(VfsError::NotDir),
        };
        if node_ptr.is_null() {
            return Err(VfsError::Io);
        }
        let node = &*node_ptr;

        let (node_count, leaf_count, dyn_count) = node.entry_counts();

        // "."
        if pos == 0 {
            if !emit(ctx.id, b".".as_ptr(), 1, 4 /* DT_DIR */, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }

        // ".." — root id is encode_id(Root, null) = 0.
        if pos == 1 {
            let parent_id = encode_id(SysctlfsKind::Root, core::ptr::null());
            if !emit(parent_id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }

        // Child nodes (directories).
        let child_base = 2u64;
        for i in 0..node_count {
            let entry_pos = child_base + i as u64;
            if pos > entry_pos {
                continue;
            }
            let Some(child) = node.child_node_at(i) else {
                break;
            };
            if !emit(0, child.name.as_ptr(), child.name_len, 4, &attr) {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }

        // Leaves (regular files).
        let leaf_base = child_base + node_count as u64;
        for i in 0..leaf_count {
            let entry_pos = leaf_base + i as u64;
            if pos > entry_pos {
                continue;
            }
            let Some(leaf) = node.leaf_at(i) else {
                break;
            };
            if !emit(0, leaf.name.as_ptr(), leaf.name_len, 8, &attr) {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }

        // Dynamic directories.
        let dyn_base = leaf_base + leaf_count as u64;
        for i in 0..dyn_count {
            let entry_pos = dyn_base + i as u64;
            if pos > entry_pos {
                continue;
            }
            let Some(dyn_dir) = node.dynamic_at(i) else {
                break;
            };
            if !emit(
                0,
                dyn_dir.name.as_ptr(),
                dyn_dir.name_len,
                4, /* DT_DIR */
                &attr,
            ) {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }

        *cookie = pos;
        Ok(Ready(()))
    }
}

unsafe fn sysctlfs_read(ctx: &WorkerIoCtx, offset: u64, dst: *mut u8, len: u64) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);

        // DynLeaf: call parent DynamicDir.lookup to regenerate content.
        if (*vd).kind == SysctlfsKind::DynLeaf {
            let dyn_ptr = (*vd).node as *const DynamicDir;
            if dyn_ptr.is_null() {
                return Err(VfsError::Io);
            }
            let dyn_dir = &*dyn_ptr;
            let mut content = [0u8; SYSCTL_BUF_SIZE];
            let name = (*vd).dyn_name.as_ptr();
            let name_len = (*vd).dyn_name_len as usize;
            let content_len =
                match (dyn_dir.lookup)(name, name_len, content.as_mut_ptr(), SYSCTL_BUF_SIZE) {
                    Some(n) => n,
                    None => return Err(VfsError::Io),
                };
            if offset as usize >= content_len {
                return Ok(Ready(0));
            }
            let available = content_len - offset as usize;
            let to_copy = (len as usize).min(available);
            core::ptr::copy_nonoverlapping(content.as_ptr().add(offset as usize), dst, to_copy);
            return Ok(Ready(to_copy as u64));
        }

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
            return Ok(Ready(0));
        }

        let available = content_len - offset as usize;
        let to_copy = if (len as usize) < available {
            len as usize
        } else {
            available
        };

        core::ptr::copy_nonoverlapping(content.as_ptr().add(offset as usize), dst, to_copy);
        Ok(Ready(to_copy as u64))
    }
}

unsafe fn sysctlfs_write(
    ctx: &WorkerIoCtx,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        match (*vd).kind {
            SysctlfsKind::Root | SysctlfsKind::Node | SysctlfsKind::DynDir => {
                return Err(VfsError::IsDir);
            }
            SysctlfsKind::DynLeaf => return Err(VfsError::Perm),
            SysctlfsKind::Leaf => {}
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
        Ok(Ready(len))
    }
}

unsafe fn sysctlfs_statfs(_ctx: &WorkerIoCtx, out: *mut VStatfs) -> VopOutcome<()> {
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
        Ok(Ready(()))
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
        read_mode: DataExecMode::WorkerSafe,
        write_mode: DataExecMode::WorkerSafe,
        readdir_mode: DataExecMode::WorkerSafe,
        readdir: sysctlfs_readdir,
        read: sysctlfs_read,
        write: sysctlfs_write,
        statfs: sysctlfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
