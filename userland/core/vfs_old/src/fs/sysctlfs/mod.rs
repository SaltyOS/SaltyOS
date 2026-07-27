// SPDX-License-Identifier: GPL-2.0-only
//! sysctlfs — FreeBSD-style sysctl MIB tree exposed as a virtual filesystem.
//!
//! Mounted at `/sys`, sysctlfs exposes kernel and system tunables as a
//! hierarchy of directories (MIB namespaces) and files (sysctl values).
//! Reading a file invokes a provider callback; writing to a read-write file
//! updates the tunable.
//!
//! Layout:
//! ```text
//! /sys/
//! ├── kern/
//! │   ├── ostype          (r/o, "SaltyOS")
//! │   ├── osrelease       (r/o, "0.1.0")
//! │   ├── hostname        (r/w)
//! │   ├── version         (r/o)
//! │   └── maxproc         (r/o)
//! ├── hw/
//! │   ├── ncpu            (r/o)
//! │   ├── pagesize        (r/o)
//! │   └── physmem         (r/o)
//! ├── net/
//! ├── vm/
//! ├── vfs/
//! └── security/
//!     └── securelevel     (r/w)
//! ```

pub(crate) mod providers;
pub(crate) mod tree;
mod vfsops;
mod vops;

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::vfs::{VfsOps, register_fs_type};
use crate::vfs_core::vop::VopVector;

use tree::{DynamicDir, SysctlNode};

// =========================================================================
// SysctlfsKind — node type discriminator
// =========================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysctlfsKind {
    /// /sys root directory.
    Root = 0,
    /// Interior MIB node (directory).
    Node = 1,
    /// Terminal MIB leaf (regular file).
    Leaf = 2,
    /// Runtime-generated directory (DynamicDir).
    DynDir = 3,
    /// Child entry of a DynamicDir (regular file, name carried in vnode data).
    DynLeaf = 4,
}

// =========================================================================
// SysctlfsVnodeData — per-vnode backend data
// =========================================================================

#[repr(C)]
pub(crate) struct SysctlfsVnodeData {
    pub(crate) kind: SysctlfsKind,
    _pad: [u8; 7],
    /// For Node/Leaf: pointer to `SysctlNode` / `SysctlLeaf`.
    /// For DynDir: pointer to the `DynamicDir`.
    /// For DynLeaf: pointer to the parent `DynamicDir`.
    /// Null for Root (uses MIB_ROOT directly).
    pub(crate) node: *const SysctlNode,
    /// For DynLeaf: the child name within its parent DynamicDir (NUL-padded).
    /// Unused for all other kinds.
    pub(crate) dyn_name: [u8; 32],
    pub(crate) dyn_name_len: u8,
    _pad2: [u8; 7],
}

// =========================================================================
// SysctlfsMountData — per-mount state
// =========================================================================

/// Maximum number of vnode-data slots in a single sysctlfs mount.
/// Ephemeral (VN_NOCACHE), so only needs to cover peak simultaneous refs.
pub(super) const MAX_SYSCTLFS_VNODES: usize = 64;

#[repr(C)]
pub(crate) struct SysctlfsMountData {
    pub(crate) vdata: [SysctlfsVnodeData; MAX_SYSCTLFS_VNODES],
    pub(crate) count: usize,
}

impl SysctlfsMountData {
    pub(super) const fn zeroed() -> Self {
        const ZERO_VDATA: SysctlfsVnodeData = SysctlfsVnodeData {
            kind: SysctlfsKind::Root,
            _pad: [0; 7],
            node: core::ptr::null(),
            dyn_name: [0; 32],
            dyn_name_len: 0,
            _pad2: [0; 7],
        };
        SysctlfsMountData {
            vdata: [ZERO_VDATA; MAX_SYSCTLFS_VNODES],
            count: 0,
        }
    }
}

// =========================================================================
// Vnode id encoding
// =========================================================================

/// Encode a sysctlfs vnode id from kind and an arbitrary pointer.
///
/// The pointer is used as a unique-enough identity for deduplication within
/// the ephemeral pool. We use the low 56 bits of the pointer.
#[inline]
pub(super) fn encode_id(kind: SysctlfsKind, ptr: *const u8) -> u64 {
    (kind as u64) | ((ptr as u64) << 8)
}

/// Encode a DynLeaf vnode id from the parent DynamicDir pointer and child name.
///
/// Mixes the pointer with a simple hash of the name bytes so different children
/// of the same DynamicDir get distinct ids.
#[inline]
pub(super) fn encode_dynleaf_id(dir: *const DynamicDir, name: &[u8]) -> u64 {
    let mut h: u64 = dir as u64;
    for &b in name {
        h = h.wrapping_mul(31).wrapping_add(b as u64);
    }
    (SysctlfsKind::DynLeaf as u64) | (h << 8)
}

// =========================================================================
// Vdata allocator
// =========================================================================

/// Allocate a vnode-data slot from the sysctlfs mount data pool.
///
/// Returns a pointer to the allocated `SysctlfsVnodeData`, or null if
/// the pool is full. The caller is responsible for initializing the slot.
///
/// # Safety
///
/// `mount_data` must point to a valid `SysctlfsMountData`.
pub(super) unsafe fn alloc_vdata(mount_data: *mut u8) -> *mut SysctlfsVnodeData {
    unsafe {
        let md = mount_data as *mut SysctlfsMountData;
        if (*md).count >= MAX_SYSCTLFS_VNODES {
            return core::ptr::null_mut();
        }
        let idx = (*md).count;
        (*md).count += 1;
        &raw mut (*md).vdata[idx]
    }
}

// =========================================================================
// Static VfsOps / VopVector
// =========================================================================

pub(crate) static SYSCTLFS_VFSOPS: VfsOps = vfsops::SYSCTLFS_VFSOPS;
pub(crate) static SYSCTLFS_VOPS: VopVector = vops::SYSCTLFS_VOPS;

// =========================================================================
// Registration
// =========================================================================

/// Register the `sysctlfs` filesystem type and initialize the MIB tree.
///
/// Called during VFS bootstrap Stage 2.
pub(crate) unsafe fn register() -> VfsResult<()> {
    unsafe {
        tree::init_tree();
        providers::init_providers();
        register_fs_type(
            b"sysctlfs",
            &raw const SYSCTLFS_VFSOPS,
            &raw const SYSCTLFS_VOPS,
        )
    }
}
