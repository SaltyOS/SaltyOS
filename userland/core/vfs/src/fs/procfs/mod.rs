// SPDX-License-Identifier: GPL-2.0-only
//! procfs — process information virtual filesystem.
//!
//! procfs is a completely independent virtual filesystem. All content is
//! generated dynamically from IPC queries to procmgr and netsrv — there
//! is no persistent storage, no block chains, no dirent arrays.
//!
//! Every procfs vnode gets `VN_NOCACHE` so it is reclaimed immediately
//! after last close. No stale PID state is ever cached.
//!
//! Layout:
//! ```text
//! /proc/
//! ├── self -> <current PID>    (symlink)
//! ├── net/
//! │   ├── route
//! │   ├── arp
//! │   └── dev
//! ├── sys/                     (Linux compat → delegates to sysctlfs MIB tree)
//! │   ├── kernel/
//! │   │   ├── hostname
//! │   │   ├── osrelease
//! │   │   └── ostype
//! │   └── vm/
//! └── <pid>/
//!     ├── stat
//!     ├── status
//!     ├── maps
//!     ├── exe -> <exe path>    (symlink)
//!     ├── cmdline
//!     └── comm
//! ```

mod generators;
mod net;
mod pid;
mod vfsops;
mod vops;

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::vfs::{register_fs_type, VfsOps};
use crate::vfs_core::vop::VopVector;

// =========================================================================
// ProcfsKind — node type discriminator
// =========================================================================

/// Identifies the semantic type of a procfs vnode.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcfsKind {
    /// /proc root directory.
    Root = 0,
    /// /proc/self symlink.
    SelfLink = 1,
    /// /proc/<pid> directory.
    PidDir = 2,
    /// /proc/<pid>/stat
    PidStat = 3,
    /// /proc/<pid>/status
    PidStatus = 4,
    /// /proc/<pid>/maps
    PidMaps = 5,
    /// /proc/<pid>/exe symlink.
    PidExe = 6,
    /// /proc/<pid>/cmdline
    PidCmdline = 7,
    /// /proc/<pid>/comm
    PidComm = 8,
    /// /proc/net directory.
    NetDir = 9,
    /// /proc/net/route
    NetRoute = 10,
    /// /proc/net/arp
    NetArp = 11,
    /// /proc/net/dev
    NetDev = 12,
    /// /proc/sys directory (Linux compat — delegates to sysctlfs MIB tree).
    SysDir = 13,
    /// /proc/sys/<leaf> (Linux compat — reads from sysctlfs provider).
    SysLeaf = 14,
}

// =========================================================================
// ProcfsVnodeData — per-vnode backend data
// =========================================================================

/// Backend-private data hung off `Vnode.data` for procfs vnodes.
#[repr(C)]
pub(crate) struct ProcfsVnodeData {
    pub(crate) kind: ProcfsKind,
    /// PID for per-process nodes (PidDir, PidStat, etc.). 0 for root/net/sys nodes.
    pub(crate) pid: u32,
    /// For SysDir/SysLeaf: pointer into the sysctlfs MIB tree. Null otherwise.
    pub(crate) sys_ptr: *const u8,
}

// =========================================================================
// ProcfsMountData — per-mount state (vdata pool only)
// =========================================================================

/// Maximum number of vnode-data slots in a single procfs mount.
///
/// procfs vnodes are ephemeral (VN_NOCACHE → reclaimed after last close),
/// so this pool only needs to hold the peak number of simultaneously-
/// referenced vnodes. 64 is generous for typical usage patterns.
const MAX_PROCFS_VNODES: usize = 64;

/// Per-mount state for procfs. Holds only the vdata pool — vnodes are
/// allocated from the global arena via trampolines.
#[repr(C)]
pub(crate) struct ProcfsMountData {
    /// Vnode-private data pool (count-indexed).
    pub(crate) vdata: [ProcfsVnodeData; MAX_PROCFS_VNODES],
    /// Number of allocated vdata slots.
    pub(crate) count: usize,
}

impl ProcfsMountData {
    pub(super) const fn zeroed() -> Self {
        const ZERO_VDATA: ProcfsVnodeData = ProcfsVnodeData {
            kind: ProcfsKind::Root,
            pid: 0,
            sys_ptr: core::ptr::null(),
        };
        ProcfsMountData {
            vdata: [ZERO_VDATA; MAX_PROCFS_VNODES],
            count: 0,
        }
    }
}

/// Encode a procfs vnode id from (kind, pid).
///
/// Layout: bits 7:0 = kind, bits 39:8 = pid.
#[inline]
pub(super) fn encode_id(kind: ProcfsKind, pid: u32) -> u64 {
    (kind as u64) | ((pid as u64) << 8)
}

/// Encode a procfs vnode id for SysDir/SysLeaf from (kind, pointer).
///
/// Uses the pointer as a unique identity (same encoding as sysctlfs).
/// Layout: bits 7:0 = kind, bits 63:8 = pointer.
#[inline]
pub(super) fn encode_sys_id(kind: ProcfsKind, ptr: *const u8) -> u64 {
    (kind as u64) | ((ptr as u64) << 8)
}

// =========================================================================
// Vdata allocator
// =========================================================================

/// Allocate a vnode-data slot from the procfs mount data pool.
///
/// Returns a pointer to the allocated `ProcfsVnodeData`, or null if
/// the pool is full. The caller is responsible for initializing the slot.
///
/// # Safety
///
/// `mount_data` must point to a valid `ProcfsMountData`.
pub(super) unsafe fn alloc_vdata(mount_data: *mut u8) -> *mut ProcfsVnodeData {
    unsafe {
        let md = mount_data as *mut ProcfsMountData;
        if (*md).count >= MAX_PROCFS_VNODES {
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

pub(crate) static PROCFS_VFSOPS: VfsOps = vfsops::PROCFS_VFSOPS;
pub(crate) static PROCFS_VOPS: VopVector = vops::PROCFS_VOPS;

// =========================================================================
// Registration
// =========================================================================

/// Register the `procfs` filesystem type. Called during VFS bootstrap Stage 2.
pub(crate) unsafe fn register() -> VfsResult<()> {
    unsafe {
        register_fs_type(
            b"procfs",
            &raw const PROCFS_VFSOPS,
            &raw const PROCFS_VOPS,
        )
    }
}
