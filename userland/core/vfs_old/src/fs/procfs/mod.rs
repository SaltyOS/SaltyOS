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
mod sysnode;
mod vfsops;
mod vops;

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::vfs::{VfsOps, register_fs_type};
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
    /// /proc/sys/<path>/ where the sysctlfs node is a DynamicDir.
    SysDynDir = 15,
    /// /proc/sys/<path>/<name> where the parent sysctlfs node is a DynamicDir.
    SysDynLeaf = 16,
    /// /proc/stat — system-wide CPU / context-switch / process counts.
    SysStat = 17,
    /// /proc/meminfo — system memory totals.
    SysMeminfo = 18,
    /// /proc/uptime — uptime + idle seconds.
    SysUptime = 19,
    /// /proc/cpuinfo — per-CPU description blocks.
    SysCpuinfo = 20,
    /// /proc/loadavg — 1/5/15-min load averages + procs running/total + last pid.
    SysLoadavg = 21,
    /// /proc/<pid>/statm — process memory stats (pages).
    PidStatm = 22,
    /// /proc/<pid>/io — per-process I/O counters (placeholder).
    PidIo = 23,
    /// /proc/<pid>/smaps — per-VMA memory stats (empty placeholder).
    PidSmaps = 24,
    /// /proc/<pid>/cgroup — cgroup membership (placeholder `"0::/\n"`).
    PidCgroup = 25,
    /// /proc/<pid>/oom_score — OOM killer score (placeholder `"0\n"`).
    PidOomScore = 26,
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
    /// For SysDir/SysLeaf: pointer to the `SysctlNode` or `SysctlLeaf`.
    /// For SysDynDir: pointer to the `DynamicDir`.
    /// For SysDynLeaf: pointer to the parent `DynamicDir`.
    /// Null otherwise.
    pub(crate) sys_ptr: *const u8,
    /// For SysDynLeaf: name of the child within its parent DynamicDir (NUL-padded).
    /// Unused for all other kinds.
    pub(crate) dyn_name: [u8; 32],
    pub(crate) dyn_name_len: u8,
    _pad: [u8; 7],
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
            dyn_name: [0; 32],
            dyn_name_len: 0,
            _pad: [0; 7],
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

/// Encode a procfs vnode id for SysDynLeaf from the parent DynamicDir pointer and child name.
#[inline]
pub(super) fn encode_sys_dynleaf_id(dir: *const u8, name: &[u8]) -> u64 {
    let mut h: u64 = dir as u64;
    for &b in name {
        h = h.wrapping_mul(31).wrapping_add(b as u64);
    }
    (ProcfsKind::SysDynLeaf as u64) | (h << 8)
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
    unsafe { register_fs_type(b"procfs", &raw const PROCFS_VFSOPS, &raw const PROCFS_VOPS) }
}
