// SPDX-License-Identifier: GPL-2.0-only
//! procfs — process information virtual filesystem.
//!
//! procfs is a completely independent virtual filesystem. All content is
//! generated dynamically from IPC queries to the init server (process
//! table, exe path, kinfo_proc, vm stats, cpu times) and netsrv (network
//! configuration, ARP table). There is no persistent storage, no block
//! chains, no dirent arrays.
//!
//! Every procfs vnode gets `VN_NOCACHE` so it is reclaimed immediately
//! after last close. No stale PID state is ever cached.

pub(super) mod generators;
pub(super) mod net;
pub(super) mod pid;
pub(super) mod sysnode;
pub(super) mod vfsops;
pub(super) mod vops;

/// Content formatters the owner `init_rpc` finalize step renders from
/// prefetched init snapshots (procfs reads are async — the init query
/// runs in the prefetch phase, the formatter at finalize).
pub(crate) use pid::{proc_gen_cmdline, proc_gen_comm, proc_gen_stat, proc_gen_status};
pub(crate) use sysnode::{proc_gen_loadavg, proc_gen_sys_stat};

use crate::core::vop::{VfsOps, VopVector};

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcfsKind {
    Root = 0,
    SelfLink = 1,
    PidDir = 2,
    PidStat = 3,
    PidStatus = 4,
    PidMaps = 5,
    PidExe = 6,
    PidCmdline = 7,
    PidComm = 8,
    NetDir = 9,
    NetRoute = 10,
    NetArp = 11,
    NetDev = 12,
    SysDir = 13,
    SysLeaf = 14,
    SysDynDir = 15,
    SysDynLeaf = 16,
    SysStat = 17,
    SysMeminfo = 18,
    SysUptime = 19,
    SysCpuinfo = 20,
    SysLoadavg = 21,
    PidStatm = 22,
    PidIo = 23,
    PidSmaps = 24,
    PidCgroup = 25,
    PidOomScore = 26,
    NetHosts = 27,
    NetResolvConf = 28,
    PidReservations = 29,
}

#[repr(C)]
pub(crate) struct ProcfsVnodeData {
    pub(crate) kind: ProcfsKind,
    pub(crate) pid: u32,
    pub(crate) sys_ptr: *const u8,
    pub(crate) dyn_name: [u8; 32],
    pub(crate) dyn_name_len: u8,
    _pad: [u8; 7],
}

const MAX_PROCFS_VNODES: usize = 64;

#[repr(C)]
pub(crate) struct ProcfsMountData {
    pub(crate) vdata: [ProcfsVnodeData; MAX_PROCFS_VNODES],
    pub(crate) count: usize,
}

impl ProcfsMountData {
    pub(super) const fn zeroed() -> Self {
        const ZERO_VDATA: ProcfsVnodeData = ProcfsVnodeData {
            kind: ProcfsKind::Root,
            pid: 0,
            sys_ptr: ::core::ptr::null(),
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

#[inline]
pub(super) fn encode_id(kind: ProcfsKind, pid: u32) -> u64 {
    (kind as u64) | ((pid as u64) << 8)
}

#[inline]
pub(super) fn encode_sys_id(kind: ProcfsKind, ptr: *const u8) -> u64 {
    (kind as u64) | ((ptr as u64) << 8)
}

#[inline]
pub(super) fn encode_sys_dynleaf_id(dir: *const u8, name: &[u8]) -> u64 {
    let mut h: u64 = dir as u64;
    for &b in name {
        h = h.wrapping_mul(31).wrapping_add(b as u64);
    }
    (ProcfsKind::SysDynLeaf as u64) | (h << 8)
}

pub(super) unsafe fn alloc_vdata(mount_data: *mut u8) -> *mut ProcfsVnodeData {
    unsafe {
        let md = mount_data as *mut ProcfsMountData;
        if (*md).count >= MAX_PROCFS_VNODES {
            return ::core::ptr::null_mut();
        }
        let idx = (*md).count;
        (*md).count += 1;
        &raw mut (*md).vdata[idx]
    }
}

pub(crate) static PROCFS_VOPS: VopVector = vops::PROCFS_VOPS;

pub(crate) static PROCFS_VFSOPS: VfsOps = VfsOps {
    mount: vfsops::procfs_mount,
    unmount: vfsops::procfs_unmount,
    root: vfsops::procfs_root,
    vget: vfsops::procfs_vget,
    statfs: vfsops::procfs_statfs,
    sync: vfsops::procfs_sync,
};
