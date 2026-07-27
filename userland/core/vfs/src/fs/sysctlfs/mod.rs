// SPDX-License-Identifier: GPL-2.0-only
//! sysctlfs — FreeBSD-style sysctl MIB tree exposed as a virtual filesystem.

pub(crate) mod providers;
pub(crate) mod tree;
pub(super) mod vfsops;
pub(super) mod vops;

use crate::core::vop::{VfsOps, VopVector};

use tree::{DynamicDir, SysctlNode};

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysctlfsKind {
    Root = 0,
    Node = 1,
    Leaf = 2,
    DynDir = 3,
    DynLeaf = 4,
}

#[repr(C)]
pub(crate) struct SysctlfsVnodeData {
    pub(crate) kind: SysctlfsKind,
    _pad: [u8; 7],
    pub(crate) node: *const SysctlNode,
    pub(crate) dyn_name: [u8; 32],
    pub(crate) dyn_name_len: u8,
    _pad2: [u8; 7],
}

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
            node: ::core::ptr::null(),
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

#[inline]
pub(super) fn encode_id(kind: SysctlfsKind, ptr: *const u8) -> u64 {
    (kind as u64) | ((ptr as u64) << 8)
}

#[inline]
pub(super) fn encode_dynleaf_id(dir: *const DynamicDir, name: &[u8]) -> u64 {
    let mut h: u64 = dir as u64;
    for &b in name {
        h = h.wrapping_mul(31).wrapping_add(b as u64);
    }
    (SysctlfsKind::DynLeaf as u64) | (h << 8)
}

pub(super) unsafe fn alloc_vdata(mount_data: *mut u8) -> *mut SysctlfsVnodeData {
    unsafe {
        let md = mount_data as *mut SysctlfsMountData;
        if (*md).count >= MAX_SYSCTLFS_VNODES {
            return ::core::ptr::null_mut();
        }
        let idx = (*md).count;
        (*md).count += 1;
        &raw mut (*md).vdata[idx]
    }
}

pub(crate) static SYSCTLFS_VOPS: VopVector = vops::SYSCTLFS_VOPS;

pub(crate) static SYSCTLFS_VFSOPS: VfsOps = VfsOps {
    mount: vfsops::sysctlfs_mount,
    unmount: vfsops::sysctlfs_unmount,
    root: vfsops::sysctlfs_root,
    vget: vfsops::sysctlfs_vget,
    statfs: vfsops::sysctlfs_statfs,
    sync: vfsops::sysctlfs_sync,
};
