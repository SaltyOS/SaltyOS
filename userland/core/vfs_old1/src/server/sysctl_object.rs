// SPDX-License-Identifier: GPL-2.0-only
//! sysctlfs leaf associations.

use crate::arena::Handle;
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) type SysctlLeafHandle = Handle<SysctlLeafState>;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysctlLeafKind {
    KernOstype = 1,
    KernOsrelease = 2,
    KernHostname = 3,
    KernVersion = 4,
    KernMaxproc = 5,
    KernBoottime = 6,
    KernUptime = 7,
    KernContextSwitches = 8,
    HwNcpu = 9,
    HwPagesize = 10,
    HwPhysmem = 11,
    VmPhysmem = 12,
    VmPagesFree = 13,
    VmPageSize = 14,
    SecuritySecurelevel = 15,
}

#[repr(C)]
pub(crate) struct SysctlLeafState {
    pub(crate) vnode: VnodeHandle,
    pub(crate) owner_mount: MountHandle,
    pub(crate) kind: SysctlLeafKind,
    _pad0: [u8; 7],
}

impl SysctlLeafState {
    pub(crate) const fn zeroed() -> Self {
        SysctlLeafState {
            vnode: VnodeHandle::INVALID,
            owner_mount: MountHandle::INVALID,
            kind: SysctlLeafKind::KernOstype,
            _pad0: [0; 7],
        }
    }
}
