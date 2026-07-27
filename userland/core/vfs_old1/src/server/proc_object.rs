// SPDX-License-Identifier: GPL-2.0-only
//! procfs generated-node associations.

use crate::arena::Handle;
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) type ProcNodeHandle = Handle<ProcNodeState>;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcNodeKind {
    SelfLink = 1,
    RootStat = 2,
    RootMeminfo = 3,
    RootUptime = 4,
    RootCpuinfo = 5,
    RootLoadavg = 6,
    RootVersion = 7,
    RootMounts = 8,
    RootFilesystems = 9,
    PidDir = 10,
    PidStat = 11,
    PidStatus = 12,
    PidCmdline = 13,
    PidComm = 14,
    PidStatm = 15,
    PidExe = 16,
}

#[repr(C)]
pub(crate) struct ProcNodeState {
    pub(crate) vnode: VnodeHandle,
    pub(crate) owner_mount: MountHandle,
    pub(crate) kind: ProcNodeKind,
    pub(crate) ephemeral: u8,
    _pad0: [u8; 2],
    pub(crate) pid: u32,
}

impl ProcNodeState {
    pub(crate) const fn zeroed() -> Self {
        ProcNodeState {
            vnode: VnodeHandle::INVALID,
            owner_mount: MountHandle::INVALID,
            kind: ProcNodeKind::SelfLink,
            ephemeral: 0,
            _pad0: [0; 2],
            pid: 0,
        }
    }
}
