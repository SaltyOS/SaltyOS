// SPDX-License-Identifier: GPL-2.0-only
//! Per-process mount namespaces.

use crate::arena::Handle;

use super::mount::MountHandle;

pub(crate) const MAX_NS_MOUNTS: usize = 32;

/// Handle-based mount-namespace identity.
pub(crate) type MountNsHandle = Handle<MountNamespace>;

#[repr(C)]
pub(crate) struct MountNamespace {
    /// Owner-managed reference count.
    pub(crate) refcount: u32,
    _pad0: [u8; 4],
    /// Root mount visible through this namespace.
    pub(crate) root_mount: MountHandle,
    /// Snapshot of visible mounts.
    pub(crate) mounts: [MountHandle; MAX_NS_MOUNTS],
    pub(crate) mount_count: u8,
}

impl MountNamespace {
    pub(crate) const fn zeroed() -> Self {
        MountNamespace {
            refcount: 0,
            _pad0: [0; 4],
            root_mount: MountHandle::INVALID,
            mounts: [MountHandle::INVALID; MAX_NS_MOUNTS],
            mount_count: 0,
        }
    }
}
