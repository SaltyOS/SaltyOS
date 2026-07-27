// SPDX-License-Identifier: GPL-2.0-only
//! Stable identity plus handle hint.
//!
//! Structural links in the namespace tree carry both a never-reused
//! identity and the last known live arena handle for the same object. The
//! identity is authoritative; the handle is only a cache hint.

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct CachedRef<Id: Copy + Eq, Handle: Copy> {
    pub(crate) id: Id,
    pub(crate) handle: Handle,
}

impl<Id: Copy + Eq, Handle: Copy> CachedRef<Id, Handle> {
    #[inline]
    pub(crate) const fn new(id: Id, handle: Handle) -> Self {
        CachedRef { id, handle }
    }
}

impl CachedRef<crate::vfs_core::identity::VnodeKey, crate::vfs_core::vnode::VnodeHandle> {
    pub(crate) const INVALID: Self = CachedRef {
        id: crate::vfs_core::identity::VnodeKey::INVALID,
        handle: crate::vfs_core::vnode::VnodeHandle::INVALID,
    };
}

impl CachedRef<crate::vfs_core::identity::FsInstanceId, crate::vfs_core::mount::MountHandle> {
    pub(crate) const INVALID: Self = CachedRef {
        id: crate::vfs_core::identity::FsInstanceId::INVALID,
        handle: crate::vfs_core::mount::MountHandle::INVALID,
    };
}
