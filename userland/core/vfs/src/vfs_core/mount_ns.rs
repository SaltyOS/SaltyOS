// SPDX-License-Identifier: GPL-2.0-only
//! Per-process mount namespaces.
//!
//! Each `MountNamespace` holds a root mount handle and a snapshot of mount
//! handles visible to the owning process group. Namespaces are refcounted
//! and allocated from `Arena<MountNamespace>` in `VfsState`.
//!
//! # Single-owner model
//!
//! The global statics (`NS_POOL`, `GLOBAL_NS`) are eliminated. The arena
//! and the global namespace handle live in `VfsState`, owned by the main loop.

use super::mount::MountHandle;
use crate::arena::Handle;

pub(crate) const MAX_NS_MOUNTS: usize = 16;

/// Type alias for handle-based namespace identity.
pub(crate) type MountNsHandle = Handle<MountNamespace>;

/// Per-process mount namespace.
///
/// Allocated from `Arena<MountNamespace>` in `VfsState`. The `refcount`
/// is managed by the owner loop (no atomics needed).
#[repr(C)]
pub(crate) struct MountNamespace {
    /// Reference count. Incremented on fork/share, decremented on exit.
    /// When it reaches zero the owner loop releases the arena slot.
    pub(crate) refcount: u32,
    _pad0: [u8; 4],

    /// Root mount of this namespace.
    pub(crate) root_mount: MountHandle,

    /// Snapshot of visible mounts. Entries are `MountHandle`; unused slots
    /// are `MountHandle::INVALID`.
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
