// SPDX-License-Identifier: GPL-2.0-only
//! namei/path anchors shared by personality and namespace code.
//!
//! The rebuilt VFS keeps vnode as the object identity, but current working
//! directory and future namei cursors should not collapse down to a naked
//! vnode key. A path anchor remembers both the owning mount instance and
//! the vnode identity so root swaps and mount crossing can be tracked
//! without re-deriving everything from fallback path renderers.

use super::cached_ref::CachedRef;
use super::identity::{FsInstanceId, VnodeKey};
use super::mount::MountHandle;
use super::vnode::VnodeHandle;

/// Stable starting point for cwd/dirfd/namei cursors.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PathAnchor {
    /// Owning mount instance for this anchor.
    pub(crate) mount: CachedRef<FsInstanceId, MountHandle>,
    /// Stable vnode identity inside that mount.
    pub(crate) vnode: VnodeKey,
}

impl PathAnchor {
    pub(crate) const INVALID: Self = Self {
        mount: CachedRef::<FsInstanceId, MountHandle>::INVALID,
        vnode: VnodeKey::INVALID,
    };

    #[inline]
    pub(crate) fn is_valid(&self) -> bool {
        self.vnode != VnodeKey::INVALID
    }
}

/// Resolved vnode together with the anchor that preserves path context.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LookupResult {
    /// Stable anchor for the resolved vnode.
    pub(crate) anchor: PathAnchor,
    /// Current live vnode handle.
    pub(crate) handle: VnodeHandle,
}

/// Absolute-path split result used by create/mutate namei helpers.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ParentLookup {
    /// Resolved parent directory.
    pub(crate) parent: LookupResult,
    /// Offset of the final component inside the original absolute path.
    pub(crate) leaf_offset: usize,
}
