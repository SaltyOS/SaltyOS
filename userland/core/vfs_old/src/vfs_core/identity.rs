// SPDX-License-Identifier: GPL-2.0-only
//! Stable structural identity for mounts and vnodes.
//!
//! `Arena` handles are `(slot, epoch)` pairs whose epoch gets bumped on
//! reclaim — they are valid for as long as the entry is alive but say
//! nothing useful across reincarnations of the same slot. Structural
//! relationships between mounts, vnodes, and clients must survive
//! arena churn (saltyfs cache pressure, mount registry recycling) and
//! therefore cannot be keyed on raw handles.
//!
//! `FsInstanceId` is a monotonically increasing per-VFS counter assigned
//! to every `Mount` on creation. Slot values of the backing `Arena<Mount>`
//! may recycle; `FsInstanceId` values never do.
//!
//! `VnodeKey` pairs the mount's `FsInstanceId` with the backend-supplied
//! `BackendNodeId` to yield a stable identifier for a filesystem node.
//! The resolve cache translates `VnodeKey → VnodeHandle` lazily — a
//! cache miss triggers the backend's `vget` path, which re-materialises
//! the vnode into a fresh arena slot and installs the new handle.
//!
//! The invalid sentinel is `FsInstanceId::INVALID == 0`; the allocator
//! starts at 1 so a zeroed field is trivially recognisable as unset.

use trona_protocol::posix::BackendNodeId;

/// Monotonic identifier for a mounted filesystem instance. Assigned once
/// at mount creation time and never reused, even if the underlying
/// `Arena<Mount>` slot recycles.
///
/// `INVALID` is the reserved sentinel for "not yet assigned" / "no
/// mount" and is the bit-pattern produced by zero-initialisation.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) struct FsInstanceId(pub u64);

impl FsInstanceId {
    pub(crate) const INVALID: FsInstanceId = FsInstanceId(0);

    #[inline]
    pub(crate) const fn new(value: u64) -> Self {
        FsInstanceId(value)
    }

    #[inline]
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub(crate) const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl Default for FsInstanceId {
    #[inline]
    fn default() -> Self {
        FsInstanceId::INVALID
    }
}

/// Stable identity of a filesystem node. Survives arena handle churn —
/// the `(fs_instance_id, backend_id)` pair is enough to re-resolve a
/// vnode even after its `Arena<Vnode>` slot was recycled, as long as
/// the backend can be asked to `vget` the node again.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct VnodeKey {
    pub(crate) fs_instance_id: FsInstanceId,
    pub(crate) backend_id: BackendNodeId,
}

impl VnodeKey {
    pub(crate) const INVALID: VnodeKey = VnodeKey {
        fs_instance_id: FsInstanceId::INVALID,
        backend_id: BackendNodeId::INVALID,
    };

    #[inline]
    pub(crate) const fn new(fs_instance_id: FsInstanceId, backend_id: BackendNodeId) -> Self {
        VnodeKey {
            fs_instance_id,
            backend_id,
        }
    }

    #[inline]
    pub(crate) const fn new_ino(fs_instance_id: FsInstanceId, inode_id: u64) -> Self {
        VnodeKey::new(fs_instance_id, BackendNodeId::new(inode_id, 0))
    }

    #[inline]
    pub(crate) const fn is_valid(self) -> bool {
        self.fs_instance_id.is_valid()
    }
}

impl Default for VnodeKey {
    #[inline]
    fn default() -> Self {
        VnodeKey::INVALID
    }
}

use crate::arena::Handle;
use crate::vfs_core::vnode::Vnode;

/// Resolve cache entry — `(VnodeKey, VnodeHandle)` triple.
///
/// Zero-initialised entries carry `VnodeKey::INVALID` and an invalid
/// arena handle; both conditions are cheap to check on lookup.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VnodeResolveCacheEntry {
    pub(crate) key: VnodeKey,
    pub(crate) handle: Handle<Vnode>,
}

impl VnodeResolveCacheEntry {
    pub(crate) const EMPTY: VnodeResolveCacheEntry = VnodeResolveCacheEntry {
        key: VnodeKey::INVALID,
        handle: Handle::<Vnode>::INVALID,
    };
}

/// Direct-mapped capacity of the resolve cache. Power of two so the
/// index can be computed with a cheap AND mask. Sized generously for
/// the expected working set (scaffold mounts + frequently-walked
/// saltyfs directories) without consuming disproportionate memory.
pub(crate) const VNODE_RESOLVE_CACHE_CAP: usize = 128;

/// FNV-style mixer used to spread backend node ids across the cache.
/// Not cryptographic — just deterministic and cheap.
pub(crate) const FNV_MIX: u64 = 0x100000001b3;

#[inline]
pub(crate) const fn resolve_cache_index(key: VnodeKey) -> usize {
    let mixed = key.backend_id.ino.wrapping_mul(FNV_MIX)
        ^ (key.backend_id.seq as u64).wrapping_mul(0xD6E8FEB86659FD93)
        ^ key.fs_instance_id.raw().wrapping_mul(0x9E3779B97F4A7C15);
    (mixed as usize) & (VNODE_RESOLVE_CACHE_CAP - 1)
}
