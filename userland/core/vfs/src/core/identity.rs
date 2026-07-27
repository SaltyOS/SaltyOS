// SPDX-License-Identifier: GPL-2.0-only
//
//! Stable identity types for mounts and vnodes.
//!
//! Arena handles are `(slot, epoch)` pairs whose epoch gets bumped
//! on reclaim — they are valid for as long as the entry is alive
//! but say nothing useful across reincarnations of the same slot.
//! Structural relationships between mounts, vnodes, and clients
//! must survive arena churn (saltyfs cache pressure, mount registry
//! recycling) and therefore cannot be keyed on raw handles.
//!
//! Completion 5-tuple validation matches incoming backend replies
//! against the live `VnodeKey`, not the raw Arena handle: a slot
//! recycled mid-flight gets a new key and the stale completion is
//! dropped instead of routed to the wrong vnode.

/// Monotonic identifier for a mounted filesystem instance. Assigned
/// once at mount creation time and never reused, even if the
/// underlying `Arena<Mount>` slot recycles.
///
/// `INVALID` is the reserved sentinel for "not yet assigned" and is
/// the bit-pattern produced by zero-initialisation.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
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

/// Backend-supplied identity for a single filesystem node. The
/// `id` half is the backend's opaque node id (saltyfs inode
/// number, netsrv socket id); `seq` is a monotonic incarnation
/// counter the backend bumps when the same `id` is reissued for a
/// new underlying object (file unlinked + recreated).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct BackendNodeId {
    pub id: u64,
    pub seq: u32,
    _pad: u32,
}

impl BackendNodeId {
    pub(crate) const INVALID: BackendNodeId = BackendNodeId {
        id: 0,
        seq: 0,
        _pad: 0,
    };

    #[inline]
    pub(crate) const fn new(id: u64, seq: u32) -> Self {
        BackendNodeId { id, seq, _pad: 0 }
    }

    #[inline]
    pub(crate) const fn is_valid(self) -> bool {
        self.id != 0 || self.seq != 0
    }
}

impl Default for BackendNodeId {
    #[inline]
    fn default() -> Self {
        BackendNodeId::INVALID
    }
}

/// Stable identity of a filesystem node. Survives arena handle
/// churn — the `(fs_instance_id, backend_id)` pair is enough to
/// re-resolve a vnode even after its `Arena<Vnode>` slot was
/// recycled, as long as the backend can be asked to vget the
/// node again.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct VnodeKey {
    pub fs_instance_id: FsInstanceId,
    pub backend_id: BackendNodeId,
}

impl VnodeKey {
    pub(crate) const NONE: VnodeKey = VnodeKey {
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
        VnodeKey::NONE
    }
}

/// Single entry in the resolver cache (`VfsState.vnode_resolve_cache`).
/// Caches the result of namei walks so repeat path resolutions skip
/// the backend round-trip.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct VnodeResolveCacheEntry {
    pub key: VnodeKey,
    /// Slot index into `VfsState.vnodes` for the resolved vnode.
    /// `u32::MAX` = empty entry.
    pub vnode_slot: u32,
    /// Vnode's epoch at insertion time. `Vnode` must still match for
    /// the entry to be honoured.
    pub vnode_epoch: u32,
    /// Hash of the parent vnode key + name, used as the lookup key.
    /// 0 = empty entry (cache slot is unused).
    pub path_hash: u64,
}

impl VnodeResolveCacheEntry {
    pub(crate) const EMPTY: Self = Self {
        key: VnodeKey::NONE,
        vnode_slot: u32::MAX,
        vnode_epoch: 0,
        path_hash: 0,
    };
}

/// Cache size — power of 2 for cheap modulo. 256 entries fits in
/// ~16 KiB; sized to absorb typical re-resolve traffic during
/// `getcwd` + repeated directory walks.
pub(crate) const VNODE_RESOLVE_CACHE_CAP: usize = 256;
