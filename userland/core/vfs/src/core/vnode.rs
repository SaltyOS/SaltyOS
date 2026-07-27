// SPDX-License-Identifier: GPL-2.0-only
//
//! `Vnode` — in-memory image of a single file-system node.
//!
//! Each Vnode lives in `VfsState.vnodes` (an `Arena<Vnode>`); its
//! identity is the `VnodeKey` triple in
//! [`crate::core::identity`]. The shape carried here is
//! personality-neutral; POSIX and Win32 personalities project
//! their views from these fields plus the owning `OpenObject`.
//!
//! Per-vnode backend state (saltyfs's per-inode cache record,
//! ramfs's in-memory page list, the netsrv socket descriptor)
//! hangs off `data`, with the dispatch table at `ops`. Both are
//! type-erased pointers — the matching `VnodeKind` plus the
//! owning `Mount.kind` are the discriminator the backend uses to
//! cast back into its concrete record type.

use crate::arena::handle::Handle;
use crate::core::byte_range_lock::ByteRangeLock;
use crate::core::identity::{BackendNodeId, FsInstanceId, VnodeKey};
use crate::core::mount::Mount;

/// Vnode kind discriminator. Matches the personality-neutral
/// posix switch; POSIX `S_IFREG` / `S_IFDIR` / etc. are derived
/// from this in the personality projection.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VnodeKind {
    /// Sentinel: slot has not been populated yet.
    Empty = 0,
    /// Regular file.
    Regular = 1,
    /// Directory.
    Directory = 2,
    /// Symbolic link (target stored inline or via the backend).
    Symlink = 3,
    /// FIFO (named pipe).
    Fifo = 4,
    /// Anonymous pipe (pipe(2)).
    Pipe = 5,
    /// UNIX or INET socket.
    Socket = 6,
    /// Character device.
    CharDev = 7,
    /// Block device.
    BlockDev = 8,
    /// Shared memory object.
    Shm = 9,
}

impl Default for VnodeKind {
    fn default() -> Self {
        Self::Empty
    }
}

/// Bit flags carried on `Vnode.flags`. Drive vnode-level reaper
/// gates and identity-recovery hints; backend-specific state lives
/// in `data` instead.
pub(crate) const VN_ROOT: u32 = 1 << 0;
pub(crate) const VN_COVERED: u32 = 1 << 1;
/// Do not cache the vnode past the last `close`. procfs /
/// sysctlfs / devfs PTY-slave vnodes use this so the dispatch
/// layer drops the slot as soon as `open_refcount` returns to
/// zero, preventing stale PID / device state from being
/// re-handed to a new caller.
pub(crate) const VN_NOCACHE: u32 = 1 << 2;

/// Vnode body. One per node-of-interest in the live mount tree.
#[repr(C)]
pub(crate) struct Vnode {
    /// Composite identity — stable across Arena slot reuse.
    pub key: VnodeKey,
    /// Discriminator. `VnodeKind::Empty` after `Arena::alloc` until
    /// the file system populates the rest.
    pub kind: VnodeKind,
    /// Handle to the owning Mount in `VfsState.mounts`.
    pub mount: Handle<Mount>,
    /// `fs_instance_id` mirrored from `mount` so worker contexts
    /// that snapshot the vnode without touching the mount arena
    /// still know which fs the node belongs to.
    pub fs_instance_id: FsInstanceId,
    /// Backend-specific per-vnode payload pointer (typed-erased).
    /// Each filesystem casts this back to its concrete record
    /// type: saltyfs → `*mut SaltyfsVnodeData`, ramfs →
    /// `*mut RamfsVnodeData`, etc. May be null for vnodes whose
    /// backend has no per-node side state.
    pub data: *mut u8,
    /// Pointer to the backend's `VopVector` (operations table).
    /// Snapshotted onto VopDataCtx at dispatch time so worker
    /// threads can issue VopDataOps without reaching back into
    /// the arena.
    pub ops: *const crate::core::vop::VopVector,
    /// Bit flags: `VN_ROOT`, `VN_COVERED`.
    pub flags: u32,
    /// Cached link count from the most recent attribute fetch.
    /// Surfaces on `getattr` reply paths without a fresh backend
    /// round-trip.
    pub nlink: u32,
    /// Identity of the mount that covers this vnode (when
    /// `VN_COVERED` is set). The mount's `fs_instance_id` survives
    /// arena slot recycling, so this is keyed by id rather than
    /// arena handle; the dispatcher walks `VfsState.mounts` to
    /// resolve it on demand.
    pub covered_by_fs: FsInstanceId,
    /// Number of `OpenObject`s currently referencing this vnode.
    /// Reaches zero just before `Arena::release` hands the slot
    /// to the reclaim sweep.
    pub open_refcount: u32,
    /// Page-cache pin count. Non-zero blocks `Arena::release`
    /// so the cache layer can drain dirty pages before identity
    /// is reused.
    pub cache_pin: u32,
    /// Number of worker/data-plane operations that still hold a
    /// raw pointer snapshot of this vnode or its backend-private
    /// `data`. Reclaim transitions the arena slot to `Retired`
    /// while this is non-zero and runs `inactive` only after the
    /// final worker drops its flight.
    pub flight_count: u32,
    /// Mirror of `key.backend_id.seq` for fast read access on
    /// dispatch hot paths. Updated together with `key`.
    pub backend_seq: u32,
    /// Head of the intrusive list of byte-range advisory locks
    /// taken on this vnode. `Handle::INVALID` when no locks are
    /// held. Records live in `VfsState.byte_range_locks` and
    /// thread through `ByteRangeLock.next`.
    pub locks_head: Handle<ByteRangeLock>,
}

impl Vnode {
    pub(crate) const EMPTY: Self = Self {
        key: VnodeKey::NONE,
        kind: VnodeKind::Empty,
        mount: Handle::INVALID,
        fs_instance_id: FsInstanceId::INVALID,
        data: ::core::ptr::null_mut(),
        ops: ::core::ptr::null(),
        flags: 0,
        nlink: 0,
        covered_by_fs: FsInstanceId::INVALID,
        open_refcount: 0,
        cache_pin: 0,
        flight_count: 0,
        backend_seq: 0,
        locks_head: Handle::INVALID,
    };

    /// Backend node id (`key.backend_id.id`). Hot-path accessor
    /// kept inline so dispatch code reads the inode number without
    /// walking the composite key.
    #[inline]
    pub(crate) fn id(&self) -> u64 {
        self.key.backend_id.id
    }

    /// Vtype byte representation — convenience for backends that
    /// expose `u8` (POSIX `d_type`-style) rather than the typed
    /// `VnodeKind` enum.
    #[inline]
    pub(crate) fn vtype(&self) -> u8 {
        self.kind as u8
    }

    /// Pin the vnode against arena reclaim by bumping `cache_pin`.
    /// Used when the vnode is the root of a mount or covered by
    /// another mount — both cases require the vnode to outlive
    /// any single-posix reference.
    #[inline]
    pub(crate) fn pin(&mut self) {
        self.cache_pin = self.cache_pin.saturating_add(1);
    }

    #[inline]
    pub(crate) fn unpin(&mut self) {
        self.cache_pin = self.cache_pin.saturating_sub(1);
    }

    /// Composite key snapshot — alias for `self.key` kept for
    /// symmetry with vfs_old's vnode_key() accessor.
    #[inline]
    pub(crate) fn vnode_key(&self) -> VnodeKey {
        self.key
    }

    /// Update the cached identity of the mount covering this
    /// vnode and set `VN_COVERED`.
    #[inline]
    pub(crate) fn set_covered_by(&mut self, fs: FsInstanceId) {
        self.covered_by_fs = fs;
        self.flags |= VN_COVERED;
    }
}

pub(crate) type VnodeHandle = Handle<Vnode>;

/// Re-export for legacy code paths that consume the `VT_*` byte
/// constants instead of the typed `VnodeKind` enum. Backends that
/// store the type as `u8` (POSIX `d_type` style) read these.
pub(crate) const VT_BAD: u8 = VnodeKind::Empty as u8;
pub(crate) const VT_REG: u8 = VnodeKind::Regular as u8;
pub(crate) const VT_DIR: u8 = VnodeKind::Directory as u8;
pub(crate) const VT_LNK: u8 = VnodeKind::Symlink as u8;
pub(crate) const VT_FIFO: u8 = VnodeKind::Fifo as u8;
pub(crate) const VT_PIPE: u8 = VnodeKind::Pipe as u8;
pub(crate) const VT_SOCK: u8 = VnodeKind::Socket as u8;
pub(crate) const VT_CHR: u8 = VnodeKind::CharDev as u8;
pub(crate) const VT_BLK: u8 = VnodeKind::BlockDev as u8;
pub(crate) const VT_SHM: u8 = VnodeKind::Shm as u8;

/// Bridge `BackendNodeId.id` to a `VnodeKind` byte for in-memory
/// filesystems that store the type as `u8`. Keeps the personality
/// translation out of the backend.
#[inline]
pub(crate) const fn kind_to_vtype(kind: VnodeKind) -> u8 {
    kind as u8
}

/// Inverse of [`kind_to_vtype`] — promote a stored `u8` (loaded
/// from a backend's per-vnode record) to the typed `VnodeKind`
/// enum. Unknown / corrupt bytes collapse to `Empty` so the caller
/// can branch on `kind == Empty` for the failure path.
#[inline]
pub(crate) const fn vtype_to_kind(vtype: u8) -> VnodeKind {
    if vtype == VT_REG {
        VnodeKind::Regular
    } else if vtype == VT_DIR {
        VnodeKind::Directory
    } else if vtype == VT_LNK {
        VnodeKind::Symlink
    } else if vtype == VT_FIFO {
        VnodeKind::Fifo
    } else if vtype == VT_PIPE {
        VnodeKind::Pipe
    } else if vtype == VT_SOCK {
        VnodeKind::Socket
    } else if vtype == VT_CHR {
        VnodeKind::CharDev
    } else if vtype == VT_BLK {
        VnodeKind::BlockDev
    } else if vtype == VT_SHM {
        VnodeKind::Shm
    } else {
        VnodeKind::Empty
    }
}

#[allow(dead_code)]
#[inline]
pub(crate) const fn _unused_node_id_layout(_n: BackendNodeId) {}
