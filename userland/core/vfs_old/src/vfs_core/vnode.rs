// SPDX-License-Identifier: GPL-2.0-only
//! Vnode — personality-neutral VFS node.
//!
//! A `Vnode` represents a single filesystem object (file, directory, symbolic
//! link, device node, FIFO, or socket). It is the anchor point that ties
//! together:
//!
//! - the owning `Mount` (via `MountHandle`);
//! - the `VopVector` dispatch table;
//! - unified access arbitration state (open/deny counters) that makes
//!   cross-personality share-mode protection possible.
//!
//! # Single-owner model
//!
//! All vnode metadata is exclusively owned by the VFS main loop. There are
//! no atomic refcounts or per-vnode locks — the arena's epoch counter
//! and the `flight_count` field replace `use_count`/`hold_count`/`Mutex`.
//!
//! Workers receive resolved raw pointers via `WorkerIoCtx` and are
//! prevented from accessing freed slots by flight counting and deferred
//! reclaim.

use super::vop::VopVector;
use crate::arena::Handle;

/// Type alias for handle-based vnode identity.
pub(crate) type VnodeHandle = Handle<Vnode>;

// =========================================================================
// Vnode type (vtype)
// =========================================================================

/// Reserved — slot is free.
pub(crate) const VT_BAD: u8 = 0;
/// Regular file.
pub(crate) const VT_REG: u8 = 1;
/// Directory.
pub(crate) const VT_DIR: u8 = 2;
/// Symbolic link.
pub(crate) const VT_LNK: u8 = 3;
/// Character device.
pub(crate) const VT_CHR: u8 = 4;
/// Block device.
pub(crate) const VT_BLK: u8 = 5;
/// Named pipe / FIFO.
pub(crate) const VT_FIFO: u8 = 6;
/// Socket.
pub(crate) const VT_SOCK: u8 = 7;

// =========================================================================
// Vnode flags
// =========================================================================

/// Root vnode of a mount (cannot be unlinked; `..` may cross to parent fs).
pub(crate) const VN_ROOT: u16 = 1 << 0;
/// This vnode is covered by another mount (a child FS is mounted on it).
/// The `Vnode.covered_by` `CachedRef` carries the covering mount's
/// `FsInstanceId` (authoritative identity that survives `Arena<Mount>`
/// slot recycling) plus a `MountHandle` hint for fast-path resolution.
pub(crate) const VN_COVERED: u16 = 1 << 1;
/// This vnode has been invalidated (forced unmount, filesystem disappeared).
/// Further operations must return `VfsError::Io`.
pub(crate) const VN_DOOMED: u16 = 1 << 2;
/// Do not cache this vnode past its last open; reclaim immediately.
/// Used for synthetic filesystems (e.g. procfs) where each lookup should
/// produce fresh state.
pub(crate) const VN_NOCACHE: u16 = 1 << 3;
/// Pin the vnode against arena reclaim. Used for structural entries
/// whose identity must survive saltyfs cache pressure: mount roots,
/// scaffold covered vnodes, client cwds. Pinning is reference-counted
/// via `Vnode::pin_count`; the flag is set while `pin_count > 0` so
/// that sweep / reclaim predicates can check it with a single bit test.
pub(crate) const VN_PINNED: u16 = 1 << 4;

// =========================================================================
// Mount handle forward reference
// =========================================================================

// MountHandle is defined in mount.rs. Import it here for the Vnode struct.
pub(crate) use super::mount::MountHandle;

// =========================================================================
// Vnode
// =========================================================================

/// Personality-neutral filesystem node.
///
/// # Lifecycle
///
/// Vnodes are allocated from `Arena<Vnode>` in `VfsState`. The arena's
/// `SlotMeta` tracks the lifecycle state (`Active`, `Retired`,
/// `Reclaimable`, `Free`). The `flight_count` field tracks in-flight
/// worker references:
///
/// - Active + flight_count == 0: normal live vnode
/// - Active + flight_count > 0: live, workers hold raw pointers
/// - Retired + flight_count > 0: logically dead, workers still referencing
/// - Reclaimable: safe to sweep (epoch will be incremented)
#[repr(C)]
pub(crate) struct Vnode {
    // ---------------------------------------------------------------------
    // Type and flags
    // ---------------------------------------------------------------------
    /// Vnode type (`VT_*`).
    pub(crate) vtype: u8,
    _pad0: u8,
    /// Status flags (`VN_*`).
    pub(crate) flags: u16,
    /// Personality-specific attribute cache hints. The core layer never
    /// interprets the contents.
    pub(crate) personality_attr: u16,
    _pad1: [u8; 2],

    // ---------------------------------------------------------------------
    // Identity
    // ---------------------------------------------------------------------
    /// Backend-defined identifier. Ramfs uses the in-memory inode number;
    /// saltyfs uses the remote inode number; devfs uses a device index;
    /// procfs uses a composite (kind, pid, subfile) encoded into 64 bits.
    pub(crate) id: u64,
    /// Backend-defined incarnation / sequence number for `id`.
    /// Backends that do not expose incarnation tracking keep this at 0.
    pub(crate) backend_seq: u32,
    _pad_identity: [u8; 4],
    /// Stable identity of the mount instance this vnode belongs to.
    /// Copied from `Mount::fs_instance_id` at vget time. Paired with
    /// `id` yields the `VnodeKey` used by the resolve cache and by
    /// identity-based mount covering resolution.
    pub(crate) fs_instance_id: crate::vfs_core::identity::FsInstanceId,

    // ---------------------------------------------------------------------
    // Handle-based linkage (replaces raw pointers)
    // ---------------------------------------------------------------------
    /// Owning mount as an identity + handle-hint pair. Authoritative
    /// identity rides on the `id()` side; `handle_hint()` is a
    /// fast-path `MountHandle` cache. Stale (slot-recycled) hints
    /// are tolerated — `CachedRef::resolve(&state)` falls back to
    /// `VfsState::mount_by_fs_instance_id` via the
    /// `ResolveByIdentity` impl. `FsInstanceId::INVALID` on the
    /// `id()` side only for uninitialised slots.
    pub(crate) mount: crate::vfs_core::cached_ref::CachedRef<
        crate::vfs_core::identity::FsInstanceId,
        MountHandle,
    >,
    /// Dispatch vtable (usually a static pointer). Never null for active vnodes.
    pub(crate) ops: *const VopVector,
    /// If a child mount covers this vnode, this holds the covering
    /// mount's stable identity + handle-hint pair. Both sides are
    /// `INVALID` when the vnode is not covered. The `id()` side is
    /// authoritative: a recycled `Arena<Mount>` slot cannot impersonate
    /// a previously-released mount, so covering resolution never
    /// returns a dangling pointer. Readers resolve via
    /// `CachedRef::resolve(&state)` which delegates to
    /// `VfsState::mount_by_fs_instance_id` on hint staleness.
    pub(crate) covered_by: crate::vfs_core::cached_ref::CachedRef<
        crate::vfs_core::identity::FsInstanceId,
        MountHandle,
    >,

    /// Filesystem-specific data. Layout depends on `ops`:
    /// - ramfs → `RamfsVnodeData` (dirents, writable chain, symlink slot, ...)
    /// - saltyfs → `SaltyfsVnodeData` (remote inode, cached attrs, ...)
    /// - devfs → `DevfsVnodeData` (DevKind, sub_id)
    /// - procfs → `ProcfsVnodeData` (kind, pid)
    pub(crate) data: *mut u8,

    // ---------------------------------------------------------------------
    // Arbitration state (owner-thread only — no atomics needed)
    // ---------------------------------------------------------------------
    /// Number of live open-file slots referencing this vnode.
    pub(crate) open_count: u32,
    /// Hard link count — reflects dirents pointing at this vnode.
    pub(crate) nlink: u32,

    /// Count of opens that request READ access.
    pub(crate) opens_read: u32,
    /// Count of opens that request WRITE access.
    pub(crate) opens_write: u32,
    /// Count of opens that request EXEC access.
    pub(crate) opens_exec: u32,

    /// Count of opens that deny others READ access.
    pub(crate) denies_read: u32,
    /// Count of opens that deny others WRITE access.
    pub(crate) denies_write: u32,
    /// Count of opens that deny dirent removal (Win32 `FILE_SHARE_DELETE`
    /// absent). POSIX `unlink` ignores this.
    pub(crate) denies_unlink_name: u32,

    /// Directory mutation epoch counter. Incremented on every
    /// create/unlink/rename/link/rmdir that modifies this directory.
    pub(crate) seq: u32,

    // ---------------------------------------------------------------------
    // Worker flight tracking
    // ---------------------------------------------------------------------
    /// Number of in-flight worker references to this vnode. Owner-thread
    /// only — workers increment/decrement this indirectly via completion
    /// queue. A vnode cannot be reclaimed while `flight_count > 0`.
    pub(crate) flight_count: u32,

    /// Structural pin count. Incremented by `pin()` and decremented by
    /// `unpin()`. While non-zero the vnode is kept alive by
    /// `should_reclaim` and skipped by `Arena<Vnode>::sweep_with`.
    /// Mount roots, scaffold covered vnodes, and client cwds all pin.
    pub(crate) pin_count: u16,
    _pad2: [u8; 2],
}

impl Vnode {
    /// Check whether this vnode should be reclaimed after the last open
    /// closes. Called by the owner loop (no lock needed).
    ///
    /// A pinned vnode is never reclaimable — structural references
    /// (mount roots, covered vnodes, cwd cache entries) must survive
    /// open_count transitions to zero.
    #[inline]
    pub(crate) fn should_reclaim(&self) -> bool {
        if self.open_count != 0 {
            return false;
        }
        if self.is_pinned() {
            return false;
        }
        (self.flags & VN_NOCACHE) != 0 || self.nlink == 0 || (self.flags & VN_DOOMED) != 0
    }

    /// Stable identity of this vnode. Valid only after the backend's
    /// `vget` has stamped `fs_instance_id` and `id`.
    #[inline]
    pub(crate) fn vnode_key(&self) -> crate::vfs_core::identity::VnodeKey {
        crate::vfs_core::identity::VnodeKey::new(self.fs_instance_id, self.backend_node_id())
    }

    /// Backend identity of this vnode. Backends that do not yet surface an
    /// incarnation sequence still use `seq = 0`.
    #[inline]
    pub(crate) fn backend_node_id(&self) -> trona_protocol::BackendNodeId {
        trona_protocol::BackendNodeId::new(self.id, self.backend_seq)
    }

    /// Pin this vnode against arena reclaim. Refcount-style — a matching
    /// `unpin()` must eventually run. Pinning is idempotent at the
    /// flag-bit level: the `VN_PINNED` bit stays set for the full
    /// pinned window and tracks `pin_count > 0`.
    #[inline]
    pub(crate) fn pin(&mut self) {
        self.pin_count = self.pin_count.saturating_add(1);
        self.flags |= VN_PINNED;
    }

    /// Drop one structural pin. Clears `VN_PINNED` on the last drop.
    /// Saturating subtraction means spurious unpins are harmless, but
    /// every `pin()` is expected to be balanced by exactly one
    /// `unpin()` to prevent leaks.
    #[inline]
    pub(crate) fn unpin(&mut self) {
        self.pin_count = self.pin_count.saturating_sub(1);
        if self.pin_count == 0 {
            self.flags &= !VN_PINNED;
        }
    }

    /// Is this vnode currently pinned? Single-bit test.
    #[inline]
    pub(crate) fn is_pinned(&self) -> bool {
        (self.flags & VN_PINNED) != 0
    }
}
