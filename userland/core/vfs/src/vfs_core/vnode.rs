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
//! Workers receive resolved raw pointers via `VopDataContext` and are
//! prevented from accessing freed slots by flight counting and deferred
//! reclaim.

use crate::arena::Handle;
use super::vop::VopVector;

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
/// The `Vnode.covered_by` field holds a `MountHandle` to the covering mount.
pub(crate) const VN_COVERED: u16 = 1 << 1;
/// This vnode has been invalidated (forced unmount, filesystem disappeared).
/// Further operations must return `VfsError::Io`.
pub(crate) const VN_DOOMED: u16 = 1 << 2;
/// Do not cache this vnode past its last open; reclaim immediately.
/// Used for synthetic filesystems (e.g. procfs) where each lookup should
/// produce fresh state.
pub(crate) const VN_NOCACHE: u16 = 1 << 3;

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

    // ---------------------------------------------------------------------
    // Handle-based linkage (replaces raw pointers)
    // ---------------------------------------------------------------------
    /// Owning mount. `MountHandle::INVALID` only for uninitialized slots.
    pub(crate) mount: MountHandle,
    /// Dispatch vtable (usually a static pointer). Never null for active vnodes.
    pub(crate) ops: *const VopVector,
    /// If a child mount covers this vnode, this holds a handle to that mount.
    /// `MountHandle::INVALID` otherwise.
    pub(crate) covered_by: MountHandle,

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
}

impl Vnode {
    /// Check whether this vnode should be reclaimed after the last open
    /// closes. Called by the owner loop (no lock needed).
    #[inline]
    pub(crate) fn should_reclaim(&self) -> bool {
        if self.open_count != 0 {
            return false;
        }
        (self.flags & VN_NOCACHE) != 0 || self.nlink == 0
    }
}
