// SPDX-License-Identifier: GPL-2.0-only
//! Mount — an instance of a filesystem mounted in the VFS tree.
//!
//! A `Mount` binds a backend (identified by `VfsOps` + `VopVector`) to a
//! location in the VFS namespace. Multiple `Mount` entries may share the
//! same `VfsOps` / `VopVector` (e.g. several ramfs instances).
//!
//! Mounts form a tree anchored at `VfsState.root_mount`. The parent link
//! (`Mount.parent: MountHandle`) walks up the tree; path resolution uses
//! `Vnode.covered_by: MountHandle` to traverse downward into child mounts.
//!
//! # Single-owner model
//!
//! All mount metadata is exclusively owned by the VFS main loop. The
//! per-mount `Mutex` and the global `MOUNT_TABLE_LOCK` / `ROOT_MOUNT`
//! statics are eliminated — structural mount-tree changes are serialized
//! by the single-threaded owner loop.

use crate::arena::Handle;
use super::vfs::VfsOps;
use super::vop::VopVector;

/// Type alias for handle-based mount identity.
pub(crate) type MountHandle = Handle<Mount>;

/// Type alias for handle-based vnode reference from within mount.
pub(crate) type VnodeHandle = Handle<super::vnode::Vnode>;

// =========================================================================
// Mount flags
// =========================================================================

/// Mount is read-only — all mutating ops return `VfsError::ReadOnly`.
pub(crate) const MNT_RDONLY: u32 = 1 << 0;
/// Ignore set-user-id and set-group-id bits when executing binaries from this mount.
pub(crate) const MNT_NOSUID: u32 = 1 << 1;
/// Disallow executing any file from this mount.
pub(crate) const MNT_NOEXEC: u32 = 1 << 2;
/// Disallow access to device special files on this mount.
pub(crate) const MNT_NODEV: u32 = 1 << 3;
/// Do not follow symbolic links on this mount.
pub(crate) const MNT_NOSYMFOLLOW: u32 = 1 << 4;
/// Lazy unmount — detach from the tree but keep backing state alive until
/// the last open reference drops.
pub(crate) const MNT_DETACH: u32 = 1 << 5;
/// Forced unmount — mark all vnodes `VN_DOOMED` and tear down backing state
/// regardless of live references.
pub(crate) const MNT_FORCE: u32 = 1 << 6;
/// Bind mount — the mount's root vnode is an existing vnode from another
/// mount, not a freshly-allocated backend root.
pub(crate) const MNT_BIND: u32 = 1 << 8;
/// Recursive bind mount — clone all sub-mounts of the source tree.
pub(crate) const MNT_RBIND: u32 = 1 << 9;
/// POSIX-only mount — invisible to Win32 `namei`.
pub(crate) const MNT_POSIX_ONLY: u32 = 1 << 10;
/// Win32-only mount — invisible to POSIX `namei`.
pub(crate) const MNT_WIN32_ONLY: u32 = 1 << 11;

/// Maximum length of a filesystem type name.
pub(crate) const MOUNT_FS_TYPE_MAX: usize = 16;
/// Maximum length of a mount path recorded for `/proc/mounts`-style output.
pub(crate) const MOUNT_PATH_MAX: usize = 64;

// =========================================================================
// Mount
// =========================================================================

/// An instance of a filesystem mounted in the VFS tree.
#[repr(C)]
pub(crate) struct Mount {
    // ---------------------------------------------------------------------
    // Identity
    // ---------------------------------------------------------------------
    /// Stable slot index — used by `/proc/mounts` and readdir cursors.
    pub(crate) id: u16,
    _pad0: [u8; 2],

    /// Mount flags (`MNT_*`).
    pub(crate) flags: u32,

    // ---------------------------------------------------------------------
    // Backend binding
    // ---------------------------------------------------------------------
    /// Filesystem-level operations (mount, unmount, root, vget, statfs, sync).
    pub(crate) vfsops: *const VfsOps,
    /// Vnode operations for every vnode allocated from this mount.
    pub(crate) vops: *const VopVector,

    // ---------------------------------------------------------------------
    // Handle-based tree linkage (replaces raw pointers)
    // ---------------------------------------------------------------------
    /// Root vnode of the mounted filesystem (`VN_ROOT` is set on it).
    pub(crate) root_vnode: VnodeHandle,
    /// The vnode in the parent filesystem that this mount covers.
    /// `VnodeHandle::INVALID` only for the root mount.
    pub(crate) covered_vnode: VnodeHandle,
    /// Parent mount. `MountHandle::INVALID` only for the root mount.
    pub(crate) parent: MountHandle,

    // ---------------------------------------------------------------------
    // Backend-private state
    // ---------------------------------------------------------------------
    /// Filesystem-specific mount data. Layout depends on `vfsops`.
    pub(crate) data: *mut u8,

    // ---------------------------------------------------------------------
    // Identification (for /proc/mounts-style introspection)
    // ---------------------------------------------------------------------
    /// Filesystem type name ("ramfs", "saltyfs", "devfs", ...).
    pub(crate) fs_type_name: [u8; MOUNT_FS_TYPE_MAX],
    pub(crate) fs_type_name_len: u8,
    _pad1: [u8; 7],

    /// Mount path as provided to `VFS_MOUNT`.
    pub(crate) mount_path: [u8; MOUNT_PATH_MAX],
    pub(crate) mount_path_len: u8,
    _pad2: [u8; 7],
}
