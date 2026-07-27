// SPDX-License-Identifier: GPL-2.0-only
//! `VfsOps` and the `FsType` registry.
//!
//! `VfsOps` is the filesystem-level dispatch table — it groups operations
//! that are intrinsic to a mount instance rather than a single vnode
//! (mount/unmount, root lookup, `vget` by backend id, statfs, sync).
//!
//! `FsType` registers a filesystem name ("ramfs", "tmpfs", "devfs",
//! "procfs", "saltyfs", ...) and binds it to a `VfsOps` + `VopVector`.
//! `register_fs_type` is called once per type during bootstrap Stage 2.

use super::error::{VfsError, VfsResult};
use super::file::VStatfs;
use super::vnode::VnodeHandle;
use super::vop::VopVector;
use super::vop_context::OwnerMountCtx;

// =========================================================================
// VfsOps
// =========================================================================

/// Filesystem-level operations.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VfsOps {
    /// Initialize a fresh mount instance. Called after a `Mount` slot has
    /// been allocated and its generic fields populated. The implementation
    /// allocates backend-private state into `mp.data` and sets `mp.root_vnode`.
    ///
    /// `source` is a backend-defined 64-bit value (e.g. an IPC capability
    /// slot for saltyfs, zero for in-memory filesystems). `opts_ptr`/`opts_len`
    /// carries an opaque byte blob from the caller — typically "key=value"
    /// pairs but backend-interpreted.
    ///
    /// `can_park` tells the backend whether its caller can wait on a
    /// backend-side completion: `true` for the standard VFS_MOUNT
    /// dispatch path (owner loop will route `MountReady` back to the
    /// original reply slot); `false` for bootstrap and `late_mount`
    /// contexts where the caller cannot drive a completion. Backends
    /// that never park (in-memory filesystems) ignore the parameter.
    ///
    /// Returns a [`VopOutcome`]: in-memory filesystems collapse to
    /// `Ok(Ready(()))` synchronously, while disk- or network-backed
    /// backends that must wait on a slow backend RPC return
    /// `Ok(Parked(...))` — but only when `can_park == true`. With
    /// `can_park == false` a backend must fall back to its synchronous
    /// path and return `Ready(())` / `Err(...)` before returning.
    pub(crate) mount: unsafe fn(
        ctx: &mut OwnerMountCtx<'_>,
        source: u64,
        opts_ptr: *const u8,
        opts_len: u8,
        can_park: bool,
    ) -> crate::vfs_core::outcome::VopOutcome<()>,

    /// Reverse of `mount`. Tear down all backend state. If `force` is true,
    /// vnodes with live references must be marked `VN_DOOMED`.
    pub(crate) unmount: unsafe fn(ctx: &mut OwnerMountCtx<'_>, force: bool) -> VfsResult<()>,

    /// Return the root vnode of this mount as a handle.
    pub(crate) root: unsafe fn(ctx: &OwnerMountCtx<'_>) -> VfsResult<VnodeHandle>,

    /// Look up a vnode by its backend-specific id, allocating a cache slot
    /// if necessary. Returns a handle.
    pub(crate) vget: unsafe fn(ctx: &mut OwnerMountCtx<'_>, id: u64) -> VfsResult<VnodeHandle>,

    /// Fill filesystem statistics.
    pub(crate) statfs: unsafe fn(ctx: &OwnerMountCtx<'_>, out: *mut VStatfs) -> VfsResult<()>,

    /// Flush any pending backend writes (best effort).
    pub(crate) sync: unsafe fn(ctx: &OwnerMountCtx<'_>) -> VfsResult<()>,
}

// =========================================================================
// FsType registry
// =========================================================================

/// Maximum length of a registered filesystem type name.
pub(crate) const FS_TYPE_NAME_MAX: usize = 16;

/// Maximum number of filesystem types that can be registered.
pub(crate) const MAX_FS_TYPES: usize = 8;

/// A registered filesystem type. Created by `register_fs_type`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct FsType {
    /// 1 if this slot holds a registered type, 0 if free.
    pub(crate) active: u8,
    pub(crate) name_len: u8,
    _pad: [u8; 6],
    pub(crate) name: [u8; FS_TYPE_NAME_MAX],
    pub(crate) vfsops: *const VfsOps,
    pub(crate) vops: *const VopVector,
}

impl FsType {
    pub(crate) const fn zeroed() -> Self {
        FsType {
            active: 0,
            name_len: 0,
            _pad: [0; 6],
            name: [0; FS_TYPE_NAME_MAX],
            vfsops: core::ptr::null(),
            vops: core::ptr::null(),
        }
    }
}

unsafe impl Sync for FsType {}

// Global registry. Written only during bootstrap Stage 2 (single-threaded)
// and read-only thereafter, so no lock is required for the common path.
// A rwlock could be added later if dynamic fs registration becomes a thing.
pub(crate) static mut FS_TYPES: [FsType; MAX_FS_TYPES] = [FsType::zeroed(); MAX_FS_TYPES];

/// Register a filesystem type under the given name.
///
/// # Preconditions
///
/// Must be called during bootstrap (before any worker threads are spawned).
///
/// # Errors
///
/// - [`VfsError::Exists`] — a type with the same name is already registered.
/// - [`VfsError::NoSpace`] — `MAX_FS_TYPES` slots exhausted.
/// - [`VfsError::NameTooLong`] — name exceeds `FS_TYPE_NAME_MAX`.
pub(crate) unsafe fn register_fs_type(
    name: &[u8],
    vfsops: *const VfsOps,
    vops: *const VopVector,
) -> VfsResult<()> {
    if name.len() > FS_TYPE_NAME_MAX {
        return Err(VfsError::NameTooLong);
    }

    let table = unsafe { &raw mut FS_TYPES };

    // Duplicate check + first free slot search.
    let mut free_idx: Option<usize> = None;
    for i in 0..MAX_FS_TYPES {
        let entry = unsafe { &mut (*table)[i] };
        if entry.active == 0 {
            if free_idx.is_none() {
                free_idx = Some(i);
            }
            continue;
        }
        if entry.name_len as usize == name.len() && &entry.name[..name.len()] == name {
            return Err(VfsError::Exists);
        }
    }

    let idx = free_idx.ok_or(VfsError::NoSpace)?;
    let entry = unsafe { &mut (*table)[idx] };
    entry.active = 1;
    entry.name_len = name.len() as u8;
    entry.name[..name.len()].copy_from_slice(name);
    entry.vfsops = vfsops;
    entry.vops = vops;
    Ok(())
}

/// Look up a registered filesystem type by name.
pub(crate) unsafe fn find_fs_type(name: &[u8]) -> Option<&'static FsType> {
    let table = unsafe { &raw const FS_TYPES };
    for i in 0..MAX_FS_TYPES {
        let entry = unsafe { &(*table)[i] };
        if entry.active == 1
            && entry.name_len as usize == name.len()
            && &entry.name[..name.len()] == name
        {
            return Some(entry);
        }
    }
    None
}
