// SPDX-License-Identifier: GPL-2.0-only
//! pipefs — Win32 named pipe filesystem.
//!
//! Exposes the `\\.\pipe\` namespace used by Win32 `CreateNamedPipe` /
//! `ConnectNamedPipe`. Pipes created here are visible only to Win32
//! processes via `namei_win32`.
//!
//! The filesystem uses a static pool of `NamedPipeSlot` entries for
//! namespace management. Actual data transfer is delegated to the
//! existing anonymous pipe infrastructure in `crate::fileops::pipe`.
//!
//! Vnodes are allocated from the global `Arena<Vnode>`. The mount data
//! stores parallel arrays of `VnodeHandle` and `u64` (vnode id) for
//! handle-based lookup by id.

pub(crate) mod types;
mod vfsops;
mod vops;

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::vfs::{register_fs_type, VfsOps};
use crate::vfs_core::vnode::VnodeHandle;
use crate::vfs_core::vop::VopVector;

use types::{NamedPipeSlot, MAX_NAMED_PIPES};

// =========================================================================
// PipefsMountData — per-mount backend data
// =========================================================================

/// Maximum vnodes: 1 root dir + MAX_NAMED_PIPES pipe entries.
pub(crate) const MAX_PIPEFS_VNODES: usize = 1 + MAX_NAMED_PIPES;

/// Per-mount state for pipefs.
///
/// Vnodes live in the global arena. This struct stores parallel arrays of
/// handles and ids for reverse lookup.
#[repr(C)]
pub(crate) struct PipefsMountData {
    /// Handle to each vnode allocated for this mount.
    pub(crate) vnode_handles: [VnodeHandle; MAX_PIPEFS_VNODES],
    /// Backend-assigned id for each vnode (parallel to `vnode_handles`).
    pub(crate) vnode_ids: [u64; MAX_PIPEFS_VNODES],
    /// Parallel array of vnode-private data.
    pub(crate) vdata: [PipefsVnodeData; MAX_PIPEFS_VNODES],
    /// Named pipe slot pool.
    pub(crate) slots: [NamedPipeSlot; MAX_NAMED_PIPES],
    /// Number of vnodes currently populated (next allocation index).
    pub(crate) count: usize,
    /// Monotonic id counter for new vnodes.
    pub(crate) next_id: u64,
}

// PipefsMountData is allocated via map_anon + write_bytes (zero-init).
// VnodeHandle::INVALID has an all-ones representation for the slot field,
// but zero-init produces slot=0/gen=0 which is also invalid (gen 0 is
// never issued by the arena). So zero-init is safe for the handle arrays.

// =========================================================================
// PipefsVnodeData — per-vnode backend data
// =========================================================================

/// Backend-private data hung off `Vnode.data` for pipefs vnodes.
#[repr(C)]
pub(crate) struct PipefsVnodeData {
    /// Index into `PipefsMountData.slots` for pipe vnodes.
    /// Unused (u32::MAX) for the root directory vnode.
    pub(crate) slot_idx: u32,
    /// `1` if this is the root directory vnode.
    pub(crate) is_root: u8,
}

impl PipefsVnodeData {
    pub(crate) const fn zeroed() -> Self {
        PipefsVnodeData {
            slot_idx: u32::MAX,
            is_root: 0,
        }
    }
}

// =========================================================================
// Mount-data helpers (used by vops)
// =========================================================================

/// Find a free vdata slot and return its index.
pub(super) unsafe fn alloc_vdata_slot(md: *mut PipefsMountData) -> Option<usize> {
    unsafe {
        let count = (*md).count;
        if count >= MAX_PIPEFS_VNODES {
            return None;
        }
        let idx = count;
        (*md).count = count + 1;
        Some(idx)
    }
}

/// Record a vnode handle and id in the mount data arrays.
pub(super) unsafe fn record_vnode(md: *mut PipefsMountData, vh: VnodeHandle, id: u64) {
    unsafe {
        // The slot was already allocated by alloc_vdata_slot, so count-1 is
        // the index of the most recently allocated entry.
        let idx = (*md).count - 1;
        (*md).vnode_handles[idx] = vh;
        (*md).vnode_ids[idx] = id;
    }
}

// =========================================================================
// Static VfsOps / VopVector
// =========================================================================

pub(crate) static PIPEFS_VFSOPS: VfsOps = vfsops::PIPEFS_VFSOPS;
pub(crate) static PIPEFS_VOPS: VopVector = vops::PIPEFS_VOPS;

// =========================================================================
// Registration
// =========================================================================

/// Register the `pipefs` filesystem type. Called during VFS bootstrap Stage 2.
pub(crate) unsafe fn register() -> VfsResult<()> {
    unsafe {
        register_fs_type(
            b"pipefs",
            &raw const PIPEFS_VFSOPS,
            &raw const PIPEFS_VOPS,
        )
    }
}
