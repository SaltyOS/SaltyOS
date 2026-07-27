// SPDX-License-Identifier: GPL-2.0-only
//! Filesystem-level dispatch table.
//!
//! Each filesystem backend exposes a typed `VfsOps` table whose pointer is
//! stored in `Mount.vfsops`. The field type stays `*const ()` so existing
//! anchor-style backend identity checks keep working; dispatch helpers
//! cast back to `*const VfsOps` before invoking a callback.

use crate::owner::VfsState;
use crate::vfs_core::vnode::VnodeHandle;

use super::mount::MountHandle;

/// Layout describing a single mounted filesystem. Backends populate the
/// callbacks they actually implement; an `empty()` table is the safe
/// default before a backend wires anything.
#[repr(C)]
pub(crate) struct VfsOps {
    /// Backend-specific statvfs implementation. None falls back to a
    /// default snapshot driven by the generic mount metadata.
    pub(crate) statfs: Option<fn(&VfsState, MountHandle, &mut StatfsSnapshot) -> u64>,
    /// Filesystem-wide sync hook. None means the backend has nothing to
    /// flush.
    pub(crate) sync: Option<fn(&mut VfsState, MountHandle) -> u64>,
    /// Mount-time option re-application. Receives the already-merged
    /// flag word plus the raw opt token slice; the backend returns an
    /// errno (or `TRONA_OK`) and updates its own per-mount data
    /// in-place. The caller is responsible for committing the new
    /// `Mount.flags` after a successful remount.
    pub(crate) remount: Option<fn(&mut VfsState, MountHandle, u32, &[u8]) -> u64>,
    /// Resolve a regular-file vnode into a transferrable mmap backing
    /// descriptor. Backends that need direct cap transfer (tmpfs MO,
    /// device pages, …) implement this; everyone else returns `Ok(None)`
    /// and lets the caller fall through to the generic file cache.
    /// On `Ok(Some(BackingResolution { kind, mo_cap }))`, the caller
    /// installs `mo_cap` in the IPC send-cap slot and replies with
    /// `kind`. The backend retains its own cap copy so the MO survives
    /// the transfer.
    pub(crate) resolve_backing:
        Option<fn(&mut VfsState, VnodeHandle) -> Result<Option<BackingResolution>, u64>>,
    /// Tear down per-vnode backend state when the generic vnode
    /// reclaim path decides the vnode is unreachable
    /// (`nlink == 0`, `open_count == 0`). Backends that hand out cap
    /// references to other servers (tmpfs → mmsrv) may keep storage
    /// alive here and finish the release later via their own
    /// notification path; everyone else releases immediately.
    pub(crate) reclaim_vnode: Option<fn(&mut VfsState, VnodeHandle)>,
}

impl VfsOps {
    pub(crate) const fn empty() -> Self {
        Self {
            statfs: None,
            sync: None,
            remount: None,
            resolve_backing: None,
            reclaim_vnode: None,
        }
    }
}

/// Output of [`VfsOps::resolve_backing`]. `kind` is one of the
/// `MMAP_BACKING_*` constants; `mo_cap` is the cap the caller hands to
/// the requester via `set_send_cap_ctx`. Backends keep their own
/// duplicate of the cap.
#[derive(Clone, Copy)]
pub(crate) struct BackingResolution {
    pub(crate) kind: u64,
    pub(crate) mo_cap: u64,
}

/// Generic statfs payload populated by `VfsOps::statfs`. Mirrors the
/// POSIX `struct statvfs` member set the IPC layer eventually exposes.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StatfsSnapshot {
    pub(crate) f_bsize: u64,
    pub(crate) f_frsize: u64,
    pub(crate) f_blocks: u64,
    pub(crate) f_bfree: u64,
    pub(crate) f_bavail: u64,
    pub(crate) f_files: u64,
    pub(crate) f_ffree: u64,
    pub(crate) f_favail: u64,
    pub(crate) f_fsid: u64,
    pub(crate) f_flag: u64,
    pub(crate) f_namemax: u64,
}

impl StatfsSnapshot {
    pub(crate) const fn zeroed() -> Self {
        Self {
            f_bsize: 0,
            f_frsize: 0,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_favail: 0,
            f_fsid: 0,
            f_flag: 0,
            f_namemax: 0,
        }
    }
}

#[inline]
pub(crate) fn table_from_ptr(ptr: *const ()) -> Option<&'static VfsOps> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: every `Mount.vfsops` pointer is sourced from a static
        // `VfsOps` table installed by the corresponding backend.
        Some(unsafe { &*(ptr as *const VfsOps) })
    }
}

/// Resolve the `VfsOps` table that owns `vnode` via its mount entry.
#[inline]
pub(crate) fn vfsops_for_vnode(state: &VfsState, vnode: VnodeHandle) -> Option<&'static VfsOps> {
    let mh = state.vnodes.get(vnode)?.mount.handle;
    let ops_ptr = state.mounts.get(mh)?.vfsops;
    table_from_ptr(ops_ptr)
}
