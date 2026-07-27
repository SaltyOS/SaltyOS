// SPDX-License-Identifier: GPL-2.0-only
//
//! pipefs — named-pipe filesystem for the Win32 `\\.\pipe\`
//! namespace.
//!
//! Static pool of `NamedPipeSlot` entries for the namespace; data
//! transfer is delegated to `posix/pipe`'s anonymous-pipe arena.
//! Vnodes live in the central `VfsState.vnodes`; per-mount state
//! stores parallel arrays of `(VnodeHandle, vnode_id, vdata)` for
//! handle-based lookup by id.

pub(crate) mod types;
mod vfsops;
mod vops;

use crate::arena::handle::Handle;
use crate::core::pipe::PipeState;
use crate::core::vnode::VnodeHandle;
use crate::core::vop::{
    DATA_OPS_DEFAULT, META_OPS_DEFAULT, VfsOps, VopDataOps, VopMetaOps, VopVector,
};

use types::{MAX_NAMED_PIPES, NamedPipeSlot};

// =========================================================================
// PipefsMountData — per-mount backend data
// =========================================================================

/// Maximum vnodes: 1 root dir + `MAX_NAMED_PIPES` pipe entries.
pub(crate) const MAX_PIPEFS_VNODES: usize = 1 + MAX_NAMED_PIPES;

/// Per-mount state for pipefs. Vnodes live in the global arena;
/// this struct stores parallel arrays of handles and ids for
/// reverse lookup.
#[repr(C)]
pub(crate) struct PipefsMountData {
    pub(crate) vnode_handles: [VnodeHandle; MAX_PIPEFS_VNODES],
    pub(crate) vnode_ids: [u64; MAX_PIPEFS_VNODES],
    pub(crate) vdata: [PipefsVnodeData; MAX_PIPEFS_VNODES],
    pub(crate) slots: [NamedPipeSlot; MAX_NAMED_PIPES],
    pub(crate) count: usize,
    pub(crate) next_id: u64,
}

// PipefsMountData is allocated via `map_anon` + `write_bytes` so a
// zero-init image is valid. `Handle::INVALID` is the all-ones slot
// pattern, but `slot=0/epoch=0` (the zero pattern) also fails the
// generation check, so a fresh page reads back as all-stale slots
// — matching the `count = 0` invariant.

#[repr(C)]
pub(crate) struct PipefsVnodeData {
    /// Index into `PipefsMountData.slots` for pipe vnodes;
    /// `u32::MAX` for the root directory.
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
// Mount-data helpers
// =========================================================================

pub(super) unsafe fn alloc_vdata_slot(md: *mut PipefsMountData) -> Option<usize> {
    unsafe {
        let count = (*md).count;
        if count >= MAX_PIPEFS_VNODES {
            return None;
        }
        Some(count)
    }
}

pub(super) unsafe fn record_vnode(md: *mut PipefsMountData, vnode_h: VnodeHandle, id: u64) {
    unsafe {
        let idx = (*md).count;
        (*md).vnode_handles[idx] = vnode_h;
        (*md).vnode_ids[idx] = id;
        (*md).count = idx + 1;
    }
}

#[allow(dead_code)]
pub(super) unsafe fn lookup_handle(md: *mut PipefsMountData, id: u64) -> VnodeHandle {
    unsafe {
        for j in 0..(*md).count {
            if (*md).vnode_ids[j] == id && (*md).vnode_handles[j].is_valid() {
                return (*md).vnode_handles[j];
            }
        }
        VnodeHandle::INVALID
    }
}

// =========================================================================
// Static dispatch tables
// =========================================================================

pub(crate) static PIPEFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: vops::pipefs_lookup,
        lookup_ci: vops::pipefs_lookup,
        create: vops::pipefs_create,
        mkdir: META_OPS_DEFAULT.mkdir,
        symlink: META_OPS_DEFAULT.symlink,
        mkfifo: META_OPS_DEFAULT.mkfifo,
        unlink: vops::pipefs_unlink,
        rmdir: META_OPS_DEFAULT.rmdir,
        link: META_OPS_DEFAULT.link,
        rename: META_OPS_DEFAULT.rename,
        open: vops::pipefs_open,
        close: vops::pipefs_close,
        getattr: vops::pipefs_getattr,
        setattr: META_OPS_DEFAULT.setattr,
        access: vops::pipefs_access,
        readlink: META_OPS_DEFAULT.readlink,
        truncate: META_OPS_DEFAULT.truncate,
        data_size: META_OPS_DEFAULT.data_size,
        inactive: vops::pipefs_inactive,
    },
    data: VopDataOps {
        read: vops::pipefs_read,
        write: vops::pipefs_write,
        writeback: vops::pipefs_write,
        fsync: DATA_OPS_DEFAULT.fsync,
        readdir: vops::pipefs_readdir,
        statfs: vops::pipefs_statfs,
        getxattr: DATA_OPS_DEFAULT.getxattr,
        setxattr: DATA_OPS_DEFAULT.setxattr,
        listxattr: DATA_OPS_DEFAULT.listxattr,
        removexattr: DATA_OPS_DEFAULT.removexattr,
        ioctl: DATA_OPS_DEFAULT.ioctl,
        mmap_get_page: DATA_OPS_DEFAULT.mmap_get_page,
    },
};

pub(crate) static PIPEFS_VFSOPS: VfsOps = VfsOps {
    mount: vfsops::pipefs_mount,
    unmount: vfsops::pipefs_unmount,
    root: vfsops::pipefs_root,
    vget: vfsops::pipefs_vget,
    statfs: vfsops::pipefs_statfs,
    sync: vfsops::pipefs_sync,
};

#[allow(dead_code)]
const _PIPE_HANDLE_TYPE: Option<Handle<PipeState>> = None;
