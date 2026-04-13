// SPDX-License-Identifier: GPL-2.0-only
//! Tmpfs data structures — per-vnode and per-mount private state.
//!
//! tmpfs is an independent in-memory filesystem with size and inode limits.
//! Unlike ramfs, tmpfs has no read-only data, no persistent file tracking,
//! and enforces configurable capacity constraints.

use crate::arena::Handle;
use crate::personality::posix::types::{PipeState, ShmData};
use crate::server::consts::*;

// =========================================================================
// Dirent — on-mount directory entry
// =========================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Dirent {
    pub(crate) active: u8,
    pub(crate) ino: u32,
    pub(crate) name: [u8; MAX_NAME_LEN],
    pub(crate) name_len: u8,
}

impl Dirent {
    pub(crate) const fn zeroed() -> Self {
        Dirent {
            active: 0,
            ino: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
        }
    }
}

// =========================================================================
// TmpfsVnodeData — stored at Vnode.data
// =========================================================================

/// Per-vnode filesystem-private data for tmpfs.
///
/// Stored as a pool-allocated object; `Vnode.data` points at it.
/// `Vnode.id` holds the same value as `id` here.
#[repr(C)]
pub(crate) struct TmpfsVnodeData {
    /// 1 if this pool slot is in use, 0 if free.
    pub(crate) active: u8,
    /// File type (VT_* from vfs_core::vnode).
    pub(crate) ftype: u8,
    /// Device subtype (DEV_CONSOLE, DEV_NULL, etc.) for char/block devices.
    pub(crate) dev_type: u8,
    _pad0: u8,

    /// Unique id within this tmpfs instance. Equals `Vnode.id`.
    pub(crate) id: u64,
    /// Canonical live vnode handle for this inode.
    pub(crate) vnode_handle: crate::vfs_core::vnode::VnodeHandle,
    /// Parent directory id (0 for root).
    pub(crate) parent_id: u64,

    /// POSIX mode bits (type + permission).
    pub(crate) mode: u32,
    /// Owner user id.
    pub(crate) uid: u32,
    /// Owner group id.
    pub(crate) gid: u32,
    /// Hard link count.
    pub(crate) nlink: u32,
    /// File size in bytes.
    pub(crate) size: u64,

    /// Access time (nanoseconds since epoch).
    pub(crate) atime: u64,
    /// Modification time.
    pub(crate) mtime: u64,
    /// Status-change time.
    pub(crate) ctime: u64,
    /// Birth (creation) time.
    pub(crate) btime: u64,

    /// Directory entries array (heap-allocated via pool).
    pub(crate) dirents: *mut Dirent,
    /// Capacity of `dirents` array.
    pub(crate) dirents_cap: u16,
    _pad1: [u8; 6],

    /// Head slot index into the writable block chain (INVALID_WRITABLE_SLOT if none).
    pub(crate) writable_head: u32,
    _pad2: [u8; 4],

    /// Pointer into the symlink pool (for VT_LNK vnodes).
    pub(crate) symlink_data: *mut u8,
    /// Backing pipe for FIFO vnodes.
    pub(crate) fifo_pipe: Handle<PipeState>,
    /// Arena-backed SHM descriptor for shm_open-created files.
    pub(crate) shm_handle: Handle<ShmData>,
}

impl TmpfsVnodeData {
    pub(crate) const fn zeroed() -> Self {
        TmpfsVnodeData {
            active: 0,
            ftype: crate::vfs_core::vnode::VT_BAD,
            dev_type: 0,
            _pad0: 0,
            id: 0,
            vnode_handle: crate::vfs_core::vnode::VnodeHandle::INVALID,
            parent_id: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            btime: 0,
            dirents: core::ptr::null_mut(),
            dirents_cap: 0,
            _pad1: [0; 6],
            writable_head: INVALID_WRITABLE_SLOT,
            _pad2: [0; 4],
            symlink_data: core::ptr::null_mut(),
            fifo_pipe: Handle::<PipeState>::INVALID,
            shm_handle: Handle::<ShmData>::INVALID,
        }
    }
}

unsafe impl Sync for TmpfsVnodeData {}

// =========================================================================
// TmpfsMountData — stored at Mount.data
// =========================================================================

/// Per-mount filesystem-private data for tmpfs.
///
/// Owns the writable block chain pool, symlink pool, vnode data pool,
/// and the Vnode pool itself. Each tmpfs mount instance has its own
/// independent set of pools plus size/inode accounting.
#[repr(C)]
pub(crate) struct TmpfsMountData {
    // -- Capacity limits (0 = unlimited) --
    /// Maximum total data bytes (set via "size=NNN" mount option).
    pub(crate) max_bytes: u64,
    /// Currently used data bytes (writable block chain storage).
    pub(crate) used_bytes: u64,
    /// Maximum inode count (set via "nr_inodes=NNN" mount option).
    pub(crate) max_inodes: u32,
    /// Currently allocated inodes.
    pub(crate) used_inodes: u32,

    // -- Vnode data pool --
    pub(crate) vdata_ptr: *mut TmpfsVnodeData,
    pub(crate) vdata_cap: usize,

    // -- Writable block chain pool --
    pub(crate) writable_pool_ptr: *mut [u8; WRITABLE_SIZE],
    pub(crate) writable_used_ptr: *mut u8,
    pub(crate) writable_next_ptr: *mut u32,
    pub(crate) writable_cap: usize,

    // -- Symlink target pool --
    pub(crate) symlink_pool_ptr: *mut [u8; MAX_PATH_LEN],
    pub(crate) symlink_used_ptr: *mut u8,
    pub(crate) symlink_cap: usize,

    // -- ID counter --
    pub(crate) next_id: u64,
}

impl TmpfsMountData {
    pub(crate) const fn zeroed() -> Self {
        TmpfsMountData {
            max_bytes: 0,
            used_bytes: 0,
            max_inodes: 0,
            used_inodes: 0,
            vdata_ptr: core::ptr::null_mut(),
            vdata_cap: 0,
            writable_pool_ptr: core::ptr::null_mut(),
            writable_used_ptr: core::ptr::null_mut(),
            writable_next_ptr: core::ptr::null_mut(),
            writable_cap: 0,
            symlink_pool_ptr: core::ptr::null_mut(),
            symlink_used_ptr: core::ptr::null_mut(),
            symlink_cap: 0,
            next_id: 1,
        }
    }
}

unsafe impl Sync for TmpfsMountData {}
