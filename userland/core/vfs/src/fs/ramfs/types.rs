// SPDX-License-Identifier: GPL-2.0-only
//! Ramfs data structures — per-vnode and per-mount private state.

use crate::arena::Handle;
use crate::personality::posix::types::PipeState;

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
// RamfsVnodeData — stored at Vnode.data
// =========================================================================

/// Per-vnode filesystem-private data for ramfs.
///
/// Stored as a pool-allocated object; `Vnode.data` points at it.
/// `Vnode.id` holds the same value as `id` here (the ramfs inode number).
#[repr(C)]
pub(crate) struct RamfsVnodeData {
    /// 1 if this pool slot is in use, 0 if free.
    pub(crate) active: u8,
    /// Read-only flag (initrd-mounted files).
    pub(crate) readonly: u8,
    /// File type (VT_* from vfs_core::vnode).
    pub(crate) ftype: u8,
    /// Device subtype (DEV_CONSOLE, DEV_NULL, etc.) for char/block devices.
    pub(crate) dev_type: u8,

    /// Unique id within this ramfs instance. Equals `Vnode.id`.
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

    /// ACL index (reserved).
    pub(crate) acl_index: u16,
    _pad0: [u8; 6],

    /// Directory entries array (heap-allocated via pool).
    pub(crate) dirents: *mut Dirent,
    /// Capacity of `dirents` array.
    pub(crate) dirents_cap: u16,
    _pad1: [u8; 6],

    /// Head slot index into the writable block chain (INVALID_WRITABLE_SLOT if none).
    pub(crate) writable_head: u32,
    _pad2: [u8; 4],

    /// Pointer to read-only data (initrd zero-copy). Null for writable files.
    pub(crate) ro_data: *const u8,
    /// Length of ro_data.
    pub(crate) ro_len: u64,

    /// Pointer into the symlink pool (for VT_LNK vnodes).
    pub(crate) symlink_data: *mut u8,
    /// Backing pipe for FIFO vnodes.
    pub(crate) fifo_pipe: Handle<PipeState>,
}

impl RamfsVnodeData {
    pub(crate) const fn zeroed() -> Self {
        RamfsVnodeData {
            active: 0,
            readonly: 0,
            ftype: crate::vfs_core::vnode::VT_BAD,
            dev_type: 0,
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
            acl_index: 0,
            _pad0: [0; 6],
            dirents: core::ptr::null_mut(),
            dirents_cap: 0,
            _pad1: [0; 6],
            writable_head: INVALID_WRITABLE_SLOT,
            _pad2: [0; 4],
            ro_data: core::ptr::null(),
            ro_len: 0,
            symlink_data: core::ptr::null_mut(),
            fifo_pipe: Handle::<PipeState>::INVALID,
        }
    }
}

unsafe impl Sync for RamfsVnodeData {}

// =========================================================================
// RamfsMountData — stored at Mount.data
// =========================================================================

/// Per-mount filesystem-private data for ramfs.
///
/// Owns the writable block chain pool, symlink pool, vnode data pool,
/// and the Vnode pool itself. Each ramfs mount instance has its own
/// independent set of pools.
#[repr(C)]
pub(crate) struct RamfsMountData {
    // -- Vnode data pool --
    pub(crate) vdata_ptr: *mut RamfsVnodeData,
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

impl RamfsMountData {
    pub(crate) const fn zeroed() -> Self {
        RamfsMountData {
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

unsafe impl Sync for RamfsMountData {}
