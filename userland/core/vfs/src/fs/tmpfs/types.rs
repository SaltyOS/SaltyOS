// SPDX-License-Identifier: GPL-2.0-only
//
//! Tmpfs data structures — per-vnode and per-mount private state.
//!
//! Independent in-memory filesystem with size and inode limits.
//! Unlike ramfs, tmpfs has no read-only data path, no persistent
//! file tracking, and enforces configurable capacity constraints.

use crate::arena::handle::Handle;
use crate::core::pipe::PipeState;
use crate::core::shm::ShmData;
use crate::core::vnode::{VT_BAD, VnodeHandle};
use crate::server::consts::{INVALID_WRITABLE_SLOT, MAX_NAME_LEN, MAX_PATH_LEN, WRITABLE_SIZE};

// =========================================================================
// Dirent
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

#[repr(C)]
pub(crate) struct TmpfsVnodeData {
    pub(crate) active: u8,
    pub(crate) ftype: u8,
    pub(crate) dev_type: u8,
    _pad0: u8,

    pub(crate) id: u64,
    pub(crate) vnode_handle: VnodeHandle,
    pub(crate) parent_id: u64,

    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) nlink: u32,
    pub(crate) size: u64,

    pub(crate) atime: u64,
    pub(crate) mtime: u64,
    pub(crate) ctime: u64,
    pub(crate) btime: u64,

    pub(crate) dirents: *mut Dirent,
    pub(crate) dirents_cap: u16,
    _pad1: [u8; 6],

    pub(crate) writable_head: u32,
    _pad2: [u8; 4],

    pub(crate) symlink_data: *mut u8,
    pub(crate) fifo_pipe: Handle<PipeState>,
    pub(crate) shm_handle: Handle<ShmData>,
}

impl TmpfsVnodeData {
    pub(crate) const fn zeroed() -> Self {
        TmpfsVnodeData {
            active: 0,
            ftype: VT_BAD,
            dev_type: 0,
            _pad0: 0,
            id: 0,
            vnode_handle: VnodeHandle::INVALID,
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
            dirents: ::core::ptr::null_mut(),
            dirents_cap: 0,
            _pad1: [0; 6],
            writable_head: INVALID_WRITABLE_SLOT,
            _pad2: [0; 4],
            symlink_data: ::core::ptr::null_mut(),
            fifo_pipe: Handle::<PipeState>::INVALID,
            shm_handle: Handle::<ShmData>::INVALID,
        }
    }
}

unsafe impl Sync for TmpfsVnodeData {}

// =========================================================================
// TmpfsMountData — stored at Mount.data
// =========================================================================

#[repr(C)]
pub(crate) struct TmpfsMountData {
    /// Maximum total data bytes (`size=NNN` mount option). 0 = unlimited.
    pub(crate) max_bytes: u64,
    /// Currently used data bytes — writable block chain accounting.
    pub(crate) used_bytes: u64,
    /// Maximum inode count (`nr_inodes=NNN` mount option). 0 = unlimited.
    pub(crate) max_inodes: u32,
    /// Currently allocated inodes.
    pub(crate) used_inodes: u32,

    pub(crate) vdata_ptr: *mut TmpfsVnodeData,
    pub(crate) vdata_cap: usize,

    pub(crate) writable_pool_ptr: *mut [u8; WRITABLE_SIZE],
    pub(crate) writable_used_ptr: *mut u8,
    pub(crate) writable_next_ptr: *mut u32,
    pub(crate) writable_cap: usize,

    pub(crate) symlink_pool_ptr: *mut [u8; MAX_PATH_LEN],
    pub(crate) symlink_used_ptr: *mut u8,
    pub(crate) symlink_cap: usize,

    pub(crate) next_id: u64,
}

impl TmpfsMountData {
    pub(crate) const fn zeroed() -> Self {
        TmpfsMountData {
            max_bytes: 0,
            used_bytes: 0,
            max_inodes: 0,
            used_inodes: 0,
            vdata_ptr: ::core::ptr::null_mut(),
            vdata_cap: 0,
            writable_pool_ptr: ::core::ptr::null_mut(),
            writable_used_ptr: ::core::ptr::null_mut(),
            writable_next_ptr: ::core::ptr::null_mut(),
            writable_cap: 0,
            symlink_pool_ptr: ::core::ptr::null_mut(),
            symlink_used_ptr: ::core::ptr::null_mut(),
            symlink_cap: 0,
            next_id: 1,
        }
    }
}

unsafe impl Sync for TmpfsMountData {}
