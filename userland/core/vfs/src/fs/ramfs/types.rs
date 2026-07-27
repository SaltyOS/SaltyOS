// SPDX-License-Identifier: GPL-2.0-only
//
//! Ramfs data structures — per-vnode and per-mount private state.
//!
//! `RamfsVnodeData` hangs off `Vnode.data`; `RamfsMountData` hangs
//! off `Mount.data`. Both are zero-init friendly so a fresh
//! `map_anon` page can be cast directly into the struct without an
//! extra ctor pass.

use crate::arena::handle::Handle;
use crate::core::pipe::PipeState;
use crate::core::vnode::{VT_BAD, VnodeHandle};
use crate::server::consts::{INVALID_WRITABLE_SLOT, MAX_NAME_LEN, MAX_PATH_LEN, WRITABLE_SIZE};

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
/// One slot per inode in the per-mount `vdata` pool. The `Vnode`
/// arena holds the personality-neutral image (`kind`, `key`, `nlink`,
/// `flags`); every ramfs-specific attribute (mode bits, owner uid /
/// gid, timestamps, the writable block chain head, the symlink
/// target pointer, the FIFO backing handle) lives here so the vnode
/// arena does not need to grow new fields per backend.
#[repr(C)]
pub(crate) struct RamfsVnodeData {
    /// 1 if this pool slot is in use, 0 if free.
    pub(crate) active: u8,
    /// Read-only flag — set on initrd-projected vnodes whose data
    /// region points at the live initrd image (zero-copy).
    pub(crate) readonly: u8,
    /// File type byte (`VT_*` in `core::vnode`).
    pub(crate) ftype: u8,
    /// Device subtype for char / block device vnodes
    /// (e.g. `DEV_URANDOM`); 0 for regular files / directories.
    pub(crate) dev_type: u8,

    /// Unique id within this ramfs instance. Mirrors the
    /// `Vnode.key.backend_id.id` of the live vnode.
    pub(crate) id: u64,
    /// Canonical live vnode handle for this inode. `vget` consults
    /// this before allocating a fresh slot so re-lookups land on
    /// the same `Vnode` while the backend slot is alive.
    pub(crate) vnode_handle: VnodeHandle,
    /// Parent directory id (0 for root).
    pub(crate) parent_id: u64,

    /// POSIX mode bits (type + permission). Stored in the POSIX
    /// projection because that is the only consumer wire that
    /// reads the bits at all; the personality layer translates on
    /// behalf of Win32 callers.
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

    /// Directory entries array (heap-allocated via the dirent pool).
    pub(crate) dirents: *mut Dirent,
    /// Capacity of `dirents` array (entries, not bytes).
    pub(crate) dirents_cap: u16,
    _pad1: [u8; 6],

    /// Head slot index into the writable block chain
    /// (`INVALID_WRITABLE_SLOT` if the file has no writable region).
    pub(crate) writable_head: u32,
    _pad2: [u8; 4],

    /// Pointer to read-only data (initrd zero-copy). `null` for
    /// writable files.
    pub(crate) ro_data: *const u8,
    /// Length of `ro_data`.
    pub(crate) ro_len: u64,

    /// Pointer into the symlink pool (for `VT_LNK` vnodes). `null`
    /// for non-symlink types.
    pub(crate) symlink_data: *mut u8,
    /// Backing pipe for FIFO vnodes. `Handle::INVALID` for non-FIFO
    /// types.
    pub(crate) fifo_pipe: Handle<PipeState>,
}

impl RamfsVnodeData {
    pub(crate) const fn zeroed() -> Self {
        RamfsVnodeData {
            active: 0,
            readonly: 0,
            ftype: VT_BAD,
            dev_type: 0,
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
            acl_index: 0,
            _pad0: [0; 6],
            dirents: ::core::ptr::null_mut(),
            dirents_cap: 0,
            _pad1: [0; 6],
            writable_head: INVALID_WRITABLE_SLOT,
            _pad2: [0; 4],
            ro_data: ::core::ptr::null(),
            ro_len: 0,
            symlink_data: ::core::ptr::null_mut(),
            fifo_pipe: Handle::<PipeState>::INVALID,
        }
    }
}

// SAFETY: Single-owner mutator (the VFS owner thread). The struct
// is accessed only through raw pointers held by that thread; the
// `Sync` claim here is a marker so the static dispatch tables can
// reference vnode-data backed pools without `static mut` chains.
unsafe impl Sync for RamfsVnodeData {}

// =========================================================================
// RamfsMountData — stored at Mount.data
// =========================================================================

/// Per-mount filesystem-private data for ramfs.
///
/// Owns the writable block chain pool, symlink pool, and vnode data
/// pool. Each ramfs mount instance has its own independent set of
/// pools so two ramfs mounts share neither vnode-data slots nor
/// writable blocks.
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

// SAFETY: Single-owner mutator — see `RamfsVnodeData` Sync impl.
unsafe impl Sync for RamfsMountData {}
