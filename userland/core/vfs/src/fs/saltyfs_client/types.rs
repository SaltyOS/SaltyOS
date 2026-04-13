// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS client data structures — per-mount and per-vnode private state.

/// Per-mount filesystem-private data for the SaltyFS client.
///
/// Stored at `Mount.data`. Carries the IPC capability to the SaltyFS server,
/// SHM transport state, and feature flag negotiation results.
#[repr(C)]
pub(crate) struct SaltyfsMountData {
    /// IPC endpoint capability slot for the SaltyFS server.
    pub(crate) fs_cap: u64,
    /// Root inode number on the remote SaltyFS.
    pub(crate) root_ino: u64,
    /// Whether VFS-SaltyFS SHM bulk transport is active.
    pub(crate) shm_active: bool,
    /// Whether the server supports V2 protocol (uid/gid in create/mkdir/symlink).
    pub(crate) v2_protocol: bool,
    /// Whether the filesystem was mounted read-only (incompat_ro enforcement).
    pub(crate) readonly: bool,
    _pad0: [u8; 5],
    /// SHM virtual address (VFS side). Zero if SHM not active.
    pub(crate) shm_vaddr: u64,
    /// SHM size in bytes.
    pub(crate) shm_size: u64,
    /// Per-mount vnode-data pool pointer.
    pub(crate) vdata_ptr: *mut SaltyfsVnodeData,
    /// Per-mount vnode-data pool capacity.
    pub(crate) vdata_cap: usize,
}

impl SaltyfsMountData {
    pub(crate) const fn zeroed() -> Self {
        SaltyfsMountData {
            fs_cap: 0,
            root_ino: 0,
            shm_active: false,
            v2_protocol: false,
            readonly: false,
            _pad0: [0; 5],
            shm_vaddr: 0,
            shm_size: 0,
            vdata_ptr: core::ptr::null_mut(),
            vdata_cap: 0,
        }
    }
}

unsafe impl Sync for SaltyfsMountData {}

/// Per-vnode filesystem-private data for the SaltyFS client.
///
/// Stored at `Vnode.data`. Carries the remote inode number and a small
/// attribute cache populated on lookup / getattr.
#[repr(C)]
pub(crate) struct SaltyfsVnodeData {
    /// 1 if this pool slot is in use, 0 if free.
    pub(crate) active: u8,
    /// File type (VT_* from vfs_core::vnode).
    pub(crate) ftype: u8,
    _pad0: [u8; 2],
    /// POSIX mode bits (type + permission).
    pub(crate) mode: u32,
    /// Remote inode number on the SaltyFS server.
    pub(crate) remote_ino: u64,
    /// Canonical live vnode handle for this inode.
    pub(crate) vnode_handle: crate::vfs_core::vnode::VnodeHandle,
    /// Cached file size.
    pub(crate) size: u64,
    /// Cached hard link count.
    pub(crate) nlink: u32,
    /// Cached owner uid.
    pub(crate) uid: u32,
    /// Cached owner gid.
    pub(crate) gid: u32,
    _pad1: [u8; 4],
    /// Cached modification time.
    pub(crate) mtime: u64,
    /// Cached block count.
    pub(crate) blocks: u64,
}

impl SaltyfsVnodeData {
    pub(crate) const fn zeroed() -> Self {
        SaltyfsVnodeData {
            active: 0,
            ftype: 0,
            _pad0: [0; 2],
            mode: 0,
            remote_ino: 0,
            vnode_handle: crate::vfs_core::vnode::VnodeHandle::INVALID,
            size: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            _pad1: [0; 4],
            mtime: 0,
            blocks: 0,
        }
    }
}

unsafe impl Sync for SaltyfsVnodeData {}

/// Maximum number of SaltyFS vnode-data entries in the per-mount pool.
pub(super) const SALTYFS_VDATA_POOL_SIZE: usize = 256;

/// Maximum SaltyFS filename length that fits in IPC registers for single-component ops.
pub(super) const SALTYFS_NAME_MAX: usize = 144;
