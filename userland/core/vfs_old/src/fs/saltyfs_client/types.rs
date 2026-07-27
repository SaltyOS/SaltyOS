// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS client data structures — per-mount and per-vnode private state.

use trona_protocol::posix::BackendNodeId;

/// Per-mount filesystem-private data for the SaltyFS client.
///
/// Stored at `Mount.data`. Carries the IPC capability to the SaltyFS server,
/// SHM transport state, and feature flag negotiation results.
#[repr(C)]
pub(crate) struct SaltyfsMountData {
    /// IPC endpoint capability slot for the SaltyFS server.
    pub(crate) fs_cap: u64,
    /// Backend session identifier. Allocated monotonically by the backend.
    pub(crate) session_id: u32,
    /// Per-session inflight credit cap advertised by the backend on session
    /// open. Consumed by the VFS credit accounting machinery to bound the
    /// number of outstanding correlated requests against this backend.
    pub(crate) max_inflight: u16,
    _pad0: [u8; 2],
    /// Stable root-node identity returned by the backend open-session reply.
    pub(crate) root_node: BackendNodeId,
    /// Negotiated backend feature bits.
    pub(crate) feature_bits: u64,
    /// Root inode number on the remote SaltyFS.
    pub(crate) root_ino: u64,
    /// Whether VFS-SaltyFS SHM bulk transport is active.
    pub(crate) shm_active: bool,
    /// Whether the server supports V2 protocol (uid/gid in create/mkdir/symlink).
    pub(crate) v2_protocol: bool,
    /// Whether the filesystem was mounted read-only (incompat_ro enforcement).
    pub(crate) readonly: bool,
    _pad1: [u8; 5],
    /// Serialises backend `BACKEND_READDIR` requests against the
    /// per-mount VFS↔saltyfs SHM region. The backend writes fixed
    /// 96-byte records starting at `shm_offset = 0`; two concurrent
    /// readdirs on the same mount would stomp each other's batches
    /// mid-drain. Set to the owning `OpenObject` handle when a
    /// readdir has its batch live in SHM / the OpenObject cache;
    /// reset to `INVALID` when the cache is fully drained (or when
    /// a new readdir detects the prior owner has been reclaimed).
    /// Stored as the owning handle (rather than a plain bool) so
    /// a client that closes the fd mid-drain does not strand the
    /// SHM region indefinitely.
    pub(crate) readdir_shm_owner: crate::server::open_object::OpenObjectHandle,
    /// Serialises backend `BACKEND_GETXATTR` / `BACKEND_SETXATTR` /
    /// `BACKEND_LISTXATTR` requests against the per-mount VFS↔saltyfs
    /// SHM region. All three write `name` (and for setxattr, `value`)
    /// starting at `shm_offset = 0` before firing the async request;
    /// the backend reads them back when processing the completion.
    /// Without serialisation two concurrent xattr ops would overwrite
    /// each other's staged bytes in SHM — the backend would read op B's
    /// name/value while processing op A. Holds the live `TxId` of the
    /// issuing async xattr op; cleared to `TxId::INVALID` when the
    /// completion router has drained the reply out of SHM. Shares
    /// mutual exclusion with [`readdir_shm_owner`] — any SHM-using op
    /// checks both fields.
    pub(crate) xattr_shm_owner: crate::owner::pending::TxId,
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
            session_id: 0,
            max_inflight: 0,
            _pad0: [0; 2],
            root_node: BackendNodeId::INVALID,
            feature_bits: 0,
            root_ino: 0,
            shm_active: false,
            v2_protocol: false,
            readonly: false,
            _pad1: [0; 5],
            readdir_shm_owner: crate::server::open_object::OpenObjectHandle::INVALID,
            xattr_shm_owner: crate::owner::pending::TxId::INVALID,
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
    /// Cached parent inode number. Set at lookup time when the
    /// backend resolves a child; lets the `readdir` helper synthesise
    /// the `..` entry without issuing a dedicated `BACKEND_GETPARENT`
    /// RPC. `0` means "unknown" — the reader falls back to echoing
    /// `remote_ino` (POSIX allows self-loops for root / detached
    /// inodes). Hard-link parents are ambiguous; this field records
    /// the parent observed at the most recent lookup of *this*
    /// `VnodeHandle` incarnation, which is the parent the kernel-side
    /// walker was crossing when the vdata entry was installed.
    pub(crate) parent_ino: u64,
    /// Remote inode incarnation sequence.
    pub(crate) remote_seq: u32,
    _pad_seq: [u8; 4],
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
            parent_ino: 0,
            remote_seq: 0,
            _pad_seq: [0; 4],
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
