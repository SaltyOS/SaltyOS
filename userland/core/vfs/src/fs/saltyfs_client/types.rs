// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyFS client data structures — per-mount and per-vnode
//! private state.

use crate::core::identity::BackendNodeId;
use crate::core::vnode::VnodeHandle;
use crate::owner::pending::TxId;
use crate::server::types::OpenObjectHandle;

/// Per-mount filesystem-private data for the SaltyFS client.
///
/// Stored at `Mount.data`. Carries the IPC capability to the
/// SaltyFS server, SHM transport state, and feature flag
/// negotiation results.
#[repr(C)]
pub(crate) struct SaltyfsMountData {
    /// IPC endpoint capability slot for the SaltyFS server.
    pub fs_cap: u64,
    /// Backend session identifier. Allocated monotonically by the
    /// backend.
    pub session_id: u32,
    /// Per-session inflight credit cap advertised by the backend
    /// on session open. Consumed by the VFS credit accounting
    /// machinery to bound the number of outstanding correlated
    /// requests against this backend.
    pub max_inflight: u16,
    _pad0: [u8; 2],
    /// Stable root-node identity returned by the backend
    /// open-session reply.
    pub root_node: BackendNodeId,
    /// Negotiated backend feature bits.
    pub feature_bits: u64,
    /// Root inode number on the remote SaltyFS.
    pub root_ino: u64,
    /// Whether VFS-SaltyFS SHM bulk transport is active.
    pub shm_active: bool,
    /// Whether the server supports V2 protocol (uid/gid in
    /// create/mkdir/symlink).
    pub v2_protocol: bool,
    /// Whether the filesystem was mounted read-only (incompat_ro
    /// enforcement).
    pub readonly: bool,
    _pad1: [u8; 5],
    /// Serialises backend `BACKEND_READDIR` requests against the
    /// per-mount VFS↔saltyfs SHM region. The backend writes
    /// fixed 96-byte records starting at `shm_offset = 0`; two
    /// concurrent readdirs on the same mount would stomp each
    /// other's batches mid-drain. Set to the owning `OpenObject`
    /// handle when a readdir has its batch live in SHM / the
    /// OpenObject cache; reset to `INVALID` when the cache is
    /// fully drained (or when a new readdir detects the prior
    /// owner has been reclaimed). Stored as the owning handle
    /// (rather than a plain bool) so a client that closes the fd
    /// mid-drain does not strand the SHM region indefinitely.
    pub readdir_shm_owner: OpenObjectHandle,
    /// Serialises backend `BACKEND_GETXATTR` / `BACKEND_SETXATTR`
    /// / `BACKEND_LISTXATTR` requests against the per-mount
    /// VFS↔saltyfs SHM region. All three write `name` (and for
    /// setxattr, `value`) starting at `shm_offset = 0` before
    /// firing the async request; the backend reads them back when
    /// processing the completion. Without serialisation two
    /// concurrent xattr ops would overwrite each other's staged
    /// bytes in SHM — the backend would read op B's name/value
    /// while processing op A. Holds the live `TxId` of the
    /// issuing async xattr op; cleared to `TxId::INVALID` when the
    /// completion router has drained the reply out of SHM. Shares
    /// mutual exclusion with [`readdir_shm_owner`] — any SHM-using
    /// op checks both fields.
    pub xattr_shm_owner: TxId,
    /// mmsrv SHM registry slot. Zero if SHM is not active.
    pub shm_id: u64,
    /// VFS-retained SHM cap. A copy is transferred to the backend
    /// during `BACKEND_SHM_SETUP`; this original is released during
    /// mount teardown after vfs's local mapping is unmapped.
    pub shm_cap: u64,
    /// SHM virtual address (VFS side). Zero if SHM not active.
    pub shm_vaddr: u64,
    /// SHM size in bytes.
    pub shm_size: u64,
    /// Per-mount vnode-data pool pointer.
    pub vdata_ptr: *mut SaltyfsVnodeData,
    /// Per-mount vnode-data pool capacity.
    pub vdata_cap: usize,
    /// Slot index into `VfsState.backend_sessions` — the canonical
    /// session bookkeeping arena. Set during mount negotiation once
    /// the slot has been allocated and the callback Watch is armed;
    /// reset to `u32::MAX` on teardown. The dispatcher's
    /// inbound-completion path looks up the slot via this index
    /// when it needs to bridge back to the per-mount data after
    /// the 5-tuple validation in `dispatch_pending_reply`.
    pub backend_session_idx: u32,
    /// Hybrid-1 SHM ring allocator state. `ring_bitmap` bit `i`
    /// is set iff slot `i` is currently leased to an in-flight
    /// `BACKEND_WRITE`; `ring_cursor` is a hint for the next
    /// search start so slots cycle FIFO-ish under load. The two
    /// fields share `BLOCK_LOCK`-equivalent serialisation: the
    /// VFS owner thread is single-mutator on `MountData`.
    pub ring_bitmap: u16,
    pub ring_cursor: u8,
    _pad2: [u8; 1],
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
            readdir_shm_owner: OpenObjectHandle::INVALID,
            xattr_shm_owner: TxId::INVALID,
            shm_id: 0,
            shm_cap: 0,
            shm_vaddr: 0,
            shm_size: 0,
            vdata_ptr: ::core::ptr::null_mut(),
            vdata_cap: 0,
            backend_session_idx: u32::MAX,
            ring_bitmap: 0,
            ring_cursor: 0,
            _pad2: [0; 1],
        }
    }

    /// Allocate a free SHM ring slot. Returns the slot index
    /// (0..`SALTYFS_RING_SLOT_COUNT`) on success; `None` when
    /// every slot is in flight. The cursor advances past the
    /// allocated slot so subsequent allocations cycle through the
    /// ring rather than re-issuing the same slot back-to-back —
    /// this keeps slow daemon completions from stranding fast
    /// callers on a hot slot.
    #[inline]
    pub(crate) fn ring_alloc(&mut self) -> Option<u8> {
        let cap = SALTYFS_RING_SLOT_COUNT;
        if cap == 0 {
            return None;
        }
        for step in 0..cap {
            let idx = ((self.ring_cursor as u16 + step as u16) % cap as u16) as u8;
            let mask = 1u16 << idx;
            if self.ring_bitmap & mask == 0 {
                self.ring_bitmap |= mask;
                self.ring_cursor = (idx + 1) % cap;
                return Some(idx);
            }
        }
        None
    }

    /// Release a SHM ring slot previously returned by `ring_alloc`.
    /// Idempotent on already-free slots so completion-side cleanup
    /// is safe to invoke unconditionally.
    #[inline]
    pub(crate) fn ring_free(&mut self, idx: u8) {
        if idx < SALTYFS_RING_SLOT_COUNT {
            self.ring_bitmap &= !(1u16 << idx);
        }
    }
}

unsafe impl Sync for SaltyfsMountData {}

/// Per-vnode filesystem-private data for the SaltyFS client.
///
/// Stored at `Vnode.data`. Carries the remote inode number and a
/// small attribute cache populated on lookup / getattr.
#[repr(C)]
pub(crate) struct SaltyfsVnodeData {
    /// 1 if this pool slot is in use, 0 if free.
    pub active: u8,
    /// File type (matches `VnodeKind`).
    pub ftype: u8,
    _pad0: [u8; 2],
    /// POSIX mode bits (type + permission).
    pub mode: u32,
    /// Remote inode number on the SaltyFS server.
    pub remote_ino: u64,
    /// Cached parent inode number. Set at lookup time when the
    /// backend resolves a child; lets the readdir helper
    /// synthesise the `..` entry without issuing a dedicated
    /// `BACKEND_GETPARENT` RPC. `0` means "unknown" — the reader
    /// falls back to echoing `remote_ino` (POSIX allows
    /// self-loops for root / detached inodes).
    pub parent_ino: u64,
    /// Remote inode incarnation sequence.
    pub remote_seq: u32,
    _pad_seq: [u8; 4],
    /// Canonical live vnode handle for this inode.
    pub vnode_handle: VnodeHandle,
    /// Cached file size.
    pub size: u64,
    /// Cached hard link count.
    pub nlink: u32,
    /// Cached owner uid.
    pub uid: u32,
    /// Cached owner gid.
    pub gid: u32,
    _pad1: [u8; 4],
    /// Cached modification time.
    pub mtime: u64,
    /// Cached block count.
    pub blocks: u64,
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
            vnode_handle: VnodeHandle::INVALID,
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

/// Maximum number of SaltyFS vnode-data entries in the per-mount
/// pool.
pub(crate) const SALTYFS_VDATA_POOL_SIZE: usize = 256;

/// Maximum SaltyFS filename length that fits in IPC registers for
/// single-component ops.
pub(super) const SALTYFS_NAME_MAX: usize = 144;

/// Hybrid-1 BACKEND_WRITE SHM ring slot size. The per-session SHM
/// region is `SALTYFS_RING_SLOT_COUNT * SALTYFS_RING_SLOT_BYTES`
/// (= 16 × 4 KiB = 64 KiB), matching the daemon-advertised
/// `SALTYFS_SHM_REGION_BYTES`. A write that fits in one slot
/// rides via `TRANSFER_KIND_SHM`; larger writes spill into a
/// per-RPC MemoryObject (`TRANSFER_KIND_MO`).
pub(crate) const SALTYFS_RING_SLOT_BYTES: u64 = 4096;
pub(crate) const SALTYFS_RING_SLOT_COUNT: u8 = 16;
