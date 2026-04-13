// SPDX-License-Identifier: GPL-2.0-only
//! Worker dispatch types: WorkItem, Completion, and queues.
//!
//! Workers are "blocking task executors" — they receive a `WorkItem` from the
//! owner loop, perform a potentially blocking operation (saltyfs IPC, netsrv
//! bridge, device read), and return a `Completion` via the completion queue.
//! Workers never touch `VfsState`.

use trona::types::core::TronaMsg;

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::vnode::VnodeHandle;
use crate::vfs_core::vop_context::VopDataContext;

// =========================================================================
// WorkItem — owner → worker
// =========================================================================

/// A unit of blocking work dispatched from the owner loop to a worker.
pub(crate) enum WorkItem {
    /// File read via VopDataOps::read.
    Read {
        request_id: u64,
        reply_slot: u64,
        data_ctx: VopDataContext,
        offset: u64,
        len: u64,
    },

    /// File write via VopDataOps::write.
    Write {
        request_id: u64,
        reply_slot: u64,
        data_ctx: VopDataContext,
        offset: u64,
        data_ptr: *const u8,
        len: u64,
    },

    /// SaltyFS remote lookup (cache miss).
    RemoteLookup {
        request_id: u64,
        reply_slot: u64,
        mount_data: *mut u8,
        parent_ino: u64,
        name: [u8; 255],
        name_len: u8,
    },

    /// Readdir streaming for remote backends.
    Readdir {
        request_id: u64,
        reply_slot: u64,
        data_ctx: VopDataContext,
        cookie: u64,
    },

    /// Bulk read via SHM transport.
    BulkRead {
        request_id: u64,
        reply_slot: u64,
        data_ctx: VopDataContext,
        offset: u64,
        shm_dst: *mut u8,
        len: u64,
    },

    /// Bulk write via SHM transport.
    BulkWrite {
        request_id: u64,
        reply_slot: u64,
        data_ctx: VopDataContext,
        offset: u64,
        shm_src: *const u8,
        len: u64,
    },

    /// Netsrv blocking IPC bridge (TCP/UDP send).
    NetBridge {
        request_id: u64,
        reply_slot: u64,
        net_msg: TronaMsg,
    },

    /// Fsync to remote backend.
    Fsync {
        request_id: u64,
        reply_slot: u64,
        data_ctx: VopDataContext,
    },
}

// Raw pointers in WorkItem are stable (non-moving arena + flight counting).
unsafe impl Send for WorkItem {}

// =========================================================================
// RemoteInodeInfo — result payload for remote lookups
// =========================================================================

/// Cached attribute snapshot returned by a worker after a remote lookup.
#[repr(C)]
pub(crate) struct RemoteInodeInfo {
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) size: u64,
    pub(crate) nlink: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mtime: u64,
    pub(crate) dir_type: u8,
    pub(crate) blocks: u64,
}

// =========================================================================
// Completion — worker → owner
// =========================================================================

/// Result of a completed work item, returned to the owner loop.
pub(crate) enum Completion {
    /// A data operation completed (read/write/fsync/bulk).
    DataResult {
        request_id: u64,
        vnode_handle: VnodeHandle,
        result: VfsResult<u64>,
        reply_slot: u64,
        reply_msg: TronaMsg,
    },

    /// A remote lookup completed.
    RemoteLookupResult {
        request_id: u64,
        reply_slot: u64,
        mount_handle: MountHandle,
        parent_ino: u64,
        name: [u8; 255],
        name_len: u8,
        result: Result<RemoteInodeInfo, crate::vfs_core::error::VfsError>,
    },

    /// Worker finished — decrement flight count on these handles.
    FlightRelease {
        handles: [VnodeHandle; 4],
        count: u8,
    },
}

unsafe impl Send for Completion {}

// =========================================================================
// Work queue and completion queue (stubs — full impl in worker integration)
// =========================================================================

/// SPSC ring buffer: owner produces, worker consumes.
///
/// Stub implementation for single-threaded mode. Full ring buffer with
/// atomic head/tail will be implemented in Task 9 (worker integration).
pub(crate) struct WorkQueue {
    _placeholder: u8,
}

impl WorkQueue {
    pub(crate) const fn new() -> Self {
        WorkQueue { _placeholder: 0 }
    }
}

/// MPSC ring buffer: worker(s) produce, owner consumes.
pub(crate) struct CompletionQueue {
    _placeholder: u8,
}

impl CompletionQueue {
    pub(crate) const fn new() -> Self {
        CompletionQueue { _placeholder: 0 }
    }
}
