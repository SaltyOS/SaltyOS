// SPDX-License-Identifier: GPL-2.0-only
//! Filesystem resume-context variants.
//!
//! Each variant captures only generic data — client handle, identity
//! keys, fds, SHM offsets, transfer descriptors. Completion routing
//! (backend-specific parsing, payload extraction, fileops handler
//! invocation) lives on [`crate::owner::session::BackendSessionSlot::
//! completion_fn`]; this module defines only the data carried across
//! the park → completion boundary.

use crate::owner::pending::{WalkCursor, WalkPhase};
use crate::server::types::ClientHandle;
use crate::vfs_core::identity::{FsInstanceId, VnodeKey};

#[derive(Clone, Copy)]
pub(crate) enum NameiTerminal {
    /// Async walk completes into a terminal access check on the
    /// resolved vnode. Used by `access(2)` and `faccessat(2)`.
    Access { mode: u32 },
    /// Async walk completes into the exec-preflight terminal
    /// sequence: `access(X_OK)` followed by `getattr`.
    StatForExec,
    /// Async walk completes into a directory open and fd install on
    /// the resolved vnode.
    OpenDir,
    /// Async walk completes into a stat-shaped reply.
    Stat,
    /// Async walk completes into a terminal `readlink` on the
    /// resolved vnode.
    Readlink,
    /// Async walk completes into a plain vnode open on the resolved
    /// terminal object.
    Open {
        request: crate::fileops::open::OpenRequest,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum FsResume {
    /// Parked on the terminal metadata RPC for `fstat` / path-stat.
    /// The backend's completion router parses its wire reply and
    /// invokes `fileops::stat::resume_fill_stat_reply` with
    /// pre-parsed attrs.
    FillStatReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on the terminal `access` metadata RPC. The backend's
    /// completion router only needs to translate its success/failure
    /// label into a generic ack.
    FillAccessReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on the terminal directory-open metadata RPC. The
    /// completion router only needs to translate its success/failure
    /// label into a generic ack; fd/object installation happens in
    /// the fileops resume helper.
    FillOpenDirReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on the exec-preflight `access(X_OK)` metadata RPC. The
    /// walker is already done; only the terminal access check remains.
    FillStatForExecAccessReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on the exec-preflight terminal `getattr` RPC after the
    /// access check already succeeded.
    FillStatForExecAttrReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on a step of the async namei walk. The walker's
    /// `WalkCursor` is preserved across the park so the walk can
    /// resume at the exact component boundary.
    NameiStep {
        client: ClientHandle,
        cursor: WalkCursor,
        phase: WalkPhase,
        terminal: NameiTerminal,
    },
    /// Parked on the terminal `readlink` metadata RPC. Cached target
    /// bytes are delivered inline by the backend's completion router
    /// to `fileops::attr::resume_fill_readlink_reply`.
    FillReadlinkReply {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on an `getxattr` metadata RPC. The value bytes land in
    /// the mount's SHM region (when the backend uses one) and are
    /// copied inline by the backend's completion router before the
    /// fileops helper runs.
    FillXattrGetReply {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
    },
    /// Parked on a `listxattr` metadata RPC. The NUL-separated name
    /// list lands in the mount's SHM region and is copied inline.
    FillListXattrReply {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
    },
    /// Parked on the terminal metadata stat RPC issued after a
    /// completed namei walk. Same shape as `FillStatReply`; kept
    /// distinct so the walk-then-stat path can be traced separately.
    FillStatAfterWalk {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on a bulk-read RPC. The backend's completion router
    /// copies the delivered payload into the client's bulk-SHM at
    /// `shm_offset` (inline vs SHM-relay is decided by the payload
    /// carried in the backend's opaque op-kind record, interpreted
    /// by the backend — not stored here).
    BulkReadStage {
        client: ClientHandle,
        vkey: VnodeKey,
        fs_id: FsInstanceId,
        fd: i32,
        shm_offset: u64,
    },
    /// Parked on a bulk-readdir RPC. The completion router populates
    /// the `OpenObject.readdir_batch` cache, emits entry 0 inline,
    /// and advances `dir_cursor`.
    BulkReaddirStage {
        client: ClientHandle,
        dir_vkey: VnodeKey,
        fs_id: FsInstanceId,
        fd: i32,
        open_handle: crate::server::open_object::OpenObjectHandle,
        start_cursor: u64,
    },
    /// Parked on a simple mutation whose completion is a plain ack
    /// (optionally carrying a refreshed attribute snapshot).
    ///
    /// Used by `setattr` (mode / uid / gid / atime / mtime / size),
    /// `setxattr`, and `removexattr`. The backend's completion
    /// router parses any snapshot out of the reply and invokes
    /// `fileops::mutate::resume_fill_ack_mutation_reply` which emits
    /// a TRONA_OK reply. Any backend-private attribute-cache refresh
    /// (e.g. propagating the returned attr snapshot into the
    /// backend's vnode-data pool) is the backend's own responsibility
    /// and happens before the fileops helper runs.
    AckMutation {
        client: ClientHandle,
        vkey: VnodeKey,
    },
    /// Parked on a compound mutation whose completion materialises a
    /// new child vnode on the parent — `create`, `mkdir`, or
    /// `symlink`. The backend's completion router parses the wire
    /// reply, allocates the new arena vnode, installs the resolve-
    /// cache entry, and hands the materialised child to
    /// [`crate::fileops::mutate::resume_fill_final_op_child_reply`]
    /// which emits either an open-style fd reply or a bare
    /// `TRONA_OK` ack depending on whether `open_request` is
    /// present.
    ///
    /// `parent_vkey` is the parent directory's identity (used by
    /// the backend to locate its mount / pool state for vnode
    /// allocation, and by the fileops helper to invalidate the
    /// parent's resolve-cache entry so a subsequent readdir
    /// refreshes). `kind_hint` selects the reply-format the
    /// fileops helper emits.
    ///
    /// `open_request` carries the deferred open re-entry state. When
    /// present, the fileops helper replays `open_vnode_owned` on the
    /// freshly materialised child and emits the fd reply. When absent,
    /// a bare `TRONA_OK` ack is emitted (`mkdirat` / `symlinkat` /
    /// `mkfifo`).
    ///
    /// `creds_uid` / `creds_gid` are the credential snapshot at
    /// dispatch time. The backend's completion router may use these
    /// to seed the new vnode's cached uid/gid when the underlying
    /// wire reply carries only the freshly-allocated node identifier.
    FinalOpChild {
        client: ClientHandle,
        parent_vkey: VnodeKey,
        kind_hint: FinalOpKind,
        open_request: Option<crate::fileops::open::OpenRequest>,
        creds_uid: u32,
        creds_gid: u32,
    },
    /// Parked on `unlink` / `rmdir`. On success the removed child's
    /// resolve-cache entry is evicted and the parent directory's
    /// `readdir_batch` snapshots on open fds are cleared. `kind`
    /// distinguishes `Unlink` from `Rmdir` for future per-kind reply
    /// shaping; today both emit a plain `TRONA_OK` ack.
    FinalOpAckRemoval {
        client: ClientHandle,
        parent_vkey: VnodeKey,
        removed_child_vkey: VnodeKey,
        kind: FinalOpRemovalKind,
    },
    /// Parked on `rename`. On success both parents' `readdir_batch`
    /// snapshots must be invalidated. `old_parent_vkey` equals
    /// `new_parent_vkey` for intra-directory rename; the completion
    /// router handles the aliasing defensively.
    FinalOpAckRename {
        client: ClientHandle,
        new_parent_vkey: VnodeKey,
        old_parent_vkey: VnodeKey,
    },
    /// Parked on `link`. On success the target parent directory's
    /// `readdir_batch` snapshots are cleared. The source inode's own
    /// resolve-cache entry stays valid (inode identity is stable).
    FinalOpAckLink {
        client: ClientHandle,
        new_parent_vkey: VnodeKey,
    },
    /// Parked on `truncate`. On success the completion router
    /// refreshes the cached file size via `file_vkey` and notifies
    /// `mmsrv` of the new extent using `fd` (so mmap'd regions past
    /// the new size get unmapped — normally done inline on the VOP
    /// `Ready` path). No parent-directory relationship.
    FinalOpAckTruncate {
        client: ClientHandle,
        file_vkey: VnodeKey,
        fd: i32,
        old_size: u64,
    },
    /// Parked on `BACKEND_OPEN_SESSION`. The handler side of mount may
    /// legitimately take seconds on a large volume (free-block bitmap
    /// scan, feature negotiation, legacy inode-counter upgrade). Parking
    /// keeps the VFS owner loop responsive to other mount points while
    /// the slow backend is still coming up. `mount_token` is the opaque
    /// token the mount dispatcher planted when it issued the
    /// `OpenSession` request; on completion the router refreshes the
    /// nascent `BackendSessionSlot` from the reply, stamps the root
    /// vnode, and emits the pending `mount(2)` ack. `client` is the
    /// caller's handle so the eventual reply targets the right client.
    MountReady {
        client: ClientHandle,
        mount_token: u64,
    },
    /// Parked on one step of the internal late-pivot scaffold builder.
    /// This continuation has no client-facing reply slot; the backend
    /// completion is routed back into `boot::late_mount` so the owner
    /// loop can keep driving the rootfs-target state machine.
    LatePivot { dir_index: u8, op: LatePivotOp },
}

/// Identifies which child-returning compound mutation produced a
/// `FinalOpChild` resume — lets the completion router pick the right
/// reply format (fd allocation for openat, bare ack for mkdir /
/// symlink / mkfifo) without re-matching the backend's opaque
/// op-kind payload.
#[derive(Clone, Copy)]
pub(crate) enum FinalOpKind {
    Create,
    Mkdir,
    Symlink,
}

/// Sub-discriminator for the removal flavour of `FinalOpAckRemoval`
/// — lets future per-kind telemetry / reply shaping distinguish
/// `unlink` from `rmdir` without a second enum walk.
#[derive(Clone, Copy)]
pub(crate) enum FinalOpRemovalKind {
    Unlink,
    Rmdir,
}

/// Which metadata operation the internal late-pivot state machine is
/// currently waiting on.
#[derive(Clone, Copy)]
pub(crate) enum LatePivotOp {
    Lookup,
    Mkdir,
}
