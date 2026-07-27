// SPDX-License-Identifier: GPL-2.0-only
//! Deferred backend RPC promotion — drain the session's waiter ring
//! when inflight credit is released.
//!
//! Companion to `crate::owner::deferred::DeferredIssue`. When a
//! completion lands and calls `backend_credit_release`, this module
//! iterates the session's waiter ring, promoting each parked
//! `DeferredIssue` to a live `PendingOp` by:
//! 1. Reserving credit (now available).
//! 2. Reserving a fresh `PendingOp` slot + `TxId`.
//! 3. Re-building the backend request from the parked `SaltyfsOpKind`
//!    using the same wire layout the original `saltyfs_ipc_*_issue`
//!    helpers produce.
//! 4. Firing `send_ctx` to the backend.
//! 5. Stamping the saved `Resume` onto the new `PendingOp` so the
//!    completion routes back to the waiting client.
//!
//! A promotion failure at any step releases the credit it just
//! reserved (if any) and synthesises an error reply to the client
//! via the saved `reply_slot`, so no deferred entry is ever silently
//! dropped.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::*;
use uapi::*;

use crate::owner::DeferArgs;
use crate::owner::VfsState;
use crate::owner::deferred::DeferredIssue;
use crate::owner::op::{OpCore, OwnerPostOp};
use crate::owner::pending::{PendingOpHandle, PendingOpState, TxId};
use crate::owner::resume::Resume;
use crate::owner::resume::fs::FsResume;
use crate::vfs_core::identity::FsInstanceId;

use super::op_kind::SaltyfsOpKind;
use super::rpc::{ipc_ctx, stamp_saltyfs_async_request};
use super::types::{SaltyfsMountData, SaltyfsVnodeData};

/// Acquire ownership of the per-mount VFS↔saltyfs SHM region for a
/// readdir batch in flight. Returns `true` when the SHM is idle or
/// the prior owner's `OpenObject` slot has been reclaimed (orphan
/// ownership left over by a client that closed the fd mid-drain);
/// in both cases the caller overwrites the owner. Returns `false`
/// when a live, distinct owner holds the SHM and the caller must
/// park instead of reissuing.
///
/// SHM exclusivity is also gated against any live async xattr op —
/// [`acquire_xattr_shm`] and this function must see `false` when the
/// other side holds the region. A stale `xattr_shm_owner` (no
/// matching live `PendingOp`) is reclaimed in place so an orphaned
/// xattr completion does not strand readdir indefinitely.
pub(crate) unsafe fn acquire_readdir_shm(
    state: &mut VfsState,
    md: *mut SaltyfsMountData,
    open_handle: crate::server::open_object::OpenObjectHandle,
) -> bool {
    unsafe {
        // Clear stale xattr ownership: the PendingOp tagged with the
        // recorded TxId may have been reaped (session teardown,
        // cancelled dispatch) without a completion running the
        // matching release. In that case treat xattr SHM as idle.
        let xattr_tx = (*md).xattr_shm_owner;
        if xattr_tx.is_valid() && state.find_pending_op(xattr_tx).is_none() {
            (*md).xattr_shm_owner = crate::owner::pending::TxId::INVALID;
        }
        if (*md).xattr_shm_owner.is_valid() {
            return false;
        }

        let current = (*md).readdir_shm_owner;
        if current == open_handle {
            // Same owner reissuing — OK.
            return true;
        }
        if !current.is_valid() {
            (*md).readdir_shm_owner = open_handle;
            return true;
        }
        // Live handle in the slot — is the referenced `OpenObject`
        // still alive? A closed fd leaves a stale handle behind; we
        // reclaim by overwriting.
        let current_obj = state.open_objects.get(current);
        if current_obj.is_none() {
            (*md).readdir_shm_owner = open_handle;
            return true;
        }
        // Orphan reclaim for mutation-induced batch invalidation:
        // `VfsState::invalidate_parent_dir_caches` zeroes the owner's
        // `readdir_batch` when the parent directory mutates, but
        // leaves `readdir_shm_owner` alone (the owner field is a
        // backend-private flag and the generic invalidation helper
        // can't reach it). A zeroed batch means the owner has no
        // live records in SHM to drain; treat that as idle and let
        // the new caller take over. Without this, a parked readdir
        // on a different fd could wait indefinitely even though the
        // SHM region is semantically free.
        let obj = current_obj.unwrap();
        if obj.readdir_batch.entries_total == 0 && obj.readdir_batch.entries_consumed == 0 {
            (*md).readdir_shm_owner = open_handle;
            return true;
        }
        false
    }
}

/// Acquire ownership of the per-mount VFS↔saltyfs SHM region for an
/// async xattr op (`BACKEND_GETXATTR` / `BACKEND_SETXATTR` /
/// `BACKEND_LISTXATTR`). Returns `true` when the SHM is idle or
/// orphaned; caller then writes its `name` / `value` payload at
/// `shm_offset = 0` and fires the request. Returns `false` when a
/// live readdir or another live async xattr op currently holds the
/// SHM — caller must park via the session's waiter ring.
///
/// Orphan detection: a prior `xattr_shm_owner` whose `PendingOp` has
/// been reaped (cancelled / session torn down without a completion
/// routed) is cleared in place; a prior `readdir_shm_owner` whose
/// `OpenObject` is gone is likewise treated as idle.
pub(crate) unsafe fn acquire_xattr_shm(
    state: &mut VfsState,
    md: *mut SaltyfsMountData,
    new_tx: crate::owner::pending::TxId,
) -> bool {
    unsafe {
        // Clear a stale xattr owner — see `acquire_readdir_shm` for
        // the same reclaim rule.
        let cur_xattr = (*md).xattr_shm_owner;
        if cur_xattr.is_valid() && cur_xattr != new_tx && state.find_pending_op(cur_xattr).is_none()
        {
            (*md).xattr_shm_owner = crate::owner::pending::TxId::INVALID;
        }
        if (*md).xattr_shm_owner.is_valid() && (*md).xattr_shm_owner != new_tx {
            return false;
        }

        // Readdir exclusion: check live OpenObject, and treat a
        // mutation-invalidated batch (entries_total == 0) as
        // semantically idle so the xattr side can reclaim — same
        // rule as `acquire_readdir_shm`'s orphan reclaim.
        let rdir = (*md).readdir_shm_owner;
        if rdir.is_valid() {
            match state.open_objects.get(rdir) {
                Some(obj)
                    if obj.readdir_batch.entries_total != 0
                        || obj.readdir_batch.entries_consumed != 0 =>
                {
                    return false;
                }
                _ => {
                    (*md).readdir_shm_owner = crate::server::open_object::OpenObjectHandle::INVALID;
                }
            }
        }

        (*md).xattr_shm_owner = new_tx;
        true
    }
}

/// Release xattr SHM ownership back to the pool. Called by the
/// completion router after draining the backend's reply payload out
/// of SHM and by [`drain_deferred_issues`] / cancel paths when the
/// owning `PendingOp` is reaped without a completion.
pub(crate) unsafe fn release_xattr_shm_if_owner(
    md: *mut SaltyfsMountData,
    tx: crate::owner::pending::TxId,
) {
    unsafe {
        if (*md).xattr_shm_owner == tx {
            (*md).xattr_shm_owner = crate::owner::pending::TxId::INVALID;
        }
    }
}

/// Non-mutating probe variant of [`acquire_xattr_shm`]. Returns
/// `true` when a fresh xattr claim *would* succeed against the
/// current state (readdir owner dead / absent AND xattr owner dead
/// / absent). Used by the drain loop to decide whether to promote
/// a parked xattr op to a live `PendingOp` — the actual ownership
/// stamp lives in [`promote_deferred_issue`] so it can use the
/// `TxId` returned by `reserve_fs_pending`.
pub(crate) unsafe fn xattr_shm_would_acquire(
    state: &mut VfsState,
    md: *mut SaltyfsMountData,
) -> bool {
    unsafe {
        let cur_xattr = (*md).xattr_shm_owner;
        if cur_xattr.is_valid() && state.find_pending_op(cur_xattr).is_none() {
            (*md).xattr_shm_owner = crate::owner::pending::TxId::INVALID;
        }
        if (*md).xattr_shm_owner.is_valid() {
            return false;
        }
        let rdir = (*md).readdir_shm_owner;
        if rdir.is_valid() {
            match state.open_objects.get(rdir) {
                Some(obj)
                    if obj.readdir_batch.entries_total != 0
                        || obj.readdir_batch.entries_consumed != 0 =>
                {
                    return false;
                }
                _ => {
                    (*md).readdir_shm_owner = crate::server::open_object::OpenObjectHandle::INVALID;
                }
            }
        }
        true
    }
}

/// Release SHM ownership back to the pool. Called by the readdir
/// VOP when the cached batch has been fully drained (so subsequent
/// readdir calls on any open directory can reissue without
/// waiting) or by [`drain_deferred_issues`] when the former owner
/// proves unreachable.
pub(crate) unsafe fn release_readdir_shm_if_owner(
    md: *mut SaltyfsMountData,
    open_handle: crate::server::open_object::OpenObjectHandle,
) {
    unsafe {
        if (*md).readdir_shm_owner == open_handle {
            (*md).readdir_shm_owner = crate::server::open_object::OpenObjectHandle::INVALID;
        }
    }
}

/// `BackendSessionSlot::readdir_eof_fn` hook. Wired at mount time in
/// [`super::vfsops::saltyfs_mount`]. Invoked by the generic fileops
/// readdir-drain helper when the backend reports zero new entries
/// (EOF). Keeps the saltyfs-specific SHM-ownership release logic off
/// the generic `fileops::dir` path; the hook resolves the mount from
/// `fs_id` and calls [`release_readdir_shm_if_owner`] on behalf of
/// the backend.
pub(crate) unsafe fn saltyfs_readdir_eof(
    state: &mut VfsState,
    fs_id: FsInstanceId,
    open_handle: crate::server::open_object::OpenObjectHandle,
) {
    unsafe {
        let Some(mh) = state.mount_by_fs_instance_id(fs_id) else {
            return;
        };
        let Some(mount) = state.mounts.get(mh) else {
            return;
        };
        let md = mount.data as *mut SaltyfsMountData;
        if md.is_null() {
            return;
        }
        release_readdir_shm_if_owner(md, open_handle);
    }
}

/// Drain the deferred-issue waiter ring for the session bound to
/// `fs_id` until either the ring is empty or credit is exhausted.
/// Invoked from every saltyfs resume handler after
/// `backend_credit_release` so a freed slot is immediately put to
/// work on the oldest parked waiter.
pub(crate) unsafe fn drain_deferred_issues(state: &mut VfsState, fs_id: FsInstanceId) {
    unsafe {
        loop {
            if !state.backend_credit_available(fs_id) {
                return;
            }
            let Some((handle, snapshot)) = state.pop_deferred_issue(fs_id) else {
                return;
            };
            // SHM-using snapshots (readdir / xattr) need the per-mount
            // SHM region free before we can reissue. If not, push the
            // entry back and stop draining — when the current SHM
            // owner finishes, it will fire another credit_release
            // that re-enters the drain with a clean state. Readdir
            // snapshots are acquired against their own `OpenObject`;
            // xattr snapshots get the xattr_shm_owner stamped by
            // [`promote_deferred_issue`] using the fresh `TxId` that
            // `reserve_fs_pending` hands out.
            let op = SaltyfsOpKind::unpack(&snapshot.op);
            let needs_shm = matches!(
                op,
                SaltyfsOpKind::Readdir { .. }
                    | SaltyfsOpKind::XattrGet { .. }
                    | SaltyfsOpKind::ListXattr { .. }
                    | SaltyfsOpKind::SetXattr { .. }
            );
            if needs_shm {
                let md_ptr = match state.mount_by_fs_instance_id(fs_id) {
                    Some(mh) => match state.mounts.get(mh) {
                        Some(m) => m.data as *mut SaltyfsMountData,
                        None => {
                            drain_promotion_fail(state, snapshot.reply_op);
                            continue;
                        }
                    },
                    None => {
                        drain_promotion_fail(state, snapshot.reply_op);
                        continue;
                    }
                };
                if md_ptr.is_null() {
                    drain_promotion_fail(state, snapshot.reply_op);
                    continue;
                }
                let shm_available = match op {
                    SaltyfsOpKind::Readdir { .. } => {
                        let open_h = readdir_open_handle_from_resume(snapshot.resume);
                        acquire_readdir_shm(state, md_ptr, open_h)
                    }
                    SaltyfsOpKind::XattrGet { .. }
                    | SaltyfsOpKind::ListXattr { .. }
                    | SaltyfsOpKind::SetXattr { .. } => {
                        // Probe-only: can xattr claim succeed against
                        // the current state? We pass `TxId::INVALID`
                        // so the check treats any live holder as
                        // blocking but doesn't stamp ownership; the
                        // real stamp happens inside
                        // [`promote_deferred_issue`] once
                        // `reserve_fs_pending` allocates the new tx.
                        xattr_shm_would_acquire(state, md_ptr)
                    }
                    _ => true,
                };
                if !shm_available {
                    // SHM still held by another live owner. Put the
                    // entry back and stop draining this round.
                    let _ = requeue_deferred_issue(state, fs_id, handle);
                    return;
                }
            }
            promote_deferred_issue(state, fs_id, handle, snapshot);
        }
    }
}

/// Extract the owning `OpenObject` handle out of a parked readdir's
/// `Resume`. Returns `INVALID` if the resume is somehow not a
/// BulkReaddirStage — should not happen for snapshots whose op is
/// `SaltyfsOpKind::Readdir` but we handle it defensively.
#[inline]
fn readdir_open_handle_from_resume(resume: Resume) -> crate::server::open_object::OpenObjectHandle {
    match resume {
        Resume::Fs(FsResume::BulkReaddirStage { open_handle, .. }) => open_handle,
        _ => crate::server::open_object::OpenObjectHandle::INVALID,
    }
}

#[inline]
fn requeue_deferred_issue(
    state: &mut VfsState,
    fs_id: FsInstanceId,
    handle: PendingOpHandle,
) -> bool {
    let Some(idx) = state.backend_session_slot_index(fs_id) else {
        return false;
    };
    state.backend_sessions[idx].wait_q_push(handle)
}

/// Promote a single popped `DeferredIssue` to a live `PendingOp`.
/// On any failure (credit reservation, pending arena, mount
/// teardown between park and drain) the caller receives a stable
/// error reply and the reply slot is released so the client
/// unblocks cleanly.
unsafe fn promote_deferred_issue(
    state: &mut VfsState,
    fs_id: FsInstanceId,
    handle: PendingOpHandle,
    snapshot: DeferredIssue,
) {
    unsafe {
        let Some(session_idx) = state.backend_session_slot_index(fs_id) else {
            state.release_deferred_issue(handle);
            return drain_promotion_fail(state, snapshot.reply_op);
        };
        let live_session = state.backend_sessions[session_idx];
        if !live_session.is_live()
            || live_session.session_id != snapshot.session_id
            || live_session.live_gen != snapshot.session_gen
        {
            state.release_deferred_issue(handle);
            return drain_promotion_fail(state, snapshot.reply_op);
        }

        // Resolve the mount's saltyfs data pointer. A torn-down mount
        // between park and drain surfaces `TRONA_INVALID_OPERATION`.
        let md_ptr = match state.mount_by_fs_instance_id(fs_id) {
            Some(mh) => match state.mounts.get(mh) {
                Some(m) => m.data as *mut SaltyfsMountData,
                None => {
                    state.release_deferred_issue(handle);
                    return drain_promotion_fail(state, snapshot.reply_op);
                }
            },
            None => {
                state.release_deferred_issue(handle);
                return drain_promotion_fail(state, snapshot.reply_op);
            }
        };
        if md_ptr.is_null() {
            state.release_deferred_issue(handle);
            return drain_promotion_fail(state, snapshot.reply_op);
        }

        if !state.backend_credit_reserve(fs_id) {
            // Raced with another drain / revocation. Put the issue
            // back on the ring — callers drained us under incorrect
            // assumptions; do NOT synthesise a client error yet.
            if requeue_deferred_issue(state, fs_id, handle) {
                return;
            }
            // Ring couldn't re-accept the entry — fall through to the
            // error path so the client unblocks.
            state.release_deferred_issue(handle);
            return drain_promotion_fail(state, snapshot.reply_op);
        }

        let op = SaltyfsOpKind::unpack(&snapshot.op);
        let tx_id = state.alloc_tx_id();
        let Some(slot) = state.pending_ops.get_mut(handle) else {
            state.backend_credit_release_no_drain(fs_id);
            return drain_promotion_fail(state, snapshot.reply_op);
        };
        slot.tx_id = tx_id;
        slot.client_badge = snapshot.client_badge;
        slot.reply_op = snapshot.reply_op;
        slot.op_state = PendingOpState::Fs {
            fs_instance_id: fs_id,
            kind: snapshot.op,
            resume_ctx: snapshot.resume,
        };
        slot.cancelled = 0;
        slot.credited = 1;
        slot.coalesce_primary_tx = TxId::INVALID;

        // For SHM-using xattr kinds, stamp `xattr_shm_owner` to the
        // fresh `TxId` now that the pending slot exists. The outer
        // drain loop already confirmed via [`xattr_shm_would_acquire`]
        // that the region is free; this is a no-fail ownership write
        // because the probe and stamp happen on the same stack frame
        // without re-entering the owner loop.
        match op {
            SaltyfsOpKind::XattrGet { .. }
            | SaltyfsOpKind::ListXattr { .. }
            | SaltyfsOpKind::SetXattr { .. } => {
                (*md_ptr).xattr_shm_owner = tx_id;
            }
            _ => {}
        }

        if !fire_saltyfs_op_from_snapshot(state, fs_id, md_ptr, op, tx_id, snapshot.target_seq) {
            // Unstamp any ownership we just wrote — the op never
            // went out on the wire, so no completion will run the
            // normal release.
            match op {
                SaltyfsOpKind::XattrGet { .. }
                | SaltyfsOpKind::ListXattr { .. }
                | SaltyfsOpKind::SetXattr { .. } => {
                    release_xattr_shm_if_owner(md_ptr, tx_id);
                }
                _ => {}
            }
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release_no_drain(fs_id);
            return drain_promotion_fail(state, snapshot.reply_op);
        }
    }
}

/// Fire the backend request that matches a parked `SaltyfsOpKind`.
/// Reproduces the wire layout each `saltyfs_ipc_*_issue` helper
/// constructs on the live-credit path. Returns `false` when the
/// op kind is one that should never arrive on the deferred path
/// (currently none — but the exhaustive match surfaces future
/// op kinds as a compile error rather than a silent drop).
///
/// `state` + `fs_id` are threaded so the post-send error code can
/// feed the reactive revocation detector via
/// `observe_backend_send`. Without this, a backend that died while
/// ops were parked on the deferred waiter ring would drain through
/// this path silently and the session teardown would never trigger.
unsafe fn fire_saltyfs_op_from_snapshot(
    state: &mut VfsState,
    fs_id: FsInstanceId,
    md: *mut SaltyfsMountData,
    op: SaltyfsOpKind,
    tx_id: TxId,
    target_seq: u32,
) -> bool {
    unsafe {
        let mut req = TronaMsg::zeroed();
        match op {
            SaltyfsOpKind::Read {
                ino,
                file_offset,
                transfer,
            } => {
                req.label = BACKEND_READ;
                req.regs[0] = ino;
                req.regs[1] = file_offset;
                let desc = transfer.encode_regs();
                req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG] = desc[0];
                req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 1] = desc[1];
                req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 2] = desc[2];
                req.length = (BACKEND_RW_REQ_DESCRIPTOR_REG + TransferDescriptor::REG_COUNT) as u64;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_READ, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Readdir {
                dir_ino,
                cookie,
                shm_offset,
                buf_bytes,
            } => {
                req.label = BACKEND_READDIR;
                req.regs[0] = dir_ino;
                req.regs[1] = cookie;
                req.regs[2] = shm_offset;
                req.regs[3] = buf_bytes;
                req.length = 4;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_READDIR, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Stat { ino } => {
                req.label = BACKEND_STAT;
                req.regs[0] = ino;
                req.length = 1;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_STAT, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::GetInfo => {
                req.label = BACKEND_GETINFO;
                req.length = 0;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_GETINFO, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Lookup {
                parent_ino,
                name,
                name_len,
            } => {
                req.label = BACKEND_LOOKUP;
                req.regs[0] = parent_ino;
                req.regs[1] = name_len as u64;
                // Copy the inline name payload into the request
                // registers starting at regs[2].
                let dst = &raw mut req.regs[2] as *mut u8;
                for i in 0..name_len as usize {
                    *dst.add(i) = name[i];
                }
                req.length = 2 + (name_len as u64 + 7) / 8;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_LOOKUP, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Readlink { ino } => {
                req.label = BACKEND_READLINK;
                req.regs[0] = ino;
                req.length = 1;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_READLINK, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::XattrGet {
                ino,
                name,
                name_len,
            } => {
                if !(*md).shm_active {
                    return false;
                }
                let shm_base = (*md).shm_vaddr as *mut u8;
                for i in 0..name_len as usize {
                    *shm_base.add(i) = name[i];
                }
                req.label = BACKEND_GETXATTR;
                req.regs[0] = ino;
                req.regs[1] = 0; // shm_offset
                req.regs[2] = 31 * 8; // buf_bytes = inline reply capacity
                req.regs[3] = name_len as u64;
                req.length = 4;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_GETXATTR, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::ListXattr { ino } => {
                if !(*md).shm_active {
                    return false;
                }
                req.label = BACKEND_LISTXATTR;
                req.regs[0] = ino;
                req.regs[1] = 0; // shm_offset
                req.regs[2] = (*md).shm_size;
                req.length = 3;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_LISTXATTR, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::SetAttr {
                ino,
                mask,
                mode,
                uid,
                gid,
                atime,
                mtime,
                size,
            } => {
                req.label = BACKEND_SETATTR;
                req.regs[0] = ino;
                req.regs[1] = mask as u64;
                req.regs[2] = mode as u64;
                req.regs[3] = (uid as u64) | ((gid as u64) << 32);
                req.regs[4] = atime;
                req.regs[5] = mtime;
                req.regs[6] = size;
                req.length = BACKEND_SETATTR_REG_COUNT as u64;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_SETATTR, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::SetXattr {
                ino,
                name,
                value,
                name_len,
                value_len,
                flags,
            } => {
                if !(*md).shm_active {
                    return false;
                }
                let shm_base = (*md).shm_vaddr as *mut u8;
                for i in 0..name_len as usize {
                    *shm_base.add(i) = name[i];
                }
                for i in 0..value_len as usize {
                    *shm_base.add(name_len as usize + i) = value[i];
                }
                req.label = BACKEND_SETXATTR;
                req.regs[0] = ino;
                req.regs[1] = flags as u64;
                req.regs[2] = 0; // shm_offset
                req.regs[3] = value_len as u64;
                req.regs[4] = name_len as u64;
                req.length = 5;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_SETXATTR, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::RemoveXattr {
                ino,
                name,
                name_len,
            } => {
                req.label = BACKEND_REMOVEXATTR;
                req.regs[0] = ino;
                req.regs[1] = name_len as u64;
                let dst = &raw mut req.regs[2] as *mut u8;
                for i in 0..name_len as usize {
                    *dst.add(i) = name[i];
                }
                req.length = 2 + (name_len as u64 + 7) / 8;
                stamp_saltyfs_async_request(
                    md,
                    &mut req,
                    BACKEND_REMOVEXATTR,
                    tx_id,
                    target_seq,
                    0,
                );
            }
            SaltyfsOpKind::Create {
                parent_ino,
                mode,
                uid,
                gid,
                name,
                name_len,
            } => {
                const V2: u64 = 1u64 << 63;
                req.label = BACKEND_CREATE;
                req.regs[0] = parent_ino | V2;
                req.regs[1] = mode as u64;
                req.regs[2] = uid as u64;
                req.regs[3] = gid as u64;
                req.regs[4] = name_len as u64;
                let dst = &raw mut req.regs[5] as *mut u8;
                for i in 0..name_len as usize {
                    *dst.add(i) = name[i];
                }
                req.length = 5 + (name_len as u64 + 7) / 8;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_CREATE, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Mkdir {
                parent_ino,
                mode,
                uid,
                gid,
                name,
                name_len,
            } => {
                const V2: u64 = 1u64 << 63;
                req.label = BACKEND_MKDIR;
                req.regs[0] = parent_ino | V2;
                req.regs[1] = mode as u64;
                req.regs[2] = uid as u64;
                req.regs[3] = gid as u64;
                req.regs[4] = name_len as u64;
                let dst = &raw mut req.regs[5] as *mut u8;
                for i in 0..name_len as usize {
                    *dst.add(i) = name[i];
                }
                req.length = 5 + (name_len as u64 + 7) / 8;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_MKDIR, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Symlink {
                parent_ino,
                uid,
                gid,
                name,
                target,
                name_len,
                target_len,
            } => {
                // Wire-layout mirror of the sync V2 helper in
                // `mutate_rpc::saltyfs_ipc_symlink`: name at fixed
                // slot regs[5..12] (56 bytes), target at fixed slot
                // regs[12..20] (64 bytes), total length 20 u64 words.
                // Replay must match byte-for-byte; packing names at
                // regs[5..] and stopping at `5 + (name_len+7)/8`
                // produces a truncated request the backend reads as
                // the wrong layout.
                const V2: u64 = 1u64 << 63;
                req.label = BACKEND_SYMLINK;
                req.regs[0] = parent_ino | V2;
                req.regs[1] = uid as u64;
                req.regs[2] = gid as u64;
                req.regs[3] = name_len as u64;
                req.regs[4] = target_len as u64;
                let dst_name = &raw mut req.regs[5] as *mut u8;
                for i in 0..name_len as usize {
                    *dst_name.add(i) = name[i];
                }
                let dst_target = &raw mut req.regs[12] as *mut u8;
                for i in 0..target_len as usize {
                    *dst_target.add(i) = target[i];
                }
                req.length = 20;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_SYMLINK, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Unlink {
                parent_ino,
                name,
                name_len,
            } => {
                req.label = BACKEND_UNLINK;
                req.regs[0] = parent_ino;
                req.regs[1] = name_len as u64;
                let dst = &raw mut req.regs[2] as *mut u8;
                for i in 0..name_len as usize {
                    *dst.add(i) = name[i];
                }
                req.length = 2 + (name_len as u64 + 7) / 8;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_UNLINK, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Rmdir {
                parent_ino,
                name,
                name_len,
            } => {
                req.label = BACKEND_RMDIR;
                req.regs[0] = parent_ino;
                req.regs[1] = name_len as u64;
                let dst = &raw mut req.regs[2] as *mut u8;
                for i in 0..name_len as usize {
                    *dst.add(i) = name[i];
                }
                req.length = 2 + (name_len as u64 + 7) / 8;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_RMDIR, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Link {
                target_ino,
                parent_ino,
                name,
                name_len,
            } => {
                req.label = BACKEND_LINK;
                req.regs[0] = target_ino;
                req.regs[1] = parent_ino;
                req.regs[2] = name_len as u64;
                let dst = &raw mut req.regs[3] as *mut u8;
                for i in 0..name_len as usize {
                    *dst.add(i) = name[i];
                }
                req.length = 3 + (name_len as u64 + 7) / 8;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_LINK, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Rename {
                old_parent_ino,
                new_parent_ino,
                old_name,
                new_name,
                old_name_len,
                new_name_len,
            } => {
                // Wire-layout mirror of `mutate_rpc::saltyfs_ipc_rename`:
                //   regs[0] = old_parent_ino
                //   regs[1] = old_name_len
                //   regs[2] = new_parent_ino
                //   regs[3] = new_name_len
                //   regs[4..12] = old_name (64 bytes, fixed)
                //   regs[12..20] = new_name (64 bytes, fixed)
                // length = 20
                // The saltyfs `handle_rename_fs` handler reads these
                // offsets literally; packing the names flush against
                // the header would land them in the wrong slots.
                req.label = BACKEND_RENAME;
                req.regs[0] = old_parent_ino;
                req.regs[1] = old_name_len as u64;
                req.regs[2] = new_parent_ino;
                req.regs[3] = new_name_len as u64;
                let old_dst = &raw mut req.regs[4] as *mut u8;
                for i in 0..old_name_len as usize {
                    *old_dst.add(i) = old_name[i];
                }
                let new_dst = &raw mut req.regs[12] as *mut u8;
                for i in 0..new_name_len as usize {
                    *new_dst.add(i) = new_name[i];
                }
                req.length = 20;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_RENAME, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::Truncate { ino, new_size } => {
                req.label = BACKEND_TRUNCATE;
                req.regs[0] = ino;
                req.regs[1] = new_size;
                req.length = 2;
                stamp_saltyfs_async_request(md, &mut req, BACKEND_TRUNCATE, tx_id, target_seq, 0);
            }
            SaltyfsOpKind::OpenSession { .. } => {
                // `OpenSession` reservations are fired inline during
                // mount and never ride the deferred-issue drain (which
                // exists to replay SHM-contested ops). Reaching this
                // arm means the op-kind tag got crossed with a
                // deferred slot — a contract violation. Drop and log.
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[VFS] deferred drain saw SaltyfsOpKind::OpenSession; dropping\n");
                });
                return false;
            }
        }
        let send_err = ipc::send_ctx(ipc_ctx(), (*md).fs_cap, &raw const req);
        state.observe_backend_send(fs_id, send_err);
        true
    }
}

/// Synthesise an error reply on a failed promotion. Releases the
/// reply slot as a side effect so the client unblocks with a stable
/// errno instead of hanging indefinitely.
unsafe fn drain_promotion_fail(state: &mut VfsState, reply_op: OpCore) {
    unsafe {
        if reply_op.reply_slot == 0 {
            return;
        }
        let mut err = TronaMsg::zeroed();
        err.label = TRONA_INVALID_OPERATION;
        err.length = 1;
        state.complete_op(reply_op, OwnerPostOp::None, &raw const err);
    }
}

/// Push-on-exhaustion hook for saltyfs sessions. Wired into the
/// `BackendSessionSlot.push_fn` slot at mount time via
/// [`super::vfsops::saltyfs_mount`]. The generic fileops path
/// invokes this when credit is exhausted with
/// backend-opaque primitives; this function does the saltyfs-
/// specific work of building a `SaltyfsOpKind` + `FsResume` from
/// the opaque vnode-data pointer and pushing a `DeferredIssue` onto
/// the session's waiter ring.
///
/// Returns `true` on successful park (client will unblock via the
/// drain path when credit frees); `false` when the waiter ring is
/// full, in which case the generic caller surfaces `TRONA_BUSY`.
pub(crate) unsafe fn saltyfs_defer_push(
    state: &mut VfsState,
    fs_id: FsInstanceId,
    args: DeferArgs,
    client_badge: u64,
    reply_op: OpCore,
) -> bool {
    unsafe {
        let session_id = state
            .backend_session_slot_index(fs_id)
            .map(|idx| state.backend_sessions[idx].session_id)
            .unwrap_or(0);
        let session_gen = state
            .backend_session_slot_index(fs_id)
            .map(|idx| state.backend_sessions[idx].live_gen)
            .unwrap_or(0);

        // Capture the caller's incarnation sequence from the `vkey`
        // carried by the DeferArgs variant. Stamped onto the
        // promoted request's correlation header at replay time so
        // backend stale-incarnation detection fires on replayed ops.
        let target_seq: u32 = match args {
            DeferArgs::Read { vkey, .. }
            | DeferArgs::Readdir { vkey, .. }
            | DeferArgs::XattrGet { vkey, .. }
            | DeferArgs::XattrList { vkey, .. }
            | DeferArgs::XattrSet { vkey, .. } => vkey.backend_id.seq,
        };

        let (op, resume) = match args {
            DeferArgs::Read {
                vnode_data,
                mount_data,
                file_offset,
                len,
                fd,
                shm_offset,
                client,
                vkey,
            } => {
                let vd = vnode_data as *const SaltyfsVnodeData;
                let md = mount_data as *const SaltyfsMountData;
                if vd.is_null() || md.is_null() {
                    return false;
                }
                let file_size = (*vd).size;
                if file_offset >= file_size {
                    return false;
                }
                let available = file_size - file_offset;
                let capped = if len > available { available } else { len };
                if capped == 0 {
                    return false;
                }
                let transfer = if capped > INLINE_TRANSFER_THRESHOLD && (*md).shm_active {
                    let shm_bound = core::cmp::min((*md).shm_size, capped);
                    TransferDescriptor::shm(0, shm_bound)
                } else {
                    let inline_bound = if capped > INLINE_TRANSFER_THRESHOLD {
                        INLINE_TRANSFER_THRESHOLD
                    } else {
                        capped
                    };
                    TransferDescriptor::inline(inline_bound)
                };
                (
                    SaltyfsOpKind::Read {
                        ino: (*vd).remote_ino,
                        file_offset,
                        transfer,
                    },
                    Resume::Fs(FsResume::BulkReadStage {
                        client,
                        vkey,
                        fs_id,
                        fd,
                        shm_offset,
                    }),
                )
            }
            DeferArgs::Readdir {
                vnode_data,
                mount_data,
                fd,
                client,
                open_handle,
                start_cursor,
                vkey,
            } => {
                let vd = vnode_data as *const SaltyfsVnodeData;
                let md = mount_data as *const SaltyfsMountData;
                if vd.is_null() || md.is_null() {
                    return false;
                }
                if !(*md).shm_active {
                    return false;
                }
                let backend_cookie = state
                    .open_objects
                    .get(open_handle)
                    .map(|o| o.readdir_batch.cookie)
                    .unwrap_or(0);
                (
                    SaltyfsOpKind::Readdir {
                        dir_ino: (*vd).remote_ino,
                        cookie: backend_cookie,
                        shm_offset: 0,
                        buf_bytes: (*md).shm_size,
                    },
                    Resume::Fs(FsResume::BulkReaddirStage {
                        client,
                        dir_vkey: vkey,
                        fs_id,
                        fd,
                        open_handle,
                        start_cursor,
                    }),
                )
            }
            DeferArgs::XattrGet {
                vnode_data,
                mount_data,
                client,
                vkey,
                name,
                name_len,
            } => {
                let vd = vnode_data as *const SaltyfsVnodeData;
                let md = mount_data as *const SaltyfsMountData;
                if vd.is_null() || md.is_null() || !(*md).shm_active {
                    return false;
                }
                (
                    SaltyfsOpKind::XattrGet {
                        ino: (*vd).remote_ino,
                        name,
                        name_len,
                    },
                    Resume::Fs(FsResume::FillXattrGetReply {
                        client,
                        vkey,
                        fs_id,
                    }),
                )
            }
            DeferArgs::XattrList {
                vnode_data,
                mount_data,
                client,
                vkey,
            } => {
                let vd = vnode_data as *const SaltyfsVnodeData;
                let md = mount_data as *const SaltyfsMountData;
                if vd.is_null() || md.is_null() || !(*md).shm_active {
                    return false;
                }
                (
                    SaltyfsOpKind::ListXattr {
                        ino: (*vd).remote_ino,
                    },
                    Resume::Fs(FsResume::FillListXattrReply {
                        client,
                        vkey,
                        fs_id,
                    }),
                )
            }
            DeferArgs::XattrSet {
                vnode_data,
                mount_data,
                client,
                vkey,
                name,
                value,
                name_len,
                value_len,
                flags,
            } => {
                let vd = vnode_data as *const SaltyfsVnodeData;
                let md = mount_data as *const SaltyfsMountData;
                if vd.is_null() || md.is_null() || !(*md).shm_active {
                    return false;
                }
                (
                    SaltyfsOpKind::SetXattr {
                        ino: (*vd).remote_ino,
                        name,
                        value,
                        name_len,
                        value_len,
                        flags,
                    },
                    Resume::Fs(FsResume::AckMutation { client, vkey }),
                )
            }
        };

        let issue = DeferredIssue {
            session_id,
            session_gen,
            client_badge,
            reply_op,
            resume,
            op: op.pack(),
            target_seq,
            _pad: 0,
        };
        state.push_deferred_issue(fs_id, issue).is_some()
    }
}
