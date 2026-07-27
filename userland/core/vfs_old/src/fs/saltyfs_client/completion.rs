// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS completion router.
//!
//! Registered on every mounted saltyfs session's
//! [`BackendSessionSlot::completion_fn`]; invoked by
//! `crate::owner::pending::dispatch_pending_reply` once the generic
//! session-gate / stale-mount checks have passed.
//!
//! Responsibilities of this module:
//! 1. Unpack the [`PendingKindPayload`] into the saltyfs-private
//!    [`SaltyfsOpKind`].
//! 2. Parse the backend reply (`BACKEND_STAT` / `BACKEND_READ` /
//!    `BACKEND_READDIR` / `BACKEND_READLINK` / `BACKEND_GETXATTR` /
//!    `BACKEND_LISTXATTR`).
//! 3. Extract any SHM-resident payload into a stack buffer (or
//!    reference the VFS↔saltyfs SHM region directly for zero-copy
//!    hops).
//! 4. Release one inflight credit against the owning session —
//!    **after** parsing so the drain callback cannot fire a new
//!    request that stomps the SHM region we are about to read.
//! 5. Invoke the matching `fileops::resume_fill_*` with fully-parsed
//!    generic args so those functions stay backend-neutral.
//!
//! The generic fileops resume helpers **must not** reach into this
//! module or touch `SaltyfsOpKind` / `SaltyfsMountData`. If you find
//! yourself doing so, add the missing piece of pre-parsed generic
//! data as a new parameter on the fileops helper instead.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::posix::{INLINE_TRANSFER_THRESHOLD, TRANSFER_KIND_INLINE};
use uapi::*;

/// Maximum inline bytes we extract from a completion's reply regs.
/// Matches the advertised `INLINE_TRANSFER_THRESHOLD`; any payload
/// bigger than this must have come through the SHM relay branch, so
/// we never need a larger stack buffer.
const INLINE_PAYLOAD_CAP: usize = INLINE_TRANSFER_THRESHOLD as usize;

use crate::owner::VfsState;
use crate::owner::op::OpCore;
use crate::owner::pending::{PendingKindPayload, TxId, WALK_SYMLINK_TARGET_MAX};
use crate::owner::resume::{
    Resume,
    fs::{FinalOpKind, FsResume, LatePivotOp},
};
use crate::vfs_core::error::{IntegrityDetail, VfsError};
use crate::vfs_core::file::VAttr;
use crate::vfs_core::identity::FsInstanceId;

use super::op_kind::SaltyfsOpKind;
use super::types::SaltyfsMountData;

/// Read-only snapshot of the VFS↔saltyfs SHM metadata for a given
/// `fs_id`. Bytes are read after parse completes and before credit
/// release so a racing drain cannot overwrite the region.
#[inline]
unsafe fn shm_base_for(state: &VfsState, fs_id: FsInstanceId) -> Option<*const u8> {
    unsafe {
        let mh = state.mount_by_fs_instance_id(fs_id)?;
        let mount = state.mounts.get(mh)?;
        let md = mount.data as *const SaltyfsMountData;
        if md.is_null() {
            return None;
        }
        let base = (*md).shm_vaddr;
        if base == 0 {
            return None;
        }
        Some(base as *const u8)
    }
}

/// SaltyFS-side completion dispatcher. Registered on every saltyfs
/// `BackendSessionSlot::completion_fn` via `saltyfs_mount`.
pub(crate) unsafe fn saltyfs_completion(
    state: &mut VfsState,
    fs_id: FsInstanceId,
    tx_id: TxId,
    kind_payload: &PendingKindPayload,
    resume_ctx: Resume,
    reply_op: OpCore,
    reply_msg: &TronaMsg,
) {
    unsafe {
        let reply_slot = reply_op.reply_slot;
        let kind = SaltyfsOpKind::unpack(kind_payload);

        // Only `Resume::Fs(_)` variants are produced by saltyfs.
        // `Placeholder` indicates a caller that forgot to stamp —
        // drop with a log. `Net` / `Pty` are reserved for future
        // subsystems and should never pair with a saltyfs completion.
        let fs_resume = match resume_ctx {
            Resume::Fs(fs_resume) => fs_resume,
            Resume::Placeholder => {
                trona_runtime::udebug!(|_lb| {
                    _lb.str(b"[VFS] saltyfs completion with placeholder resume; dropping\n");
                });
                if reply_slot != 0 {
                    state.release_saved_reply_slot(reply_slot);
                }
                state.backend_credit_release(fs_id);
                return;
            }
            Resume::Net(_) | Resume::Pty(_) => {
                trona_runtime::udebug!(|_lb| {
                    _lb.str(b"[VFS] saltyfs completion paired with non-fs resume; dropping\n");
                });
                if reply_slot != 0 {
                    state.release_saved_reply_slot(reply_slot);
                }
                state.backend_credit_release(fs_id);
                return;
            }
        };

        match fs_resume {
            FsResume::FillStatReply { client, vkey }
            | FsResume::FillStatAfterWalk { client, vkey } => {
                let attr = parse_stat_attr(reply_msg, vkey.fs_instance_id);
                // No inflight-credit accounting on this path — stat
                // issues go through `saltyfs_ipc_stat_issue` which
                // currently does not reserve credit. Once all meta
                // ops migrate into the credit machinery this branch
                // will release credit too (see codex ws:23 follow-up).
                crate::fileops::stat::resume_fill_stat_reply(state, client, vkey, reply_slot, attr);
            }
            FsResume::FillReadlinkReply { client, vkey } => {
                let parsed = super::saltyfs_ipc_readlink_parse(reply_msg);
                match parsed {
                    Some((buf, len)) => {
                        crate::fileops::attr::resume_fill_readlink_reply(
                            state,
                            client,
                            vkey,
                            reply_slot,
                            Some((&buf[..len.min(WALK_SYMLINK_TARGET_MAX)])),
                        );
                    }
                    None => {
                        crate::fileops::attr::resume_fill_readlink_reply(
                            state, client, vkey, reply_slot, None,
                        );
                    }
                }
            }
            FsResume::FillAccessReply { client, vkey } => {
                // Terminal access/open-dir/exec-preflight acks all
                // share the same backend contract here: wire parsing is
                // just success/failure translation, while the fileops
                // helper owns vnode re-resolution and reply shaping.
                let ack = if reply_msg.label == TRONA_OK {
                    Ok(())
                } else {
                    Err(super::vops::trona_to_vfs_error(reply_msg.label))
                };
                crate::fileops::stat::resume_fill_access_reply(
                    state, client, vkey, reply_slot, ack,
                );
            }
            FsResume::FillOpenDirReply { client, vkey } => {
                let ack = if reply_msg.label == TRONA_OK {
                    Ok(())
                } else {
                    Err(super::vops::trona_to_vfs_error(reply_msg.label))
                };
                crate::fileops::dir::resume_fill_opendir_reply(
                    state, client, vkey, reply_slot, ack,
                );
            }
            FsResume::FillStatForExecAccessReply { client, vkey } => {
                let ack = if reply_msg.label == TRONA_OK {
                    Ok(())
                } else {
                    Err(super::vops::trona_to_vfs_error(reply_msg.label))
                };
                crate::fileops::stat::resume_fill_stat_for_exec_access_reply(
                    state, client, vkey, reply_slot, ack,
                );
            }
            FsResume::FillStatForExecAttrReply { client, vkey } => {
                let attr = parse_stat_attr(reply_msg, vkey.fs_instance_id);
                crate::fileops::stat::resume_fill_stat_for_exec_attr_reply(
                    state, client, vkey, reply_slot, attr,
                );
            }
            FsResume::FillXattrGetReply {
                client,
                vkey,
                fs_id: rfs_id,
            } => {
                let parsed = super::saltyfs_ipc_xattr_get_parse(reply_msg);
                let shm = shm_base_for(state, rfs_id);
                let mut buf = [0u8; VAL_INLINE_CAP];
                let value_slice = match (parsed, shm) {
                    (Some(val_len), Some(src)) if val_len > 0 => {
                        let copy = val_len.min(VAL_INLINE_CAP);
                        for i in 0..copy {
                            buf[i] = *src.add(i);
                        }
                        Some((val_len, copy))
                    }
                    (Some(val_len), _) => Some((val_len, 0)),
                    (None, _) => None,
                };
                // Release xattr SHM ownership NOW — we've finished
                // reading the region. Then release credit, which
                // fires the session's drain hook so any parked xattr
                // op observes both the freed SHM slot and the freed
                // credit before the fileops helper runs.
                release_xattr_shm_only(state, fs_id, tx_id);
                state.backend_credit_release(fs_id);
                crate::fileops::attr::resume_fill_xattr_get_reply(
                    state,
                    client,
                    vkey,
                    reply_slot,
                    value_slice.map(|(val_len, copy)| (val_len, &buf[..copy])),
                );
            }
            FsResume::FillListXattrReply {
                client,
                vkey,
                fs_id: rfs_id,
            } => {
                let parsed = super::saltyfs_ipc_listxattr_parse(reply_msg);
                let shm = shm_base_for(state, rfs_id);
                let mut buf = [0u8; VAL_INLINE_CAP];
                let copy_result = match (parsed, shm) {
                    (Some((bytes_needed, bytes_written)), Some(src)) => {
                        let copy = bytes_written.min(VAL_INLINE_CAP);
                        for i in 0..copy {
                            buf[i] = *src.add(i);
                        }
                        Some((bytes_needed, copy))
                    }
                    (Some((bytes_needed, _)), None) => Some((bytes_needed, 0)),
                    (None, _) => None,
                };
                release_xattr_shm_only(state, fs_id, tx_id);
                state.backend_credit_release(fs_id);
                crate::fileops::attr::resume_fill_listxattr_reply(
                    state,
                    client,
                    vkey,
                    reply_slot,
                    copy_result.map(|(bytes_needed, copy)| (bytes_needed, &buf[..copy])),
                );
            }
            FsResume::BulkReadStage {
                client,
                vkey,
                fs_id: rfs_id,
                fd,
                shm_offset,
            } => {
                let (transfer, read_offset) = match kind {
                    SaltyfsOpKind::Read {
                        transfer,
                        file_offset,
                        ..
                    } => (transfer, file_offset),
                    _ => {
                        if reply_slot != 0 {
                            state.release_saved_reply_slot(reply_slot);
                        }
                        state.backend_credit_release(fs_id);
                        return;
                    }
                };
                let bytes_read = super::saltyfs_ipc_read_parse(reply_msg);
                // Verify the backend honoured the request's transfer
                // envelope. A reply that claims more bytes than the
                // requested length, or a transfer descriptor
                // reporting an oversized slice, indicates either a
                // protocol bug or on-disk corruption overrunning the
                // extent map. Record as `DataCorrupt` with the
                // offending node + offset so operators can locate
                // the affected inode in the audit log.
                if let Some(n) = bytes_read {
                    if n > transfer.length as u64 {
                        let err = VfsError::DataCorrupt {
                            fs: rfs_id,
                            node: vkey.backend_id,
                            offset: read_offset,
                        };
                        err.audit_log();
                        state.backend_credit_release(fs_id);
                        if reply_slot != 0 {
                            state.release_saved_reply_slot(reply_slot);
                        }
                        return;
                    }
                }
                // Extract payload while SHM is still locked against the
                // next drain. If inline, read from reply regs; if SHM,
                // read from backend SHM buffer at the parked descriptor
                // offset.
                let mut inline_buf = [0u8; INLINE_PAYLOAD_CAP];
                let payload_slice: Option<&[u8]> = match bytes_read {
                    Some(n) if n == 0 => Some(&inline_buf[..0]),
                    Some(n) => {
                        let nz = n as usize;
                        if transfer.kind == TRANSFER_KIND_INLINE {
                            let cap = nz.min(INLINE_PAYLOAD_CAP);
                            let src = &reply_msg.regs
                                [trona_protocol::vfs::backend::BACKEND_READ_INLINE_PAYLOAD_REG]
                                as *const u64 as *const u8;
                            for i in 0..cap {
                                inline_buf[i] = *src.add(i);
                            }
                            Some(&inline_buf[..cap])
                        } else {
                            // SHM relay: read from backend SHM at
                            // `transfer.offset` into inline_buf (capped
                            // at INLINE_PAYLOAD_CAP — larger reads
                            // should have used a direct SHM-to-client
                            // relay path which lives inside the fileops
                            // helper). For now the fileops helper
                            // copies from its own SHM pointer (it
                            // retains the authority to access
                            // client SHM). This path therefore hands
                            // the fileops helper the byte count and
                            // transfer descriptor; the helper does the
                            // physical copy.
                            //
                            // That means we pass the raw backend SHM
                            // pointer+len via a dedicated argument shape.
                            // Fall through to the helper below using
                            // the variant-specific entry point so the
                            // code path stays simple.
                            let shm = shm_base_for(state, rfs_id);
                            if let Some(base) = shm {
                                // Release credit AFTER copying, so drive
                                // copy first here and then release.
                                let src = base.add(transfer.offset as usize);
                                // Defer actual copy to the fileops
                                // helper by forwarding a dedicated shm
                                // call shape below.
                                crate::fileops::bulk::resume_fill_bulk_read_reply_shm(
                                    state, client, vkey, rfs_id, fd, shm_offset, reply_slot, n, src,
                                );
                                state.backend_credit_release(fs_id);
                                return;
                            }
                            None
                        }
                    }
                    None => None,
                };

                // Inline / zero-byte / error path — release credit
                // before handing control to the generic helper so the
                // drain can proceed while the helper formats the reply.
                state.backend_credit_release(fs_id);
                crate::fileops::bulk::resume_fill_bulk_read_reply(
                    state,
                    client,
                    vkey,
                    rfs_id,
                    fd,
                    shm_offset,
                    reply_slot,
                    bytes_read.unwrap_or(0),
                    payload_slice,
                );
            }
            FsResume::BulkReaddirStage {
                client,
                dir_vkey,
                fs_id: rfs_id,
                fd,
                open_handle,
                start_cursor,
            } => {
                let parsed = super::saltyfs_ipc_readdir_parse(reply_msg);
                let shm = shm_base_for(state, rfs_id);
                let first_entry = match (parsed, shm) {
                    (Some((next_cursor, entries_written, bytes_written)), Some(base))
                        if entries_written > 0 =>
                    {
                        // Entry layout: u64 ino @0, u32 mode @32, u8 d_type @48,
                        // u8 name_len @49, name bytes @52.
                        let entry_ino = core::ptr::read_unaligned(base as *const u64);
                        let entry_mode = core::ptr::read_unaligned(base.add(32) as *const u32);
                        let entry_dtype_raw = *base.add(48);
                        let mut name_len = *base.add(49) as usize;
                        if name_len > super::READDIR_NAME_MAX {
                            name_len = super::READDIR_NAME_MAX;
                        }
                        let mut name_buf = [0u8; crate::fileops::dir::READDIR_FIRST_ENTRY_NAME_MAX];
                        let name_src = base.add(52);
                        for i in 0..name_len {
                            name_buf[i] = *name_src.add(i);
                        }
                        let d_type = if entry_dtype_raw != 0 {
                            entry_dtype_raw
                        } else {
                            super::readdir_mode_to_dtype(entry_mode)
                        };
                        Some(crate::fileops::dir::ReaddirReplyData {
                            next_cursor,
                            entries_written,
                            bytes_written,
                            first_entry_ino: entry_ino,
                            first_entry_dtype: d_type,
                            first_entry_name_len: name_len,
                            first_entry_name: name_buf,
                        })
                    }
                    (Some((next_cursor, entries_written, bytes_written)), _) => {
                        // EOF or SHM missing → deliver zero-entry reply.
                        Some(crate::fileops::dir::ReaddirReplyData {
                            next_cursor,
                            entries_written,
                            bytes_written,
                            first_entry_ino: 0,
                            first_entry_dtype: 0,
                            first_entry_name_len: 0,
                            first_entry_name: [0u8;
                                crate::fileops::dir::READDIR_FIRST_ENTRY_NAME_MAX],
                        })
                    }
                    (None, _) => None,
                };

                state.backend_credit_release(fs_id);
                crate::fileops::dir::resume_fill_bulk_readdir_reply(
                    state,
                    client,
                    dir_vkey,
                    rfs_id,
                    fd,
                    open_handle,
                    start_cursor,
                    reply_slot,
                    first_entry,
                );
            }
            FsResume::AckMutation { client, vkey } => {
                // Map completion to either Ok(()) (backend-applied)
                // or Err(VfsError). For `SetAttr`, additionally
                // apply the post-commit snapshot to the cached
                // `SaltyfsVnodeData` so subsequent stat calls see
                // the new mode/uid/gid/... without a follow-up RPC.
                let ack: Result<(), crate::vfs_core::error::VfsError> = match kind {
                    SaltyfsOpKind::SetAttr { .. } => {
                        match super::mutate_rpc::saltyfs_ipc_setattr_parse(reply_msg) {
                            Some(attr) => {
                                apply_attr_snapshot(state, vkey, &attr);
                                Ok(())
                            }
                            None => Err(super::vops::trona_to_vfs_error(reply_msg.label)),
                        }
                    }
                    SaltyfsOpKind::SetXattr { .. } => {
                        let res = match super::xattr_rpc::saltyfs_ipc_setxattr_parse(reply_msg) {
                            Ok(()) => Ok(()),
                            Err(label) => Err(super::vops::trona_to_vfs_error(label)),
                        };
                        // Release xattr SHM claim — credit release
                        // below fires the drain so a parked xattr op
                        // promotes onto the freed slot.
                        release_xattr_shm_only(state, fs_id, tx_id);
                        res
                    }
                    SaltyfsOpKind::RemoveXattr { .. } => {
                        match super::xattr_rpc::saltyfs_ipc_removexattr_parse(reply_msg) {
                            Ok(()) => Ok(()),
                            Err(label) => Err(super::vops::trona_to_vfs_error(label)),
                        }
                    }
                    // Defensive fallback — other kinds should not be
                    // paired with an `AckMutation` resume; surface
                    // the backend's label.
                    _ => Err(super::vops::trona_to_vfs_error(reply_msg.label)),
                };
                // All three `AckMutation` backends (setattr / setxattr
                // / removexattr) go through the credit machinery as
                // of this revision — release the credit and fire the
                // drain hook uniformly.
                state.backend_credit_release(fs_id);
                crate::fileops::attr::resume_fill_ack_mutation_reply(
                    state, client, vkey, reply_slot, ack,
                );
            }
            FsResume::FinalOpChild {
                client,
                parent_vkey,
                kind_hint,
                open_request,
                creds_uid,
                creds_gid,
            } => {
                // The compound-mutation async RPCs (`BACKEND_CREATE`
                // / `_MKDIR` / `_SYMLINK`) return just the new ino;
                // synthesise the rest of the attrs from the client-
                // known request state (mode, uid/gid from creds,
                // sensible defaults for size/nlink/blocks) so the
                // completion router doesn't have to chain a follow-
                // up `BACKEND_STAT` round-trip. A later authoritative
                // `getattr` refreshes the cache via the existing
                // stat-issue path if the client needs fresh attrs.
                let ack: Result<u64, crate::vfs_core::error::VfsError> =
                    match super::mutate_rpc::saltyfs_ipc_child_reply_parse(reply_msg) {
                        Ok(new_ino) => Ok(new_ino),
                        Err(label) => Err(super::vops::trona_to_vfs_error(label)),
                    };

                let new_vh = if let Ok(new_ino) = ack {
                    // Resolve parent mount handle via
                    // `FsInstanceId → MountHandle`, not via the
                    // resolve cache. The 128-slot direct-mapped
                    // resolve cache may have evicted the parent's
                    // entry by the time this completion lands (cache
                    // collision, unrelated lookup of a different
                    // vkey that hashes to the same slot, etc.).
                    // Falling back to `MountHandle::INVALID` would
                    // force `alloc_saltyfs_vnode_from_state` to
                    // surface `TRONA_OUT_OF_MEMORY` for an op the
                    // backend already committed — the client would
                    // see failure then get `EEXIST` on retry. The
                    // `backend_sessions` table keyed by `fs_id` is
                    // authoritative for mount identity and survives
                    // resolve-cache churn.
                    let mount_handle = state
                        .mount_by_fs_instance_id(parent_vkey.fs_instance_id)
                        .unwrap_or(crate::vfs_core::mount::MountHandle::INVALID);
                    let parent_ino = kind_hint_parent_ino(kind);
                    let (synth_mode, synth_size, synth_nlink, synth_dir_type) = match kind_hint {
                        FinalOpKind::Create => (
                            open_request
                                .map(|req| req.create_mode | 0o100000)
                                .unwrap_or(0o100000),
                            0u64,
                            1u32,
                            0u8,
                        ),
                        FinalOpKind::Mkdir => {
                            let mode = if let SaltyfsOpKind::Mkdir { mode, .. } = kind {
                                mode | 0o040000
                            } else {
                                0o040755
                            };
                            (mode, 0u64, 2u32, 4u8)
                        }
                        FinalOpKind::Symlink => {
                            let target_len = if let SaltyfsOpKind::Symlink { target_len, .. } = kind
                            {
                                target_len as u64
                            } else {
                                0
                            };
                            (0o120777u32, target_len, 1u32, 10u8)
                        }
                        _ => (0u32, 0u64, 0u32, 0u8),
                    };
                    match super::vops::alloc_saltyfs_vnode_from_state(
                        state,
                        mount_handle,
                        parent_ino,
                        new_ino,
                        0, // remote_seq: freshly-allocated inode starts at 0
                        synth_mode,
                        synth_size,
                        synth_nlink,
                        0, // mtime: leave 0 until next getattr refreshes
                        creds_uid,
                        creds_gid,
                        synth_dir_type,
                        0, // blocks
                    ) {
                        Ok(vh) => Some(vh),
                        Err(_) => None,
                    }
                } else {
                    None
                };

                // Release credit before emitting the reply — drain
                // hook runs and a parked waiter promotes onto the
                // freed slot in parallel with the reply send.
                state.backend_credit_release(fs_id);

                crate::fileops::mutate::resume_fill_final_op_child_reply(
                    state,
                    client,
                    parent_vkey,
                    kind_hint,
                    reply_slot,
                    reply_msg,
                    new_vh,
                    open_request,
                    ack.err(),
                );
            }
            FsResume::FinalOpAckRemoval {
                client: _,
                parent_vkey,
                removed_child_vkey,
                kind: _,
            } => {
                if reply_msg.label == TRONA_OK {
                    if removed_child_vkey.is_valid() {
                        state.invalidate_resolve_cache_for(removed_child_vkey);
                    }
                    state.invalidate_parent_dir_caches(parent_vkey);
                }
                state.backend_credit_release(fs_id);
                crate::fileops::mutate::resume_fill_final_op_ack_reply(
                    state, reply_slot, reply_msg,
                );
            }
            FsResume::FinalOpAckRename {
                client: _,
                new_parent_vkey,
                old_parent_vkey,
            } => {
                if reply_msg.label == TRONA_OK {
                    state.invalidate_parent_dir_caches(new_parent_vkey);
                    if old_parent_vkey != new_parent_vkey && old_parent_vkey.is_valid() {
                        state.invalidate_parent_dir_caches(old_parent_vkey);
                    }
                }
                state.backend_credit_release(fs_id);
                crate::fileops::mutate::resume_fill_final_op_ack_reply(
                    state, reply_slot, reply_msg,
                );
            }
            FsResume::FinalOpAckLink {
                client: _,
                new_parent_vkey,
            } => {
                if reply_msg.label == TRONA_OK {
                    state.invalidate_parent_dir_caches(new_parent_vkey);
                }
                state.backend_credit_release(fs_id);
                crate::fileops::mutate::resume_fill_final_op_ack_reply(
                    state, reply_slot, reply_msg,
                );
            }
            FsResume::FinalOpAckTruncate {
                client,
                file_vkey,
                fd,
                old_size,
            } => {
                if reply_msg.label == TRONA_OK {
                    if let SaltyfsOpKind::Truncate { new_size, .. } = kind {
                        // Refresh the cached `size` on the backend's
                        // vdata pool so the next `getattr` / stat
                        // sees the post-truncate size without a
                        // follow-up stat RPC.
                        if let Some(vh) = state.lookup_resolve_cache(file_vkey) {
                            if let Some(vn) = state.vnodes.get(vh) {
                                let vd = vn.data as *mut super::types::SaltyfsVnodeData;
                                if !vd.is_null() {
                                    (*vd).size = new_size;
                                }
                            }
                        }
                        // Notify mmsrv to update mmap'd region length.
                        if fd >= 0 {
                            if let Some(obj) = state.open_object_at(client, fd as usize) {
                                crate::backend::notify_mmsrv_mmap_truncate(
                                    state, obj, old_size, new_size,
                                );
                            }
                        }
                    }
                }
                state.backend_credit_release(fs_id);
                crate::fileops::mutate::resume_fill_final_op_ack_reply(
                    state, reply_slot, reply_msg,
                );
            }
            FsResume::NameiStep {
                client,
                cursor,
                phase,
                terminal,
            } => {
                // Backend boundary: parse SaltyFS wire state here and
                // hand only generic outcomes back to the async walker.
                match phase {
                    crate::owner::pending::WalkPhase::Lookup => {
                        let lookup =
                            materialize_namei_lookup_result(state, &cursor, kind, reply_msg);
                        crate::vfs_core::namei_async::resume_namei_after_lookup(
                            state, client, cursor, terminal, reply_slot, lookup,
                        );
                    }
                    crate::owner::pending::WalkPhase::Readlink => {
                        let mut target_buf = [0u8; WALK_SYMLINK_TARGET_MAX];
                        let parsed = match super::saltyfs_ipc_readlink_parse(reply_msg) {
                            Some((target, len)) => {
                                let copy = len.min(WALK_SYMLINK_TARGET_MAX);
                                for i in 0..copy {
                                    target_buf[i] = target[i];
                                }
                                Ok(&target_buf[..copy])
                            }
                            None => Err(VfsError::Io),
                        };
                        crate::vfs_core::namei_async::resume_namei_after_readlink(
                            state, client, cursor, terminal, reply_slot, parsed,
                        );
                    }
                    crate::owner::pending::WalkPhase::CrossMountVget => {
                        let root_vh =
                            materialize_namei_cross_mount_root(state, &cursor, kind, reply_msg);
                        crate::vfs_core::namei_async::resume_namei_after_cross_mount_vget(
                            state, client, cursor, terminal, reply_slot, root_vh,
                        );
                    }
                    crate::owner::pending::WalkPhase::FinalOp => {
                        let ack = validate_namei_final_op(kind, reply_msg);
                        crate::vfs_core::namei_async::resume_namei_after_final_op(
                            state, client, cursor, terminal, reply_slot, ack,
                        );
                    }
                }
            }
            FsResume::MountReady {
                client,
                mount_token,
            } => {
                let _ = client;
                let _ = mount_token;
                let (mh, fs_cap) = match kind {
                    SaltyfsOpKind::OpenSession { mh, fs_cap } => (mh, fs_cap),
                    _ => {
                        trona_runtime::uwarn!(|_lb| {
                            _lb.str(b"[VFS] MountReady with non-OpenSession op_kind\n");
                        });
                        state.release_saved_reply_slot(reply_slot);
                        return;
                    }
                };
                let finalize_result =
                    super::vfsops::saltyfs_mount_finalize(state, mh, fs_cap, reply_msg);
                // Complete the VFS-side tail of the mount (root pin,
                // covering link) and emit the VFS_MOUNT ack to the
                // original caller. Failure on either stage triggers a
                // full teardown so the mount slot + backend session +
                // mount-data allocation do not leak.
                let mut out = TronaMsg::zeroed();
                match finalize_result {
                    Ok(()) => {
                        // Identity-based target resolution. `covered`'s
                        // `handle_hint` can be stale if the target
                        // vnode's arena slot was recycled during the
                        // park; the authoritative `VnodeKey` survives,
                        // and `lookup_resolve_cache` walks forward to
                        // whichever handle now hosts that key.
                        let (target_key, fs_id_local) = state
                            .mounts
                            .get(mh)
                            .map(|m| (m.covered.id(), m.fs_instance_id))
                            .unwrap_or((
                                crate::vfs_core::identity::VnodeKey::INVALID,
                                crate::vfs_core::identity::FsInstanceId::INVALID,
                            ));
                        let target_vh = if target_key.is_valid() {
                            state
                                .lookup_resolve_cache(target_key)
                                .unwrap_or(crate::vfs_core::vnode::VnodeHandle::INVALID)
                        } else {
                            crate::vfs_core::vnode::VnodeHandle::INVALID
                        };
                        if let Err(e) = crate::vfs_core::mount_ctl::finalize_mount_tail(
                            state,
                            mh,
                            target_vh,
                            fs_id_local,
                        ) {
                            super::vfsops::saltyfs_mount_teardown(state, mh);
                            out.label = e.to_trona();
                        } else {
                            out.label = TRONA_OK;
                            crate::vfs_core::mount_ctl::refresh_global_ns(state);
                        }
                    }
                    Err(e) => {
                        super::vfsops::saltyfs_mount_teardown(state, mh);
                        out.label = e.to_trona();
                    }
                }
                state.send_saved_reply(reply_slot, &raw const out);
            }
            FsResume::LatePivot { dir_index, op } => match op {
                LatePivotOp::Lookup => {
                    let lookup_result = match kind {
                        SaltyfsOpKind::Lookup { parent_ino, .. } => {
                            match super::rpc::saltyfs_ipc_lookup_parse(reply_msg) {
                                Ok(Some((
                                    child_ino,
                                    child_seq,
                                    mode,
                                    size,
                                    nlink,
                                    mtime,
                                    uid,
                                    gid,
                                    dir_type,
                                    blocks,
                                ))) => {
                                    let mount_handle = state
                                        .mount_by_fs_instance_id(fs_id)
                                        .unwrap_or(crate::vfs_core::mount::MountHandle::INVALID);
                                    match super::vops::alloc_saltyfs_vnode_from_state(
                                        state,
                                        mount_handle,
                                        parent_ino,
                                        child_ino,
                                        child_seq,
                                        mode,
                                        size,
                                        nlink,
                                        mtime,
                                        uid,
                                        gid,
                                        dir_type,
                                        blocks,
                                    ) {
                                        Ok(vh) => Ok(Some(vh)),
                                        Err(e) => Err(e),
                                    }
                                }
                                Ok(None) => Ok(None),
                                Err(e) => Err(e),
                            }
                        }
                        _ => Err(VfsError::Io),
                    };
                    crate::boot::late_mount::resume_deferred_pivot_lookup(
                        state,
                        dir_index,
                        lookup_result,
                    );
                }
                LatePivotOp::Mkdir => {
                    let mkdir_result = match kind {
                        SaltyfsOpKind::Mkdir {
                            parent_ino,
                            mode,
                            uid,
                            gid,
                            ..
                        } => match super::mutate_rpc::saltyfs_ipc_child_reply_parse(reply_msg) {
                            Ok(new_ino) => {
                                let mount_handle = state
                                    .mount_by_fs_instance_id(fs_id)
                                    .unwrap_or(crate::vfs_core::mount::MountHandle::INVALID);
                                match super::vops::alloc_saltyfs_vnode_from_state(
                                    state,
                                    mount_handle,
                                    parent_ino,
                                    new_ino,
                                    0,
                                    mode,
                                    0,
                                    2,
                                    0,
                                    uid,
                                    gid,
                                    4,
                                    0,
                                ) {
                                    Ok(vh) => Ok(vh),
                                    Err(e) => Err(e),
                                }
                            }
                            Err(label) => Err(super::vops::trona_to_vfs_error(label)),
                        },
                        _ => Err(VfsError::Io),
                    };
                    state.backend_credit_release(fs_id);
                    crate::boot::late_mount::resume_deferred_pivot_mkdir(
                        state,
                        dir_index,
                        mkdir_result,
                    );
                }
            },
        }
    }
}

/// Inline-reply value capacity (`31 * 8`). Matches the shape of every
/// fileops xattr/listxattr reply path.
const VAL_INLINE_CAP: usize = 31 * 8;

/// Drop xattr SHM ownership for the op identified by `tx_id`. The
/// caller is responsible for invoking [`backend_credit_release`]
/// afterwards — credit release triggers the session's drain hook,
/// and we don't want two drains stacked on the same completion.
/// No-op when the mount is torn down between park and completion
/// (the [`release_xattr_shm_if_owner`] helper is a conditional
/// write).
#[inline]
unsafe fn release_xattr_shm_only(
    state: &mut crate::owner::VfsState,
    fs_id: FsInstanceId,
    tx_id: TxId,
) {
    unsafe {
        if let Some(mh) = state.mount_by_fs_instance_id(fs_id) {
            if let Some(mount) = state.mounts.get(mh) {
                let md = mount.data as *mut SaltyfsMountData;
                if !md.is_null() {
                    super::deferred::release_xattr_shm_if_owner(md, tx_id);
                }
            }
        }
    }
}

unsafe fn materialize_namei_lookup_result(
    state: &mut crate::owner::VfsState,
    cursor: &crate::owner::pending::WalkCursor,
    kind: SaltyfsOpKind,
    reply: &TronaMsg,
) -> crate::vfs_core::error::VfsResult<Option<crate::vfs_core::vnode::VnodeHandle>> {
    let (parent_ino, name, name_len) = match kind {
        SaltyfsOpKind::Lookup {
            parent_ino,
            name,
            name_len,
        } => (parent_ino, name, name_len),
        _ => return Err(VfsError::Io),
    };
    let parsed = super::saltyfs_ipc_lookup_parse(reply)?;
    let Some((child_ino, child_seq, mode, size, nlink, mtime, uid, gid, dir_type, blocks)) = parsed
    else {
        return Ok(None);
    };
    let parent_vh =
        crate::vfs_core::namei_async::resolve_cursor_cwd(state, cursor).ok_or(VfsError::Io)?;
    let parent_mh = state.resolve_vnode_mount(parent_vh).ok_or(VfsError::Io)?;
    let cached_parent_ino = if name_len == 2 && name[0] == b'.' && name[1] == b'.' {
        0
    } else {
        parent_ino
    };
    let child_vh = super::vops::alloc_saltyfs_vnode_from_state(
        state,
        parent_mh,
        cached_parent_ino,
        child_ino,
        child_seq,
        mode,
        size,
        nlink,
        mtime,
        uid,
        gid,
        dir_type,
        blocks,
    )?;
    Ok(Some(child_vh))
}

unsafe fn materialize_namei_cross_mount_root(
    state: &mut crate::owner::VfsState,
    cursor: &crate::owner::pending::WalkCursor,
    kind: SaltyfsOpKind,
    reply: &TronaMsg,
) -> crate::vfs_core::error::VfsResult<crate::vfs_core::vnode::VnodeHandle> {
    let ino_hint = match kind {
        SaltyfsOpKind::Stat { ino } => ino,
        SaltyfsOpKind::Lookup { parent_ino, .. } => parent_ino,
        _ => return Err(VfsError::Io),
    };
    let (_size, _mode, _nlink, _mtime, _blocks, _uid, _gid, seq) =
        super::parse_stat_reply(reply).ok_or(VfsError::Io)?;
    let ino_reply = reply.regs[0];
    let fs_id = cursor.cwd_vkey.fs_instance_id;
    let mh = state
        .mount_by_fs_instance_id(fs_id)
        .ok_or(VfsError::Stale)?;
    let mount_ptr = state.mounts.raw_ptr(mh).ok_or(VfsError::Io)?;
    let vfsops = unsafe { (*mount_ptr).vfsops };
    if vfsops.is_null() {
        return Err(VfsError::Io);
    }
    let mut mctx =
        crate::vfs_core::vop_context::OwnerMountCtx::from_state(state, mh).ok_or(VfsError::Io)?;
    let effective_ino = if ino_reply != 0 { ino_reply } else { ino_hint };
    let root_vh = match unsafe { ((*vfsops).vget)(&mut mctx, effective_ino) } {
        Ok(h) => h,
        Err(e) => return Err(e),
    };
    if !root_vh.is_valid() {
        return Err(VfsError::Io);
    }
    if let Some(root_vp) = state.vnodes.raw_ptr(root_vh) {
        unsafe {
            (*root_vp).backend_seq = seq;
        }
    }
    Ok(root_vh)
}

fn validate_namei_final_op(
    kind: SaltyfsOpKind,
    reply: &TronaMsg,
) -> crate::vfs_core::error::VfsResult<()> {
    match kind {
        SaltyfsOpKind::Stat { .. } => {
            let _ = super::parse_stat_reply(reply).ok_or(VfsError::Io)?;
            Ok(())
        }
        _ => Err(VfsError::Io),
    }
}

/// Extract the parent directory's ino from a compound-mutation
/// `SaltyfsOpKind`. Used by the `FinalOpChild` resume path to seed
/// the freshly-materialised child's cached `parent_ino` for dot-dot
/// resolution. Returns `0` for op kinds that do not produce a
/// child (defensive — only `Create` / `Mkdir` / `Symlink` should
/// reach this resume arm).
#[inline]
fn kind_hint_parent_ino(kind: SaltyfsOpKind) -> u64 {
    match kind {
        SaltyfsOpKind::Create { parent_ino, .. }
        | SaltyfsOpKind::Mkdir { parent_ino, .. }
        | SaltyfsOpKind::Symlink { parent_ino, .. } => parent_ino,
        _ => 0,
    }
}

/// Apply a post-commit attribute snapshot to the cached
/// `SaltyfsVnodeData` for the given key so subsequent stat calls
/// observe the mutation without a fresh `BACKEND_STAT`. No-op when
/// the vnode has been reclaimed between park and completion (the
/// next access will re-materialise via `vget`).
unsafe fn apply_attr_snapshot(
    state: &mut crate::owner::VfsState,
    vkey: crate::vfs_core::identity::VnodeKey,
    attr: &VAttr,
) {
    unsafe {
        let Some(vh) = state.lookup_resolve_cache(vkey) else {
            return;
        };
        let Some(vn) = state.vnodes.get(vh) else {
            return;
        };
        let vd = vn.data as *mut super::types::SaltyfsVnodeData;
        if vd.is_null() {
            return;
        }
        (*vd).mode = attr.mode;
        (*vd).uid = attr.uid;
        (*vd).gid = attr.gid;
        (*vd).size = attr.size;
        (*vd).nlink = attr.nlink;
        (*vd).mtime = attr.mtime;
    }
}

/// Parse a `BACKEND_STAT` completion into [`VAttr`]. Returns `None`
/// on a malformed or error reply. Any sanity failure of the returned
/// attribute record — e.g. an `S_IFMT` bit pattern outside the POSIX
/// catalogue, or a zeroed `mode` that violates saltyfs's
/// "allocated inode carries a type" invariant — raises an
/// [`IntegrityFailure`](VfsError::IntegrityFailure) audit entry,
/// scoped by the owning mount's identity, and drops the reply as if
/// it were malformed. The caller sees the same `None` result in
/// either case; the audit log gives operators a distinguishable
/// trail.
#[inline]
fn parse_stat_attr(reply: &TronaMsg, fs: FsInstanceId) -> Option<VAttr> {
    let (size, mode, nlink, mtime, blocks, uid, gid, _seq) =
        super::rpc::saltyfs_ipc_stat_parse(reply)?;
    // Validate the S_IFMT file-type field. Anything outside the
    // POSIX catalogue means the backend either returned an
    // uninitialised inode or the on-disk structure diverged from the
    // type-byte invariant.
    const S_IFMT: u32 = 0o170000;
    let ftype = mode & S_IFMT;
    let valid_ftype = matches!(
        ftype,
        0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000,
    );
    if mode == 0 || !valid_ftype {
        let err = VfsError::IntegrityFailure {
            fs,
            detail: IntegrityDetail::Inode,
        };
        err.audit_log();
        return None;
    }
    let mut attr = VAttr::zeroed();
    attr.size = size;
    attr.blocks = blocks;
    attr.mode = mode;
    attr.uid = uid;
    attr.gid = gid;
    attr.nlink = nlink;
    attr.mtime = mtime;
    Some(attr)
}
