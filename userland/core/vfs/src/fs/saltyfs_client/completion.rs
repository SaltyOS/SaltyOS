// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyFS completion router.
//!
//! Registered on every mounted saltyfs session's
//! [`BackendSessionSlot::completion_fn`]; invoked by
//! `crate::owner::pending::dispatch_pending_reply` once the generic
//! session-gate / stale-mount checks have passed.
//!
//! Responsibilities:
//! 1. Unpack [`PendingKindPayload`] into the saltyfs-private
//!    [`SaltyfsOpKind`].
//! 2. Parse the backend reply (`BACKEND_STAT` / `BACKEND_READ` /
//!    `BACKEND_READDIR` / `BACKEND_READLINK` / `BACKEND_GETXATTR` /
//!    `BACKEND_LISTXATTR`).
//! 3. Read SHM-resident payload through the per-mount-instance ring
//!    *before* releasing inflight credit, so a racing drain hook
//!    cannot fire a new request that stomps the ring slot we are
//!    about to copy from. There is no inline-regs branch — every
//!    bulk reply rides through SHM uniformly.
//! 4. Release one inflight credit against the owning session.
//! 5. Invoke the matching personality reply dispatcher with
//!    fully-parsed generic args so backend parsing stays here.
//!
//! The generic resume helpers must not reach into this
//! module or touch `SaltyfsOpKind` / `SaltyfsMountData`. If you find
//! yourself doing so, add the missing piece of pre-parsed generic
//! data as a new parameter on the helper instead.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::{
    IntegrityDetail, VfsError, VfsResult, audit_data_corrupt, audit_integrity_failure,
};
use crate::core::file::VAttr;
use crate::core::identity::{FsInstanceId, VnodeKey};
use crate::core::vop::IoctlReply;
use crate::ipc::protocol::backend::VFS_BACKEND_REPLY_OK;
use crate::owner::VfsState;
use crate::owner::pending::{PendingKindPayload, TxId, WALK_SYMLINK_TARGET_MAX};
use crate::owner::resume::{
    FinalOpKind, FinalOpRemovalKind, FsResume, LatePivotOp, PAGERRESUME_OP_READ,
    PAGERRESUME_OP_WRITEBACK, PagerResume, Resume,
};
use trona_protocol::common::TRONA_IO_ERROR;
use trona_server::ReplyLease;

use super::op_kind::SaltyfsOpKind;
use super::types::SaltyfsMountData;

/// Inline-reply value capacity for xattr / listxattr completions
/// (`31 * 8` bytes — 31 reply regs × 8 bytes per reg, with the
/// register layout matching every xattr reply path).
const VAL_INLINE_CAP: usize = 31 * 8;

/// Read-only snapshot of the VFS↔saltyfs SHM base pointer for the
/// given `fs_id`. Reads are taken before credit release so a
/// concurrent drain cannot overwrite the region between parse and
/// copy. Returns `None` when the mount is gone, the mount data is
/// detached, or no SHM has been negotiated for the session.
#[inline]
unsafe fn shm_base_for(state: &VfsState, fs_id: FsInstanceId) -> Option<*const u8> {
    unsafe {
        let mount_h = state.mount_by_fs_instance_id(fs_id)?;
        let mount = state.mounts.get(mount_h)?;
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

/// Update the fd cursor after a backend-positioned read completes.
///
/// The completion router owns this because it has the authoritative
/// backend byte count and must advance the OpenObject before the
/// next client request can issue against the same fd.
fn advance_fd_offset(
    state: &mut VfsState,
    client: crate::server::types::ClientHandle,
    fd: i32,
    new_offset: u64,
) {
    if fd < 0 {
        return;
    }
    let Some(cli) = state.clients.get(client) else {
        return;
    };
    let Some(open_h) = cli.slot_table.lookup(fd as u32) else {
        return;
    };
    if let Some(obj) = state.open_objects.get_mut(open_h) {
        obj.offset = new_offset;
    }
}

#[inline]
fn client_accepts_completion(state: &VfsState, client: crate::server::types::ClientHandle) -> bool {
    state
        .clients
        .get(client)
        .map(|c| c.is_active())
        .unwrap_or(false)
}

/// Copy a completed backend SHM read into the caller's registered
/// bulk SHM region. Returns the byte count visible to the client.
unsafe fn copy_bulk_read_to_client(
    state: &mut VfsState,
    client: crate::server::types::ClientHandle,
    client_shm_offset: u64,
    client_shm_len: u64,
    bytes_read: u64,
    shm_src: *const u8,
) -> u64 {
    let region_h = state
        .clients
        .get(client)
        .map(|c| c.bulk_shm)
        .unwrap_or(crate::owner::client_shm::ClientShmHandle::INVALID);
    // `ClientShmRegion` owns a cap (non-Copy); borrow it for the slice
    // (the returned pointer does not extend the borrow).
    let region = match state.client_shm_regions.get(region_h) {
        Some(r) if !r.is_empty() && r.owner_client == client => r,
        _ => return 0,
    };
    let actual = bytes_read.min(client_shm_len);
    if actual > 0 && !shm_src.is_null() {
        let Some(dst) =
            crate::owner::client_shm::slice_in_region(region, client_shm_offset, actual)
        else {
            return 0;
        };
        unsafe { ::core::ptr::copy_nonoverlapping(shm_src, dst, actual as usize) };
    }
    actual
}

/// SaltyFS-side completion dispatcher. Registered on every saltyfs
/// `BackendSessionSlot::completion_fn` via `saltyfs_mount`.
pub(crate) unsafe fn saltyfs_completion(
    state: &mut VfsState,
    fs_id: FsInstanceId,
    tx_id: TxId,
    kind_payload: &PendingKindPayload,
    resume_ctx: Resume,
    _backend_session_idx: u32,
    reply_lease: Option<ReplyLease>,
    reply_msg: &TronaMsg,
    personality: crate::personality::Personality,
) {
    unsafe {
        let kind = SaltyfsOpKind::unpack(kind_payload);
        if !kind.validate_completion_envelope() {
            audit_integrity_failure(fs_id, IntegrityDetail::Malformed);
            if let Some(lease) = reply_lease {
                crate::owner::op::reply_drop(lease);
            }
            state.backend_credit_release(fs_id);
            return;
        }

        // saltyfs is the backend for both filesystem RPCs (the
        // `Resume::Fs(_)` family) and the pager-supply path
        // (`Resume::Pager(_)`). Pager completions are kernel-emit
        // events with no client lease — `reply_lease` may legally
        // be `None` on that arm. Every other Resume requires a
        // live lease; absence drains the backend credit and exits.
        let fs_resume = match resume_ctx {
            Resume::Pager(pager) => {
                handle_pager_completion(state, fs_id, pager, reply_lease, reply_msg);
                return;
            }
            Resume::Fs(fs_resume) => fs_resume,
            Resume::Placeholder
            | Resume::Net(_)
            | Resume::Pty(_)
            | Resume::Fb(_)
            | Resume::Poll(_)
            | Resume::Init(_) => {
                // `Resume::Init` is driven by `init_rpc::init_reply_complete`
                // on the `KIND_INIT_REPLY` channel, never a backend-session
                // completion — landing here is a stamping bug, so drop the
                // lease and release the credit like the other domains.
                if let Some(lease) = reply_lease {
                    crate::owner::op::reply_drop(lease);
                }
                state.backend_credit_release(fs_id);
                return;
            }
        };
        if let FsResume::DeleteOnClose {
            parent_vkey,
            removed_child_vkey,
            kind,
        } = fs_resume
        {
            if reply_msg.label == VFS_BACKEND_REPLY_OK {
                if removed_child_vkey.is_valid() {
                    state.invalidate_resolve_cache_for(removed_child_vkey);
                    if matches!(kind, FinalOpRemovalKind::Rmdir) {
                        state.invalidate_parent_dir_caches(removed_child_vkey);
                    }
                }
                state.invalidate_parent_dir_caches(parent_vkey);
            }
            if let Some(lease) = reply_lease {
                crate::owner::op::reply_drop(lease);
            }
            state.backend_credit_release(fs_id);
            return;
        }
        if let FsResume::LatePivot { dir_index, op } = fs_resume {
            match op {
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
                                        .unwrap_or(crate::core::mount::MountHandle::INVALID);
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
                                        Ok(vnode_h) => Ok(Some(vnode_h)),
                                        Err(e) => Err(e),
                                    }
                                }
                                Ok(None) => Ok(None),
                                Err(e) => Err(e),
                            }
                        }
                        _ => Err(VfsError::Io),
                    };
                    if let Some(lease) = reply_lease {
                        crate::owner::op::reply_drop(lease);
                    }
                    state.backend_credit_release(fs_id);
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
                                    .unwrap_or(crate::core::mount::MountHandle::INVALID);
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
                                    Ok(vnode_h) => Ok(vnode_h),
                                    Err(e) => Err(e),
                                }
                            }
                            Err(label) => Err(VfsError::from_backend_reply(label)),
                        },
                        _ => Err(VfsError::Io),
                    };
                    if let Some(lease) = reply_lease {
                        crate::owner::op::reply_drop(lease);
                    }
                    state.backend_credit_release(fs_id);
                    crate::boot::late_mount::resume_deferred_pivot_mkdir(
                        state,
                        dir_index,
                        mkdir_result,
                    );
                }
            }
            return;
        }
        if reply_lease.is_none() {
            state.backend_credit_release(fs_id);
            return;
        }
        let reply_lease = reply_lease.expect("Resume::Fs branch ensures Some above");

        match fs_resume {
            // The controlling-tty binding dump only ever completes on the
            // pty backend (`pty_completion`); it can never reach the
            // saltyfs completion router. Handle defensively: release the
            // credit and drop the (misrouted) lease.
            FsResume::CttyDump { .. } => {
                state.backend_credit_release(fs_id);
                crate::owner::op::reply_drop(reply_lease);
            }
            FsResume::FillOpenReply {
                client,
                vkey,
                anchor,
                spec,
                reply,
            } => {
                let result =
                    backend_ack_result(reply_msg).and_then(|()| resolve_vkey_handle(state, vkey));
                state.backend_credit_release(fs_id);
                match result {
                    Ok(vnode_h) => crate::ops::open::finish_open_resolved_leaf_with_anchor(
                        state,
                        client,
                        vnode_h,
                        anchor,
                        spec,
                        crate::ops::open::pick_open_action(
                            spec.create,
                            /* leaf_was_missing = */ false,
                        ),
                        reply,
                        reply_lease,
                    ),
                    Err(e) => {
                        crate::personality::reply::emit_open(reply_lease, reply, Err(e));
                    }
                }
            }
            FsResume::FillNtAclOpenReply {
                client,
                vkey,
                anchor,
                spec,
                reply,
                desired_access,
            } => {
                if !client_accepts_completion(state, client) {
                    release_xattr_shm_only(state, fs_id, tx_id);
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }

                let mut acl_buf = [0u8; crate::ops::open::NT_ACL_LOOKUP_MAX];
                let acl_lookup: VfsResult<&[u8]> = if reply_msg.label != VFS_BACKEND_REPLY_OK {
                    Err(VfsError::from_backend_reply(reply_msg.label))
                } else {
                    match super::saltyfs_ipc_xattr_get_parse(reply_msg) {
                        Some(0) => Ok(&acl_buf[..0]),
                        Some(n) if n > acl_buf.len() => Err(VfsError::Range),
                        Some(n) => match shm_base_for(state, fs_id) {
                            Some(src) => {
                                for i in 0..n {
                                    acl_buf[i] = *src.add(i);
                                }
                                Ok(&acl_buf[..n])
                            }
                            None => Err(VfsError::Io),
                        },
                        None => Err(VfsError::Io),
                    }
                };

                release_xattr_shm_only(state, fs_id, tx_id);
                state.backend_credit_release(fs_id);
                crate::ops::open::resume_open_after_nt_acl_lookup(
                    state,
                    client,
                    vkey,
                    anchor,
                    spec,
                    reply,
                    desired_access,
                    acl_lookup,
                    reply_lease,
                );
            }
            FsResume::FillGetAttrReply {
                client,
                vkey,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                let attr =
                    backend_attr_result(reply_msg, vkey.fs_instance_id).and_then(|mut attr| {
                        decorate_attr_from_vkey(state, vkey, &mut attr)?;
                        Ok(attr)
                    });
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_attr(reply_lease, reply, attr);
            }
            FsResume::FillSetAttrReply {
                client,
                vkey,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                let ack = parse_setattr_completion(state, vkey, reply_msg);
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_ack(reply_lease, reply, 0, ack);
            }
            FsResume::FillReadlinkReply { client, vkey } => {
                let _ = (client, vkey);
                let parsed = super::saltyfs_ipc_readlink_parse(reply_msg);
                let payload = parsed.map(|(buf, len)| (buf, len.min(WALK_SYMLINK_TARGET_MAX)));
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_readlink_bytes(
                    reply_lease,
                    personality,
                    payload
                        .as_ref()
                        .map(|(buf, len)| &buf[..*len])
                        .ok_or(VfsError::Io),
                );
            }
            FsResume::FillAccessReply {
                client,
                vkey,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                if vkey.is_valid() && resolve_vkey_handle(state, vkey).is_err() {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                // Terminal access / exec-preflight acks share
                // the same backend contract: wire parsing is just
                // success / failure translation.
                let ack = backend_ack_result(reply_msg);
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_ack(reply_lease, reply, 0, ack);
            }
            FsResume::FillStatForExecAccessReply { client, vkey } => {
                let ack = backend_ack_result(reply_msg);
                state.backend_credit_release(fs_id);
                crate::personality::namei_terminal::resume_stat_for_exec_access_reply(
                    state,
                    client,
                    vkey,
                    reply_lease,
                    ack,
                    personality,
                );
            }
            FsResume::FillOpenForExecAccessReply { client, vkey } => {
                let ack = backend_ack_result(reply_msg);
                state.backend_credit_release(fs_id);
                crate::personality::namei_terminal::resume_open_for_exec_access_reply(
                    state,
                    client,
                    vkey,
                    reply_lease,
                    ack,
                    personality,
                );
            }
            FsResume::FillStatForExecAttrReply { client, vkey } => {
                let attr =
                    backend_attr_result(reply_msg, vkey.fs_instance_id).and_then(|mut attr| {
                        decorate_attr_from_vkey(state, vkey, &mut attr)?;
                        Ok(attr)
                    });
                state.backend_credit_release(fs_id);
                crate::personality::namei_terminal::resume_stat_for_exec_attr_reply(
                    state,
                    client,
                    vkey,
                    reply_lease,
                    attr,
                    personality,
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
                release_xattr_shm_only(state, fs_id, tx_id);
                state.backend_credit_release(fs_id);
                let _ = (client, vkey);
                crate::personality::reply::emit_xattr_get(
                    reply_lease,
                    personality,
                    value_slice
                        .map(|(val_len, copy)| (val_len, &buf[..copy]))
                        .ok_or(VfsError::NoEnt),
                );
            }
            FsResume::FillNtSecurityQueryReply {
                client,
                vkey,
                fs_id: rfs_id,
            } => {
                if !client_accepts_completion(state, client) {
                    release_xattr_shm_only(state, fs_id, tx_id);
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                if vkey.is_valid() && resolve_vkey_handle(state, vkey).is_err() {
                    release_xattr_shm_only(state, fs_id, tx_id);
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                let payload = if reply_msg.label == VFS_BACKEND_REPLY_OK {
                    let parsed = super::saltyfs_ipc_xattr_get_parse(reply_msg);
                    let shm = shm_base_for(state, rfs_id);
                    let mut buf = [0u8; VAL_INLINE_CAP];
                    match (parsed, shm) {
                        (Some(val_len), Some(src)) if val_len > 0 => {
                            let copy = val_len.min(VAL_INLINE_CAP);
                            for i in 0..copy {
                                buf[i] = *src.add(i);
                            }
                            Some(Ok((val_len, copy, buf)))
                        }
                        (Some(val_len), _) => Some(Ok((val_len, 0, buf))),
                        (None, _) => Some(Err(VfsError::Io)),
                    }
                } else {
                    let e = VfsError::from_backend_reply(reply_msg.label);
                    if e == VfsError::NoEnt {
                        Some(Ok((0, 0, [0u8; VAL_INLINE_CAP])))
                    } else {
                        Some(Err(e))
                    }
                };
                release_xattr_shm_only(state, fs_id, tx_id);
                state.backend_credit_release(fs_id);
                match payload.unwrap_or(Err(VfsError::Io)) {
                    Ok((val_len, copy, buf)) => crate::personality::reply::emit_xattr_get(
                        reply_lease,
                        crate::personality::Personality::Win32,
                        Ok((val_len, &buf[..copy])),
                    ),
                    Err(e) => crate::personality::reply::emit_xattr_get(
                        reply_lease,
                        crate::personality::Personality::Win32,
                        Err(e),
                    ),
                }
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
                let _ = (client, vkey);
                crate::personality::reply::emit_xattr_list(
                    reply_lease,
                    personality,
                    copy_result
                        .map(|(bytes_needed, copy)| (bytes_needed, &buf[..copy]))
                        .ok_or(VfsError::Io),
                );
            }
            FsResume::BulkReadStage {
                client,
                vkey,
                fs_id: rfs_id,
                fd,
                shm_offset,
                reply,
            } => {
                // Recover the transfer descriptor stamped at issue
                // time and the file offset so the audit-log path can
                // pinpoint the offending range.
                let (transfer, read_offset) = match kind {
                    SaltyfsOpKind::Read {
                        transfer,
                        file_offset,
                        ..
                    } => (transfer, file_offset),
                    _ => {
                        crate::owner::op::reply_drop(reply_lease);
                        state.backend_credit_release(fs_id);
                        return;
                    }
                };
                let bytes_read = super::saltyfs_ipc_read_parse(reply_msg);

                // Verify the backend honoured the request envelope.
                // A reply that claims more bytes than the transfer
                // descriptor reserved means either a protocol bug or
                // on-disk extent corruption overrunning its slot.
                // Record as `DataCorrupt` with the offending node +
                // offset so operators can locate the affected inode
                // in the audit log.
                if let Some(n) = bytes_read {
                    if n > transfer.length {
                        audit_data_corrupt(rfs_id, vkey.backend_id, read_offset);
                        state.backend_credit_release(fs_id);
                        crate::owner::op::reply_drop(reply_lease);
                        return;
                    }
                }

                // SHM-only path. The bytes live at
                // `shm_base + transfer.offset` for `bytes_read`
                // bytes; the personality reply layer packs from
                // that pointer directly into the saved reply.
                match (bytes_read, shm_base_for(state, rfs_id)) {
                    (Some(0), _) => {
                        state.backend_credit_release(fs_id);
                        crate::personality::reply::emit_read_inline_payload(
                            reply_lease,
                            reply,
                            0,
                            None,
                        );
                    }
                    (Some(n), Some(base)) => {
                        let src = base.add(transfer.offset as usize);
                        advance_fd_offset(state, client, fd, shm_offset.saturating_add(n));
                        crate::personality::reply::emit_read_inline_from_ptr(
                            reply_lease,
                            reply,
                            n,
                            src,
                        );
                        state.backend_credit_release(fs_id);
                    }
                    _ => {
                        // Backend error or SHM region detached —
                        // surface as a zero-byte reply, preserving
                        // the legacy completion behavior.
                        state.backend_credit_release(fs_id);
                        crate::personality::reply::emit_read_inline_payload(
                            reply_lease,
                            reply,
                            0,
                            None,
                        );
                    }
                }
            }
            FsResume::BulkReadStageShm {
                client,
                vkey,
                fs_id: rfs_id,
                fd,
                client_shm_offset,
                client_shm_len,
                reply,
            } => {
                // Same envelope checks as BulkReadStage, but the
                // helper copies into the caller's bulk SHM region
                // rather than packing the bytes inline.
                let (transfer, read_offset) = match kind {
                    SaltyfsOpKind::Read {
                        transfer,
                        file_offset,
                        ..
                    } => (transfer, file_offset),
                    _ => {
                        crate::owner::op::reply_drop(reply_lease);
                        state.backend_credit_release(fs_id);
                        return;
                    }
                };
                let bytes_read = super::saltyfs_ipc_read_parse(reply_msg);
                if let Some(n) = bytes_read {
                    if n > transfer.length {
                        audit_data_corrupt(rfs_id, vkey.backend_id, read_offset);
                        state.backend_credit_release(fs_id);
                        crate::owner::op::reply_drop(reply_lease);
                        return;
                    }
                }
                match (bytes_read, shm_base_for(state, rfs_id)) {
                    (Some(0), _) => {
                        state.backend_credit_release(fs_id);
                        crate::personality::reply::emit_read_shm(reply_lease, reply, Ok(0));
                    }
                    (Some(n), Some(base)) => {
                        let src = base.add(transfer.offset as usize);
                        let actual = copy_bulk_read_to_client(
                            state,
                            client,
                            client_shm_offset,
                            client_shm_len,
                            n,
                            src,
                        );
                        advance_fd_offset(state, client, fd, read_offset.saturating_add(actual));
                        crate::personality::reply::emit_read_shm(reply_lease, reply, Ok(actual));
                        state.backend_credit_release(fs_id);
                    }
                    _ => {
                        state.backend_credit_release(fs_id);
                        crate::personality::reply::emit_read_shm(reply_lease, reply, Ok(0));
                    }
                }
            }
            FsResume::BulkWriteStage {
                client,
                vkey,
                fs_id: rfs_id,
                fd,
                file_offset,
                requested_len,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                let (transfer, write_offset) = match kind {
                    SaltyfsOpKind::Write {
                        transfer,
                        file_offset,
                        ..
                    } => (transfer, file_offset),
                    _ => {
                        state.backend_credit_release(fs_id);
                        crate::owner::op::reply_drop(reply_lease);
                        return;
                    }
                };
                if transfer.kind == trona_protocol::vfs::backend::TRANSFER_KIND_SHM {
                    let raw_slot = transfer.offset / super::types::SALTYFS_RING_SLOT_BYTES;
                    if let Ok(slot_idx) = u8::try_from(raw_slot) {
                        if let Some(mount_h) = state.mount_by_fs_instance_id(rfs_id) {
                            if let Some(mount) = state.mounts.get(mount_h) {
                                let md = mount.data as *mut SaltyfsMountData;
                                if !md.is_null() {
                                    (*md).ring_free(slot_idx);
                                }
                            }
                        }
                    }
                }
                let result = if reply_msg.label == VFS_BACKEND_REPLY_OK {
                    let n = reply_msg.regs[0].min(transfer.length).min(requested_len);
                    if reply_msg.regs[0] > transfer.length {
                        audit_data_corrupt(rfs_id, vkey.backend_id, write_offset);
                        Err(VfsError::Io)
                    } else {
                        Ok(n)
                    }
                } else {
                    Err(VfsError::from_backend_reply(reply_msg.label))
                };
                if let Ok(n) = result {
                    advance_fd_offset(state, client, fd, file_offset.saturating_add(n));
                }
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_write(reply_lease, reply, result);
            }
            FsResume::BulkReaddirStage {
                client,
                dir_vkey,
                fs_id: rfs_id,
                fd,
                open_handle,
                start_cursor,
                reply,
            } => {
                let parsed = super::saltyfs_ipc_readdir_parse(reply_msg);
                let shm = shm_base_for(state, rfs_id);
                let first_entry = match (parsed, shm) {
                    (Some((next_cursor, entries_written, bytes_written)), Some(base))
                        if entries_written > 0
                            && bytes_written >= super::READDIR_ENTRY_BYTES as u64 =>
                    {
                        // Entry layout: u64 ino @0, u32 mode @32,
                        // u8 d_type @48, u8 name_len @49, name bytes
                        // @52. Layout is fixed per saltyfs ABI; do
                        // not refactor without bumping the ABI tag.
                        let entry_ino = ::core::ptr::read_unaligned(base as *const u64);
                        let entry_mode = ::core::ptr::read_unaligned(base.add(32) as *const u32);
                        let entry_dtype_raw = *base.add(48);
                        let mut name_len = *base.add(49) as usize;
                        if name_len > super::READDIR_NAME_MAX {
                            name_len = super::READDIR_NAME_MAX;
                        }
                        let mut name_buf =
                            [0u8; crate::personality::reply::READDIR_FIRST_ENTRY_NAME_MAX];
                        let name_src = base.add(52);
                        for i in 0..name_len {
                            name_buf[i] = *name_src.add(i);
                        }
                        let d_type = if entry_dtype_raw != 0 {
                            super::readdir_dir_type_to_dtype(entry_dtype_raw, entry_mode)
                        } else {
                            super::readdir_mode_to_dtype(entry_mode)
                        };
                        Some(crate::personality::reply::ReaddirReplyData {
                            next_cursor,
                            entries_written: entries_written as u32,
                            bytes_written: bytes_written as u32,
                            first_entry_ino: entry_ino,
                            first_entry_dtype: d_type,
                            first_entry_name_len: name_len,
                            first_entry_name: name_buf,
                        })
                    }
                    (Some((next_cursor, entries_written, bytes_written)), _) => {
                        // EOF or SHM missing — deliver a zero-entry
                        // reply so the client observes EOF rather
                        // than a hung readdir.
                        Some(crate::personality::reply::ReaddirReplyData {
                            next_cursor,
                            entries_written: entries_written as u32,
                            bytes_written: bytes_written as u32,
                            first_entry_ino: 0,
                            first_entry_dtype: 0,
                            first_entry_name_len: 0,
                            first_entry_name: [0u8;
                                crate::personality::reply::READDIR_FIRST_ENTRY_NAME_MAX],
                        })
                    }
                    (None, _) => None,
                };

                state.backend_credit_release(fs_id);
                if let Some(data) = first_entry {
                    if let Some(obj) = state.open_objects.get_mut(open_handle) {
                        obj.offset = data.next_cursor;
                    }
                }
                let _ = (client, dir_vkey, rfs_id, fd, start_cursor);
                crate::personality::reply::emit_readdir_batch(
                    reply_lease,
                    reply,
                    first_entry.ok_or(VfsError::Io),
                );
            }
            FsResume::FillIoctlReply {
                client,
                vkey,
                cmd: _,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                if vkey.is_valid() && resolve_vkey_handle(state, vkey).is_err() {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                let result = backend_ioctl_result(reply_msg);
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_ioctl(reply_lease, reply, result);
            }
            FsResume::BindCttyOpen { .. } => {
                // The controlling-tty lookup that backs `open("/dev/tty")`
                // is issued only against the pty backend session, so its
                // completion is routed by pty_completion — it cannot reach
                // the saltyfs completion router.
                state.backend_credit_release(fs_id);
                crate::owner::op::reply_drop(reply_lease);
            }
            FsResume::AckMutation {
                client,
                vkey,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                // Map completion to either Ok(()) (backend-applied)
                // or Err(VfsError). For `SetAttr`, additionally
                // apply the post-commit snapshot to the cached
                // `SaltyfsVnodeData` so subsequent stat calls see
                // the new mode/uid/gid/... without a follow-up RPC.
                let ack: VfsResult<()> = match kind {
                    SaltyfsOpKind::SetAttr { .. } => {
                        match super::mutate_rpc::saltyfs_ipc_setattr_parse(reply_msg) {
                            Some(attr) => {
                                apply_attr_snapshot(state, vkey, &attr);
                                Ok(())
                            }
                            None => Err(VfsError::from_backend_reply(reply_msg.label)),
                        }
                    }
                    SaltyfsOpKind::SetXattr { .. } => {
                        let res = match super::xattr_rpc::saltyfs_ipc_setxattr_parse(reply_msg) {
                            Ok(()) => Ok(()),
                            Err(label) => Err(VfsError::from_backend_reply(label)),
                        };
                        release_xattr_shm_only(state, fs_id, tx_id);
                        res
                    }
                    SaltyfsOpKind::RemoveXattr { .. } => {
                        match super::xattr_rpc::saltyfs_ipc_removexattr_parse(reply_msg) {
                            Ok(()) => Ok(()),
                            Err(label) => Err(VfsError::from_backend_reply(label)),
                        }
                    }
                    SaltyfsOpKind::Write { transfer, .. } => {
                        // BACKEND_WRITE reply: regs[0] = bytes_written,
                        // VFS_BACKEND_REPLY_OK on success.
                        //
                        // Hybrid-1 SHM ring slot release: the issue
                        // path (`vops::saltyfs_write`) leased one
                        // slot of `SALTYFS_RING_SLOT_BYTES` bytes
                        // for `TRANSFER_KIND_SHM`. The slot index
                        // is recoverable from `transfer.offset`
                        // (slot byte offset / slot size). INLINE
                        // and MO transfers do not consume a ring
                        // slot, so no release is needed for them.
                        if transfer.kind == trona_protocol::vfs::backend::TRANSFER_KIND_SHM {
                            let slot_idx =
                                (transfer.offset / super::types::SALTYFS_RING_SLOT_BYTES) as u8;
                            if let Some(mount_h) = state.mount_by_fs_instance_id(fs_id) {
                                if let Some(mount) = state.mounts.get(mount_h) {
                                    let md = mount.data as *mut SaltyfsMountData;
                                    if !md.is_null() {
                                        (*md).ring_free(slot_idx);
                                    }
                                }
                            }
                        }
                        if reply_msg.label == VFS_BACKEND_REPLY_OK {
                            Ok(())
                        } else {
                            Err(VfsError::from_backend_reply(reply_msg.label))
                        }
                    }
                    // `SaltyfsOpKind::Fsync` is intercepted ahead of
                    // the saltyfs completion fn by the router's
                    // ordering-hold short-circuit (`OpKind::Sync` is
                    // barrier-gated on the ordering gate, and the
                    // dispatch path stashes the backend ack on the
                    // PendingOp slot rather than forwarding it
                    // here). Never reached.
                    _ => Err(VfsError::from_backend_reply(reply_msg.label)),
                };
                state.backend_credit_release(fs_id);
                // Dependency-graph successor notification is owned
                // by `dispatch_pending_reply`: the router holds the
                // live `op_handle` and walks the graph just before
                // releasing the arena slot. The completion fn here
                // only renders the reply payload.
                crate::personality::reply::emit_ack(reply_lease, reply, 0, ack);
            }
            FsResume::FinalOpChild {
                client,
                parent_vkey,
                kind_hint,
                spec,
                open_reply,
                ack_reply,
                creds_uid,
                creds_gid,
            } => {
                // Compound-mutation async RPCs (`BACKEND_CREATE` /
                // `_MKDIR` / `_SYMLINK`) return just the new ino.
                // Synthesise the rest of the attrs from the client-
                // known request state (mode, uid/gid from creds,
                // sensible defaults for size/nlink/blocks) so the
                // completion router doesn't have to chain a follow-
                // up `BACKEND_STAT` round-trip. A later authoritative
                // `getattr` refreshes the cache via the existing
                // stat-issue path.
                let ack: VfsResult<u64> =
                    match super::mutate_rpc::saltyfs_ipc_child_reply_parse(reply_msg) {
                        Ok(new_ino) => Ok(new_ino),
                        Err(label) => Err(VfsError::from_backend_reply(label)),
                    };

                let new_vh = if let Ok(new_ino) = ack {
                    // Resolve parent mount handle via
                    // `FsInstanceId → MountHandle`, not via the
                    // resolve cache. The cache may have evicted the
                    // parent's entry by the time this completion
                    // lands; falling back to `MountHandle::INVALID`
                    // would force `alloc_saltyfs_vnode_from_state`
                    // to surface OOM for an op the backend already
                    // committed. The backend_sessions mapping keyed
                    // by `fs_id` is authoritative.
                    let mount_handle = state
                        .mount_by_fs_instance_id(parent_vkey.fs_instance_id)
                        .unwrap_or(crate::core::mount::MountHandle::INVALID);
                    let parent_ino = kind_hint_parent_ino(kind);
                    let (synth_mode, synth_size, synth_nlink, synth_dir_type) = match kind_hint {
                        FinalOpKind::Create => (
                            spec.map(|open_spec| open_spec.mode | 0o100000)
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
                    };
                    match super::vops::alloc_saltyfs_vnode_from_state(
                        state,
                        mount_handle,
                        parent_ino,
                        new_ino,
                        0,
                        synth_mode,
                        synth_size,
                        synth_nlink,
                        0,
                        creds_uid,
                        creds_gid,
                        synth_dir_type,
                        0,
                    ) {
                        Ok(vnode_h) => Some(vnode_h),
                        Err(_) => None,
                    }
                } else {
                    None
                };

                state.backend_credit_release(fs_id);
                match (spec, new_vh, ack.err()) {
                    (Some(open_spec), Some(vnode_h), None) => {
                        let anchor = match kind {
                            SaltyfsOpKind::Create { name, name_len, .. } => {
                                crate::server::open_object::OpenObjectAnchor::from_component(
                                    parent_vkey,
                                    &name[..name_len as usize],
                                    name_len,
                                )
                            }
                            _ => crate::server::open_object::OpenObjectAnchor::EMPTY,
                        };
                        crate::ops::open::finish_open_resolved_leaf_with_anchor(
                            state,
                            client,
                            vnode_h,
                            anchor,
                            open_spec,
                            crate::ops::OpenCreateAction::Created,
                            open_reply,
                            reply_lease,
                        );
                    }
                    (Some(_), _, Some(e)) => {
                        crate::personality::reply::emit_open(reply_lease, open_reply, Err(e));
                    }
                    (Some(_), None, None) => {
                        crate::personality::reply::emit_open(
                            reply_lease,
                            open_reply,
                            Err(VfsError::Io),
                        );
                    }
                    (None, Some(_), None) => {
                        crate::personality::reply::emit_ack(reply_lease, ack_reply, 0, Ok(()));
                    }
                    (None, _, Some(e)) => {
                        crate::personality::reply::emit_ack(reply_lease, ack_reply, 0, Err(e));
                    }
                    (None, None, None) => {
                        crate::personality::reply::emit_ack(
                            reply_lease,
                            ack_reply,
                            0,
                            Err(VfsError::Io),
                        );
                    }
                }
            }
            FsResume::FinalOpAckRemoval {
                client,
                parent_vkey,
                removed_child_vkey,
                kind,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                if reply_msg.label == VFS_BACKEND_REPLY_OK {
                    if removed_child_vkey.is_valid() {
                        state.invalidate_resolve_cache_for(removed_child_vkey);
                        if matches!(kind, FinalOpRemovalKind::Rmdir) {
                            state.invalidate_parent_dir_caches(removed_child_vkey);
                        }
                    }
                    state.invalidate_parent_dir_caches(parent_vkey);
                }
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_ack(
                    reply_lease,
                    reply,
                    0,
                    backend_ack_result(reply_msg),
                );
            }
            FsResume::DeleteOnClose { .. } => {
                state.backend_credit_release(fs_id);
                crate::owner::op::reply_drop(reply_lease);
            }
            FsResume::LatePivot { .. } => {
                state.backend_credit_release(fs_id);
                crate::owner::op::reply_drop(reply_lease);
            }
            FsResume::FinalOpAckRename {
                client,
                new_parent_vkey,
                old_parent_vkey,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                if reply_msg.label == VFS_BACKEND_REPLY_OK {
                    state.invalidate_parent_dir_caches(new_parent_vkey);
                    if old_parent_vkey != new_parent_vkey && old_parent_vkey.is_valid() {
                        state.invalidate_parent_dir_caches(old_parent_vkey);
                    }
                }
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_ack(
                    reply_lease,
                    reply,
                    0,
                    backend_ack_result(reply_msg),
                );
            }
            FsResume::FinalOpAckLink {
                client,
                new_parent_vkey,
                reply,
            } => {
                if !client_accepts_completion(state, client) {
                    state.backend_credit_release(fs_id);
                    crate::owner::op::reply_drop(reply_lease);
                    return;
                }
                if reply_msg.label == VFS_BACKEND_REPLY_OK {
                    state.invalidate_parent_dir_caches(new_parent_vkey);
                }
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_ack(
                    reply_lease,
                    reply,
                    0,
                    backend_ack_result(reply_msg),
                );
            }
            FsResume::FinalOpAckTruncate {
                client,
                file_vkey,
                fd,
                old_size,
                reply,
            } => {
                if reply_msg.label == VFS_BACKEND_REPLY_OK {
                    if let SaltyfsOpKind::Truncate { new_size, .. } = kind {
                        // Refresh the cached `size` on the backend's
                        // vdata pool so the next getattr / stat sees
                        // the post-truncate size without another RPC.
                        if let Some(vnode_h) = state.lookup_resolve_cache(file_vkey) {
                            if let Some(vn) = state.vnodes.get(vnode_h) {
                                let vdata = vn.data as *mut super::types::SaltyfsVnodeData;
                                if !vdata.is_null() {
                                    (*vdata).size = new_size;
                                }
                            }
                            // Decommit the trimmed page range from any
                            // file-backed MO bound to this vnode. The
                            // kernel releases the phys backing for
                            // pages past `new_size`; the next fault on
                            // a trimmed page surfaces a fresh
                            // `EVENT_TYPE_PAGER_REQUEST` that the
                            // pager handler resolves to SIGBUS.
                            crate::owner::pager_rpc::invoke_mo_decommit_for_truncate(
                                state, vnode_h, new_size,
                            );
                        }
                        let _ = (client, fd, old_size);
                    }
                }
                state.backend_credit_release(fs_id);
                crate::personality::reply::emit_ack(
                    reply_lease,
                    reply,
                    0,
                    backend_ack_result(reply_msg),
                );
            }
            FsResume::NameiStep {
                client,
                cursor,
                phase,
                terminal,
            } => {
                // Backend boundary: parse SaltyFS wire state here
                // and hand only generic outcomes back to the async
                // walker — backend-specific shape stops at this
                // module.
                match phase {
                    crate::owner::pending::WalkPhase::Lookup => {
                        let lookup =
                            materialize_namei_lookup_result(state, &cursor, kind, reply_msg);
                        crate::core::namei_async::resume_namei_after_lookup(
                            state,
                            client,
                            cursor,
                            terminal,
                            reply_lease,
                            lookup,
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
                        crate::core::namei_async::resume_namei_after_readlink(
                            state,
                            client,
                            cursor,
                            terminal,
                            reply_lease,
                            parsed,
                        );
                    }
                }
            }
        }
    }
}

/// Drop xattr SHM ownership for the op identified by `tx_id`. The
/// caller is responsible for invoking
/// [`VfsState::backend_credit_release`] afterwards — credit release
/// triggers the session's drain hook, and stacking two drains on
/// the same completion would let a parked xattr op observe a half-
/// freed SHM region. No-op when the mount is gone (the
/// [`super::deferred::release_xattr_shm_if_owner`] helper is a
/// conditional write).
#[inline]
unsafe fn release_xattr_shm_only(state: &mut VfsState, fs_id: FsInstanceId, tx_id: TxId) {
    unsafe {
        if let Some(mount_h) = state.mount_by_fs_instance_id(fs_id) {
            if let Some(mount) = state.mounts.get(mount_h) {
                let md = mount.data as *mut SaltyfsMountData;
                if !md.is_null() {
                    super::deferred::release_xattr_shm_if_owner(md, tx_id);
                }
            }
        }
    }
}

/// Materialise a SaltyFS lookup completion into a generic
/// `Option<VnodeHandle>` for the async namei walker. Wraps the
/// allocation of a fresh vnode from the lookup attrs while
/// translating "no entry" into `None` (so the walker emits
/// `ENOENT`) and backend-format errors into `VfsError::Io`.
unsafe fn materialize_namei_lookup_result(
    state: &mut VfsState,
    cursor: &crate::owner::pending::WalkCursor,
    kind: SaltyfsOpKind,
    reply: &TronaMsg,
) -> VfsResult<Option<crate::core::vnode::VnodeHandle>> {
    let (parent_ino, name, name_len) = match kind {
        SaltyfsOpKind::Lookup {
            parent_ino,
            name,
            name_len,
        } => (parent_ino, name, name_len),
        _ => return Err(VfsError::Io),
    };
    let parsed = super::rpc::saltyfs_ipc_lookup_parse(reply)?;
    let Some((child_ino, child_seq, mode, size, nlink, mtime, uid, gid, dir_type, blocks)) = parsed
    else {
        return Ok(None);
    };
    let parent_vh =
        crate::core::namei_async::resolve_cursor_cwd(state, cursor).ok_or(VfsError::Io)?;
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

/// Extract the parent directory's ino from a compound-mutation
/// `SaltyfsOpKind`. Used by the `FinalOpChild` resume path to seed
/// the freshly-materialised child's cached `parent_ino` for dot-dot
/// resolution. Returns `0` for op kinds that do not produce a
/// child — defensive fallback only `Create` / `Mkdir` / `Symlink`
/// should reach this resume arm.
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
/// the vnode has been reclaimed between park and completion (next
/// access re-materialises via `vget`).
unsafe fn apply_attr_snapshot(
    state: &mut VfsState,
    vkey: crate::core::identity::VnodeKey,
    attr: &VAttr,
) {
    unsafe {
        let Some(vnode_h) = state.lookup_resolve_cache(vkey) else {
            return;
        };
        let Some(vn) = state.vnodes.get(vnode_h) else {
            return;
        };
        let vdata = vn.data as *mut super::types::SaltyfsVnodeData;
        if vdata.is_null() {
            return;
        }
        (*vdata).mode = attr.mode;
        (*vdata).uid = attr.uid;
        (*vdata).gid = attr.gid;
        (*vdata).size = attr.size;
        (*vdata).nlink = attr.nlink;
        (*vdata).mtime = attr.mtime;
    }
}

#[inline]
fn backend_ack_result(reply: &TronaMsg) -> VfsResult<()> {
    if reply.label == VFS_BACKEND_REPLY_OK {
        Ok(())
    } else {
        Err(VfsError::from_backend_reply(reply.label))
    }
}

#[inline]
fn backend_attr_result(reply: &TronaMsg, fs: FsInstanceId) -> VfsResult<VAttr> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return Err(VfsError::from_backend_reply(reply.label));
    }
    parse_stat_attr(reply, fs).ok_or(VfsError::Io)
}

#[inline]
fn backend_ioctl_result(reply: &TronaMsg) -> VfsResult<IoctlReply> {
    if reply.label != VFS_BACKEND_REPLY_OK {
        return Err(VfsError::from_backend_reply(reply.label));
    }
    let mut out = IoctlReply::EMPTY;
    out.byte_count = reply.regs[0].min(u32::MAX as u64) as u32;
    let word_count = (reply.regs[1] as usize).min(out.words.len());
    for i in 0..word_count {
        let src = 2 + i;
        if src >= reply.regs.len() {
            break;
        }
        out.words[i] = reply.regs[src];
        out.word_count = (i + 1) as u8;
    }
    Ok(out)
}

fn resolve_vkey_handle(
    state: &VfsState,
    vkey: VnodeKey,
) -> VfsResult<crate::core::vnode::VnodeHandle> {
    state.lookup_resolve_cache(vkey).ok_or(VfsError::NoEnt)
}

fn decorate_attr_from_vkey(state: &VfsState, vkey: VnodeKey, attr: &mut VAttr) -> VfsResult<()> {
    let vnode_h = resolve_vkey_handle(state, vkey)?;
    let vnode = state.vnodes.get(vnode_h).ok_or(VfsError::NoEnt)?;
    attr.fs_instance_id = vkey.fs_instance_id;
    attr.backend_node_id = vkey.backend_id.id;
    attr.backend_seq = vkey.backend_id.seq;
    attr.kind = vnode.kind;
    Ok(())
}

fn parse_setattr_completion(
    state: &mut VfsState,
    vkey: VnodeKey,
    reply: &TronaMsg,
) -> VfsResult<()> {
    match super::mutate_rpc::saltyfs_ipc_setattr_parse(reply) {
        Some(attr) => {
            unsafe { apply_attr_snapshot(state, vkey, &attr) };
            Ok(())
        }
        None => Err(VfsError::from_backend_reply(reply.label)),
    }
}

/// Parse a `BACKEND_STAT` completion into [`VAttr`]. Returns `None`
/// on a malformed or error reply. Any sanity failure of the returned
/// attribute record — e.g. an `S_IFMT` bit pattern outside the POSIX
/// catalogue, or a zeroed `mode` that violates saltyfs's "allocated
/// inode carries a type" invariant — raises an
/// `audit_integrity_failure` entry,
/// scoped by the owning mount's identity, and drops the reply as if
/// it were malformed. Callers see the same `None` either way; the
/// audit log gives operators a distinguishable trail.
#[inline]
fn parse_stat_attr(reply: &TronaMsg, fs: FsInstanceId) -> Option<VAttr> {
    let (size, mode, nlink, mtime, blocks, uid, gid, _seq) =
        super::rpc::saltyfs_ipc_stat_parse(reply)?;
    // Validate the S_IFMT file-type field. Anything outside the
    // POSIX catalogue means the backend either returned an
    // uninitialised inode or the on-disk structure diverged from
    // the type-byte invariant.
    const S_IFMT: u32 = 0o170000;
    let ftype = mode & S_IFMT;
    let valid_ftype = matches!(
        ftype,
        0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000,
    );
    if mode == 0 || !valid_ftype {
        audit_integrity_failure(fs, IntegrityDetail::Inode);
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

/// Service a backend completion that originated from a kernel
/// `EVENT_TYPE_PAGER_REQUEST` event. The backend round-trip parked the
/// page bytes in the mount SHM ring; this handler hands that VA to the
/// kernel via `PAGER_SUPPLY_COPY` (READ — the kernel sources the
/// page-cache page from the global PMM and copies the bytes in) or
/// signals completion via `PAGER_WRITEBACK_DONE` (WRITEBACK), and
/// releases the backend credit. The reply lease parked on the
/// PendingOp is a placeholder — kernel pager events have no caller
/// to reply to — so the lease is dropped without a `reply_send`.
unsafe fn handle_pager_completion(
    state: &mut VfsState,
    fs_id: FsInstanceId,
    pager: PagerResume,
    reply_lease: Option<ReplyLease>,
    reply_msg: &TronaMsg,
) {
    state.backend_credit_release(fs_id);
    // Kernel `EVENT_TYPE_PAGER_REQUEST` has no caller, so the
    // PendingOp normally parks no lease. The `Some` branch below
    // handles legacy paths that may still carry a lease through
    // — they simply get dropped.
    if let Some(lease) = reply_lease {
        crate::owner::op::reply_drop(lease);
    }

    let pager_cap = state.pager_cap.as_raw();
    if pager_cap == 0 {
        // Pager torn down mid-flight. Nothing to clean up — in the
        // page-cache supply model vfs holds no frame or scratch mapping,
        // and the TCB blocked on this request was already woken by the
        // `PAGER_DETACH` cascade.
        return;
    }

    let vnode_key_matches = state
        .vnodes
        .get(pager.vnode)
        .map(|v| v.key == pager.vkey)
        .unwrap_or(false);
    if !vnode_key_matches {
        audit_integrity_failure(fs_id, IntegrityDetail::StaleVnode);
        unsafe {
            if pager.op_type == PAGERRESUME_OP_READ {
                crate::owner::pager_rpc::invoke_pager_fail(
                    pager_cap,
                    pager.mo_id,
                    pager.page_idx,
                    TRONA_IO_ERROR,
                );
            } else if pager.op_type == PAGERRESUME_OP_WRITEBACK {
                let _ = crate::owner::pager_rpc::invoke_pager_writeback_done(
                    pager_cap,
                    pager.mo_id,
                    pager.page_idx,
                    pager.writeback_epoch,
                    TRONA_IO_ERROR,
                );
                crate::owner::pager_rpc::mmsrv_writeback_page_done(
                    state,
                    pager.mmsrv_writeback_token,
                    false,
                );
            }
        }
        return;
    }

    let mut backend_ok = reply_msg.label == VFS_BACKEND_REPLY_OK;
    if backend_ok
        && pager.op_type == PAGERRESUME_OP_READ
        && reply_msg.regs[0] > u64::from(pager.length)
    {
        audit_data_corrupt(fs_id, pager.vkey.backend_id, pager.page_offset);
        backend_ok = false;
    }

    if !backend_ok {
        unsafe {
            match pager.op_type {
                PAGERRESUME_OP_READ => {
                    // Backend READ failed — surface SIGBUS. No page was
                    // supplied (the single PAGER_SUPPLY_COPY only fires on
                    // success), so there is nothing to release.
                    crate::owner::pager_rpc::invoke_pager_fail(
                        pager_cap,
                        pager.mo_id,
                        pager.page_idx,
                        TRONA_IO_ERROR,
                    );
                }
                PAGERRESUME_OP_WRITEBACK => {
                    // Backend WRITE failed. Complete the kernel
                    // writeback with a non-zero status so WRITEBACK
                    // is cleared but DIRTY remains set for the next
                    // retry.
                    let _ = crate::owner::pager_rpc::invoke_pager_writeback_done(
                        pager_cap,
                        pager.mo_id,
                        pager.page_idx,
                        pager.writeback_epoch,
                        TRONA_IO_ERROR,
                    );
                    let key = crate::owner::page_cache::PageKey {
                        vnode: pager.vnode,
                        page_offset: pager.page_offset,
                    };
                    if let Some(handle) = crate::owner::page_cache::lookup(state, key) {
                        crate::owner::page_cache::complete_writeback(state, handle, false);
                    }
                    crate::owner::pager_rpc::mmsrv_writeback_page_done(
                        state,
                        pager.mmsrv_writeback_token,
                        false,
                    );
                }
                _ => {}
            }
        }
        return;
    }

    match pager.op_type {
        PAGERRESUME_OP_READ => {
            // The saltyfs daemon parked the page bytes in the mount SHM ring
            // (offset 0). Hand that VA + length to the kernel, which sources
            // the page-cache page from the global PMM and copies the bytes
            // in; the kernel zero-fills past `bytes_read` for partial pages.
            let bytes_read = reply_msg.regs[0];
            let (shm_vaddr, shm_size) = {
                let mut sv = 0u64;
                let mut ss = 0u64;
                if let Some(mh) = state.mount_by_fs_instance_id(fs_id) {
                    if let Some(mount) = state.mounts.get(mh) {
                        let md = mount.data as *const super::types::SaltyfsMountData;
                        if !md.is_null() {
                            // SAFETY: `md` is the live saltyfs mount-data
                            // pointer for this backend instance.
                            unsafe {
                                sv = (*md).shm_vaddr;
                                ss = (*md).shm_size;
                            }
                        }
                    }
                }
                (sv, ss)
            };
            if shm_vaddr == 0 {
                unsafe {
                    crate::owner::pager_rpc::invoke_pager_fail(
                        pager_cap,
                        pager.mo_id,
                        pager.page_idx,
                        TRONA_IO_ERROR,
                    );
                }
            } else {
                let copy_len = ::core::cmp::min(bytes_read, shm_size);
                let rc = unsafe {
                    crate::owner::pager_rpc::invoke_pager_supply_copy(
                        pager_cap,
                        pager.mo_id,
                        pager.page_idx,
                        shm_vaddr,
                        copy_len,
                    )
                };
                if rc == 0 {
                    crate::owner::pager_rpc::record_supplied_page_clean(
                        state,
                        pager.vnode,
                        pager.page_offset,
                    );
                }
            }
        }
        PAGERRESUME_OP_WRITEBACK => {
            let (rc, dirty_pending) = unsafe {
                crate::owner::pager_rpc::invoke_pager_writeback_done(
                    pager_cap,
                    pager.mo_id,
                    pager.page_idx,
                    pager.writeback_epoch,
                    0,
                )
            };
            let key = crate::owner::page_cache::PageKey {
                vnode: pager.vnode,
                page_offset: pager.page_offset,
            };
            if let Some(handle) = crate::owner::page_cache::lookup(state, key) {
                crate::owner::page_cache::complete_writeback(
                    state,
                    handle,
                    rc == 0 && !dirty_pending,
                );
            }
            crate::owner::pager_rpc::mmsrv_writeback_page_done(
                state,
                pager.mmsrv_writeback_token,
                rc == 0,
            );
        }
        _ => {}
    }
}
