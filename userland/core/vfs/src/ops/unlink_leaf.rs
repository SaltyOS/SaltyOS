// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-neutral unlink-leaf logic helper.
//!
//! POSIX `unlink` / `rmdir` and Win32 deletion entries all
//! collapse to "walk to parent, fire `meta.unlink` /
//! `meta.rmdir` against `last_name`".
//!
//! The [`UnlinkKind`] variant on the terminal selects which
//! vop runs (`File` → `meta.unlink`, `Directory` →
//! `meta.rmdir`, `Either` → tries `meta.unlink` and falls back
//! to `meta.rmdir` on `EISDIR`). The ack flows through
//! `personality::reply::emit_ack`.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::identity::VnodeKey;
use crate::core::namei_async::NameiAsyncResult;
use crate::core::namei_common::NAMEI_NOFOLLOW_FINAL;
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::ops::{AckReplyIntent, UnlinkKind};
use crate::owner::VfsState;
use crate::owner::pending::WalkPolicy;
use crate::owner::resume::{FinalOpRemovalKind, FsResume, NameiTerminal, Resume};
use crate::server::open_object::OpenObjectAnchor;
use crate::server::types::ClientHandle;

/// Drive the async namei walker to the
/// [`NameiTerminal::UnlinkLeaf`] terminal. The walker stops at
/// the parent + last_name; the callback fires the matching vop.
pub(crate) unsafe fn do_unlink_from_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_vkey: VnodeKey,
    path_bytes: &[u8],
    path_len: usize,
    kind: UnlinkKind,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    let policy = WalkPolicy::StopAtParentLookup {
        final_name: [0u8; crate::owner::pending::WALK_NAME_MAX],
        final_name_len: 0,
        missing_ok: false,
    };
    unsafe {
        crate::core::namei_async::begin_path_walk_from_bytes(
            state,
            client,
            anchor_vkey,
            path_bytes,
            path_len,
            policy,
            NAMEI_NOFOLLOW_FINAL,
            NameiTerminal::UnlinkLeaf {
                kind,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

/// `NameiTerminal::UnlinkLeaf` callback.
pub(crate) unsafe fn resume_unlink_walk_result(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    kind: UnlinkKind,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if state.clients.get(client).is_none() {
            return;
        }
        if !result.dir_vnode_h.is_valid() {
            emit_ack_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        if result.last_name_len == 0
            || result.last_name_len as usize > crate::owner::pending::WALK_NAME_MAX
        {
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let name_slice = &result.last_name[..result.last_name_len as usize];
        if name_slice == b"." || name_slice == b".." {
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        if result.vnode_h.is_valid()
            && crate::core::mount_ctl::covering_mount_for_vnode(state, result.vnode_h).is_some()
        {
            emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
            return;
        }
        finish_unlink_for_parent(
            state,
            client,
            result.dir_vnode_h,
            result.last_name,
            result.last_name_len,
            kind,
            reply_intent,
            reply_lease,
        );
    }
}

unsafe fn finish_unlink_for_parent(
    state: &mut VfsState,
    client: ClientHandle,
    parent_h: VnodeHandle,
    name_buf: [u8; crate::owner::pending::WALK_NAME_MAX],
    name_len: u8,
    kind: UnlinkKind,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, parent_h)
        else {
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let parent_vkey = (*ctx.vnode).key;

        let (vop_outcome, removal_kind) = match kind {
            UnlinkKind::File | UnlinkKind::Either => (
                ((*ops).meta.unlink)(&mut ctx, name_buf.as_ptr(), name_len),
                FinalOpRemovalKind::Unlink,
            ),
            UnlinkKind::Directory => (
                ((*ops).meta.rmdir)(&mut ctx, name_buf.as_ptr(), name_len),
                FinalOpRemovalKind::Rmdir,
            ),
        };
        match vop_outcome {
            Ok(Ready(())) => {
                crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
            }
            Ok(Parked(handle)) => {
                let badge = state
                    .clients
                    .get(client)
                    .map(|c| c.client_badge)
                    .unwrap_or(0);
                if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                    handle,
                    badge,
                    Some(reply_lease),
                    Resume::Fs(FsResume::FinalOpAckRemoval {
                        client,
                        parent_vkey,
                        removed_child_vkey: VnodeKey::NONE,
                        kind: removal_kind,
                        reply: reply_intent,
                    }),
                ) {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            // POSIX `unlink` on a directory falls back to `rmdir`
            // when the kind permits either — surface EISDIR
            // otherwise.
            Err(VfsError::IsDir) if matches!(kind, UnlinkKind::Either) => {
                match ((*ops).meta.rmdir)(&mut ctx, name_buf.as_ptr(), name_len) {
                    Ok(Ready(())) => {
                        crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
                    }
                    Ok(Parked(handle)) => {
                        let badge = state
                            .clients
                            .get(client)
                            .map(|c| c.client_badge)
                            .unwrap_or(0);
                        if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                            handle,
                            badge,
                            Some(reply_lease),
                            Resume::Fs(FsResume::FinalOpAckRemoval {
                                client,
                                parent_vkey,
                                removed_child_vkey: VnodeKey::NONE,
                                kind: FinalOpRemovalKind::Rmdir,
                                reply: reply_intent,
                            }),
                        ) {
                            emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
                        }
                    }
                    Err(e) => emit_ack_error(reply_lease, reply_intent, e),
                }
            }
            Err(e) => emit_ack_error(reply_lease, reply_intent, e),
        }
    }
}

unsafe fn emit_ack_error(reply_lease: ReplyLease, intent: AckReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, intent, 0, Err(err));
    }
}

/// Fire the NT delete-on-close unlink after the final handle
/// reference is dropped. There is no client reply to consume here:
/// synchronous success only invalidates caches, and parked backend
/// work resumes through `FsResume::DeleteOnClose`.
pub(crate) unsafe fn delete_anchor_on_close(state: &mut VfsState, anchor: OpenObjectAnchor) {
    unsafe {
        if !anchor.is_valid() {
            return;
        }
        let Some(parent_h) = resolve_vkey(state, anchor.parent_vkey) else {
            return;
        };
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, parent_h)
        else {
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            return;
        }
        let parent_vkey = (*ctx.vnode).key;
        let name = anchor.name.as_ptr();
        let name_len = anchor.name_len;
        let mut removal_kind = FinalOpRemovalKind::Unlink;
        let mut outcome = ((*ops).meta.unlink)(&mut ctx, name, name_len);
        if matches!(outcome, Err(VfsError::IsDir)) {
            removal_kind = FinalOpRemovalKind::Rmdir;
            outcome = ((*ops).meta.rmdir)(&mut ctx, name, name_len);
        }
        match outcome {
            Ok(Ready(())) => {
                state.invalidate_parent_dir_caches(parent_vkey);
            }
            Ok(Parked(handle)) => {
                let _ = state.stamp_resume_ctx(
                    handle,
                    0,
                    None,
                    Resume::Fs(FsResume::DeleteOnClose {
                        parent_vkey,
                        removed_child_vkey: VnodeKey::NONE,
                        kind: removal_kind,
                    }),
                );
            }
            Err(_) => {}
        }
    }
}

fn resolve_vkey(state: &VfsState, key: VnodeKey) -> Option<VnodeHandle> {
    if let Some(h) = state.lookup_resolve_cache(key) {
        return Some(h);
    }
    let mut found = None;
    state.vnodes.for_each_active(|h, vnode| {
        if vnode.key == key {
            found = Some(h);
            false
        } else {
            true
        }
    });
    found
}
