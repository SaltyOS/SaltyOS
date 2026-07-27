// SPDX-License-Identifier: GPL-2.0-only
//
//! New-leaf creation logic helper. POSIX `mkdir` / `symlink` /
//! `mkfifo` and Win32 creation entries all walk to the parent + last
//! name and call the matching `meta.*` vop on the parent.

use trona_server::ReplyLease;

use crate::core::cred::VfsCred;
use crate::core::error::VfsError;
use crate::core::identity::VnodeKey;
use crate::core::namei_async::NameiAsyncResult;
use crate::core::namei_common::NAMEI_NOFOLLOW_FINAL;
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::ops::{AckReplyIntent, CreateLeafKind, OpenReplyIntent};
use crate::owner::VfsState;
use crate::owner::namei_aux::{NameiAuxHandle, NameiAuxState};
use crate::owner::pending::WalkPolicy;
use crate::owner::resume::{FinalOpKind, FsResume, NameiTerminal, Resume};
use crate::server::types::ClientHandle;

/// Drive the walker to the [`NameiTerminal::CreateLeaf`]
/// terminal. `aux_handle` carries the symlink target bytes for
/// `CreateLeafKind::Symlink`; pass [`NameiAuxHandle::INVALID`]
/// for the inline kinds (mkdir / mkfifo / mknod).
pub(crate) unsafe fn do_create_leaf_from_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_vkey: VnodeKey,
    path_bytes: &[u8],
    path_len: usize,
    kind: CreateLeafKind,
    aux_handle: NameiAuxHandle,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    let policy = WalkPolicy::StopAtParent {
        final_name: [0u8; crate::owner::pending::WALK_NAME_MAX],
        final_name_len: 0,
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
            NameiTerminal::CreateLeaf {
                kind,
                aux_handle,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

/// `NameiTerminal::CreateLeaf` callback.
pub(crate) unsafe fn resume_create_leaf_walk_result(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    kind: CreateLeafKind,
    aux_handle: NameiAuxHandle,
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
        finish_create_leaf(
            state,
            client,
            result.dir_vnode_h,
            result.last_name,
            result.last_name_len,
            kind,
            aux_handle,
            reply_intent,
            reply_lease,
        );
    }
}

unsafe fn finish_create_leaf(
    state: &mut VfsState,
    client: ClientHandle,
    parent_h: VnodeHandle,
    name_buf: [u8; crate::owner::pending::WALK_NAME_MAX],
    name_len: u8,
    kind: CreateLeafKind,
    aux_handle: NameiAuxHandle,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        let symlink_target = if matches!(kind, CreateLeafKind::Symlink { .. }) {
            let aux = match state.namei_aux.get(aux_handle) {
                Some(a) => *a,
                None => {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                    return;
                }
            };
            match aux {
                NameiAuxState::Symlink {
                    target, target_len, ..
                } => {
                    let target_len = match u8::try_from(target_len) {
                        Ok(value) => value,
                        Err(_) => u8::MAX,
                    };
                    Some((target, target_len))
                }
                _ => {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                    return;
                }
            }
        } else {
            None
        };
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
        let cred = VfsCred::root();

        let outcome = match kind {
            CreateLeafKind::Mkdir { mode } => {
                ((*ops).meta.mkdir)(&mut ctx, name_buf.as_ptr(), name_len, mode, &raw const cred)
            }
            CreateLeafKind::Mkfifo { mode } => {
                ((*ops).meta.mkfifo)(&mut ctx, name_buf.as_ptr(), name_len, mode, &raw const cred)
            }
            CreateLeafKind::Mknod { mode, dev } => {
                let _ = (mode, dev);
                // saltyos has no `meta.mknod` vop today; surface
                // NotSup until the device-node vop lands.
                Err(VfsError::NotSup)
            }
            CreateLeafKind::Symlink { mode: _ } => {
                let Some((target, target_len)) = symlink_target.as_ref() else {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                    return;
                };
                ((*ops).meta.symlink)(
                    &mut ctx,
                    name_buf.as_ptr(),
                    name_len,
                    target.as_ptr(),
                    *target_len,
                    &raw const cred,
                )
            }
        };

        match outcome {
            Ok(Ready(new_vnode_h)) => {
                if !new_vnode_h.is_valid() {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                    if aux_handle.is_valid() {
                        state.namei_aux.release(aux_handle);
                    }
                    return;
                }
                crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
                if aux_handle.is_valid() {
                    state.namei_aux.release(aux_handle);
                }
            }
            Ok(Parked(handle)) => {
                let badge = state
                    .clients
                    .get(client)
                    .map(|c| c.client_badge)
                    .unwrap_or(0);
                let kind_hint = match kind {
                    CreateLeafKind::Mkdir { .. } => FinalOpKind::Mkdir,
                    CreateLeafKind::Symlink { .. } => FinalOpKind::Symlink,
                    CreateLeafKind::Mkfifo { .. } | CreateLeafKind::Mknod { .. } => {
                        FinalOpKind::Mkdir
                    }
                };
                if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                    handle,
                    badge,
                    Some(reply_lease),
                    Resume::Fs(FsResume::FinalOpChild {
                        client,
                        parent_vkey,
                        kind_hint,
                        spec: None,
                        open_reply: OpenReplyIntent::PosixOpen,
                        ack_reply: reply_intent,
                        creds_uid: 0,
                        creds_gid: 0,
                    }),
                ) {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => {
                emit_ack_error(reply_lease, reply_intent, e);
                if aux_handle.is_valid() {
                    state.namei_aux.release(aux_handle);
                }
            }
        }
    }
}

unsafe fn emit_ack_error(reply_lease: ReplyLease, intent: AckReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, intent, 0, Err(err));
    }
}
