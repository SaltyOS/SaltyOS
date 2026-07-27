// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-neutral attribute-query + attribute-mutation
//! logic helpers.
//!
//! Both POSIX (`personality/posix/stat.rs`,
//! `personality/posix/chmod.rs`, ...) and Win32
//! (`personality/win32/attr.rs`,
//! `personality/win32/set_information.rs`) decode their wire
//! into a personality-neutral request and call into the helpers
//! below. The helpers drive the matching vop (`meta.getattr` /
//! `meta.setattr`) against the core vnode and route the
//! reply through `personality::reply::emit_attr` /
//! `personality::reply::emit_ack`.
//!
//! The `core::file::VAttr` struct is the personality-neutral
//! wire shape that flows through this module — POSIX projects to
//! `struct stat`, Win32 projects to `Windows-specific value` /
//! `Windows-specific value` / etc. at the personality reply
//! layer.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::file::VAttr;
use crate::core::identity::VnodeKey;
use crate::core::namei_async::NameiAsyncResult;
use crate::core::namei_common::{NAMEI_FOLLOW, NAMEI_NOFOLLOW_FINAL};
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::ops::AttrReplyIntent;
use crate::owner::VfsState;
use crate::owner::pending::WalkPolicy;
use crate::owner::resume::{FsResume, NameiTerminal, Resume};
use crate::server::types::ClientHandle;

/// Drive the async namei walker to the [`NameiTerminal::GetAttr`]
/// terminal with the supplied `reply_intent`. The walker either
/// resolves the leaf synchronously (the terminal callback runs
/// `meta.getattr` and emits the reply) or parks on a backend
/// RPC (`FsResume::FillGetAttrReply { reply }` is stamped).
///
/// `follow_leaf_symlink` distinguishes POSIX `stat` (follow) from
/// `lstat` / Win32 attribute queries with
/// `OBJ_DONT_FOLLOW_SYMLINK` (no follow).
pub(crate) unsafe fn do_getattr_from_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_vkey: VnodeKey,
    path_bytes: &[u8],
    path_len: usize,
    follow_leaf_symlink: bool,
    reply_intent: AttrReplyIntent,
    reply_lease: ReplyLease,
) {
    let walker_flags = if follow_leaf_symlink {
        NAMEI_FOLLOW
    } else {
        NAMEI_NOFOLLOW_FINAL
    };
    unsafe {
        crate::core::namei_async::begin_path_walk_from_bytes(
            state,
            client,
            anchor_vkey,
            path_bytes,
            path_len,
            WalkPolicy::FinalMustExist,
            walker_flags,
            NameiTerminal::GetAttr {
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

/// Run `meta.getattr` against an already-resolved vnode handle —
/// fd-based callers (POSIX `fstat`, Win32 handle queries)
/// reach the vop chain through this entry. Sync hit emits the
/// reply inline; backend park stamps `FsResume::FillGetAttrReply`.
pub(crate) unsafe fn do_getattr_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    reply_intent: AttrReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        finish_getattr_for_vnode(state, client, vnode_h, reply_intent, reply_lease);
    }
}

/// `NameiTerminal::GetAttr { reply }` callback. Invoked by
/// `crate::core::namei_async` when the async walker reaches
/// the leaf with `WalkPolicy::FinalMustExist`. The leaf either
/// resolved (run getattr) or did not (`VfsError::NoEnt`).
pub(crate) unsafe fn resume_getattr_walk_result(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    reply_intent: AttrReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if state.clients.get(client).is_none() {
            return;
        }
        if !result.vnode_h.is_valid() {
            emit_attr_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        finish_getattr_for_vnode(state, client, result.vnode_h, reply_intent, reply_lease);
    }
}

/// Run `meta.getattr` and dispatch the reply through
/// [`crate::personality::reply::emit_attr`].
unsafe fn finish_getattr_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    reply_intent: AttrReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_attr_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            emit_attr_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let vkey = (*ctx.vnode).key;
        let mut attr = VAttr::zeroed();
        match ((*ops).meta.getattr)(&mut ctx, &raw mut attr) {
            Ok(Ready(())) => {
                crate::personality::reply::emit_attr(reply_lease, reply_intent, Ok(attr));
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
                    Resume::Fs(FsResume::FillGetAttrReply {
                        client,
                        vkey,
                        reply: reply_intent,
                    }),
                ) {
                    emit_attr_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => emit_attr_error(reply_lease, reply_intent, e),
        }
    }
}

/// Personality-aware error reply for an attribute query.
unsafe fn emit_attr_error(reply_lease: ReplyLease, reply_intent: AttrReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_attr(reply_lease, reply_intent, Err(err));
    }
}
