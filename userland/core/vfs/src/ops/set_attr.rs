// SPDX-License-Identifier: GPL-2.0-only
//
//! Leaf-attribute mutation logic helper. POSIX `chmod` /
//! `chown` / `utimes` / path-`truncate`, Windows
//! Win32 attribute updates all collapse to
//! a `meta.setattr` call with [`VAttr::valid`] flagging which
//! fields are mutated.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::file::{
    VATTR_ATIME, VATTR_GID, VATTR_MODE, VATTR_MTIME, VATTR_SIZE, VATTR_UID, VAttr,
};
use crate::core::identity::VnodeKey;
use crate::core::namei_async::NameiAsyncResult;
use crate::core::namei_common::NAMEI_FOLLOW;
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::ops::{AckReplyIntent, SetAttrKind};
use crate::owner::VfsState;
use crate::owner::pending::WalkPolicy;
use crate::owner::resume::{FsResume, NameiTerminal, Resume};
use crate::server::types::ClientHandle;

/// Drive the namei walker to the [`NameiTerminal::SetAttr`]
/// terminal.
pub(crate) unsafe fn do_setattr_from_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_vkey: VnodeKey,
    path_bytes: &[u8],
    path_len: usize,
    kind: SetAttrKind,
    follow_leaf_symlink: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    let walker_flags = if follow_leaf_symlink {
        NAMEI_FOLLOW
    } else {
        crate::core::namei_common::NAMEI_NOFOLLOW_FINAL
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
            NameiTerminal::SetAttr {
                kind,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

/// Run `meta.setattr` against an already-resolved vnode (fd-based
/// callers — `fchmod` / `fchown` / `futimes`).
pub(crate) unsafe fn do_setattr_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    kind: SetAttrKind,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        finish_setattr_for_vnode(state, client, vnode_h, kind, reply_intent, reply_lease);
    }
}

/// `NameiTerminal::SetAttr` callback.
pub(crate) unsafe fn resume_setattr_walk_result(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    kind: SetAttrKind,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if state.clients.get(client).is_none() {
            return;
        }
        if !result.vnode_h.is_valid() {
            emit_ack_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        finish_setattr_for_vnode(
            state,
            client,
            result.vnode_h,
            kind,
            reply_intent,
            reply_lease,
        );
    }
}

unsafe fn finish_setattr_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    kind: SetAttrKind,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if let SetAttrKind::PathTruncate { new_size } = kind {
            crate::ops::io::finish_truncate_for_vnode(
                state,
                client,
                vnode_h,
                -1,
                new_size,
                reply_intent,
                reply_lease,
            );
            return;
        }

        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let vkey = (*ctx.vnode).key;

        let attr = build_vattr_for_setattr(kind);

        match ((*ops).meta.setattr)(&mut ctx, &raw const attr) {
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
                    Resume::Fs(FsResume::FillSetAttrReply {
                        client,
                        vkey,
                        reply: reply_intent,
                    }),
                ) {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => emit_ack_error(reply_lease, reply_intent, e),
        }
    }
}

fn build_vattr_for_setattr(kind: SetAttrKind) -> VAttr {
    let mut attr = VAttr::zeroed();
    match kind {
        SetAttrKind::Mode { mode } => {
            attr.valid = VATTR_MODE;
            attr.mode = mode;
        }
        SetAttrKind::Owner { uid, gid } => {
            if let Some(u) = uid {
                attr.valid |= VATTR_UID;
                attr.uid = u;
            }
            if let Some(g) = gid {
                attr.valid |= VATTR_GID;
                attr.gid = g;
            }
        }
        SetAttrKind::Times {
            atime_nanos,
            mtime_nanos,
        } => {
            if let Some(a) = atime_nanos {
                attr.valid |= VATTR_ATIME;
                attr.atime = a;
            }
            if let Some(m) = mtime_nanos {
                attr.valid |= VATTR_MTIME;
                attr.mtime = m;
            }
        }
        SetAttrKind::PathTruncate { new_size } => {
            attr.valid = VATTR_SIZE;
            attr.size = new_size;
        }
        SetAttrKind::BasicBundle {
            creation_time_nanos: _,
            last_access_nanos,
            last_write_nanos,
            change_time_nanos: _,
            nt_file_attributes,
        } => {
            // Map the Windows bundle onto the closest POSIX subset:
            // Win32 time values -> atime/mtime, readonly attribute
            // bit collapses onto mode (clear write bits).
            if let Some(a) = last_access_nanos {
                attr.valid |= VATTR_ATIME;
                attr.atime = a;
            }
            if let Some(m) = last_write_nanos {
                attr.valid |= VATTR_MTIME;
                attr.mtime = m;
            }
            if let Some(fa) = nt_file_attributes {
                const READONLY_ATTRIBUTE_BIT: u32 = 0x1;
                if (fa & READONLY_ATTRIBUTE_BIT) != 0 {
                    attr.valid |= VATTR_MODE;
                    attr.mode = 0o444;
                }
            }
        }
    }
    // Path truncate is intercepted before `build_vattr_for_setattr`
    // reaches the backend; it uses `meta.truncate`, not `setattr`.
    attr
}

/// Path-based truncate (`POSIX truncate(path, size)`).
pub(crate) unsafe fn do_truncate_path_from_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_vkey: VnodeKey,
    path_bytes: &[u8],
    path_len: usize,
    new_size: u64,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        do_setattr_from_bytes(
            state,
            client,
            anchor_vkey,
            path_bytes,
            path_len,
            SetAttrKind::PathTruncate { new_size },
            /* follow_leaf_symlink = */ true,
            reply_intent,
            reply_lease,
        );
    }
}

unsafe fn emit_ack_error(reply_lease: ReplyLease, intent: AckReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, intent, 0, Err(err));
    }
}
