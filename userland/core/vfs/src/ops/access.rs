// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-neutral access-check helper.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::namei_async::NameiAsyncResult;
use crate::core::outcome::{Parked, Ready};
use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::owner::resume::{FsResume, Resume};
use crate::server::types::ClientHandle;

pub(crate) unsafe fn resume_access_walk_result(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    mode: u32,
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
        let Some(mut ctx) =
            crate::core::vop_context::OwnerVopCtx::from_state(state, result.vnode_h)
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
        let cred = crate::core::cred::VfsCred::root();
        match ((*ops).meta.access)(&mut ctx, mode, &raw const cred) {
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
                    Resume::Fs(FsResume::FillAccessReply {
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

unsafe fn emit_ack_error(reply_lease: ReplyLease, intent: AckReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, intent, 0, Err(err));
    }
}
