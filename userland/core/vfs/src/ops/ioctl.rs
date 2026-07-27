// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-neutral fd ioctl helper.
//!
//! Callers decode their own wire shape into `(fd, cmd, arg)` and
//! emit their own reply shape. This layer only resolves the fd,
//! invokes `VopDataOps::ioctl`, and returns the raw reply words.

use crate::core::error::VfsError;
use crate::core::outcome::{Parked, Ready};
use crate::ops::IoctlReplyIntent;
use crate::owner::VfsState;
use crate::owner::resume::{FsResume, Resume};
use crate::server::types::ClientHandle;
use trona_server::ReplyLease;

pub(crate) unsafe fn do_ioctl_from_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    cmd: u32,
    arg: u64,
    reply_intent: IoctlReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            emit_ioctl_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            emit_ioctl_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let vnode_h = match state.open_objects.get(open_h) {
            Some(obj) => obj.vnode,
            None => {
                emit_ioctl_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };

        let caller_badge = state
            .clients
            .get(client)
            .map(|c| c.client_badge)
            .unwrap_or(0);

        let Some(meta_ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_ioctl_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*meta_ctx.vnode).ops;
        if ops.is_null() {
            emit_ioctl_error(reply_lease, reply_intent, VfsError::NotSup);
            return;
        }
        let vkey = (*meta_ctx.vnode).key;

        let worker_ctx = meta_ctx
            .data_ctx()
            .with_caller_badge(caller_badge)
            .with_open_object(open_h);
        match ((*ops).data.ioctl)(&worker_ctx, cmd, arg) {
            Ok(Ready(reply)) => {
                crate::personality::reply::emit_ioctl(reply_lease, reply_intent, Ok(reply));
            }
            Ok(Parked(handle)) => {
                // A devfs ctty-control ioctl parks on an init session
                // resolve (`Resume::Init`): hand the lease to the init
                // machine, which re-issues the pty ioctl with the resolved
                // session at finalize. Backend ioctls are not init ops, so
                // they fall through to the normal `FillIoctlReply` stamp.
                match crate::owner::init_rpc::attach_ctty_ioctl(state, handle, client, reply_lease)
                {
                    Ok(()) => {}
                    Err(reply_lease) => {
                        let badge = state
                            .clients
                            .get(client)
                            .map(|c| c.client_badge)
                            .unwrap_or(0);
                        if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                            handle,
                            badge,
                            Some(reply_lease),
                            Resume::Fs(FsResume::FillIoctlReply {
                                client,
                                vkey,
                                cmd,
                                reply: reply_intent,
                            }),
                        ) {
                            emit_ioctl_error(reply_lease, reply_intent, VfsError::Busy);
                        }
                    }
                }
            }
            Err(e) => emit_ioctl_error(reply_lease, reply_intent, e),
        }
    }
}

unsafe fn emit_ioctl_error(reply_lease: ReplyLease, reply_intent: IoctlReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ioctl(reply_lease, reply_intent, Err(err));
    }
}
