// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_READLINK` handler. Resolves the path through the async
//! namei walker (with `NAMEI_NOFOLLOW_FINAL` so the symlink leaf
//! itself is not followed), then invokes the leaf vnode's
//! `meta.readlink` and surfaces the target bytes inline in the
//! reply IPC buffer.
//!
//! Wire layout:
//! - Request: `regs[0]` = anchor fd (`-100` = `AT_FDCWD`),
//!   `regs[1]` = path_len, `regs[2..]` = path bytes (8 per word).
//! - Reply: `label = VFS_PUBLIC_REPLY_OK`, `regs[0] = bytes_written`,
//!   `regs[1..]` = target bytes inline (8 per word), matching the
//!   client's `posix_readlinkat` decode. Capped at the reply
//!   register payload — the new message-pipe transport does not
//!   carry the IPC buffer's `reserved[]` area to the caller.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::ipc::protocol::public::vfs_error_to_public_reply;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

/// Size of the staging buffer the backend `readlink` op fills. The
/// inline reply emitter further caps what is actually transmitted to
/// the reply register payload, so targets longer than that are
/// truncated on the wire.
pub(crate) const MAX_READLINK_REPLY: usize = 1024;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        // Wire layout:
        //   regs[0]   = anchor_fd (i32, -100 == AT_FDCWD)
        //   regs[1]   = path_len (u32)
        //   regs[2..] = path bytes packed 8 per word
        let anchor_fd = msg.regs[0] as i32;
        let path_len = msg.regs[1] as usize;
        if path_len == 0 || path_len > crate::owner::pending::WALK_PATH_MAX {
            crate::personality::wire::send_reply_err_for_client(
                state,
                client,
                reply_lease,
                VfsError::Inval,
            );
            return;
        }
        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        crate::personality::posix::namei::begin_path_walk(
            state,
            client,
            anchor_vkey,
            msg,
            /* path_words_start = */ 2,
            path_len,
            crate::owner::pending::WalkPolicy::FinalMustExist,
            crate::core::namei_common::NAMEI_NOFOLLOW_FINAL,
            crate::owner::resume::NameiTerminal::Readlink,
            reply_lease,
        );
    }
}

/// Issue `meta.readlink` against `vnode_h` and emit a readlink-
/// shaped reply. Called by the async namei walker once the
/// terminal `NameiTerminal::Readlink` arm fires.
pub(crate) unsafe fn send_readlink_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        // Capture the caller's badge before `from_state` borrows state, so
        // an init-async procfs vop (e.g. /proc/<pid>/exe) can tag its
        // parked op for client-teardown reaping.
        let caller_badge = state
            .clients
            .get(client)
            .map(|c| c.client_badge)
            .unwrap_or(0);
        let cred = state
            .clients
            .get(client)
            .map(|c| c.cred)
            .unwrap_or_else(crate::core::cred::VfsCred::root);
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            out.label = vfs_error_to_public_reply(VfsError::Io);
            crate::owner::op::reply_send(reply_lease, &out);
            return;
        };
        ctx.caller_badge = caller_badge;
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            out.label = vfs_error_to_public_reply(VfsError::Io);
            crate::owner::op::reply_send(reply_lease, &out);
            return;
        }
        let vkey = (*ctx.vnode).key;

        let mut buf = [0u8; MAX_READLINK_REPLY];
        let result = ((*ops).meta.readlink)(&mut ctx, buf.as_mut_ptr(), buf.len(), &raw const cred);
        match result {
            Ok(Ready(len)) => {
                let copy_len = len.min(MAX_READLINK_REPLY);
                // Emit the target inline (`regs[0]=len, regs[1..]=bytes`)
                // — the message-pipe transport delivers only the reply
                // registers, not the IPC buffer's `reserved[]` area, so
                // a `reserved[]` write would never reach the caller. The
                // async resume path uses this same emitter.
                crate::personality::reply::emit_readlink_bytes(
                    reply_lease,
                    crate::personality::Personality::Posix,
                    Ok(&buf[..copy_len]),
                );
            }
            Ok(Parked(handle)) => {
                // init-async procfs reads (e.g. /proc/<pid>/exe) carry
                // `Resume::Init` and own a snapshot that holds the lease
                // across the init-query chain — park it there. Backend
                // readlinks fall through to the normal stamp.
                match crate::owner::init_rpc::attach_lease_if_init(state, handle, reply_lease) {
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
                            crate::owner::resume::Resume::Fs(
                                crate::owner::resume::FsResume::FillReadlinkReply { client, vkey },
                            ),
                        ) {
                            out.label = vfs_error_to_public_reply(VfsError::Busy);
                            crate::owner::op::reply_send(reply_lease, &out);
                        }
                    }
                }
            }
            Err(e) => {
                out.label = vfs_error_to_public_reply(e);
                crate::owner::op::reply_send(reply_lease, &out);
            }
        }
    }
}
