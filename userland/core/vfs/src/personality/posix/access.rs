// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_ACCESS` / `VFS_FACCESSAT` entry.
//!
//! Drives the shared async path-walk seam with
//! `NameiTerminal::Access { mode }`. The walker either lands on
//! `personality::posix::stat::send_access_reply_for_vnode` (sync hit)
//! or stamps `FsResume::FillAccessReply` on the parked PendingOp
//! when the backend round-trip is needed.
//!
//! Wire layout:
//! - `regs[0]` = anchor_fd (i32, `-100` == AT_FDCWD)
//! - `regs[1]` = mode (`R_OK`/`W_OK`/`X_OK`/`F_OK` mask)
//! - `regs[2]` = at_flags (`AT_SYMLINK_NOFOLLOW`, `AT_EACCESS`, …)
//! - `regs[3]` = path_len (u32)
//! - `regs[4..]` = path bytes packed 8 per word

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::owner::pending::{WALK_PATH_MAX, WalkPolicy};
use crate::owner::resume::NameiTerminal;
use crate::personality::posix::namei::begin_path_walk;
use crate::personality::wire::send_reply_err_for_client;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let mode = msg.regs[1] as u32;
        let at_flags = msg.regs[2] as i32;
        let path_len = msg.regs[3] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        let walk_flags = crate::ops::anchor::namei_follow_flags_from_at(at_flags);
        begin_path_walk(
            state,
            client,
            anchor_vkey,
            msg,
            /* path_words_start = */ 4,
            path_len,
            WalkPolicy::FinalMustExist,
            walk_flags,
            NameiTerminal::Access {
                mode,
                reply: AckReplyIntent::PosixAck,
            },
            reply_lease,
        );
    }
}
