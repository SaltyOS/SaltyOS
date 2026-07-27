// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_UNLINK` / `VFS_RMDIR` entries.
//!
//! Wire layout (both labels):
//! - `regs[0]` — anchor fd (`-100 == AT_FDCWD`).
//! - `regs[1]` — flags (currently unused).
//! - `regs[2]` — path byte length.
//! - `regs[3..]` — path bytes, 8 per word.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::anchor::AT_REMOVEDIR;
use crate::ops::{AckReplyIntent, UnlinkKind};
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;

/// `VFS_UNLINK` entry — file removal (refuses directories).
pub(crate) unsafe fn handle_unlink(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let flags = msg.regs[1] as i32;
        let kind = if (flags & AT_REMOVEDIR) != 0 {
            UnlinkKind::Directory
        } else {
            UnlinkKind::File
        };
        dispatch_path_unlink(state, client, msg, kind, reply_lease);
    }
}

/// `VFS_RMDIR` entry — directory removal (refuses non-directories).
pub(crate) unsafe fn handle_rmdir(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        dispatch_path_unlink(state, client, msg, UnlinkKind::Directory, reply_lease);
    }
}

unsafe fn dispatch_path_unlink(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    kind: UnlinkKind,
    reply_lease: ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let _flags = msg.regs[1] as u32;
        let path_len = msg.regs[2] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }
        let mut path_buf = [0u8; WALK_PATH_MAX];
        let mut byte_idx = 0usize;
        while byte_idx < path_len {
            let word_idx = 3 + byte_idx / 8;
            if word_idx >= msg.regs.len() {
                super::reply::emit_error(reply_lease, VfsError::Inval);
                return;
            }
            let word = msg.regs[word_idx];
            let lane = byte_idx % 8;
            path_buf[byte_idx] = ((word >> (lane * 8)) & 0xff) as u8;
            byte_idx += 1;
        }
        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        crate::ops::unlink_leaf::do_unlink_from_bytes(
            state,
            client,
            anchor_vkey,
            &path_buf[..path_len],
            path_len,
            kind,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}
