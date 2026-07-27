// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_MKDIR` / `VFS_MKDIRAT` entry.
//!
//! Wire layout:
//! - `regs[0]` — anchor fd (`mkdirat`).
//! - `regs[1]` — mode.
//! - `regs[2]` — path byte length.
//! - `regs[3..]` — path bytes, 8 per word.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{AckReplyIntent, CreateLeafKind};
use crate::owner::VfsState;
use crate::owner::namei_aux::NameiAuxHandle;
use crate::owner::pending::WALK_PATH_MAX;
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
        let path_len = msg.regs[2] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }
        let mut path_buf = [0u8; WALK_PATH_MAX];
        super::wire::decode_path_bytes(msg, 3, path_len, &mut path_buf);
        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        crate::ops::create_leaf::do_create_leaf_from_bytes(
            state,
            client,
            anchor_vkey,
            &path_buf[..path_len],
            path_len,
            CreateLeafKind::Mkdir { mode },
            NameiAuxHandle::INVALID,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}
