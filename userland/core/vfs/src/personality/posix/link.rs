// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_LINK` entry.
//!
//! Wire layout:
//! - `regs[0]` — anchor_fd_old (`linkat`).
//! - `regs[1]` — anchor_fd_new.
//! - `regs[2]` — target_path_len (existing file).
//! - `regs[3]` — link_path_len (new directory entry).
//! - `regs[4]` — flags (`AT_SYMLINK_FOLLOW`).
//! - `regs[5..]` — target path bytes, then link path bytes,
//!   packed little-endian, 8 per word.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::AckReplyIntent;
use crate::ops::anchor::AT_SYMLINK_FOLLOW;
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let anchor_fd_old = msg.regs[0] as i32;
        let anchor_fd_new = msg.regs[1] as i32;
        let target_path_len = msg.regs[2] as usize;
        let link_path_len = msg.regs[3] as usize;
        let flags = msg.regs[4] as u32;
        if target_path_len == 0 || target_path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }
        if link_path_len == 0 || link_path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }

        let mut target_buf = [0u8; WALK_PATH_MAX];
        decode_packed(msg, 5, target_path_len, &mut target_buf);
        let target_words = (target_path_len + 7) / 8;
        let mut link_buf = [0u8; WALK_PATH_MAX];
        decode_packed(msg, 5 + target_words, link_path_len, &mut link_buf);

        let anchor_old_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd_old);
        let anchor_new_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd_new);

        let follow_target = (flags & AT_SYMLINK_FOLLOW as u32) != 0;

        crate::ops::rename_link::do_link_from_paths(
            state,
            client,
            anchor_old_vkey,
            &target_buf[..target_path_len],
            target_path_len,
            anchor_new_vkey,
            &link_buf[..link_path_len],
            link_path_len,
            follow_target,
            /* no_replace = */ true,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}

unsafe fn decode_packed(
    msg: &TronaMsg,
    word_start: usize,
    len: usize,
    dst: &mut [u8; WALK_PATH_MAX],
) {
    let cap = len.min(WALK_PATH_MAX);
    let regs_len = msg.regs.len();
    let mut written = 0usize;
    let mut idx = word_start;
    while written < cap && idx < regs_len {
        let word = msg.regs[idx].to_le_bytes();
        let take = (cap - written).min(8);
        dst[written..written + take].copy_from_slice(&word[..take]);
        written += take;
        idx += 1;
    }
}
