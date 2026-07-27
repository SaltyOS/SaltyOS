// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_RENAME` entry.
//!
//! Wire layout:
//! - `regs[0]` — anchor_fd_old (`renameat`).
//! - `regs[1]` — anchor_fd_new.
//! - `regs[2]` — old_path_len.
//! - `regs[3]` — new_path_len.
//! - `regs[4..]` — old path bytes, then new path bytes, packed
//!   little-endian, 8 per word.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::AckReplyIntent;
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
        let old_path_len = msg.regs[2] as usize;
        let new_path_len = msg.regs[3] as usize;
        if old_path_len == 0 || old_path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }
        if new_path_len == 0 || new_path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }

        let mut old_path_buf = [0u8; WALK_PATH_MAX];
        decode_packed(msg, 4, old_path_len, &mut old_path_buf);
        let old_path_words = (old_path_len + 7) / 8;
        let mut new_path_buf = [0u8; WALK_PATH_MAX];
        decode_packed(msg, 4 + old_path_words, new_path_len, &mut new_path_buf);

        let anchor_old_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd_old);
        let anchor_new_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd_new);

        crate::ops::rename_link::do_rename_from_paths(
            state,
            client,
            anchor_old_vkey,
            &old_path_buf[..old_path_len],
            old_path_len,
            anchor_new_vkey,
            &new_path_buf[..new_path_len],
            new_path_len,
            /* no_replace = */ false,
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
