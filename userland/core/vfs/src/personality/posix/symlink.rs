// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_SYMLINK` / `VFS_SYMLINKAT` entry.
//!
//! Wire layout:
//! - `regs[0]` — anchor fd.
//! - `regs[1]` — target byte length.
//! - `regs[2]` — link path byte length.
//! - `regs[3..]` — target bytes, then link path bytes, 8 per word.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::namei_common::NAMEI_NOFOLLOW_FINAL;
use crate::ops::{AckReplyIntent, CreateLeafKind, RenameLinkKind};
use crate::owner::VfsState;
use crate::owner::namei_aux::NameiAuxState;
use crate::owner::pending::{WALK_NAME_MAX, WALK_PATH_MAX, WALK_SYMLINK_TARGET_MAX, WalkPolicy};
use crate::owner::resume::NameiTerminal;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let target_len = msg.regs[1] as usize;
        let link_path_len = msg.regs[2] as usize;
        if target_len == 0 || target_len > WALK_SYMLINK_TARGET_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }
        if link_path_len == 0 || link_path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }

        // Decode target bytes into a buffer, then link path bytes
        // (after the target word block).
        let mut target_buf = [0u8; WALK_SYMLINK_TARGET_MAX];
        decode_into(msg, 3, target_len, &mut target_buf);
        let target_words = (target_len + 7) / 8;
        let mut link_path_buf = [0u8; WALK_PATH_MAX];
        super::wire::decode_path_bytes(msg, 3 + target_words, link_path_len, &mut link_path_buf);

        // Stash target bytes in the namei aux slot — the
        // CreateLeaf terminal callback reads them back and feeds
        // them to `meta.symlink`.
        let Some(aux_h) = state.namei_aux.alloc() else {
            super::reply::emit_error(reply_lease, VfsError::NoMem);
            return;
        };
        if let Some(slot) = state.namei_aux.get_mut(aux_h) {
            *slot = NameiAuxState::Symlink {
                target: target_buf,
                target_len: target_len as u16,
            };
        }

        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        let _ = RenameLinkKind::Rename { no_replace: false };
        crate::core::namei_async::begin_path_walk_from_bytes(
            state,
            client,
            anchor_vkey,
            &link_path_buf[..link_path_len],
            link_path_len,
            WalkPolicy::StopAtParent {
                final_name: [0u8; WALK_NAME_MAX],
                final_name_len: 0,
            },
            NAMEI_NOFOLLOW_FINAL,
            NameiTerminal::CreateLeaf {
                kind: CreateLeafKind::Symlink { mode: 0o777 },
                aux_handle: aux_h,
                reply: AckReplyIntent::PosixAck,
            },
            reply_lease,
        );
    }
}

unsafe fn decode_into(
    msg: &TronaMsg,
    word_start: usize,
    len: usize,
    dst: &mut [u8; WALK_SYMLINK_TARGET_MAX],
) {
    let cap = len.min(WALK_SYMLINK_TARGET_MAX);
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
