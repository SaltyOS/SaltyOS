// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `stat` / `lstat` / `fstat` / `fstatat` entries.
//!
//! Path-based labels:
//! - `VFS_STAT` / `VFS_LSTAT`: `regs[0] = path byte length`,
//!   `regs[1..] = path bytes`, little-endian, 8 per word.
//! - `VFS_FSTATAT`: `regs[0] = anchor fd`, `regs[1] = flags`,
//!   `regs[2] = path byte length`, `regs[3..] = path bytes`.
//!
//! Fd-based label (`VFS_FSTAT`):
//! - `regs[0]` — fd (i32).

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::AttrReplyIntent;
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;
use trona_protocol::vfs::public::{VFS_FSTAT, VFS_FSTATAT, VFS_LSTAT, VFS_STAT};

mod resume;

pub(crate) use self::resume::{
    resume_fill_open_for_exec_access_reply, resume_fill_stat_for_exec_access_reply,
    resume_fill_stat_for_exec_attr_reply, send_open_for_exec_reply_for_vnode,
    send_stat_for_exec_reply_for_vnode,
};

const POSIX_AT_SYMLINK_NOFOLLOW: u32 = 0x100;

/// Single entry covering `VFS_STAT` / `VFS_LSTAT` / `VFS_FSTAT` /
/// `VFS_FSTATAT`. The label discriminates path vs fd vs follow vs
/// nofollow.
pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        match msg.label {
            VFS_FSTAT => handle_fstat(state, client, msg, reply_lease),
            VFS_STAT => handle_path_stat(
                state,
                client,
                msg,
                /* follow_leaf = */ true,
                /* path_words_start = */ 1,
                reply_lease,
            ),
            VFS_LSTAT => handle_path_stat(
                state,
                client,
                msg,
                /* follow_leaf = */ false,
                /* path_words_start = */ 1,
                reply_lease,
            ),
            VFS_FSTATAT => {
                let flags = msg.regs[1] as u32;
                let follow = (flags & POSIX_AT_SYMLINK_NOFOLLOW) == 0;
                handle_path_stat(
                    state,
                    client,
                    msg,
                    follow,
                    /* path_words_start = */ 3,
                    reply_lease,
                );
            }
            _ => super::reply::emit_error(reply_lease, VfsError::Inval),
        }
    }
}

/// `VFS_FSTAT` — fd-based.
unsafe fn handle_fstat(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        if fd < 0 {
            super::reply::emit_error(reply_lease, VfsError::BadF);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            super::reply::emit_error(reply_lease, VfsError::BadF);
            return;
        };
        let vnode_h = match state.open_objects.get(open_h) {
            Some(obj) => obj.vnode,
            None => {
                super::reply::emit_error(reply_lease, VfsError::BadF);
                return;
            }
        };
        crate::ops::attr::do_getattr_for_vnode(
            state,
            client,
            vnode_h,
            AttrReplyIntent::PosixStat,
            reply_lease,
        );
    }
}

/// `VFS_STAT` / `VFS_LSTAT` / `VFS_FSTATAT` — path-based.
///
/// `path_words_start` — `VFS_STAT` / `VFS_LSTAT` use offset 1
/// (no anchor or flags slot); `VFS_FSTATAT` uses 3 (anchor at
/// regs[0], flags at regs[1], path_len at regs[2], path bytes
/// from regs[3]).
unsafe fn handle_path_stat(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    follow_leaf: bool,
    path_words_start: usize,
    reply_lease: ReplyLease,
) {
    unsafe {
        let (anchor_fd, path_len, payload_start) = match path_words_start {
            // VFS_STAT / VFS_LSTAT: regs[0]=path_len, regs[1..]=path.
            1 => {
                let path_len = msg.regs[0] as usize;
                (-100i32, path_len, 1usize)
            }
            // VFS_FSTATAT: regs[0]=anchor, regs[1]=flags,
            //              regs[2]=path_len, regs[3..]=path.
            3 => {
                let anchor = msg.regs[0] as i32;
                let path_len = msg.regs[2] as usize;
                (anchor, path_len, 3usize)
            }
            _ => {
                super::reply::emit_error(reply_lease, VfsError::Inval);
                return;
            }
        };
        if path_len == 0 || path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }

        let mut path_buf = [0u8; WALK_PATH_MAX];
        let mut byte_idx = 0usize;
        while byte_idx < path_len {
            let word_idx = payload_start + byte_idx / 8;
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

        crate::ops::attr::do_getattr_from_bytes(
            state,
            client,
            anchor_vkey,
            &path_buf[..path_len],
            path_len,
            follow_leaf,
            AttrReplyIntent::PosixStat,
            reply_lease,
        );
    }
}
