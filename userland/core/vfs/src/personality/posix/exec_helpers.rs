// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_STAT_FOR_EXEC` / `VFS_CANON_PATH` — exec-preflight helpers.
//!
//! `stat_for_exec` is the compact metadata fetch the exec path
//! needs: just the bits that gate `exec(2)` (mode for X-bit checks,
//! uid / gid for set-id, size for loader preallocation, mtime for
//! loader-cache invalidation, and the vnode type).
//! Distinct from `VFS_STAT` so the caller can keep the wire payload
//! tight.
//!
//! `canon_path` returns the namei-resolved absolute path string for
//! a (possibly relative or symlink-laden) input path. Callers use
//! this to record the canonical form they should serve future
//! exec-time queries against without forcing a full walk on every
//! check.
//!
//! ## Wire layout
//!
//! `VFS_STAT_FOR_EXEC`:
//!   regs[0] = anchor_fd (i32, AT_FDCWD = -100)
//!   regs[1] = path_len (u32)
//!   regs[2..] = path bytes
//!   reply.regs[0] = mode
//!   reply.regs[1] = uid
//!   reply.regs[2] = gid
//!   reply.regs[3] = size
//!   reply.regs[4] = mtime_ns
//!   reply.regs[5] = type
//!
//! `VFS_CANON_PATH`:
//!   regs[0] = anchor_fd (i32, AT_FDCWD = -100)
//!   regs[1] = path_len (u32)
//!   regs[2..] = path bytes
//!   reply.regs[0] = canon_len
//!   reply.regs[1..] = canonical path bytes packed 8 per word.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::namei_common::NAMEI_FOLLOW;
use crate::owner::VfsState;
use crate::owner::pending::{WALK_PATH_MAX, WalkPolicy};
use crate::owner::resume::NameiTerminal;
use crate::personality::posix::namei::begin_path_walk;
use crate::personality::wire::send_reply_err_for_client;
use crate::server::types::ClientHandle;

// ---------------------------------------------------------------------------
// VFS_STAT_FOR_EXEC
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_stat_for_exec(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let path_len = msg.regs[1] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        begin_path_walk(
            state,
            client,
            anchor_vkey,
            msg,
            /* path_words_start = */ 2,
            path_len,
            WalkPolicy::FinalMustExist,
            NAMEI_FOLLOW,
            NameiTerminal::StatForExec,
            reply_lease,
        );
    }
}

// ---------------------------------------------------------------------------
// VFS_OPEN_FOR_EXEC
// ---------------------------------------------------------------------------

/// `execve` binary open. Same walk as `stat_for_exec` (FinalMustExist,
/// follow symlinks), but the `OpenForExec` terminal checks Regular-file /
/// `MNT_NOEXEC` policy and replies with a non-exec backing MemoryObject.
///
/// Wire: regs[0]=anchor_fd (i32), regs[1]=path_len (u32), regs[2..]=path.
/// Reply: regs[0]=size, regs[1]=image byte offset within the backing MO;
/// caps[0]=non-exec backing MO.
pub(crate) unsafe fn handle_open_for_exec(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let path_len = msg.regs[1] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        begin_path_walk(
            state,
            client,
            anchor_vkey,
            msg,
            /* path_words_start = */ 2,
            path_len,
            WalkPolicy::FinalMustExist,
            NAMEI_FOLLOW,
            NameiTerminal::OpenForExec,
            reply_lease,
        );
    }
}

// ---------------------------------------------------------------------------
// VFS_CANON_PATH
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_canon_path(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let path_len = msg.regs[1] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }

        // Snapshot the input bytes and produce the canonical form
        // before kicking the walker — the walker confirms the path
        // resolves to a live vnode, but the canonical *string* is a
        // pure lexical transformation against the cwd.
        let mut input = [0u8; WALK_PATH_MAX];
        decode_packed_bytes(msg, 2, path_len, &mut input);

        let mut canon = [0u8; WALK_PATH_MAX];
        let canon_len = match crate::personality::posix::cwd::canonicalise_path(
            state,
            client,
            &input[..path_len],
            &mut canon,
        ) {
            Some(n) => n,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::NameTooLong);
                return;
            }
        };

        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        begin_path_walk(
            state,
            client,
            anchor_vkey,
            msg,
            /* path_words_start = */ 2,
            path_len,
            WalkPolicy::FinalMustExist,
            NAMEI_FOLLOW,
            NameiTerminal::CanonPath {
                canon_path: canon,
                canon_len: canon_len as u16,
            },
            reply_lease,
        );
    }
}

pub(crate) unsafe fn send_canon_path_reply(
    state: &mut VfsState,
    client: ClientHandle,
    canon_path: [u8; WALK_PATH_MAX],
    canon_len: u16,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let len = usize::from(canon_len);
        let path_words = (u64::from(canon_len) + 7) / 8;
        if 1 + path_words > 20 {
            send_reply_err_for_client(state, client, reply_lease, VfsError::NameTooLong);
            return;
        }
        let mut out = TronaMsg::default();
        out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
        out.regs[0] = len as u64;
        let dst = &mut out.regs[1] as *mut u64 as *mut u8;
        for i in 0..len {
            *dst.add(i) = canon_path[i];
        }
        out.length = 1 + path_words;
        crate::owner::op::reply_send(reply_lease, &out);
    }
}

unsafe fn decode_packed_bytes(msg: &TronaMsg, word_start: usize, len: usize, dst: &mut [u8]) {
    let cap = len.min(dst.len());
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
