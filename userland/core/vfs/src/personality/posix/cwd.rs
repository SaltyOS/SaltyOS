// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_CHDIR` / `VFS_GETCWD` — per-client working-directory state.
//!
//! `ClientState.cwd_vnode_slot` / `cwd_vnode_epoch` carry the
//! resolved cwd vnode for namei `AT_FDCWD` anchoring. A separate
//! `cwd_path` byte buffer caches the canonical absolute-path string
//! so `getcwd(2)` does not need a backend reverse-walk on every
//! call.
//!
//! ## Wire layout
//!
//! `VFS_CHDIR`:
//!   regs[0] = anchor_fd (i32, AT_FDCWD = -100)
//!   regs[1] = path_len (u32)
//!   regs[2..] = path bytes packed 8 per word
//!
//! `VFS_GETCWD`:
//!   regs[0] = max_len (u32) — caller's reply-buffer cap.
//!   reply.regs[0] = path_len (number of bytes written into
//!                   `regs[1..]`, *excluding* the implicit trailing
//!                   NUL the caller supplies).
//!   reply.regs[1..] = path bytes packed 8 per word.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::namei_common::NAMEI_FOLLOW;
use crate::core::vnode::{VnodeHandle, VnodeKind};
use crate::owner::VfsState;
use crate::owner::pending::{WALK_PATH_MAX, WalkPolicy};
use crate::owner::resume::NameiTerminal;
use crate::personality::posix::namei::begin_path_walk;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

// ---------------------------------------------------------------------------
// VFS_CHDIR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_chdir(
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

        // Snapshot the input path bytes for the post-walk path
        // canonicalisation step. `begin_path_walk` reads them off
        // the same `msg` so we duplicate into a local buffer first.
        let mut path_buf = [0u8; WALK_PATH_MAX];
        decode_packed_bytes(msg, 2, path_len, &mut path_buf);

        // Compose the canonical absolute path now (the namei walk
        // resolves symlinks but does not produce a path string).
        // Failures here are caller errors and skip the walk
        // entirely.
        let mut canon = [0u8; WALK_PATH_MAX];
        let canon_len = match canonicalise_path(state, client, &path_buf[..path_len], &mut canon) {
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
            NameiTerminal::Chdir {
                canon_path: canon,
                canon_len: canon_len as u16,
            },
            reply_lease,
        );
    }
}

/// Terminal callback for `VFS_CHDIR`. Validates that the resolved
/// vnode is a directory, swaps the canonical path snapshot into the
/// client's `cwd_path`, and updates `cwd_vnode_slot` / epoch.
pub(crate) unsafe fn finish_chdir(
    state: &mut VfsState,
    client: ClientHandle,
    target_vh: VnodeHandle,
    canon_path: [u8; WALK_PATH_MAX],
    canon_len: u16,
    reply_lease: trona_server::ReplyLease,
) {
    let vp = match state.vnodes.get(target_vh) {
        Some(v) => v,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
            return;
        }
    };
    if !matches!(vp.kind, VnodeKind::Directory) {
        send_reply_err_for_client(state, client, reply_lease, VfsError::NotDir);
        return;
    }
    let slot_idx = target_vh.slot();
    let slot_epoch = target_vh.epoch();

    let cli = match state.clients.get_mut(client) {
        Some(c) => c,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
            return;
        }
    };
    cli.cwd_vnode_slot = slot_idx;
    cli.cwd_vnode_epoch = slot_epoch;
    cli.cwd_path = canon_path;
    cli.cwd_path_len = canon_len;

    send_reply_ok_for_client(state, client, reply_lease, &[]);
}

// ---------------------------------------------------------------------------
// VFS_GETCWD
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_getcwd(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let max_len = msg.regs[0] as usize;
        let cli = match state.clients.get(client) {
            Some(c) => c,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                return;
            }
        };
        let path_len = cli.cwd_path_len as usize;
        if path_len == 0 {
            // Client never called chdir and `register_client` did
            // not seed the cwd. POSIX `getcwd` returns ENOENT in
            // that pathological case rather than fabricating "/".
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoEnt);
            return;
        }
        if path_len > max_len {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Range);
            return;
        }

        let path_words = (path_len + 7) / 8;
        if 1 + path_words > 20 {
            send_reply_err_for_client(state, client, reply_lease, VfsError::NameTooLong);
            return;
        }

        let mut out = TronaMsg::default();
        out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
        out.regs[0] = path_len as u64;

        let dst = &mut out.regs[1] as *mut u64 as *mut u8;
        for i in 0..path_len {
            *dst.add(i) = cli.cwd_path[i];
        }
        out.length = (1 + path_words) as u64;

        crate::owner::op::reply_send(reply_lease, &out);
    }
}

// ---------------------------------------------------------------------------
// Path canonicalisation (lexical only; symlink expansion is namei's
// responsibility — the resulting cwd vnode is what survives, this
// helper just produces the matching string form).
// ---------------------------------------------------------------------------

/// Build a canonical absolute path by joining `input` against the
/// caller's existing `cwd_path` (when `input` is relative) and
/// folding `.` / `..` / duplicated separators.
///
/// Returns `Some(written_len)` on success, or `None` when the
/// canonical form would exceed `out.len()` (`WALK_PATH_MAX`).
pub(crate) fn canonicalise_path(
    state: &VfsState,
    client: ClientHandle,
    input: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let absolute = !input.is_empty() && input[0] == b'/';
    let mut composed = [0u8; WALK_PATH_MAX * 2];
    let mut composed_len = 0usize;

    if !absolute {
        let cli = state.clients.get(client)?;
        let base = if cli.cwd_path_len > 0 {
            &cli.cwd_path[..cli.cwd_path_len as usize]
        } else {
            b"/" as &[u8]
        };
        if base.len() > composed.len() {
            return None;
        }
        composed[..base.len()].copy_from_slice(base);
        composed_len = base.len();
        if composed_len == 0 || composed[composed_len - 1] != b'/' {
            if composed_len + 1 > composed.len() {
                return None;
            }
            composed[composed_len] = b'/';
            composed_len += 1;
        }
    }
    if composed_len + input.len() > composed.len() {
        return None;
    }
    composed[composed_len..composed_len + input.len()].copy_from_slice(input);
    composed_len += input.len();

    fold_path(&composed[..composed_len], out)
}

/// Lexically fold a path: collapse `//` runs, eliminate `.`
/// components, and resolve `..` against the accumulated parent
/// stack. The input MUST start with `/` (caller guarantees this
/// via `canonicalise_path`).
fn fold_path(input: &[u8], out: &mut [u8]) -> Option<usize> {
    if input.is_empty() || input[0] != b'/' {
        return None;
    }
    let mut written = 1usize;
    if out.is_empty() {
        return None;
    }
    out[0] = b'/';

    let mut i = 1usize;
    while i < input.len() {
        // Skip duplicate separators.
        while i < input.len() && input[i] == b'/' {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        // Find component end.
        let start = i;
        while i < input.len() && input[i] != b'/' {
            i += 1;
        }
        let comp = &input[start..i];

        match comp {
            b"." => {
                // No-op.
            }
            b".." => {
                // Pop one component (down to the leading '/').
                if written > 1 {
                    written -= 1; // drop trailing '/' or last char
                    while written > 1 && out[written - 1] != b'/' {
                        written -= 1;
                    }
                    // Now `written` points one past the surviving
                    // separator, OR equals 1 (root). Rewind off the
                    // separator unless we're already at root.
                    if written > 1 {
                        written -= 1;
                    }
                }
            }
            _ => {
                // Append "/comp".
                if written == 0 || out[written - 1] != b'/' {
                    if written + 1 > out.len() {
                        return None;
                    }
                    out[written] = b'/';
                    written += 1;
                }
                if written + comp.len() > out.len() {
                    return None;
                }
                out[written..written + comp.len()].copy_from_slice(comp);
                written += comp.len();
            }
        }
    }

    // Strip trailing '/' for non-root paths.
    if written > 1 && out[written - 1] == b'/' {
        written -= 1;
    }
    Some(written)
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
