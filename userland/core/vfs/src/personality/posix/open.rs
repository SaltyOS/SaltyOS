// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_OPEN` / `VFS_OPENAT` entry.
//!
//! Wire layout:
//! - `regs[0]` — anchor fd (i32, `-100 == AT_FDCWD`).
//! - `regs[1]` — `O_*` flag word (u32).
//! - `regs[2]` — file mode applied when `O_CREAT` materialises a
//!   new leaf, masked by the caller's umask before reaching the
//!   wire.
//! - `regs[3]` — path byte length (u32).
//! - `regs[4..]` — path bytes, packed little-endian, 8 per word.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{CreateMode, OpenAccess, OpenOptions, OpenReplyIntent, SharePolicy, VfsOpenSpec};
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;

// POSIX `O_*` bits — kept here rather than re-imported so the
// entry is self-contained against a future rewire of the public
// constants module.
const POSIX_O_RDONLY: u32 = 0x0;
const POSIX_O_WRONLY: u32 = 0x1;
const POSIX_O_RDWR: u32 = 0x2;
const POSIX_O_ACCMODE: u32 = 0x3;
const POSIX_O_CREAT: u32 = 0x40;
const POSIX_O_EXCL: u32 = 0x80;
const POSIX_O_TRUNC: u32 = 0x200;
const POSIX_O_APPEND: u32 = 0x400;
const POSIX_O_NONBLOCK: u32 = 0x800;
const POSIX_O_DIRECTORY: u32 = 0x10000;
const POSIX_O_NOFOLLOW: u32 = 0x20000;
const POSIX_O_NOCTTY: u32 = 0x100;
const POSIX_O_SYNC: u32 = 0x101000;
const POSIX_O_DSYNC: u32 = 0x1000;
const POSIX_O_DIRECT: u32 = 0x4000;
const POSIX_O_CLOEXEC: u32 = 0x80000;

/// `VFS_OPEN` / `VFS_OPENAT` entry.
pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let flags = msg.regs[1] as u32;
        let mode = msg.regs[2] as u32;
        let path_len = msg.regs[3] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }

        // Decode path bytes from the wire packing (little-endian,
        // 8 bytes per word, starting at regs[4]).
        let mut path_buf = [0u8; WALK_PATH_MAX];
        let path_words_start = 4usize;
        let mut byte_idx = 0usize;
        while byte_idx < path_len {
            let word_idx = path_words_start + byte_idx / 8;
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
        let spec = posix_flags_to_spec(flags, mode);
        let reply_intent = OpenReplyIntent::PosixOpen;

        crate::ops::open::do_namei_open_from_bytes(
            state,
            client,
            anchor_vkey,
            &path_buf[..path_len],
            path_len,
            spec,
            reply_intent,
            reply_lease,
        );
    }
}

/// Project the caller's POSIX `O_*` flag word + `mode` argument
/// onto a personality-neutral [`VfsOpenSpec`].
///
/// Mapping rules for `CreateMode` from POSIX bits:
/// - `!O_CREAT && !O_TRUNC` → [`CreateMode::Open`]
/// - `!O_CREAT &&  O_TRUNC` → [`CreateMode::Truncate`]
/// - ` O_CREAT && !O_EXCL && !O_TRUNC` → [`CreateMode::OpenAlways`]
/// - ` O_CREAT && !O_EXCL &&  O_TRUNC` → [`CreateMode::CreateAlways`]
/// - ` O_CREAT &&  O_EXCL` → [`CreateMode::Create`] (truncate bit
///   ignored — `O_EXCL` requires the leaf to be freshly created
///   so a no-op truncate has no observable effect)
fn posix_flags_to_spec(flags: u32, mode: u32) -> VfsOpenSpec {
    let access = match flags & POSIX_O_ACCMODE {
        POSIX_O_RDONLY => OpenAccess::Read,
        POSIX_O_WRONLY => OpenAccess::Write,
        POSIX_O_RDWR => OpenAccess::ReadWrite,
        _ => OpenAccess::Read,
    };

    let has_creat = (flags & POSIX_O_CREAT) != 0;
    let has_excl = (flags & POSIX_O_EXCL) != 0;
    let has_trunc = (flags & POSIX_O_TRUNC) != 0;
    let create = if has_creat && has_excl {
        CreateMode::Create
    } else if has_creat && has_trunc {
        CreateMode::CreateAlways
    } else if has_creat {
        CreateMode::OpenAlways
    } else if has_trunc {
        CreateMode::Truncate
    } else {
        CreateMode::Open
    };

    let mut options = OpenOptions::empty();
    if (flags & POSIX_O_NONBLOCK) != 0 {
        options = options.with(OpenOptions::NON_BLOCKING);
    }
    if (flags & POSIX_O_APPEND) != 0 {
        options = options.with(OpenOptions::APPEND);
    }
    if (flags & POSIX_O_DIRECTORY) != 0 {
        options = options.with(OpenOptions::DIRECTORY);
    }
    if (flags & POSIX_O_NOFOLLOW) != 0 {
        options = options.with(OpenOptions::NO_FOLLOW_LEAF);
    }
    if (flags & POSIX_O_NOCTTY) != 0 {
        options = options.with(OpenOptions::NO_CTTY);
    }
    if (flags & (POSIX_O_SYNC | POSIX_O_DSYNC)) != 0 {
        options = options.with(OpenOptions::SYNC_WRITES);
    }
    if (flags & POSIX_O_DIRECT) != 0 {
        options = options.with(OpenOptions::DIRECT);
    }

    let fd_flags = if (flags & POSIX_O_CLOEXEC) != 0 {
        0x01
    } else {
        0
    };

    VfsOpenSpec {
        access,
        create,
        mode,
        share: SharePolicy::permissive(),
        delete_access: false,
        options,
        fd_flags,
    }
}
