// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX wire reply emitters.
//!
//! Each emitter consumes a [`trona_server::ReplyLease`] and
//! produces the POSIX-shaped reply for the matching operation.
//! The ops helper layer never reaches `TronaMsg` directly —
//! it produces a [`crate::ops::OpenResult`] / [`VAttr`] /
//! byte count, hands the value plus the originally-attached
//! [`crate::ops::OpenReplyIntent`] / etc. to
//! [`super::reply::emit_open`] / [`super::reply::emit_ack`] etc.,
//! and that dispatcher routes here when the intent is POSIX.
//!
//! Wire shapes:
//!
//! * **error** — `out.label = vfs_error_to_public_reply(err)`,
//!   `out.length = 0`. The basaltc shim maps the public-reply
//!   label back to errno on the caller side.
//! * **ack** — `out.label = VFS_PUBLIC_REPLY_OK`, `out.length = 0`.
//! * **open** — `out.regs[0] = fd`. The
//!   [`crate::ops::OpenCreateAction`] is discarded because
//!   POSIX has no equivalent of NT's create-disposition action
//!   codes.

#![allow(dead_code)]

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::file::{VAttr, VStatfs};
use crate::ipc::protocol::public::vfs_error_to_public_reply;
use crate::ops::OpenResult;
use crate::owner::op::reply_send;
use crate::personality::posix::types::{Dirent, POSIX_NAME_MAX, Stat, Statvfs, Timespec};
use trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;

/// Emit a typed-error reply — POSIX errno-shaped.
///
/// The `vfs_error_to_public_reply` mapping is the authoritative
/// errno surface; the basaltc shim consumes the public-reply
/// label byte and produces the matching `errno` value.
pub(crate) unsafe fn emit_error(reply_lease: ReplyLease, err: VfsError) {
    let mut out = TronaMsg::default();
    out.label = vfs_error_to_public_reply(err);
    out.length = 0;
    reply_send(reply_lease, &out);
}

/// Emit a generic POSIX `errno=0` ack — no body.
pub(crate) unsafe fn emit_ack(reply_lease: ReplyLease) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.length = 0;
    reply_send(reply_lease, &out);
}

/// Emit a successful `open` / `openat` reply: `regs[0] = fd`.
///
/// The [`OpenResult::action`] field is discarded — POSIX surfaces
/// successful opens with the same `errno=0` regardless of whether
/// the leaf was opened or freshly created. NT callers consume the
/// action via [`super::super::win32::reply::emit_create_file_ok`].
pub(crate) unsafe fn emit_open_ok(reply_lease: ReplyLease, result: OpenResult) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.length = 1;
    out.regs[0] = result.fd as u64;
    reply_send(reply_lease, &out);
}

/// Emit a POSIX success reply carrying a single value word in
/// `regs[0]` (e.g. `dup`'s new fd). errno = 0.
pub(crate) unsafe fn emit_value(reply_lease: ReplyLease, value: u64) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.length = 1;
    out.regs[0] = value;
    reply_send(reply_lease, &out);
}

/// Emit a successful `stat` / `lstat` / `fstat` / `fstatat` reply.
///
/// Wire layout (matches the basaltc shim's `struct stat`
/// projection):
/// - `regs[0]` — backend node id (POSIX `st_ino`).
/// - `regs[1]` — POSIX mode word (type bits + permission bits).
/// - `regs[2]` — link count (`st_nlink`).
/// - `regs[3]` — file size in bytes (`st_size`).
/// - `regs[4]` — owner uid (`st_uid`).
/// - `regs[5]` — owner gid (`st_gid`).
/// - `regs[6]` — modify time, seconds since epoch (`st_mtime`).
/// - `regs[7]` — vnode kind discriminator (basaltc projects to
///   `st_dev` heuristics).
pub(crate) unsafe fn emit_stat_ok(reply_lease: ReplyLease, attr: &VAttr) {
    let stat = Stat {
        st_dev: attr.kind as u64,
        st_ino: attr.backend_node_id,
        st_nlink: attr.nlink as u64,
        st_mode: attr.mode,
        st_uid: attr.uid,
        st_gid: attr.gid,
        _pad0: 0,
        st_rdev: 0,
        st_size: attr.size as i64,
        st_blksize: 4096,
        st_blocks: attr.blocks as i64,
        st_atim: nanos_to_timespec(attr.atime),
        st_mtim: nanos_to_timespec(attr.mtime),
        st_ctim: nanos_to_timespec(attr.ctime),
        _unused: [0; 3],
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[0] = stat.st_ino;
    out.regs[1] = stat.st_mode as u64;
    out.regs[2] = stat.st_nlink;
    out.regs[3] = stat.st_size as u64;
    out.regs[4] = stat.st_uid as u64;
    out.regs[5] = stat.st_gid as u64;
    out.regs[6] = stat.st_mtim.tv_sec as u64;
    out.regs[7] = stat.st_dev;
    out.length = 8;
    reply_send(reply_lease, &out);
}

/// Emit a successful `statvfs` / `fstatvfs` reply.
pub(crate) unsafe fn emit_statvfs_ok(reply_lease: ReplyLease, stats: &VStatfs) {
    let statvfs = Statvfs {
        f_bsize: stats.bsize as u64,
        f_frsize: stats.frsize as u64,
        f_blocks: stats.blocks,
        f_bfree: stats.bfree,
        f_bavail: stats.bavail,
        f_files: stats.files,
        f_ffree: stats.ffree,
        f_favail: stats.favail,
        f_fsid: stats.fsid,
        f_flag: stats.flag as u64,
        f_namemax: stats.namemax as u64,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[0] = statvfs.f_bsize;
    out.regs[1] = statvfs.f_frsize;
    out.regs[2] = statvfs.f_blocks;
    out.regs[3] = statvfs.f_bfree;
    out.regs[4] = statvfs.f_bavail;
    out.regs[5] = statvfs.f_files;
    out.regs[6] = statvfs.f_ffree;
    out.regs[7] = statvfs.f_favail;
    out.regs[8] = statvfs.f_fsid;
    out.regs[9] = statvfs.f_flag;
    out.regs[10] = statvfs.f_namemax;
    out.length = 11;
    reply_send(reply_lease, &out);
}

fn nanos_to_timespec(nanos: u64) -> Timespec {
    Timespec {
        tv_sec: (nanos / 1_000_000_000) as i64,
        tv_nsec: (nanos % 1_000_000_000) as i64,
    }
}

/// Emit a successful inline-mode `read` reply.
///
/// Wire layout:
/// - `regs[0]` — bytes_read.
/// - `regs[1..]` — data packed 8 bytes per word, little-endian.
pub(crate) unsafe fn emit_read_inline_ok(reply_lease: ReplyLease, data: &[u8]) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[0] = data.len() as u64;
    let words = (data.len() + 7) / 8;
    for i in 0..words {
        let base = i * 8;
        let take = (data.len() - base).min(8);
        let mut word = [0u8; 8];
        word[..take].copy_from_slice(&data[base..base + take]);
        out.regs[1 + i] = u64::from_le_bytes(word);
    }
    out.length = ((1 + words).min(32)) as u64;
    reply_send(reply_lease, &out);
}

/// Emit a successful SHM-mode `read` reply: `regs[0] =
/// bytes_read`. The data lives in the caller's bulk SHM region
/// already; the reply only carries the byte count.
pub(crate) unsafe fn emit_read_count_ok(reply_lease: ReplyLease, bytes_read: u64) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[0] = bytes_read;
    out.length = 1;
    reply_send(reply_lease, &out);
}

/// Emit a successful `write` reply: `regs[0] = bytes_written`.
pub(crate) unsafe fn emit_write_count_ok(reply_lease: ReplyLease, bytes_written: u64) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[0] = bytes_written;
    out.length = 1;
    reply_send(reply_lease, &out);
}

/// Emit a successful `lseek` reply: `regs[0] = new_offset`.
pub(crate) unsafe fn emit_seek_offset_ok(reply_lease: ReplyLease, new_offset: u64) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[0] = new_offset;
    out.length = 1;
    reply_send(reply_lease, &out);
}

/// Emit a successful `getdents` / `getdents64` reply.
///
/// Wire layout: `regs[0]` = bytes packed; the dirent records
/// themselves live in the bulk SHM region the caller registered
/// (the worker-io readdir bridge writes them there before
/// completion).
pub(crate) unsafe fn emit_dir_count_ok(reply_lease: ReplyLease, bytes_packed: u64) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[0] = bytes_packed;
    out.length = 1;
    reply_send(reply_lease, &out);
}

/// Build the POSIX `dirent64` projection for the first entry in a
/// readdir batch. The compact VFS reply still carries the fields
/// in registers for the current runtime shim, but constructing the
/// ABI object here keeps the record-layout knowledge in the POSIX
/// personality instead of in the shared reply dispatcher.
pub(crate) fn make_dirent_projection(ino: u64, next_cursor: u64, dtype: u8, name: &[u8]) -> Dirent {
    let mut d = Dirent::default();
    let copy_len = name.len().min(POSIX_NAME_MAX);
    d.d_ino = ino;
    d.d_off = next_cursor as i64;
    d.d_reclen = (::core::mem::size_of::<Dirent>() - (POSIX_NAME_MAX + 1) + copy_len + 1) as u16;
    d.d_type = dtype;
    d.d_name[..copy_len].copy_from_slice(&name[..copy_len]);
    d.d_name[copy_len] = 0;
    d
}
