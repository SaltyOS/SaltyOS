// SPDX-License-Identifier: GPL-2.0-only
//
//! VFS-local public-reply helpers.
//!
//! Cross-process labels and payload limits live in
//! `trona_protocol::vfs::public`. This module only translates the
//! server's personality-neutral [`VfsError`] into those protocol reply
//! labels.

use trona_protocol::vfs::public::{
    VFS_PUBLIC_REPLY_AGAIN, VFS_PUBLIC_REPLY_BAD_F, VFS_PUBLIC_REPLY_BUSY, VFS_PUBLIC_REPLY_EXIST,
    VFS_PUBLIC_REPLY_INTR, VFS_PUBLIC_REPLY_INVALID, VFS_PUBLIC_REPLY_IO_ERROR,
    VFS_PUBLIC_REPLY_IS_DIR, VFS_PUBLIC_REPLY_LOOP, VFS_PUBLIC_REPLY_NAME_TOO_LONG,
    VFS_PUBLIC_REPLY_NO_MEM, VFS_PUBLIC_REPLY_NOT_DIR, VFS_PUBLIC_REPLY_NOT_EMPTY,
    VFS_PUBLIC_REPLY_NOT_FOUND, VFS_PUBLIC_REPLY_NOT_SUPPORTED, VFS_PUBLIC_REPLY_NOT_TTY,
    VFS_PUBLIC_REPLY_PERM, VFS_PUBLIC_REPLY_PREDECESSOR_FAILED, VFS_PUBLIC_REPLY_QUOTA,
    VFS_PUBLIC_REPLY_RANGE, VFS_PUBLIC_REPLY_RO_FS, VFS_PUBLIC_REPLY_SESSION_TORN_DOWN,
    VFS_PUBLIC_REPLY_STALE_INCARNATION, VFS_PUBLIC_REPLY_TIMED_OUT, VFS_PUBLIC_REPLY_X_DEV,
};

/// Translate a [`VfsError`] into the matching client-facing reply
/// label. Single server-side source for the VFS error projection; the
/// numeric labels themselves are owned by `trona_protocol`.
#[inline]
pub(crate) const fn vfs_error_to_public_reply(err: crate::core::error::VfsError) -> u64 {
    use crate::core::error::VfsError as E;
    match err {
        E::BadF => VFS_PUBLIC_REPLY_BAD_F,
        E::Acces => VFS_PUBLIC_REPLY_PERM,
        E::Busy => VFS_PUBLIC_REPLY_BUSY,
        E::Exist => VFS_PUBLIC_REPLY_EXIST,
        E::NotEmpty => VFS_PUBLIC_REPLY_NOT_EMPTY,
        E::XDev => VFS_PUBLIC_REPLY_X_DEV,
        E::Io => VFS_PUBLIC_REPLY_IO_ERROR,
        E::IsDir => VFS_PUBLIC_REPLY_IS_DIR,
        E::NotDir => VFS_PUBLIC_REPLY_NOT_DIR,
        E::NoMem => VFS_PUBLIC_REPLY_NO_MEM,
        E::Inval => VFS_PUBLIC_REPLY_INVALID,
        E::NoEnt => VFS_PUBLIC_REPLY_NOT_FOUND,
        E::Loop => VFS_PUBLIC_REPLY_LOOP,
        E::NotSup => VFS_PUBLIC_REPLY_NOT_SUPPORTED,
        E::NameTooLong => VFS_PUBLIC_REPLY_NAME_TOO_LONG,
        E::RoFs => VFS_PUBLIC_REPLY_RO_FS,
        E::Again => VFS_PUBLIC_REPLY_AGAIN,
        E::Intr => VFS_PUBLIC_REPLY_INTR,
        E::SessionTornDown => VFS_PUBLIC_REPLY_SESSION_TORN_DOWN,
        E::PredecessorFailed => VFS_PUBLIC_REPLY_PREDECESSOR_FAILED,
        E::StaleIncarnation => VFS_PUBLIC_REPLY_STALE_INCARNATION,
        E::Quota => VFS_PUBLIC_REPLY_QUOTA,
        E::TimedOut => VFS_PUBLIC_REPLY_TIMED_OUT,
        E::NotTty => VFS_PUBLIC_REPLY_NOT_TTY,
        E::Range => VFS_PUBLIC_REPLY_RANGE,
    }
}
