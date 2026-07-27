// SPDX-License-Identifier: GPL-2.0-only
//
//! Backend-facing wire labels (block 0x600..=0x6FF), payload
//! primitives, and feature flags.
//!
//! These are the labels vfs invokes against backend service-EPs
//! (saltyfs daemon, netsrv, posix_ttysrv pty pair, blkdrv, etc.)
//! and the matching reply labels backends echo. The set is the
//! union of every backend's supported operations; each backend
//! handler picks the subset relevant to its session kind.
//!
//! The wire numerics, payload structs, register layout, and
//! feature flags all live in `trona_protocol` so backend daemons
//! that cannot depend on this crate (saltyfs, future ext4) reach
//! the same definitions through the substrate. This module is
//! the vfs-side `pub use` view that lets the rest of vfs spell
//! the labels without naming `trona_protocol::` everywhere.
//!
//! `TransferDescriptor` is the wire shape every backend READ /
//! WRITE / READDIR / XATTR call uses to point at the
//! per-mount-instance SHM ring slot that carries the payload.
//! All bulk payloads ride through SHM — there is no inline-regs
//! fast path. The Zircon-VMO equivalent: one mechanism, used
//! uniformly, so the completion router has a single decode path
//! and the dispatcher's stack carries no fixed-cap inline buffer.

pub(crate) use trona_protocol::posix::{
    BACKEND_CLOSE_SESSION, BACKEND_CREATE, BACKEND_DRAIN, BACKEND_FSYNC, BACKEND_GETINFO,
    BACKEND_GETXATTR, BACKEND_LINK, BACKEND_LISTXATTR, BACKEND_LOOKUP, BACKEND_MKDIR, BACKEND_READ,
    BACKEND_READDIR, BACKEND_READLINK, BACKEND_REMOVEXATTR, BACKEND_RENAME, BACKEND_RMDIR,
    BACKEND_RW_REQ_DESCRIPTOR_REG, BACKEND_SETATTR, BACKEND_SETXATTR, BACKEND_STAT,
    BACKEND_SYMLINK, BACKEND_TRUNCATE, BACKEND_UNLINK, BACKEND_WRITE, SETATTR_MASK_ATIME,
    SETATTR_MASK_GID, SETATTR_MASK_MODE, SETATTR_MASK_MTIME, SETATTR_MASK_UID, TransferDescriptor,
    VFS_BACKEND_REPLY_BUSY, VFS_BACKEND_REPLY_EXIST, VFS_BACKEND_REPLY_INVALID,
    VFS_BACKEND_REPLY_IO_ERROR, VFS_BACKEND_REPLY_IS_DIR, VFS_BACKEND_REPLY_LOOP,
    VFS_BACKEND_REPLY_NAME_TOO_LONG, VFS_BACKEND_REPLY_NO_SPACE, VFS_BACKEND_REPLY_NOT_DIR,
    VFS_BACKEND_REPLY_NOT_EMPTY, VFS_BACKEND_REPLY_NOT_FOUND, VFS_BACKEND_REPLY_NOT_SUPPORTED,
    VFS_BACKEND_REPLY_OK, VFS_BACKEND_REPLY_PERM, VFS_BACKEND_REPLY_QUOTA, VFS_BACKEND_REPLY_RO_FS,
    VFS_BACKEND_REPLY_X_DEV,
};
