// SPDX-License-Identifier: GPL-2.0-only
//
//! Logic helpers shared by POSIX and Win32 personalities.
//!
//! Each helper consumes already-decoded request shapes (e.g.
//! [`spec::VfsOpenSpec`], [`spec::CaseFoldPolicy`]) and drives
//! the vop chain. Wire decode and reply emit live in
//! `personality/{posix,win32}/`.
//!
//! Module-local invariants:
//! - No `kernel IPC message` reference.
//! - No public protocol label constants.
//! - No Windows struct types / POSIX error-code integers; errors flow
//!   through [`crate::core::error::VfsError`].

pub(crate) mod access;
pub(crate) mod anchor;
pub(crate) mod attr;
pub(crate) mod backing_mo;
pub(crate) mod close;
pub(crate) mod create_leaf;
pub(crate) mod dir;
pub(crate) mod dup;
pub(crate) mod fcntl;
pub(crate) mod io;
pub(crate) mod ioctl;
pub(crate) mod lock;
pub(crate) mod open;
pub(crate) mod pipe;
pub(crate) mod rename_link;
pub(crate) mod set_attr;
pub(crate) mod spec;
pub(crate) mod statfs;
pub(crate) mod unlink_leaf;

pub(crate) use crate::personality::reply_intent::{
    AckReplyIntent, AttrReplyIntent, IoctlReplyIntent, OpenReplyIntent, ReadDirReplyIntent,
    ReadReplyIntent, SeekReplyIntent, StatfsReplyIntent, WriteReplyIntent,
};
pub(crate) use spec::{
    CaseFoldPolicy, CreateLeafKind, CreateMode, OpenAccess, OpenCreateAction, OpenOptions,
    OpenResult, RenameLinkKind, SetAttrKind, SharePolicy, UnlinkKind, VfsOpenSpec,
};
