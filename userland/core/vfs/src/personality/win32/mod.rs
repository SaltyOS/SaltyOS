// SPDX-License-Identifier: GPL-2.0-only
//
//! Win32 personality. Owns the NT wire types (FILE_ATTRIBUTE_*,
//! ACCESS_MASK / GENERIC_*, FILE_SHARE_*, CreateOptions /
//! CreateDisposition), drive-letter resolution, and the namei
//! rules (case-insensitive with preservation, `\` separators,
//! `\\?\` extended-length prefix, UNC paths, DOS reserved names
//! CON / NUL / PRN / AUX / COM1..=COM9 / LPT1..=LPT9).
//!
//! Filesystems that need to present an NT-style ABI to Win32
//! processes see the world through this module. The vnode core
//! stays personality-neutral so the same node is also reachable
//! from `personality/posix`.
//!
//! Built up incrementally — the present skeleton carries the
//! constant + type modules; the namei + dispatch entry points
//! land alongside the `0x540..=0x57F` label range as Win32 PE
//! processes start reaching vfs.

pub(crate) mod attr;
pub(crate) mod casefold;
pub(crate) mod close;
pub(crate) mod consts;
pub(crate) mod create_leaf;
pub(crate) mod create_pipe;
pub(crate) mod create_section;
pub(crate) mod cwd_table;
pub(crate) mod device_io_control;
pub(crate) mod dir;
pub(crate) mod dispatch;
pub(crate) mod drives;
pub(crate) mod duplicate;
pub(crate) mod io;
pub(crate) mod lifecycle;
pub(crate) mod lock;
pub(crate) mod namei;
pub(crate) mod nt_decode;
pub(crate) mod nt_reply;
pub(crate) mod open;
pub(crate) mod open_state;
pub(crate) mod path;
pub(crate) mod policy;
pub(crate) mod rename;
pub(crate) mod reply;
pub(crate) mod reserved;
pub(crate) mod security;
pub(crate) mod set_information;
pub(crate) mod statvfs;
pub(crate) mod types;
pub(crate) mod unlink;
pub(crate) mod utf16;
