// SPDX-License-Identifier: GPL-2.0-only
//! Win32 personality — path resolution, drive mapping, reserved names,
//! DOS attributes, NT security, open arbitration, and error mapping.
//!
//! Win32 path semantics differ from POSIX in several ways:
//!
//! - Backslash (`\`) is a path separator (in addition to `/`).
//! - Paths may begin with a drive letter (`C:\`).
//! - `\\?\` and `\\.\` prefixes enable extended-length paths and device
//!   namespace access.
//! - Component names are case-insensitive (exact first, then CI fallback).
//! - Certain names (CON, NUL, COM1-9, LPT1-9, AUX, PRN) are reserved
//!   and always redirect to device nodes.
//! - Trailing dots and spaces are stripped from component names.
//! - Characters `< > : " | ? *` are forbidden in filenames.
//! - MAX_PATH is 260 without prefix, 32767 with `\\?\`.
//! - Mounts marked `MNT_POSIX_ONLY` are invisible during path walks.

pub(crate) mod casefold;
pub(crate) mod cwd_table;
pub(crate) mod dispatch;
pub(crate) mod drives;
pub(crate) mod errno;
pub(crate) mod namei;
pub(crate) mod path;
pub(crate) mod policy;
pub(crate) mod reserved;
pub(crate) mod security;
