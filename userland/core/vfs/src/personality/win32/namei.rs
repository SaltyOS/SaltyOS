// SPDX-License-Identifier: GPL-2.0-only
//
//! Win32 path-policy decisions — drive-letter resolution,
//! `\\?\`-prefixed extended-length paths, UNC `\\server\share`,
//! DOS reserved names, separator normalisation. The personality
//! layer hands the cleaned components to `core::namei_async`
//! for the actual walk; this module only decides *what* to walk.
//!
//! The vnode core stays personality-neutral, so the same node is
//! reachable from POSIX and Win32 callers through their own path
//! policy modules.
#![allow(dead_code)]

/// Path classification — the dispatch layer routes the parsed
/// remainder onto the matching mount-namespace lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Win32PathKind {
    /// `C:\foo\bar` — drive-letter rooted. Drive index in the
    /// payload (0 = A, 1 = B, …).
    DriveAbsolute { drive_index: u8 },
    /// `\foo\bar` — current-drive rooted. Resolves against the
    /// caller's per-process current drive.
    CurrentDriveRooted,
    /// `foo\bar` — relative to current working directory of the
    /// current drive.
    Relative,
    /// `\\?\C:\foo` — extended-length drive path. Bypasses
    /// normalisation and the `MAX_PATH` cap.
    ExtendedLengthDrive { drive_index: u8 },
    /// `\\?\UNC\server\share\foo` — extended-length UNC.
    ExtendedLengthUnc,
    /// `\\server\share\foo` — UNC.
    Unc,
    /// `\\.\NUL`, `\\.\COM1`, `\\.\PIPE\name` — device namespace.
    DosDevice,
    /// `con`, `nul`, `prn`, `com1`..=`com9`, `lpt1`..=`lpt9` —
    /// DOS reserved names. Resolved to the matching device entry,
    /// not to a regular file.
    DosReserved { kind: DosReservedKind },
}

/// Reserved DOS device names. Win32 resolves these to the
/// equivalent device regardless of the directory component
/// supplied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DosReservedKind {
    Con,
    Nul,
    Prn,
    Aux,
    /// `COM1`..=`COM9`. The number is in `1..=9`.
    Com(u8),
    /// `LPT1`..=`LPT9`. The number is in `1..=9`.
    Lpt(u8),
}

/// Classify a UTF-16 path against the Win32 rules. Returns the
/// path kind and the offset (in UTF-16 chars) where the actual
/// path component start — anything before that offset is prefix
/// metadata (drive letter, `\\?\`, UNC head).
///
/// On malformed input (e.g. `\\?\` with no body, drive letter
/// with no colon) the function returns `None`; the dispatcher
/// translates that to `STATUS_OBJECT_PATH_SYNTAX_BAD`.
pub(crate) fn classify_path_utf16(_path: &[u16]) -> Option<(Win32PathKind, usize)> {
    // Implementation lands when the Win32 dispatch entry is wired —
    // the design specifies the rules above so future work fills in
    // the parser without revisiting policy.
    None
}
