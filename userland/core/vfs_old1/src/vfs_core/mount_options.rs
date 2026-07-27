// SPDX-License-Identifier: GPL-2.0-only
//! Generic mount-option string parser.
//!
//! Mount options arrive as a comma-separated byte slice (e.g.
//! `b"nocase,size=4M,nr_inodes=1024"`). The parser walks the slice once,
//! splits on `,`, and converts the well-known generic tokens into
//! [`Mount::flags`] bits. Backend-specific tokens (`size=`, `nr_inodes=`,
//! `hidepid=`, …) are left intact for the per-backend `alloc_mount` to
//! interpret. Unknown tokens are silently dropped — this matches Linux's
//! permissive behavior and keeps options forward-compatible.

use super::mount::{
    MNT_CASEFOLD, MNT_NOATIME, MNT_NODEV, MNT_NOEXEC, MNT_NOSUID, MNT_NOSYMFOLLOW, MNT_RDONLY,
};

/// Parse a comma-separated option slice into mount flags. Returns the
/// OR of every recognized "set" token (e.g. `ro`, `noatime`); negation
/// tokens (`rw`, `atime`, …) are treated as clears in
/// [`parse_generic_flag_changes`] and ignored here, mirroring the
/// caller-friendly union expected by initial mount setup paths.
pub(crate) fn parse_generic_flags(opts: &[u8]) -> u32 {
    parse_generic_flag_changes(opts).set_mask
}

/// Bitwise diff produced by the option parser. `touched_mask` is the
/// union of every flag the caller named — either to set or to clear —
/// so callers can distinguish "leave alone" from "explicitly cleared".
/// `set_mask` lists the bits the caller asked to enable; `clear_mask`
/// lists the bits asked to disable. The two never overlap because the
/// parser resolves the last token wins.
#[derive(Clone, Copy, Default)]
pub(crate) struct MountFlagChanges {
    pub(crate) set_mask: u32,
    pub(crate) clear_mask: u32,
    pub(crate) touched_mask: u32,
}

/// Walk `opts` once and split tokens into "set" / "clear" buckets. The
/// remount path uses this to merge user-named bits onto the existing
/// mount flag word without touching the rest. Negation tokens
/// (`rw` / `atime` / `dev` / `exec` / `suid`) clear the matching bit;
/// every other recognized token sets it. Last token wins on conflict.
pub(crate) fn parse_generic_flag_changes(opts: &[u8]) -> MountFlagChanges {
    let mut changes = MountFlagChanges::default();
    for_each_token(opts, |token| {
        let (bit, action) = match token {
            b"ro" | b"readonly" => (MNT_RDONLY, FlagAction::Set),
            b"rw" => (MNT_RDONLY, FlagAction::Clear),
            b"nosuid" => (MNT_NOSUID, FlagAction::Set),
            b"suid" => (MNT_NOSUID, FlagAction::Clear),
            b"noexec" => (MNT_NOEXEC, FlagAction::Set),
            b"exec" => (MNT_NOEXEC, FlagAction::Clear),
            b"nodev" => (MNT_NODEV, FlagAction::Set),
            b"dev" => (MNT_NODEV, FlagAction::Clear),
            b"nosymfollow" => (MNT_NOSYMFOLLOW, FlagAction::Set),
            b"symfollow" => (MNT_NOSYMFOLLOW, FlagAction::Clear),
            b"nocase" | b"casefold" => (MNT_CASEFOLD, FlagAction::Set),
            b"case" => (MNT_CASEFOLD, FlagAction::Clear),
            b"noatime" => (MNT_NOATIME, FlagAction::Set),
            b"atime" => (MNT_NOATIME, FlagAction::Clear),
            _ => return,
        };
        changes.touched_mask |= bit;
        match action {
            FlagAction::Set => {
                changes.set_mask |= bit;
                changes.clear_mask &= !bit;
            }
            FlagAction::Clear => {
                changes.clear_mask |= bit;
                changes.set_mask &= !bit;
            }
        }
    });
    changes
}

#[derive(Clone, Copy)]
enum FlagAction {
    Set,
    Clear,
}

/// Run `cb` once for each non-empty comma-separated token in `opts`.
/// Whitespace at either end of a token is trimmed.
pub(crate) fn for_each_token<F: FnMut(&[u8])>(opts: &[u8], mut cb: F) {
    let mut pos = 0usize;
    while pos < opts.len() {
        let start = pos;
        while pos < opts.len() && opts[pos] != b',' {
            pos += 1;
        }
        let token = trim_ascii(&opts[start..pos]);
        if pos < opts.len() {
            pos += 1;
        }
        if !token.is_empty() {
            cb(token);
        }
    }
}

/// Split the value out of a `key=value` token. Returns `None` for
/// flag-style tokens with no `=` separator.
pub(crate) fn split_kv(token: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut idx = 0usize;
    while idx < token.len() {
        if token[idx] == b'=' {
            return Some((trim_ascii(&token[..idx]), trim_ascii(&token[idx + 1..])));
        }
        idx += 1;
    }
    None
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0usize;
    while start < s.len() && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    let mut end = s.len();
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}
