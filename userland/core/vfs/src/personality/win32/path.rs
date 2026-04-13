// SPDX-License-Identifier: GPL-2.0-only
//! Win32 path canonicalization helpers.
//!
//! Win32 paths have several quirks that must be normalized before the
//! component walk in `namei_win32`:
//!
//! - Backslash (`\`) is an alternative path separator (normalized to `/`).
//! - `\\?\` and `\\.\` prefixes bypass certain checks and raise the
//!   MAX_PATH limit.
//! - Trailing dots and spaces on each component are silently stripped
//!   (except under `\\?\`).
//! - A set of characters (< > : " | ? *) is forbidden in component names
//!   (except under `\\?\`).
//! - Path length is capped at 260 (MAX_PATH) without prefix, or 32767
//!   with `\\?\` prefix.

use crate::vfs_core::error::{VfsError, VfsResult};

/// Win32 MAX_PATH (without \\?\ prefix).
pub(crate) const MAX_PATH_WIN32: usize = 260;

/// Win32 extended-length path limit (with \\?\ prefix).
pub(crate) const MAX_PATH_WIN32_LONG: usize = 32767;

/// Result of stripping an NT prefix from a Win32 path.
pub(crate) struct NtPrefixResult {
    /// Whether a prefix was found (\\?\ or \\.\).
    pub(crate) had_prefix: bool,
    /// Whether the prefix was \\?\ (verbatim — disables canonicalization).
    pub(crate) is_verbatim: bool,
    /// Whether the path targets the named pipe namespace (`\\.\pipe\`).
    /// When true, `offset` points past `\\.\pipe\` so the remaining bytes
    /// are the pipe name.
    pub(crate) is_pipe_ns: bool,
    /// Offset into the original path where the stripped content begins.
    pub(crate) offset: usize,
}

/// Check for and strip `\\?\` or `\\.\` prefixes from a Win32 path.
///
/// Win32 paths may be preceded by:
/// - `\\?\` — verbatim (extended-length): no canonicalization, 32767 limit
/// - `\\.\` — device namespace: similar treatment
///
/// Both backslash and forward-slash variants are recognized (the path may
/// have already been partially normalized).
///
/// # Safety
///
/// `path` must point to at least `len` readable bytes.
pub(crate) unsafe fn strip_nt_prefix(path: *const u8, len: usize) -> NtPrefixResult {
    if len < 4 {
        return NtPrefixResult {
            had_prefix: false,
            is_verbatim: false,
            is_pipe_ns: false,
            offset: 0,
        };
    }

    unsafe {
        let b0 = *path;
        let b1 = *path.add(1);
        let b2 = *path.add(2);
        let b3 = *path.add(3);

        let is_sep = |b: u8| b == b'\\' || b == b'/';

        // \\?\ or //?/
        if is_sep(b0) && is_sep(b1) && b2 == b'?' && is_sep(b3) {
            return NtPrefixResult {
                had_prefix: true,
                is_verbatim: true,
                is_pipe_ns: false,
                offset: 4,
            };
        }

        // \\.\ or //./
        if is_sep(b0) && is_sep(b1) && b2 == b'.' && is_sep(b3) {
            // Check for \\.\pipe\ — named pipe namespace.
            // After the 4-byte prefix, look for "pipe" followed by a separator.
            let pipe_ns = is_pipe_prefix(path.add(4), len - 4);
            if pipe_ns {
                // Offset past "\\.\pipe\" (4 + 5 = 9 bytes).
                return NtPrefixResult {
                    had_prefix: true,
                    is_verbatim: false,
                    is_pipe_ns: true,
                    offset: 9,
                };
            }

            return NtPrefixResult {
                had_prefix: true,
                is_verbatim: false,
                is_pipe_ns: false,
                offset: 4,
            };
        }

        NtPrefixResult {
            had_prefix: false,
            is_verbatim: false,
            is_pipe_ns: false,
            offset: 0,
        }
    }
}

/// Check whether `buf[..len]` starts with `pipe\` or `pipe/`
/// (case-insensitive on the "pipe" portion).
unsafe fn is_pipe_prefix(buf: *const u8, len: usize) -> bool {
    if len < 5 {
        return false;
    }
    unsafe {
        let to_lower = |b: u8| if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        to_lower(*buf) == b'p'
            && to_lower(*buf.add(1)) == b'i'
            && to_lower(*buf.add(2)) == b'p'
            && to_lower(*buf.add(3)) == b'e'
            && (*buf.add(4) == b'\\' || *buf.add(4) == b'/')
    }
}

/// Normalize path separators: backslash → forward slash.
///
/// Copies `src[..len]` into `dst`, replacing `\` with `/`. Collapses
/// runs of consecutive separators into a single `/`.
///
/// Returns the number of bytes written to `dst`.
///
/// # Safety
///
/// - `src` must point to at least `len` readable bytes.
/// - `dst` must point to at least `len` writable bytes.
pub(crate) unsafe fn normalize_separators(
    src: *const u8,
    len: usize,
    dst: *mut u8,
) -> usize {
    unsafe {
        let mut out = 0usize;
        let mut prev_sep = false;

        let mut i = 0;
        while i < len {
            let b = *src.add(i);
            let is_sep = b == b'\\' || b == b'/';

            if is_sep {
                if !prev_sep {
                    *dst.add(out) = b'/';
                    out += 1;
                }
                prev_sep = true;
            } else {
                *dst.add(out) = b;
                out += 1;
                prev_sep = false;
            }
            i += 1;
        }

        out
    }
}

/// Trim trailing dots and spaces from a path component.
///
/// Win32 silently strips trailing `.` and ` ` (space) from filename
/// components. This allows `"readme.txt."` to resolve to `"readme.txt"`.
///
/// Returns the trimmed slice. If the entire component is dots/spaces,
/// returns an empty slice.
pub(crate) fn trim_trailing_dots_spaces(comp: &[u8]) -> &[u8] {
    let mut end = comp.len();
    while end > 0 && (comp[end - 1] == b'.' || comp[end - 1] == b' ') {
        end -= 1;
    }
    &comp[..end]
}

/// Validate that a path component does not contain forbidden Win32
/// characters: `< > : " | ? *`
///
/// These characters are reserved by the Win32 API and cannot appear in
/// filenames. The colon `:` is also forbidden because it's the drive
/// letter separator (and alternate data stream separator on NTFS).
///
/// Returns `Ok(())` if valid, `Err(VfsError::Inval)` if any forbidden
/// character is found.
pub(crate) fn validate_no_forbidden_chars(comp: &[u8]) -> VfsResult<()> {
    for &b in comp {
        match b {
            b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*' => {
                return Err(VfsError::Inval);
            }
            // Control characters (0x00-0x1F) are also forbidden.
            0x00..=0x1F => {
                return Err(VfsError::Inval);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Check whether a path length is within the Win32 limit.
///
/// - Without a prefix: MAX_PATH (260)
/// - With `\\?\` prefix: MAX_PATH_WIN32_LONG (32767)
pub(crate) fn check_path_length(len: usize, had_nt_prefix: bool) -> VfsResult<()> {
    let limit = if had_nt_prefix {
        MAX_PATH_WIN32_LONG
    } else {
        MAX_PATH_WIN32
    };
    if len > limit {
        Err(VfsError::NameTooLong)
    } else {
        Ok(())
    }
}
