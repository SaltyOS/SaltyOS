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

use crate::core::error::{VfsError, VfsResult};
use crate::core::identity::VnodeKey;

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
pub(crate) unsafe fn normalize_separators(src: *const u8, len: usize, dst: *mut u8) -> usize {
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

/// Canonical NT path plus the namei anchor it must be resolved
/// against. `anchor_vkey == VnodeKey::NONE` means the path is
/// already rooted in the global namespace; otherwise `bytes` is a
/// relative path to walk from the supplied per-drive cwd.
pub(crate) struct CanonicalNtPath<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) anchor_vkey: VnodeKey,
}

/// Canonicalise an NT-shaped UTF-8 path into a saltyos namei
/// walker-shaped absolute path. Pipeline:
///
/// 1. Strip `\\?\` / `\\.\` prefix via [`strip_nt_prefix`].
/// 2. Replace `\` with `/` via [`normalize_separators`] (also
///    collapses runs of consecutive separators).
/// 3. Resolve the leading drive letter (`C:` → `/c`). The
///    saltyos drive table picks up each mounted drive at boot;
///    callers that hit an unbound letter receive
///    `VfsError::NoEnt`.
/// 4. Validate length + forbidden characters.
///
/// Returns the canonical UTF-8 path written into `dst`. The
/// caller owns `dst`; the returned slice borrows from it.
///
/// # Safety
///
/// `dst` must have at least `src.len() + 4` bytes (enough room
/// for the worst-case `/d/<rest>` expansion of a drive letter).
pub(crate) unsafe fn canonicalize_nt_path<'a>(
    src: &[u8],
    drives: &super::drives::DriveTable,
    drive_cwds: &[VnodeKey; super::drives::DRIVE_LETTER_COUNT],
    dst: &'a mut [u8],
) -> VfsResult<CanonicalNtPath<'a>> {
    if src.is_empty() {
        return Err(VfsError::Inval);
    }
    if dst.len() < src.len() + 4 {
        return Err(VfsError::NameTooLong);
    }

    // 1. Strip NT prefix.
    let prefix = unsafe { strip_nt_prefix(src.as_ptr(), src.len()) };
    let after_prefix = &src[prefix.offset..];

    // Reject `\\.\pipe\...` — pipe namespace not yet wired into
    // canonicalisation; the dispatcher should route those to the
    // pipe path before calling here.
    if prefix.is_pipe_ns {
        return Err(VfsError::NotSup);
    }

    // 2. Normalise separators into a scratch buffer.
    let mut sep_scratch = [0u8; MAX_PATH_WIN32_LONG];
    if after_prefix.len() > sep_scratch.len() {
        return Err(VfsError::NameTooLong);
    }
    let normalised_len = unsafe {
        normalize_separators(
            after_prefix.as_ptr(),
            after_prefix.len(),
            sep_scratch.as_mut_ptr(),
        )
    };
    let normalised = &sep_scratch[..normalised_len];

    // 3. Drive-letter resolution. `C:/foo/bar` → `/c/foo/bar`;
    // `C:foo` walks from C:'s recorded cwd when one exists.
    let mut out_len = 0usize;
    let mut anchor_vkey = VnodeKey::NONE;
    let mut anchored_relative = false;
    let resolved_tail = if normalised.len() >= 2 && normalised[1] == b':' {
        let letter = normalised[0];
        let Some(drive_idx) = super::casefold::drive_letter_index(letter) else {
            return Err(VfsError::Inval);
        };
        let slot = drives.lookup(drive_idx as u8);
        if !slot.is_assigned() {
            return Err(VfsError::NoEnt);
        }
        let mut rest = &normalised[2..];
        if !rest.is_empty() && rest[0] == b'/' {
            emit_drive_prefix(dst, &mut out_len, drive_idx as u8)?;
            rest = &rest[1..];
        } else if let Some(vkey) = drive_cwds
            .get(drive_idx)
            .copied()
            .filter(|vkey| vkey.is_valid())
        {
            anchor_vkey = vkey;
            anchored_relative = true;
        } else {
            emit_drive_prefix(dst, &mut out_len, drive_idx as u8)?;
        }
        rest
    } else if !normalised.is_empty() && normalised[0] == b'/' {
        // Root-relative path (`\foo`) is rooted at the current
        // Win32 drive, not at the neutral namespace root.
        let drive_idx = current_drive_index(drives)?;
        if !drives.lookup(drive_idx).is_assigned() {
            return Err(VfsError::NoEnt);
        }
        emit_drive_prefix(dst, &mut out_len, drive_idx)?;
        &normalised[1..]
    } else {
        // Plain relative path: walk from current-drive cwd when
        // present, otherwise fall back to that drive's root.
        let drive_idx = current_drive_index(drives)?;
        if !drives.lookup(drive_idx).is_assigned() {
            return Err(VfsError::NoEnt);
        }
        if let Some(vkey) = drive_cwds
            .get(drive_idx as usize)
            .copied()
            .filter(|vkey| vkey.is_valid())
        {
            anchor_vkey = vkey;
            anchored_relative = true;
        } else {
            emit_drive_prefix(dst, &mut out_len, drive_idx)?;
        }
        normalised
    };

    if !resolved_tail.is_empty() {
        out_len = append_tail_components(
            resolved_tail,
            prefix.is_verbatim,
            dst,
            out_len,
            prefix.had_prefix,
            !anchored_relative,
        )?;
    } else if out_len == 0 {
        if anchored_relative {
            dst[0] = b'.';
            out_len = 1;
        } else {
            // Empty path post-canonicalisation → "/".
            dst[0] = b'/';
            out_len = 1;
        }
    }

    // 4. Length cap (post-canonicalisation).
    check_path_length(out_len, prefix.had_prefix)?;

    Ok(CanonicalNtPath {
        bytes: &dst[..out_len],
        anchor_vkey,
    })
}

fn append_tail_components(
    tail: &[u8],
    verbatim: bool,
    dst: &mut [u8],
    mut out_len: usize,
    had_nt_prefix: bool,
    force_absolute: bool,
) -> VfsResult<usize> {
    if out_len == 0 {
        if force_absolute {
            if dst.is_empty() {
                return Err(VfsError::NameTooLong);
            }
            dst[0] = b'/';
            out_len = 1;
        }
    } else if dst[out_len - 1] != b'/' {
        if out_len >= dst.len() {
            return Err(VfsError::NameTooLong);
        }
        dst[out_len] = b'/';
        out_len += 1;
    }

    let mut component_start = 0usize;
    let mut wrote_any = false;
    while component_start <= tail.len() {
        let component_end = match tail[component_start..].iter().position(|&b| b == b'/') {
            Some(pos) => component_start + pos,
            None => tail.len(),
        };
        let raw = &tail[component_start..component_end];
        let component = if verbatim {
            raw
        } else {
            trim_trailing_dots_spaces(raw)
        };

        if !component.is_empty() {
            if !verbatim {
                validate_no_forbidden_chars(component)?;
                if let Some(dev) = super::reserved::intercept(component) {
                    return rewrite_reserved_device(dev, dst, had_nt_prefix);
                }
            }
            if wrote_any {
                if out_len >= dst.len() {
                    return Err(VfsError::NameTooLong);
                }
                dst[out_len] = b'/';
                out_len += 1;
            }
            if out_len + component.len() > dst.len() {
                return Err(VfsError::NameTooLong);
            }
            dst[out_len..out_len + component.len()].copy_from_slice(component);
            out_len += component.len();
            wrote_any = true;
        }

        if component_end == tail.len() {
            break;
        }
        component_start = component_end + 1;
    }

    check_path_length(out_len, had_nt_prefix)?;
    Ok(out_len)
}

fn emit_drive_prefix(dst: &mut [u8], out_len: &mut usize, drive_idx: u8) -> VfsResult<()> {
    if *out_len + 2 > dst.len() {
        return Err(VfsError::NameTooLong);
    }
    dst[*out_len] = b'/';
    *out_len += 1;
    dst[*out_len] = b'a' + drive_idx;
    *out_len += 1;
    Ok(())
}

fn current_drive_index(drives: &super::drives::DriveTable) -> VfsResult<u8> {
    if drives.current_drive < super::drives::DRIVE_LETTER_COUNT as u8 {
        Ok(drives.current_drive)
    } else {
        Err(VfsError::NoEnt)
    }
}

fn rewrite_reserved_device(
    dev: super::reserved::ReservedDev,
    dst: &mut [u8],
    had_nt_prefix: bool,
) -> VfsResult<usize> {
    let name = super::reserved::devfs_name(dev);
    let prefix = b"/dev/";
    let out_len = prefix.len() + name.len();
    if out_len > dst.len() {
        return Err(VfsError::NameTooLong);
    }
    dst[..prefix.len()].copy_from_slice(prefix);
    dst[prefix.len()..out_len].copy_from_slice(name);
    check_path_length(out_len, had_nt_prefix)?;
    Ok(out_len)
}
