// SPDX-License-Identifier: GPL-2.0-only
//! Win32 path normalization onto the neutral VFS namespace.

use uapi::*;

use crate::owner::VfsState;
use crate::server::client::MAX_PATH_LEN;
use crate::server::types::ClientHandle;
use crate::vfs_core::namei::PathAnchor;

fn reserved_device_path(path: &[u8], verbatim: bool) -> Option<&'static [u8]> {
    if verbatim {
        return None;
    }
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let start = path[..end]
        .iter()
        .rposition(|&b| b == b'/')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let component = trim_trailing_dots_spaces(&path[start..end]);
    let dev = super::reserved::intercept(component)?;
    Some(super::reserved::devfs_path(dev))
}

pub(crate) const MAX_PATH_WIN32: usize = 260;
pub(crate) const MAX_PATH_WIN32_LONG: usize = 32767;

struct NtPrefixResult {
    had_prefix: bool,
    is_verbatim: bool,
    is_pipe_ns: bool,
    offset: usize,
}

#[inline]
fn drive_letter_index(letter: u8) -> Option<usize> {
    if letter >= b'A' && letter <= b'Z' {
        Some((letter - b'A') as usize)
    } else if letter >= b'a' && letter <= b'z' {
        Some((letter - b'a') as usize)
    } else {
        None
    }
}

unsafe fn strip_nt_prefix(path: *const u8, len: usize) -> NtPrefixResult {
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

        if is_sep(b0) && is_sep(b1) && b2 == b'?' && is_sep(b3) {
            return NtPrefixResult {
                had_prefix: true,
                is_verbatim: true,
                is_pipe_ns: false,
                offset: 4,
            };
        }

        if is_sep(b0) && is_sep(b1) && b2 == b'.' && is_sep(b3) {
            let is_pipe_ns = len >= 9
                && ((*path.add(4) | 0x20) == b'p')
                && ((*path.add(5) | 0x20) == b'i')
                && ((*path.add(6) | 0x20) == b'p')
                && ((*path.add(7) | 0x20) == b'e')
                && is_sep(*path.add(8));
            return NtPrefixResult {
                had_prefix: true,
                is_verbatim: false,
                is_pipe_ns,
                offset: if is_pipe_ns { 9 } else { 4 },
            };
        }
    }

    NtPrefixResult {
        had_prefix: false,
        is_verbatim: false,
        is_pipe_ns: false,
        offset: 0,
    }
}

unsafe fn normalize_separators(src: *const u8, len: usize, dst: *mut u8) -> usize {
    unsafe {
        let mut out = 0usize;
        let mut prev_sep = false;
        for idx in 0..len {
            let b = *src.add(idx);
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
        }
        out
    }
}

fn trim_trailing_dots_spaces(component: &[u8]) -> &[u8] {
    let mut end = component.len();
    while end > 0 && (component[end - 1] == b'.' || component[end - 1] == b' ') {
        end -= 1;
    }
    &component[..end]
}

fn path_prefix_boundary_len(path: &[u8], prefix: &[u8]) -> Option<usize> {
    if path.is_empty() || prefix.is_empty() || path[0] != b'/' || prefix[0] != b'/' {
        return None;
    }
    if prefix.len() == 1 {
        return Some(1);
    }
    if path.len() < prefix.len() || &path[..prefix.len()] != prefix {
        return None;
    }
    if path.len() == prefix.len() || path[prefix.len()] == b'/' {
        Some(prefix.len())
    } else {
        None
    }
}

#[inline]
fn drive_letter(index: usize) -> u8 {
    b'A' + (index as u8)
}

fn validate_no_forbidden_chars(component: &[u8]) -> Result<(), u64> {
    for &b in component {
        match b {
            b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*' | 0x00..=0x1f => {
                return Err(TRONA_INVALID_ARGUMENT);
            }
            _ => {}
        }
    }
    Ok(())
}

fn build_absolute_from_base(
    base: &[u8],
    normalized: &[u8],
    verbatim: bool,
    out: *mut u8,
) -> Result<usize, u64> {
    let mut raw_abs = [0u8; MAX_PATH_LEN];
    if base.is_empty() || base[0] != b'/' || base.len() > raw_abs.len() {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    raw_abs[..base.len()].copy_from_slice(base);
    let mut raw_len = base.len();

    if !normalized.is_empty() {
        let base_is_root = raw_len == 1 && raw_abs[0] == b'/';
        if !base_is_root {
            if raw_len >= raw_abs.len() {
                return Err(TRONA_OUT_OF_RANGE);
            }
            raw_abs[raw_len] = b'/';
            raw_len += 1;
        }
        if raw_len + normalized.len() > raw_abs.len() {
            return Err(TRONA_OUT_OF_RANGE);
        }
        raw_abs[raw_len..raw_len + normalized.len()].copy_from_slice(normalized);
        raw_len += normalized.len();
    }

    let mut out_len = 1usize;
    unsafe {
        *out = b'/';
    }
    let mut comp_starts = [0usize; MAX_PATH_LEN / 2];
    let mut depth = 0usize;
    let mut pos = if raw_len > 0 && raw_abs[0] == b'/' {
        1
    } else {
        0
    };

    while pos < raw_len {
        while pos < raw_len && raw_abs[pos] == b'/' {
            pos += 1;
        }
        if pos >= raw_len {
            break;
        }

        let start = pos;
        while pos < raw_len && raw_abs[pos] != b'/' {
            pos += 1;
        }
        let raw_component = &raw_abs[start..pos];
        let component = if verbatim {
            raw_component
        } else {
            trim_trailing_dots_spaces(raw_component)
        };

        if component.is_empty() || (component.len() == 1 && component[0] == b'.') {
            continue;
        }
        if !verbatim {
            validate_no_forbidden_chars(component)?;
        }
        if component.len() == 2 && component[0] == b'.' && component[1] == b'.' {
            if depth > 0 {
                depth -= 1;
                out_len = comp_starts[depth];
                if out_len == 0 {
                    out_len = 1;
                    unsafe {
                        *out = b'/';
                    }
                }
            }
            continue;
        }

        if depth >= comp_starts.len() {
            return Err(TRONA_OUT_OF_RANGE);
        }
        if out_len > 1 {
            if out_len >= MAX_PATH_LEN {
                return Err(TRONA_OUT_OF_RANGE);
            }
            unsafe {
                *out.add(out_len) = b'/';
            }
            out_len += 1;
        }
        if out_len + component.len() > MAX_PATH_LEN {
            return Err(TRONA_OUT_OF_RANGE);
        }
        comp_starts[depth] = out_len;
        depth += 1;
        unsafe {
            core::ptr::copy_nonoverlapping(component.as_ptr(), out.add(out_len), component.len());
        }
        out_len += component.len();
    }

    Ok(out_len.max(1))
}

pub(crate) unsafe fn normalize_path_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    in_path: *const u8,
    in_len: u8,
    out: *mut u8,
) -> Result<usize, u64> {
    if in_len == 0 || in_path.is_null() {
        return Err(TRONA_INVALID_ARGUMENT);
    }

    let path_len = in_len as usize;
    let prefix = unsafe { strip_nt_prefix(in_path, path_len) };
    if prefix.offset > path_len {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let content_ptr = unsafe { in_path.add(prefix.offset) };
    let content_len = path_len - prefix.offset;
    let limit = if prefix.had_prefix {
        MAX_PATH_WIN32_LONG
    } else {
        MAX_PATH_WIN32
    };
    if content_len > limit || content_len > MAX_PATH_LEN {
        return Err(TRONA_OUT_OF_RANGE);
    }

    let mut normalized = [0u8; MAX_PATH_LEN];
    let norm_len =
        unsafe { normalize_separators(content_ptr, content_len, normalized.as_mut_ptr()) };

    if prefix.is_pipe_ns {
        return build_absolute_from_base(
            b"/pipe",
            &normalized[..norm_len],
            prefix.is_verbatim,
            out,
        );
    }
    if let Some(device_path) = reserved_device_path(&normalized[..norm_len], prefix.is_verbatim) {
        if device_path.len() > MAX_PATH_LEN {
            return Err(TRONA_OUT_OF_RANGE);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(device_path.as_ptr(), out, device_path.len());
        }
        return Ok(device_path.len());
    }

    let mut drive_index = state.win32_current_drive(cli_handle);
    let mut pos = 0usize;
    let mut absolute = false;

    if norm_len >= 2 && normalized[1] == b':' {
        let Some(idx) = drive_letter_index(normalized[0]) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        drive_index = idx;
        pos = 2;
        if pos < norm_len && normalized[pos] == b'/' {
            absolute = true;
            while pos < norm_len && normalized[pos] == b'/' {
                pos += 1;
            }
        }
    } else if norm_len > 0 && normalized[0] == b'/' {
        absolute = true;
        pos = 1;
        while pos < norm_len && normalized[pos] == b'/' {
            pos += 1;
        }
    }

    let base_vnode = state
        .win32_drive_base_vnode(cli_handle, drive_index, absolute)
        .ok_or(TRONA_NOT_FOUND)?;
    let base_anchor = state
        .anchor_for_vnode(base_vnode)
        .ok_or(TRONA_INVALID_OPERATION)?;
    let mut base = [0u8; MAX_PATH_LEN];
    let base_len = state
        .render_anchor_path(base_anchor, &mut base)
        .ok_or(TRONA_INVALID_OPERATION)?;
    build_absolute_from_base(
        &base[..base_len],
        &normalized[pos..norm_len],
        prefix.is_verbatim,
        out,
    )
}

pub(crate) unsafe fn explicit_drive_index(in_path: *const u8, in_len: u8) -> Option<usize> {
    if in_len == 0 || in_path.is_null() {
        return None;
    }
    let len = in_len as usize;
    let prefix = unsafe { strip_nt_prefix(in_path, len) };
    if prefix.is_pipe_ns || prefix.offset >= len {
        return None;
    }
    let path = unsafe { in_path.add(prefix.offset) };
    if len - prefix.offset < 2 {
        return None;
    }
    let letter = unsafe { *path };
    let colon = unsafe { *path.add(1) };
    if colon != b':' {
        return None;
    }
    drive_letter_index(letter)
}

pub(crate) unsafe fn uses_explicit_root_or_drive(in_path: *const u8, in_len: u8) -> bool {
    if in_len == 0 || in_path.is_null() {
        return false;
    }
    let len = in_len as usize;
    let prefix = unsafe { strip_nt_prefix(in_path, len) };
    if prefix.is_pipe_ns || prefix.offset >= len {
        return prefix.is_pipe_ns;
    }
    let path = unsafe { in_path.add(prefix.offset) };
    let remaining = len - prefix.offset;
    if remaining >= 2 && unsafe { *path.add(1) } == b':' {
        if drive_letter_index(unsafe { *path }).is_some() {
            return true;
        }
    }
    let first = unsafe { *path };
    first == b'/' || first == b'\\'
}

pub(crate) unsafe fn normalize_path_from_base_owned(
    base: &[u8],
    in_path: *const u8,
    in_len: u8,
    out: *mut u8,
) -> Result<usize, u64> {
    if in_len == 0 || in_path.is_null() || out.is_null() {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    if base.is_empty() || base[0] != b'/' || base.len() > MAX_PATH_LEN {
        return Err(TRONA_INVALID_ARGUMENT);
    }

    let path_len = in_len as usize;
    let prefix = unsafe { strip_nt_prefix(in_path, path_len) };
    if prefix.offset > path_len {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let content_ptr = unsafe { in_path.add(prefix.offset) };
    let content_len = path_len - prefix.offset;
    let limit = if prefix.had_prefix {
        MAX_PATH_WIN32_LONG
    } else {
        MAX_PATH_WIN32
    };
    if content_len > limit || content_len > MAX_PATH_LEN {
        return Err(TRONA_OUT_OF_RANGE);
    }

    let mut normalized = [0u8; MAX_PATH_LEN];
    let norm_len =
        unsafe { normalize_separators(content_ptr, content_len, normalized.as_mut_ptr()) };

    if prefix.is_pipe_ns {
        return build_absolute_from_base(
            b"/pipe",
            &normalized[..norm_len],
            prefix.is_verbatim,
            out,
        );
    }
    if let Some(device_path) = reserved_device_path(&normalized[..norm_len], prefix.is_verbatim) {
        if device_path.len() > MAX_PATH_LEN {
            return Err(TRONA_OUT_OF_RANGE);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(device_path.as_ptr(), out, device_path.len());
        }
        return Ok(device_path.len());
    }

    if norm_len > 0 && normalized[0] == b'/' {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    if norm_len >= 2 && normalized[1] == b':' {
        return Err(TRONA_INVALID_ARGUMENT);
    }

    build_absolute_from_base(base, &normalized[..norm_len], prefix.is_verbatim, out)
}

pub(crate) fn render_absolute_path_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    neutral_path: &[u8],
    out: *mut u8,
) -> Result<usize, u64> {
    if neutral_path.is_empty() || neutral_path[0] != b'/' || out.is_null() {
        return Err(TRONA_INVALID_ARGUMENT);
    }

    let current_drive = state.win32_current_drive(cli_handle);
    let mut best_drive = None;
    let mut best_prefix_len = 0usize;
    let mut root_buf = [0u8; MAX_PATH_LEN];

    let mut consider_drive = |drive_index: usize| {
        let Some(root_vh) = (unsafe { super::drives::resolve_drive_root(state, drive_index) })
        else {
            return;
        };
        let Some(root_anchor) = state.anchor_for_vnode(root_vh) else {
            return;
        };
        let Some(root_len) = state.render_anchor_path(root_anchor, &mut root_buf) else {
            return;
        };
        let Some(prefix_len) = path_prefix_boundary_len(neutral_path, &root_buf[..root_len]) else {
            return;
        };
        let better = prefix_len > best_prefix_len
            || (prefix_len == best_prefix_len
                && drive_index == current_drive
                && best_drive != Some(current_drive));
        if better {
            best_drive = Some(drive_index);
            best_prefix_len = prefix_len;
        }
    };

    consider_drive(current_drive);
    for drive_index in 0..26 {
        if drive_index != current_drive {
            consider_drive(drive_index);
        }
    }

    let Some(drive_index) = best_drive else {
        return Err(TRONA_NOT_FOUND);
    };

    let mut rel_start = best_prefix_len;
    if rel_start < neutral_path.len() && neutral_path[rel_start] == b'/' {
        rel_start += 1;
    }

    if 3 + neutral_path.len().saturating_sub(rel_start) > MAX_PATH_LEN {
        return Err(TRONA_OUT_OF_RANGE);
    }

    unsafe {
        *out = drive_letter(drive_index);
        *out.add(1) = b':';
        *out.add(2) = b'\\';
    }

    let mut out_len = 3usize;
    for &b in &neutral_path[rel_start..] {
        unsafe {
            *out.add(out_len) = if b == b'/' { b'\\' } else { b };
        }
        out_len += 1;
    }
    Ok(out_len)
}

pub(crate) fn render_anchor_path_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    anchor: PathAnchor,
    out: *mut u8,
) -> Result<usize, u64> {
    let mut neutral = [0u8; MAX_PATH_LEN];
    let Some(path_len) = state.render_anchor_path(anchor, &mut neutral) else {
        return Err(TRONA_INVALID_OPERATION);
    };
    render_absolute_path_owned(state, cli_handle, &neutral[..path_len], out)
}
