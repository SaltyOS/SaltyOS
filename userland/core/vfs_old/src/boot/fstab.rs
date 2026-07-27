// SPDX-License-Identifier: GPL-2.0-only
//! Minimal `/etc/fstab` parser for boot-time mount orchestration.

use crate::vfs_core::mount;

pub(crate) const MAX_FSTAB_ENTRIES: usize = 16;

#[repr(C)]
pub(crate) struct FstabEntry {
    pub(crate) active: u8,
    pub(crate) source: [u8; 64],
    pub(crate) source_len: u8,
    pub(crate) target: [u8; 128],
    pub(crate) target_len: u8,
    pub(crate) fstype: [u8; 16],
    pub(crate) fstype_len: u8,
    pub(crate) dump: u8,
    pub(crate) pass: u8,
    pub(crate) flags: u32,
    pub(crate) nofail: u8,
}

impl FstabEntry {
    pub(crate) const fn zeroed() -> Self {
        FstabEntry {
            active: 0,
            source: [0; 64],
            source_len: 0,
            target: [0; 128],
            target_len: 0,
            fstype: [0; 16],
            fstype_len: 0,
            dump: 0,
            pass: 0,
            flags: 0,
            nofail: 0,
        }
    }

    pub(crate) fn target_slice(&self) -> &[u8] {
        &self.target[..self.target_len as usize]
    }

    pub(crate) fn fstype_slice(&self) -> &[u8] {
        &self.fstype[..self.fstype_len as usize]
    }

    pub(crate) fn source_slice(&self) -> &[u8] {
        &self.source[..self.source_len as usize]
    }

    pub(crate) fn is_root(&self) -> bool {
        self.target_len == 1 && self.target[0] == b'/'
    }
}

/// Parse an fstab buffer into an array of entries.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes.
pub(crate) unsafe fn parse(data: *const u8, len: usize) -> [FstabEntry; MAX_FSTAB_ENTRIES] {
    let mut entries = [const { FstabEntry::zeroed() }; MAX_FSTAB_ENTRIES];
    if data.is_null() || len == 0 {
        return entries;
    }

    let buf = unsafe { core::slice::from_raw_parts(data, len) };
    let mut idx = 0usize;
    let mut pos = 0usize;

    while pos < buf.len() && idx < MAX_FSTAB_ENTRIES {
        // Find line end
        let line_start = pos;
        while pos < buf.len() && buf[pos] != b'\n' {
            pos += 1;
        }
        let line = &buf[line_start..pos];
        if pos < buf.len() {
            pos += 1; // skip newline
        }

        // Skip blank lines and comments
        let trimmed = trim_leading_whitespace(line);
        if trimmed.is_empty() || trimmed[0] == b'#' {
            continue;
        }

        // Split into fields: source target fstype options dump pass
        let mut fields: [&[u8]; 6] = [&[]; 6];
        let field_count = split_whitespace(trimmed, &mut fields);
        if field_count < 4 {
            continue;
        }

        let entry = &mut entries[idx];
        entry.active = 1;

        copy_field(&mut entry.source, &mut entry.source_len, fields[0], 64);
        copy_field(&mut entry.target, &mut entry.target_len, fields[1], 128);
        copy_field(&mut entry.fstype, &mut entry.fstype_len, fields[2], 16);

        entry.flags = parse_options(fields[3], &mut entry.nofail);

        if field_count >= 5 {
            entry.dump = parse_digit(fields[4]);
        }
        if field_count >= 6 {
            entry.pass = parse_digit(fields[5]);
        }

        idx += 1;
    }

    entries
}

fn trim_leading_whitespace(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    &s[i..]
}

fn split_whitespace<'a>(s: &'a [u8], fields: &mut [&'a [u8]; 6]) -> usize {
    let mut count = 0usize;
    let mut pos = 0usize;

    while pos < s.len() && count < 6 {
        // Skip whitespace
        while pos < s.len() && (s[pos] == b' ' || s[pos] == b'\t') {
            pos += 1;
        }
        if pos >= s.len() {
            break;
        }
        let start = pos;
        while pos < s.len() && s[pos] != b' ' && s[pos] != b'\t' {
            pos += 1;
        }
        fields[count] = &s[start..pos];
        count += 1;
    }

    count
}

fn copy_field(dst: &mut [u8], dst_len: &mut u8, src: &[u8], cap: usize) {
    let len = if src.len() < cap { src.len() } else { cap };
    dst[..len].copy_from_slice(&src[..len]);
    *dst_len = len as u8;
}

fn parse_digit(s: &[u8]) -> u8 {
    if s.is_empty() {
        return 0;
    }
    let c = s[0];
    if c >= b'0' && c <= b'9' { c - b'0' } else { 0 }
}

fn parse_options(opts: &[u8], nofail: &mut u8) -> u32 {
    let mut flags = 0u32;
    *nofail = 0;

    let mut pos = 0usize;
    while pos < opts.len() {
        let start = pos;
        while pos < opts.len() && opts[pos] != b',' {
            pos += 1;
        }
        let opt = &opts[start..pos];
        if pos < opts.len() {
            pos += 1; // skip comma
        }

        if bytes_match(opt, b"ro") {
            flags |= mount::MNT_RDONLY;
        } else if bytes_match(opt, b"nosuid") {
            flags |= mount::MNT_NOSUID;
        } else if bytes_match(opt, b"noexec") {
            flags |= mount::MNT_NOEXEC;
        } else if bytes_match(opt, b"nodev") {
            flags |= mount::MNT_NODEV;
        } else if bytes_match(opt, b"nosymfollow") {
            flags |= mount::MNT_NOSYMFOLLOW;
        } else if bytes_match(opt, b"bind") {
            flags |= mount::MNT_BIND;
        } else if bytes_match(opt, b"rbind") {
            flags |= mount::MNT_RBIND;
        } else if bytes_match(opt, b"nofail") {
            *nofail = 1;
        }
        // "defaults" and "rw" set no flags
    }

    flags
}

fn bytes_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
