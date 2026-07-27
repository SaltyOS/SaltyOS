// SPDX-License-Identifier: GPL-2.0-only
//
//! UTF-16LE → UTF-8 conversion for the Win32 NT wire.
//!
//! NT path strings (`UNICODE_STRING.Buffer`) ride the wire as
//! little-endian UTF-16. The vfs personality layer normalises
//! everything to UTF-8 before handing the path to the
//! personality-neutral namei walker — separators are also flipped
//! (`\` → `/`) and `\\?\` / `\\.\\` prefixes stripped by
//! `super::path` after this conversion runs.
//!
//! Surrogate pairs are decoded; an unpaired surrogate produces a
//! `None` return so the caller can surface
//! `STATUS_OBJECT_NAME_INVALID` rather than feeding malformed
//! bytes downstream.

#![allow(dead_code)]

/// Decode a UTF-16LE byte stream into UTF-8. Returns the number
/// of bytes written into `dst` on success, `None` when:
/// * `src_bytes` is not an even byte count (truncated UTF-16),
/// * `dst` is too small for the UTF-8 expansion,
/// * an unpaired surrogate is encountered.
pub(crate) fn utf16le_bytes_to_utf8(src_bytes: &[u8], dst: &mut [u8]) -> Option<usize> {
    if src_bytes.len() % 2 != 0 {
        return None;
    }
    let n_units = src_bytes.len() / 2;
    let mut written = 0usize;
    let mut i = 0usize;
    while i < n_units {
        let lo = src_bytes[i * 2] as u16;
        let hi = src_bytes[i * 2 + 1] as u16;
        let unit = lo | (hi << 8);

        let cp: u32 = if (0xD800..=0xDBFF).contains(&unit) {
            // High surrogate — must be followed by low surrogate.
            if i + 1 >= n_units {
                return None;
            }
            let lo2 = src_bytes[(i + 1) * 2] as u16;
            let hi2 = src_bytes[(i + 1) * 2 + 1] as u16;
            let unit2 = lo2 | (hi2 << 8);
            if !(0xDC00..=0xDFFF).contains(&unit2) {
                return None;
            }
            i += 2;
            0x10000u32 + (((unit as u32 & 0x3FF) << 10) | (unit2 as u32 & 0x3FF))
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            // Unpaired low surrogate.
            return None;
        } else {
            i += 1;
            unit as u32
        };

        // Encode the codepoint as UTF-8.
        let need = if cp < 0x80 {
            1
        } else if cp < 0x800 {
            2
        } else if cp < 0x10000 {
            3
        } else {
            4
        };
        if written + need > dst.len() {
            return None;
        }
        match need {
            1 => dst[written] = cp as u8,
            2 => {
                dst[written] = 0xC0 | ((cp >> 6) as u8 & 0x1F);
                dst[written + 1] = 0x80 | (cp as u8 & 0x3F);
            }
            3 => {
                dst[written] = 0xE0 | ((cp >> 12) as u8 & 0x0F);
                dst[written + 1] = 0x80 | ((cp >> 6) as u8 & 0x3F);
                dst[written + 2] = 0x80 | (cp as u8 & 0x3F);
            }
            _ => {
                dst[written] = 0xF0 | ((cp >> 18) as u8 & 0x07);
                dst[written + 1] = 0x80 | ((cp >> 12) as u8 & 0x3F);
                dst[written + 2] = 0x80 | ((cp >> 6) as u8 & 0x3F);
                dst[written + 3] = 0x80 | (cp as u8 & 0x3F);
            }
        }
        written += need;
    }
    Some(written)
}

/// Encode a UTF-8 byte slice as UTF-16LE bytes. Mirror of
/// [`utf16le_bytes_to_utf8`] for the reply path
/// (`FILE_NAMES_INFORMATION` / `FILE_NAME_INFORMATION` carry the
/// resolved name back as UTF-16LE bytes). Returns the byte count
/// written into `dst` or `None` if `dst` is too small / the input
/// is not valid UTF-8.
pub(crate) fn utf8_to_utf16le_bytes(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    if dst.len() % 2 != 0 {
        return None;
    }
    let mut written = 0usize;
    let mut i = 0usize;
    while i < src.len() {
        let b0 = src[i];
        let (cp, advance): (u32, usize) = if b0 < 0x80 {
            (b0 as u32, 1)
        } else if b0 & 0xE0 == 0xC0 {
            if i + 1 >= src.len() {
                return None;
            }
            let cp = ((b0 as u32 & 0x1F) << 6) | (src[i + 1] as u32 & 0x3F);
            (cp, 2)
        } else if b0 & 0xF0 == 0xE0 {
            if i + 2 >= src.len() {
                return None;
            }
            let cp = ((b0 as u32 & 0x0F) << 12)
                | ((src[i + 1] as u32 & 0x3F) << 6)
                | (src[i + 2] as u32 & 0x3F);
            (cp, 3)
        } else if b0 & 0xF8 == 0xF0 {
            if i + 3 >= src.len() {
                return None;
            }
            let cp = ((b0 as u32 & 0x07) << 18)
                | ((src[i + 1] as u32 & 0x3F) << 12)
                | ((src[i + 2] as u32 & 0x3F) << 6)
                | (src[i + 3] as u32 & 0x3F);
            (cp, 4)
        } else {
            return None;
        };
        i += advance;

        if cp < 0x10000 {
            if written + 2 > dst.len() {
                return None;
            }
            dst[written] = cp as u8;
            dst[written + 1] = (cp >> 8) as u8;
            written += 2;
        } else {
            if written + 4 > dst.len() {
                return None;
            }
            let v = cp - 0x10000;
            let high = 0xD800 + (v >> 10);
            let low = 0xDC00 + (v & 0x3FF);
            dst[written] = high as u8;
            dst[written + 1] = (high >> 8) as u8;
            dst[written + 2] = low as u8;
            dst[written + 3] = (low >> 8) as u8;
            written += 4;
        }
    }
    Some(written)
}

/// UTF-16 wide-char count from a byte length. UTF-16 is fixed at
/// 2 bytes per unit; the helper exists so call sites do not have
/// to spell `bytes / 2` in line every time and so a future code
/// pages or alignment shift keeps a single point of truth.
#[inline]
pub(crate) const fn utf16_wchars_from_bytes(bytes: usize) -> usize {
    bytes / 2
}
