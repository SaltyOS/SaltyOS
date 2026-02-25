//! Wide character / multibyte support (UTF-8)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! SaltyOS uses a UTF-8 locale. Multibyte functions implement full UTF-8
//! encoding/decoding (`wchar_t = i32`, MB_CUR_MAX = 4).
//! Wide string operations (`wcslen`, `wcscmp`, `wcscpy`, etc.) operate on
//! 32-bit wchar_t arrays. Conversion functions (`wcstod`, `wcstoull`) narrow
//! to byte strings and delegate to the narrow equivalents.

pub type WcharT = i32;
pub type WintT = u32;
pub type MbstateT = u32;

pub const WEOF: WintT = 0xFFFFFFFF;

// ---------------------------------------------------------------------------
// UTF-8 codec helpers
// ---------------------------------------------------------------------------

/// Returns the expected byte length of a UTF-8 sequence from its lead byte.
/// Returns 0 for invalid lead bytes (continuation bytes 0x80-0xBF, 0xFE-0xFF).
#[inline]
fn utf8_char_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead < 0xC2 {
        // 0x80-0xBF are continuation bytes, 0xC0-0xC1 are overlong 2-byte
        0
    } else if lead < 0xE0 {
        2
    } else if lead < 0xF0 {
        3
    } else if lead < 0xF5 {
        // 0xF5-0xFF would produce codepoints > U+10FFFF
        4
    } else {
        0
    }
}

/// Returns true if `cp` is a valid Unicode scalar value (excludes surrogates).
#[inline]
fn is_valid_codepoint(cp: u32) -> bool {
    cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF)
}

/// Returns true if the encoding is overlong for the given codepoint.
#[inline]
fn is_overlong(cp: u32, seq_len: usize) -> bool {
    match seq_len {
        2 => cp < 0x80,
        3 => cp < 0x800,
        4 => cp < 0x10000,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Multibyte <-> wide character conversions
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mbrtowc(
    pwc: *mut WcharT,
    s: *const u8,
    n: usize,
    _ps: *mut MbstateT,
) -> usize {
    unsafe {
        if s.is_null() {
            return 0;
        }
        if n == 0 {
            return usize::MAX - 1; // (size_t)-2 -- incomplete sequence
        }
        let lead = *s;
        if lead == 0 {
            if !pwc.is_null() {
                *pwc = 0;
            }
            return 0;
        }
        // ASCII fast path
        if lead < 0x80 {
            if !pwc.is_null() {
                *pwc = lead as WcharT;
            }
            return 1;
        }
        let seq_len = utf8_char_len(lead);
        if seq_len == 0 {
            crate::errno::set_errno(crate::errno::EILSEQ);
            return usize::MAX; // (size_t)-1
        }
        if n < seq_len {
            return usize::MAX - 1; // (size_t)-2 -- incomplete
        }
        // Decode multi-byte sequence
        let mut cp: u32 = match seq_len {
            2 => (lead & 0x1F) as u32,
            3 => (lead & 0x0F) as u32,
            4 => (lead & 0x07) as u32,
            _ => 0,
        };
        let mut i = 1;
        while i < seq_len {
            let cont = *s.add(i);
            if cont & 0xC0 != 0x80 {
                crate::errno::set_errno(crate::errno::EILSEQ);
                return usize::MAX;
            }
            cp = (cp << 6) | (cont & 0x3F) as u32;
            i += 1;
        }
        // Reject overlong encodings and invalid codepoints
        if is_overlong(cp, seq_len) || !is_valid_codepoint(cp) {
            crate::errno::set_errno(crate::errno::EILSEQ);
            return usize::MAX;
        }
        if !pwc.is_null() {
            *pwc = cp as WcharT;
        }
        seq_len
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcrtomb(
    s: *mut u8,
    wc: WcharT,
    _ps: *mut MbstateT,
) -> usize {
    unsafe {
        if s.is_null() {
            return 1;
        }
        let cp = wc as u32;
        if cp < 0x80 {
            *s = cp as u8;
            1
        } else if cp < 0x800 {
            *s = (0xC0 | (cp >> 6)) as u8;
            *s.add(1) = (0x80 | (cp & 0x3F)) as u8;
            2
        } else if cp < 0x10000 {
            if cp >= 0xD800 && cp <= 0xDFFF {
                crate::errno::set_errno(crate::errno::EILSEQ);
                return usize::MAX;
            }
            *s = (0xE0 | (cp >> 12)) as u8;
            *s.add(1) = (0x80 | ((cp >> 6) & 0x3F)) as u8;
            *s.add(2) = (0x80 | (cp & 0x3F)) as u8;
            3
        } else if cp <= 0x10FFFF {
            *s = (0xF0 | (cp >> 18)) as u8;
            *s.add(1) = (0x80 | ((cp >> 12) & 0x3F)) as u8;
            *s.add(2) = (0x80 | ((cp >> 6) & 0x3F)) as u8;
            *s.add(3) = (0x80 | (cp & 0x3F)) as u8;
            4
        } else {
            crate::errno::set_errno(crate::errno::EILSEQ);
            usize::MAX
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mblen(s: *const u8, n: usize) -> i32 {
    if s.is_null() {
        return 0;
    }
    unsafe {
        if n == 0 {
            return -1;
        }
        let lead = *s;
        if lead == 0 {
            return 0;
        }
        if lead < 0x80 {
            return 1;
        }
        let seq_len = utf8_char_len(lead);
        if seq_len == 0 || n < seq_len {
            return -1;
        }
        // Validate continuation bytes
        let mut i = 1;
        while i < seq_len {
            if *s.add(i) & 0xC0 != 0x80 {
                return -1;
            }
            i += 1;
        }
        seq_len as i32
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mbtowc(
    pwc: *mut WcharT,
    s: *const u8,
    n: usize,
) -> i32 {
    if s.is_null() {
        return 0;
    }
    unsafe {
        let result = mbrtowc(pwc, s, n, core::ptr::null_mut());
        if result == usize::MAX || result == usize::MAX - 1 {
            -1
        } else {
            result as i32
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wctomb(s: *mut u8, wc: WcharT) -> i32 {
    if s.is_null() {
        return 0;
    }
    unsafe {
        let result = wcrtomb(s, wc, core::ptr::null_mut());
        if result == usize::MAX {
            -1
        } else {
            result as i32
        }
    }
}

// ---------------------------------------------------------------------------
// btowc / wctob — single-byte ↔ wide-character conversion
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn btowc(c: i32) -> WintT {
    if c < 0 || c > 127 {
        WEOF
    } else {
        c as WintT
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wctob(c: WintT) -> i32 {
    if c > 127 {
        -1 // EOF
    } else {
        c as i32
    }
}

// ---------------------------------------------------------------------------
// Wide character classification
// ---------------------------------------------------------------------------

#[inline]
fn is_alpha_ascii(wc: WintT) -> bool {
    (wc >= b'A' as u32 && wc <= b'Z' as u32)
        || (wc >= b'a' as u32 && wc <= b'z' as u32)
}

#[inline]
fn is_digit_ascii(wc: WintT) -> bool {
    wc >= b'0' as u32 && wc <= b'9' as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn iswalpha(wc: WintT) -> i32 {
    if is_alpha_ascii(wc) { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswdigit(wc: WintT) -> i32 {
    if is_digit_ascii(wc) { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswalnum(wc: WintT) -> i32 {
    if is_alpha_ascii(wc) || is_digit_ascii(wc) { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswspace(wc: WintT) -> i32 {
    if wc == b' ' as u32
        || wc == b'\t' as u32
        || wc == b'\n' as u32
        || wc == b'\r' as u32
        || wc == b'\x0b' as u32
        || wc == b'\x0c' as u32
    {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswupper(wc: WintT) -> i32 {
    if wc >= b'A' as u32 && wc <= b'Z' as u32 { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswlower(wc: WintT) -> i32 {
    if wc >= b'a' as u32 && wc <= b'z' as u32 { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswprint(wc: WintT) -> i32 {
    // ASCII printable
    if wc >= 0x20 && wc <= 0x7E {
        return 1;
    }
    // C0 controls and DEL
    if wc < 0x20 || wc == 0x7F {
        return 0;
    }
    // C1 controls (0x80-0x9F)
    if wc >= 0x80 && wc <= 0x9F {
        return 0;
    }
    // Surrogates
    if wc >= 0xD800 && wc <= 0xDFFF {
        return 0;
    }
    // Noncharacters
    if wc >= 0xFDD0 && wc <= 0xFDEF {
        return 0;
    }
    if (wc & 0xFFFE) == 0xFFFE {
        return 0;
    }
    // Everything else in the valid Unicode range is printable
    if wc <= 0x10FFFF { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswcntrl(wc: WintT) -> i32 {
    if wc < 0x20 || wc == 0x7F || (wc >= 0x80 && wc <= 0x9F) {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswgraph(wc: WintT) -> i32 {
    if iswprint(wc) != 0 && wc != b' ' as u32 { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswblank(wc: WintT) -> i32 {
    if wc == b' ' as u32 || wc == b'\t' as u32 { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswxdigit(wc: WintT) -> i32 {
    if is_digit_ascii(wc)
        || (wc >= b'a' as u32 && wc <= b'f' as u32)
        || (wc >= b'A' as u32 && wc <= b'F' as u32)
    {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswpunct(wc: WintT) -> i32 {
    if iswgraph(wc) != 0 && iswalnum(wc) == 0 { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn towlower(wc: WintT) -> WintT {
    if wc >= b'A' as u32 && wc <= b'Z' as u32 {
        wc + 32
    } else {
        wc
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn towupper(wc: WintT) -> WintT {
    if wc >= b'a' as u32 && wc <= b'z' as u32 {
        wc - 32
    } else {
        wc
    }
}

const WCTYPE_ALPHA: u64 = 1;
const WCTYPE_DIGIT: u64 = 2;
const WCTYPE_ALNUM: u64 = 3;
const WCTYPE_SPACE: u64 = 4;
const WCTYPE_UPPER: u64 = 5;
const WCTYPE_LOWER: u64 = 6;
const WCTYPE_PRINT: u64 = 7;
const WCTYPE_CNTRL: u64 = 8;
const WCTYPE_PUNCT: u64 = 9;
const WCTYPE_BLANK: u64 = 10;
const WCTYPE_XDIGIT: u64 = 11;
const WCTYPE_GRAPH: u64 = 12;

const WCTRANS_TOLOWER: u64 = 1;
const WCTRANS_TOUPPER: u64 = 2;

unsafe fn wc_name_eq(name: *const u8, lit: &[u8]) -> bool {
    unsafe {
        let mut i = 0usize;
        while i < lit.len() {
            if *name.add(i) != lit[i] {
                return false;
            }
            i += 1;
        }
        *name.add(lit.len()) == 0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wctype(name: *const u8) -> u64 {
    if name.is_null() {
        return 0;
    }
    unsafe {
        if wc_name_eq(name, b"alpha") { WCTYPE_ALPHA }
        else if wc_name_eq(name, b"digit") { WCTYPE_DIGIT }
        else if wc_name_eq(name, b"alnum") { WCTYPE_ALNUM }
        else if wc_name_eq(name, b"space") { WCTYPE_SPACE }
        else if wc_name_eq(name, b"upper") { WCTYPE_UPPER }
        else if wc_name_eq(name, b"lower") { WCTYPE_LOWER }
        else if wc_name_eq(name, b"print") { WCTYPE_PRINT }
        else if wc_name_eq(name, b"cntrl") { WCTYPE_CNTRL }
        else if wc_name_eq(name, b"punct") { WCTYPE_PUNCT }
        else if wc_name_eq(name, b"blank") { WCTYPE_BLANK }
        else if wc_name_eq(name, b"xdigit") { WCTYPE_XDIGIT }
        else if wc_name_eq(name, b"graph") { WCTYPE_GRAPH }
        else { 0 }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswctype(wc: WintT, desc: u64) -> i32 {
    match desc {
        WCTYPE_ALPHA => iswalpha(wc),
        WCTYPE_DIGIT => iswdigit(wc),
        WCTYPE_ALNUM => iswalnum(wc),
        WCTYPE_SPACE => iswspace(wc),
        WCTYPE_UPPER => iswupper(wc),
        WCTYPE_LOWER => iswlower(wc),
        WCTYPE_PRINT => iswprint(wc),
        WCTYPE_CNTRL => iswcntrl(wc),
        WCTYPE_PUNCT => iswpunct(wc),
        WCTYPE_BLANK => iswblank(wc),
        WCTYPE_XDIGIT => iswxdigit(wc),
        WCTYPE_GRAPH => iswgraph(wc),
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn nextwctype(wc: WintT, desc: u64) -> WintT {
    let mut next = if wc == WEOF { 0 } else { wc + 1 };
    while next < 0x80 {
        if iswctype(next, desc) != 0 {
            return next;
        }
        next += 1;
    }
    WEOF
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wctrans(name: *const u8) -> u64 {
    if name.is_null() {
        return 0;
    }
    unsafe {
        if wc_name_eq(name, b"tolower") {
            WCTRANS_TOLOWER
        } else if wc_name_eq(name, b"toupper") {
            WCTRANS_TOUPPER
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn towctrans(wc: WintT, desc: u64) -> WintT {
    match desc {
        WCTRANS_TOLOWER => towlower(wc),
        WCTRANS_TOUPPER => towupper(wc),
        _ => wc,
    }
}

// ---------------------------------------------------------------------------
// wcwidth — Unicode-aware character width
// ---------------------------------------------------------------------------

/// Returns true for zero-width characters (combining marks, format controls).
#[inline]
fn is_zero_width(wc: u32) -> bool {
    // Soft hyphen
    if wc == 0x00AD {
        return true;
    }
    // Combining Diacritical Marks
    if wc >= 0x0300 && wc <= 0x036F {
        return true;
    }
    // Cyrillic combining
    if wc >= 0x0483 && wc <= 0x0489 {
        return true;
    }
    // Hebrew combining
    if wc >= 0x0591 && wc <= 0x05BD {
        return true;
    }
    if wc == 0x05BF || wc == 0x05C7 {
        return true;
    }
    if wc >= 0x05C1 && wc <= 0x05C2 {
        return true;
    }
    if wc >= 0x05C4 && wc <= 0x05C5 {
        return true;
    }
    // Arabic format/combining
    if wc >= 0x0600 && wc <= 0x0605 {
        return true;
    }
    if wc >= 0x0610 && wc <= 0x061A {
        return true;
    }
    if wc == 0x061C {
        return true;
    }
    if wc >= 0x064B && wc <= 0x065F {
        return true;
    }
    if wc == 0x0670 {
        return true;
    }
    if wc >= 0x06D6 && wc <= 0x06DD {
        return true;
    }
    if wc >= 0x06DF && wc <= 0x06E4 {
        return true;
    }
    if wc >= 0x06E7 && wc <= 0x06E8 {
        return true;
    }
    if wc >= 0x06EA && wc <= 0x06ED {
        return true;
    }
    if wc == 0x070F {
        return true;
    }
    if wc == 0x0711 {
        return true;
    }
    if wc >= 0x0730 && wc <= 0x074A {
        return true;
    }
    // Thaana / NKo combining
    if wc >= 0x07A6 && wc <= 0x07B0 {
        return true;
    }
    if wc >= 0x07EB && wc <= 0x07F3 {
        return true;
    }
    // Devanagari and other Indic combining marks
    if wc >= 0x0900 && wc <= 0x0902 {
        return true;
    }
    if wc == 0x093A || wc == 0x093C {
        return true;
    }
    if wc >= 0x0941 && wc <= 0x0948 {
        return true;
    }
    if wc == 0x094D {
        return true;
    }
    // Thai / Lao combining
    if wc == 0x0E31 {
        return true;
    }
    if wc >= 0x0E34 && wc <= 0x0E3A {
        return true;
    }
    if wc >= 0x0E47 && wc <= 0x0E4E {
        return true;
    }
    if wc == 0x0EB1 {
        return true;
    }
    if wc >= 0x0EB4 && wc <= 0x0EBC {
        return true;
    }
    if wc >= 0x0EC8 && wc <= 0x0ECE {
        return true;
    }
    // Combining Diacritical Marks Extended
    if wc >= 0x1AB0 && wc <= 0x1AFF {
        return true;
    }
    // Combining Diacritical Marks Supplement
    if wc >= 0x1DC0 && wc <= 0x1DFF {
        return true;
    }
    // Combining Diacritical Marks for Symbols
    if wc >= 0x20D0 && wc <= 0x20FF {
        return true;
    }
    // Zero-width characters
    if wc >= 0x200B && wc <= 0x200F {
        return true;
    }
    // Bidi formatting
    if wc >= 0x202A && wc <= 0x202E {
        return true;
    }
    if wc >= 0x2060 && wc <= 0x206F {
        return true;
    }
    // CJK combining marks
    if wc >= 0x302A && wc <= 0x302F {
        return true;
    }
    // Japanese combining (dakuten, handakuten)
    if wc >= 0x3099 && wc <= 0x309A {
        return true;
    }
    // Variation Selectors
    if wc >= 0xFE00 && wc <= 0xFE0F {
        return true;
    }
    // Combining Half Marks
    if wc >= 0xFE20 && wc <= 0xFE2F {
        return true;
    }
    // BOM / ZWNBSP
    if wc == 0xFEFF {
        return true;
    }
    // Tags block
    if wc >= 0xE0001 && wc <= 0xE007F {
        return true;
    }
    // Variation Selectors Supplement
    if wc >= 0xE0100 && wc <= 0xE01EF {
        return true;
    }
    false
}

/// Returns true for East Asian fullwidth/wide characters.
#[inline]
fn is_wide_char(wc: u32) -> bool {
    // Hangul Jamo initial consonants
    (wc >= 0x1100 && wc <= 0x115F)
    // East Asian wide angle brackets
    || wc == 0x2329 || wc == 0x232A
    // CJK Radicals Supplement through CJK Symbols and Punctuation
    || (wc >= 0x2E80 && wc <= 0x303E)
    // Hiragana through Hangul Compatibility Jamo
    || (wc >= 0x3041 && wc <= 0x33FF)
    // CJK Unified Ideographs Extension A
    || (wc >= 0x3400 && wc <= 0x4DBF)
    // CJK Unified Ideographs through Yi Radicals
    || (wc >= 0x4E00 && wc <= 0xA4CF)
    // Hangul Syllables
    || (wc >= 0xAC00 && wc <= 0xD7A3)
    // CJK Compatibility Ideographs
    || (wc >= 0xF900 && wc <= 0xFAFF)
    // Vertical Forms
    || (wc >= 0xFE10 && wc <= 0xFE19)
    // CJK Compatibility Forms through Small Form Variants
    || (wc >= 0xFE30 && wc <= 0xFE6F)
    // Fullwidth Forms
    || (wc >= 0xFF01 && wc <= 0xFF60)
    || (wc >= 0xFFE0 && wc <= 0xFFE6)
    // Emoji and Symbols (common wide ranges)
    || (wc >= 0x1F300 && wc <= 0x1F9FF)
    // CJK Unified Ideographs Extension B through Extension G+
    || (wc >= 0x20000 && wc <= 0x3FFFF)
}

#[unsafe(no_mangle)]
pub extern "C" fn wcwidth(wc: WcharT) -> i32 {
    let cp = wc as u32;
    // NUL
    if cp == 0 {
        return 0;
    }
    // C0 controls, DEL
    if cp < 0x20 || cp == 0x7F {
        return -1;
    }
    // C1 controls
    if cp >= 0x80 && cp <= 0x9F {
        return -1;
    }
    // Surrogates, noncharacters
    if cp >= 0xD800 && cp <= 0xDFFF {
        return -1;
    }
    if cp > 0x10FFFF {
        return -1;
    }
    // Zero-width (combining marks, format characters)
    if is_zero_width(cp) {
        return 0;
    }
    // East Asian wide/fullwidth
    if is_wide_char(cp) {
        return 2;
    }
    // Everything else is single-width
    1
}

// ---------------------------------------------------------------------------
// Wide string operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcslen(ws: *const WcharT) -> usize {
    unsafe {
        let mut len: usize = 0;
        while *ws.add(len) != 0 {
            len += 1;
        }
        len
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcscmp(s1: *const WcharT, s2: *const WcharT) -> i32 {
    unsafe {
        let mut i: usize = 0;
        loop {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b || a == 0 {
                return if a < b { -1 } else if a > b { 1 } else { 0 };
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcsncmp(
    s1: *const WcharT,
    s2: *const WcharT,
    n: usize,
) -> i32 {
    unsafe {
        let mut i: usize = 0;
        while i < n {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b || a == 0 {
                return if a < b { -1 } else if a > b { 1 } else { 0 };
            }
            i += 1;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcscpy(
    dst: *mut WcharT,
    src: *const WcharT,
) -> *mut WcharT {
    unsafe {
        let mut i: usize = 0;
        loop {
            *dst.add(i) = *src.add(i);
            if *src.add(i) == 0 {
                break;
            }
            i += 1;
        }
        dst
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcsncpy(
    dst: *mut WcharT,
    src: *const WcharT,
    n: usize,
) -> *mut WcharT {
    unsafe {
        let mut i: usize = 0;
        while i < n && *src.add(i) != 0 {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        while i < n {
            *dst.add(i) = 0;
            i += 1;
        }
        dst
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcschr(
    ws: *const WcharT,
    wc: WcharT,
) -> *mut WcharT {
    unsafe {
        let mut i: usize = 0;
        loop {
            if *ws.add(i) == wc {
                return ws.add(i) as *mut WcharT;
            }
            if *ws.add(i) == 0 {
                return core::ptr::null_mut();
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcsrchr(
    ws: *const WcharT,
    wc: WcharT,
) -> *mut WcharT {
    unsafe {
        let mut last: *mut WcharT = core::ptr::null_mut();
        let mut i: usize = 0;
        loop {
            if *ws.add(i) == wc {
                last = ws.add(i) as *mut WcharT;
            }
            if *ws.add(i) == 0 {
                return last;
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcscat(
    dst: *mut WcharT,
    src: *const WcharT,
) -> *mut WcharT {
    unsafe {
        let end = wcslen(dst);
        wcscpy(dst.add(end), src);
        dst
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcsncat(
    dst: *mut WcharT,
    src: *const WcharT,
    n: usize,
) -> *mut WcharT {
    unsafe {
        let end = wcslen(dst);
        let mut i: usize = 0;
        while i < n && *src.add(i) != 0 {
            *dst.add(end + i) = *src.add(i);
            i += 1;
        }
        *dst.add(end + i) = 0;
        dst
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wmemcpy(
    dst: *mut WcharT,
    src: *const WcharT,
    n: usize,
) -> *mut WcharT {
    unsafe {
        let mut i: usize = 0;
        while i < n {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        dst
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wmemset(
    dst: *mut WcharT,
    wc: WcharT,
    n: usize,
) -> *mut WcharT {
    unsafe {
        let mut i: usize = 0;
        while i < n {
            *dst.add(i) = wc;
            i += 1;
        }
        dst
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wmemchr(
    ws: *const WcharT,
    wc: WcharT,
    n: usize,
) -> *mut WcharT {
    unsafe {
        let mut i: usize = 0;
        while i < n {
            if *ws.add(i) == wc {
                return ws.add(i) as *mut WcharT;
            }
            i += 1;
        }
        core::ptr::null_mut()
    }
}

// ---------------------------------------------------------------------------
// Multibyte state / string conversions
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn mbsinit(_ps: *const MbstateT) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mbsrtowcs(
    dst: *mut WcharT,
    src: *mut *const u8,
    len: usize,
    _ps: *mut MbstateT,
) -> usize {
    unsafe {
        if src.is_null() || (*src).is_null() {
            return 0;
        }

        let mut s = *src;
        let mut wc_count: usize = 0;

        if dst.is_null() {
            // Count mode: count wide characters
            loop {
                let mut wc: WcharT = 0;
                let result = mbrtowc(&raw mut wc, s, 4, core::ptr::null_mut());
                if result == 0 {
                    break;
                }
                if result == usize::MAX || result == usize::MAX - 1 {
                    crate::errno::set_errno(crate::errno::EILSEQ);
                    return usize::MAX;
                }
                s = s.add(result);
                wc_count += 1;
            }
            return wc_count;
        }

        while wc_count < len {
            let mut wc: WcharT = 0;
            let result = mbrtowc(&raw mut wc, s, 4, core::ptr::null_mut());
            if result == 0 {
                *dst.add(wc_count) = 0;
                *src = core::ptr::null();
                return wc_count;
            }
            if result == usize::MAX || result == usize::MAX - 1 {
                crate::errno::set_errno(crate::errno::EILSEQ);
                return usize::MAX;
            }
            *dst.add(wc_count) = wc;
            s = s.add(result);
            wc_count += 1;
        }

        *src = s;
        wc_count
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcsrtombs(
    dst: *mut u8,
    src: *mut *const WcharT,
    len: usize,
    _ps: *mut MbstateT,
) -> usize {
    unsafe {
        if src.is_null() || (*src).is_null() {
            return 0;
        }

        let mut s = *src;
        let mut byte_count: usize = 0;

        if dst.is_null() {
            // Count mode: count total bytes needed
            loop {
                let wc = *s;
                if wc == 0 {
                    break;
                }
                let mut buf: [u8; 4] = [0; 4];
                let result = wcrtomb(buf.as_mut_ptr(), wc, core::ptr::null_mut());
                if result == usize::MAX {
                    return usize::MAX;
                }
                byte_count += result;
                s = s.add(1);
            }
            return byte_count;
        }

        loop {
            let wc = *s;
            if wc == 0 {
                if byte_count < len {
                    *dst.add(byte_count) = 0;
                }
                *src = core::ptr::null();
                return byte_count;
            }
            let mut buf: [u8; 4] = [0; 4];
            let result = wcrtomb(buf.as_mut_ptr(), wc, core::ptr::null_mut());
            if result == usize::MAX {
                return usize::MAX;
            }
            if byte_count + result > len {
                break;
            }
            let mut i = 0;
            while i < result {
                *dst.add(byte_count + i) = buf[i];
                i += 1;
            }
            byte_count += result;
            s = s.add(1);
        }

        *src = s;
        byte_count
    }
}

// ---------------------------------------------------------------------------
// Locale / codeset helpers
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn nl_langinfo(item: i32) -> *const u8 {
    const ABMON: [&[u8]; 12] = [
        b"Jan\0", b"Feb\0", b"Mar\0", b"Apr\0", b"May\0", b"Jun\0",
        b"Jul\0", b"Aug\0", b"Sep\0", b"Oct\0", b"Nov\0", b"Dec\0",
    ];
    match item {
        14 => b"UTF-8\0".as_ptr(), // CODESET
        33..=44 => ABMON[(item - 33) as usize].as_ptr(),
        51 => b"md\0".as_ptr(),    // D_MD_ORDER
        _ => b"\0".as_ptr(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __ctype_get_mb_cur_max() -> usize {
    4
}

// ---------------------------------------------------------------------------
// mbstowcs / wcstombs / mbrlen
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mbstowcs(
    dst: *mut WcharT,
    src: *const u8,
    n: usize,
) -> usize {
    unsafe {
        if src.is_null() {
            return 0;
        }
        let mut s = src;
        let mut wc_count: usize = 0;

        if dst.is_null() {
            loop {
                let mut wc: WcharT = 0;
                let result = mbrtowc(&raw mut wc, s, 4, core::ptr::null_mut());
                if result == 0 {
                    break;
                }
                if result == usize::MAX || result == usize::MAX - 1 {
                    crate::errno::set_errno(crate::errno::EILSEQ);
                    return usize::MAX;
                }
                s = s.add(result);
                wc_count += 1;
            }
            return wc_count;
        }

        while wc_count < n {
            let mut wc: WcharT = 0;
            let result = mbrtowc(&raw mut wc, s, 4, core::ptr::null_mut());
            if result == 0 {
                *dst.add(wc_count) = 0;
                return wc_count;
            }
            if result == usize::MAX || result == usize::MAX - 1 {
                crate::errno::set_errno(crate::errno::EILSEQ);
                return usize::MAX;
            }
            *dst.add(wc_count) = wc;
            s = s.add(result);
            wc_count += 1;
        }
        wc_count
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcstombs(
    dst: *mut u8,
    src: *const WcharT,
    n: usize,
) -> usize {
    unsafe {
        if src.is_null() {
            return 0;
        }
        let mut s = src;
        let mut byte_count: usize = 0;

        if dst.is_null() {
            loop {
                let wc = *s;
                if wc == 0 {
                    break;
                }
                let mut buf: [u8; 4] = [0; 4];
                let result = wcrtomb(buf.as_mut_ptr(), wc, core::ptr::null_mut());
                if result == usize::MAX {
                    return usize::MAX;
                }
                byte_count += result;
                s = s.add(1);
            }
            return byte_count;
        }

        loop {
            let wc = *s;
            if wc == 0 {
                if byte_count < n {
                    *dst.add(byte_count) = 0;
                }
                return byte_count;
            }
            let mut buf: [u8; 4] = [0; 4];
            let result = wcrtomb(buf.as_mut_ptr(), wc, core::ptr::null_mut());
            if result == usize::MAX {
                return usize::MAX;
            }
            if byte_count + result > n {
                break;
            }
            let mut i = 0;
            while i < result {
                *dst.add(byte_count + i) = buf[i];
                i += 1;
            }
            byte_count += result;
            s = s.add(1);
        }
        byte_count
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mbrlen(
    s: *const u8,
    n: usize,
    ps: *mut MbstateT,
) -> usize {
    unsafe { mbrtowc(core::ptr::null_mut(), s, n, ps) }
}

// ---------------------------------------------------------------------------
// wcscoll / wcsstr / wcstoull / wcstod / fwprintf
// ---------------------------------------------------------------------------

/// wcscoll — collation in C locale is just wcscmp.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcscoll(s1: *const WcharT, s2: *const WcharT) -> i32 {
    unsafe { wcscmp(s1, s2) }
}

/// wcsstr — find wide substring.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcsstr(
    haystack: *const WcharT,
    needle: *const WcharT,
) -> *mut WcharT {
    unsafe {
        if *needle == 0 {
            return haystack as *mut WcharT;
        }
        let nlen = wcslen(needle);
        let hlen = wcslen(haystack);
        if nlen > hlen {
            return core::ptr::null_mut();
        }
        let mut i: usize = 0;
        while i <= hlen - nlen {
            if wcsncmp(haystack.add(i), needle, nlen) == 0 {
                return haystack.add(i) as *mut WcharT;
            }
            i += 1;
        }
        core::ptr::null_mut()
    }
}

unsafe extern "C" {
    safe fn strtod(s: *const u8, endp: *mut *mut u8) -> f64;
    safe fn strtoull(s: *const u8, endp: *mut *mut u8, base: i32) -> u64;
    safe fn malloc(size: usize) -> *mut u8;
    safe fn free(ptr: *mut u8);
}

/// wcstod — convert wide string to double (C locale: just narrow and call strtod).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcstod(
    wcs: *const WcharT,
    endp: *mut *mut WcharT,
) -> f64 {
    unsafe {
        let len = wcslen(wcs);
        let buf = malloc(len + 1);
        if buf.is_null() {
            return 0.0;
        }
        for i in 0..len {
            *buf.add(i) = *wcs.add(i) as u8;
        }
        *buf.add(len) = 0;
        let mut narrow_end: *mut u8 = core::ptr::null_mut();
        let result = strtod(buf, &raw mut narrow_end);
        if !endp.is_null() {
            let consumed = narrow_end.offset_from(buf) as usize;
            *endp = wcs.add(consumed) as *mut WcharT;
        }
        free(buf);
        result
    }
}

/// wcstoull — convert wide string to unsigned long long.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcstoull(
    wcs: *const WcharT,
    endp: *mut *mut WcharT,
    base: i32,
) -> u64 {
    unsafe {
        let len = wcslen(wcs);
        let buf = malloc(len + 1);
        if buf.is_null() {
            return 0;
        }
        for i in 0..len {
            *buf.add(i) = *wcs.add(i) as u8;
        }
        *buf.add(len) = 0;
        let mut narrow_end: *mut u8 = core::ptr::null_mut();
        let result = strtoull(buf, &raw mut narrow_end, base);
        if !endp.is_null() {
            let consumed = narrow_end.offset_from(buf) as usize;
            *endp = wcs.add(consumed) as *mut WcharT;
        }
        free(buf);
        result
    }
}

/// wcsdup — duplicate wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcsdup(src: *const WcharT) -> *mut WcharT {
    unsafe {
        let len = wcslen(src);
        let buf = malloc((len + 1) * 4) as *mut WcharT;
        if buf.is_null() {
            return core::ptr::null_mut();
        }
        core::ptr::copy_nonoverlapping(src, buf, len + 1);
        buf
    }
}

/// fwprintf — wide formatted print. Not implemented.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fwprintf(
    _stream: *mut u8,
    _fmt: *const WcharT,
    _args: ...
) -> i32 {
    crate::errno::set_errno(crate::errno::ENOSYS);
    -1
}

// ---------------------------------------------------------------------------
// Wide character I/O (UTF-8 encoding)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    safe fn fgetc(stream: *mut crate::stdio::FILE) -> i32;
    safe fn fputc(c: i32, stream: *mut crate::stdio::FILE) -> i32;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fgetwc(stream: *mut crate::stdio::FILE) -> WintT {
    let c = fgetc(stream);
    if c < 0 {
        return WEOF;
    }
    let lead = c as u8;
    // ASCII fast path
    if lead < 0x80 {
        return lead as WintT;
    }
    let seq_len = utf8_char_len(lead);
    if seq_len == 0 {
        crate::errno::set_errno(crate::errno::EILSEQ);
        return WEOF;
    }
    let mut buf: [u8; 4] = [0; 4];
    buf[0] = lead;
    let mut i = 1;
    while i < seq_len {
        let next = fgetc(stream);
        if next < 0 {
            crate::errno::set_errno(crate::errno::EILSEQ);
            return WEOF;
        }
        buf[i] = next as u8;
        i += 1;
    }
    let mut wc: WcharT = 0;
    unsafe {
        let result = mbrtowc(&raw mut wc, buf.as_ptr(), seq_len, core::ptr::null_mut());
        if result == usize::MAX || result == usize::MAX - 1 {
            return WEOF;
        }
    }
    wc as WintT
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fputwc(wc: WintT, stream: *mut crate::stdio::FILE) -> WintT {
    if wc == WEOF {
        return WEOF;
    }
    let mut buf: [u8; 4] = [0; 4];
    let len = unsafe { wcrtomb(buf.as_mut_ptr(), wc as WcharT, core::ptr::null_mut()) };
    if len == usize::MAX {
        return WEOF;
    }
    let mut i = 0;
    while i < len {
        let c = fputc(buf[i] as i32, stream);
        if c < 0 {
            return WEOF;
        }
        i += 1;
    }
    wc
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getwc(stream: *mut crate::stdio::FILE) -> WintT {
    unsafe { fgetwc(stream) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getwchar() -> WintT {
    crate::stdio::ensure_stdio_init();
    unsafe {
        fgetwc((*(&raw const crate::stdio::stdin)))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn putwchar(wc: WintT) -> WintT {
    crate::stdio::ensure_stdio_init();
    unsafe {
        fputwc(wc, (*(&raw const crate::stdio::stdout)))
    }
}
