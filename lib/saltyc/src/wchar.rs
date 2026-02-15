//! Wide character / multibyte stubs (ASCII-only)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Since SaltyOS uses an ASCII/UTF-8 locale, all multibyte functions treat
//! each byte as a single character (`wchar_t = i32`, MB_CUR_MAX = 1).
//! Wide string operations (`wcslen`, `wcscmp`, `wcscpy`, etc.) operate on
//! 32-bit wchar_t arrays. Conversion functions (`wcstod`, `wcstoull`) narrow
//! to byte strings and delegate to the narrow equivalents.

pub type WcharT = i32;
pub type WintT = u32;
pub type MbstateT = u32;

pub const WEOF: WintT = 0xFFFFFFFF;

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
        let byte = *s;
        if byte == 0 {
            if !pwc.is_null() {
                *pwc = 0;
            }
            return 0;
        }
        if !pwc.is_null() {
            *pwc = byte as WcharT;
        }
        1
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
        *s = wc as u8;
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mblen(s: *const u8, _n: usize) -> i32 {
    if s.is_null() {
        return 0;
    }
    unsafe {
        if *s == 0 {
            0
        } else {
            1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mbtowc(
    pwc: *mut WcharT,
    s: *const u8,
    _n: usize,
) -> i32 {
    if s.is_null() {
        return 0;
    }
    unsafe {
        if *s == 0 {
            if !pwc.is_null() {
                *pwc = 0;
            }
            return 0;
        }
        if !pwc.is_null() {
            *pwc = *s as WcharT;
        }
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wctomb(s: *mut u8, wc: WcharT) -> i32 {
    if s.is_null() {
        return 0;
    }
    unsafe {
        *s = wc as u8;
        1
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
fn is_ascii(wc: WintT) -> bool {
    wc <= 0x7f
}

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
    if wc >= 0x20 && wc <= 0x7e { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswcntrl(wc: WintT) -> i32 {
    if (is_ascii(wc) && wc < 0x20) || wc == 0x7f { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn iswgraph(wc: WintT) -> i32 {
    if wc >= 0x21 && wc <= 0x7e { 1 } else { 0 }
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

#[unsafe(no_mangle)]
pub extern "C" fn wcwidth(wc: WcharT) -> i32 {
    if wc < 32 {
        0
    } else if wc >= 32 && wc < 127 {
        1
    } else {
        -1
    }
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

        let s = *src;
        let mut i: usize = 0;

        if dst.is_null() {
            // Just count characters
            while *s.add(i) != 0 {
                i += 1;
            }
            return i;
        }

        while i < len {
            let byte = *s.add(i);
            if byte == 0 {
                *dst.add(i) = 0;
                *src = core::ptr::null();
                return i;
            }
            *dst.add(i) = byte as WcharT;
            i += 1;
        }

        *src = s.add(i);
        i
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

        let s = *src;
        let mut i: usize = 0;

        if dst.is_null() {
            // Just count characters
            while *s.add(i) != 0 {
                i += 1;
            }
            return i;
        }

        while i < len {
            let wc = *s.add(i);
            if wc == 0 {
                *dst.add(i) = 0;
                *src = core::ptr::null();
                return i;
            }
            *dst.add(i) = wc as u8;
            i += 1;
        }

        *src = s.add(i);
        i
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
    1
}

// ---------------------------------------------------------------------------
// mbstowcs / mbrlen
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
        let mut i: usize = 0;
        if dst.is_null() {
            while *src.add(i) != 0 {
                i += 1;
            }
            return i;
        }
        while i < n {
            let byte = *src.add(i);
            if byte == 0 {
                *dst.add(i) = 0;
                return i;
            }
            *dst.add(i) = byte as WcharT;
            i += 1;
        }
        i
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mbrlen(
    s: *const u8,
    n: usize,
    _ps: *mut MbstateT,
) -> usize {
    unsafe {
        if s.is_null() || n == 0 {
            return 0;
        }
        if *s == 0 { 0 } else { 1 }
    }
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
