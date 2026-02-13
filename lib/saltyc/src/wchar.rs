//! Wide character / multibyte stubs (ASCII-only)
//! SPDX-License-Identifier: GPL-2.0-only

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
    if item == 14 {
        // CODESET
        b"UTF-8\0".as_ptr()
    } else {
        b"\0".as_ptr()
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
