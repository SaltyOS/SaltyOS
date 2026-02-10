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
