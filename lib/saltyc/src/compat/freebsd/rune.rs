//! FreeBSD locale/rune internals
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! FreeBSD headers inline ctype/wctype operations around `_CurrentRuneLocale`
//! and `_DefaultRuneLocale`. Keep these symbols/layouts ABI-compatible so
//! binaries built with FreeBSD headers classify ASCII correctly.

#[repr(C)]
pub struct RuneEntry {
    pub __min: i32,
    pub __max: i32,
    pub __map: i32,
    pub __types: *mut u64,
}

#[repr(C)]
pub struct RuneRange {
    pub __nranges: i32,
    pub __ranges: *mut RuneEntry,
}

type SgetRuneFn = unsafe extern "C" fn(*const u8, usize, *mut *const u8) -> i32;
type SputRuneFn = unsafe extern "C" fn(i32, *mut u8, usize, *mut *mut u8) -> i32;

#[repr(C)]
pub struct RuneLocale {
    pub __magic: [u8; 8],
    pub __encoding: [u8; 32],
    pub __sgetrune: Option<SgetRuneFn>,
    pub __sputrune: Option<SputRuneFn>,
    pub __invalid_rune: i32,
    pub __runetype: [u64; 256],
    pub __maplower: [i32; 256],
    pub __mapupper: [i32; 256],
    pub __runetype_ext: RuneRange,
    pub __maplower_ext: RuneRange,
    pub __mapupper_ext: RuneRange,
    pub __variable: *mut core::ffi::c_void,
    pub __variable_len: i32,
}

const EMPTY_RANGE: RuneRange = RuneRange {
    __nranges: 0,
    __ranges: core::ptr::null_mut(),
};

const EMPTY_LOCALE: RuneLocale = RuneLocale {
    __magic: [0; 8],
    __encoding: [0; 32],
    __sgetrune: None,
    __sputrune: None,
    __invalid_rune: -1,
    __runetype: [0; 256],
    __maplower: [0; 256],
    __mapupper: [0; 256],
    __runetype_ext: EMPTY_RANGE,
    __maplower_ext: EMPTY_RANGE,
    __mapupper_ext: EMPTY_RANGE,
    __variable: core::ptr::null_mut(),
    __variable_len: 0,
};

static mut ASCII_RUNE_INITED: bool = false;
static mut ASCII_RUNE_LOCALE: RuneLocale = EMPTY_LOCALE;

#[unsafe(no_mangle)]
pub static mut _DefaultRuneLocale: RuneLocale = EMPTY_LOCALE;

#[unsafe(no_mangle)]
pub static mut _CurrentRuneLocale: *const RuneLocale = core::ptr::null();

unsafe fn ensure_ascii_rune() {
    unsafe {
        if ASCII_RUNE_INITED {
            return;
        }

        // FreeBSD _ctype.h bit definitions.
        const _CTYPE_A: u64 = 0x0000_0100;
        const _CTYPE_C: u64 = 0x0000_0200;
        const _CTYPE_D: u64 = 0x0000_0400;
        const _CTYPE_G: u64 = 0x0000_0800;
        const _CTYPE_L: u64 = 0x0000_1000;
        const _CTYPE_P: u64 = 0x0000_2000;
        const _CTYPE_S: u64 = 0x0000_4000;
        const _CTYPE_U: u64 = 0x0000_8000;
        const _CTYPE_X: u64 = 0x0001_0000;
        const _CTYPE_B: u64 = 0x0002_0000;
        const _CTYPE_R: u64 = 0x0004_0000;

        ASCII_RUNE_LOCALE = EMPTY_LOCALE;
        _DefaultRuneLocale = EMPTY_LOCALE;

        ASCII_RUNE_LOCALE.__magic = *b"RuneMagi";
        ASCII_RUNE_LOCALE.__encoding[0] = b'C';
        _DefaultRuneLocale.__magic = *b"RuneMagi";
        _DefaultRuneLocale.__encoding[0] = b'C';

        for i in 0u16..256 {
            let c = i as u8;
            let mut t: u64 = 0;

            if c < 32 || c == 127 {
                t |= _CTYPE_C;
            }
            if c == b' ' || c == b'\t' {
                t |= _CTYPE_B;
            }
            if c == b' ' || (9..=13).contains(&c) {
                t |= _CTYPE_S;
            }
            if c.is_ascii_uppercase() {
                t |= _CTYPE_U | _CTYPE_A | _CTYPE_G | _CTYPE_R;
            }
            if c.is_ascii_lowercase() {
                t |= _CTYPE_L | _CTYPE_A | _CTYPE_G | _CTYPE_R;
            }
            if c.is_ascii_digit() {
                t |= _CTYPE_D | _CTYPE_G | _CTYPE_R;
            }
            if c.is_ascii_hexdigit() {
                t |= _CTYPE_X;
            }
            if (33..=126).contains(&c) {
                t |= _CTYPE_R;
                if !c.is_ascii_alphanumeric() {
                    t |= _CTYPE_P | _CTYPE_G;
                }
            }
            if c == b' ' {
                t |= _CTYPE_R;
            }

            ASCII_RUNE_LOCALE.__runetype[i as usize] = t;
            _DefaultRuneLocale.__runetype[i as usize] = t;

            let lower = if c.is_ascii_uppercase() {
                (c + 32) as i32
            } else {
                c as i32
            };
            let upper = if c.is_ascii_lowercase() {
                (c - 32) as i32
            } else {
                c as i32
            };
            ASCII_RUNE_LOCALE.__maplower[i as usize] = lower;
            ASCII_RUNE_LOCALE.__mapupper[i as usize] = upper;
            _DefaultRuneLocale.__maplower[i as usize] = lower;
            _DefaultRuneLocale.__mapupper[i as usize] = upper;
        }

        _CurrentRuneLocale = &raw const ASCII_RUNE_LOCALE;
        ASCII_RUNE_INITED = true;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ___runetype(c: i32) -> u64 {
    unsafe {
        ensure_ascii_rune();
        if c >= 0 && c < 256 {
            (*_CurrentRuneLocale).__runetype[c as usize]
        } else {
            0
        }
    }
}

/// Initialize `_CurrentRuneLocale` to point to ASCII tables.
/// Called from CRT startup before `main()`.
pub fn init_rune_locale() {
    unsafe {
        ensure_ascii_rune();
        _CurrentRuneLocale = &raw const ASCII_RUNE_LOCALE;
    }
}

/// ASCII single-byte locale.
#[unsafe(no_mangle)]
pub static mut __mb_sb_limit: i32 = 128;

/// MB_CUR_MAX for the C locale.
#[unsafe(no_mangle)]
pub static ___mb_cur_max: i32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn ___toupper(c: i32) -> i32 {
    if c >= b'a' as i32 && c <= b'z' as i32 {
        c - 32
    } else {
        c
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ___tolower(c: i32) -> i32 {
    if c >= b'A' as i32 && c <= b'Z' as i32 {
        c + 32
    } else {
        c
    }
}
