//! FreeBSD locale/rune internals
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! FreeBSD's ctype.h inline functions expand to ___runetype() and friends.
//! These provide an ASCII rune table for character classification.

// Minimal _RuneLocale structure — just enough for __getCurrentRuneLocale
#[repr(C)]
pub struct RuneLocale {
    pub __runetype: [u32; 256],
}

// ASCII rune table: classify characters for ctype
static mut ASCII_RUNE_LOCALE: RuneLocale = RuneLocale {
    __runetype: [0; 256],
};
static mut ASCII_RUNE_INITED: bool = false;

unsafe fn ensure_ascii_rune() {
    unsafe {
        if ASCII_RUNE_INITED {
            return;
        }
        let rt = &raw mut ASCII_RUNE_LOCALE;
        // FreeBSD rune type bits
        const _CTYPE_U: u32 = 0x01; // upper
        const _CTYPE_L: u32 = 0x02; // lower
        const _CTYPE_D: u32 = 0x04; // digit
        const _CTYPE_S: u32 = 0x08; // space
        const _CTYPE_P: u32 = 0x10; // punct
        const _CTYPE_C: u32 = 0x20; // control
        const _CTYPE_X: u32 = 0x80; // xdigit
        const _CTYPE_B: u32 = 0x100; // blank
        const _CTYPE_A: u32 = 0x40; // alpha
        const _CTYPE_G: u32 = 0x200; // graph
        const _CTYPE_R: u32 = 0x400; // print

        for i in 0u16..256 {
            let mut t: u32 = 0;
            if i < 32 || i == 127 {
                t |= _CTYPE_C;
            }
            if i >= b'A' as u16 && i <= b'Z' as u16 {
                t |= _CTYPE_U | _CTYPE_A | _CTYPE_G | _CTYPE_R;
            }
            if i >= b'a' as u16 && i <= b'z' as u16 {
                t |= _CTYPE_L | _CTYPE_A | _CTYPE_G | _CTYPE_R;
            }
            if i >= b'0' as u16 && i <= b'9' as u16 {
                t |= _CTYPE_D | _CTYPE_G | _CTYPE_R;
            }
            if (i >= b'A' as u16 && i <= b'F' as u16)
                || (i >= b'a' as u16 && i <= b'f' as u16)
                || (i >= b'0' as u16 && i <= b'9' as u16)
            {
                t |= _CTYPE_X;
            }
            if i == b' ' as u16 || i == b'\t' as u16 {
                t |= _CTYPE_B;
            }
            if i == b' ' as u16
                || (i >= 9 && i <= 13) // \t \n \v \f \r
            {
                t |= _CTYPE_S;
            }
            if i >= 33 && i <= 126 {
                // All visible ASCII are printable
                t |= _CTYPE_R;
                if (t & (_CTYPE_A | _CTYPE_D)) == 0 {
                    t |= _CTYPE_P | _CTYPE_G;
                }
            }
            if i == b' ' as u16 {
                t |= _CTYPE_R; // space is printable
            }
            (*rt).__runetype[i as usize] = t;
        }
        ASCII_RUNE_INITED = true;
    }
}

#[unsafe(no_mangle)]
pub static mut _CurrentRuneLocale: *mut RuneLocale = core::ptr::null_mut();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ___runetype(c: i32) -> u32 {
    unsafe {
        ensure_ascii_rune();
        if c >= 0 && c < 256 {
            ASCII_RUNE_LOCALE.__runetype[c as usize]
        } else {
            0
        }
    }
}

/// Initialize _CurrentRuneLocale to point to ASCII table.
/// Called from CRT startup.
pub fn init_rune_locale() {
    unsafe {
        ensure_ascii_rune();
        _CurrentRuneLocale = &raw mut ASCII_RUNE_LOCALE;
    }
}

// Single-byte limit for multibyte chars (ASCII = 128)
#[unsafe(no_mangle)]
pub static mut __mb_sb_limit: i32 = 128;

/// ___mb_cur_max — FreeBSD's MB_CUR_MAX macro reads this. 1 = single-byte locale.
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
