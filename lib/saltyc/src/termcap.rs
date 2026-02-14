//! Termcap — minimal dumb terminal support
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides `tgetent` (always succeeds), `tgetflag` (always false), `tgetnum`
//! (returns `co=80`, `li=24`, -1 for others), `tgetstr` (returns null),
//! `tputs` (outputs string directly), and `tgoto` (returns null).
//! Sufficient for programs that probe terminal capabilities but fall back
//! to dumb-terminal mode.

use core::ptr;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tgetent(_bp: *mut u8, _name: *const u8) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tgetnum(id: *const u8) -> i32 {
    unsafe {
        let c0 = *id;
        let c1 = *id.add(1);
        if c0 == b'c' && c1 == b'o' {
            80
        } else if c0 == b'l' && c1 == b'i' {
            24
        } else {
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tgetflag(_id: *const u8) -> i32 {
    0
}

// Static byte arrays for escape sequences
static SEQ_UP: [u8; 4] = [0x1b, b'[', b'A', 0];
static SEQ_DO: [u8; 4] = [0x1b, b'[', b'B', 0];
static SEQ_LE: [u8; 2] = [0x08, 0];
static SEQ_ND: [u8; 4] = [0x1b, b'[', b'C', 0];
static SEQ_CL: [u8; 8] = [0x1b, b'[', b'H', 0x1b, b'[', b'2', b'J', 0];
static SEQ_CE: [u8; 4] = [0x1b, b'[', b'K', 0];
static SEQ_CM: [u8; 9] = [0x1b, b'[', b'%', b'd', b';', b'%', b'd', b'H', 0];
static SEQ_CR: [u8; 2] = [b'\r', 0];
static SEQ_NL: [u8; 2] = [b'\n', 0];
static SEQ_BL: [u8; 2] = [0x07, 0];
static SEQ_PC: [u8; 1] = [0];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tgetstr(id: *const u8, _area: *mut *mut u8) -> *const u8 {
    unsafe {
        let c0 = *id;
        let c1 = *id.add(1);
        match (c0, c1) {
            (b'u', b'p') => SEQ_UP.as_ptr(),
            (b'd', b'o') => SEQ_DO.as_ptr(),
            (b'l', b'e') => SEQ_LE.as_ptr(),
            (b'n', b'd') => SEQ_ND.as_ptr(),
            (b'c', b'l') => SEQ_CL.as_ptr(),
            (b'c', b'e') => SEQ_CE.as_ptr(),
            (b'c', b'm') => SEQ_CM.as_ptr(),
            (b'c', b'r') => SEQ_CR.as_ptr(),
            (b'n', b'l') => SEQ_NL.as_ptr(),
            (b'b', b'l') => SEQ_BL.as_ptr(),
            (b'p', b'c') => SEQ_PC.as_ptr(),
            _ => ptr::null(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tputs(str: *const u8, _affcnt: i32, putc_fn: unsafe extern "C" fn(i32) -> i32) -> i32 {
    if str.is_null() {
        return 0;
    }
    unsafe {
        let mut i = 0;
        while *str.add(i) != 0 {
            putc_fn(*str.add(i) as i32);
            i += 1;
        }
    }
    0
}

static mut TGOTO_BUF: [u8; 32] = [0; 32];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tgoto(_cm: *const u8, col: i32, row: i32) -> *const u8 {
    unsafe {
        let buf = &raw mut TGOTO_BUF;
        let buf_ptr = buf as *mut u8;
        let mut pos = 0;

        // Write "\x1b["
        *buf_ptr.add(pos) = 0x1b;
        pos += 1;
        *buf_ptr.add(pos) = b'[';
        pos += 1;

        // Write row+1
        pos += write_decimal(buf_ptr.add(pos), (row + 1) as u32);

        // Write ";"
        *buf_ptr.add(pos) = b';';
        pos += 1;

        // Write col+1
        pos += write_decimal(buf_ptr.add(pos), (col + 1) as u32);

        // Write "H"
        *buf_ptr.add(pos) = b'H';
        pos += 1;

        // Null-terminate
        *buf_ptr.add(pos) = 0;

        buf_ptr as *const u8
    }
}

fn write_decimal(buf: *mut u8, val: u32) -> usize {
    if val == 0 {
        unsafe {
            *buf = b'0';
        }
        return 1;
    }

    let mut tmp = [0u8; 10];
    let mut n = val;
    let mut len = 0;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }

    // Reverse into buf
    for i in 0..len {
        unsafe {
            *buf.add(i) = tmp[len - 1 - i];
        }
    }
    len
}
