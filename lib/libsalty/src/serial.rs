//! Serial output via DebugPutChar syscall
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::SYS_DEBUG_PUTCHAR;
use crate::syscall::syscall;

#[inline(always)]
pub fn serial_putc(c: u8) {
    syscall(SYS_DEBUG_PUTCHAR, c as u64, 0, 0, 0, 0, 0);
}

pub fn serial_puts(s: &[u8]) {
    for &b in s {
        serial_putc(b);
    }
}

pub fn serial_hex(val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    serial_putc(b'0');
    serial_putc(b'x');
    if val == 0 {
        serial_putc(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut pos: i32 = 15;
    let mut v = val;
    while v > 0 && pos >= 0 {
        buf[pos as usize] = HEX[(v & 0xF) as usize];
        v >>= 4;
        pos -= 1;
    }
    for i in (pos + 1) as usize..16 {
        serial_putc(buf[i]);
    }
}

pub fn serial_dec(val: u64) {
    if val == 0 {
        serial_putc(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos = 19i32;
    let mut v = val;
    while v > 0 && pos >= 0 {
        buf[pos as usize] = b'0' + (v % 10) as u8;
        v /= 10;
        pos -= 1;
    }
    for i in (pos + 1) as usize..20 {
        serial_putc(buf[i]);
    }
}
