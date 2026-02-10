//! Serial output via DebugPutBuf syscall
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::{SYS_DEBUG_PUTCHAR, SYS_DEBUG_PUTBUF};
use crate::syscall::syscall;

#[inline(always)]
pub fn serial_putc(c: u8) {
    syscall(SYS_DEBUG_PUTCHAR, c as u64, 0, 0, 0, 0, 0);
}

/// Write a byte slice to serial atomically (up to 256 bytes per syscall).
///
/// The kernel copies the data from user memory and outputs it under
/// SERIAL_LOCK in a single critical section, preventing interleaving.
pub fn serial_puts(s: &[u8]) {
    let mut off = 0;
    while off < s.len() {
        let chunk = if s.len() - off < 256 { s.len() - off } else { 256 };
        syscall(
            SYS_DEBUG_PUTBUF,
            s[off..].as_ptr() as u64,
            chunk as u64,
            0, 0, 0, 0,
        );
        off += chunk;
    }
}

/// Write a hexadecimal number to serial atomically (single syscall).
pub fn serial_hex(val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18]; // "0x" + up to 16 hex digits
    buf[0] = b'0';
    buf[1] = b'x';
    if val == 0 {
        buf[2] = b'0';
        serial_puts(&buf[..3]);
        return;
    }
    let mut tmp = [0u8; 16];
    let mut pos: usize = 16;
    let mut v = val;
    while v > 0 {
        pos -= 1;
        tmp[pos] = HEX[(v & 0xF) as usize];
        v >>= 4;
    }
    let digits = &tmp[pos..];
    let len = 2 + digits.len();
    buf[2..len].copy_from_slice(digits);
    serial_puts(&buf[..len]);
}

/// Write a decimal number to serial atomically (single syscall).
pub fn serial_dec(val: u64) {
    if val == 0 {
        serial_puts(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos: usize = 20;
    let mut v = val;
    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    serial_puts(&buf[pos..]);
}

/// Line buffer for compound serial output.
///
/// Accumulates multiple `.str()` / `.hex()` / `.dec()` calls into a single
/// buffer, then flushes atomically via one `serial_puts()` call. This ensures
/// compound messages (e.g. label + hex value + newline) are never interleaved
/// with output from other threads or CPUs.
///
/// ```rust
/// let mut lb = LineBuf::new();
/// lb.str(b"[TAG] Value=");
/// lb.hex(0x1234);
/// lb.str(b"\n");
/// lb.flush();
/// ```
pub struct LineBuf {
    buf: [u8; 256],
    pos: usize,
}

impl LineBuf {
    pub fn new() -> Self {
        Self { buf: [0; 256], pos: 0 }
    }

    pub fn str(&mut self, s: &[u8]) {
        for &b in s {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = b;
                self.pos += 1;
            }
        }
    }

    pub fn bytes(&mut self, s: &[u8]) {
        self.str(s);
    }

    pub fn hex(&mut self, val: u64) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.str(b"0x");
        if val == 0 {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = b'0';
                self.pos += 1;
            }
            return;
        }
        let mut tmp = [0u8; 16];
        let mut p: usize = 16;
        let mut v = val;
        while v > 0 && p > 0 {
            p -= 1;
            tmp[p] = HEX[(v & 0xF) as usize];
            v >>= 4;
        }
        for i in p..16 {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = tmp[i];
                self.pos += 1;
            }
        }
    }

    pub fn dec(&mut self, val: u64) {
        if val == 0 {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = b'0';
                self.pos += 1;
            }
            return;
        }
        let mut tmp = [0u8; 20];
        let mut p: usize = 20;
        let mut v = val;
        while v > 0 && p > 0 {
            p -= 1;
            tmp[p] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        for i in p..20 {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = tmp[i];
                self.pos += 1;
            }
        }
    }

    pub fn putc(&mut self, c: u8) {
        if self.pos < self.buf.len() - 1 {
            self.buf[self.pos] = c;
            self.pos += 1;
        }
    }

    pub fn flush(&mut self) {
        if self.pos > 0 {
            serial_puts(&self.buf[..self.pos]);
            self.pos = 0;
        }
    }
}
