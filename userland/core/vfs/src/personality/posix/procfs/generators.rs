// SPDX-License-Identifier: GPL-2.0-only
//! Formatting utilities and byte-level generators for /proc content.

/// Parse a decimal ASCII string as a PID. Returns (value, ok).
pub(crate) fn parse_pid(buf: &[u8]) -> (u32, bool) {
    if buf.is_empty() || buf.len() > 10 {
        return (0, false);
    }
    let mut val: u32 = 0;
    for &b in buf {
        if b < b'0' || b > b'9' {
            return (0, false);
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u32);
    }
    (val, true)
}

/// Format u32 as decimal into buf. Returns number of bytes written.
pub(crate) fn fmt_u32(mut v: u32, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while v > 0 && len < 10 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

/// Format u64 as decimal into buf. Returns number of bytes written.
pub(crate) fn fmt_u64(mut v: u64, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while v > 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

/// Format u64 as hex into buf. Returns number of bytes written.
pub(crate) fn fmt_u64_hex(mut v: u64, buf: &mut [u8]) -> usize {
    if v == 0 {
        if buf.len() >= 3 {
            buf[0] = b'0';
            buf[1] = b'x';
            buf[2] = b'0';
            return 3;
        }
        return 0;
    }
    let mut tmp = [0u8; 16];
    let mut len = 0usize;
    while v > 0 && len < 16 {
        let d = (v & 0xf) as u8;
        tmp[len] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v >>= 4;
        len += 1;
    }
    if buf.len() < len + 2 {
        return 0;
    }
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..len {
        buf[2 + i] = tmp[len - 1 - i];
    }
    len + 2
}

/// Simple memory comparison (no libc).
pub(crate) fn mem_eq(a: *const u8, b: *const u8, len: usize) -> bool {
    for i in 0..len {
        // SAFETY: caller guarantees both pointers are valid for `len` bytes.
        unsafe {
            if *a.add(i) != *b.add(i) {
                return false;
            }
        }
    }
    true
}

pub(super) fn append_bytes(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
    let mut i = 0usize;
    while i < data.len() && *pos < buf.len() {
        buf[*pos] = data[i];
        *pos += 1;
        i += 1;
    }
}

pub(super) fn append_u32_dec(buf: &mut [u8], pos: &mut usize, v: u32) {
    let mut tmp = [0u8; 16];
    let len = fmt_u32(v, &mut tmp);
    append_bytes(buf, pos, &tmp[..len]);
}

pub(super) fn append_u64_dec(buf: &mut [u8], pos: &mut usize, mut v: u64) {
    if v == 0 {
        append_bytes(buf, pos, b"0");
        return;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while v > 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        append_bytes(buf, pos, &tmp[len..len + 1]);
    }
}

pub(super) fn append_ipv4(buf: &mut [u8], pos: &mut usize, ip: u32) {
    append_u32_dec(buf, pos, (ip >> 24) & 0xFF);
    append_bytes(buf, pos, b".");
    append_u32_dec(buf, pos, (ip >> 16) & 0xFF);
    append_bytes(buf, pos, b".");
    append_u32_dec(buf, pos, (ip >> 8) & 0xFF);
    append_bytes(buf, pos, b".");
    append_u32_dec(buf, pos, ip & 0xFF);
}

pub(super) fn append_mac(buf: &mut [u8], pos: &mut usize, mac: &[u8; 6]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0usize;
    while i < 6 {
        let b = mac[i];
        append_bytes(buf, pos, &[HEX[(b >> 4) as usize], HEX[(b & 0x0F) as usize]]);
        if i != 5 {
            append_bytes(buf, pos, b":");
        }
        i += 1;
    }
}

pub(super) fn append_hex_u32_fixed(buf: &mut [u8], pos: &mut usize, mut v: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = [0u8; 8];
    let mut i = 8usize;
    while i > 0 {
        i -= 1;
        out[i] = HEX[(v & 0x0F) as usize];
        v >>= 4;
    }
    append_bytes(buf, pos, &out);
}
