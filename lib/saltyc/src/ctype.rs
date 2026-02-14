//! Character classification (ASCII lookup table)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All classification functions use a 128-entry lookup table indexed by
//! character value. Characters outside 0-127 return false for all tests.
//! This covers ASCII only — no multibyte or Unicode support.

const C: u8 = 0x01; // control
const S: u8 = 0x02; // space
const P: u8 = 0x04; // punct
const D: u8 = 0x08; // digit
const U: u8 = 0x10; // upper
const L: u8 = 0x20; // lower
const X: u8 = 0x40; // hex digit

#[rustfmt::skip]
static CTYPE_TABLE: [u8; 128] = [
    C,C,C,C,C,C,C,C,C,C|S,C|S,C|S,C|S,C|S,C,C,  // 0x00-0x0F
    C,C,C,C,C,C,C,C,C,C,C,C,C,C,C,C,              // 0x10-0x1F
    S,P,P,P,P,P,P,P,P,P,P,P,P,P,P,P,              // 0x20-0x2F  !"#$%&'()*+,-./
    D|X,D|X,D|X,D|X,D|X,D|X,D|X,D|X,D|X,D|X,     // 0x30-0x39  0-9
    P,P,P,P,P,P,                                    // 0x3A-0x3F  :;<=>?
    P,U|X,U|X,U|X,U|X,U|X,U|X,U,U,U,U,U,U,U,U,U, // 0x40-0x4F  @A-O
    U,U,U,U,U,U,U,U,U,U,U,P,P,P,P,P,              // 0x50-0x5F  P-Z[\]^_
    P,L|X,L|X,L|X,L|X,L|X,L|X,L,L,L,L,L,L,L,L,L, // 0x60-0x6F  `a-o
    L,L,L,L,L,L,L,L,L,L,L,P,P,P,P,C,              // 0x70-0x7F  p-z{|}~DEL
];

fn ct(c: i32) -> u8 {
    if c >= 0 && c < 128 {
        CTYPE_TABLE[c as usize]
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn isalpha(c: i32) -> i32 {
    ((ct(c) & (U | L)) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn isdigit(c: i32) -> i32 {
    ((ct(c) & D) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn isalnum(c: i32) -> i32 {
    ((ct(c) & (U | L | D)) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn isspace(c: i32) -> i32 {
    ((ct(c) & S) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn isupper(c: i32) -> i32 {
    ((ct(c) & U) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn islower(c: i32) -> i32 {
    ((ct(c) & L) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn isprint(c: i32) -> i32 {
    (c >= 0x20 && c < 0x7f) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn iscntrl(c: i32) -> i32 {
    ((ct(c) & C) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn ispunct(c: i32) -> i32 {
    ((ct(c) & P) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn isxdigit(c: i32) -> i32 {
    ((ct(c) & X) != 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn isgraph(c: i32) -> i32 {
    (c > 0x20 && c < 0x7f) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn isascii(c: i32) -> i32 {
    (c >= 0 && c < 128) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn toupper(c: i32) -> i32 {
    if c >= b'a' as i32 && c <= b'z' as i32 {
        c - 32
    } else {
        c
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tolower(c: i32) -> i32 {
    if c >= b'A' as i32 && c <= b'Z' as i32 {
        c + 32
    } else {
        c
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn isblank(c: i32) -> i32 {
    (c == b' ' as i32 || c == b'\t' as i32) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn toascii(c: i32) -> i32 {
    c & 0x7f
}
