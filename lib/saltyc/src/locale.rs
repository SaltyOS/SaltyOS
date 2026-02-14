//! Locale stubs (C locale only)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Only the "C" / "POSIX" locale is supported. `setlocale` always returns
//! "C" regardless of the requested locale. `localeconv` returns a static
//! `Lconv` with POSIX defaults. GNU gettext functions (`gettext`, `dgettext`,
//! `ngettext`, `dcgettext`) pass through the message string unchanged.

pub const LC_CTYPE: i32 = 0;
pub const LC_NUMERIC: i32 = 1;
pub const LC_TIME: i32 = 2;
pub const LC_COLLATE: i32 = 3;
pub const LC_MONETARY: i32 = 4;
pub const LC_MESSAGES: i32 = 5;
pub const LC_ALL: i32 = 6;

#[repr(C)]
pub struct Lconv {
    pub decimal_point: *const u8,
    pub thousands_sep: *const u8,
    pub grouping: *const u8,
    pub int_curr_symbol: *const u8,
    pub currency_symbol: *const u8,
    pub mon_decimal_point: *const u8,
    pub mon_thousands_sep: *const u8,
    pub mon_grouping: *const u8,
    pub positive_sign: *const u8,
    pub negative_sign: *const u8,
    pub int_frac_digits: u8,
    pub frac_digits: u8,
    pub p_cs_precedes: u8,
    pub p_sep_by_space: u8,
    pub n_cs_precedes: u8,
    pub n_sep_by_space: u8,
    pub p_sign_posn: u8,
    pub n_sign_posn: u8,
}

static DECIMAL_POINT: [u8; 2] = *b".\0";
static EMPTY: [u8; 1] = *b"\0";
static C_LOCALE: [u8; 2] = *b"C\0";

static mut LCONV: Lconv = Lconv {
    decimal_point: core::ptr::null(),
    thousands_sep: core::ptr::null(),
    grouping: core::ptr::null(),
    int_curr_symbol: core::ptr::null(),
    currency_symbol: core::ptr::null(),
    mon_decimal_point: core::ptr::null(),
    mon_thousands_sep: core::ptr::null(),
    mon_grouping: core::ptr::null(),
    positive_sign: core::ptr::null(),
    negative_sign: core::ptr::null(),
    int_frac_digits: 127,
    frac_digits: 127,
    p_cs_precedes: 127,
    p_sep_by_space: 127,
    n_cs_precedes: 127,
    n_sep_by_space: 127,
    p_sign_posn: 127,
    n_sign_posn: 127,
};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setlocale(_category: i32, _locale: *const u8) -> *const u8 {
    C_LOCALE.as_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn localeconv() -> *mut Lconv {
    unsafe {
        let lc = &raw mut LCONV;
        (*lc).decimal_point = DECIMAL_POINT.as_ptr();
        (*lc).thousands_sep = EMPTY.as_ptr();
        (*lc).grouping = EMPTY.as_ptr();
        (*lc).int_curr_symbol = EMPTY.as_ptr();
        (*lc).currency_symbol = EMPTY.as_ptr();
        (*lc).mon_decimal_point = EMPTY.as_ptr();
        (*lc).mon_thousands_sep = EMPTY.as_ptr();
        (*lc).mon_grouping = EMPTY.as_ptr();
        (*lc).positive_sign = EMPTY.as_ptr();
        (*lc).negative_sign = EMPTY.as_ptr();
        lc
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn textdomain(domain: *const u8) -> *const u8 {
    domain
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bindtextdomain(_domain: *const u8, dir: *const u8) -> *const u8 {
    dir
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gettext(msgid: *const u8) -> *const u8 {
    msgid
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgettext(_domain: *const u8, msgid: *const u8) -> *const u8 {
    msgid
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dcgettext(
    _domain: *const u8,
    msgid: *const u8,
    _category: i32,
) -> *const u8 {
    msgid
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngettext(
    msgid1: *const u8,
    msgid2: *const u8,
    n: u64,
) -> *const u8 {
    if n == 1 {
        msgid1
    } else {
        msgid2
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dngettext(
    _domain: *const u8,
    msgid1: *const u8,
    msgid2: *const u8,
    n: u64,
) -> *const u8 {
    if n == 1 {
        msgid1
    } else {
        msgid2
    }
}
