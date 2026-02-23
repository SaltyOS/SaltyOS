//! Time functions
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! UTC-only time implementation (no timezone or DST support). Time values use
//! Unix epoch (seconds since 1970-01-01 00:00:00 UTC). The `Tm` struct follows
//! POSIX conventions: `tm_mon` is 0-based (0 = January), `tm_year` is years
//! since 1900, and `tm_wday` is 0 = Sunday.
//!
//! Non-reentrant functions (`localtime`, `gmtime`, `ctime`, `asctime`) use
//! shared static buffers. The `_r` variants accept caller-provided buffers.

use crate::errno;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub type TimeT = i64;
pub type ClockT = i64;

/// Broken-down time representation (POSIX `struct tm`).
#[repr(C)]
pub struct Tm {
    /// Seconds (0-60; 60 for leap second).
    pub tm_sec: i32,
    /// Minutes (0-59).
    pub tm_min: i32,
    /// Hours (0-23).
    pub tm_hour: i32,
    /// Day of the month (1-31).
    pub tm_mday: i32,
    /// Month (0-11; 0 = January).
    pub tm_mon: i32,
    /// Years since 1900 (e.g. 126 for year 2026).
    pub tm_year: i32,
    /// Day of the week (0-6; 0 = Sunday).
    pub tm_wday: i32,
    /// Day of the year (0-365).
    pub tm_yday: i32,
    /// Daylight saving time flag. Always 0 (UTC only, no DST).
    pub tm_isdst: i32,
}

#[repr(C)]
pub struct Tms {
    pub tms_utime: ClockT,
    pub tms_stime: ClockT,
    pub tms_cutime: ClockT,
    pub tms_cstime: ClockT,
}

#[repr(C)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

// ---------------------------------------------------------------------------
// Static buffers for non-reentrant functions
// ---------------------------------------------------------------------------

static mut TM_BUF: Tm = Tm {
    tm_sec: 0,
    tm_min: 0,
    tm_hour: 0,
    tm_mday: 0,
    tm_mon: 0,
    tm_year: 0,
    tm_wday: 0,
    tm_yday: 0,
    tm_isdst: 0,
};

static mut ASCTIME_BUF: [u8; 64] = [0; 64];
static mut CTIME_BUF: [u8; 64] = [0; 64];

// ---------------------------------------------------------------------------
// Day and month name tables
// ---------------------------------------------------------------------------

static WDAY_ABBR: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];

static WDAY_FULL: [&[u8]; 7] = [
    b"Sunday",
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
];

static MON_ABBR: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

static MON_FULL: [&[u8]; 12] = [
    b"January",
    b"February",
    b"March",
    b"April",
    b"May",
    b"June",
    b"July",
    b"August",
    b"September",
    b"October",
    b"November",
    b"December",
];

static DAYS_IN_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_year(year: i32) -> i32 {
    if is_leap_year(year) {
        366
    } else {
        365
    }
}

fn days_in_month(month: i32, year: i32) -> i32 {
    if month == 1 && is_leap_year(year) {
        29
    } else {
        DAYS_IN_MONTH[month as usize]
    }
}

/// Convert a Unix epoch timestamp to broken-down time (UTC).
unsafe fn epoch_to_tm(epoch: TimeT, tm: *mut Tm) {
    unsafe {
        let mut rem = epoch;
        let mut days: i64;

        if rem >= 0 {
            days = rem / 86400;
            rem %= 86400;
        } else {
            days = rem / 86400;
            rem %= 86400;
            if rem < 0 {
                days -= 1;
                rem += 86400;
            }
        }

        (*tm).tm_hour = (rem / 3600) as i32;
        rem %= 3600;
        (*tm).tm_min = (rem / 60) as i32;
        (*tm).tm_sec = (rem % 60) as i32;

        // Day of week: Jan 1, 1970 = Thursday (4)
        let mut wday = ((days % 7) + 4) % 7;
        if wday < 0 {
            wday += 7;
        }
        (*tm).tm_wday = wday as i32;

        // Compute year from days since epoch
        let mut year: i32 = 1970;
        if days >= 0 {
            loop {
                let dy = days_in_year(year) as i64;
                if days < dy {
                    break;
                }
                days -= dy;
                year += 1;
            }
        } else {
            loop {
                year -= 1;
                let dy = days_in_year(year) as i64;
                days += dy;
                if days >= 0 {
                    break;
                }
            }
        }

        (*tm).tm_year = year - 1900;
        (*tm).tm_yday = days as i32;

        // Compute month and day from day-of-year
        let mut mon: i32 = 0;
        let mut remaining = days as i32;
        while mon < 11 {
            let dm = days_in_month(mon, year);
            if remaining < dm {
                break;
            }
            remaining -= dm;
            mon += 1;
        }

        (*tm).tm_mon = mon;
        (*tm).tm_mday = remaining + 1;
        (*tm).tm_isdst = 0;
    }
}

/// Convert broken-down time back to epoch.
fn tm_to_epoch(tm: *const Tm) -> TimeT {
    unsafe {
        let year = (*tm).tm_year + 1900;
        let mon = (*tm).tm_mon;
        let mday = (*tm).tm_mday;

        // Count days from epoch to start of this year
        let mut days: i64 = 0;
        if year >= 1970 {
            let mut y = 1970;
            while y < year {
                days += days_in_year(y) as i64;
                y += 1;
            }
        } else {
            let mut y = 1969;
            while y >= year {
                days -= days_in_year(y) as i64;
                y -= 1;
            }
        }

        // Add days for months
        let mut m: i32 = 0;
        while m < mon && m < 12 {
            days += days_in_month(m, year) as i64;
            m += 1;
        }

        // Add day of month (1-based)
        days += (mday - 1) as i64;

        days * 86400 + (*tm).tm_hour as i64 * 3600 + (*tm).tm_min as i64 * 60 + (*tm).tm_sec as i64
    }
}

/// Write a decimal number with zero-padding into buf. Returns number of bytes written.
unsafe fn write_padded(buf: *mut u8, max: usize, val: i32, width: usize) -> usize {
    unsafe {
        if max == 0 {
            return 0;
        }
        let mut tmp: [u8; 16] = [0; 16];
        let mut v = if val < 0 { -(val as i64) } else { val as i64 };
        let neg = val < 0;
        let mut i: usize = 0;

        if v == 0 {
            tmp[0] = b'0';
            i = 1;
        } else {
            while v > 0 && i < 16 {
                tmp[i] = b'0' + (v % 10) as u8;
                v /= 10;
                i += 1;
            }
        }

        let digits = i;
        let total_width = if width > digits { width } else { digits };
        let sign_len = if neg { 1 } else { 0 };
        let total = total_width + sign_len;

        if total > max {
            return 0;
        }

        let mut pos: usize = 0;
        if neg {
            *buf.add(pos) = b'-';
            pos += 1;
        }

        // Zero padding
        let pad = if total_width > digits {
            total_width - digits
        } else {
            0
        };
        let mut p = 0usize;
        while p < pad {
            *buf.add(pos) = b'0';
            pos += 1;
            p += 1;
        }

        // Digits in reverse order
        let mut d = digits;
        while d > 0 {
            d -= 1;
            *buf.add(pos) = tmp[d];
            pos += 1;
        }

        pos
    }
}

/// Copy a byte slice into buf. Returns bytes written.
unsafe fn write_str(buf: *mut u8, max: usize, s: &[u8]) -> usize {
    unsafe {
        let len = s.len();
        if len > max {
            return 0;
        }
        core::ptr::copy_nonoverlapping(s.as_ptr(), buf, len);
        len
    }
}

/// Helper to get time value from salty
unsafe fn get_epoch_secs() -> TimeT {
    unsafe {
        let mut ts = salty::types::Timespec::zeroed();
        let ret = salty::posix::posix_clock_gettime(0, &raw mut ts);
        if ret < 0 {
            return 0;
        }
        ts.tv_sec as TimeT
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn time(t: *mut TimeT) -> TimeT {
    unsafe {
        let secs = get_epoch_secs();
        if !t.is_null() {
            *t = secs;
        }
        secs
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gettimeofday(tv: *mut Timeval, _tz: *mut u8) -> i32 {
    unsafe {
        let mut stv = salty::types::Timeval::zeroed();
        let ret = salty::posix::posix_gettimeofday(&raw mut stv);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        if !tv.is_null() {
            (*tv).tv_sec = stv.tv_sec as i64;
            (*tv).tv_usec = stv.tv_usec as i64;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32 {
    unsafe {
        let mut sts = salty::types::Timespec::zeroed();
        let ret = salty::posix::posix_clock_gettime(clock_id, &raw mut sts);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        if !tp.is_null() {
            (*tp).tv_sec = sts.tv_sec as i64;
            (*tp).tv_nsec = sts.tv_nsec as i64;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_settime(_clock_id: i32, _tp: *const Timespec) -> i32 {
    errno::set_errno(errno::EPERM);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock() -> ClockT {
    unsafe {
        let secs = get_epoch_secs();
        secs * 1_000_000
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn times(buf: *mut Tms) -> ClockT {
    unsafe {
        if !buf.is_null() {
            (*buf).tms_utime = 0;
            (*buf).tms_stime = 0;
            (*buf).tms_cutime = 0;
            (*buf).tms_cstime = 0;
        }
        get_epoch_secs() * 100
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn difftime(time1: TimeT, time0: TimeT) -> f64 {
    (time1 - time0) as f64
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmtime_r(timep: *const TimeT, result: *mut Tm) -> *mut Tm {
    unsafe {
        if timep.is_null() || result.is_null() {
            return core::ptr::null_mut();
        }
        epoch_to_tm(*timep, result);
        result
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmtime(timep: *const TimeT) -> *mut Tm {
    unsafe {
        if timep.is_null() {
            return core::ptr::null_mut();
        }
        epoch_to_tm(*timep, &raw mut TM_BUF);
        &raw mut TM_BUF as *mut Tm
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime_r(timep: *const TimeT, result: *mut Tm) -> *mut Tm {
    // No timezone support; UTC only
    unsafe { gmtime_r(timep, result) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime(timep: *const TimeT) -> *mut Tm {
    // No timezone support; UTC only
    unsafe { gmtime(timep) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mktime(tm: *mut Tm) -> TimeT {
    unsafe {
        if tm.is_null() {
            return -1;
        }
        let epoch = tm_to_epoch(tm);
        // Normalize the Tm struct
        epoch_to_tm(epoch, tm);
        epoch
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn asctime_r(tm: *const Tm, buf: *mut u8) -> *mut u8 {
    unsafe {
        if tm.is_null() || buf.is_null() {
            return core::ptr::null_mut();
        }

        let wday = if (*tm).tm_wday >= 0 && (*tm).tm_wday < 7 {
            (*tm).tm_wday as usize
        } else {
            0
        };
        let mon = if (*tm).tm_mon >= 0 && (*tm).tm_mon < 12 {
            (*tm).tm_mon as usize
        } else {
            0
        };

        // Format: "Day Mon DD HH:MM:SS YYYY\n\0"
        let mut pos: usize = 0;

        // Day abbreviation
        pos += write_str(buf.add(pos), 64 - pos, WDAY_ABBR[wday]);
        *buf.add(pos) = b' ';
        pos += 1;

        // Month abbreviation
        pos += write_str(buf.add(pos), 64 - pos, MON_ABBR[mon]);
        *buf.add(pos) = b' ';
        pos += 1;

        // Day of month with space padding
        if (*tm).tm_mday < 10 {
            *buf.add(pos) = b' ';
            pos += 1;
            pos += write_padded(buf.add(pos), 64 - pos, (*tm).tm_mday, 1);
        } else {
            pos += write_padded(buf.add(pos), 64 - pos, (*tm).tm_mday, 2);
        }
        *buf.add(pos) = b' ';
        pos += 1;

        // HH:MM:SS
        pos += write_padded(buf.add(pos), 64 - pos, (*tm).tm_hour, 2);
        *buf.add(pos) = b':';
        pos += 1;
        pos += write_padded(buf.add(pos), 64 - pos, (*tm).tm_min, 2);
        *buf.add(pos) = b':';
        pos += 1;
        pos += write_padded(buf.add(pos), 64 - pos, (*tm).tm_sec, 2);
        *buf.add(pos) = b' ';
        pos += 1;

        // Year (4-digit)
        pos += write_padded(buf.add(pos), 64 - pos, (*tm).tm_year + 1900, 4);
        *buf.add(pos) = b'\n';
        pos += 1;
        *buf.add(pos) = 0;

        buf
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn asctime(tm: *const Tm) -> *mut u8 {
    unsafe { asctime_r(tm, (&raw mut ASCTIME_BUF) as *mut u8) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ctime_r(timep: *const TimeT, buf: *mut u8) -> *mut u8 {
    unsafe {
        let mut tmp = Tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
        };
        if localtime_r(timep, &raw mut tmp).is_null() {
            return core::ptr::null_mut();
        }
        asctime_r(&raw const tmp, buf)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ctime(timep: *const TimeT) -> *mut u8 {
    unsafe { ctime_r(timep, (&raw mut CTIME_BUF) as *mut u8) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strftime(
    buf: *mut u8,
    maxsize: usize,
    format: *const u8,
    tm: *const Tm,
) -> usize {
    unsafe {
        if buf.is_null() || format.is_null() || tm.is_null() || maxsize == 0 {
            return 0;
        }

        let fmtlen = crate::string::strlen(format);
        let mut pos: usize = 0;
        let mut fi: usize = 0;
        let remaining = maxsize - 1; // reserve space for null terminator

        while fi < fmtlen {
            if pos >= remaining {
                return 0;
            }

            let c = *format.add(fi);
            if c != b'%' {
                *buf.add(pos) = c;
                pos += 1;
                fi += 1;
                continue;
            }

            fi += 1;
            if fi >= fmtlen {
                break;
            }

            let spec = *format.add(fi);
            fi += 1;

            let avail = remaining - pos;

            let written = match spec {
                // %% — literal %
                b'%' => {
                    if avail < 1 {
                        return 0;
                    }
                    *buf.add(pos) = b'%';
                    1
                }

                // %Y — 4-digit year
                b'Y' => write_padded(buf.add(pos), avail, (*tm).tm_year + 1900, 4),

                // %m — month 01-12
                b'm' => write_padded(buf.add(pos), avail, (*tm).tm_mon + 1, 2),

                // %d — day 01-31
                b'd' => write_padded(buf.add(pos), avail, (*tm).tm_mday, 2),

                // %e — day with space-padding
                b'e' => {
                    if avail < 2 {
                        return 0;
                    }
                    if (*tm).tm_mday < 10 {
                        *buf.add(pos) = b' ';
                        1 + write_padded(buf.add(pos + 1), avail - 1, (*tm).tm_mday, 1)
                    } else {
                        write_padded(buf.add(pos), avail, (*tm).tm_mday, 2)
                    }
                }

                // %H — hour 00-23
                b'H' => write_padded(buf.add(pos), avail, (*tm).tm_hour, 2),

                // %I — hour 01-12
                b'I' => {
                    let h = (*tm).tm_hour % 12;
                    let h12 = if h == 0 { 12 } else { h };
                    write_padded(buf.add(pos), avail, h12, 2)
                }

                // %M — minute 00-59
                b'M' => write_padded(buf.add(pos), avail, (*tm).tm_min, 2),

                // %S — second 00-60
                b'S' => write_padded(buf.add(pos), avail, (*tm).tm_sec, 2),

                // %p — AM/PM
                b'p' => {
                    let s = if (*tm).tm_hour < 12 {
                        b"AM" as &[u8]
                    } else {
                        b"PM"
                    };
                    write_str(buf.add(pos), avail, s)
                }

                // %a — abbreviated weekday
                b'a' => {
                    let wday = if (*tm).tm_wday >= 0 && (*tm).tm_wday < 7 {
                        (*tm).tm_wday as usize
                    } else {
                        0
                    };
                    write_str(buf.add(pos), avail, WDAY_ABBR[wday])
                }

                // %A — full weekday
                b'A' => {
                    let wday = if (*tm).tm_wday >= 0 && (*tm).tm_wday < 7 {
                        (*tm).tm_wday as usize
                    } else {
                        0
                    };
                    write_str(buf.add(pos), avail, WDAY_FULL[wday])
                }

                // %b, %h — abbreviated month
                b'b' | b'h' => {
                    let mon = if (*tm).tm_mon >= 0 && (*tm).tm_mon < 12 {
                        (*tm).tm_mon as usize
                    } else {
                        0
                    };
                    write_str(buf.add(pos), avail, MON_ABBR[mon])
                }

                // %B — full month name
                b'B' => {
                    let mon = if (*tm).tm_mon >= 0 && (*tm).tm_mon < 12 {
                        (*tm).tm_mon as usize
                    } else {
                        0
                    };
                    write_str(buf.add(pos), avail, MON_FULL[mon])
                }

                // %c — date and time: "Day Mon DD HH:MM:SS YYYY"
                b'c' => {
                    let n = strftime(
                        buf.add(pos),
                        avail + 1,
                        b"%a %b %e %H:%M:%S %Y\0".as_ptr(),
                        tm,
                    );
                    if n == 0 && avail > 0 {
                        return 0;
                    }
                    n
                }

                // %x — date: "MM/DD/YY"
                b'x' => {
                    let n = strftime(buf.add(pos), avail + 1, b"%m/%d/%y\0".as_ptr(), tm);
                    if n == 0 && avail > 0 {
                        return 0;
                    }
                    n
                }

                // %X — time: "HH:MM:SS"
                b'X' => {
                    let n = strftime(buf.add(pos), avail + 1, b"%H:%M:%S\0".as_ptr(), tm);
                    if n == 0 && avail > 0 {
                        return 0;
                    }
                    n
                }

                // %y — 2-digit year
                b'y' => write_padded(buf.add(pos), avail, ((*tm).tm_year + 1900) % 100, 2),

                // %j — day of year 001-366
                b'j' => write_padded(buf.add(pos), avail, (*tm).tm_yday + 1, 3),

                // %w — weekday 0-6 (Sunday=0)
                b'w' => write_padded(buf.add(pos), avail, (*tm).tm_wday, 1),

                // %u — weekday 1-7 (Monday=1)
                b'u' => {
                    let u = if (*tm).tm_wday == 0 { 7 } else { (*tm).tm_wday };
                    write_padded(buf.add(pos), avail, u, 1)
                }

                // %Z — timezone name (always UTC)
                b'Z' => write_str(buf.add(pos), avail, b"UTC"),

                // %R — %H:%M
                b'R' => {
                    let n = strftime(buf.add(pos), avail + 1, b"%H:%M\0".as_ptr(), tm);
                    if n == 0 && avail > 0 {
                        return 0;
                    }
                    n
                }

                // %T — %H:%M:%S
                b'T' => {
                    let n = strftime(buf.add(pos), avail + 1, b"%H:%M:%S\0".as_ptr(), tm);
                    if n == 0 && avail > 0 {
                        return 0;
                    }
                    n
                }

                // %n — newline
                b'n' => {
                    if avail < 1 {
                        return 0;
                    }
                    *buf.add(pos) = b'\n';
                    1
                }

                // %t — tab
                b't' => {
                    if avail < 1 {
                        return 0;
                    }
                    *buf.add(pos) = b'\t';
                    1
                }

                // Unknown specifier: output as-is
                _ => {
                    if avail < 2 {
                        return 0;
                    }
                    *buf.add(pos) = b'%';
                    *buf.add(pos + 1) = spec;
                    2
                }
            };

            if written == 0 && spec != b'%' && spec != b'n' && spec != b't' {
                // Buffer too small for this specifier
                return 0;
            }

            pos += written;
        }

        *buf.add(pos) = 0;
        pos
    }
}

// ---------------------------------------------------------------------------
// Interval timer stubs
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setitimer(
    _which: i32,
    _new_value: *const Itimerval,
    old_value: *mut Itimerval,
) -> i32 {
    unsafe {
        if !old_value.is_null() {
            (*old_value).it_interval.tv_sec = 0;
            (*old_value).it_interval.tv_usec = 0;
            (*old_value).it_value.tv_sec = 0;
            (*old_value).it_value.tv_usec = 0;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getitimer(_which: i32, curr_value: *mut Itimerval) -> i32 {
    unsafe {
        if !curr_value.is_null() {
            (*curr_value).it_interval.tv_sec = 0;
            (*curr_value).it_interval.tv_usec = 0;
            (*curr_value).it_value.tv_sec = 0;
            (*curr_value).it_value.tv_usec = 0;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// timegm / strptime
// ---------------------------------------------------------------------------

/// timegm — like mktime() but always interprets tm as UTC.
/// Since SaltyOS is UTC-only, this is identical to mktime().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timegm(tm: *mut Tm) -> TimeT {
    unsafe { mktime(tm) }
}

/// strptime — parse a time string according to a format.
/// Minimal implementation supporting: %Y %m %d %H %M %S %T %D %n %t %%
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strptime(buf: *const u8, fmt: *const u8, tm: *mut Tm) -> *mut u8 {
    unsafe {
        if buf.is_null() || fmt.is_null() || tm.is_null() {
            return core::ptr::null_mut();
        }

        let mut bi: usize = 0; // index into buf
        let mut fi: usize = 0; // index into fmt

        while *fmt.add(fi) != 0 {
            let fc = *fmt.add(fi);

            if fc == b'%' {
                fi += 1;
                if *fmt.add(fi) == 0 {
                    break;
                }
                let spec = *fmt.add(fi);
                fi += 1;

                match spec {
                    b'Y' => {
                        // 4-digit year
                        let (val, adv) = parse_digits(buf.add(bi), 4);
                        if adv != 4 {
                            return core::ptr::null_mut();
                        }
                        (*tm).tm_year = val - 1900;
                        bi += adv;
                    }
                    b'm' => {
                        // 1-2 digit month (01-12)
                        let (val, adv) = parse_digits(buf.add(bi), 2);
                        if adv == 0 || val < 1 || val > 12 {
                            return core::ptr::null_mut();
                        }
                        (*tm).tm_mon = val - 1;
                        bi += adv;
                    }
                    b'd' => {
                        // 1-2 digit day (01-31)
                        let (val, adv) = parse_digits(buf.add(bi), 2);
                        if adv == 0 || val < 1 || val > 31 {
                            return core::ptr::null_mut();
                        }
                        (*tm).tm_mday = val;
                        bi += adv;
                    }
                    b'H' => {
                        // 1-2 digit hour (00-23)
                        let (val, adv) = parse_digits(buf.add(bi), 2);
                        if adv == 0 || val > 23 {
                            return core::ptr::null_mut();
                        }
                        (*tm).tm_hour = val;
                        bi += adv;
                    }
                    b'M' => {
                        // 1-2 digit minute (00-59)
                        let (val, adv) = parse_digits(buf.add(bi), 2);
                        if adv == 0 || val > 59 {
                            return core::ptr::null_mut();
                        }
                        (*tm).tm_min = val;
                        bi += adv;
                    }
                    b'S' => {
                        // 1-2 digit second (00-60, leap second)
                        let (val, adv) = parse_digits(buf.add(bi), 2);
                        if adv == 0 || val > 60 {
                            return core::ptr::null_mut();
                        }
                        (*tm).tm_sec = val;
                        bi += adv;
                    }
                    b'T' => {
                        // %H:%M:%S
                        let result = strptime(buf.add(bi), b"%H:%M:%S\0".as_ptr(), tm);
                        if result.is_null() {
                            return core::ptr::null_mut();
                        }
                        bi += (result as *const u8).offset_from(buf.add(bi)) as usize;
                    }
                    b'D' => {
                        // %m/%d/%y
                        let result = strptime(buf.add(bi), b"%m/%d/%y\0".as_ptr(), tm);
                        if result.is_null() {
                            return core::ptr::null_mut();
                        }
                        bi += (result as *const u8).offset_from(buf.add(bi)) as usize;
                    }
                    b'y' => {
                        // 2-digit year (00-99, maps to 1969-2068)
                        let (val, adv) = parse_digits(buf.add(bi), 2);
                        if adv != 2 {
                            return core::ptr::null_mut();
                        }
                        (*tm).tm_year = if val >= 69 { val } else { val + 100 };
                        bi += adv;
                    }
                    b'n' | b't' => {
                        // Skip whitespace
                        while *buf.add(bi) != 0
                            && (*buf.add(bi) == b' '
                                || *buf.add(bi) == b'\t'
                                || *buf.add(bi) == b'\n')
                        {
                            bi += 1;
                        }
                    }
                    b'%' => {
                        if *buf.add(bi) != b'%' {
                            return core::ptr::null_mut();
                        }
                        bi += 1;
                    }
                    _ => {
                        // Unknown specifier, fail
                        return core::ptr::null_mut();
                    }
                }
            } else if fc == b' ' || fc == b'\t' {
                // Format whitespace matches any amount of input whitespace
                fi += 1;
                while *buf.add(bi) != 0 && (*buf.add(bi) == b' ' || *buf.add(bi) == b'\t') {
                    bi += 1;
                }
            } else {
                // Literal character match
                if *buf.add(bi) != fc {
                    return core::ptr::null_mut();
                }
                bi += 1;
                fi += 1;
            }
        }

        buf.add(bi) as *mut u8
    }
}

/// Parse up to `max_digits` decimal digits from `s`. Returns (value, chars_consumed).
unsafe fn parse_digits(s: *const u8, max_digits: usize) -> (i32, usize) {
    unsafe {
        let mut val: i32 = 0;
        let mut i: usize = 0;
        while i < max_digits && *s.add(i) >= b'0' && *s.add(i) <= b'9' {
            val = val * 10 + (*s.add(i) - b'0') as i32;
            i += 1;
        }
        (val, i)
    }
}
