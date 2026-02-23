//! BSD file flag functions
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! chflags/lchflags/fchflags — BSD file flags (UF_IMMUTABLE etc.)
//! fflagstostr — convert flags to string representation
//! strmode/setmode/getmode — mode_t formatting and parsing

use crate::errno;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn chflags(_path: *const u8, _flags: u64) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lchflags(_path: *const u8, _flags: u64) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fchflags(_fd: i32, _flags: u64) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn undelete(_path: *const u8) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

static EMPTY_FLAGS_STR: [u8; 1] = [0];

#[unsafe(no_mangle)]
pub extern "C" fn fflagstostr(_flags: u64) -> *const u8 {
    EMPTY_FLAGS_STR.as_ptr()
}

/// strmode — convert mode_t to ls-style string (12 chars: type+rwxrwxrwx+space+NUL)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strmode(mode: i32, bp: *mut u8) {
    unsafe {
        let m = mode as u32;
        // File type
        *bp.add(0) = match m & 0o170000 {
            0o140000 => b's', // socket
            0o120000 => b'l', // symlink
            0o100000 => b'-', // regular
            0o060000 => b'b', // block device
            0o040000 => b'd', // directory
            0o020000 => b'c', // char device
            0o010000 => b'p', // FIFO
            _ => b'?',
        };
        // Owner
        *bp.add(1) = if m & 0o400 != 0 { b'r' } else { b'-' };
        *bp.add(2) = if m & 0o200 != 0 { b'w' } else { b'-' };
        *bp.add(3) = if m & 0o4000 != 0 {
            if m & 0o100 != 0 { b's' } else { b'S' }
        } else {
            if m & 0o100 != 0 { b'x' } else { b'-' }
        };
        // Group
        *bp.add(4) = if m & 0o040 != 0 { b'r' } else { b'-' };
        *bp.add(5) = if m & 0o020 != 0 { b'w' } else { b'-' };
        *bp.add(6) = if m & 0o2000 != 0 {
            if m & 0o010 != 0 { b's' } else { b'S' }
        } else {
            if m & 0o010 != 0 { b'x' } else { b'-' }
        };
        // Other
        *bp.add(7) = if m & 0o004 != 0 { b'r' } else { b'-' };
        *bp.add(8) = if m & 0o002 != 0 { b'w' } else { b'-' };
        *bp.add(9) = if m & 0o1000 != 0 {
            if m & 0o001 != 0 { b't' } else { b'T' }
        } else {
            if m & 0o001 != 0 { b'x' } else { b'-' }
        };
        *bp.add(10) = b' ';
        *bp.add(11) = 0;
    }
}

/// setmode — numeric mode parsing (symbolic modes not yet supported)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setmode(mode_str: *const u8) -> *mut u8 {
    unsafe {
        if mode_str.is_null() || *mode_str == 0 {
            return core::ptr::null_mut();
        }
        // Try parsing as octal number
        let mut p = mode_str;
        let mut val: u32 = 0;
        let mut is_numeric = true;
        while *p != 0 {
            let c = *p;
            if c >= b'0' && c <= b'7' {
                val = val * 8 + (c - b'0') as u32;
            } else {
                is_numeric = false;
                break;
            }
            p = p.add(1);
        }
        if is_numeric {
            let buf = crate::malloc::malloc(4); // sizeof(u32)
            if buf.is_null() {
                return core::ptr::null_mut();
            }
            *(buf as *mut u32) = val;
            return buf;
        }
        // Symbolic modes not yet supported
        core::ptr::null_mut()
    }
}

/// strtofflags — parse file flags string. Stub: no flags supported.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtofflags(
    _flags: *mut *mut u8,
    setp: *mut u64,
    clrp: *mut u64,
) -> i32 {
    unsafe {
        if !setp.is_null() {
            *setp = 0;
        }
        if !clrp.is_null() {
            *clrp = 0;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getmode(set: *const u8, omode: u32) -> u32 {
    unsafe {
        if set.is_null() {
            return omode;
        }
        *(set as *const u32)
    }
}
