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

// --- setmode/getmode internal representation ---
//
// The opaque buffer returned by setmode() is a packed array of ModeOp entries
// terminated by a sentinel (who == 0, op == 0, perm == 0).  getmode() applies
// each operation to a base mode.
//
// For numeric modes (e.g. "0755") we store a single CMD_SET entry with who=0x7
// (ugo) and the parsed value in perm, plus the sentinel.

const CMD_SET: u8 = b'=';
const CMD_ADD: u8 = b'+';
const CMD_REM: u8 = b'-';

const WHO_USER: u8 = 0x1;
const WHO_GROUP: u8 = 0x2;
const WHO_OTHER: u8 = 0x4;
const WHO_ALL: u8 = WHO_USER | WHO_GROUP | WHO_OTHER;

#[repr(C)]
struct ModeOp {
    who: u8,    // bitmask: WHO_USER | WHO_GROUP | WHO_OTHER
    op: u8,     // CMD_SET, CMD_ADD, CMD_REM
    perm: u16,  // permission bits positioned for mode_t (rwx for each who)
}

/// setmode — parse numeric or symbolic mode string
///
/// Returns a malloc'd opaque buffer for use with getmode(), or NULL on error.
/// Supports octal numeric modes ("0755", "644") and symbolic modes
/// ("u+x", "g-w,o=rx", "a+r", "ug=rw", "+x", etc.).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setmode(mode_str: *const u8) -> *mut u8 {
    unsafe {
        if mode_str.is_null() || *mode_str == 0 {
            return core::ptr::null_mut();
        }

        // Try parsing as octal number first
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
            // Numeric mode: allocate space for 1 ModeOp + sentinel
            let size = core::mem::size_of::<ModeOp>() * 2;
            let buf = crate::malloc::malloc(size);
            if buf.is_null() {
                return core::ptr::null_mut();
            }
            core::ptr::write_bytes(buf, 0, size);
            let ops = buf as *mut ModeOp;
            (*ops).who = WHO_ALL;
            (*ops).op = CMD_SET;
            (*ops).perm = (val & 0o7777) as u16;
            // Sentinel is zero-initialized
            return buf;
        }

        // Parse symbolic mode: [ugoa]*[+-=][rwxXst]*(,[ugoa]*[+-=][rwxXst]*)*
        // First pass: count clauses to know allocation size
        let mut count: usize = 0;
        p = mode_str;
        while *p != 0 {
            // Skip who chars
            while *p == b'u' || *p == b'g' || *p == b'o' || *p == b'a' {
                p = p.add(1);
            }
            // Must have an operator
            if *p != b'+' && *p != b'-' && *p != b'=' {
                return core::ptr::null_mut();
            }
            p = p.add(1);
            count += 1;
            // Skip perm chars
            while *p == b'r' || *p == b'w' || *p == b'x'
                || *p == b'X' || *p == b's' || *p == b't'
            {
                p = p.add(1);
            }
            // Expect comma or end
            if *p == b',' {
                p = p.add(1);
            } else if *p != 0 {
                return core::ptr::null_mut();
            }
        }

        if count == 0 {
            return core::ptr::null_mut();
        }

        // Allocate ops array + sentinel
        let size = core::mem::size_of::<ModeOp>() * (count + 1);
        let buf = crate::malloc::malloc(size);
        if buf.is_null() {
            return core::ptr::null_mut();
        }
        core::ptr::write_bytes(buf, 0, size);
        let ops = buf as *mut ModeOp;

        // Second pass: parse and fill
        p = mode_str;
        let mut idx: usize = 0;
        while *p != 0 && idx < count {
            // Parse who
            let mut who: u8 = 0;
            while *p == b'u' || *p == b'g' || *p == b'o' || *p == b'a' {
                match *p {
                    b'u' => who |= WHO_USER,
                    b'g' => who |= WHO_GROUP,
                    b'o' => who |= WHO_OTHER,
                    b'a' => who |= WHO_ALL,
                    _ => {}
                }
                p = p.add(1);
            }
            // Default: 'a' if no who specified
            if who == 0 {
                who = WHO_ALL;
            }

            // Parse operator
            let op = *p;
            p = p.add(1);

            // Parse permissions and build the mode_t bits
            let mut perm: u16 = 0;
            while *p == b'r' || *p == b'w' || *p == b'x'
                || *p == b'X' || *p == b's' || *p == b't'
            {
                match *p {
                    b'r' => {
                        if who & WHO_USER != 0 { perm |= 0o400; }
                        if who & WHO_GROUP != 0 { perm |= 0o040; }
                        if who & WHO_OTHER != 0 { perm |= 0o004; }
                    }
                    b'w' => {
                        if who & WHO_USER != 0 { perm |= 0o200; }
                        if who & WHO_GROUP != 0 { perm |= 0o020; }
                        if who & WHO_OTHER != 0 { perm |= 0o002; }
                    }
                    b'x' => {
                        if who & WHO_USER != 0 { perm |= 0o100; }
                        if who & WHO_GROUP != 0 { perm |= 0o010; }
                        if who & WHO_OTHER != 0 { perm |= 0o001; }
                    }
                    b'X' => {
                        // X = execute only if directory or already has execute
                        // We set a marker bit (0x8000) that getmode resolves
                        perm |= 0x8000;
                        if who & WHO_USER != 0 { perm |= 0o100; }
                        if who & WHO_GROUP != 0 { perm |= 0o010; }
                        if who & WHO_OTHER != 0 { perm |= 0o001; }
                    }
                    b's' => {
                        if who & WHO_USER != 0 { perm |= 0o4000; } // setuid
                        if who & WHO_GROUP != 0 { perm |= 0o2000; } // setgid
                    }
                    b't' => {
                        perm |= 0o1000; // sticky
                    }
                    _ => {}
                }
                p = p.add(1);
            }

            (*ops.add(idx)).who = who;
            (*ops.add(idx)).op = op;
            (*ops.add(idx)).perm = perm;
            idx += 1;

            if *p == b',' {
                p = p.add(1);
            }
        }

        buf
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

/// getmode — apply a mode set (from setmode) to a base mode
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getmode(set: *const u8, omode: u32) -> u32 {
    unsafe {
        if set.is_null() {
            return omode;
        }

        let ops = set as *const ModeOp;
        let mut mode = omode;
        let mut i: usize = 0;

        loop {
            let op = &*ops.add(i);
            // Sentinel: all fields zero
            if op.who == 0 && op.op == 0 && op.perm == 0 {
                break;
            }

            let mut perm = op.perm as u32;

            // Handle 'X' conditional execute (marker bit 0x8000)
            if perm & 0x8000 != 0 {
                perm &= !0x8000;
                // 'X' only applies if target is a directory or already has
                // any execute bit set
                let is_dir = (mode & 0o170000) == 0o040000;
                let has_exec = (mode & 0o111) != 0;
                if !is_dir && !has_exec {
                    // Strip the execute bits that X would have added
                    perm &= !0o111u32;
                }
            }

            // Build a mask of the bits this 'who' controls
            let mut who_mask: u32 = 0;
            if op.who & WHO_USER != 0 { who_mask |= 0o4700; }
            if op.who & WHO_GROUP != 0 { who_mask |= 0o2070; }
            if op.who & WHO_OTHER != 0 { who_mask |= 0o1007; }

            match op.op {
                CMD_SET => {
                    // Clear who's bits, then set
                    mode = (mode & !who_mask) | (perm & who_mask);
                }
                CMD_ADD => {
                    mode |= perm;
                }
                CMD_REM => {
                    mode &= !perm;
                }
                _ => {}
            }

            i += 1;
        }

        mode & 0o7777
    }
}
