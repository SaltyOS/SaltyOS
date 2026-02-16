//! String functions
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! NUL-terminated C string operations: `strlen`, `strcmp`, `strcpy`, `strcat`,
//! `strchr`, `strrchr`, `strstr`, `strtok`, `strerror`, plus BSD extensions
//! `strlcpy`, `strlcat`, `strsep`. The `strtok` function uses a static
//! save pointer (not thread-safe, matches POSIX behavior).

use crate::arch::{Arch, ArchString};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    unsafe { <Arch as ArchString>::strlen(s) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strnlen(s: *const u8, maxlen: usize) -> usize {
    unsafe {
        let mut len = 0;
        while len < maxlen && *s.add(len) != 0 {
            len += 1;
        }
        len
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcpy(dest: *mut u8, src: *const u8) -> *mut u8 {
    unsafe {
        let mut i = 0;
        loop {
            *dest.add(i) = *src.add(i);
            if *src.add(i) == 0 {
                break;
            }
            i += 1;
        }
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n && *src.add(i) != 0 {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
        while i < n {
            *dest.add(i) = 0;
            i += 1;
        }
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stpcpy(dest: *mut u8, src: *const u8) -> *mut u8 {
    unsafe {
        let mut i = 0;
        loop {
            *dest.add(i) = *src.add(i);
            if *src.add(i) == 0 {
                return dest.add(i);
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stpncpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n && *src.add(i) != 0 {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
        let ret = dest.add(i);
        while i < n {
            *dest.add(i) = 0;
            i += 1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(s1: *const u8, s2: *const u8) -> i32 {
    unsafe {
        let mut i = 0;
        loop {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b || a == 0 {
                return a as i32 - b as i32;
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe {
        let mut i = 0;
        while i < n {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b || a == 0 {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcasecmp(s1: *const u8, s2: *const u8) -> i32 {
    unsafe {
        let mut i = 0;
        loop {
            let a = to_lower(*s1.add(i));
            let b = to_lower(*s2.add(i));
            if a != b || a == 0 {
                return a as i32 - b as i32;
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncasecmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe {
        let mut i = 0;
        while i < n {
            let a = to_lower(*s1.add(i));
            let b = to_lower(*s2.add(i));
            if a != b || a == 0 {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
}

fn to_lower(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' {
        c + 32
    } else {
        c
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *mut u8 {
    unsafe {
        let ch = c as u8;
        let mut i = 0;
        loop {
            if *s.add(i) == ch {
                return s.add(i) as *mut u8;
            }
            if *s.add(i) == 0 {
                return core::ptr::null_mut();
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strrchr(s: *const u8, c: i32) -> *mut u8 {
    unsafe {
        let ch = c as u8;
        let mut last: *mut u8 = core::ptr::null_mut();
        let mut i = 0;
        loop {
            if *s.add(i) == ch {
                last = s.add(i) as *mut u8;
            }
            if *s.add(i) == 0 {
                return last;
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchrnul(s: *const u8, c: i32) -> *mut u8 {
    unsafe {
        let ch = c as u8;
        let mut i = 0;
        loop {
            if *s.add(i) == ch || *s.add(i) == 0 {
                return s.add(i) as *mut u8;
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcat(dest: *mut u8, src: *const u8) -> *mut u8 {
    unsafe {
        let end = strlen(dest);
        strcpy(dest.add(end), src);
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncat(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let end = strlen(dest);
        let mut i = 0;
        while i < n && *src.add(i) != 0 {
            *dest.add(end + i) = *src.add(i);
            i += 1;
        }
        *dest.add(end + i) = 0;
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strstr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    unsafe {
        if *needle == 0 {
            return haystack as *mut u8;
        }
        let needle_len = strlen(needle);
        let mut i = 0;
        while *haystack.add(i) != 0 {
            let mut j = 0;
            while j < needle_len && *haystack.add(i + j) == *needle.add(j) {
                j += 1;
            }
            if j == needle_len {
                return haystack.add(i) as *mut u8;
            }
            i += 1;
        }
        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcasestr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    unsafe {
        if *needle == 0 {
            return haystack as *mut u8;
        }
        let needle_len = strlen(needle);
        let mut i = 0;
        while *haystack.add(i) != 0 {
            let mut j = 0;
            while j < needle_len
                && to_lower(*haystack.add(i + j)) == to_lower(*needle.add(j))
            {
                j += 1;
            }
            if j == needle_len {
                return haystack.add(i) as *mut u8;
            }
            i += 1;
        }
        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strpbrk(s: *const u8, accept: *const u8) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while *s.add(i) != 0 {
            let mut j = 0;
            while *accept.add(j) != 0 {
                if *s.add(i) == *accept.add(j) {
                    return s.add(i) as *mut u8;
                }
                j += 1;
            }
            i += 1;
        }
        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strspn(s: *const u8, accept: *const u8) -> usize {
    unsafe {
        let mut i = 0;
        'outer: while *s.add(i) != 0 {
            let mut j = 0;
            while *accept.add(j) != 0 {
                if *s.add(i) == *accept.add(j) {
                    i += 1;
                    continue 'outer;
                }
                j += 1;
            }
            break;
        }
        i
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcspn(s: *const u8, reject: *const u8) -> usize {
    unsafe {
        let mut i = 0;
        while *s.add(i) != 0 {
            let mut j = 0;
            while *reject.add(j) != 0 {
                if *s.add(i) == *reject.add(j) {
                    return i;
                }
                j += 1;
            }
            i += 1;
        }
        i
    }
}

static mut STRTOK_SAVE: *mut u8 = core::ptr::null_mut();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtok(s: *mut u8, delim: *const u8) -> *mut u8 {
    unsafe { strtok_r(s, delim, &raw mut STRTOK_SAVE) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtok_r(
    s: *mut u8,
    delim: *const u8,
    saveptr: *mut *mut u8,
) -> *mut u8 {
    unsafe {
        let mut p = if !s.is_null() { s } else { *saveptr };
        if p.is_null() {
            return core::ptr::null_mut();
        }

        // Skip leading delimiters
        p = p.add(strspn(p, delim));
        if *p == 0 {
            *saveptr = core::ptr::null_mut();
            return core::ptr::null_mut();
        }

        let token = p;
        let span = strcspn(p, delim);
        p = p.add(span);
        if *p != 0 {
            *p = 0;
            *saveptr = p.add(1);
        } else {
            *saveptr = core::ptr::null_mut();
        }
        token
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn strcoll(s1: *const u8, s2: *const u8) -> i32 {
    // C locale: strcoll == strcmp
    unsafe { strcmp(s1, s2) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strxfrm(dest: *mut u8, src: *const u8, n: usize) -> usize {
    unsafe {
        let len = strlen(src);
        if n > 0 {
            let copy = if len < n { len } else { n - 1 };
            core::ptr::copy_nonoverlapping(src, dest, copy);
            *dest.add(copy) = 0;
        }
        len
    }
}

// Error string table
static ERRNO_STRINGS: [&[u8]; 13] = [
    b"Success\0",
    b"Operation not permitted\0",
    b"No such file or directory\0",
    b"No such process\0",
    b"Interrupted system call\0",
    b"I/O error\0",
    b"No such device or address\0",
    b"Argument list too long\0",
    b"Exec format error\0",
    b"Bad file descriptor\0",
    b"No child processes\0",
    b"Resource temporarily unavailable\0",
    b"Cannot allocate memory\0",
];

static UNKNOWN_ERROR: &[u8] = b"Unknown error\0";

#[unsafe(no_mangle)]
pub extern "C" fn strerror(errnum: i32) -> *const u8 {
    if errnum >= 0 && (errnum as usize) < ERRNO_STRINGS.len() {
        ERRNO_STRINGS[errnum as usize].as_ptr()
    } else {
        UNKNOWN_ERROR.as_ptr()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn strerror_r(errnum: i32, buf: *mut u8, buflen: usize) -> i32 {
    let msg = strerror(errnum);
    unsafe {
        let len = strlen(msg);
        let copy = if len < buflen { len } else { buflen - 1 };
        core::ptr::copy_nonoverlapping(msg, buf, copy);
        *buf.add(copy) = 0;
    }
    0
}

static SIG_NAMES: [&[u8]; 23] = [
    b"Unknown signal\0",
    b"Hangup\0",
    b"Interrupt\0",
    b"Quit\0",
    b"Illegal instruction\0",
    b"Trace/breakpoint trap\0",
    b"Aborted\0",
    b"Bus error\0",
    b"Floating point exception\0",
    b"Killed\0",
    b"User defined signal 1\0",
    b"Segmentation fault\0",
    b"User defined signal 2\0",
    b"Broken pipe\0",
    b"Alarm clock\0",
    b"Terminated\0",
    b"Stack fault\0",
    b"Child exited\0",
    b"Continued\0",
    b"Stopped (signal)\0",
    b"Stopped\0",
    b"Stopped (tty input)\0",
    b"Stopped (tty output)\0",
];

#[unsafe(no_mangle)]
pub extern "C" fn strsignal(sig: i32) -> *const u8 {
    if sig >= 0 && (sig as usize) < SIG_NAMES.len() {
        SIG_NAMES[sig as usize].as_ptr()
    } else {
        SIG_NAMES[0].as_ptr()
    }
}

// ---------------------------------------------------------------------------
// BSD strlcpy / strlcat
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlcpy(dst: *mut u8, src: *const u8, dstsize: usize) -> usize {
    unsafe {
        let srclen = strlen(src);
        if dstsize > 0 {
            let copy = if srclen < dstsize { srclen } else { dstsize - 1 };
            core::ptr::copy_nonoverlapping(src, dst, copy);
            *dst.add(copy) = 0;
        }
        srclen
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlcat(dst: *mut u8, src: *const u8, dstsize: usize) -> usize {
    unsafe {
        let srclen = strlen(src);
        let dstlen = strnlen(dst, dstsize);

        // dst is not NUL-terminated within dstsize
        if dstlen == dstsize {
            return dstsize + srclen;
        }

        let remaining = dstsize - dstlen - 1;
        let copy = if srclen < remaining + 1 {
            srclen
        } else {
            remaining
        };
        core::ptr::copy_nonoverlapping(src, dst.add(dstlen), copy);
        *dst.add(dstlen + copy) = 0;

        dstlen + srclen
    }
}
