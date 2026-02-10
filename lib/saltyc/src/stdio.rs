//! Buffered I/O (stdio)
//! SPDX-License-Identifier: GPL-2.0-only

use crate::errno;
use core::ffi::VaList;

const BUF_SIZE: usize = 1024;
const FILE_READ: u32 = 1;
const FILE_WRITE: u32 = 2;
const FILE_APPEND: u32 = 4;
const FILE_EOF: u32 = 8;
const FILE_ERROR: u32 = 16;

const _IOFBF: i32 = 0;
const _IOLBF: i32 = 1;
const _IONBF: i32 = 2;

pub const EOF: i32 = -1;

#[repr(C)]
pub struct FILE {
    fd: i32,
    flags: u32,
    buf: [u8; BUF_SIZE],
    buf_pos: usize,
    buf_len: usize,
    ungetc_char: i32,
    buf_mode: i32,
}

impl FILE {
    const fn new(fd: i32, flags: u32, buf_mode: i32) -> Self {
        FILE {
            fd,
            flags,
            buf: [0; BUF_SIZE],
            buf_pos: 0,
            buf_len: 0,
            ungetc_char: -1,
            buf_mode,
        }
    }
}

static mut STDIN_FILE: FILE = FILE::new(0, FILE_READ, _IOFBF);
static mut STDOUT_FILE: FILE = FILE::new(1, FILE_WRITE, _IOLBF);
static mut STDERR_FILE: FILE = FILE::new(2, FILE_WRITE, _IONBF);

#[unsafe(no_mangle)]
pub static mut stdin: *mut FILE = core::ptr::null_mut();
#[unsafe(no_mangle)]
pub static mut stdout: *mut FILE = core::ptr::null_mut();
#[unsafe(no_mangle)]
pub static mut stderr: *mut FILE = core::ptr::null_mut();

// Initialize stdio pointers (called from module init or lazily)
fn ensure_stdio_init() {
    unsafe {
        if stdin.is_null() {
            stdin = &raw mut STDIN_FILE;
            stdout = &raw mut STDOUT_FILE;
            stderr = &raw mut STDERR_FILE;
        }
    }
}

const MAX_OPEN_FILES: usize = 16;
static mut OPEN_FILES: [FILE; MAX_OPEN_FILES] = {
    const ZERO: FILE = FILE::new(-1, 0, _IOFBF);
    [ZERO; MAX_OPEN_FILES]
};

unsafe fn alloc_file(fd: i32, flags: u32) -> *mut FILE {
    unsafe {
        for i in 0..MAX_OPEN_FILES {
            if OPEN_FILES[i].fd == -1 {
                OPEN_FILES[i] = FILE::new(fd, flags, _IOFBF);
                return &raw mut OPEN_FILES[i];
            }
        }
        core::ptr::null_mut()
    }
}

fn parse_mode(mode: *const u8) -> (u32, i32) {
    unsafe {
        let c0 = *mode;
        let c1 = if c0 != 0 { *mode.add(1) } else { 0 };
        let _c2 = if c1 != 0 { *mode.add(2) } else { 0 };

        match c0 {
            b'r' => {
                if c1 == b'+' {
                    (FILE_READ | FILE_WRITE, salty::O_RDWR as i32)
                } else {
                    (FILE_READ, salty::O_RDONLY as i32)
                }
            }
            b'w' => {
                if c1 == b'+' {
                    (FILE_READ | FILE_WRITE, (salty::O_RDWR | salty::O_CREAT | salty::O_TRUNC) as i32)
                } else {
                    (FILE_WRITE, (salty::O_WRONLY | salty::O_CREAT | salty::O_TRUNC) as i32)
                }
            }
            b'a' => {
                if c1 == b'+' {
                    (FILE_READ | FILE_WRITE | FILE_APPEND, (salty::O_RDWR | salty::O_CREAT | salty::O_APPEND) as i32)
                } else {
                    (FILE_WRITE | FILE_APPEND, (salty::O_WRONLY | salty::O_CREAT | salty::O_APPEND) as i32)
                }
            }
            _ => (0, 0),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fopen(path: *const u8, mode: *const u8) -> *mut FILE {
    ensure_stdio_init();
    let (flags, oflags) = parse_mode(mode);
    if flags == 0 {
        errno::set_errno(errno::EINVAL);
        return core::ptr::null_mut();
    }

    unsafe {
        let fd = salty::posix::posix_open(path, oflags);
        if fd < 0 {
            errno::set_errno(errno::ENOENT);
            return core::ptr::null_mut();
        }
        let f = alloc_file(fd, flags);
        if f.is_null() {
            salty::posix::posix_close(fd);
            errno::set_errno(errno::ENOMEM);
        }
        f
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fdopen(fd: i32, mode: *const u8) -> *mut FILE {
    ensure_stdio_init();
    let (flags, _) = parse_mode(mode);
    if flags == 0 || fd < 0 {
        return core::ptr::null_mut();
    }
    unsafe { alloc_file(fd, flags) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fclose(f: *mut FILE) -> i32 {
    if f.is_null() {
        return EOF;
    }
    unsafe {
        fflush(f);
        let ret = salty::posix::posix_close((*f).fd);
        (*f).fd = -1;
        (*f).flags = 0;
        if ret < 0 { EOF } else { 0 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn freopen(
    path: *const u8,
    mode: *const u8,
    f: *mut FILE,
) -> *mut FILE {
    if f.is_null() {
        return unsafe { fopen(path, mode) };
    }
    unsafe {
        fflush(f);
        salty::posix::posix_close((*f).fd);
        let (flags, oflags) = parse_mode(mode);
        let fd = salty::posix::posix_open(path, oflags);
        if fd < 0 {
            (*f).fd = -1;
            return core::ptr::null_mut();
        }
        (*f).fd = fd;
        (*f).flags = flags;
        (*f).buf_pos = 0;
        (*f).buf_len = 0;
        (*f).ungetc_char = -1;
        f
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fflush(f: *mut FILE) -> i32 {
    if f.is_null() {
        // Flush all
        unsafe { fflush_all() };
        return 0;
    }
    unsafe {
        if (*f).flags & FILE_WRITE != 0 && (*f).buf_pos > 0 {
            let n = salty::posix::posix_write((*f).fd, (*f).buf.as_ptr(), (*f).buf_pos as u64);
            if n < 0 {
                (*f).flags |= FILE_ERROR;
                return EOF;
            }
            (*f).buf_pos = 0;
        }
        0
    }
}

pub unsafe fn fflush_all() {
    ensure_stdio_init();
    unsafe {
        fflush(&raw mut STDOUT_FILE);
        fflush(&raw mut STDERR_FILE);
        for i in 0..MAX_OPEN_FILES {
            if OPEN_FILES[i].fd >= 0 {
                fflush(&raw mut OPEN_FILES[i]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fgetc(f: *mut FILE) -> i32 {
    if f.is_null() {
        return EOF;
    }
    unsafe {
        if (*f).ungetc_char >= 0 {
            let c = (*f).ungetc_char;
            (*f).ungetc_char = -1;
            return c;
        }
        if (*f).buf_pos >= (*f).buf_len {
            let n = salty::posix::posix_read((*f).fd, (*f).buf.as_mut_ptr(), BUF_SIZE as u64);
            if n <= 0 {
                (*f).flags |= if n == 0 { FILE_EOF } else { FILE_ERROR };
                return EOF;
            }
            (*f).buf_pos = 0;
            (*f).buf_len = n as usize;
        }
        let c = (*f).buf[(*f).buf_pos] as i32;
        (*f).buf_pos += 1;
        c
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getchar() -> i32 {
    ensure_stdio_init();
    unsafe { fgetc(stdin) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getc(f: *mut FILE) -> i32 {
    unsafe { fgetc(f) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ungetc(c: i32, f: *mut FILE) -> i32 {
    if f.is_null() || c == EOF {
        return EOF;
    }
    unsafe {
        (*f).ungetc_char = c;
        (*f).flags &= !FILE_EOF;
        c
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fputc(c: i32, f: *mut FILE) -> i32 {
    if f.is_null() {
        return EOF;
    }
    unsafe {
        let byte = c as u8;
        if (*f).buf_mode == _IONBF {
            let n = salty::posix::posix_write((*f).fd, &byte, 1);
            return if n == 1 { c } else { EOF };
        }
        (*f).buf[(*f).buf_pos] = byte;
        (*f).buf_pos += 1;
        if (*f).buf_pos >= BUF_SIZE
            || ((*f).buf_mode == _IOLBF && byte == b'\n')
        {
            if fflush(f) != 0 {
                return EOF;
            }
        }
        c
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn putchar(c: i32) -> i32 {
    ensure_stdio_init();
    unsafe { fputc(c, stdout) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn putc(c: i32, f: *mut FILE) -> i32 {
    unsafe { fputc(c, f) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fputs(s: *const u8, f: *mut FILE) -> i32 {
    if s.is_null() || f.is_null() {
        return EOF;
    }
    unsafe {
        let mut i = 0;
        while *s.add(i) != 0 {
            if fputc(*s.add(i) as i32, f) == EOF {
                return EOF;
            }
            i += 1;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn puts(s: *const u8) -> i32 {
    ensure_stdio_init();
    unsafe {
        if fputs(s, stdout) == EOF {
            return EOF;
        }
        fputc(b'\n' as i32, stdout)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fgets(buf: *mut u8, size: i32, f: *mut FILE) -> *mut u8 {
    if buf.is_null() || size <= 0 || f.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let mut i = 0;
        let max = (size - 1) as usize;
        while i < max {
            let c = fgetc(f);
            if c == EOF {
                if i == 0 {
                    return core::ptr::null_mut();
                }
                break;
            }
            *buf.add(i) = c as u8;
            i += 1;
            if c == b'\n' as i32 {
                break;
            }
        }
        *buf.add(i) = 0;
        buf
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fread(
    ptr: *mut u8,
    size: usize,
    nmemb: usize,
    f: *mut FILE,
) -> usize {
    if size == 0 || nmemb == 0 || f.is_null() {
        return 0;
    }
    unsafe {
        let total = size * nmemb;
        let mut read = 0;
        while read < total {
            let c = fgetc(f);
            if c == EOF {
                break;
            }
            *ptr.add(read) = c as u8;
            read += 1;
        }
        read / size
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fwrite(
    ptr: *const u8,
    size: usize,
    nmemb: usize,
    f: *mut FILE,
) -> usize {
    if size == 0 || nmemb == 0 || f.is_null() {
        return 0;
    }
    unsafe {
        let total = size * nmemb;
        let mut written = 0;
        while written < total {
            if fputc(*ptr.add(written) as i32, f) == EOF {
                break;
            }
            written += 1;
        }
        written / size
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fseek(f: *mut FILE, offset: i64, whence: i32) -> i32 {
    if f.is_null() {
        return -1;
    }
    unsafe {
        fflush(f);
        (*f).buf_pos = 0;
        (*f).buf_len = 0;
        (*f).ungetc_char = -1;
        (*f).flags &= !FILE_EOF;
        let ret = salty::posix::posix_lseek((*f).fd, offset, whence);
        if ret < 0 { -1 } else { 0 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftell(f: *mut FILE) -> i64 {
    if f.is_null() {
        return -1;
    }
    unsafe {
        fflush(f);
        salty::posix::posix_lseek((*f).fd, 0, salty::SEEK_CUR as i32)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rewind(f: *mut FILE) {
    unsafe {
        fseek(f, 0, salty::SEEK_SET as i32);
        if !f.is_null() {
            (*f).flags &= !(FILE_ERROR | FILE_EOF);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fileno(f: *mut FILE) -> i32 {
    if f.is_null() {
        return -1;
    }
    unsafe { (*f).fd }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ferror(f: *mut FILE) -> i32 {
    if f.is_null() {
        return 0;
    }
    unsafe { ((*f).flags & FILE_ERROR != 0) as i32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn feof(f: *mut FILE) -> i32 {
    if f.is_null() {
        return 0;
    }
    unsafe { ((*f).flags & FILE_EOF != 0) as i32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clearerr(f: *mut FILE) {
    if !f.is_null() {
        unsafe {
            (*f).flags &= !(FILE_ERROR | FILE_EOF);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setvbuf(f: *mut FILE, _buf: *mut u8, mode: i32, _size: usize) -> i32 {
    if f.is_null() {
        return -1;
    }
    unsafe {
        (*f).buf_mode = mode;
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setbuf(f: *mut FILE, buf: *mut u8) {
    let mode = if buf.is_null() { _IONBF } else { _IOFBF };
    unsafe {
        setvbuf(f, buf, mode, BUF_SIZE);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setlinebuf(f: *mut FILE) {
    unsafe {
        setvbuf(f, core::ptr::null_mut(), _IOLBF, 0);
    }
}

// ======================================================================
// printf / fprintf / snprintf / vsnprintf
// ======================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vsnprintf(
    buf: *mut u8,
    size: usize,
    fmt: *const u8,
    mut ap: VaList<'_>,
) -> i32 {
    unsafe { format_impl(buf, size, fmt, &mut ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn snprintf(
    buf: *mut u8,
    size: usize,
    fmt: *const u8,
    mut args: ...
) -> i32 {
    unsafe { format_impl(buf, size, fmt, &mut args) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sprintf(buf: *mut u8, fmt: *const u8, mut args: ...) -> i32 {
    unsafe { format_impl(buf, usize::MAX, fmt, &mut args) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vsprintf(buf: *mut u8, fmt: *const u8, ap: VaList<'_>) -> i32 {
    unsafe { vsnprintf(buf, usize::MAX, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfprintf(f: *mut FILE, fmt: *const u8, ap: VaList<'_>) -> i32 {
    let mut buf = [0u8; 4096];
    unsafe {
        let n = vsnprintf(buf.as_mut_ptr(), 4096, fmt, ap);
        if n > 0 {
            let write_len = if (n as usize) < 4096 { n as usize } else { 4095 };
            for i in 0..write_len {
                fputc(buf[i] as i32, f);
            }
        }
        n
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fprintf(f: *mut FILE, fmt: *const u8, args: ...) -> i32 {
    unsafe { vfprintf(f, fmt, args) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn printf(fmt: *const u8, args: ...) -> i32 {
    ensure_stdio_init();
    unsafe { vfprintf(stdout, fmt, args) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vprintf(fmt: *const u8, ap: VaList<'_>) -> i32 {
    ensure_stdio_init();
    unsafe { vfprintf(stdout, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dprintf(fd: i32, fmt: *const u8, args: ...) -> i32 {
    let mut buf = [0u8; 4096];
    unsafe {
        let n = vsnprintf(buf.as_mut_ptr(), 4096, fmt, args);
        if n > 0 {
            let write_len = if (n as usize) < 4096 { n as usize } else { 4095 };
            salty::posix::posix_write(fd, buf.as_ptr(), write_len as u64);
        }
        n
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn asprintf(strp: *mut *mut u8, fmt: *const u8, args: ...) -> i32 {
    let mut buf = [0u8; 4096];
    unsafe {
        let n = vsnprintf(buf.as_mut_ptr(), 4096, fmt, args);
        if n < 0 {
            *strp = core::ptr::null_mut();
            return -1;
        }
        let len = n as usize;
        let p = crate::malloc::malloc(len + 1);
        if p.is_null() {
            *strp = core::ptr::null_mut();
            return -1;
        }
        core::ptr::copy_nonoverlapping(buf.as_ptr(), p, len);
        *p.add(len) = 0;
        *strp = p;
        n
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vasprintf(strp: *mut *mut u8, fmt: *const u8, ap: VaList<'_>) -> i32 {
    let mut buf = [0u8; 4096];
    unsafe {
        let n = vsnprintf(buf.as_mut_ptr(), 4096, fmt, ap);
        if n < 0 {
            *strp = core::ptr::null_mut();
            return -1;
        }
        let len = n as usize;
        let p = crate::malloc::malloc(len + 1);
        if p.is_null() {
            *strp = core::ptr::null_mut();
            return -1;
        }
        core::ptr::copy_nonoverlapping(buf.as_ptr(), p, len);
        *p.add(len) = 0;
        *strp = p;
        n
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn perror(s: *const u8) {
    ensure_stdio_init();
    unsafe {
        let err = errno::get_errno();
        if !s.is_null() && *s != 0 {
            fputs(s, stderr);
            fputs(b": \0".as_ptr(), stderr);
        }
        fputs(crate::string::strerror(err), stderr);
        fputc(b'\n' as i32, stderr);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn remove(path: *const u8) -> i32 {
    unsafe { salty::posix::posix_unlink(path) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rename(old: *const u8, new: *const u8) -> i32 {
    unsafe { salty::posix::posix_rename(old, new) }
}

// ======================================================================
// sscanf stub (bash uses this minimally)
// ======================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sscanf(_s: *const u8, _fmt: *const u8, _args: ...) -> i32 {
    // Minimal stub - bash mostly uses this for simple integer parsing
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vsscanf(_s: *const u8, _fmt: *const u8, _ap: VaList<'_>) -> i32 {
    0
}

// ======================================================================
// open_memstream
// ======================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn open_memstream(
    ptr: *mut *mut u8,
    sizeloc: *mut usize,
) -> *mut FILE {
    // Minimal: just create a file backed by /dev/null
    // Real open_memstream needs a custom FILE with malloc buffer
    unsafe {
        let buf = crate::malloc::malloc(256);
        if buf.is_null() {
            return core::ptr::null_mut();
        }
        *buf = 0;
        *ptr = buf;
        *sizeloc = 0;
    }
    core::ptr::null_mut() // TODO: full implementation
}

// ======================================================================
// tmpfile / mkstemp stubs
// ======================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tmpfile() -> *mut FILE {
    unsafe { fopen(b"/tmp/saltyc_tmp\0".as_ptr(), b"w+\0".as_ptr()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkstemp(template: *mut u8) -> i32 {
    if template.is_null() {
        return -1;
    }
    unsafe {
        // Replace trailing XXXXXX with a simple counter
        static mut COUNTER: u32 = 0;
        let len = crate::string::strlen(template);
        if len < 6 {
            return -1;
        }
        let base = len - 6;
        let n = COUNTER;
        COUNTER += 1;
        let digits = b"0123456789abcdef";
        for i in 0..6 {
            *template.add(base + i) = digits[((n >> (i * 4)) & 0xf) as usize];
        }
        salty::posix::posix_open(template, (salty::O_RDWR | salty::O_CREAT | salty::O_EXCL) as i32)
    }
}

// ======================================================================
// Format implementation (vsnprintf core)
// ======================================================================

unsafe fn format_impl(
    buf: *mut u8,
    size: usize,
    fmt: *const u8,
    ap: &mut VaList<'_>,
) -> i32 {
    unsafe {
        let mut out = 0usize; // total chars (even beyond buffer)
        let mut i = 0usize;

        macro_rules! emit {
            ($c:expr) => {
                if out < size.saturating_sub(1) {
                    *buf.add(out) = $c;
                }
                out += 1;
            };
        }

        while *fmt.add(i) != 0 {
            if *fmt.add(i) != b'%' {
                emit!(*fmt.add(i));
                i += 1;
                continue;
            }
            i += 1; // skip '%'

            // Flags
            let mut flag_minus = false;
            let mut flag_plus = false;
            let mut flag_space = false;
            let mut flag_zero = false;
            let mut flag_hash = false;
            loop {
                match *fmt.add(i) {
                    b'-' => { flag_minus = true; i += 1; }
                    b'+' => { flag_plus = true; i += 1; }
                    b' ' => { flag_space = true; i += 1; }
                    b'0' => { flag_zero = true; i += 1; }
                    b'#' => { flag_hash = true; i += 1; }
                    _ => break,
                }
            }

            // Width
            let mut width: i32 = 0;
            if *fmt.add(i) == b'*' {
                width = ap.arg::<i32>();
                if width < 0 {
                    flag_minus = true;
                    width = -width;
                }
                i += 1;
            } else {
                while *fmt.add(i) >= b'0' && *fmt.add(i) <= b'9' {
                    width = width * 10 + (*fmt.add(i) - b'0') as i32;
                    i += 1;
                }
            }

            // Precision
            let mut precision: i32 = -1;
            if *fmt.add(i) == b'.' {
                i += 1;
                precision = 0;
                if *fmt.add(i) == b'*' {
                    precision = ap.arg::<i32>();
                    i += 1;
                } else {
                    while *fmt.add(i) >= b'0' && *fmt.add(i) <= b'9' {
                        precision = precision * 10 + (*fmt.add(i) - b'0') as i32;
                        i += 1;
                    }
                }
            }

            // Length modifier
            let mut length: u8 = 0; // 0=none, 1=h, 2=hh, 3=l, 4=ll, 5=z, 6=j, 7=t
            match *fmt.add(i) {
                b'h' => {
                    i += 1;
                    if *fmt.add(i) == b'h' { length = 2; i += 1; } else { length = 1; }
                }
                b'l' => {
                    i += 1;
                    if *fmt.add(i) == b'l' { length = 4; i += 1; } else { length = 3; }
                }
                b'z' | b'Z' => { length = 5; i += 1; }
                b'j' => { length = 6; i += 1; }
                b't' => { length = 7; i += 1; }
                _ => {}
            }

            // Specifier
            let spec = *fmt.add(i);
            i += 1;

            match spec {
                b'%' => { emit!(b'%'); }
                b'c' => {
                    let c = ap.arg::<i32>() as u8;
                    if !flag_minus {
                        let mut w = width - 1;
                        while w > 0 { emit!(b' '); w -= 1; }
                    }
                    emit!(c);
                    if flag_minus {
                        let mut w = width - 1;
                        while w > 0 { emit!(b' '); w -= 1; }
                    }
                }
                b's' => {
                    let s = ap.arg::<*const u8>();
                    let s = if s.is_null() { b"(null)\0".as_ptr() } else { s };
                    let mut slen = crate::string::strlen(s);
                    if precision >= 0 && (precision as usize) < slen {
                        slen = precision as usize;
                    }
                    let pad = if width as usize > slen { width as usize - slen } else { 0 };
                    if !flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                    for j in 0..slen { emit!(*s.add(j)); }
                    if flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                }
                b'd' | b'i' => {
                    let val: i64 = match length {
                        4 | 5 | 6 | 7 => ap.arg::<i64>(),
                        _ => ap.arg::<i32>() as i64,
                    };
                    let mut num_buf = [0u8; 22];
                    let num_len = format_signed(val, &mut num_buf, flag_plus, flag_space);
                    let pad_char = if flag_zero && !flag_minus { b'0' } else { b' ' };
                    let pad = if width as usize > num_len { width as usize - num_len } else { 0 };
                    if !flag_minus && pad_char == b' ' {
                        for _ in 0..pad { emit!(b' '); }
                    }
                    // Sign
                    if num_buf[0] == b'-' || num_buf[0] == b'+' || num_buf[0] == b' ' {
                        emit!(num_buf[0]);
                        if !flag_minus && pad_char == b'0' {
                            for _ in 0..pad { emit!(b'0'); }
                        }
                        for j in 1..num_len { emit!(num_buf[j]); }
                    } else {
                        if !flag_minus && pad_char == b'0' {
                            for _ in 0..pad { emit!(b'0'); }
                        }
                        for j in 0..num_len { emit!(num_buf[j]); }
                    }
                    if flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                }
                b'u' => {
                    let val: u64 = match length {
                        4 | 5 | 6 | 7 => ap.arg::<u64>(),
                        _ => ap.arg::<u32>() as u64,
                    };
                    let mut num_buf = [0u8; 22];
                    let num_len = format_unsigned(val, 10, false, &mut num_buf);
                    let pad_char = if flag_zero && !flag_minus { b'0' } else { b' ' };
                    let pad = if width as usize > num_len { width as usize - num_len } else { 0 };
                    if !flag_minus {
                        for _ in 0..pad { emit!(pad_char); }
                    }
                    for j in 0..num_len { emit!(num_buf[j]); }
                    if flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                }
                b'x' | b'X' => {
                    let val: u64 = match length {
                        4 | 5 | 6 | 7 => ap.arg::<u64>(),
                        _ => ap.arg::<u32>() as u64,
                    };
                    let upper = spec == b'X';
                    let mut num_buf = [0u8; 22];
                    let num_len = format_unsigned(val, 16, upper, &mut num_buf);
                    let prefix_len = if flag_hash && val != 0 { 2 } else { 0 };
                    let total_len = prefix_len + num_len;
                    let pad_char = if flag_zero && !flag_minus { b'0' } else { b' ' };
                    let pad = if width as usize > total_len { width as usize - total_len } else { 0 };
                    if !flag_minus && pad_char == b' ' {
                        for _ in 0..pad { emit!(b' '); }
                    }
                    if flag_hash && val != 0 {
                        emit!(b'0');
                        emit!(if upper { b'X' } else { b'x' });
                    }
                    if !flag_minus && pad_char == b'0' {
                        for _ in 0..pad { emit!(b'0'); }
                    }
                    for j in 0..num_len { emit!(num_buf[j]); }
                    if flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                }
                b'o' => {
                    let val: u64 = match length {
                        4 | 5 | 6 | 7 => ap.arg::<u64>(),
                        _ => ap.arg::<u32>() as u64,
                    };
                    let mut num_buf = [0u8; 22];
                    let num_len = format_unsigned(val, 8, false, &mut num_buf);
                    let prefix_len = if flag_hash && val != 0 { 1 } else { 0 };
                    let total_len = prefix_len + num_len;
                    let pad = if width as usize > total_len { width as usize - total_len } else { 0 };
                    if !flag_minus {
                        let pc = if flag_zero { b'0' } else { b' ' };
                        for _ in 0..pad { emit!(pc); }
                    }
                    if flag_hash && val != 0 { emit!(b'0'); }
                    for j in 0..num_len { emit!(num_buf[j]); }
                    if flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                }
                b'p' => {
                    let val = ap.arg::<u64>();
                    emit!(b'0');
                    emit!(b'x');
                    let mut num_buf = [0u8; 22];
                    let num_len = format_unsigned(val, 16, false, &mut num_buf);
                    for j in 0..num_len { emit!(num_buf[j]); }
                }
                b'n' => {
                    let p = ap.arg::<*mut i32>();
                    if !p.is_null() {
                        *p = out as i32;
                    }
                }
                b'f' | b'e' | b'g' | b'F' | b'E' | b'G' => {
                    // Consume the double argument to keep va_list aligned
                    let _ = ap.arg::<f64>();
                    let stub = b"0.0";
                    for &c in stub { emit!(c); }
                }
                _ => {
                    emit!(b'%');
                    emit!(spec);
                }
            }
            let _ = flag_hash;
            let _ = precision;
        }

        // Null-terminate
        if size > 0 {
            let term_pos = if out < size { out } else { size - 1 };
            *buf.add(term_pos) = 0;
        }

        out as i32
    }
}

fn format_signed(val: i64, buf: &mut [u8; 22], plus: bool, space: bool) -> usize {
    let mut pos = 0;
    if val < 0 {
        buf[0] = b'-';
        pos = 1;
        let n = format_unsigned((-val) as u64, 10, false, &mut {
            let mut b = [0u8; 22];
            let len = format_unsigned_into((-val) as u64, 10, false, &mut b);
            for i in 0..len {
                buf[pos + i] = b[i];
            }
            pos += len;
            b
        });
        let _ = n;
        return pos;
    }
    if plus {
        buf[0] = b'+';
        pos = 1;
    } else if space {
        buf[0] = b' ';
        pos = 1;
    }
    // Use a temp buffer for the digits
    let abs_val = val as u64;
    let len = format_unsigned_into(abs_val, 10, false, &mut buf[pos..]);
    pos + len
}

fn format_unsigned(val: u64, base: u64, upper: bool, buf: &mut [u8; 22]) -> usize {
    format_unsigned_into(val, base, upper, buf)
}

fn format_unsigned_into(val: u64, base: u64, upper: bool, buf: &mut [u8]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }

    let digits = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };

    let mut tmp = [0u8; 22];
    let mut pos = 0;
    let mut v = val;
    while v > 0 {
        tmp[pos] = digits[(v % base) as usize];
        v /= base;
        pos += 1;
    }

    // Reverse into buf
    for i in 0..pos {
        buf[i] = tmp[pos - 1 - i];
    }
    pos
}

// Re-do format_signed properly without the convoluted macro
#[allow(unused)]
fn format_signed_proper(val: i64, buf: &mut [u8], plus: bool, space: bool) -> usize {
    let mut pos = 0;
    let abs_val;
    if val < 0 {
        buf[0] = b'-';
        pos = 1;
        abs_val = (-(val + 1)) as u64 + 1; // handle i64::MIN
    } else {
        if plus {
            buf[0] = b'+';
            pos = 1;
        } else if space {
            buf[0] = b' ';
            pos = 1;
        }
        abs_val = val as u64;
    }
    let len = format_unsigned_into(abs_val, 10, false, &mut buf[pos..]);
    pos + len
}
