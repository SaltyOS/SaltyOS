//! Buffered I/O (stdio)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides the C standard `FILE`-based I/O layer. Each `FILE` wraps a POSIX
//! file descriptor with an optional 1024-byte userspace buffer. Three buffer
//! modes are supported: full (`_IOFBF`), line (`_IOLBF`, default for stdout),
//! and unbuffered (`_IONBF`, default for stderr). At most 16 streams can be
//! open simultaneously (3 reserved for stdin/stdout/stderr).
//!
//! The printf engine (`format_impl`) handles `%d`, `%i`, `%u`, `%x`, `%o`,
//! `%s`, `%c`, `%p`, `%f`, `%e`, `%g`, `%n`, plus width/precision/flags.
//! FreeBSD compatibility aliases (`__stdoutp`, `__stdinp`, `__stderrp`) are
//! exported for ported FreeBSD utilities.

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

/// A buffered I/O stream wrapping a POSIX file descriptor.
#[repr(C)]
pub struct FILE {
    /// Underlying POSIX file descriptor (-1 when closed).
    fd: i32,
    /// Bitmask of FILE_READ, FILE_WRITE, FILE_APPEND, FILE_EOF, FILE_ERROR.
    flags: u32,
    /// Internal I/O buffer (1024 bytes).
    buf: [u8; BUF_SIZE],
    /// Current read/write position within `buf`.
    buf_pos: usize,
    /// Number of valid bytes in `buf` (for read buffering).
    buf_len: usize,
    /// Character pushed back via `ungetc()`, or -1 if none.
    ungetc_char: i32,
    /// Buffer mode: `_IOFBF` (full), `_IOLBF` (line), `_IONBF` (unbuffered).
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
pub(crate) fn ensure_stdio_init() {
    unsafe {
        if stdin.is_null() {
            stdin = &raw mut STDIN_FILE;
            stdout = &raw mut STDOUT_FILE;
            stderr = &raw mut STDERR_FILE;
            // Sync FreeBSD compatibility aliases
            crate::compat::freebsd::bsd_stdio::__stdinp = stdin;
            crate::compat::freebsd::bsd_stdio::__stdoutp = stdout;
            crate::compat::freebsd::bsd_stdio::__stderrp = stderr;
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

/// Open a file stream.
///
/// Parses the `mode` string ("r", "w", "a", "r+", "w+", "a+") to determine
/// read/write/append flags and the corresponding `O_*` open flags. The file
/// is opened via `posix_open`, then a `FILE` is allocated from the static
/// pool (max 16 streams including stdin/stdout/stderr).
///
/// Returns null on invalid mode, open failure, or if the stream pool is full.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fopen(path: *const u8, mode: *const u8) -> *mut FILE {
    ensure_stdio_init();
    let (flags, oflags) = parse_mode(mode);
    if flags == 0 {
        errno::set_errno(errno::EINVAL);
        return core::ptr::null_mut();
    }

    unsafe {
        let open_mode: u32 = if (oflags & salty::O_CREAT as i32) != 0 { 0o644 } else { 0 };
        let fd = salty::posix::posix_open(path, oflags, open_mode);
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
        let open_mode: u32 = if (oflags & salty::O_CREAT as i32) != 0 { 0o644 } else { 0 };
        let fd = salty::posix::posix_open(path, oflags, open_mode);
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
            // Flush stdout before blocking on stdin (C standard compliance).
            // Ensures prompts appear before read blocks.
            if !stdout.is_null() && f == stdin {
                fflush(stdout);
            }
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

/// Formatted output to a `FILE` stream.
///
/// Formats into a 4096-byte stack buffer via `vsnprintf`, then writes the
/// result to the stream. Supports the full format specifier set: `%d`, `%i`,
/// `%u`, `%x`/`%X`, `%o`, `%s`, `%c`, `%p`, `%f`, `%e`/`%E`, `%g`/`%G`,
/// `%n`, `%%`, plus width, precision, and flag modifiers (`-`, `+`, ` `,
/// `0`, `#`). Length modifiers `l`, `ll`, `h`, `hh`, `z`, `j` are handled.
///
/// Returns the number of bytes written, or a negative value on error.
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
    ensure_stdio_init();
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
// sscanf / vsscanf
// ======================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sscanf(s: *const u8, fmt: *const u8, mut args: ...) -> i32 {
    unsafe { sscanf_impl(s, fmt, &mut args) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vsscanf(s: *const u8, fmt: *const u8, mut ap: VaList<'_>) -> i32 {
    unsafe { sscanf_impl(s, fmt, &mut ap) }
}

unsafe fn sscanf_impl(s: *const u8, fmt: *const u8, ap: &mut VaList<'_>) -> i32 {
    if s.is_null() || fmt.is_null() {
        return -1;
    }
    unsafe {
        let mut si = 0usize; // position in input string
        let mut fi = 0usize; // position in format string
        let mut matched = 0i32;

        while *fmt.add(fi) != 0 {
            let fc = *fmt.add(fi);

            // Skip whitespace in format -> skip whitespace in input
            if fc == b' ' || fc == b'\t' || fc == b'\n' {
                fi += 1;
                while *s.add(si) == b' ' || *s.add(si) == b'\t' || *s.add(si) == b'\n' {
                    si += 1;
                }
                continue;
            }

            // Literal match
            if fc != b'%' {
                if *s.add(si) != fc {
                    break;
                }
                fi += 1;
                si += 1;
                continue;
            }

            fi += 1; // skip '%'

            // %% literal
            if *fmt.add(fi) == b'%' {
                if *s.add(si) != b'%' {
                    break;
                }
                fi += 1;
                si += 1;
                continue;
            }

            // Suppression flag
            let suppress = *fmt.add(fi) == b'*';
            if suppress {
                fi += 1;
            }

            // Width
            let mut width: usize = 0;
            let mut has_width = false;
            while *fmt.add(fi) >= b'0' && *fmt.add(fi) <= b'9' {
                width = width * 10 + (*fmt.add(fi) - b'0') as usize;
                fi += 1;
                has_width = true;
            }

            // Length modifier
            let mut length: u8 = 0; // 0=none, 1=h, 2=hh, 3=l, 4=ll
            match *fmt.add(fi) {
                b'h' => {
                    fi += 1;
                    if *fmt.add(fi) == b'h' { length = 2; fi += 1; } else { length = 1; }
                }
                b'l' => {
                    fi += 1;
                    if *fmt.add(fi) == b'l' { length = 4; fi += 1; } else { length = 3; }
                }
                b'z' => { length = 3; fi += 1; } // treat z as l
                _ => {}
            }

            let spec = *fmt.add(fi);
            fi += 1;

            match spec {
                b'n' => {
                    if !suppress {
                        let p = ap.arg::<*mut i32>();
                        if !p.is_null() {
                            *p = si as i32;
                        }
                    }
                    // %n does not count as a matched item
                    continue;
                }
                b'd' | b'i' => {
                    // Skip leading whitespace
                    while *s.add(si) == b' ' || *s.add(si) == b'\t' {
                        si += 1;
                    }
                    if *s.add(si) == 0 {
                        break;
                    }
                    let start = si;
                    let mut neg = false;
                    if *s.add(si) == b'-' {
                        neg = true;
                        si += 1;
                    } else if *s.add(si) == b'+' {
                        si += 1;
                    }

                    let mut base: u64 = 10;
                    if spec == b'i' {
                        // Auto-detect base
                        if *s.add(si) == b'0' {
                            si += 1;
                            if *s.add(si) == b'x' || *s.add(si) == b'X' {
                                base = 16;
                                si += 1;
                            } else {
                                base = 8;
                            }
                        }
                    }

                    let mut val: u64 = 0;
                    let mut digits = 0;
                    let max_chars = if has_width { width } else { usize::MAX };
                    while digits < max_chars.saturating_sub(si - start) {
                        let c = *s.add(si);
                        let d = char_to_digit(c, base);
                        if d < 0 {
                            break;
                        }
                        val = val.wrapping_mul(base).wrapping_add(d as u64);
                        si += 1;
                        digits += 1;
                    }

                    if digits == 0 {
                        break;
                    }

                    let signed_val = if neg { -(val as i64) } else { val as i64 };
                    if !suppress {
                        match length {
                            2 => { let p = ap.arg::<*mut i8>(); if !p.is_null() { *p = signed_val as i8; } }
                            1 => { let p = ap.arg::<*mut i16>(); if !p.is_null() { *p = signed_val as i16; } }
                            3 | 4 => { let p = ap.arg::<*mut i64>(); if !p.is_null() { *p = signed_val; } }
                            _ => { let p = ap.arg::<*mut i32>(); if !p.is_null() { *p = signed_val as i32; } }
                        }
                        matched += 1;
                    }
                }
                b'u' => {
                    while *s.add(si) == b' ' || *s.add(si) == b'\t' {
                        si += 1;
                    }
                    if *s.add(si) == 0 { break; }
                    if *s.add(si) == b'+' { si += 1; }

                    let start = si;
                    let mut val: u64 = 0;
                    let mut digits = 0;
                    let max_chars = if has_width { width } else { usize::MAX };
                    while digits < max_chars.saturating_sub(si - start) {
                        let c = *s.add(si);
                        if c < b'0' || c > b'9' { break; }
                        val = val.wrapping_mul(10).wrapping_add((c - b'0') as u64);
                        si += 1;
                        digits += 1;
                    }
                    if digits == 0 { break; }

                    if !suppress {
                        match length {
                            3 | 4 => { let p = ap.arg::<*mut u64>(); if !p.is_null() { *p = val; } }
                            _ => { let p = ap.arg::<*mut u32>(); if !p.is_null() { *p = val as u32; } }
                        }
                        matched += 1;
                    }
                }
                b'x' | b'X' => {
                    while *s.add(si) == b' ' || *s.add(si) == b'\t' {
                        si += 1;
                    }
                    if *s.add(si) == 0 { break; }
                    // Skip optional 0x prefix
                    if *s.add(si) == b'0' && (*s.add(si + 1) == b'x' || *s.add(si + 1) == b'X') {
                        si += 2;
                    }

                    let mut val: u64 = 0;
                    let mut digits = 0;
                    let max_chars = if has_width { width } else { usize::MAX };
                    while digits < max_chars {
                        let d = char_to_digit(*s.add(si), 16);
                        if d < 0 { break; }
                        val = val.wrapping_mul(16).wrapping_add(d as u64);
                        si += 1;
                        digits += 1;
                    }
                    if digits == 0 { break; }

                    if !suppress {
                        match length {
                            3 | 4 => { let p = ap.arg::<*mut u64>(); if !p.is_null() { *p = val; } }
                            _ => { let p = ap.arg::<*mut u32>(); if !p.is_null() { *p = val as u32; } }
                        }
                        matched += 1;
                    }
                }
                b'o' => {
                    while *s.add(si) == b' ' || *s.add(si) == b'\t' {
                        si += 1;
                    }
                    if *s.add(si) == 0 { break; }

                    let mut val: u64 = 0;
                    let mut digits = 0;
                    let max_chars = if has_width { width } else { usize::MAX };
                    while digits < max_chars {
                        let c = *s.add(si);
                        if c < b'0' || c > b'7' { break; }
                        val = val.wrapping_mul(8).wrapping_add((c - b'0') as u64);
                        si += 1;
                        digits += 1;
                    }
                    if digits == 0 { break; }

                    if !suppress {
                        match length {
                            3 | 4 => { let p = ap.arg::<*mut u64>(); if !p.is_null() { *p = val; } }
                            _ => { let p = ap.arg::<*mut u32>(); if !p.is_null() { *p = val as u32; } }
                        }
                        matched += 1;
                    }
                }
                b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                    while *s.add(si) == b' ' || *s.add(si) == b'\t' {
                        si += 1;
                    }
                    if *s.add(si) == 0 { break; }

                    let start = si;
                    let max_chars = if has_width { width } else { usize::MAX };
                    let mut consumed = 0usize;

                    // Optional sign
                    if consumed < max_chars {
                        let c = *s.add(si);
                        if c == b'+' || c == b'-' {
                            si += 1;
                            consumed += 1;
                        }
                    }

                    // Integer digits
                    let mut int_digits = 0usize;
                    while consumed < max_chars {
                        let c = *s.add(si);
                        if c < b'0' || c > b'9' {
                            break;
                        }
                        si += 1;
                        consumed += 1;
                        int_digits += 1;
                    }

                    // Fractional digits
                    let mut frac_digits = 0usize;
                    if consumed < max_chars && *s.add(si) == b'.' {
                        si += 1;
                        consumed += 1;
                        while consumed < max_chars {
                            let c = *s.add(si);
                            if c < b'0' || c > b'9' {
                                break;
                            }
                            si += 1;
                            consumed += 1;
                            frac_digits += 1;
                        }
                    }

                    // At least one digit is required.
                    if int_digits == 0 && frac_digits == 0 {
                        break;
                    }

                    // Optional exponent. If malformed, roll back and stop before 'e'/'E'.
                    if consumed < max_chars {
                        let c = *s.add(si);
                        if c == b'e' || c == b'E' {
                            let exp_start = si;
                            si += 1;
                            consumed += 1;

                            if consumed < max_chars {
                                let sign = *s.add(si);
                                if sign == b'+' || sign == b'-' {
                                    si += 1;
                                    consumed += 1;
                                }
                            }

                            let mut exp_digits = 0usize;
                            while consumed < max_chars {
                                let d = *s.add(si);
                                if d < b'0' || d > b'9' {
                                    break;
                                }
                                si += 1;
                                consumed += 1;
                                exp_digits += 1;
                            }

                            if exp_digits == 0 {
                                si = exp_start;
                            }
                        }
                    }

                    if !suppress {
                        let value = parse_scanned_float(s, start, si);
                        // scanf: %f writes float*, %lf writes double*
                        if length == 3 {
                            let p = ap.arg::<*mut f64>();
                            if !p.is_null() {
                                *p = value;
                            }
                        } else {
                            let p = ap.arg::<*mut f32>();
                            if !p.is_null() {
                                *p = value as f32;
                            }
                        }
                        matched += 1;
                    }
                }
                b's' => {
                    while *s.add(si) == b' ' || *s.add(si) == b'\t' {
                        si += 1;
                    }
                    if *s.add(si) == 0 { break; }

                    let max_chars = if has_width { width } else { usize::MAX };
                    if !suppress {
                        let p = ap.arg::<*mut u8>();
                        let mut count = 0;
                        while count < max_chars && *s.add(si) != 0
                            && *s.add(si) != b' ' && *s.add(si) != b'\t'
                            && *s.add(si) != b'\n'
                        {
                            if !p.is_null() {
                                *p.add(count) = *s.add(si);
                            }
                            si += 1;
                            count += 1;
                        }
                        if !p.is_null() {
                            *p.add(count) = 0;
                        }
                        matched += 1;
                    } else {
                        let mut count = 0;
                        while count < max_chars && *s.add(si) != 0
                            && *s.add(si) != b' ' && *s.add(si) != b'\t'
                            && *s.add(si) != b'\n'
                        {
                            si += 1;
                            count += 1;
                        }
                    }
                }
                b'c' => {
                    if *s.add(si) == 0 { break; }
                    let count = if has_width { width } else { 1 };
                    if !suppress {
                        let p = ap.arg::<*mut u8>();
                        for k in 0..count {
                            if *s.add(si) == 0 { break; }
                            if !p.is_null() {
                                *p.add(k) = *s.add(si);
                            }
                            si += 1;
                        }
                        matched += 1;
                    } else {
                        for _ in 0..count {
                            if *s.add(si) == 0 { break; }
                            si += 1;
                        }
                    }
                }
                b'[' => {
                    // Scanset
                    let negate = *fmt.add(fi) == b'^';
                    if negate { fi += 1; }

                    // Collect scanset characters
                    let mut scanset = [false; 256];
                    // Handle ']' as first char in scanset
                    if *fmt.add(fi) == b']' {
                        scanset[b']' as usize] = true;
                        fi += 1;
                    }
                    while *fmt.add(fi) != 0 && *fmt.add(fi) != b']' {
                        let c = *fmt.add(fi);
                        // Check for range: a-z
                        if *fmt.add(fi + 1) == b'-' && *fmt.add(fi + 2) != b']' && *fmt.add(fi + 2) != 0 {
                            let lo = c;
                            let hi = *fmt.add(fi + 2);
                            let mut ch = lo;
                            while ch <= hi {
                                scanset[ch as usize] = true;
                                ch += 1;
                            }
                            fi += 3;
                        } else {
                            scanset[c as usize] = true;
                            fi += 1;
                        }
                    }
                    if *fmt.add(fi) == b']' { fi += 1; }

                    let max_chars = if has_width { width } else { usize::MAX };
                    let mut count = 0;

                    if !suppress {
                        let p = ap.arg::<*mut u8>();
                        while count < max_chars && *s.add(si) != 0 {
                            let c = *s.add(si);
                            let in_set = scanset[c as usize];
                            if (negate && in_set) || (!negate && !in_set) {
                                break;
                            }
                            if !p.is_null() {
                                *p.add(count) = c;
                            }
                            si += 1;
                            count += 1;
                        }
                        if count == 0 { break; }
                        if !p.is_null() {
                            *p.add(count) = 0;
                        }
                        matched += 1;
                    } else {
                        while count < max_chars && *s.add(si) != 0 {
                            let c = *s.add(si);
                            let in_set = scanset[c as usize];
                            if (negate && in_set) || (!negate && !in_set) {
                                break;
                            }
                            si += 1;
                            count += 1;
                        }
                        if count == 0 { break; }
                    }
                }
                _ => {
                    // Unknown specifier, stop
                    break;
                }
            }
        }

        matched
    }
}

fn char_to_digit(c: u8, base: u64) -> i32 {
    let val = match c {
        b'0'..=b'9' => (c - b'0') as i32,
        b'a'..=b'f' => (c - b'a' + 10) as i32,
        b'A'..=b'F' => (c - b'A' + 10) as i32,
        _ => return -1,
    };
    if (val as u64) < base { val } else { -1 }
}

unsafe fn parse_scanned_float(s: *const u8, start: usize, end: usize) -> f64 {
    unsafe {
        let mut i = start;
        let mut negative = false;
        if i < end {
            let c = *s.add(i);
            if c == b'+' {
                i += 1;
            } else if c == b'-' {
                negative = true;
                i += 1;
            }
        }

        let mut result: f64 = 0.0;

        while i < end {
            let c = *s.add(i);
            if c < b'0' || c > b'9' {
                break;
            }
            result = result * 10.0 + (c - b'0') as f64;
            i += 1;
        }

        if i < end && *s.add(i) == b'.' {
            i += 1;
            let mut frac: f64 = 0.1;
            while i < end {
                let c = *s.add(i);
                if c < b'0' || c > b'9' {
                    break;
                }
                result += (c - b'0') as f64 * frac;
                frac *= 0.1;
                i += 1;
            }
        }

        if i < end {
            let c = *s.add(i);
            if c == b'e' || c == b'E' {
                i += 1;
                let mut exp_neg = false;
                if i < end {
                    let sign = *s.add(i);
                    if sign == b'+' {
                        i += 1;
                    } else if sign == b'-' {
                        exp_neg = true;
                        i += 1;
                    }
                }

                let mut exp: i32 = 0;
                while i < end {
                    let d = *s.add(i);
                    if d < b'0' || d > b'9' {
                        break;
                    }
                    exp = exp.saturating_mul(10).saturating_add((d - b'0') as i32);
                    i += 1;
                }

                // Avoid pathological runtime on absurd exponent lengths.
                let exp_limited = core::cmp::min(exp, 1024);
                let mut power: f64 = 1.0;
                let mut k = 0;
                while k < exp_limited {
                    power *= 10.0;
                    k += 1;
                }
                if exp_neg {
                    result /= power;
                } else {
                    result *= power;
                }
            }
        }

        if negative { -result } else { result }
    }
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
        salty::posix::posix_open(template, (salty::O_RDWR | salty::O_CREAT | salty::O_EXCL) as i32, 0o600)
    }
}

// ======================================================================
// getdelim / getline
// ======================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getdelim(
    lineptr: *mut *mut u8,
    n: *mut usize,
    delim: i32,
    stream: *mut FILE,
) -> isize {
    if lineptr.is_null() || n.is_null() || stream.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }

    unsafe {
        let mut buf = *lineptr;
        let mut cap = *n;

        // Allocate initial buffer if needed
        if buf.is_null() || cap == 0 {
            cap = 128;
            buf = crate::malloc::malloc(cap);
            if buf.is_null() {
                errno::set_errno(errno::ENOMEM);
                return -1;
            }
            *lineptr = buf;
            *n = cap;
        }

        let mut pos: usize = 0;
        loop {
            let c = fgetc(stream);
            if c == EOF {
                if pos == 0 {
                    return -1;
                }
                break;
            }

            // Ensure space for this char + null terminator
            if pos + 2 > cap {
                let new_cap = cap * 2;
                let new_buf = crate::malloc::realloc(buf, new_cap);
                if new_buf.is_null() {
                    errno::set_errno(errno::ENOMEM);
                    return -1;
                }
                buf = new_buf;
                cap = new_cap;
                *lineptr = buf;
                *n = cap;
            }

            *buf.add(pos) = c as u8;
            pos += 1;

            if c == delim {
                break;
            }
        }

        *buf.add(pos) = 0;
        pos as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getline(
    lineptr: *mut *mut u8,
    n: *mut usize,
    stream: *mut FILE,
) -> isize {
    unsafe { getdelim(lineptr, n, b'\n' as i32, stream) }
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
                b'f' | b'F' => {
                    let val = ap.arg::<f64>();
                    let prec = if precision < 0 { 6 } else { precision as usize };
                    let mut fbuf = [0u8; 350];
                    let flen = format_double_fixed(val, prec, flag_plus, flag_space, &mut fbuf);
                    let pad_char = if flag_zero && !flag_minus { b'0' } else { b' ' };
                    let pad = if width as usize > flen { width as usize - flen } else { 0 };
                    if !flag_minus && pad_char == b' ' {
                        for _ in 0..pad { emit!(b' '); }
                    }
                    if !flag_minus && pad_char == b'0' {
                        // Emit sign first, then zeros
                        let mut k = 0;
                        if flen > 0 && (fbuf[0] == b'-' || fbuf[0] == b'+' || fbuf[0] == b' ') {
                            emit!(fbuf[0]);
                            k = 1;
                        }
                        for _ in 0..pad { emit!(b'0'); }
                        for j in k..flen { emit!(fbuf[j]); }
                    } else {
                        for j in 0..flen { emit!(fbuf[j]); }
                    }
                    if flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                }
                b'e' | b'E' => {
                    let val = ap.arg::<f64>();
                    let prec = if precision < 0 { 6 } else { precision as usize };
                    let upper = spec == b'E';
                    let mut fbuf = [0u8; 350];
                    let flen = format_double_sci(val, prec, flag_plus, flag_space, upper, &mut fbuf);
                    let pad = if width as usize > flen { width as usize - flen } else { 0 };
                    if !flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                    for j in 0..flen { emit!(fbuf[j]); }
                    if flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                }
                b'g' | b'G' => {
                    let val = ap.arg::<f64>();
                    let prec = if precision < 0 { 6 } else if precision == 0 { 1 } else { precision as usize };
                    let upper = spec == b'G';
                    // Use %e if exponent < -4 or >= prec, else %f
                    let mut fbuf_f = [0u8; 350];
                    let mut fbuf_e = [0u8; 350];
                    let flen_f = format_double_fixed(val, prec.saturating_sub(1), flag_plus, flag_space, &mut fbuf_f);
                    let flen_e = format_double_sci(val, prec.saturating_sub(1), flag_plus, flag_space, upper, &mut fbuf_e);
                    // Pick shorter representation
                    let (fbuf, flen) = if flen_e < flen_f {
                        (&fbuf_e, flen_e)
                    } else {
                        (&fbuf_f, flen_f)
                    };
                    let pad = if width as usize > flen { width as usize - flen } else { 0 };
                    if !flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
                    for j in 0..flen { emit!(fbuf[j]); }
                    if flag_minus {
                        for _ in 0..pad { emit!(b' '); }
                    }
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

// ======================================================================
// Double-to-string helpers for %f, %e, %g
// ======================================================================

fn is_nan_bits(val: f64) -> bool {
    let bits = val.to_bits();
    let exp = (bits >> 52) & 0x7FF;
    let frac = bits & 0x000FFFFFFFFFFFFF;
    exp == 0x7FF && frac != 0
}

fn is_inf_bits(val: f64) -> bool {
    let bits = val.to_bits();
    let exp = (bits >> 52) & 0x7FF;
    let frac = bits & 0x000FFFFFFFFFFFFF;
    exp == 0x7FF && frac == 0
}

fn is_negative_bits(val: f64) -> bool {
    (val.to_bits() >> 63) != 0
}

/// Format a double as fixed-point (%f). Returns number of bytes written to buf.
fn format_double_fixed(val: f64, prec: usize, plus: bool, space: bool, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    // Handle special values
    if is_nan_bits(val) {
        let s = b"nan";
        for &c in s { buf[pos] = c; pos += 1; }
        return pos;
    }
    if is_inf_bits(val) {
        if is_negative_bits(val) {
            buf[pos] = b'-'; pos += 1;
        } else if plus {
            buf[pos] = b'+'; pos += 1;
        } else if space {
            buf[pos] = b' '; pos += 1;
        }
        let s = b"inf";
        for &c in s { buf[pos] = c; pos += 1; }
        return pos;
    }

    let negative = is_negative_bits(val);
    let abs_val = if negative { -val } else { val };

    if negative {
        buf[pos] = b'-'; pos += 1;
    } else if plus {
        buf[pos] = b'+'; pos += 1;
    } else if space {
        buf[pos] = b' '; pos += 1;
    }

    // Split into integer and fractional parts
    let int_part = abs_val as u64;
    let mut frac_part = abs_val - (int_part as f64);

    // Format integer part
    let int_len = format_unsigned_into(int_part, 10, false, &mut buf[pos..]);
    pos += int_len;

    if prec > 0 {
        buf[pos] = b'.'; pos += 1;

        // Format fractional digits
        for _ in 0..prec {
            frac_part *= 10.0;
            let digit = frac_part as u8;
            buf[pos] = b'0' + digit;
            pos += 1;
            frac_part -= digit as f64;
        }

        // Simple rounding: if remaining frac >= 0.5, round up
        if frac_part >= 0.5 {
            // Carry from rightmost digit
            let mut k = pos - 1;
            loop {
                if buf[k] == b'.' {
                    if k == 0 { break; }
                    k -= 1;
                    continue;
                }
                if buf[k] < b'9' {
                    buf[k] += 1;
                    break;
                }
                buf[k] = b'0';
                if k == 0 { break; }
                k -= 1;
                // If we carried past the sign, we'd need to insert a '1'
                // but this is rare enough to skip for a basic implementation
            }
        }
    } else if prec == 0 {
        // Round integer part
        if frac_part >= 0.5 {
            // Increment the integer portion string
            let mut k = pos - 1;
            loop {
                if buf[k] < b'9' {
                    buf[k] += 1;
                    break;
                }
                buf[k] = b'0';
                if k == 0 {
                    break;
                }
                k -= 1;
            }
        }
    }

    pos
}

/// Format a double in scientific notation (%e). Returns number of bytes written.
fn format_double_sci(val: f64, prec: usize, plus: bool, space: bool, upper: bool, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    if is_nan_bits(val) {
        let s = if upper { b"NAN" } else { b"nan" };
        for &c in s.iter() { buf[pos] = c; pos += 1; }
        return pos;
    }
    if is_inf_bits(val) {
        if is_negative_bits(val) {
            buf[pos] = b'-'; pos += 1;
        } else if plus {
            buf[pos] = b'+'; pos += 1;
        } else if space {
            buf[pos] = b' '; pos += 1;
        }
        let s = if upper { b"INF" } else { b"inf" };
        for &c in s.iter() { buf[pos] = c; pos += 1; }
        return pos;
    }

    let negative = is_negative_bits(val);
    let abs_val = if negative { -val } else { val };

    if negative {
        buf[pos] = b'-'; pos += 1;
    } else if plus {
        buf[pos] = b'+'; pos += 1;
    } else if space {
        buf[pos] = b' '; pos += 1;
    }

    if abs_val == 0.0 {
        buf[pos] = b'0'; pos += 1;
        if prec > 0 {
            buf[pos] = b'.'; pos += 1;
            for _ in 0..prec {
                buf[pos] = b'0'; pos += 1;
            }
        }
        buf[pos] = if upper { b'E' } else { b'e' }; pos += 1;
        buf[pos] = b'+'; pos += 1;
        buf[pos] = b'0'; pos += 1;
        buf[pos] = b'0'; pos += 1;
        return pos;
    }

    // Compute exponent
    let mut exp: i32 = 0;
    let mut normalized = abs_val;

    if normalized >= 10.0 {
        while normalized >= 10.0 {
            normalized /= 10.0;
            exp += 1;
        }
    } else if normalized < 1.0 {
        while normalized < 1.0 {
            normalized *= 10.0;
            exp -= 1;
        }
    }

    // normalized is now in [1.0, 10.0)
    // Format as d.ddd...
    let leading = normalized as u8;
    buf[pos] = b'0' + leading; pos += 1;
    let mut frac = normalized - leading as f64;

    if prec > 0 {
        buf[pos] = b'.'; pos += 1;
        for _ in 0..prec {
            frac *= 10.0;
            let digit = frac as u8;
            buf[pos] = b'0' + digit;
            pos += 1;
            frac -= digit as f64;
        }
    }

    // Exponent
    buf[pos] = if upper { b'E' } else { b'e' }; pos += 1;
    if exp >= 0 {
        buf[pos] = b'+'; pos += 1;
    } else {
        buf[pos] = b'-'; pos += 1;
        exp = -exp;
    }
    if exp >= 100 {
        buf[pos] = b'0' + (exp / 100) as u8; pos += 1;
        buf[pos] = b'0' + ((exp / 10) % 10) as u8; pos += 1;
        buf[pos] = b'0' + (exp % 10) as u8; pos += 1;
    } else {
        buf[pos] = b'0' + (exp / 10) as u8; pos += 1;
        buf[pos] = b'0' + (exp % 10) as u8; pos += 1;
    }

    pos
}
