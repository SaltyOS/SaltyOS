//! BSD err(3) error reporting functions
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Implements: `err`, `errx`, `errc`, `warn`, `warnx`, `warnc`, and their
//! `v`-prefixed `VaList` variants (`verr`, `verrx`, `vwarn`, `vwarnx`,
//! `vwarnc`). Output format: `progname: message: strerror(errno)\n`.
//! The `err`/`errx`/`errc` functions call `exit()` after printing; the
//! `warn` variants return normally.

use core::ffi::VaList;

unsafe extern "C" {
    safe fn getprogname() -> *const u8;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Write the program name prefix ("progname: ") to stderr.
unsafe fn write_prefix() {
    unsafe {
        let se = crate::stdio::stderr;
        let prog = getprogname();
        if !prog.is_null() {
            crate::stdio::fputs(prog, se);
            crate::stdio::fputs(b": \0".as_ptr(), se);
        }
    }
}

/// Write a formatted message to stderr using vfprintf.
/// Does nothing if fmt is NULL.
unsafe fn write_fmt(fmt: *const u8, ap: VaList<'_>) {
    unsafe {
        if !fmt.is_null() {
            let se = crate::stdio::stderr;
            crate::stdio::vfprintf(se, fmt, ap);
        }
    }
}

/// Write ": <strerror(code)>\n" to stderr.
unsafe fn write_error_suffix(code: i32) {
    unsafe {
        let se = crate::stdio::stderr;
        crate::stdio::fputs(b": \0".as_ptr(), se);
        crate::stdio::fputs(crate::string::strerror(code), se);
        crate::stdio::fputc(b'\n' as i32, se);
    }
}

/// Write a bare "\n" to stderr.
unsafe fn write_newline() {
    unsafe {
        crate::stdio::fputc(b'\n' as i32, crate::stdio::stderr);
    }
}

// ---------------------------------------------------------------------------
// vwarn, vwarnx, vwarnc — va_list variants
// ---------------------------------------------------------------------------

/// Print "progname: fmt_output: strerror(errno)\n" to stderr.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vwarn(fmt: *const u8, ap: VaList<'_>) {
    unsafe {
        write_prefix();
        write_fmt(fmt, ap);
        write_error_suffix(crate::errno::get_errno());
    }
}

/// Print "progname: fmt_output\n" to stderr (no errno).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vwarnx(fmt: *const u8, ap: VaList<'_>) {
    unsafe {
        write_prefix();
        write_fmt(fmt, ap);
        write_newline();
    }
}

/// Print "progname: fmt_output: strerror(code)\n" to stderr.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vwarnc(code: i32, fmt: *const u8, ap: VaList<'_>) {
    unsafe {
        write_prefix();
        write_fmt(fmt, ap);
        write_error_suffix(code);
    }
}

// ---------------------------------------------------------------------------
// warn, warnx, warnc — variadic wrappers
// ---------------------------------------------------------------------------

/// Print "progname: fmt_output: strerror(errno)\n" to stderr.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warn(fmt: *const u8, args: ...) {
    unsafe {
        vwarn(fmt, args);
    }
}

/// Print "progname: fmt_output\n" to stderr (no errno).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warnx(fmt: *const u8, args: ...) {
    unsafe {
        vwarnx(fmt, args);
    }
}

/// Print "progname: fmt_output: strerror(code)\n" to stderr.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn warnc(code: i32, fmt: *const u8, args: ...) {
    unsafe {
        vwarnc(code, fmt, args);
    }
}

// ---------------------------------------------------------------------------
// verr, verrx — va_list variants that exit
// ---------------------------------------------------------------------------

/// Print "progname: fmt_output: strerror(errno)\n" to stderr, then exit(eval).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verr(eval: i32, fmt: *const u8, ap: VaList<'_>) -> ! {
    unsafe {
        vwarn(fmt, ap);
        crate::crt::exit(eval);
    }
}

/// Print "progname: fmt_output\n" to stderr, then exit(eval).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verrx(eval: i32, fmt: *const u8, ap: VaList<'_>) -> ! {
    unsafe {
        vwarnx(fmt, ap);
        crate::crt::exit(eval);
    }
}

// ---------------------------------------------------------------------------
// err, errx, errc — variadic wrappers that exit
// ---------------------------------------------------------------------------

/// Print "progname: fmt_output: strerror(errno)\n" to stderr, then exit(eval).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn err(eval: i32, fmt: *const u8, args: ...) -> ! {
    unsafe {
        vwarn(fmt, args);
        crate::crt::exit(eval);
    }
}

/// Print "progname: fmt_output\n" to stderr, then exit(eval).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn errx(eval: i32, fmt: *const u8, args: ...) -> ! {
    unsafe {
        vwarnx(fmt, args);
        crate::crt::exit(eval);
    }
}

/// Print "progname: fmt_output: strerror(code)\n" to stderr, then exit(eval).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn errc(eval: i32, code: i32, fmt: *const u8, args: ...) -> ! {
    unsafe {
        vwarnc(code, fmt, args);
        crate::crt::exit(eval);
    }
}
