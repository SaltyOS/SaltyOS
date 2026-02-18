//! errno implementation
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Global errno variable with `__errno_location()` accessor for C code.
//! Values use Linux numbering (e.g. `ENOENT = 2`, `EINVAL = 22`).
//!
//! Thread-safe: uses per-thread errno via the TLS block when available,
//! falling back to a global variable during early single-threaded startup.

// errno constants
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const E2BIG: i32 = 7;
pub const ENOEXEC: i32 = 8;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENODEV: i32 = 19;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EMFILE: i32 = 24;
pub const ENOTTY: i32 = 25;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const EROFS: i32 = 30;
pub const EMLINK: i32 = 31;
pub const EPIPE: i32 = 32;
pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ELOOP: i32 = 40;
pub const EWOULDBLOCK: i32 = EAGAIN;
pub const ENAMETOOLONG: i32 = 36;
pub const EOVERFLOW: i32 = 75;
pub const EILSEQ: i32 = 84;
pub const EDEADLK: i32 = 35;
pub const ENOLCK: i32 = 37;
pub const ENODATA: i32 = 61;
pub const ETIME: i32 = 62;
pub const EPROTO: i32 = 71;
pub const EMULTIHOP: i32 = 72;
pub const EBADMSG: i32 = 74;
pub const ENOTSOCK: i32 = 88;
pub const EOPNOTSUPP: i32 = 95;
pub const ENOTSUP: i32 = EOPNOTSUPP;
pub const EAFNOSUPPORT: i32 = 97;
pub const EADDRINUSE: i32 = 98;
pub const ECONNRESET: i32 = 104;
pub const ENOBUFS: i32 = 105;
pub const EISCONN: i32 = 106;
pub const ENOTCONN: i32 = 107;
pub const ETIMEDOUT: i32 = 110;
pub const ECONNREFUSED: i32 = 111;
pub const EALREADY: i32 = 114;
pub const EINPROGRESS: i32 = 115;
pub const ECANCELED: i32 = 125;
pub const EOWNERDEAD: i32 = 130;
pub const ENOTRECOVERABLE: i32 = 131;

/// Global fallback errno for when TLS is not yet initialized.
static mut ERRNO: i32 = 0;

/// Return a pointer to the per-thread errno.
///
/// Uses the TLS block's `errno` field if TLS is initialized, otherwise
/// falls back to the global `ERRNO` (safe during early single-threaded
/// startup before threads are created).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __errno_location() -> *mut i32 {
    let tls_ptr = salty::tls::current_errno();
    if !tls_ptr.is_null() {
        tls_ptr
    } else {
        &raw mut ERRNO
    }
}

/// Set errno from Rust code.
pub fn set_errno(val: i32) {
    unsafe {
        *__errno_location() = val;
    }
}

/// Get errno from Rust code.
pub fn get_errno() -> i32 {
    unsafe { *__errno_location() }
}
