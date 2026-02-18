//! Miscellaneous FreeBSD/BSD compatibility functions
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Functions here have no POSIX equivalent or are FreeBSD-specific
//! interfaces used by ported utilities.

use crate::errno;

// ---------------------------------------------------------------------------
// getprogname / setprogname — BSD program name accessors
// ---------------------------------------------------------------------------

static mut PROGNAME: *const u8 = b"\0".as_ptr();

#[unsafe(no_mangle)]
pub extern "C" fn getprogname() -> *const u8 {
    // SAFETY: PROGNAME is only written via setprogname and during startup.
    unsafe { *(&raw const PROGNAME) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setprogname(name: *const u8) {
    if name.is_null() {
        return;
    }
    unsafe {
        // Store the basename portion (after last '/')
        let mut last_slash: *const u8 = core::ptr::null();
        let mut p = name;
        while *p != 0 {
            if *p == b'/' {
                last_slash = p;
            }
            p = p.add(1);
        }
        if !last_slash.is_null() {
            *(&raw mut PROGNAME) = last_slash.add(1);
        } else {
            *(&raw mut PROGNAME) = name;
        }
    }
}

// ---------------------------------------------------------------------------
// __xuname — FreeBSD uname wrapper
// ---------------------------------------------------------------------------

/// __xuname — FreeBSD's uname() is a macro that calls __xuname(SYS_NMLN, buf).
/// We ignore the nmln parameter and fill our standard Utsname.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xuname(_nmln: i32, buf: *mut crate::sysinfo::Utsname) -> i32 {
    unsafe { crate::sysinfo::uname(buf) }
}

// ---------------------------------------------------------------------------
// FreeBSD-specific miscellaneous functions
// ---------------------------------------------------------------------------

/// getosreldate — FreeBSD OS release date.
#[unsafe(no_mangle)]
pub extern "C" fn getosreldate() -> i32 {
    1402000
}

/// getloginclass — FreeBSD login class. Not supported.
#[unsafe(no_mangle)]
pub extern "C" fn getloginclass(_buf: *mut u8, _len: usize) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

/// getlogin — return login name. Returns "root".
#[unsafe(no_mangle)]
pub extern "C" fn getlogin() -> *const u8 {
    b"root\0".as_ptr()
}

/// getgrouplist — get groups for user. Returns just the primary group.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrouplist(
    _user: *const u8,
    group: u32,
    groups: *mut u32,
    ngroups: *mut i32,
) -> i32 {
    unsafe {
        if !groups.is_null() && !ngroups.is_null() && *ngroups >= 1 {
            *groups = group;
            *ngroups = 1;
            return 0;
        }
        if !ngroups.is_null() {
            *ngroups = 1;
        }
        -1
    }
}

/// pledge — OpenBSD security model. No-op on SaltyOS (uses capabilities).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pledge(_promises: *const u8, _execpromises: *const u8) -> i32 {
    0
}

/// unveil — OpenBSD security model. No-op on SaltyOS (uses capabilities).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unveil(_path: *const u8, _permissions: *const u8) -> i32 {
    0
}

/// lchmod — chmod on symlink. Not supported.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lchmod(_path: *const u8, _mode: u32) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

/// mknod — create device special file. Not supported.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mknod(_path: *const u8, _mode: u32, _dev: u64) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

unsafe extern "C" {
    safe fn abort() -> !;
}

/// FreeBSD __assert(func, file, line, expr) — called by FreeBSD's assert() macro.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __assert(
    _func: *const u8,
    _file: *const u8,
    _line: i32,
    _expr: *const u8,
) -> ! {
    abort()
}

static mut GETBSIZE_BUF: [u8; 32] = [0; 32];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getbsize(headerlenp: *mut i32, blocksizep: *mut i64) -> *mut u8 {
    unsafe {
        // Default: 512-byte blocks, "512" header
        if !blocksizep.is_null() {
            *blocksizep = 512;
        }
        if !headerlenp.is_null() {
            *headerlenp = 3; // length of "512"
        }
        let buf = core::ptr::addr_of_mut!(GETBSIZE_BUF) as *mut u8;
        *buf.add(0) = b'5';
        *buf.add(1) = b'1';
        *buf.add(2) = b'2';
        *buf.add(3) = 0;
        buf
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpathconf(_path: *const u8, name: i32) -> i64 {
    unsafe { crate::unistd::pathconf(_path, name) }
}

unsafe extern "C" {
    safe fn access(path: *const u8, mode: i32) -> i32;
}

/// eaccess — like access() but uses effective uid/gid. We only have one uid so just alias.
#[unsafe(no_mangle)]
pub extern "C" fn eaccess(path: *const u8, mode: i32) -> i32 {
    access(path, mode)
}

unsafe extern "C" {
    safe fn fseek(stream: *mut u8, offset: i64, whence: i32) -> i32;
}

/// fseeko — same as fseek with off_t (both 64-bit on our platform).
#[unsafe(no_mangle)]
pub extern "C" fn fseeko(stream: *mut u8, offset: i64, whence: i32) -> i32 {
    fseek(stream, offset, whence)
}

/// ftello — same as ftell with off_t.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftello(stream: *mut u8) -> i64 {
    unsafe extern "C" {
        safe fn ftell(stream: *mut u8) -> i64;
    }
    ftell(stream)
}

unsafe extern "C" {
    safe fn fork() -> i32;
}

/// vfork — alias for fork (no MMU optimization needed with COW).
#[unsafe(no_mangle)]
pub extern "C" fn vfork() -> i32 {
    fork()
}

/// kqueue — BSD event notification. Not supported.
#[unsafe(no_mangle)]
pub extern "C" fn kqueue() -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

/// kevent — BSD event notification. Not supported.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kevent(
    _kq: i32,
    _changelist: *const u8,
    _nchanges: i32,
    _eventlist: *mut u8,
    _nevents: i32,
    _timeout: *const u8,
) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

/// fstatfs — not supported.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatfs(_fd: i32, _buf: *mut u8) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

/// statfs — not supported.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn statfs(_path: *const u8, _buf: *mut u8) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}
