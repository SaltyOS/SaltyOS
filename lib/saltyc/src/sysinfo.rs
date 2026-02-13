//! System information stubs
//! SPDX-License-Identifier: GPL-2.0-only

use crate::errno;

#[repr(C)]
pub struct Utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
}

#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

pub const RLIM_INFINITY: u64 = u64::MAX;

// sysconf constants
pub const _SC_ARG_MAX: i32 = 0;
pub const _SC_CHILD_MAX: i32 = 1;
pub const _SC_CLK_TCK: i32 = 2;
pub const _SC_OPEN_MAX: i32 = 4;
pub const _SC_STREAM_MAX: i32 = 5;
pub const _SC_PAGESIZE: i32 = 30;
pub const _SC_PAGE_SIZE: i32 = 30;
pub const _SC_LINE_MAX: i32 = 43;
pub const _SC_GETGR_R_SIZE_MAX: i32 = 69;
pub const _SC_GETPW_R_SIZE_MAX: i32 = 70;
pub const _SC_NPROCESSORS_CONF: i32 = 83;
pub const _SC_NPROCESSORS_ONLN: i32 = 84;
pub const _SC_PHYS_PAGES: i32 = 85;

/// Copy `src` bytes into `dst`, padding the remainder with zeroes.
unsafe fn copy_str(dst: *mut u8, dst_len: usize, src: &[u8]) {
    unsafe {
        let copy_len = if src.len() < dst_len { src.len() } else { dst_len - 1 };
        let mut i = 0;
        while i < copy_len {
            *dst.add(i) = src[i];
            i += 1;
        }
        // Zero-fill the rest
        while i < dst_len {
            *dst.add(i) = 0;
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn uname(buf: *mut Utsname) -> i32 {
    if buf.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        copy_str((*buf).sysname.as_mut_ptr(), 65, b"SaltyOS");
        copy_str((*buf).nodename.as_mut_ptr(), 65, b"salty");
        copy_str((*buf).release.as_mut_ptr(), 65, b"0.1.0");
        copy_str((*buf).version.as_mut_ptr(), 65, b"0.1.0");
        copy_str((*buf).machine.as_mut_ptr(), 65, b"x86_64");
    }
    0
}

/// __xuname — FreeBSD's uname() is a macro that calls __xuname(SYS_NMLN, buf).
/// We ignore the nmln parameter and fill our standard Utsname.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xuname(_nmln: i32, buf: *mut Utsname) -> i32 {
    unsafe { uname(buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gethostname(name: *mut u8, len: usize) -> i32 {
    if name.is_null() || len == 0 {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let hostname = b"salty\0";
        let copy_len = if hostname.len() < len { hostname.len() } else { len };
        let mut i = 0;
        while i < copy_len {
            *name.add(i) = hostname[i];
            i += 1;
        }
        // Ensure null termination if we truncated
        if copy_len == len {
            *name.add(len - 1) = 0;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sysconf(name: i32) -> i64 {
    match name {
        _SC_CLK_TCK => 100,
        _SC_OPEN_MAX => 256,
        _SC_PAGESIZE => 4096,
        _SC_NPROCESSORS_ONLN => 1,
        _SC_NPROCESSORS_CONF => 1,
        _SC_CHILD_MAX => 64,
        _SC_ARG_MAX => 131072,
        _SC_STREAM_MAX => 16,
        _SC_LINE_MAX => 2048,
        _SC_GETPW_R_SIZE_MAX => 1024,
        _SC_GETGR_R_SIZE_MAX => 1024,
        _SC_PHYS_PAGES => 65536, // 256 MB / 4096 bytes per page
        _ => -1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrlimit(_resource: i32, rlp: *mut Rlimit) -> i32 {
    if rlp.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        (*rlp).rlim_cur = RLIM_INFINITY;
        (*rlp).rlim_max = RLIM_INFINITY;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setrlimit(_resource: i32, _rlp: *const Rlimit) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrusage(_who: i32, usage: *mut u8) -> i32 {
    if usage.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        // Zero out the full rusage struct (144 bytes on x86_64)
        let mut i = 0;
        while i < 144 {
            *usage.add(i) = 0;
            i += 1;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn getdtablesize() -> i32 {
    256
}
