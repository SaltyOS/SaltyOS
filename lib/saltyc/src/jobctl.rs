//! Job control — process groups and sessions
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Thin wrappers around `salty::posix::posix_setpgid` / `posix_setsid` /
//! `posix_getpgrp`. Terminal process group functions (`tcgetpgrp`,
//! `tcsetpgrp`) return stubs since SaltyOS has no controlling terminal.

use crate::errno;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpgid(pid: i32, pgid: i32) -> i32 {
    let ret = unsafe { salty::posix::posix_setpgid(pid, pgid) };
    if ret < 0 {
        errno::set_errno(errno::ESRCH);
        return -1;
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpgid(pid: i32) -> i32 {
    let ret = unsafe { salty::posix::posix_getpgid(pid) };
    if ret < 0 {
        errno::set_errno(errno::ESRCH);
        return -1;
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpgrp() -> i32 {
    unsafe { getpgid(0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpgrp() -> i32 {
    unsafe { setpgid(0, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setsid() -> i32 {
    let ret = unsafe { salty::posix::posix_setsid() };
    if ret < 0 {
        errno::set_errno(errno::EPERM);
        return -1;
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsid(pid: i32) -> i32 {
    unsafe { getpgid(pid) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcgetpgrp(fd: i32) -> i32 {
    let ret = unsafe { salty::posix::posix_ioctl(fd, salty::consts::TIOCGPGRP, 0) };
    if ret < 0 {
        errno::set_errno(errno::ENOTTY);
        return -1;
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcsetpgrp(fd: i32, pgrp: i32) -> i32 {
    let ret = unsafe {
        salty::posix::posix_ioctl(fd, salty::consts::TIOCSPGRP, pgrp as u64)
    };
    if ret < 0 {
        errno::set_errno(errno::ENOTTY);
        return -1;
    }
    ret
}
