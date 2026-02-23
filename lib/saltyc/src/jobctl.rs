//! Job control — process groups and sessions
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Thin wrappers around `salty::posix::posix_setpgid` / `posix_setsid` /
//! `posix_getpgrp`. Terminal process group functions (`tcgetpgrp`,
//! `tcsetpgrp`) return stubs since SaltyOS has no controlling terminal.

use crate::errno;
use salty::serial::LineBuf;

static mut JOBCTL_DBG_BUDGET: u32 = 128;

#[inline(always)]
unsafe fn jobctl_dbg3(tag: &[u8], a: i32, b: i32, ret: i32) {
    unsafe {
        if JOBCTL_DBG_BUDGET == 0 {
            return;
        }
        JOBCTL_DBG_BUDGET -= 1;
        let mut lb = LineBuf::new();
        lb.str(b"[JOBCTL] ");
        lb.str(tag);
        lb.str(b" a=");
        lb.dec(a as u64);
        lb.str(b" b=");
        lb.dec(b as u64);
        lb.str(b" -> ");
        lb.dec(ret as u64);
        lb.str(b"\n");
        lb.flush();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpgid(pid: i32, pgid: i32) -> i32 {
    let ret = unsafe { salty::posix::posix_setpgid(pid, pgid) };
    unsafe {
        jobctl_dbg3(b"setpgid", pid, pgid, ret);
    }
    if ret < 0 {
        errno::set_errno(-ret);
        return -1;
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpgid(pid: i32) -> i32 {
    let ret = unsafe { salty::posix::posix_getpgid(pid) };
    unsafe {
        jobctl_dbg3(b"getpgid", pid, 0, ret);
    }
    if ret < 0 {
        errno::set_errno(-ret);
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
    unsafe {
        jobctl_dbg3(b"setsid", 0, 0, ret);
    }
    if ret < 0 {
        errno::set_errno(-ret);
        return -1;
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsid(pid: i32) -> i32 {
    let ret = unsafe { salty::posix::posix_getsid(pid) };
    unsafe {
        jobctl_dbg3(b"getsid", pid, 0, ret);
    }
    if ret < 0 {
        errno::set_errno(-ret);
        return -1;
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcgetpgrp(fd: i32) -> i32 {
    let ret = unsafe { salty::posix::posix_ioctl(fd, salty::consts::TIOCGPGRP, 0) };
    unsafe {
        jobctl_dbg3(b"tcgetpgrp", fd, 0, ret);
    }
    if ret < 0 {
        errno::set_errno(-ret);
        return -1;
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcsetpgrp(fd: i32, pgrp: i32) -> i32 {
    let ret = unsafe { salty::posix::posix_ioctl(fd, salty::consts::TIOCSPGRP, pgrp as u64) };
    unsafe {
        jobctl_dbg3(b"tcsetpgrp", fd, pgrp, ret);
    }
    if ret < 0 {
        errno::set_errno(-ret);
        return -1;
    }
    ret
}
