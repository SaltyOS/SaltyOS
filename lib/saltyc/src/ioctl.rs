//! ioctl system call wrapper
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Forwards ioctl requests to the VFS/TTYD via posix_ioctl.

use crate::errno;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioctl(fd: i32, request: u64, mut args: ...) -> i32 {
    let arg: u64 = unsafe { args.arg::<u64>() };

    let ret = unsafe { salty::posix::posix_ioctl(fd, request, arg) };
    if ret < 0 {
        errno::set_errno(-ret);
        return -1;
    }
    ret
}
