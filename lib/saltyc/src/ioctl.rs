//! ioctl system call wrapper
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Only `TIOCGWINSZ` is handled, returning a hardcoded 80x24 terminal size.
//! All other ioctl requests return `ENOTTY`.

use crate::errno;

const TIOCGWINSZ: u64 = 0x5413;

#[repr(C)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioctl(fd: i32, request: u64, mut args: ...) -> i32 {
    let arg: u64 = unsafe { args.arg::<u64>() };

    if request == TIOCGWINSZ {
        let ws = arg as *mut Winsize;
        if !ws.is_null() {
            unsafe {
                (*ws).ws_row = 24;
                (*ws).ws_col = 80;
                (*ws).ws_xpixel = 0;
                (*ws).ws_ypixel = 0;
            }
        }
        return 0;
    }

    let ret = unsafe { salty::posix::posix_ioctl(fd, request, arg) };
    if ret < 0 {
        errno::set_errno(-ret);
        return -1;
    }
    ret
}
