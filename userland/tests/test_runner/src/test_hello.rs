//! Hello test - exercises POSIX wrapper API: getpid, open, write, close
//! Ported from userland/hello/main.c
//! SPDX-License-Identifier: GPL-2.0-only

use salty::consts::*;
use salty::posix;
use salty::serial;

pub fn run() -> bool {
    serial::serial_puts(b"[TEST_HELLO] starting\n");

    // 1. getpid
    let pid = unsafe { posix::posix_getpid() };
    { let mut lb = serial::LineBuf::new(); lb.str(b"[TEST_HELLO] PID="); lb.hex(pid as u64); lb.str(b"\n"); lb.flush(); }
    if pid <= 0 {
        serial::serial_puts(b"[TEST_HELLO] FAIL: getpid <= 0\n");
        return false;
    }

    // 2. open /dev/console
    let fd = unsafe { posix::posix_open(b"/dev/console\0".as_ptr(), O_WRONLY as i32, 0) };
    { let mut lb = serial::LineBuf::new(); lb.str(b"[TEST_HELLO] open /dev/console fd="); lb.hex(fd as u64); lb.str(b"\n"); lb.flush(); }

    if fd >= 0 {
        // 3. write greeting via VFS -> console
        let msg = b"[TEST_HELLO] Hello from Rust test runner!\n";
        unsafe { posix::posix_write(fd, msg.as_ptr(), msg.len() as u64) };
    }

    // 4. open /dev/null and write to it
    let fd_null = unsafe { posix::posix_open(b"/dev/null\0".as_ptr(), O_WRONLY as i32, 0) };
    { let mut lb = serial::LineBuf::new(); lb.str(b"[TEST_HELLO] open /dev/null fd="); lb.hex(fd_null as u64); lb.str(b"\n"); lb.flush(); }

    if fd_null >= 0 {
        unsafe {
            posix::posix_write(fd_null, b"discard".as_ptr(), 7);
            posix::posix_close(fd_null);
        }
        serial::serial_puts(b"[TEST_HELLO] close /dev/null\n");
    }

    // 5. close console fd
    if fd >= 0 {
        unsafe { posix::posix_close(fd) };
        serial::serial_puts(b"[TEST_HELLO] close /dev/console\n");
    }

    serial::serial_puts(b"[TEST_HELLO] PASS\n");
    true
}
