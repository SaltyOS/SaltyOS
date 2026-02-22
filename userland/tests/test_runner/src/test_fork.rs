//! Fork/waitpid tests
//! Ported from userland/test_fork/main.c
//! SPDX-License-Identifier: GPL-2.0-only

use salty::posix;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub fn run() -> bool {
    puts(b"[TEST_FORK] Starting fork tests\n");

    // Test 1: getpid
    let my_pid = unsafe { posix::posix_getpid() };
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_FORK] Test 1: getpid = "); lb.dec(my_pid as u64); lb.str(b"\n"); lb.flush(); }
    if my_pid <= 0 {
        puts(b"[TEST_FORK] FAIL: getpid\n");
        return false;
    }
    puts(b"[TEST_FORK] Test 1: PASS\n");

    // Test 2: getppid
    let my_ppid = unsafe { posix::posix_getppid() };
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_FORK] Test 2: getppid = "); lb.dec(my_ppid as u64); lb.str(b"\n"); lb.flush(); }
    puts(b"[TEST_FORK] Test 2: PASS\n");

    // Test 3: fork + waitpid
    puts(b"[TEST_FORK] Test 3: fork...\n");
    let pid = posix::posix_fork();
    if pid < 0 {
        puts(b"[TEST_FORK] FAIL: fork returned -1\n");
        return false;
    }

    if pid == 0 {
        puts(b"[TEST_FORK] Child: I am the child, exiting with code 7\n");
        unsafe { posix::posix_exit(7) };
    }

    { let mut lb = LineBuf::new(); lb.str(b"[TEST_FORK] Parent: child PID = "); lb.dec(pid as u64); lb.str(b"\n"); lb.flush(); }

    let mut status: i32 = 0;
    let ret = unsafe { posix::posix_waitpid(pid, &raw mut status) };
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_FORK] Parent: waitpid returned "); lb.dec(ret as u64); lb.str(b", status = "); lb.dec(status as u64); lb.str(b"\n"); lb.flush(); }

    if ret != pid || !wifexited(status) || wexitstatus(status) != 7 {
        puts(b"[TEST_FORK] FAIL: waitpid\n");
        return false;
    }
    puts(b"[TEST_FORK] Test 3: PASS\n");

    puts(b"[TEST_FORK] All tests passed!\n");
    true
}
