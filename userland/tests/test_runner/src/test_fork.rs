//! Fork/waitpid tests
//! Ported from userland/test_fork/main.c
//! SPDX-License-Identifier: GPL-2.0-only

use trona::serial;
use trona::serial::LineBuf;
use trona::types::core::*;
use trona_posix::proc as posix;
use trona_posix::*;

const STACK_TOUCH_BYTES: usize = 32 * 1024;
fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn expected_stack_checksum(seed: u8) -> u64 {
    let mut sum = 0u64;
    let mut page_idx = 0usize;
    while page_idx * 4096 < STACK_TOUCH_BYTES {
        sum += seed.wrapping_add(page_idx as u8) as u64;
        page_idx += 1;
    }
    sum
}

#[inline(never)]
fn stack_checksum(seed: u8) -> u64 {
    let mut buf = [0u8; STACK_TOUCH_BYTES];
    let mut page_idx = 0usize;
    while page_idx * 4096 < buf.len() {
        let offset = page_idx * 4096;
        let value = seed.wrapping_add(page_idx as u8);
        unsafe {
            core::ptr::write_volatile(buf.as_mut_ptr().add(offset), value);
        }
        page_idx += 1;
    }

    let mut sum = 0u64;
    let mut read_idx = 0usize;
    while read_idx * 4096 < buf.len() {
        let offset = read_idx * 4096;
        unsafe {
            sum += core::ptr::read_volatile(buf.as_ptr().add(offset)) as u64;
        }
        read_idx += 1;
    }
    sum
}

pub fn run() -> bool {
    puts(b"[TEST_FORK] Starting fork tests\n");

    // Test 1: getpid
    let my_pid = unsafe { trona_posix::posix_getpid() };
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_FORK] Test 1: getpid = "); lb.dec(my_pid as u64); lb.str(b"\n"); lb.flush(); }
    if my_pid <= 0 {
        puts(b"[TEST_FORK] FAIL: getpid\n");
        return false;
    }
    puts(b"[TEST_FORK] Test 1: PASS\n");

    // Test 2: getppid
    let my_ppid = unsafe { trona_posix::posix_getppid() };
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_FORK] Test 2: getppid = "); lb.dec(my_ppid as u64); lb.str(b"\n"); lb.flush(); }
    puts(b"[TEST_FORK] Test 2: PASS\n");

    // Test 3: fork + waitpid
    puts(b"[TEST_FORK] Test 3: fork...\n");
    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"[TEST_FORK] FAIL: fork returned -1\n");
        return false;
    }

    if pid == 0 {
        puts(b"[TEST_FORK] Child: I am the child, exiting with code 7\n");
        unsafe { trona_posix::posix_exit(7) };
    }

    { let mut lb = LineBuf::new(); lb.str(b"[TEST_FORK] Parent: child PID = "); lb.dec(pid as u64); lb.str(b"\n"); lb.flush(); }

    let mut status: i32 = 0;
    let ret = unsafe { trona_posix::posix_waitpid(pid, &raw mut status) };
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_FORK] Parent: waitpid returned "); lb.dec(ret as u64); lb.str(b", status = "); lb.dec(status as u64); lb.str(b"\n"); lb.flush(); }

    if ret != pid || !wifexited(status) || wexitstatus(status) != 7 {
        puts(b"[TEST_FORK] FAIL: waitpid\n");
        return false;
    }
    puts(b"[TEST_FORK] Test 3: PASS\n");

    // Test 4: default process stack must be large enough for post-fork toolchain paths.
    puts(b"[TEST_FORK] Test 4: fork + stack headroom\n");
    let expected_parent = expected_stack_checksum(0x30);
    let expected_child = expected_stack_checksum(0x70);
    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"[TEST_FORK] FAIL: second fork returned -1\n");
        return false;
    }

    if pid == 0 {
        let sum = stack_checksum(0x70);
        unsafe { trona_posix::posix_exit(if sum == expected_child { 11 } else { 12 }) };
    }

    let parent_sum = stack_checksum(0x30);
    if parent_sum != expected_parent {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_FORK] FAIL: parent stack checksum mismatch got ");
        lb.dec(parent_sum);
        lb.str(b" expected ");
        lb.dec(expected_parent);
        lb.str(b"\n");
        lb.flush();
        return false;
    }

    let mut stack_status: i32 = 0;
    let ret = unsafe { trona_posix::posix_waitpid(pid, &raw mut stack_status) };
    if ret != pid || !wifexited(stack_status) || wexitstatus(stack_status) != 11 {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_FORK] FAIL: stack headroom child status=");
        lb.dec(stack_status as u64);
        lb.str(b"\n");
        lb.flush();
        return false;
    }
    puts(b"[TEST_FORK] Test 4: PASS\n");

    puts(b"[TEST_FORK] All tests passed!\n");
    true
}
