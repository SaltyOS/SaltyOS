//! Time API test suite
//! SPDX-License-Identifier: GPL-2.0-only

use trona_posix::proc as posix;
use trona::serial;
use trona::types::core::Timespec;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

/// Test clock_gettime monotonicity
fn test_clock_monotonic() -> bool {
    let mut ts1 = Timespec::zeroed();
    let mut ts2 = Timespec::zeroed();

    let ret = unsafe { trona_posix::posix_clock_gettime(0, &raw mut ts1) };
    if ret != 0 {
        puts(b"  clock_gettime(1) failed\n");
        return false;
    }

    // Yield a few times to advance clock
    for _ in 0..10 {
        trona::syscall::syscall(trona::consts::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    let ret = unsafe { trona_posix::posix_clock_gettime(0, &raw mut ts2) };
    if ret != 0 {
        puts(b"  clock_gettime(2) failed\n");
        return false;
    }

    let ns1 = ts1.tv_sec * 1_000_000_000 + ts1.tv_nsec;
    let ns2 = ts2.tv_sec * 1_000_000_000 + ts2.tv_nsec;

    if ns2 <= ns1 {
        puts(b"  clock not monotonic\n");
        return false;
    }

    { let mut lb = serial::LineBuf::new(); lb.str(b"  time advanced by "); lb.dec(ns2 - ns1); lb.str(b" ns\n"); lb.flush(); }
    true
}

/// Test nanosleep (sleep ~50ms and verify elapsed time)
fn test_nanosleep() -> bool {
    let mut before = Timespec::zeroed();
    let mut after = Timespec::zeroed();

    unsafe { trona_posix::posix_clock_gettime(0, &raw mut before) };

    let req = Timespec { tv_sec: 0, tv_nsec: 50_000_000 }; // 50ms
    let ret = unsafe { trona_posix::posix_nanosleep(&raw const req, core::ptr::null_mut()) };
    if ret != 0 {
        puts(b"  nanosleep failed\n");
        return false;
    }

    unsafe { trona_posix::posix_clock_gettime(0, &raw mut after) };

    let ns_before = before.tv_sec * 1_000_000_000 + before.tv_nsec;
    let ns_after = after.tv_sec * 1_000_000_000 + after.tv_nsec;
    let elapsed = ns_after - ns_before;

    puts(b"  slept for ");
    serial::serial_dec(elapsed / 1_000_000);
    puts(b" ms\n");

    // Should have slept at least 40ms (allow 10ms tolerance)
    if elapsed < 40_000_000 {
        puts(b"  sleep too short\n");
        return false;
    }

    true
}

pub fn run() -> bool {
    puts(b"  [test_time] clock monotonicity...\n");
    if !test_clock_monotonic() { return false; }

    puts(b"  [test_time] nanosleep 50ms...\n");
    if !test_nanosleep() { return false; }

    true
}
