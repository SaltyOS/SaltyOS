//! SaltyOS Test Runner
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Unified test runner that consolidates all userland tests into a single
//! dynamically-linked binary. Spawned by init via procmgr.
//! Exit code 42 = all tests passed, 1 = failure.

#![no_std]
#![no_main]

extern crate besalt;

mod test_hello;
mod test_fs;
mod test_mmap;
mod test_fork;
mod test_signal;
mod test_socket;
mod test_pipe;
mod test_time;
mod test_terminal;
mod test_epoll;
mod test_pthread;
mod test_saltyfs;
mod test_dns;
#[cfg(target_arch = "x86_64")]
mod test_sse;
#[cfg(target_arch = "aarch64")]
mod test_neon;

use besalt::consts::*;
use besalt::posix;
use besalt::serial;
use besalt::serial::LineBuf;

const CAP_READINESS_NTFN: u64 = 14;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn signal_ready() {
    let _ = besalt::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    puts(b"[TEST_RUNNER] SaltyOS Test Runner starting\n");
    signal_ready();

    let base_tests: [(&[u8], fn() -> bool); 13] = [
        (b"test_hello", test_hello::run),
        (b"test_fs", test_fs::run),
        (b"test_mmap", test_mmap::run),
        (b"test_fork", test_fork::run),
        (b"test_signal", test_signal::run),
        (b"test_socket", test_socket::run),
        (b"test_pipe", test_pipe::run),
        (b"test_time", test_time::run),
        (b"test_terminal", test_terminal::run),
        (b"test_epoll", test_epoll::run),
        (b"test_pthread", test_pthread::run),
        (b"test_saltyfs", test_saltyfs::run),
        (b"test_dns", test_dns::run),
    ];
    #[cfg(target_arch = "x86_64")]
    let arch_tests: [(&[u8], fn() -> bool); 1] = [
        (b"test_sse", test_sse::run),
    ];
    #[cfg(target_arch = "aarch64")]
    let arch_tests: [(&[u8], fn() -> bool); 1] = [
        (b"test_neon", test_neon::run),
    ];
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch_tests: [(&[u8], fn() -> bool); 0] = [];

    let mut passed = 0u32;
    let mut failed = 0u32;

    fn run_suite(
        tests: &[(&[u8], fn() -> bool)],
        passed: &mut u32,
        failed: &mut u32,
    ) {
        for (name, test_fn) in tests {
            { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] Running "); lb.str(name); lb.str(b"...\n"); lb.flush(); }
            let result = test_fn();
            if result {
                { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] "); lb.str(name); lb.str(b" ... PASS\n"); lb.flush(); }
                *passed += 1;
            } else {
                { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] "); lb.str(name); lb.str(b" ... FAIL\n"); lb.flush(); }
                *failed += 1;
            }
        }
    }

    run_suite(&base_tests, &mut passed, &mut failed);
    run_suite(&arch_tests, &mut passed, &mut failed);

    { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] Results: "); lb.dec(passed as u64); lb.str(b" passed, "); lb.dec(failed as u64); lb.str(b" failed\n"); lb.flush(); }

    if failed == 0 {
        puts(b"[TEST_RUNNER] ALL TESTS PASSED\n");
        unsafe { posix::posix_exit(42) };
    } else {
        puts(b"[TEST_RUNNER] TESTS FAILED\n");
        unsafe { posix::posix_exit(1) };
    }
}
