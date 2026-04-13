//! SaltyOS Test Runner
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Unified test runner that consolidates all userland tests into a single
//! dynamically-linked binary. Spawned by init via procmgr.
//! Exit code 42 = all tests passed, 1 = failure.

#![no_std]
#![no_main]

extern crate trona;
extern crate trona_posix;

mod test_dns;
mod test_epoll;
mod test_fork;
mod test_fs;
mod test_hello;
mod test_mmap;
#[cfg(target_arch = "aarch64")]
mod test_neon;
mod test_pipe;
mod test_pthread;
mod test_saltyfs;
mod test_signal;
mod test_socket;
#[cfg(target_arch = "x86_64")]
mod test_sse;
mod test_terminal;
mod test_time;
mod test_vfs_stress_mt;
mod test_win32_console_stress;

use trona::consts::kernel::*;
use trona::serial;
use trona::serial::LineBuf;
use trona_posix::*;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, trona::caps::readiness_ntfn(), 1, 0, 0, 0, 0);
}

unsafe fn waitpid_retry_eintr(pid: i32, status: *mut i32) -> i32 {
    unsafe {
        loop {
            let waited = trona_posix::posix_waitpid(pid, status);
            if waited == -4 {
                continue;
            }
            return waited;
        }
    }
}

// Maximum wall-clock time allowed for a single test child. Covers the
// heavy stress tests (vfs_stress_mt with PE exec swarm) with headroom.
const PER_TEST_TIMEOUT_NS: u64 = 180_000_000_000; // 180s

/// Spawn a watchdog child that kills `test_pid` after PER_TEST_TIMEOUT_NS.
/// Returns the watchdog pid, or a negative value on fork failure.
fn spawn_watchdog(test_pid: i32) -> i32 {
    let wd_pid = trona_posix::posix_fork();
    if wd_pid < 0 {
        return wd_pid;
    }
    if wd_pid == 0 {
        let req = trona_posix::Timespec {
            tv_sec: PER_TEST_TIMEOUT_NS / 1_000_000_000,
            tv_nsec: PER_TEST_TIMEOUT_NS % 1_000_000_000,
        };
        unsafe {
            let _ = trona_posix::posix_nanosleep(&raw const req, core::ptr::null_mut());
            let _ = trona_posix::posix_kill(test_pid, trona_posix::SIGKILL);
            trona_posix::posix_exit(0);
        }
    }
    wd_pid
}

fn run_test_isolated(name: &[u8], test_fn: fn() -> bool) -> bool {
    let pid = trona_posix::posix_fork();
    if pid < 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_RUNNER] ");
        lb.str(name);
        lb.str(b" ... FAIL (fork failed)\n");
        lb.flush();
        return false;
    }

    if pid == 0 {
        let code = if test_fn() { 0 } else { 1 };
        unsafe { trona_posix::posix_exit(code) };
    }

    // Fork the watchdog after we know the test child's pid.
    let watchdog_pid = spawn_watchdog(pid);
    if watchdog_pid < 0 {
        // Fall through without a watchdog — the test may hang, but the
        // alternative (abandoning the test entirely) is worse.
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_RUNNER] ");
        lb.str(name);
        lb.str(b" WARN: watchdog fork failed; running without timeout\n");
        lb.flush();
    }

    let mut status = 0i32;
    let waited = unsafe { waitpid_retry_eintr(pid, &raw mut status) };

    // Reap the watchdog regardless of which child exited first.
    if watchdog_pid > 0 {
        unsafe {
            let _ = trona_posix::posix_kill(watchdog_pid, trona_posix::SIGKILL);
            let mut wd_status = 0i32;
            let _ = waitpid_retry_eintr(watchdog_pid, &raw mut wd_status);
        }
    }

    if waited != pid {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_RUNNER] ");
        lb.str(name);
        lb.str(b" ... FAIL (waitpid mismatch)\n");
        lb.flush();
        return false;
    }

    if wifexited(status) {
        return wexitstatus(status) == 0;
    }

    if wifsignaled(status) {
        let sig = wtermsig(status);
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_RUNNER] ");
        lb.str(name);
        if sig == trona_posix::SIGKILL && watchdog_pid > 0 {
            lb.str(b" ... FAIL (timeout after ");
            lb.dec(PER_TEST_TIMEOUT_NS / 1_000_000_000);
            lb.str(b"s)\n");
        } else {
            lb.str(b" child killed by signal ");
            lb.dec(sig as u64);
            lb.str(b"\n");
        }
        lb.flush();
    }

    false
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    puts(b"[TEST_RUNNER] SaltyOS Test Runner starting\n");
    signal_ready();

    let base_tests: [(&[u8], fn() -> bool); 15] = [
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
        (b"test_vfs_stress_mt", test_vfs_stress_mt::run),
        (b"test_win32_console_stress", test_win32_console_stress::run),
        (b"test_saltyfs", test_saltyfs::run),
        (b"test_dns", test_dns::run),
    ];
    #[cfg(target_arch = "x86_64")]
    let arch_tests: [(&[u8], fn() -> bool); 1] = [(b"test_sse", test_sse::run)];
    #[cfg(target_arch = "aarch64")]
    let arch_tests: [(&[u8], fn() -> bool); 1] = [(b"test_neon", test_neon::run)];
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch_tests: [(&[u8], fn() -> bool); 0] = [];

    let mut passed = 0u32;
    let mut failed = 0u32;

    fn run_suite(tests: &[(&[u8], fn() -> bool)], passed: &mut u32, failed: &mut u32) {
        for (name, test_fn) in tests {
            {
                let mut lb = LineBuf::new();
                lb.str(b"[TEST_RUNNER] Running ");
                lb.str(name);
                lb.str(b"...\n");
                lb.flush();
            }
            let result = run_test_isolated(name, *test_fn);
            if result {
                {
                    let mut lb = LineBuf::new();
                    lb.str(b"[TEST_RUNNER] ");
                    lb.str(name);
                    lb.str(b" ... PASS\n");
                    lb.flush();
                }
                *passed += 1;
            } else {
                {
                    let mut lb = LineBuf::new();
                    lb.str(b"[TEST_RUNNER] ");
                    lb.str(name);
                    lb.str(b" ... FAIL\n");
                    lb.flush();
                }
                *failed += 1;
            }
        }
    }

    run_suite(&base_tests, &mut passed, &mut failed);
    run_suite(&arch_tests, &mut passed, &mut failed);

    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_RUNNER] Results: ");
        lb.dec(passed as u64);
        lb.str(b" passed, ");
        lb.dec(failed as u64);
        lb.str(b" failed\n");
        lb.flush();
    }

    if failed == 0 {
        puts(b"[TEST_RUNNER] ALL TESTS PASSED\n");
        unsafe { trona_posix::posix_exit(42) };
    } else {
        puts(b"[TEST_RUNNER] TESTS FAILED\n");
        unsafe { trona_posix::posix_exit(1) };
    }
}
