//! SaltyOS Test Runner
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Unified test runner that consolidates all userland tests into a single
//! dynamically-linked binary. Spawned by init via procmgr.
//! Exit code 42 = all tests passed, 1 = failure.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

mod test_cap_table;
mod test_casefold;
mod test_cspace_expand;
mod test_dns;
mod test_epoll;
mod test_exec;
mod test_fork;
mod test_fs;
mod test_hello;
mod test_memory_accounting;
mod test_mmap;
#[cfg(target_arch = "aarch64")]
mod test_neon;
mod test_pipe;
mod test_pthread;
mod test_saltyfs;
mod test_sched_race;
mod test_signal;
mod test_socket;
#[cfg(target_arch = "x86_64")]
mod test_sse;
mod test_terminal;
mod test_time;
mod test_vfs_stress_mt;
mod test_win32_console_stress;

use trona_posix::*;
use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn monotonic_now_ns() -> u64 {
    trona_kernel::syscall::clock_read_monotonic(trona_runtime::client::caps::clock_cap().addr())
}

unsafe fn waitpid_deadline_retry_eintr(pid: i32, status: *mut i32, deadline_ns: u64) -> i32 {
    unsafe {
        loop {
            let waited = trona_posix::posix_waitpid_deadline_ns(pid, status, 0, deadline_ns);
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

// Extra margin past the parent's SIGKILL delivery before we treat a
// wedged waitpid as a procmgr-exit regression and exit(2) to surface it.
// Any legitimate timeout flow reaps the test child well within this
// envelope; exceeding it means procmgr is not making a Zombie visible.
const STALL_DETECTION_EXTRA_NS: u64 = 5_000_000_000; // 5s

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

    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_RUNNER] parent forked pid=");
        lb.dec(pid as u64);
        lb.str(b" entering waitpid\n");
        lb.flush();
    }
    let mut status = 0i32;
    let timeout_deadline_ns = monotonic_now_ns().saturating_add(PER_TEST_TIMEOUT_NS);
    let mut forced_kill = false;
    let mut waited =
        unsafe { waitpid_deadline_retry_eintr(pid, &raw mut status, timeout_deadline_ns) };
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_RUNNER] waitpid returned waited=");
        lb.dec(waited as u64);
        lb.str(b" status=");
        lb.hex(status as u64);
        lb.str(b"\n");
        lb.flush();
    }
    if waited == -110 {
        let _ = unsafe { trona_posix::posix_kill(pid, trona_posix::SIGKILL) };
        forced_kill = true;
        let reap_deadline_ns = monotonic_now_ns().saturating_add(STALL_DETECTION_EXTRA_NS);
        waited = unsafe { waitpid_deadline_retry_eintr(pid, &raw mut status, reap_deadline_ns) };
        if waited == -110 {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_RUNNER] FATAL: waitpid stalled pid=");
            lb.dec(pid as u64);
            lb.str(b" after timeout SIGKILL; procmgr exit regression\n");
            lb.flush();
            unsafe { trona_posix::posix_exit(2) };
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
        if sig == trona_posix::SIGKILL && forced_kill {
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

    let base_tests: [(&[u8], fn() -> bool); 21] = [
        (b"test_cap_table", test_cap_table::run),
        (b"test_cspace_expand", test_cspace_expand::run),
        (b"test_hello", test_hello::run),
        (b"test_fs", test_fs::run),
        (b"test_casefold", test_casefold::run),
        (b"test_mmap", test_mmap::run),
        (b"test_memory_accounting", test_memory_accounting::run),
        (b"test_fork", test_fork::run),
        (b"test_exec", test_exec::run),
        (b"test_signal", test_signal::run),
        (b"test_socket", test_socket::run),
        (b"test_pipe", test_pipe::run),
        (b"test_time", test_time::run),
        (b"test_terminal", test_terminal::run),
        (b"test_epoll", test_epoll::run),
        (b"test_pthread", test_pthread::run),
        (b"test_sched_race", test_sched_race::run),
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
