//! Concurrent Win32 console/csrss stress test.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::serial;
use trona_posix::*;

const CONSOLE_STRESS_PATH: &[u8] = b"/bin/console_stress_pe\0";
const CONSOLE_CHILDREN: usize = 4;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
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

pub fn run() -> bool {
    puts(b"[TEST_WIN32_CONSOLE_STRESS] Starting Win32 console stress test\n");

    let mut pids = [0i32; CONSOLE_CHILDREN];
    for pid_slot in &mut pids {
        let pid = trona_posix::posix_fork();
        if pid < 0 {
            puts(b"[TEST_WIN32_CONSOLE_STRESS] FAIL: fork\n");
            return false;
        }

        if pid == 0 {
            unsafe {
                let argv = [CONSOLE_STRESS_PATH.as_ptr(), core::ptr::null()];
                trona_posix::proc::posix_execve(
                    CONSOLE_STRESS_PATH.as_ptr(),
                    argv.as_ptr(),
                    core::ptr::null(),
                );
                trona_posix::posix_exit(127);
            }
        }

        *pid_slot = pid;
    }

    for &pid in &pids {
        let mut status = 0i32;
        let waited = unsafe { waitpid_retry_eintr(pid, &raw mut status) };
        if waited != pid {
            puts(b"[TEST_WIN32_CONSOLE_STRESS] FAIL: waitpid mismatch\n");
            return false;
        }
        if !wifexited(status) || wexitstatus(status) != 0 {
            puts(b"[TEST_WIN32_CONSOLE_STRESS] FAIL: console_stress_pe child exit\n");
            return false;
        }
    }

    puts(b"[TEST_WIN32_CONSOLE_STRESS] PASS\n");
    true
}
