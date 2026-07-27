//! POSIX signal tests (9 tests)
//! Ported from userland/test_signal/main.c
//! SPDX-License-Identifier: GPL-2.0-only

use trona_posix::consts::*;
use trona_posix::signals;
use trona_posix::*;
use trona_runtime::debug::serial;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

static mut G_SIGUSR1_COUNT: i32 = 0;
static mut G_SIGCHLD_COUNT: i32 = 0;

unsafe extern "C" fn sigusr1_handler(_sig: i32) {
    unsafe {
        G_SIGUSR1_COUNT += 1;
    }
    puts(b"[TEST_SIGNAL] SIGUSR1 handler called\n");
}

unsafe extern "C" fn sigchld_handler(_sig: i32) {
    unsafe {
        G_SIGCHLD_COUNT += 1;
    }
    puts(b"[TEST_SIGNAL] SIGCHLD received\n");
}

pub fn run() -> bool {
    puts(b"[TEST_SIGNAL] Starting signal tests\n");

    let restore_sigusr1: usize;
    let restore_sigusr2: usize;
    let restore_sigchld: usize;

    let my_pid = unsafe { trona_posix::posix_getpid() };
    if my_pid <= 0 {
        puts(b"[TEST_SIGNAL] FAIL: getpid\n");
        return false;
    }

    // Test 1: SIGUSR1 handler
    puts(b"[TEST_SIGNAL] Test 1: SIGUSR1 handler\n");
    unsafe { G_SIGUSR1_COUNT = 0 };
    let old = unsafe { signals::posix_signal(SIGUSR1, sigusr1_handler as *const () as usize) };
    if old == usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: posix_signal returned SIG_ERR\n");
        return false;
    }
    restore_sigusr1 = old;

    if unsafe { trona_posix::posix_kill(my_pid, SIGUSR1) } != 0 {
        puts(b"[TEST_SIGNAL] FAIL: posix_kill self SIGUSR1\n");
        return false;
    }

    trona_kernel::syscall::yield_now();

    // The handler may have already been called by the kernel's signal
    // frame injection (EINTR path) during the kill IPC itself. Poll for
    // any remaining pending signals just in case.
    unsafe { signals::posix_sigcheck() };
    if unsafe { G_SIGUSR1_COUNT } == 0 {
        puts(b"[TEST_SIGNAL] FAIL: SIGUSR1 handler not called\n");
        return false;
    }
    puts(b"[TEST_SIGNAL] Test 1: PASS\n");

    // Test 2: SIG_IGN on SIGUSR2
    puts(b"[TEST_SIGNAL] Test 2: SIGUSR2 SIG_IGN\n");
    let old = unsafe { signals::posix_signal(SIGUSR2, SIG_IGN) };
    if old == usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: posix_signal SIGUSR2 SIG_IGN\n");
        return false;
    }
    restore_sigusr2 = old;

    if unsafe { trona_posix::posix_kill(my_pid, SIGUSR2) } != 0 {
        puts(b"[TEST_SIGNAL] FAIL: posix_kill self SIGUSR2\n");
        return false;
    }

    trona_kernel::syscall::yield_now();
    unsafe { signals::posix_sigcheck() };
    puts(b"[TEST_SIGNAL] Test 2: PASS\n");

    // Test 3: SIGTERM default kills child
    puts(b"[TEST_SIGNAL] Test 3: SIGTERM default kills child\n");
    let child_pid = trona_posix::posix_fork();
    if child_pid < 0 {
        puts(b"[TEST_SIGNAL] FAIL: fork for test 3\n");
        return false;
    }

    if child_pid == 0 {
        loop {
            trona_kernel::syscall::yield_now();
        }
    }

    trona_kernel::syscall::yield_now();
    trona_kernel::syscall::yield_now();

    if unsafe { trona_posix::posix_kill(child_pid, SIGTERM) } != 0 {
        puts(b"[TEST_SIGNAL] FAIL: posix_kill child SIGTERM\n");
        return false;
    }

    let mut status: i32 = 0;
    let ret = unsafe { trona_posix::posix_waitpid(child_pid, &raw mut status) };
    if ret != child_pid {
        puts(b"[TEST_SIGNAL] FAIL: waitpid returned wrong pid\n");
        return false;
    }

    if !wifsignaled(status) || wtermsig(status) != SIGTERM {
        puts(b"[TEST_SIGNAL] FAIL: expected WIFSIGNALED+SIGTERM\n");
        return false;
    }
    puts(b"[TEST_SIGNAL] Test 3: PASS\n");

    // Test 4: SIGCHLD from child exit
    puts(b"[TEST_SIGNAL] Test 4: SIGCHLD from child exit\n");
    unsafe { G_SIGCHLD_COUNT = 0 };
    let old = unsafe { signals::posix_signal(SIGCHLD, sigchld_handler as *const () as usize) };
    if old == usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: posix_signal SIGCHLD\n");
        return false;
    }
    restore_sigchld = old;

    let child2_pid = trona_posix::posix_fork();
    if child2_pid < 0 {
        puts(b"[TEST_SIGNAL] FAIL: fork for test 4\n");
        return false;
    }

    if child2_pid == 0 {
        unsafe { trona_posix::posix_exit(0) };
    }

    let mut status4: i32 = 0;
    unsafe { trona_posix::posix_waitpid(child2_pid, &raw mut status4) };
    unsafe { signals::posix_sigcheck() };

    if unsafe { G_SIGCHLD_COUNT } == 0 {
        puts(b"[TEST_SIGNAL] FAIL: SIGCHLD handler not called\n");
        return false;
    }
    puts(b"[TEST_SIGNAL] Test 4: PASS\n");

    // Test 5: SIGKILL cannot be caught
    puts(b"[TEST_SIGNAL] Test 5: SIGKILL uncatchable\n");
    let old = unsafe { signals::posix_signal(SIGKILL, sigusr1_handler as *const () as usize) };
    if old != usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: posix_signal(SIGKILL) should return SIG_ERR\n");
        return false;
    }
    puts(b"[TEST_SIGNAL] Test 5: PASS\n");

    // Test 6: SIGCHLD fires when signal-killed child has waiting parent
    puts(b"[TEST_SIGNAL] Test 6: SIGCHLD on signal-killed child\n");
    unsafe { G_SIGCHLD_COUNT = 0 };

    let child6_pid = trona_posix::posix_fork();
    if child6_pid < 0 {
        puts(b"[TEST_SIGNAL] FAIL: fork for test 6\n");
        return false;
    }

    if child6_pid == 0 {
        loop {
            trona_kernel::syscall::yield_now();
        }
    }

    trona_kernel::syscall::yield_now();
    trona_kernel::syscall::yield_now();

    if unsafe { trona_posix::posix_kill(child6_pid, SIGTERM) } != 0 {
        puts(b"[TEST_SIGNAL] FAIL: posix_kill child6 SIGTERM\n");
        return false;
    }

    let mut status6: i32 = 0;
    let ret6 = unsafe { trona_posix::posix_waitpid(child6_pid, &raw mut status6) };
    if ret6 != child6_pid {
        puts(b"[TEST_SIGNAL] FAIL: waitpid test 6\n");
        return false;
    }

    unsafe { signals::posix_sigcheck() };

    if unsafe { G_SIGCHLD_COUNT } == 0 {
        puts(b"[TEST_SIGNAL] FAIL: SIGCHLD not delivered for signal-killed child\n");
        return false;
    }
    puts(b"[TEST_SIGNAL] Test 6: PASS\n");

    // Test 7: SIGSTOP cannot be caught
    puts(b"[TEST_SIGNAL] Test 7: SIGSTOP uncatchable\n");
    let old = unsafe { signals::posix_signal(SIGSTOP, sigusr1_handler as *const () as usize) };
    if old != usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: posix_signal(SIGSTOP) should return SIG_ERR\n");
        return false;
    }
    puts(b"[TEST_SIGNAL] Test 7: PASS\n");

    // Test 8: SIGSTOP suspends child, SIGCONT resumes
    puts(b"[TEST_SIGNAL] Test 8: SIGSTOP/SIGCONT\n");
    let child8_pid = trona_posix::posix_fork();
    if child8_pid < 0 {
        puts(b"[TEST_SIGNAL] FAIL: fork for test 8\n");
        return false;
    }

    if child8_pid == 0 {
        loop {
            trona_kernel::syscall::yield_now();
        }
    }

    trona_kernel::syscall::yield_now();
    trona_kernel::syscall::yield_now();

    // Stop the child
    if unsafe { trona_posix::posix_kill(child8_pid, SIGSTOP) } != 0 {
        puts(b"[TEST_SIGNAL] FAIL: posix_kill child8 SIGSTOP\n");
        return false;
    }

    // Verify child is stopped via WUNTRACED
    let mut status8: i32 = 0;
    let ret8 =
        unsafe { trona_posix::posix_waitpid3(child8_pid, &raw mut status8, WNOHANG as i32 | 2) }; // 2 = WUNTRACED
    if ret8 != child8_pid || !wifstopped(status8) {
        puts(b"[TEST_SIGNAL] FAIL: child not reported as stopped\n");
        return false;
    }
    if wstopsig(status8) != SIGSTOP {
        puts(b"[TEST_SIGNAL] FAIL: WSTOPSIG != SIGSTOP\n");
        return false;
    }

    // Resume the child
    if unsafe { trona_posix::posix_kill(child8_pid, SIGCONT) } != 0 {
        puts(b"[TEST_SIGNAL] FAIL: posix_kill child8 SIGCONT\n");
        return false;
    }

    trona_kernel::syscall::yield_now();

    // Kill the resumed child
    if unsafe { trona_posix::posix_kill(child8_pid, SIGKILL) } != 0 {
        puts(b"[TEST_SIGNAL] FAIL: posix_kill child8 SIGKILL\n");
        return false;
    }

    let mut status8b: i32 = 0;
    let ret8b = unsafe { trona_posix::posix_waitpid(child8_pid, &raw mut status8b) };
    if ret8b != child8_pid || !wifsignaled(status8b) || wtermsig(status8b) != SIGKILL {
        puts(b"[TEST_SIGNAL] FAIL: resumed child not killed correctly\n");
        return false;
    }
    puts(b"[TEST_SIGNAL] Test 8: PASS\n");

    // Test 9: posix_signal(SIGUSR1, SIG_ERR) returns SIG_ERR
    puts(b"[TEST_SIGNAL] Test 9: SIG_ERR rejected\n");
    let old = unsafe { signals::posix_signal(SIGUSR1, usize::MAX) };
    if old != usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: posix_signal(SIGUSR1, SIG_ERR) should return SIG_ERR\n");
        return false;
    }
    puts(b"[TEST_SIGNAL] Test 9: PASS\n");

    if unsafe { signals::posix_signal(SIGUSR1, restore_sigusr1) } == usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: restore SIGUSR1\n");
        return false;
    }
    if unsafe { signals::posix_signal(SIGUSR2, restore_sigusr2) } == usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: restore SIGUSR2\n");
        return false;
    }
    if unsafe { signals::posix_signal(SIGCHLD, restore_sigchld) } == usize::MAX {
        puts(b"[TEST_SIGNAL] FAIL: restore SIGCHLD\n");
        return false;
    }

    puts(b"[TEST_SIGNAL] All signal tests passed!\n");
    true
}
