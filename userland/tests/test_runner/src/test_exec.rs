//! Path-based `execve` tests — positive (load an ELF by its vfs path)
//! and negative (a missing path fails cleanly without replacing the
//! caller's image).
//! SPDX-License-Identifier: GPL-2.0-only

use trona_posix::*;
use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

// A real dynamically-linked ELF that ships in the rootfs at a stable
// path; its `main` returns 0. Init resolves exec paths through vfs only,
// so loading it exercises the full vfs open/read + ELF interpreter DSO
// closure path, not just the initrd bootstrap.
const EXEC_ELF_PATH: &[u8] = b"/bin/vfs_stress_elf\0";
// A path that exists nowhere — resolution must fail with no image swap.
const EXEC_MISSING_PATH: &[u8] = b"/bin/no_such_test_binary_zzz\0";

// Child fell through to `exit` because `execve` returned instead of
// replacing the image (the only way `execve` returns is on failure).
const SENTINEL_EXECVE_RETURNED: i32 = 123;
const SENTINEL_ELF_EXECVE_FAILED: i32 = 124;

pub fn run() -> bool {
    puts(b"[TEST_EXEC] Starting execve tests\n");

    // Test 1: fork + execve a real ELF by vfs path. The child is replaced
    // by /bin/vfs_stress_elf, whose main() returns 0; a 0 exit therefore
    // proves the image was resolved through vfs, loaded, and run. If
    // execve fails the child falls through to a non-zero sentinel.
    puts(b"[TEST_EXEC] Test 1: execve ELF via vfs path\n");
    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"[TEST_EXEC] FAIL: fork (elf)\n");
        return false;
    }
    if pid == 0 {
        unsafe {
            let argv = [EXEC_ELF_PATH.as_ptr(), core::ptr::null()];
            trona_posix::proc::posix_execve(
                EXEC_ELF_PATH.as_ptr(),
                argv.as_ptr(),
                core::ptr::null(),
            );
            trona_posix::posix_exit(SENTINEL_ELF_EXECVE_FAILED);
        }
    }
    let mut status: i32 = 0;
    let ret = unsafe { trona_posix::posix_waitpid(pid, &raw mut status) };
    if ret != pid || !wifexited(status) || wexitstatus(status) != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_EXEC] FAIL: ELF execve child ret=");
        lb.dec(ret as u64);
        lb.str(b" status=");
        lb.dec(status as u64);
        lb.str(b"\n");
        lb.flush();
        return false;
    }
    puts(b"[TEST_EXEC] Test 1: PASS\n");

    // Test 2: execve of a non-existent path must fail cleanly and leave
    // the caller's image intact. The original path-based-exec bug misread
    // the path length as a manifest service index and mis-exec'd an
    // unrelated server; here the child must instead return from execve and
    // reach the sentinel exit. Reaping exactly that sentinel proves execve
    // failed without replacing the image.
    puts(b"[TEST_EXEC] Test 2: execve of missing path fails cleanly\n");
    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"[TEST_EXEC] FAIL: fork (missing)\n");
        return false;
    }
    if pid == 0 {
        unsafe {
            let argv = [EXEC_MISSING_PATH.as_ptr(), core::ptr::null()];
            trona_posix::proc::posix_execve(
                EXEC_MISSING_PATH.as_ptr(),
                argv.as_ptr(),
                core::ptr::null(),
            );
            trona_posix::posix_exit(SENTINEL_EXECVE_RETURNED);
        }
    }
    let mut status: i32 = 0;
    let ret = unsafe { trona_posix::posix_waitpid(pid, &raw mut status) };
    if ret != pid || !wifexited(status) || wexitstatus(status) != SENTINEL_EXECVE_RETURNED {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_EXEC] FAIL: missing-path execve child ret=");
        lb.dec(ret as u64);
        lb.str(b" status=");
        lb.dec(status as u64);
        lb.str(b"\n");
        lb.flush();
        return false;
    }
    puts(b"[TEST_EXEC] Test 2: PASS\n");

    puts(b"[TEST_EXEC] All tests passed!\n");
    true
}
