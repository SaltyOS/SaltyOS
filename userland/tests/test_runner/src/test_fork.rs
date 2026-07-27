//! Fork/waitpid tests
//! Ported from userland/test_fork/main.c
//! SPDX-License-Identifier: GPL-2.0-only

use trona_posix::*;
use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf;

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
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_FORK] Test 1: getpid = ");
        lb.dec(my_pid as u64);
        lb.str(b"\n");
        lb.flush();
    }
    if my_pid <= 0 {
        puts(b"[TEST_FORK] FAIL: getpid\n");
        return false;
    }
    puts(b"[TEST_FORK] Test 1: PASS\n");

    // Test 2: getppid
    let my_ppid = unsafe { trona_posix::posix_getppid() };
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_FORK] Test 2: getppid = ");
        lb.dec(my_ppid as u64);
        lb.str(b"\n");
        lb.flush();
    }
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

    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_FORK] Parent: child PID = ");
        lb.dec(pid as u64);
        lb.str(b"\n");
        lb.flush();
    }

    let mut status: i32 = 0;
    let ret = unsafe { trona_posix::posix_waitpid(pid, &raw mut status) };
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_FORK] Parent: waitpid returned ");
        lb.dec(ret as u64);
        lb.str(b", status = ");
        lb.dec(status as u64);
        lb.str(b"\n");
        lb.flush();
    }

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

    // Test 5: waitpid(-1) drains N unreaped children exactly once each.
    // Exercises the parent-owned zombie FIFO on the supervisor side: each
    // child exits before the parent reaps, so all N ExitRecords must be
    // queued and then drained one by one. N=64 also exercises the
    // post-redesign supervisor cap allocator: the historical
    // `internal_slots::alloc_child_base` flat layout would have run out
    // around child 31 (4096 slots / 128-slot stride), so this sweep
    // doubles past that threshold to cover the runtime SpawnLease /
    // ProcessLease lifecycle.
    puts(b"[TEST_FORK] Test 5: waitpid(-1) drain over N=64 queued zombies\n");
    const N: usize = 64;
    let mut child_pids: [i32; N] = [0; N];
    for i in 0..N {
        let cp = trona_posix::posix_fork();
        if cp < 0 {
            puts(b"[TEST_FORK] FAIL: fork in N-loop\n");
            return false;
        }
        if cp == 0 {
            unsafe { trona_posix::posix_exit(20 + i as i32) };
        }
        child_pids[i] = cp;
    }

    let mut reaped = [false; N];
    let mut remaining = N;
    while remaining > 0 {
        let mut st: i32 = 0;
        let r = unsafe { trona_posix::posix_waitpid(-1, &raw mut st) };
        if r <= 0 {
            puts(b"[TEST_FORK] FAIL: waitpid(-1) returned <= 0\n");
            return false;
        }
        let mut found: Option<usize> = None;
        let mut k = 0;
        while k < N {
            if child_pids[k] == r {
                found = Some(k);
                break;
            }
            k += 1;
        }
        let Some(idx) = found else {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_FORK] FAIL: waitpid(-1) returned unknown pid ");
            lb.dec(r as u64);
            lb.str(b"\n");
            lb.flush();
            return false;
        };
        if reaped[idx] {
            puts(b"[TEST_FORK] FAIL: same pid reaped twice\n");
            return false;
        }
        if !wifexited(st) || wexitstatus(st) != 20 + idx as i32 {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_FORK] FAIL: Test 5 wrong status pid=");
            lb.dec(r as u64);
            lb.str(b" status=");
            lb.dec(st as u64);
            lb.str(b"\n");
            lb.flush();
            return false;
        }
        reaped[idx] = true;
        remaining -= 1;
    }
    puts(b"[TEST_FORK] Test 5: PASS\n");

    // Test 6: waitpid(middle_pid) unlinks a specific entry from the FIFO
    // while leaving the other N-1 zombies queued, and a subsequent
    // waitpid(-1) drain must retrieve each of the others exactly once.
    puts(b"[TEST_FORK] Test 6: middle-pid unlink\n");
    const M: usize = 5;
    let mut m_pids: [i32; M] = [0; M];
    for i in 0..M {
        let cp = trona_posix::posix_fork();
        if cp < 0 {
            puts(b"[TEST_FORK] FAIL: Test 6 fork\n");
            return false;
        }
        if cp == 0 {
            unsafe { trona_posix::posix_exit(30 + i as i32) };
        }
        m_pids[i] = cp;
    }

    let middle_idx = M / 2;
    let middle_pid = m_pids[middle_idx];
    let mut mst: i32 = 0;
    let r = unsafe { trona_posix::posix_waitpid(middle_pid, &raw mut mst) };
    if r != middle_pid || !wifexited(mst) || wexitstatus(mst) != 30 + middle_idx as i32 {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_FORK] FAIL: waitpid(middle) r=");
        lb.dec(r as u64);
        lb.str(b" status=");
        lb.dec(mst as u64);
        lb.str(b"\n");
        lb.flush();
        return false;
    }

    // Drain the remaining M-1 via waitpid(-1); each must be one of the
    // non-middle children and each exactly once.
    let mut m_reaped = [false; M];
    m_reaped[middle_idx] = true;
    let mut m_remaining = M - 1;
    while m_remaining > 0 {
        let mut st: i32 = 0;
        let r = unsafe { trona_posix::posix_waitpid(-1, &raw mut st) };
        if r <= 0 {
            puts(b"[TEST_FORK] FAIL: Test 6 drain waitpid <= 0\n");
            return false;
        }
        let mut found: Option<usize> = None;
        let mut k = 0;
        while k < M {
            if m_pids[k] == r {
                found = Some(k);
                break;
            }
            k += 1;
        }
        let Some(idx) = found else {
            puts(b"[TEST_FORK] FAIL: Test 6 drain returned unknown pid\n");
            return false;
        };
        if m_reaped[idx] {
            puts(b"[TEST_FORK] FAIL: Test 6 drain duplicate reap\n");
            return false;
        }
        m_reaped[idx] = true;
        m_remaining -= 1;
    }
    puts(b"[TEST_FORK] Test 6: PASS\n");

    // Test 7: multi-generation cleanup. A parent forks grandchildren,
    // lets them exit, and then exits itself *without* reaping them.
    // The grandparent (this test) then reaps the parent. Procmgr's
    // `cleanup_proc_resources` queue-drain must recycle the queued
    // grandchildren in the same dispatch so the proctab does not leak
    // — we verify liveness via a canary fork after the reap.
    puts(b"[TEST_FORK] Test 7: multi-generation cleanup drain\n");
    let par = trona_posix::posix_fork();
    if par < 0 {
        puts(b"[TEST_FORK] FAIL: Test 7 parent fork\n");
        return false;
    }
    if par == 0 {
        let mut i = 0;
        while i < 3 {
            let gc = trona_posix::posix_fork();
            if gc < 0 {
                unsafe { trona_posix::posix_exit(1) };
            }
            if gc == 0 {
                unsafe { trona_posix::posix_exit(40 + i) };
            }
            i += 1;
        }
        // Do NOT waitpid the grandchildren — leave them queued.
        unsafe { trona_posix::posix_exit(99) };
    }
    let mut pst: i32 = 0;
    let r = unsafe { trona_posix::posix_waitpid(par, &raw mut pst) };
    if r != par || !wifexited(pst) || wexitstatus(pst) != 99 {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_FORK] FAIL: Test 7 parent wait r=");
        lb.dec(r as u64);
        lb.str(b" status=");
        lb.dec(pst as u64);
        lb.str(b"\n");
        lb.flush();
        return false;
    }

    let canary = trona_posix::posix_fork();
    if canary < 0 {
        puts(b"[TEST_FORK] FAIL: Test 7 canary fork\n");
        return false;
    }
    if canary == 0 {
        unsafe { trona_posix::posix_exit(55) };
    }
    let mut cst: i32 = 0;
    let r2 = unsafe { trona_posix::posix_waitpid(canary, &raw mut cst) };
    if r2 != canary || !wifexited(cst) || wexitstatus(cst) != 55 {
        puts(b"[TEST_FORK] FAIL: Test 7 canary wait\n");
        return false;
    }
    puts(b"[TEST_FORK] Test 7: PASS\n");

    puts(b"[TEST_FORK] All tests passed!\n");
    true
}
