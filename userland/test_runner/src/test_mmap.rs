//! Memory management tests - exercises brk/sbrk/mmap/munmap
//! Ported from userland/mmap_test/main.c
//! SPDX-License-Identifier: GPL-2.0-only

use salty::consts::*;
use salty::posix_mm;
use salty::serial;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub fn run() -> bool {
    puts(b"[TEST_MMAP] Starting memory management tests\n");

    // Initialize posix_mm with caps from procmgr
    let frame_slot = unsafe { salty::__salty_next_frame_slot };
    unsafe {
        posix_mm::posix_mm_init(
            CAP_UNTYPED,
            CAP_SELF_VSPACE,
            CAP_SELF_CSPACE,
            frame_slot,
            0x12000000, // heap base (avoid rtld-loaded libs)
            0x20000000, // mmap base
        );
    }

    // Test 1: sbrk
    puts(b"[TEST_MMAP] Test 1: sbrk(4096)\n");
    let old_brk = unsafe { posix_mm::posix_sbrk(4096) };
    if old_brk == u64::MAX {
        puts(b"[TEST_MMAP] FAIL: sbrk returned -1\n");
        return false;
    }
    puts(b"[TEST_MMAP] sbrk returned: ");
    serial::serial_hex(old_brk);
    puts(b"\n");

    // Write and read back
    unsafe {
        let heap = old_brk as *mut u8;
        core::ptr::write_volatile(heap, 0xAA);
        core::ptr::write_volatile(heap.add(4095), 0xBB);
        if core::ptr::read_volatile(heap) != 0xAA || core::ptr::read_volatile(heap.add(4095)) != 0xBB {
            puts(b"[TEST_MMAP] FAIL: heap read-back mismatch\n");
            return false;
        }
    }
    puts(b"[TEST_MMAP] PASS: sbrk write/read OK\n");

    // Check current break
    let cur_brk = unsafe { posix_mm::posix_sbrk(0) };
    if cur_brk != old_brk + 4096 {
        puts(b"[TEST_MMAP] FAIL: sbrk(0) not at expected break\n");
        return false;
    }
    puts(b"[TEST_MMAP] PASS: sbrk(0) check OK\n");

    // Test 2: mmap anonymous
    puts(b"[TEST_MMAP] Test 2: mmap anonymous page\n");
    let page = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page as usize == usize::MAX {
        puts(b"[TEST_MMAP] FAIL: mmap returned MAP_FAILED\n");
        return false;
    }
    puts(b"[TEST_MMAP] mmap returned: ");
    serial::serial_hex(page as u64);
    puts(b"\n");

    // Verify zero-initialized
    unsafe {
        let mp = page;
        if core::ptr::read_volatile(mp) != 0
            || core::ptr::read_volatile(mp.add(2048)) != 0
            || core::ptr::read_volatile(mp.add(4095)) != 0
        {
            puts(b"[TEST_MMAP] FAIL: mmap page not zero\n");
            return false;
        }

        // Write and read
        core::ptr::write_volatile(mp, 0xCC);
        core::ptr::write_volatile(mp.add(4095), 0xDD);
        if core::ptr::read_volatile(mp) != 0xCC || core::ptr::read_volatile(mp.add(4095)) != 0xDD {
            puts(b"[TEST_MMAP] FAIL: mmap read-back mismatch\n");
            return false;
        }
    }
    puts(b"[TEST_MMAP] PASS: mmap write/read OK\n");

    // Test 3: munmap
    puts(b"[TEST_MMAP] Test 3: munmap\n");
    let ret = unsafe { posix_mm::posix_munmap(page, 4096) };
    if ret != 0 {
        puts(b"[TEST_MMAP] FAIL: munmap returned error\n");
        return false;
    }
    puts(b"[TEST_MMAP] PASS: munmap OK\n");

    // Test 4: Multiple mmap regions
    puts(b"[TEST_MMAP] Test 4: multiple mmap regions\n");
    let p1 = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let p2 = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            8192,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p1 as usize == usize::MAX || p2 as usize == usize::MAX {
        puts(b"[TEST_MMAP] FAIL: multi mmap failed\n");
        return false;
    }

    // Verify no overlap
    let a1 = p1 as u64;
    let a2 = p2 as u64;
    if a1 == a2 || (a1 < a2 + 8192 && a2 < a1 + 4096) {
        puts(b"[TEST_MMAP] FAIL: mmap regions overlap\n");
        return false;
    }

    // Write to both
    unsafe {
        core::ptr::write_volatile(p1, 0x11);
        core::ptr::write_volatile(p2, 0x22);
        if core::ptr::read_volatile(p1) != 0x11 || core::ptr::read_volatile(p2) != 0x22 {
            puts(b"[TEST_MMAP] FAIL: multi mmap read-back mismatch\n");
            return false;
        }
    }
    puts(b"[TEST_MMAP] PASS: multiple mmap regions OK\n");

    unsafe {
        posix_mm::posix_munmap(p1, 4096);
        posix_mm::posix_munmap(p2, 8192);
    }

    puts(b"[TEST_MMAP] All memory management tests PASSED\n");
    true
}
