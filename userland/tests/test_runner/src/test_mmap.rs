//! Memory management tests - exercises brk/sbrk/mmap/munmap
//! Ported from userland/mmap_test/main.c
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::uapi;
use trona_posix;
use trona_posix::consts::*;
use trona_posix::mm as posix_mm;
use trona_runtime::client::mm as runtime_mm;
use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn ensure_tmp_dir() -> bool {
    let ret = unsafe { trona_posix::posix_mkdir(b"/tmp\0".as_ptr(), 0o755) };
    ret == 0 || ret == -17
}

pub fn run() -> bool {
    puts(b"[TEST_MMAP] Starting memory management tests\n");

    // posix_mm reads mmsrv via trona_runtime::client::caps::mmsrv_ep() now — no explicit
    // init call needed here.

    // Test 1: sbrk
    puts(b"[TEST_MMAP] Test 1: sbrk(4096)\n");
    let old_brk = unsafe { posix_mm::posix_sbrk(4096) };
    if old_brk == u64::MAX {
        puts(b"[TEST_MMAP] FAIL: sbrk returned -1\n");
        return false;
    }
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_MMAP] sbrk returned: ");
        lb.hex(old_brk);
        lb.str(b"\n");
        lb.flush();
    }

    // Write and read back
    unsafe {
        let heap = old_brk as *mut u8;
        core::ptr::write_volatile(heap, 0xAA);
        core::ptr::write_volatile(heap.add(4095), 0xBB);
        if core::ptr::read_volatile(heap) != 0xAA
            || core::ptr::read_volatile(heap.add(4095)) != 0xBB
        {
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
    {
        let mut lb = LineBuf::new();
        lb.str(b"[TEST_MMAP] mmap returned: ");
        lb.hex(page as u64);
        lb.str(b"\n");
        lb.flush();
    }

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

    // Test 4b: munmap over multiple regions and holes
    puts(b"[TEST_MMAP] Test 4b: munmap multi-region and hole ranges\n");
    let multi = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            8192,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if multi as usize == usize::MAX {
        puts(b"[TEST_MMAP] FAIL: multi-region setup mmap failed\n");
        return false;
    }
    if unsafe { posix_mm::posix_mprotect(multi.add(4096), 4096, PROT_READ) } != 0 {
        puts(b"[TEST_MMAP] FAIL: split mprotect for multi-region munmap failed\n");
        unsafe {
            posix_mm::posix_munmap(multi, 8192);
        }
        return false;
    }
    if unsafe { posix_mm::posix_munmap(multi, 8192) } != 0 {
        puts(b"[TEST_MMAP] FAIL: munmap spanning adjacent regions failed\n");
        return false;
    }

    let holed = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            12288,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if holed as usize == usize::MAX {
        puts(b"[TEST_MMAP] FAIL: holed-range setup mmap failed\n");
        return false;
    }
    if unsafe { posix_mm::posix_munmap(holed.add(4096), 4096) } != 0 {
        puts(b"[TEST_MMAP] FAIL: middle-page munmap for holed range failed\n");
        unsafe {
            posix_mm::posix_munmap(holed, 12288);
        }
        return false;
    }
    if unsafe { posix_mm::posix_munmap(holed, 12288) } != 0 {
        puts(b"[TEST_MMAP] FAIL: munmap spanning hole failed\n");
        return false;
    }
    puts(b"[TEST_MMAP] PASS: munmap multi-region and holes OK\n");

    // Test 5: file-backed lazy page-in
    puts(b"[TEST_MMAP] Test 5: file-backed mmap lazy page-in\n");
    if !ensure_tmp_dir() {
        puts(b"[TEST_MMAP] FAIL: mkdir /tmp failed\n");
        return false;
    }
    unsafe {
        trona_posix::posix_unlink(b"/tmp/mmap.bin\0".as_ptr());
    }

    let fd = unsafe {
        trona_posix::posix_open(
            b"/tmp/mmap.bin\0".as_ptr(),
            (O_CREAT | O_RDWR) as i32,
            0o644,
        )
    };
    if fd < 0 {
        puts(b"[TEST_MMAP] FAIL: open /tmp/mmap.bin failed\n");
        return false;
    }

    let mut page_buf = [0u8; 4096];
    for i in 0..page_buf.len() {
        page_buf[i] = (i & 0xFF) as u8;
    }
    let written =
        unsafe { trona_posix::posix_pwrite(fd, page_buf.as_ptr(), page_buf.len() as u64, 0) };
    if written != page_buf.len() as i64 {
        puts(b"[TEST_MMAP] FAIL: seed pwrite returned wrong count\n");
        unsafe {
            trona_posix::posix_close(fd);
        }
        return false;
    }

    let file_map =
        unsafe { posix_mm::posix_mmap(core::ptr::null_mut(), 4096, PROT_READ, MAP_PRIVATE, fd, 0) };
    if file_map as usize == usize::MAX {
        puts(b"[TEST_MMAP] FAIL: file-backed MAP_PRIVATE mmap failed\n");
        unsafe {
            trona_posix::posix_close(fd);
        }
        return false;
    }
    unsafe {
        if core::ptr::read_volatile(file_map) != page_buf[0]
            || core::ptr::read_volatile(file_map.add(123)) != page_buf[123]
            || core::ptr::read_volatile(file_map.add(4095)) != page_buf[4095]
        {
            puts(b"[TEST_MMAP] FAIL: file-backed lazy page-in mismatch\n");
            posix_mm::posix_munmap(file_map, 4096);
            trona_posix::posix_close(fd);
            return false;
        }
        posix_mm::posix_munmap(file_map, 4096);
    }
    puts(b"[TEST_MMAP] PASS: file-backed lazy page-in OK\n");

    // Test 6: MAP_SHARED writeback
    puts(b"[TEST_MMAP] Test 6: file-backed MAP_SHARED writeback\n");
    let shared_map = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        )
    };
    if shared_map as usize == usize::MAX {
        puts(b"[TEST_MMAP] FAIL: file-backed MAP_SHARED mmap failed\n");
        unsafe {
            trona_posix::posix_close(fd);
        }
        return false;
    }
    unsafe {
        core::ptr::write_volatile(shared_map.add(10), 0xA1);
        core::ptr::write_volatile(shared_map.add(2048), 0xB2);
        core::ptr::write_volatile(shared_map.add(4095), 0xC3);
        if posix_mm::posix_munmap(shared_map, 4096) != 0 {
            puts(b"[TEST_MMAP] FAIL: munmap shared mapping failed\n");
            trona_posix::posix_close(fd);
            return false;
        }
    }

    let mut byte = [0u8; 1];
    let rd10 = unsafe { trona_posix::posix_pread(fd, byte.as_mut_ptr(), 1, 10) };
    if rd10 != 1 || byte[0] != 0xA1 {
        puts(b"[TEST_MMAP] FAIL: writeback byte 10 mismatch\n");
        unsafe {
            trona_posix::posix_close(fd);
        }
        return false;
    }
    let rd2048 = unsafe { trona_posix::posix_pread(fd, byte.as_mut_ptr(), 1, 2048) };
    if rd2048 != 1 || byte[0] != 0xB2 {
        puts(b"[TEST_MMAP] FAIL: writeback byte 2048 mismatch\n");
        unsafe {
            trona_posix::posix_close(fd);
        }
        return false;
    }
    let rd4095 = unsafe { trona_posix::posix_pread(fd, byte.as_mut_ptr(), 1, 4095) };
    if rd4095 != 1 || byte[0] != 0xC3 {
        puts(b"[TEST_MMAP] FAIL: writeback byte 4095 mismatch\n");
        unsafe {
            trona_posix::posix_close(fd);
        }
        return false;
    }
    puts(b"[TEST_MMAP] PASS: file-backed MAP_SHARED writeback OK\n");

    // Test 7: MAP_FIXED replacement semantics
    puts(b"[TEST_MMAP] Test 7: MAP_FIXED replacement\n");
    let fixed_base = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if fixed_base as usize == usize::MAX {
        puts(b"[TEST_MMAP] FAIL: anonymous mmap for MAP_FIXED failed\n");
        unsafe {
            trona_posix::posix_close(fd);
        }
        return false;
    }

    unsafe {
        core::ptr::write_volatile(fixed_base, 0x5A);
    }

    let noreplace = unsafe {
        runtime_mm::mmap(
            fixed_base,
            4096,
            PROT_READ,
            MAP_PRIVATE | MAP_FIXED_NOREPLACE,
            fd,
            0,
        )
    };
    match noreplace {
        Err(label) if label == uapi::KERNITE_ERR_ALREADY_MAPPED as u64 => {}
        Err(_) => {
            puts(b"[TEST_MMAP] FAIL: MAP_FIXED_NOREPLACE collision did not return EEXIST\n");
            unsafe {
                posix_mm::posix_munmap(fixed_base, 4096);
                trona_posix::posix_close(fd);
            }
            return false;
        }
        Ok(mapped) => {
            puts(b"[TEST_MMAP] FAIL: MAP_FIXED_NOREPLACE collision unexpectedly mapped\n");
            unsafe {
                posix_mm::posix_munmap(mapped, 4096);
                trona_posix::posix_close(fd);
            }
            return false;
        }
    }
    unsafe {
        if core::ptr::read_volatile(fixed_base) != 0x5A {
            puts(b"[TEST_MMAP] FAIL: MAP_FIXED_NOREPLACE disturbed existing mapping\n");
            posix_mm::posix_munmap(fixed_base, 4096);
            trona_posix::posix_close(fd);
            return false;
        }
    }
    puts(b"[TEST_MMAP] PASS: MAP_FIXED_NOREPLACE collision returned EEXIST\n");

    let replaced = unsafe {
        posix_mm::posix_mmap(fixed_base, 4096, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0)
    };
    if replaced != fixed_base {
        puts(b"[TEST_MMAP] FAIL: MAP_FIXED did not preserve requested base\n");
        unsafe {
            posix_mm::posix_munmap(fixed_base, 4096);
            trona_posix::posix_close(fd);
        }
        return false;
    }

    unsafe {
        if core::ptr::read_volatile(replaced) != page_buf[0]
            || core::ptr::read_volatile(replaced.add(123)) != page_buf[123]
            || core::ptr::read_volatile(replaced.add(4095)) != 0xC3
        {
            puts(b"[TEST_MMAP] FAIL: MAP_FIXED replacement contents mismatch\n");
            posix_mm::posix_munmap(replaced, 4096);
            trona_posix::posix_close(fd);
            return false;
        }
        posix_mm::posix_munmap(replaced, 4096);
    }
    puts(b"[TEST_MMAP] PASS: MAP_FIXED replacement OK\n");

    // Test 8: partial-overlap MAP_FIXED keeps neighbors intact
    puts(b"[TEST_MMAP] Test 8: partial-overlap MAP_FIXED\n");
    unsafe {
        trona_posix::posix_close(fd);
        trona_posix::posix_unlink(b"/tmp/mmap.bin\0".as_ptr());
        trona_posix::posix_unlink(b"/tmp/mmap-fixed.bin\0".as_ptr());
    }

    let fd_fixed = unsafe {
        trona_posix::posix_open(
            b"/tmp/mmap-fixed.bin\0".as_ptr(),
            (O_CREAT | O_RDWR) as i32,
            0o644,
        )
    };
    if fd_fixed < 0 {
        puts(b"[TEST_MMAP] FAIL: open /tmp/mmap-fixed.bin failed\n");
        return false;
    }

    let mut fill_page = [0u8; 4096];
    for byte in &mut fill_page {
        *byte = 0x11;
    }
    if unsafe { trona_posix::posix_pwrite(fd_fixed, fill_page.as_ptr(), 4096, 0) } != 4096 {
        puts(b"[TEST_MMAP] FAIL: seed page 0 failed\n");
        unsafe {
            trona_posix::posix_close(fd_fixed);
        }
        return false;
    }
    for byte in &mut fill_page {
        *byte = 0x22;
    }
    if unsafe { trona_posix::posix_pwrite(fd_fixed, fill_page.as_ptr(), 4096, 4096) } != 4096 {
        puts(b"[TEST_MMAP] FAIL: seed page 1 failed\n");
        unsafe {
            trona_posix::posix_close(fd_fixed);
        }
        return false;
    }
    for byte in &mut fill_page {
        *byte = 0x33;
    }
    if unsafe { trona_posix::posix_pwrite(fd_fixed, fill_page.as_ptr(), 4096, 8192) } != 4096 {
        puts(b"[TEST_MMAP] FAIL: seed page 2 failed\n");
        unsafe {
            trona_posix::posix_close(fd_fixed);
        }
        return false;
    }

    let span = unsafe {
        posix_mm::posix_mmap(
            core::ptr::null_mut(),
            12288,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if span as usize == usize::MAX {
        puts(b"[TEST_MMAP] FAIL: 3-page anonymous span mmap failed\n");
        unsafe {
            trona_posix::posix_close(fd_fixed);
        }
        return false;
    }

    unsafe {
        core::ptr::write_volatile(span, 0xA0);
        core::ptr::write_volatile(span.add(4095), 0xA1);
        core::ptr::write_volatile(span.add(4096), 0xB0);
        core::ptr::write_volatile(span.add(4096 + 4095), 0xB1);
        core::ptr::write_volatile(span.add(8192), 0xC0);
        core::ptr::write_volatile(span.add(8192 + 4095), 0xC1);
    }

    let mid = unsafe {
        posix_mm::posix_mmap(
            span.add(4096),
            4096,
            PROT_READ,
            MAP_PRIVATE | MAP_FIXED,
            fd_fixed,
            4096,
        )
    };
    if mid != unsafe { span.add(4096) } {
        puts(b"[TEST_MMAP] FAIL: MAP_FIXED middle-page replacement failed\n");
        unsafe {
            posix_mm::posix_munmap(span, 12288);
            trona_posix::posix_close(fd_fixed);
        }
        return false;
    }

    unsafe {
        if core::ptr::read_volatile(span) != 0xA0
            || core::ptr::read_volatile(span.add(4095)) != 0xA1
            || core::ptr::read_volatile(mid) != 0x22
            || core::ptr::read_volatile(mid.add(123)) != 0x22
            || core::ptr::read_volatile(mid.add(4095)) != 0x22
            || core::ptr::read_volatile(span.add(8192)) != 0xC0
            || core::ptr::read_volatile(span.add(8192 + 4095)) != 0xC1
        {
            puts(b"[TEST_MMAP] FAIL: partial-overlap MAP_FIXED corrupted neighboring pages\n");
            posix_mm::posix_munmap(span, 12288);
            trona_posix::posix_close(fd_fixed);
            return false;
        }
    }
    puts(b"[TEST_MMAP] PASS: partial-overlap MAP_FIXED OK\n");

    // Test 9: MAP_SHARED replacement at non-zero file offset writes back
    puts(b"[TEST_MMAP] Test 9: MAP_SHARED MAP_FIXED with file offset\n");
    let head = unsafe {
        posix_mm::posix_mmap(
            span,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_FIXED,
            fd_fixed,
            8192,
        )
    };
    if head != span {
        puts(b"[TEST_MMAP] FAIL: MAP_SHARED head replacement failed\n");
        unsafe {
            posix_mm::posix_munmap(span, 12288);
            trona_posix::posix_close(fd_fixed);
        }
        return false;
    }

    unsafe {
        if core::ptr::read_volatile(head) != 0x33
            || core::ptr::read_volatile(head.add(4095)) != 0x33
            || core::ptr::read_volatile(mid) != 0x22
            || core::ptr::read_volatile(span.add(8192)) != 0xC0
        {
            puts(b"[TEST_MMAP] FAIL: MAP_SHARED replacement initial contents mismatch\n");
            posix_mm::posix_munmap(span, 12288);
            trona_posix::posix_close(fd_fixed);
            return false;
        }

        core::ptr::write_volatile(head.add(7), 0xD1);
        core::ptr::write_volatile(head.add(4095), 0xE2);
        if posix_mm::posix_munmap(head, 4096) != 0 {
            puts(b"[TEST_MMAP] FAIL: munmap shared MAP_FIXED page failed\n");
            trona_posix::posix_close(fd_fixed);
            return false;
        }
    }

    let rd_head_7 = unsafe { trona_posix::posix_pread(fd_fixed, byte.as_mut_ptr(), 1, 8192 + 7) };
    if rd_head_7 != 1 || byte[0] != 0xD1 {
        puts(b"[TEST_MMAP] FAIL: MAP_SHARED replacement writeback byte 7 mismatch\n");
        unsafe {
            posix_mm::posix_munmap(mid, 8192);
            trona_posix::posix_close(fd_fixed);
        }
        return false;
    }
    let rd_head_last =
        unsafe { trona_posix::posix_pread(fd_fixed, byte.as_mut_ptr(), 1, 8192 + 4095) };
    if rd_head_last != 1 || byte[0] != 0xE2 {
        puts(b"[TEST_MMAP] FAIL: MAP_SHARED replacement writeback last byte mismatch\n");
        unsafe {
            posix_mm::posix_munmap(mid, 8192);
            trona_posix::posix_close(fd_fixed);
        }
        return false;
    }

    unsafe {
        if core::ptr::read_volatile(mid) != 0x22
            || core::ptr::read_volatile(mid.add(4095)) != 0x22
            || core::ptr::read_volatile(span.add(8192)) != 0xC0
            || core::ptr::read_volatile(span.add(8192 + 4095)) != 0xC1
        {
            puts(b"[TEST_MMAP] FAIL: MAP_SHARED replacement disturbed adjacent regions\n");
            posix_mm::posix_munmap(mid, 8192);
            trona_posix::posix_close(fd_fixed);
            return false;
        }

        posix_mm::posix_munmap(mid, 8192);
        trona_posix::posix_close(fd_fixed);
        trona_posix::posix_unlink(b"/tmp/mmap-fixed.bin\0".as_ptr());
    }
    puts(b"[TEST_MMAP] PASS: MAP_SHARED MAP_FIXED writeback OK\n");

    puts(b"[TEST_MMAP] All memory management tests PASSED\n");
    true
}
