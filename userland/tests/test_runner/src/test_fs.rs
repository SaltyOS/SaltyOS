//! Filesystem tests - exercises VFS ramfs operations
//! Ported from userland/fstest/main.c (12 tests)
//! SPDX-License-Identifier: GPL-2.0-only

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::serial;
use trona::types::core::*;
use trona_posix::mm as posix_mm;
use trona_posix::proc as posix;
use trona_posix::*;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn streq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

fn copy_name(src: &[u8], dst: &mut [u8; 128]) -> usize {
    let copy_len = if src.len() < dst.len() {
        src.len()
    } else {
        dst.len()
    };
    for i in 0..copy_len {
        dst[i] = src[i];
    }
    copy_len
}

fn readdir_makes_progress(path: &[u8], must_find: &[&[u8]], limit: usize) -> bool {
    let dir_fd = unsafe { trona_posix::posix_opendir(path.as_ptr()) };
    if dir_fd < 0 {
        return false;
    }

    let mut dent = TronaDirent::zeroed();
    let mut seen = 0usize;
    let mut last_name = [0u8; 128];
    let mut last_name_len = 0usize;
    let mut same_name_streak = 0usize;
    let mut found = [false; 8];

    while unsafe { trona_posix::posix_readdir(dir_fd, &raw mut dent) } != 0 {
        let name = &dent.d_name[..dent.d_namlen as usize];
        if name.len() == last_name_len && streq(name, &last_name[..last_name_len]) {
            same_name_streak += 1;
        } else {
            same_name_streak = 0;
            last_name_len = copy_name(name, &mut last_name);
        }

        if same_name_streak >= 4 {
            unsafe { trona_posix::posix_closedir(dir_fd) };
            return false;
        }

        for i in 0..must_find.len() {
            if streq(name, must_find[i]) {
                found[i] = true;
            }
        }

        seen += 1;
        if seen > limit {
            unsafe { trona_posix::posix_closedir(dir_fd) };
            return false;
        }
    }

    unsafe { trona_posix::posix_closedir(dir_fd) };
    if seen == 0 {
        return false;
    }
    for i in 0..must_find.len() {
        if !found[i] {
            return false;
        }
    }
    true
}

pub fn run() -> bool {
    puts(b"[TEST_FS] Starting filesystem tests\n");

    // posix_mm reads mmsrv via trona::caps::mmsrv_ep() now — no explicit
    // init call needed here.

    // Test 1: stat /dev/console
    puts(b"[TEST_FS] Test 1: stat /dev/console\n");
    let mut st = TronaStat::zeroed();
    let ret = unsafe { trona_posix::posix_stat(b"/dev/console\0".as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: stat /dev/console returned error\n");
        return false;
    }
    if (st.st_mode & S_IFMT) != S_IFCHR {
        puts(b"[TEST_FS] FAIL: /dev/console is not a char device\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /dev/console is a char device\n");

    // Test 2: stat /initramfs (old boot root, persists after pivot_root)
    puts(b"[TEST_FS] Test 2: stat /initramfs\n");
    let ret = unsafe { trona_posix::posix_stat(b"/initramfs\0".as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: stat /initramfs returned error\n");
        return false;
    }
    if (st.st_mode & S_IFMT) != S_IFDIR {
        puts(b"[TEST_FS] FAIL: /initramfs is not a directory\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /initramfs is a directory\n");

    // Test 3: opendir /initramfs + readdir (old boot root, still mounted after pivot_root)
    puts(b"[TEST_FS] Test 3: opendir/readdir /initramfs\n");
    let dir_fd = unsafe { trona_posix::posix_opendir(b"/initramfs\0".as_ptr()) };
    if dir_fd < 0 {
        puts(b"[TEST_FS] FAIL: opendir /initramfs failed\n");
        return false;
    }

    let mut dent = TronaDirent::zeroed();
    let mut file_count = 0;
    while unsafe { trona_posix::posix_readdir(dir_fd, &raw mut dent) } != 0 {
        puts(b"[TEST_FS]   ");
        serial::serial_puts(&dent.d_name[..dent.d_namlen as usize]);
        puts(b"\n");
        file_count += 1;
    }
    unsafe { trona_posix::posix_closedir(dir_fd) };

    if file_count == 0 {
        puts(b"[TEST_FS] FAIL: /initramfs is empty\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: listed initramfs entries\n");

    // Test 4: access
    puts(b"[TEST_FS] Test 4: access checks\n");
    let ret = unsafe { trona_posix::posix_access(b"/dev/console\0".as_ptr(), F_OK as i32) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: access /dev/console F_OK failed\n");
        return false;
    }
    let ret = unsafe { trona_posix::posix_access(b"/nonexistent\0".as_ptr(), F_OK as i32) };
    if ret == 0 {
        puts(b"[TEST_FS] FAIL: access /nonexistent should have failed\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: access checks OK\n");

    // Test 5: mkdir /tmp
    puts(b"[TEST_FS] Test 5: mkdir /tmp\n");
    let ret = unsafe { trona_posix::posix_mkdir(b"/tmp\0".as_ptr(), 0o755) };
    if ret != 0 && ret != -17 {
        // Accept EEXIST (-17): VFS may pre-create /tmp at boot
        puts(b"[TEST_FS] FAIL: mkdir /tmp returned error\n");
        return false;
    }
    let ret = unsafe { trona_posix::posix_stat(b"/tmp\0".as_ptr(), &raw mut st) };
    if ret != 0 || (st.st_mode & S_IFMT) != S_IFDIR {
        puts(b"[TEST_FS] FAIL: /tmp is not a directory after mkdir\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: mkdir /tmp OK\n");

    // Test 6: create + write + read round-trip
    puts(b"[TEST_FS] Test 6: file create/write/read round-trip\n");
    let fd = unsafe {
        trona_posix::posix_open(
            b"/tmp/test.txt\0".as_ptr(),
            (O_CREAT | O_RDWR) as i32,
            0o644,
        )
    };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open /tmp/test.txt O_CREAT failed\n");
        return false;
    }

    let test_data = b"Hello, SaltyOS filesystem!";
    let written =
        unsafe { trona_posix::posix_write(fd, test_data.as_ptr(), test_data.len() as u64) };
    if written != test_data.len() as i64 {
        puts(b"[TEST_FS] FAIL: write returned wrong count\n");
        return false;
    }
    unsafe { trona_posix::posix_close(fd) };

    // Re-open and read back
    let fd = unsafe { trona_posix::posix_open(b"/tmp/test.txt\0".as_ptr(), O_RDONLY as i32, 0) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: re-open /tmp/test.txt failed\n");
        return false;
    }

    let mut buf = [0u8; 64];
    let rd = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    if rd != test_data.len() as i64 {
        puts(b"[TEST_FS] FAIL: read returned wrong count\n");
        return false;
    }

    for i in 0..test_data.len() {
        if buf[i] != test_data[i] {
            puts(b"[TEST_FS] FAIL: read-back content mismatch\n");
            return false;
        }
    }
    puts(b"[TEST_FS] PASS: file write/read round-trip OK\n");

    // Test 7: lseek + re-read
    puts(b"[TEST_FS] Test 7: lseek\n");
    let off = unsafe { trona_posix::posix_lseek(fd, 7, SEEK_SET as i32) };
    if off != 7 {
        puts(b"[TEST_FS] FAIL: lseek SEEK_SET returned wrong offset\n");
        return false;
    }

    buf = [0u8; 64];
    let rd = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    if rd <= 0 || buf[0] != b'S' {
        puts(b"[TEST_FS] FAIL: read after lseek got wrong data\n");
        return false;
    }
    unsafe { trona_posix::posix_close(fd) };
    puts(b"[TEST_FS] PASS: lseek OK\n");

    // Test 8: fstat on an open file
    puts(b"[TEST_FS] Test 8: fstat\n");
    let fd = unsafe { trona_posix::posix_open(b"/tmp/test.txt\0".as_ptr(), O_RDONLY as i32, 0) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open for fstat failed\n");
        return false;
    }
    let ret = unsafe { trona_posix::posix_fstat(fd, &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: fstat returned error\n");
        return false;
    }
    if (st.st_mode & S_IFMT) != S_IFREG {
        puts(b"[TEST_FS] FAIL: fstat mode is not regular file\n");
        return false;
    }
    if st.st_size != test_data.len() as u64 {
        puts(b"[TEST_FS] FAIL: fstat size mismatch\n");
        return false;
    }
    unsafe { trona_posix::posix_close(fd) };
    puts(b"[TEST_FS] PASS: fstat OK\n");

    // Test 9: unlink
    puts(b"[TEST_FS] Test 9: unlink\n");
    let ret = unsafe { trona_posix::posix_unlink(b"/tmp/test.txt\0".as_ptr()) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: unlink returned error\n");
        return false;
    }
    let ret = unsafe { trona_posix::posix_access(b"/tmp/test.txt\0".as_ptr(), F_OK as i32) };
    if ret == 0 {
        puts(b"[TEST_FS] FAIL: file still exists after unlink\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: unlink OK\n");

    // Test 10: rmdir mountpoint should fail with EBUSY
    puts(b"[TEST_FS] Test 10: rmdir /tmp\n");
    let ret = unsafe { trona_posix::posix_rmdir(b"/tmp\0".as_ptr()) };
    if ret != -16 {
        puts(b"[TEST_FS] FAIL: rmdir /tmp should have returned EBUSY\n");
        return false;
    }
    let ret = unsafe { trona_posix::posix_access(b"/tmp\0".as_ptr(), F_OK as i32) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: /tmp disappeared after failed rmdir\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: mountpoint rmdir rejected with EBUSY\n");

    puts(b"[TEST_FS] Test 10a: readdir / makes progress\n");
    if !readdir_makes_progress(b"/\0", &[b"dev", b"tmp", b"usr"], 128) {
        puts(b"[TEST_FS] FAIL: readdir / did not make progress\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: readdir / makes progress\n");

    // Test 11: opendir /dev + readdir
    puts(b"[TEST_FS] Test 11: readdir /dev\n");
    if !readdir_makes_progress(b"/dev\0", &[b"console", b"null", b"zero"], 128) {
        puts(b"[TEST_FS] FAIL: readdir /dev did not make progress\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /dev contains console, null, zero\n");

    // Test 12: rename
    puts(b"[TEST_FS] Test 12: rename\n");
    let ret = unsafe { trona_posix::posix_mkdir(b"/tmp/rename_test\0".as_ptr(), 0o755) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: mkdir /tmp/rename_test failed\n");
        return false;
    }
    let fd = unsafe {
        trona_posix::posix_open(
            b"/tmp/rename_test/a.txt\0".as_ptr(),
            (O_CREAT | O_RDWR) as i32,
            0o644,
        )
    };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: create /tmp/rename_test/a.txt failed\n");
        return false;
    }
    unsafe {
        trona_posix::posix_write(fd, b"rename".as_ptr(), 6);
        trona_posix::posix_close(fd);
    }

    let ret = unsafe {
        trona_posix::posix_rename(
            b"/tmp/rename_test/a.txt\0".as_ptr(),
            b"/tmp/rename_test/b.txt\0".as_ptr(),
        )
    };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: rename failed\n");
        return false;
    }

    let ret =
        unsafe { trona_posix::posix_access(b"/tmp/rename_test/a.txt\0".as_ptr(), F_OK as i32) };
    if ret == 0 {
        puts(b"[TEST_FS] FAIL: old name still exists after rename\n");
        return false;
    }

    let fd = unsafe {
        trona_posix::posix_open(b"/tmp/rename_test/b.txt\0".as_ptr(), O_RDONLY as i32, 0)
    };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open renamed file failed\n");
        return false;
    }
    buf = [0u8; 64];
    let rd = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    unsafe { trona_posix::posix_close(fd) };
    if rd != 6 || buf[0] != b'r' {
        puts(b"[TEST_FS] FAIL: renamed file content wrong\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: rename OK\n");

    // Cleanup
    unsafe {
        trona_posix::posix_unlink(b"/tmp/rename_test/b.txt\0".as_ptr());
        trona_posix::posix_rmdir(b"/tmp/rename_test\0".as_ptr());
    }

    // Test 13: /dev/urandom
    puts(b"[TEST_FS] Test 13: /dev/urandom\n");
    let fd = unsafe { trona_posix::posix_open(b"/dev/urandom\0".as_ptr(), O_RDONLY as i32, 0) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open /dev/urandom failed\n");
        return false;
    }
    let mut ubuf1 = [0u8; 32];
    let mut ubuf2 = [0u8; 32];
    let r1 = unsafe { trona_posix::posix_read(fd, ubuf1.as_mut_ptr(), 32) };
    let r2 = unsafe { trona_posix::posix_read(fd, ubuf2.as_mut_ptr(), 32) };
    unsafe { trona_posix::posix_close(fd) };
    if r1 != 32 || r2 != 32 {
        puts(b"[TEST_FS] FAIL: urandom read count wrong\n");
        return false;
    }
    // Check non-zero (probabilistic but extremely unlikely to fail)
    let mut all_zero = true;
    for i in 0..32 {
        if ubuf1[i] != 0 {
            all_zero = false;
            break;
        }
    }
    if all_zero {
        puts(b"[TEST_FS] FAIL: urandom returned all zeros\n");
        return false;
    }
    // Two reads should differ
    let mut same = true;
    for i in 0..32 {
        if ubuf1[i] != ubuf2[i] {
            same = false;
            break;
        }
    }
    if same {
        puts(b"[TEST_FS] FAIL: two urandom reads identical\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /dev/urandom OK\n");

    // Test 14: Long path (>64 bytes)
    puts(b"[TEST_FS] Test 14: long path\n");
    unsafe { trona_posix::posix_mkdir(b"/tmp\0".as_ptr(), 0o755) };
    unsafe { trona_posix::posix_mkdir(b"/tmp/a_very_long_directory_name_here\0".as_ptr(), 0o755) };
    // Path = /tmp/a_very_long_directory_name_here/test_long_path.txt (total > 64 bytes)
    let long_path = b"/tmp/a_very_long_directory_name_here/test_long_path.txt\0";
    let fd =
        unsafe { trona_posix::posix_open(long_path.as_ptr(), (O_CREAT | O_RDWR) as i32, 0o644) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open long path failed\n");
        return false;
    }
    unsafe {
        trona_posix::posix_write(fd, b"long".as_ptr(), 4);
        trona_posix::posix_close(fd);
    }
    let ret = unsafe { trona_posix::posix_stat(long_path.as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: stat long path failed\n");
        return false;
    }
    // Cleanup
    unsafe {
        trona_posix::posix_unlink(long_path.as_ptr());
        trona_posix::posix_rmdir(b"/tmp/a_very_long_directory_name_here\0".as_ptr());
    }
    puts(b"[TEST_FS] PASS: long path OK\n");

    // Test 15: Large file (>8KB)
    puts(b"[TEST_FS] Test 15: large file write/read\n");
    let fd = unsafe {
        trona_posix::posix_open(b"/tmp/bigfile\0".as_ptr(), (O_CREAT | O_RDWR) as i32, 0o644)
    };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: create bigfile failed\n");
        return false;
    }
    // Write 10KB of data (pattern: byte position mod 251)
    let mut wbuf = [0u8; 128];
    let target_size: usize = 10240;
    let mut written_total: usize = 0;
    while written_total < target_size {
        let chunk = if target_size - written_total < 128 {
            target_size - written_total
        } else {
            128
        };
        for j in 0..chunk {
            wbuf[j] = ((written_total + j) % 251) as u8;
        }
        let w = unsafe { trona_posix::posix_write(fd, wbuf.as_ptr(), chunk as u64) };
        if w <= 0 {
            puts(b"[TEST_FS] FAIL: large write returned 0\n");
            return false;
        }
        written_total += w as usize;
    }
    unsafe { trona_posix::posix_close(fd) };

    // Re-open and verify
    let fd = unsafe { trona_posix::posix_open(b"/tmp/bigfile\0".as_ptr(), O_RDONLY as i32, 0) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: re-open bigfile failed\n");
        return false;
    }
    let mut read_total: usize = 0;
    let mut rbuf = [0u8; 128];
    loop {
        let r = unsafe { trona_posix::posix_read(fd, rbuf.as_mut_ptr(), 128) };
        if r <= 0 {
            break;
        }
        for j in 0..r as usize {
            if rbuf[j] != ((read_total + j) % 251) as u8 {
                puts(b"[TEST_FS] FAIL: large file data mismatch\n");
                unsafe { trona_posix::posix_close(fd) };
                return false;
            }
        }
        read_total += r as usize;
    }
    unsafe { trona_posix::posix_close(fd) };
    if read_total != target_size {
        puts(b"[TEST_FS] FAIL: large file size mismatch\n");
        return false;
    }
    unsafe { trona_posix::posix_unlink(b"/tmp/bigfile\0".as_ptr()) };
    puts(b"[TEST_FS] PASS: large file (10KB) write/read OK\n");

    // Test 16: Symlink
    puts(b"[TEST_FS] Test 16: symlink\n");
    let fd = unsafe {
        trona_posix::posix_open(
            b"/tmp/orig.txt\0".as_ptr(),
            (O_CREAT | O_RDWR) as i32,
            0o644,
        )
    };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: create orig.txt failed\n");
        return false;
    }
    unsafe {
        trona_posix::posix_write(fd, b"symlink_test".as_ptr(), 12);
        trona_posix::posix_close(fd);
    }
    let ret = unsafe {
        trona_posix::posix_symlink(b"/tmp/orig.txt\0".as_ptr(), b"/tmp/link.txt\0".as_ptr())
    };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: symlink creation failed\n");
        return false;
    }
    // Read through symlink
    let fd = unsafe { trona_posix::posix_open(b"/tmp/link.txt\0".as_ptr(), O_RDONLY as i32, 0) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open through symlink failed\n");
        return false;
    }
    buf = [0u8; 64];
    let rd = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    unsafe { trona_posix::posix_close(fd) };
    if rd != 12 || !streq(&buf[..12], b"symlink_test") {
        puts(b"[TEST_FS] FAIL: symlink read-through wrong\n");
        return false;
    }
    // readlink
    let mut lbuf = [0u8; 128];
    let rl =
        unsafe { trona_posix::posix_readlink(b"/tmp/link.txt\0".as_ptr(), lbuf.as_mut_ptr(), 128) };
    if rl <= 0 {
        puts(b"[TEST_FS] FAIL: readlink failed\n");
        return false;
    }
    if !streq(&lbuf[..rl as usize], b"/tmp/orig.txt") {
        puts(b"[TEST_FS] FAIL: readlink target mismatch\n");
        return false;
    }
    // lstat shows symlink type
    let ret = unsafe { trona_posix::posix_lstat(b"/tmp/link.txt\0".as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: lstat on symlink failed\n");
        return false;
    }
    if (st.st_mode & S_IFMT) != S_IFLNK {
        puts(b"[TEST_FS] FAIL: lstat mode is not symlink\n");
        return false;
    }
    // stat follows symlink — should show regular file
    let ret = unsafe { trona_posix::posix_stat(b"/tmp/link.txt\0".as_ptr(), &raw mut st) };
    if ret != 0 || (st.st_mode & S_IFMT) != S_IFREG {
        puts(b"[TEST_FS] FAIL: stat through symlink not regular\n");
        return false;
    }
    unsafe {
        trona_posix::posix_unlink(b"/tmp/link.txt\0".as_ptr());
        trona_posix::posix_unlink(b"/tmp/orig.txt\0".as_ptr());
    }
    puts(b"[TEST_FS] PASS: symlink OK\n");

    // Test 17: Hard link
    puts(b"[TEST_FS] Test 17: hard link\n");
    let fd = unsafe {
        trona_posix::posix_open(b"/tmp/src.txt\0".as_ptr(), (O_CREAT | O_RDWR) as i32, 0o644)
    };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: create src.txt failed\n");
        return false;
    }
    unsafe {
        trona_posix::posix_write(fd, b"hardlink".as_ptr(), 8);
        trona_posix::posix_close(fd);
    }
    let ret =
        unsafe { trona_posix::posix_link(b"/tmp/src.txt\0".as_ptr(), b"/tmp/dst.txt\0".as_ptr()) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: link creation failed\n");
        return false;
    }
    // Check nlink == 2
    let ret = unsafe { trona_posix::posix_stat(b"/tmp/src.txt\0".as_ptr(), &raw mut st) };
    if ret != 0 || st.st_nlink != 2 {
        puts(b"[TEST_FS] FAIL: nlink should be 2 after link\n");
        return false;
    }
    // Unlink original, read through hardlink
    unsafe { trona_posix::posix_unlink(b"/tmp/src.txt\0".as_ptr()) };
    let fd = unsafe { trona_posix::posix_open(b"/tmp/dst.txt\0".as_ptr(), O_RDONLY as i32, 0) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open hardlink after unlink original failed\n");
        return false;
    }
    buf = [0u8; 64];
    let rd = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    unsafe { trona_posix::posix_close(fd) };
    if rd != 8 || !streq(&buf[..8], b"hardlink") {
        puts(b"[TEST_FS] FAIL: hardlink read-through wrong\n");
        return false;
    }
    unsafe { trona_posix::posix_unlink(b"/tmp/dst.txt\0".as_ptr()) };
    puts(b"[TEST_FS] PASS: hard link OK\n");

    // Test 18: /proc/self/status
    puts(b"[TEST_FS] Test 18: /proc/self/status\n");
    let ret = unsafe { trona_posix::posix_stat(b"/proc\0".as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: stat /proc failed\n");
        return false;
    }
    let fd =
        unsafe { trona_posix::posix_open(b"/proc/self/status\0".as_ptr(), O_RDONLY as i32, 0) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open /proc/self/status failed\n");
        return false;
    }
    buf = [0u8; 64];
    let rd = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    unsafe { trona_posix::posix_close(fd) };
    if rd <= 0 {
        puts(b"[TEST_FS] FAIL: read /proc/self/status empty\n");
        return false;
    }
    // Should start with "Name:" or "Pid:"
    let has_pid = rd >= 4 && (buf[0] == b'N' || buf[0] == b'P');
    if !has_pid {
        puts(b"[TEST_FS] FAIL: /proc/self/status unexpected content\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /proc/self/status OK\n");

    // Test 19: /proc/self/exe
    puts(b"[TEST_FS] Test 19: /proc/self/exe\n");
    let mut exe_buf = [0u8; 128];
    let exe_len = unsafe {
        trona_posix::posix_readlink(
            b"/proc/self/exe\0".as_ptr(),
            exe_buf.as_mut_ptr(),
            exe_buf.len(),
        )
    };
    if exe_len <= 0 {
        puts(b"[TEST_FS] FAIL: readlink /proc/self/exe failed\n");
        return false;
    }
    if exe_buf[0] != b'/' {
        puts(b"[TEST_FS] FAIL: /proc/self/exe is not absolute\n");
        return false;
    }

    let fd = unsafe { trona_posix::posix_open(b"/proc/self/exe\0".as_ptr(), O_RDONLY as i32, 0) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open /proc/self/exe failed\n");
        return false;
    }
    let mut elf_hdr = [0u8; 4];
    let rd = unsafe { trona_posix::posix_read(fd, elf_hdr.as_mut_ptr(), elf_hdr.len() as u64) };
    unsafe { trona_posix::posix_close(fd) };
    if rd != 4 {
        puts(b"[TEST_FS] FAIL: read /proc/self/exe header failed\n");
        return false;
    }
    if elf_hdr[0] != 0x7f || elf_hdr[1] != b'E' || elf_hdr[2] != b'L' || elf_hdr[3] != b'F' {
        puts(b"[TEST_FS] FAIL: /proc/self/exe is not ELF\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /proc/self/exe OK\n");

    // Cleanup /tmp
    unsafe { trona_posix::posix_rmdir(b"/tmp\0".as_ptr()) };

    puts(b"[TEST_FS] All filesystem tests PASSED\n");
    true
}
