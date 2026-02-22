//! Filesystem tests - exercises VFS ramfs operations
//! Ported from userland/fstest/main.c (12 tests)
//! SPDX-License-Identifier: GPL-2.0-only

use salty::consts::*;
use salty::posix;
use salty::posix_mm;
use salty::serial;
use salty::types::*;

const CAP_MMSRV_EP: u64 = 7;

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

pub fn run() -> bool {
    puts(b"[TEST_FS] Starting filesystem tests\n");

    // Initialize posix_mm with the mmsrv endpoint (slot 7)
    unsafe {
        posix_mm::posix_mm_init(CAP_MMSRV_EP);
    }

    // Test 1: stat /dev/console
    puts(b"[TEST_FS] Test 1: stat /dev/console\n");
    let mut st = SaltyStat::zeroed();
    let ret = unsafe { posix::posix_stat(b"/dev/console\0".as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: stat /dev/console returned error\n");
        return false;
    }
    if (st.st_mode & S_IFMT) != S_IFCHR {
        puts(b"[TEST_FS] FAIL: /dev/console is not a char device\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /dev/console is a char device\n");

    // Test 2: stat /initrd
    puts(b"[TEST_FS] Test 2: stat /initrd\n");
    let ret = unsafe { posix::posix_stat(b"/initrd\0".as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: stat /initrd returned error\n");
        return false;
    }
    if (st.st_mode & S_IFMT) != S_IFDIR {
        puts(b"[TEST_FS] FAIL: /initrd is not a directory\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /initrd is a directory\n");

    // Test 3: opendir /initrd + readdir
    puts(b"[TEST_FS] Test 3: opendir/readdir /initrd\n");
    let dir_fd = unsafe { posix::posix_opendir(b"/initrd\0".as_ptr()) };
    if dir_fd < 0 {
        puts(b"[TEST_FS] FAIL: opendir /initrd failed\n");
        return false;
    }

    let mut dent = SaltyDirent::zeroed();
    let mut file_count = 0;
    while unsafe { posix::posix_readdir(dir_fd, &raw mut dent) } != 0 {
        puts(b"[TEST_FS]   ");
        serial::serial_puts(&dent.d_name[..dent.d_namlen as usize]);
        puts(b"\n");
        file_count += 1;
    }
    unsafe { posix::posix_closedir(dir_fd) };

    if file_count == 0 {
        puts(b"[TEST_FS] FAIL: /initrd is empty\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: listed initrd entries\n");

    // Test 4: access
    puts(b"[TEST_FS] Test 4: access checks\n");
    let ret = unsafe { posix::posix_access(b"/dev/console\0".as_ptr(), F_OK as i32) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: access /dev/console F_OK failed\n");
        return false;
    }
    let ret = unsafe { posix::posix_access(b"/nonexistent\0".as_ptr(), F_OK as i32) };
    if ret == 0 {
        puts(b"[TEST_FS] FAIL: access /nonexistent should have failed\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: access checks OK\n");

    // Test 5: mkdir /tmp
    puts(b"[TEST_FS] Test 5: mkdir /tmp\n");
    let ret = unsafe { posix::posix_mkdir(b"/tmp\0".as_ptr(), 0o755) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: mkdir /tmp returned error\n");
        return false;
    }
    let ret = unsafe { posix::posix_stat(b"/tmp\0".as_ptr(), &raw mut st) };
    if ret != 0 || (st.st_mode & S_IFMT) != S_IFDIR {
        puts(b"[TEST_FS] FAIL: /tmp is not a directory after mkdir\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: mkdir /tmp OK\n");

    // Test 6: create + write + read round-trip
    puts(b"[TEST_FS] Test 6: file create/write/read round-trip\n");
    let fd = unsafe { posix::posix_open(b"/tmp/test.txt\0".as_ptr(), (O_CREAT | O_RDWR) as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open /tmp/test.txt O_CREAT failed\n");
        return false;
    }

    let test_data = b"Hello, SaltyOS filesystem!";
    let written = unsafe { posix::posix_write(fd, test_data.as_ptr(), test_data.len() as u64) };
    if written != test_data.len() as i64 {
        puts(b"[TEST_FS] FAIL: write returned wrong count\n");
        return false;
    }
    unsafe { posix::posix_close(fd) };

    // Re-open and read back
    let fd = unsafe { posix::posix_open(b"/tmp/test.txt\0".as_ptr(), O_RDONLY as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: re-open /tmp/test.txt failed\n");
        return false;
    }

    let mut buf = [0u8; 64];
    let rd = unsafe { posix::posix_read(fd, buf.as_mut_ptr(), 64) };
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
    let off = unsafe { posix::posix_lseek(fd, 7, SEEK_SET as i32) };
    if off != 7 {
        puts(b"[TEST_FS] FAIL: lseek SEEK_SET returned wrong offset\n");
        return false;
    }

    buf = [0u8; 64];
    let rd = unsafe { posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    if rd <= 0 || buf[0] != b'S' {
        puts(b"[TEST_FS] FAIL: read after lseek got wrong data\n");
        return false;
    }
    unsafe { posix::posix_close(fd) };
    puts(b"[TEST_FS] PASS: lseek OK\n");

    // Test 8: fstat on an open file
    puts(b"[TEST_FS] Test 8: fstat\n");
    let fd = unsafe { posix::posix_open(b"/tmp/test.txt\0".as_ptr(), O_RDONLY as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open for fstat failed\n");
        return false;
    }
    let ret = unsafe { posix::posix_fstat(fd, &raw mut st) };
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
    unsafe { posix::posix_close(fd) };
    puts(b"[TEST_FS] PASS: fstat OK\n");

    // Test 9: unlink
    puts(b"[TEST_FS] Test 9: unlink\n");
    let ret = unsafe { posix::posix_unlink(b"/tmp/test.txt\0".as_ptr()) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: unlink returned error\n");
        return false;
    }
    let ret = unsafe { posix::posix_access(b"/tmp/test.txt\0".as_ptr(), F_OK as i32) };
    if ret == 0 {
        puts(b"[TEST_FS] FAIL: file still exists after unlink\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: unlink OK\n");

    // Test 10: rmdir
    puts(b"[TEST_FS] Test 10: rmdir /tmp\n");
    let ret = unsafe { posix::posix_rmdir(b"/tmp\0".as_ptr()) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: rmdir /tmp returned error\n");
        return false;
    }
    let ret = unsafe { posix::posix_access(b"/tmp\0".as_ptr(), F_OK as i32) };
    if ret == 0 {
        puts(b"[TEST_FS] FAIL: /tmp still exists after rmdir\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: rmdir OK\n");

    // Test 11: opendir /dev + readdir
    puts(b"[TEST_FS] Test 11: readdir /dev\n");
    let dir_fd = unsafe { posix::posix_opendir(b"/dev\0".as_ptr()) };
    if dir_fd < 0 {
        puts(b"[TEST_FS] FAIL: opendir /dev failed\n");
        return false;
    }

    let mut found_console = false;
    let mut found_null = false;
    let mut found_zero = false;
    while unsafe { posix::posix_readdir(dir_fd, &raw mut dent) } != 0 {
        let name = &dent.d_name[..dent.d_namlen as usize];
        if streq(name, b"console") {
            found_console = true;
        }
        if streq(name, b"null") {
            found_null = true;
        }
        if streq(name, b"zero") {
            found_zero = true;
        }
    }
    unsafe { posix::posix_closedir(dir_fd) };

    if !found_console || !found_null || !found_zero {
        puts(b"[TEST_FS] FAIL: missing device entries in /dev\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /dev contains console, null, zero\n");

    // Test 12: rename
    puts(b"[TEST_FS] Test 12: rename\n");
    let ret = unsafe { posix::posix_mkdir(b"/tmp2\0".as_ptr(), 0o755) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: mkdir /tmp2 failed\n");
        return false;
    }
    let fd = unsafe { posix::posix_open(b"/tmp2/a.txt\0".as_ptr(), (O_CREAT | O_RDWR) as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: create /tmp2/a.txt failed\n");
        return false;
    }
    unsafe {
        posix::posix_write(fd, b"rename".as_ptr(), 6);
        posix::posix_close(fd);
    }

    let ret = unsafe { posix::posix_rename(b"/tmp2/a.txt\0".as_ptr(), b"/tmp2/b.txt\0".as_ptr()) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: rename failed\n");
        return false;
    }

    let ret = unsafe { posix::posix_access(b"/tmp2/a.txt\0".as_ptr(), F_OK as i32) };
    if ret == 0 {
        puts(b"[TEST_FS] FAIL: old name still exists after rename\n");
        return false;
    }

    let fd = unsafe { posix::posix_open(b"/tmp2/b.txt\0".as_ptr(), O_RDONLY as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open renamed file failed\n");
        return false;
    }
    buf = [0u8; 64];
    let rd = unsafe { posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    unsafe { posix::posix_close(fd) };
    if rd != 6 || buf[0] != b'r' {
        puts(b"[TEST_FS] FAIL: renamed file content wrong\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: rename OK\n");

    // Cleanup
    unsafe {
        posix::posix_unlink(b"/tmp2/b.txt\0".as_ptr());
        posix::posix_rmdir(b"/tmp2\0".as_ptr());
    }

    // Test 13: /dev/urandom
    puts(b"[TEST_FS] Test 13: /dev/urandom\n");
    let fd = unsafe { posix::posix_open(b"/dev/urandom\0".as_ptr(), O_RDONLY as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open /dev/urandom failed\n");
        return false;
    }
    let mut ubuf1 = [0u8; 32];
    let mut ubuf2 = [0u8; 32];
    let r1 = unsafe { posix::posix_read(fd, ubuf1.as_mut_ptr(), 32) };
    let r2 = unsafe { posix::posix_read(fd, ubuf2.as_mut_ptr(), 32) };
    unsafe { posix::posix_close(fd) };
    if r1 != 32 || r2 != 32 {
        puts(b"[TEST_FS] FAIL: urandom read count wrong\n");
        return false;
    }
    // Check non-zero (probabilistic but extremely unlikely to fail)
    let mut all_zero = true;
    for i in 0..32 {
        if ubuf1[i] != 0 { all_zero = false; break; }
    }
    if all_zero {
        puts(b"[TEST_FS] FAIL: urandom returned all zeros\n");
        return false;
    }
    // Two reads should differ
    let mut same = true;
    for i in 0..32 {
        if ubuf1[i] != ubuf2[i] { same = false; break; }
    }
    if same {
        puts(b"[TEST_FS] FAIL: two urandom reads identical\n");
        return false;
    }
    puts(b"[TEST_FS] PASS: /dev/urandom OK\n");

    // Test 14: Long path (>64 bytes)
    puts(b"[TEST_FS] Test 14: long path\n");
    unsafe { posix::posix_mkdir(b"/tmp\0".as_ptr(), 0o755) };
    unsafe { posix::posix_mkdir(b"/tmp/a_very_long_directory_name_here\0".as_ptr(), 0o755) };
    // Path = /tmp/a_very_long_directory_name_here/test_long_path.txt (total > 64 bytes)
    let long_path = b"/tmp/a_very_long_directory_name_here/test_long_path.txt\0";
    let fd = unsafe { posix::posix_open(long_path.as_ptr(), (O_CREAT | O_RDWR) as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open long path failed\n");
        return false;
    }
    unsafe {
        posix::posix_write(fd, b"long".as_ptr(), 4);
        posix::posix_close(fd);
    }
    let ret = unsafe { posix::posix_stat(long_path.as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: stat long path failed\n");
        return false;
    }
    // Cleanup
    unsafe {
        posix::posix_unlink(long_path.as_ptr());
        posix::posix_rmdir(b"/tmp/a_very_long_directory_name_here\0".as_ptr());
    }
    puts(b"[TEST_FS] PASS: long path OK\n");

    // Test 15: Large file (>8KB)
    puts(b"[TEST_FS] Test 15: large file write/read\n");
    let fd = unsafe { posix::posix_open(b"/tmp/bigfile\0".as_ptr(), (O_CREAT | O_RDWR) as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: create bigfile failed\n");
        return false;
    }
    // Write 10KB of data (pattern: byte position mod 251)
    let mut wbuf = [0u8; 128];
    let target_size: usize = 10240;
    let mut written_total: usize = 0;
    while written_total < target_size {
        let chunk = if target_size - written_total < 128 { target_size - written_total } else { 128 };
        for j in 0..chunk {
            wbuf[j] = ((written_total + j) % 251) as u8;
        }
        let w = unsafe { posix::posix_write(fd, wbuf.as_ptr(), chunk as u64) };
        if w <= 0 {
            puts(b"[TEST_FS] FAIL: large write returned 0\n");
            return false;
        }
        written_total += w as usize;
    }
    unsafe { posix::posix_close(fd) };

    // Re-open and verify
    let fd = unsafe { posix::posix_open(b"/tmp/bigfile\0".as_ptr(), O_RDONLY as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: re-open bigfile failed\n");
        return false;
    }
    let mut read_total: usize = 0;
    let mut rbuf = [0u8; 128];
    loop {
        let r = unsafe { posix::posix_read(fd, rbuf.as_mut_ptr(), 128) };
        if r <= 0 { break; }
        for j in 0..r as usize {
            if rbuf[j] != ((read_total + j) % 251) as u8 {
                puts(b"[TEST_FS] FAIL: large file data mismatch\n");
                unsafe { posix::posix_close(fd) };
                return false;
            }
        }
        read_total += r as usize;
    }
    unsafe { posix::posix_close(fd) };
    if read_total != target_size {
        puts(b"[TEST_FS] FAIL: large file size mismatch\n");
        return false;
    }
    unsafe { posix::posix_unlink(b"/tmp/bigfile\0".as_ptr()) };
    puts(b"[TEST_FS] PASS: large file (10KB) write/read OK\n");

    // Test 16: Symlink
    puts(b"[TEST_FS] Test 16: symlink\n");
    let fd = unsafe { posix::posix_open(b"/tmp/orig.txt\0".as_ptr(), (O_CREAT | O_RDWR) as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: create orig.txt failed\n");
        return false;
    }
    unsafe {
        posix::posix_write(fd, b"symlink_test".as_ptr(), 12);
        posix::posix_close(fd);
    }
    let ret = unsafe { posix::posix_symlink(b"/tmp/orig.txt\0".as_ptr(), b"/tmp/link.txt\0".as_ptr()) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: symlink creation failed\n");
        return false;
    }
    // Read through symlink
    let fd = unsafe { posix::posix_open(b"/tmp/link.txt\0".as_ptr(), O_RDONLY as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open through symlink failed\n");
        return false;
    }
    buf = [0u8; 64];
    let rd = unsafe { posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    unsafe { posix::posix_close(fd) };
    if rd != 12 || !streq(&buf[..12], b"symlink_test") {
        puts(b"[TEST_FS] FAIL: symlink read-through wrong\n");
        return false;
    }
    // readlink
    let mut lbuf = [0u8; 128];
    let rl = unsafe { posix::posix_readlink(b"/tmp/link.txt\0".as_ptr(), lbuf.as_mut_ptr(), 128) };
    if rl <= 0 {
        puts(b"[TEST_FS] FAIL: readlink failed\n");
        return false;
    }
    if !streq(&lbuf[..rl as usize], b"/tmp/orig.txt") {
        puts(b"[TEST_FS] FAIL: readlink target mismatch\n");
        return false;
    }
    // lstat shows symlink type
    let ret = unsafe { posix::posix_lstat(b"/tmp/link.txt\0".as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: lstat on symlink failed\n");
        return false;
    }
    if (st.st_mode & S_IFMT) != S_IFLNK {
        puts(b"[TEST_FS] FAIL: lstat mode is not symlink\n");
        return false;
    }
    // stat follows symlink — should show regular file
    let ret = unsafe { posix::posix_stat(b"/tmp/link.txt\0".as_ptr(), &raw mut st) };
    if ret != 0 || (st.st_mode & S_IFMT) != S_IFREG {
        puts(b"[TEST_FS] FAIL: stat through symlink not regular\n");
        return false;
    }
    unsafe {
        posix::posix_unlink(b"/tmp/link.txt\0".as_ptr());
        posix::posix_unlink(b"/tmp/orig.txt\0".as_ptr());
    }
    puts(b"[TEST_FS] PASS: symlink OK\n");

    // Test 17: Hard link
    puts(b"[TEST_FS] Test 17: hard link\n");
    let fd = unsafe { posix::posix_open(b"/tmp/src.txt\0".as_ptr(), (O_CREAT | O_RDWR) as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: create src.txt failed\n");
        return false;
    }
    unsafe {
        posix::posix_write(fd, b"hardlink".as_ptr(), 8);
        posix::posix_close(fd);
    }
    let ret = unsafe { posix::posix_link(b"/tmp/src.txt\0".as_ptr(), b"/tmp/dst.txt\0".as_ptr()) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: link creation failed\n");
        return false;
    }
    // Check nlink == 2
    let ret = unsafe { posix::posix_stat(b"/tmp/src.txt\0".as_ptr(), &raw mut st) };
    if ret != 0 || st.st_nlink != 2 {
        puts(b"[TEST_FS] FAIL: nlink should be 2 after link\n");
        return false;
    }
    // Unlink original, read through hardlink
    unsafe { posix::posix_unlink(b"/tmp/src.txt\0".as_ptr()) };
    let fd = unsafe { posix::posix_open(b"/tmp/dst.txt\0".as_ptr(), O_RDONLY as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open hardlink after unlink original failed\n");
        return false;
    }
    buf = [0u8; 64];
    let rd = unsafe { posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    unsafe { posix::posix_close(fd) };
    if rd != 8 || !streq(&buf[..8], b"hardlink") {
        puts(b"[TEST_FS] FAIL: hardlink read-through wrong\n");
        return false;
    }
    unsafe { posix::posix_unlink(b"/tmp/dst.txt\0".as_ptr()) };
    puts(b"[TEST_FS] PASS: hard link OK\n");

    // Test 18: /proc/self/status
    puts(b"[TEST_FS] Test 18: /proc/self/status\n");
    let ret = unsafe { posix::posix_stat(b"/proc\0".as_ptr(), &raw mut st) };
    if ret != 0 {
        puts(b"[TEST_FS] FAIL: stat /proc failed\n");
        return false;
    }
    let fd = unsafe { posix::posix_open(b"/proc/self/status\0".as_ptr(), O_RDONLY as i32) };
    if fd < 0 {
        puts(b"[TEST_FS] FAIL: open /proc/self/status failed\n");
        return false;
    }
    buf = [0u8; 64];
    let rd = unsafe { posix::posix_read(fd, buf.as_mut_ptr(), 64) };
    unsafe { posix::posix_close(fd) };
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

    // Cleanup /tmp
    unsafe { posix::posix_rmdir(b"/tmp\0".as_ptr()) };

    puts(b"[TEST_FS] All filesystem tests PASSED\n");
    true
}
