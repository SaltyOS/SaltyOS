//! SaltyFS filesystem tests - exercises on-disk filesystem operations
//! All tests operate under /mnt/data/ (SaltyFS mount point).
//! Tests are skipped gracefully if no data disk is present.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::serial;
use trona::serial::LineBuf;
use trona::types::core::*;
use trona_posix::proc as posix;
use trona_posix::*;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

/// Check if /mnt/data is accessible (SaltyFS is mounted).
fn saltyfs_available() -> bool {
    let mut st = TronaStat::zeroed();
    let ret = unsafe { trona_posix::posix_stat(b"/mnt/data\0".as_ptr(), &raw mut st) };
    ret == 0
}

pub fn run() -> bool {
    puts(b"[TEST_SALTYFS] Starting SaltyFS tests\n");

    if !saltyfs_available() {
        puts(b"[TEST_SALTYFS] /mnt/data not available - skipping (PASS)\n");
        return true;
    }

    // Test 1: stat /mnt/data
    puts(b"[TEST_SALTYFS] Test 1: stat /mnt/data\n");
    {
        let mut st = TronaStat::zeroed();
        let ret = unsafe { trona_posix::posix_stat(b"/mnt/data\0".as_ptr(), &raw mut st) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: stat /mnt/data returned error\n");
            return false;
        }
        if (st.st_mode & S_IFMT) != S_IFDIR {
            puts(b"[TEST_SALTYFS] FAIL: /mnt/data is not a directory\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: /mnt/data is a directory\n");
    }

    // Test 2: mkdir /mnt/data/testdir
    puts(b"[TEST_SALTYFS] Test 2: mkdir /mnt/data/testdir\n");
    {
        let ret = unsafe { trona_posix::posix_mkdir(b"/mnt/data/testdir\0".as_ptr(), 0o755) };
        if ret != 0 {
            // On re-run the directory may already exist; treat that as success
            let mut st2 = TronaStat::zeroed();
            let sret =
                unsafe { trona_posix::posix_stat(b"/mnt/data/testdir\0".as_ptr(), &raw mut st2) };
            if sret != 0 || (st2.st_mode & S_IFMT) != S_IFDIR {
                puts(b"[TEST_SALTYFS] FAIL: mkdir /mnt/data/testdir failed\n");
                return false;
            }
        }
        let mut st = TronaStat::zeroed();
        let ret = unsafe { trona_posix::posix_stat(b"/mnt/data/testdir\0".as_ptr(), &raw mut st) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: stat /mnt/data/testdir failed\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: mkdir succeeded\n");
    }

    // Test 3: create + write + read round-trip
    puts(b"[TEST_SALTYFS] Test 3: create + write + read file\n");
    {
        let path = b"/mnt/data/testdir/test.txt\0";
        let fd = unsafe {
            trona_posix::posix_open(path.as_ptr(), (O_CREAT | O_TRUNC | O_WRONLY) as i32, 0o644)
        };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open for write failed\n");
            return false;
        }

        let data = b"Hello SaltyFS!";
        let written = unsafe { trona_posix::posix_write(fd, data.as_ptr(), data.len() as u64) };
        unsafe { trona_posix::posix_close(fd) };

        if written != data.len() as i64 {
            puts(b"[TEST_SALTYFS] FAIL: write returned wrong count\n");
            return false;
        }

        let fd = unsafe { trona_posix::posix_open(path.as_ptr(), O_RDONLY as i32, 0) };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open for read failed\n");
            return false;
        }

        let mut buf = [0u8; 64];
        let read_count = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), buf.len() as u64) };
        unsafe { trona_posix::posix_close(fd) };

        if read_count != data.len() as i64 {
            puts(b"[TEST_SALTYFS] FAIL: read returned wrong count\n");
            return false;
        }

        let mut ok = true;
        for i in 0..data.len() {
            if buf[i] != data[i] {
                ok = false;
                break;
            }
        }
        if !ok {
            puts(b"[TEST_SALTYFS] FAIL: read data mismatch\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: write + read round-trip OK\n");
    }

    // Test 4: large file write + read (>4KB, multi-block)
    puts(b"[TEST_SALTYFS] Test 4: large file write + read (8KB)\n");
    {
        let path = b"/mnt/data/testdir/large.bin\0";
        let fd =
            unsafe { trona_posix::posix_open(path.as_ptr(), (O_CREAT | O_WRONLY) as i32, 0o644) };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open large file for write failed\n");
            return false;
        }

        // Write 8KB of patterned data in chunks
        let mut pattern = [0u8; 256];
        for i in 0..256 {
            pattern[i] = i as u8;
        }

        let total_size: usize = 8192;
        let mut written_total: usize = 0;
        while written_total < total_size {
            let chunk = core::cmp::min(pattern.len(), total_size - written_total);
            let w = unsafe { trona_posix::posix_write(fd, pattern.as_ptr(), chunk as u64) };
            if w <= 0 {
                puts(b"[TEST_SALTYFS] FAIL: write chunk failed\n");
                unsafe { trona_posix::posix_close(fd) };
                return false;
            }
            written_total += w as usize;
        }
        unsafe { trona_posix::posix_close(fd) };

        // Read back and verify
        let fd = unsafe { trona_posix::posix_open(path.as_ptr(), O_RDONLY as i32, 0) };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open large file for read failed\n");
            return false;
        }

        let mut read_total: usize = 0;
        let mut read_buf = [0u8; 256];
        let mut data_ok = true;
        while read_total < total_size {
            let r = unsafe {
                trona_posix::posix_read(fd, read_buf.as_mut_ptr(), read_buf.len() as u64)
            };
            if r <= 0 {
                break;
            }
            for i in 0..r as usize {
                let expected = ((read_total + i) % 256) as u8;
                if read_buf[i] != expected {
                    data_ok = false;
                    {
                        let mut lb = LineBuf::new();
                        lb.str(b"[TEST_SALTYFS] mismatch at offset ");
                        lb.dec((read_total + i) as u64);
                        lb.str(b": expected ");
                        lb.hex(expected as u64);
                        lb.str(b" got ");
                        lb.hex(read_buf[i] as u64);
                        lb.str(b"\n");
                        lb.flush();
                    }
                    break;
                }
            }
            if !data_ok {
                break;
            }
            read_total += r as usize;
        }
        unsafe { trona_posix::posix_close(fd) };

        if !data_ok || read_total != total_size {
            {
                let mut lb = LineBuf::new();
                lb.str(b"[TEST_SALTYFS] FAIL: large file read_total=");
                lb.dec(read_total as u64);
                lb.str(b" expected=");
                lb.dec(total_size as u64);
                lb.str(b"\n");
                lb.flush();
            }
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: large file 8KB round-trip OK\n");
    }

    // Test 5: readdir /mnt/data/testdir
    puts(b"[TEST_SALTYFS] Test 5: readdir /mnt/data/testdir\n");
    {
        let dir_fd = unsafe { trona_posix::posix_opendir(b"/mnt/data/testdir\0".as_ptr()) };
        if dir_fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: opendir /mnt/data/testdir failed\n");
            return false;
        }

        let mut dent = TronaDirent::zeroed();
        let mut count = 0u32;
        while unsafe { trona_posix::posix_readdir(dir_fd, &raw mut dent) } != 0 {
            count += 1;
        }
        unsafe { trona_posix::posix_closedir(dir_fd) };

        if count < 2 {
            puts(b"[TEST_SALTYFS] FAIL: readdir found fewer than 2 entries\n");
            return false;
        }
        {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SALTYFS] PASS: readdir found ");
            lb.dec(count as u64);
            lb.str(b" entries\n");
            lb.flush();
        }
    }

    // Test 6: lseek on mounted file
    puts(b"[TEST_SALTYFS] Test 6: lseek on mounted file\n");
    {
        let path = b"/mnt/data/testdir/test.txt\0";
        let fd = unsafe { trona_posix::posix_open(path.as_ptr(), O_RDONLY as i32, 0) };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open for lseek test failed\n");
            return false;
        }

        // Seek to offset 6
        let off = unsafe { trona_posix::posix_lseek(fd, 6, SEEK_SET as i32) };
        if off != 6 {
            puts(b"[TEST_SALTYFS] FAIL: lseek SET failed\n");
            unsafe { trona_posix::posix_close(fd) };
            return false;
        }

        let mut buf = [0u8; 8];
        let r = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 8) };
        unsafe { trona_posix::posix_close(fd) };

        if r < 8 || buf[0] != b'S' || buf[1] != b'a' || buf[2] != b'l' {
            puts(b"[TEST_SALTYFS] FAIL: read after lseek returned wrong data\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: lseek + read OK\n");
    }

    // Test 7: fstat on mounted file
    puts(b"[TEST_SALTYFS] Test 7: fstat on mounted file\n");
    {
        let path = b"/mnt/data/testdir/test.txt\0";
        let fd = unsafe { trona_posix::posix_open(path.as_ptr(), O_RDONLY as i32, 0) };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open for fstat test failed\n");
            return false;
        }

        let mut st = TronaStat::zeroed();
        let ret = unsafe { trona_posix::posix_fstat(fd, &raw mut st) };
        unsafe { trona_posix::posix_close(fd) };

        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: fstat failed\n");
            return false;
        }
        if st.st_size != 14 {
            let mut lb = LineBuf::new();
            lb.str(b"[TEST_SALTYFS] FAIL: fstat size=");
            lb.dec(st.st_size);
            lb.str(b" expected 14\n");
            lb.flush();
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: fstat size=14 OK\n");
    }

    // Test 8: truncate file
    puts(b"[TEST_SALTYFS] Test 8: truncate file\n");
    {
        let path = b"/mnt/data/testdir/trunc.txt\0";
        let fd =
            unsafe { trona_posix::posix_open(path.as_ptr(), (O_CREAT | O_WRONLY) as i32, 0o644) };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open for truncate test failed\n");
            return false;
        }
        let data = b"0123456789ABCDEF";
        unsafe { trona_posix::posix_write(fd, data.as_ptr(), data.len() as u64) };
        unsafe { trona_posix::posix_close(fd) };

        // Open for truncate via ftruncate
        let fd2 = unsafe { trona_posix::posix_open(path.as_ptr(), O_WRONLY as i32, 0) };
        if fd2 < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open for ftruncate failed\n");
            return false;
        }
        let ret = unsafe { trona_posix::posix_ftruncate(fd2, 8) };
        unsafe { trona_posix::posix_close(fd2) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: ftruncate failed\n");
            return false;
        }

        let mut st = TronaStat::zeroed();
        let ret = unsafe { trona_posix::posix_stat(path.as_ptr(), &raw mut st) };
        if ret != 0 || st.st_size != 8 {
            puts(b"[TEST_SALTYFS] FAIL: stat after truncate wrong size\n");
            return false;
        }

        // Read back truncated data
        let fd = unsafe { trona_posix::posix_open(path.as_ptr(), O_RDONLY as i32, 0) };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open after truncate failed\n");
            return false;
        }
        let mut buf = [0u8; 16];
        let r = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 16) };
        unsafe { trona_posix::posix_close(fd) };
        if r != 8 || buf[0] != b'0' || buf[7] != b'7' {
            puts(b"[TEST_SALTYFS] FAIL: data after truncate wrong\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: truncate OK\n");
    }

    // Test 9: rename file
    puts(b"[TEST_SALTYFS] Test 9: rename file\n");
    {
        let old = b"/mnt/data/testdir/trunc.txt\0";
        let new = b"/mnt/data/testdir/renamed.txt\0";
        let ret = unsafe { trona_posix::posix_rename(old.as_ptr(), new.as_ptr()) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: rename failed\n");
            return false;
        }

        let mut st = TronaStat::zeroed();
        let ret = unsafe { trona_posix::posix_stat(new.as_ptr(), &raw mut st) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: stat renamed file failed\n");
            return false;
        }
        let ret = unsafe { trona_posix::posix_stat(old.as_ptr(), &raw mut st) };
        if ret == 0 {
            puts(b"[TEST_SALTYFS] FAIL: old path still exists after rename\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: rename OK\n");
    }

    // Test 10: unlink file
    puts(b"[TEST_SALTYFS] Test 10: unlink file\n");
    {
        let path = b"/mnt/data/testdir/renamed.txt\0";
        let ret = unsafe { trona_posix::posix_unlink(path.as_ptr()) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: unlink failed\n");
            return false;
        }
        let mut st = TronaStat::zeroed();
        let ret = unsafe { trona_posix::posix_stat(path.as_ptr(), &raw mut st) };
        if ret == 0 {
            puts(b"[TEST_SALTYFS] FAIL: file still exists after unlink\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: unlink OK\n");
    }

    // Test 11: symlink + readlink
    puts(b"[TEST_SALTYFS] Test 11: symlink + readlink\n");
    {
        let target = b"/mnt/data/testdir/test.txt\0";
        let link = b"/mnt/data/testdir/link.txt\0";
        let ret = unsafe { trona_posix::posix_symlink(target.as_ptr(), link.as_ptr()) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: symlink failed\n");
            return false;
        }

        let mut buf = [0u8; 128];
        let r = unsafe { trona_posix::posix_readlink(link.as_ptr(), buf.as_mut_ptr(), 128) };
        if r <= 0 {
            puts(b"[TEST_SALTYFS] FAIL: readlink failed\n");
            return false;
        }

        let expected = b"/mnt/data/testdir/test.txt";
        let r_len = r as usize;
        if r_len != expected.len() {
            {
                let mut lb = LineBuf::new();
                lb.str(b"[TEST_SALTYFS] FAIL: readlink len=");
                lb.dec(r_len as u64);
                lb.str(b" expected ");
                lb.dec(expected.len() as u64);
                lb.str(b"\n");
                lb.flush();
            }
            return false;
        }

        let mut ok = true;
        for i in 0..r_len {
            if buf[i] != expected[i] {
                ok = false;
                break;
            }
        }
        if !ok {
            puts(b"[TEST_SALTYFS] FAIL: readlink target mismatch\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: symlink + readlink OK\n");
    }

    // Test 12: hard link
    puts(b"[TEST_SALTYFS] Test 12: hard link\n");
    {
        let src = b"/mnt/data/testdir/test.txt\0";
        let dst = b"/mnt/data/testdir/hardlink.txt\0";
        let ret = unsafe { trona_posix::posix_link(src.as_ptr(), dst.as_ptr()) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: link failed\n");
            return false;
        }

        // Read through the hard link
        let fd = unsafe { trona_posix::posix_open(dst.as_ptr(), O_RDONLY as i32, 0) };
        if fd < 0 {
            puts(b"[TEST_SALTYFS] FAIL: open hard link failed\n");
            return false;
        }
        let mut buf = [0u8; 64];
        let r = unsafe { trona_posix::posix_read(fd, buf.as_mut_ptr(), 64) };
        unsafe { trona_posix::posix_close(fd) };

        if r != 14 {
            puts(b"[TEST_SALTYFS] FAIL: read through hard link wrong count\n");
            return false;
        }

        let expected = b"Hello SaltyFS!";
        let mut ok = true;
        for i in 0..14 {
            if buf[i] != expected[i] {
                ok = false;
                break;
            }
        }
        if !ok {
            puts(b"[TEST_SALTYFS] FAIL: hard link data mismatch\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: hard link OK\n");
    }

    // Test 13: rmdir
    puts(b"[TEST_SALTYFS] Test 13: cleanup - unlink files + rmdir\n");
    {
        // Clean up files first
        unsafe {
            trona_posix::posix_unlink(b"/mnt/data/testdir/test.txt\0".as_ptr());
            trona_posix::posix_unlink(b"/mnt/data/testdir/large.bin\0".as_ptr());
            trona_posix::posix_unlink(b"/mnt/data/testdir/link.txt\0".as_ptr());
            trona_posix::posix_unlink(b"/mnt/data/testdir/hardlink.txt\0".as_ptr());
        }

        let ret = unsafe { trona_posix::posix_rmdir(b"/mnt/data/testdir\0".as_ptr()) };
        if ret != 0 {
            puts(b"[TEST_SALTYFS] FAIL: rmdir /mnt/data/testdir failed\n");
            return false;
        }

        let mut st = TronaStat::zeroed();
        let ret = unsafe { trona_posix::posix_stat(b"/mnt/data/testdir\0".as_ptr(), &raw mut st) };
        if ret == 0 {
            puts(b"[TEST_SALTYFS] FAIL: testdir still exists after rmdir\n");
            return false;
        }
        puts(b"[TEST_SALTYFS] PASS: cleanup + rmdir OK\n");
    }

    puts(b"[TEST_SALTYFS] All SaltyFS tests passed\n");
    true
}
