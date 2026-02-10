//! Pipe and dup test suite
//! SPDX-License-Identifier: GPL-2.0-only

use salty::posix;
use salty::serial;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

/// Test basic pipe read/write
fn test_basic_pipe() -> bool {
    let mut fds = [0i32; 2];
    let ret = unsafe { posix::posix_pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        puts(b"  pipe() failed\n");
        return false;
    }

    let read_fd = fds[0];
    let write_fd = fds[1];

    // Write "hello" to pipe
    let data = b"hello";
    let written = unsafe { posix::posix_write(write_fd, data.as_ptr(), 5) };
    if written != 5 {
        puts(b"  write returned wrong count\n");
        return false;
    }

    // Read from pipe
    let mut buf = [0u8; 16];
    let read_count = unsafe { posix::posix_read(read_fd, buf.as_mut_ptr(), 16) };
    if read_count != 5 {
        puts(b"  read returned wrong count\n");
        return false;
    }
    if buf[0] != b'h' || buf[1] != b'e' || buf[2] != b'l' || buf[3] != b'l' || buf[4] != b'o' {
        puts(b"  read data mismatch\n");
        return false;
    }

    unsafe { posix::posix_close(read_fd) };
    unsafe { posix::posix_close(write_fd) };
    true
}

/// Test EOF on write-end close
fn test_pipe_eof() -> bool {
    let mut fds = [0i32; 2];
    let ret = unsafe { posix::posix_pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        puts(b"  pipe() failed\n");
        return false;
    }

    // Write some data, then close write end
    let data = b"X";
    unsafe { posix::posix_write(fds[1], data.as_ptr(), 1) };
    unsafe { posix::posix_close(fds[1]) };

    // Read the data
    let mut buf = [0u8; 8];
    let n = unsafe { posix::posix_read(fds[0], buf.as_mut_ptr(), 8) };
    if n != 1 || buf[0] != b'X' {
        puts(b"  first read wrong\n");
        return false;
    }

    // Next read should return EOF (0)
    let n2 = unsafe { posix::posix_read(fds[0], buf.as_mut_ptr(), 8) };
    if n2 != 0 {
        puts(b"  expected EOF, got data\n");
        return false;
    }

    unsafe { posix::posix_close(fds[0]) };
    true
}

/// Test dup
fn test_dup() -> bool {
    let mut fds = [0i32; 2];
    let ret = unsafe { posix::posix_pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        puts(b"  pipe() failed\n");
        return false;
    }

    // dup the write end
    let dup_fd = unsafe { posix::posix_dup(fds[1]) };
    if dup_fd < 0 {
        puts(b"  dup() failed\n");
        return false;
    }

    // Close original write fd
    unsafe { posix::posix_close(fds[1]) };

    // Write through dup'd fd should still work (write refcount > 0)
    let data = b"dup";
    let n = unsafe { posix::posix_write(dup_fd, data.as_ptr(), 3) };
    if n != 3 {
        puts(b"  write via dup'd fd failed\n");
        return false;
    }

    // Read should get the data
    let mut buf = [0u8; 8];
    let n = unsafe { posix::posix_read(fds[0], buf.as_mut_ptr(), 8) };
    if n != 3 || buf[0] != b'd' || buf[1] != b'u' || buf[2] != b'p' {
        puts(b"  read after dup write wrong\n");
        return false;
    }

    unsafe { posix::posix_close(dup_fd) };
    unsafe { posix::posix_close(fds[0]) };
    true
}

/// Test dup2
fn test_dup2() -> bool {
    let mut fds = [0i32; 2];
    let ret = unsafe { posix::posix_pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        puts(b"  pipe() failed\n");
        return false;
    }

    // dup2 write end to a specific fd (e.g., fd 20)
    let target_fd = 20;
    let ret = unsafe { posix::posix_dup2(fds[1], target_fd) };
    if ret != target_fd {
        puts(b"  dup2() returned wrong fd\n");
        return false;
    }

    // Close original write fd
    unsafe { posix::posix_close(fds[1]) };

    // Write through dup2'd fd
    let data = b"d2";
    let n = unsafe { posix::posix_write(target_fd, data.as_ptr(), 2) };
    if n != 2 {
        puts(b"  write via dup2'd fd failed\n");
        return false;
    }

    let mut buf = [0u8; 8];
    let n = unsafe { posix::posix_read(fds[0], buf.as_mut_ptr(), 8) };
    if n != 2 || buf[0] != b'd' || buf[1] != b'2' {
        puts(b"  read after dup2 write wrong\n");
        return false;
    }

    unsafe { posix::posix_close(target_fd) };
    unsafe { posix::posix_close(fds[0]) };
    true
}

pub fn run() -> bool {
    puts(b"  [test_pipe] basic pipe r/w...\n");
    if !test_basic_pipe() { return false; }

    puts(b"  [test_pipe] EOF on close...\n");
    if !test_pipe_eof() { return false; }

    puts(b"  [test_pipe] dup...\n");
    if !test_dup() { return false; }

    puts(b"  [test_pipe] dup2...\n");
    if !test_dup2() { return false; }

    true
}
