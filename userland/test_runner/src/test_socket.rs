//! Socket, poll, and shared memory tests
//! Exercises AF_UNIX socketpair, data exchange, poll, SCM_RIGHTS, and POSIX shm
//! SPDX-License-Identifier: GPL-2.0-only

use salty::consts::*;
use salty::posix;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub fn run() -> bool {
    puts(b"[TEST_SOCKET] Starting socket tests\n");

    if !test_socketpair() {
        return false;
    }
    if !test_poll() {
        return false;
    }
    if !test_scm_rights() {
        return false;
    }
    if !test_shm() {
        return false;
    }

    puts(b"[TEST_SOCKET] All socket tests PASSED\n");
    true
}

// ---- Test 1: socketpair + bidirectional data exchange ----
fn test_socketpair() -> bool {
    puts(b"[TEST_SOCKET] Test 1: socketpair + data exchange\n");

    let mut fds: [i32; 2] = [-1, -1];
    let ret = unsafe { posix::posix_socketpair(fds.as_mut_ptr()) };
    if ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: socketpair returned error\n");
        return false;
    }
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] socketpair fds: "); lb.dec(fds[0] as u64); lb.str(b", "); lb.dec(fds[1] as u64); lb.str(b"\n"); lb.flush(); }

    if fds[0] < 0 || fds[1] < 0 {
        puts(b"[TEST_SOCKET] FAIL: invalid fds\n");
        return false;
    }

    // Write "hello" on fds[0], read on fds[1]
    let data = b"hello";
    let written = unsafe { posix::posix_write(fds[0], data.as_ptr(), data.len() as u64) };
    if written != data.len() as i64 {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] FAIL: write returned "); lb.hex(written as u64); lb.str(b"\n"); lb.flush(); }
        return false;
    }

    let mut buf = [0u8; 32];
    let nread = unsafe { posix::posix_read(fds[1], buf.as_mut_ptr(), buf.len() as u64) };
    if nread != data.len() as i64 {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] FAIL: read returned "); lb.hex(nread as u64); lb.str(b"\n"); lb.flush(); }
        return false;
    }

    if &buf[..5] != b"hello" {
        puts(b"[TEST_SOCKET] FAIL: data mismatch\n");
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: socketpair data exchange OK\n");

    // Write in reverse direction
    let data2 = b"world";
    let w2 = unsafe { posix::posix_write(fds[1], data2.as_ptr(), data2.len() as u64) };
    if w2 != data2.len() as i64 {
        puts(b"[TEST_SOCKET] FAIL: reverse write error\n");
        return false;
    }

    let mut buf2 = [0u8; 32];
    let r2 = unsafe { posix::posix_read(fds[0], buf2.as_mut_ptr(), buf2.len() as u64) };
    if r2 != data2.len() as i64 || &buf2[..5] != b"world" {
        puts(b"[TEST_SOCKET] FAIL: reverse read mismatch\n");
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: bidirectional exchange OK\n");

    // Close both ends
    unsafe {
        posix::posix_close(fds[0]);
        posix::posix_close(fds[1]);
    }

    true
}

// ---- Test 2: poll on socket fds ----
fn test_poll() -> bool {
    puts(b"[TEST_SOCKET] Test 2: poll on sockets\n");

    let mut fds: [i32; 2] = [-1, -1];
    let ret = unsafe { posix::posix_socketpair(fds.as_mut_ptr()) };
    if ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: socketpair for poll failed\n");
        return false;
    }

    // Poll fds[1] for POLLIN — should have nothing yet (timeout=0, non-blocking)
    let mut pfd = [PollFd {
        fd: fds[1],
        events: POLLIN,
        revents: 0,
    }];
    let n = unsafe { posix::posix_poll(pfd.as_mut_ptr(), 1, 0) };
    if n < 0 {
        puts(b"[TEST_SOCKET] FAIL: poll returned error\n");
        unsafe {
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }
    if pfd[0].revents & POLLIN != 0 {
        puts(b"[TEST_SOCKET] FAIL: POLLIN set on empty socket\n");
        unsafe {
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: poll empty socket has no POLLIN\n");

    // Write data, then poll again
    let data = b"test";
    unsafe { posix::posix_write(fds[0], data.as_ptr(), data.len() as u64) };

    pfd[0].revents = 0;
    let n2 = unsafe { posix::posix_poll(pfd.as_mut_ptr(), 1, 0) };
    if n2 < 0 {
        puts(b"[TEST_SOCKET] FAIL: poll after write returned error\n");
        unsafe {
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }
    if pfd[0].revents & POLLIN == 0 {
        puts(b"[TEST_SOCKET] FAIL: POLLIN not set after write\n");
        unsafe {
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: poll detects POLLIN after write\n");

    // Drain data
    let mut buf = [0u8; 32];
    unsafe { posix::posix_read(fds[1], buf.as_mut_ptr(), buf.len() as u64) };

    unsafe {
        posix::posix_close(fds[0]);
        posix::posix_close(fds[1]);
    }
    true
}

// ---- Test 3: SCM_RIGHTS (fd passing via sendmsg/recvmsg) ----
fn test_scm_rights() -> bool {
    puts(b"[TEST_SOCKET] Test 3: SCM_RIGHTS fd passing\n");

    // Create socketpair for passing fds
    let mut fds: [i32; 2] = [-1, -1];
    let ret = unsafe { posix::posix_socketpair(fds.as_mut_ptr()) };
    if ret != 0 {
        puts(b"[TEST_SOCKET] FAIL: socketpair for SCM_RIGHTS failed\n");
        return false;
    }

    // Open a file to pass
    let file_fd = unsafe { posix::posix_open(b"/dev/null\0".as_ptr(), O_RDWR as i32) };
    if file_fd < 0 {
        puts(b"[TEST_SOCKET] FAIL: open /dev/null failed\n");
        unsafe {
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }

    // sendmsg: send data + file_fd over fds[0]
    let msg_data = b"fd";
    let fd_to_send: [i32; 1] = [file_fd];
    let sent = unsafe {
        posix::posix_sendmsg(
            fds[0],
            msg_data.as_ptr(),
            msg_data.len() as u64,
            fd_to_send.as_ptr(),
            1,
        )
    };
    if sent < 0 {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] FAIL: sendmsg returned "); lb.hex(sent as u64); lb.str(b"\n"); lb.flush(); }
        unsafe {
            posix::posix_close(file_fd);
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] sendmsg sent "); lb.dec(sent as u64); lb.str(b" bytes + 1 fd\n"); lb.flush(); }

    // recvmsg: receive data + fd on fds[1]
    let mut recv_buf = [0u8; 32];
    let mut recv_fds: [i32; 4] = [-1; 4];
    let mut recv_fd_count: u32 = 4;
    let rcvd = unsafe {
        posix::posix_recvmsg(
            fds[1],
            recv_buf.as_mut_ptr(),
            recv_buf.len() as u64,
            recv_fds.as_mut_ptr(),
            &mut recv_fd_count,
        )
    };
    if rcvd < 0 {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] FAIL: recvmsg returned "); lb.hex(rcvd as u64); lb.str(b"\n"); lb.flush(); }
        unsafe {
            posix::posix_close(file_fd);
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }

    if rcvd != 2 || &recv_buf[..2] != b"fd" {
        puts(b"[TEST_SOCKET] FAIL: recvmsg data mismatch\n");
        unsafe {
            posix::posix_close(file_fd);
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }

    if recv_fd_count != 1 || recv_fds[0] < 0 {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] FAIL: expected 1 fd, got "); lb.dec(recv_fd_count as u64); lb.str(b"\n"); lb.flush(); }
        unsafe {
            posix::posix_close(file_fd);
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }

    { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] received fd="); lb.dec(recv_fds[0] as u64); lb.str(b"\n"); lb.flush(); }

    // Verify the received fd works (write to /dev/null should succeed)
    let wr = unsafe { posix::posix_write(recv_fds[0], b"x".as_ptr(), 1) };
    if wr < 0 {
        puts(b"[TEST_SOCKET] FAIL: write via passed fd failed\n");
        unsafe {
            posix::posix_close(recv_fds[0]);
            posix::posix_close(file_fd);
            posix::posix_close(fds[0]);
            posix::posix_close(fds[1]);
        }
        return false;
    }

    puts(b"[TEST_SOCKET] PASS: SCM_RIGHTS fd passing OK\n");

    unsafe {
        posix::posix_close(recv_fds[0]);
        posix::posix_close(file_fd);
        posix::posix_close(fds[0]);
        posix::posix_close(fds[1]);
    }
    true
}

// ---- Test 4: POSIX shared memory ----
fn test_shm() -> bool {
    puts(b"[TEST_SOCKET] Test 4: POSIX shared memory\n");

    // shm_open
    let fd = unsafe { posix::posix_shm_open(b"/test_shm\0".as_ptr(), (O_CREAT | O_RDWR) as i32) };
    if fd < 0 {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] FAIL: shm_open returned "); lb.hex(fd as u64); lb.str(b"\n"); lb.flush(); }
        return false;
    }
    { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] shm_open fd="); lb.dec(fd as u64); lb.str(b"\n"); lb.flush(); }

    // ftruncate to 4096
    let ret = unsafe { posix::posix_ftruncate(fd, 4096) };
    if ret != 0 {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] FAIL: ftruncate returned "); lb.hex(ret as u64); lb.str(b"\n"); lb.flush(); }
        unsafe { posix::posix_close(fd) };
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: ftruncate OK\n");

    // Close and cleanup
    unsafe { posix::posix_close(fd) };

    // Unlink
    let ret = unsafe { posix::posix_shm_unlink(b"/test_shm\0".as_ptr()) };
    if ret != 0 {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_SOCKET] FAIL: shm_unlink returned "); lb.hex(ret as u64); lb.str(b"\n"); lb.flush(); }
        return false;
    }
    puts(b"[TEST_SOCKET] PASS: shm_open/ftruncate/unlink OK\n");

    true
}
