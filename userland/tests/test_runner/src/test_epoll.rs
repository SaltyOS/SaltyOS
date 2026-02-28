//! Epoll tests
//! SPDX-License-Identifier: GPL-2.0-only

use besalt::consts::*;
use besalt::posix;
use besalt::serial;
use besalt::types::*;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub fn run() -> bool {
    puts(b"[TEST_EPOLL] Starting epoll tests\n");

    // Test 1: epoll_create1
    puts(b"[TEST_EPOLL] Test 1: epoll_create1\n");
    let epfd = unsafe { posix::posix_epoll_create() };
    if epfd < 0 {
        puts(b"[TEST_EPOLL] FAIL: epoll_create1 returned negative\n");
        return false;
    }
    puts(b"[TEST_EPOLL] PASS: epoll_create1 returned valid fd\n");

    // Test 2: epoll_ctl ADD + epoll_wait with pipe
    puts(b"[TEST_EPOLL] Test 2: epoll_ctl ADD + epoll_wait\n");

    let mut pipefds: [i32; 2] = [0; 2];
    let ret = unsafe { posix::posix_pipe(pipefds.as_mut_ptr()) };
    if ret != 0 {
        puts(b"[TEST_EPOLL] FAIL: pipe() for epoll test failed\n");
        return false;
    }
    let read_fd = pipefds[0];
    let write_fd = pipefds[1];

    // Add read end to epoll with EPOLLIN
    let ret = unsafe {
        posix::posix_epoll_ctl(epfd, EPOLL_CTL_ADD, read_fd, EPOLLIN, read_fd as u64)
    };
    if ret != 0 {
        puts(b"[TEST_EPOLL] FAIL: epoll_ctl ADD failed\n");
        return false;
    }

    // Write some data to the pipe
    let data = b"hi";
    let written = unsafe { posix::posix_write(write_fd, data.as_ptr(), 2) };
    if written != 2 {
        puts(b"[TEST_EPOLL] FAIL: write to pipe failed\n");
        return false;
    }

    // epoll_wait with timeout=0 should return 1 event
    let mut events: [EpollEvent; 4] = [EpollEvent::zeroed(); 4];
    let nready = unsafe {
        posix::posix_epoll_wait(epfd, events.as_mut_ptr(), 4, 0)
    };
    if nready != 1 {
        puts(b"[TEST_EPOLL] FAIL: epoll_wait expected 1 ready event\n");
        return false;
    }
    if events[0].events & EPOLLIN == 0 {
        puts(b"[TEST_EPOLL] FAIL: expected EPOLLIN in events\n");
        return false;
    }
    if events[0].data != read_fd as u64 {
        puts(b"[TEST_EPOLL] FAIL: epoll event data mismatch\n");
        return false;
    }
    puts(b"[TEST_EPOLL] PASS: epoll_ctl + epoll_wait works\n");

    // Test 3: epoll_ctl DEL
    puts(b"[TEST_EPOLL] Test 3: epoll_ctl DEL\n");
    let ret = unsafe { posix::posix_epoll_ctl(epfd, EPOLL_CTL_DEL, read_fd, 0, 0) };
    if ret != 0 {
        puts(b"[TEST_EPOLL] FAIL: epoll_ctl DEL failed\n");
        return false;
    }

    // Drain the pipe so we get a clean state
    let mut buf = [0u8; 16];
    unsafe { posix::posix_read(read_fd, buf.as_mut_ptr(), 16) };

    // epoll_wait should now return 0
    let nready = unsafe {
        posix::posix_epoll_wait(epfd, events.as_mut_ptr(), 4, 0)
    };
    if nready != 0 {
        puts(b"[TEST_EPOLL] FAIL: epoll_wait expected 0 after DEL\n");
        return false;
    }
    puts(b"[TEST_EPOLL] PASS: epoll_ctl DEL works\n");

    // Test 4: Close epoll fd
    puts(b"[TEST_EPOLL] Test 4: close epoll fd\n");
    unsafe {
        posix::posix_close(read_fd);
        posix::posix_close(write_fd);
        posix::posix_close(epfd);
    }
    puts(b"[TEST_EPOLL] PASS: cleanup complete\n");

    puts(b"[TEST_EPOLL] All epoll tests passed\n");
    true
}
