//! Terminal (termios) tests
//! SPDX-License-Identifier: GPL-2.0-only

use trona::consts::TIOCGWINSZ;
use trona_posix::proc as posix;
use trona::serial;
use trona::types::*;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

#[repr(C)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

pub fn run() -> bool {
    puts(b"[TEST_TERMINAL] Starting terminal tests\n");

    // Open /dev/console explicitly (test_runner doesn't have fd 0 pre-opened)
    let fd = unsafe { trona_posix::posix_open(b"/dev/console\0".as_ptr(), 0, 0) };
    if fd < 0 {
        puts(b"[TEST_TERMINAL] FAIL: could not open /dev/console\n");
        return false;
    }

    // Test 1: tcgetattr on console fd
    puts(b"[TEST_TERMINAL] Test 1: tcgetattr\n");
    let mut termios = Termios::zeroed();
    let ret = unsafe { trona_posix::posix_tcgetattr(fd, &raw mut termios) };
    if ret != 0 {
        puts(b"[TEST_TERMINAL] FAIL: tcgetattr returned error\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    // Verify ICANON|ECHO|ISIG are set in c_lflag (default canonical mode)
    let lflag = termios.c_lflag;
    if lflag & 0o000002 == 0 {
        // ICANON
        puts(b"[TEST_TERMINAL] FAIL: ICANON not set\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }
    if lflag & 0o000010 == 0 {
        // ECHO
        puts(b"[TEST_TERMINAL] FAIL: ECHO not set\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }
    if lflag & 0o000001 == 0 {
        // ISIG
        puts(b"[TEST_TERMINAL] FAIL: ISIG not set\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }
    puts(b"[TEST_TERMINAL] PASS: tcgetattr returned correct c_lflag\n");

    // Test 2: ioctl(TIOCGWINSZ) writes a struct winsize
    puts(b"[TEST_TERMINAL] Test 2: ioctl(TIOCGWINSZ)\n");
    let mut ws = Winsize {
        ws_row: 0xFFFF,
        ws_col: 0xFFFF,
        ws_xpixel: 0xFFFF,
        ws_ypixel: 0xFFFF,
    };
    let ret = unsafe {
        trona_posix::posix_ioctl(
            fd,
            TIOCGWINSZ,
            (&raw mut ws as *mut Winsize).cast::<u8>() as u64,
        )
    };
    if ret != 0 {
        puts(b"[TEST_TERMINAL] FAIL: ioctl(TIOCGWINSZ) returned error\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }
    if ws.ws_row == 0 || ws.ws_col == 0 || ws.ws_row > 500 || ws.ws_col > 1000 {
        puts(b"[TEST_TERMINAL] FAIL: ioctl(TIOCGWINSZ) returned invalid size\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }
    puts(b"[TEST_TERMINAL] PASS: ioctl(TIOCGWINSZ) filled winsize\n");

    // Test 3: tcsetattr — switch to raw mode and verify
    puts(b"[TEST_TERMINAL] Test 3: tcsetattr raw mode\n");
    let mut raw = termios;
    raw.c_lflag &= !(0o000002 | 0o000010 | 0o000001 | 0o100000); // clear ICANON|ECHO|ISIG|IEXTEN
    raw.c_iflag &= !(0o000400 | 0o002000); // clear ICRNL|IXON
    raw.c_oflag &= !0o000001; // clear OPOST
    raw.c_cc[6] = 1; // VMIN = 1
    raw.c_cc[5] = 0; // VTIME = 0

    let ret = unsafe { trona_posix::posix_tcsetattr(fd, 0, &raw const raw) };
    if ret != 0 {
        puts(b"[TEST_TERMINAL] FAIL: tcsetattr raw mode failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    // Verify raw mode took effect
    let mut check = Termios::zeroed();
    let ret = unsafe { trona_posix::posix_tcgetattr(fd, &raw mut check) };
    if ret != 0 {
        puts(b"[TEST_TERMINAL] FAIL: tcgetattr after raw mode failed\n");
        unsafe { trona_posix::posix_tcsetattr(fd, 0, &raw const termios) };
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    if check.c_lflag & 0o000002 != 0 {
        puts(b"[TEST_TERMINAL] FAIL: ICANON still set after raw mode\n");
        unsafe { trona_posix::posix_tcsetattr(fd, 0, &raw const termios) };
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }
    puts(b"[TEST_TERMINAL] PASS: raw mode verified\n");

    // Test 4: Restore original termios
    puts(b"[TEST_TERMINAL] Test 4: restore original termios\n");
    let ret = unsafe { trona_posix::posix_tcsetattr(fd, 0, &raw const termios) };
    if ret != 0 {
        puts(b"[TEST_TERMINAL] FAIL: tcsetattr restore failed\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }

    let mut restored = Termios::zeroed();
    let ret = unsafe { trona_posix::posix_tcgetattr(fd, &raw mut restored) };
    if ret != 0 || restored.c_lflag & 0o000002 == 0 {
        puts(b"[TEST_TERMINAL] FAIL: ICANON not restored\n");
        unsafe { trona_posix::posix_close(fd) };
        return false;
    }
    puts(b"[TEST_TERMINAL] PASS: original termios restored\n");

    unsafe { trona_posix::posix_close(fd) };
    puts(b"[TEST_TERMINAL] All terminal tests passed\n");
    true
}
