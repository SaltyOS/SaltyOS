// SPDX-License-Identifier: GPL-2.0-only
//! Mount-wide case-insensitive lookup test.
//!
//! Mounts a fresh tmpfs with the `casefold` option on `/mnt`, creates
//! `Foo.txt`, then walks back through the mixed-case spellings
//! (`foo.TXT`, `FOO.txt`) for `open`, `unlink`, and `link`. Bypasses
//! the regular fstab path because the case-folded mount only exists
//! for the duration of the test.
//!
//! All `[TEST_CASEFOLD]` lines emit through `LineBuf` to keep
//! per-result observation latency to a single serial flush.

use trona_posix::{
    O_CREAT, O_RDWR, O_WRONLY, posix_close, posix_mkdir, posix_mount, posix_open, posix_unlink,
};
use trona_runtime::debug::serial::LineBuf;

const MOUNT_POINT: &[u8] = b"/mnt\0";
const CANONICAL_NAME: &[u8] = b"/mnt/Foo.txt\0";
const LOWER_NAME: &[u8] = b"/mnt/foo.txt\0";
const UPPER_NAME: &[u8] = b"/mnt/FOO.TXT\0";
const MIXED_NAME: &[u8] = b"/mnt/fOO.tXt\0";

fn pass(label: &[u8]) {
    let mut lb = LineBuf::new();
    lb.str(b"[TEST_CASEFOLD] PASS: ");
    lb.str(label);
    lb.str(b"\n");
    lb.flush();
}

fn fail(label: &[u8], detail: i32) {
    let mut lb = LineBuf::new();
    lb.str(b"[TEST_CASEFOLD] FAIL: ");
    lb.str(label);
    lb.str(b" rc=");
    lb.dec(detail as i64 as u64);
    lb.str(b"\n");
    lb.flush();
}

fn close_fd(fd: i32) {
    if fd >= 0 {
        let _ = unsafe { posix_close(fd) };
    }
}

pub fn run() -> bool {
    let mut ok = true;

    // Bootstrap doesn't ship a `/mnt` directory. Create it lazily so
    // the rest of the test does not depend on rootfs layout. EEXIST
    // (-17) is fine — a previous run may have left it behind.
    let mkdir_rc = unsafe { posix_mkdir(MOUNT_POINT.as_ptr(), 0o755) };
    if mkdir_rc != 0 && mkdir_rc != -17 {
        fail(b"mkdir /mnt", mkdir_rc);
        return false;
    }

    let mount_rc = unsafe { posix_mount(b"/mnt", b"tmpfs", 0, b"casefold") };
    if mount_rc != 0 {
        fail(b"mount tmpfs casefold", mount_rc);
        return false;
    }
    pass(b"mount tmpfs casefold OK");

    let create_fd =
        unsafe { posix_open(CANONICAL_NAME.as_ptr(), (O_CREAT | O_WRONLY) as i32, 0o644) };
    if create_fd < 0 {
        fail(b"create Foo.txt", create_fd);
        return false;
    }
    close_fd(create_fd);
    pass(b"create Foo.txt OK");

    for (label, path) in [
        (b"lookup foo.txt".as_slice(), LOWER_NAME),
        (b"lookup FOO.TXT".as_slice(), UPPER_NAME),
        (b"lookup fOO.tXt".as_slice(), MIXED_NAME),
    ] {
        let fd = unsafe { posix_open(path.as_ptr(), O_RDWR as i32, 0) };
        if fd < 0 {
            fail(label, fd);
            ok = false;
        } else {
            close_fd(fd);
            pass(b"case-insensitive lookup OK");
        }
    }

    let unlink_rc = unsafe { posix_unlink(UPPER_NAME.as_ptr()) };
    if unlink_rc != 0 {
        fail(b"unlink FOO.TXT", unlink_rc);
        ok = false;
    } else {
        pass(b"case-insensitive unlink OK");
    }

    let probe = unsafe { posix_open(LOWER_NAME.as_ptr(), O_RDWR as i32, 0) };
    if probe >= 0 {
        close_fd(probe);
        fail(b"foo.txt should be gone after unlink", 0);
        ok = false;
    } else {
        pass(b"unlink removed every spelling");
    }

    ok
}
