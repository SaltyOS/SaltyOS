//! SaltyOS getty — boot console session bootstrap.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! `posix_getty` runs the classic getty sequence for the boot console:
//! become a session leader, open `/dev/console` (the pty0-backed console
//! tty), claim it as the controlling terminal via `TIOCSCTTY`, install it
//! as stdin/stdout/stderr, then `execve("/bin/login")` (falling back to an
//! interactive shell). `TIOCSCTTY` also seeds the foreground process group
//! from the caller's pgid, so login and its children take console signals.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

use trona_posix::*;

fn append_decimal(buf: &mut [u8], pos: &mut usize, mut value: u64) -> bool {
    if *pos >= buf.len() {
        return false;
    }
    if value == 0 {
        if *pos >= buf.len() {
            return false;
        }
        buf[*pos] = b'0';
        *pos += 1;
        return true;
    }
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    while value != 0 {
        digits[count] = b'0' + (value % 10) as u8;
        value /= 10;
        count += 1;
    }
    if *pos + count > buf.len() {
        return false;
    }
    while count != 0 {
        count -= 1;
        buf[*pos] = digits[count];
        *pos += 1;
    }
    true
}

fn build_tty_env_var(buf: &mut [u8], tty_dev: u64) -> bool {
    let mut pos = 0usize;
    let prefix = b"TTY=";
    if prefix.len() >= buf.len() {
        return false;
    }
    while pos < prefix.len() {
        buf[pos] = prefix[pos];
        pos += 1;
    }

    if tty_dev == trona_posix::consts::TTY_DEV_CONSOLE {
        let suffix = b"/dev/console";
        if pos + suffix.len() + 1 > buf.len() {
            return false;
        }
        for &b in suffix {
            buf[pos] = b;
            pos += 1;
        }
    } else if tty_dev >= trona_posix::consts::TTY_DEV_PTS_BASE {
        let prefix = b"/dev/pts/";
        if pos + prefix.len() + 1 > buf.len() {
            return false;
        }
        for &b in prefix {
            buf[pos] = b;
            pos += 1;
        }
        if !append_decimal(
            buf,
            &mut pos,
            tty_dev - trona_posix::consts::TTY_DEV_PTS_BASE,
        ) {
            return false;
        }
    } else {
        return false;
    }

    if pos >= buf.len() {
        return false;
    }
    buf[pos] = 0;
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    unsafe {
        trona_runtime::debug::serial::serial_puts(b"[posix_getty] bootstrapping console session\n");

        // Become a session leader (init already spawns getty as one, so
        // this is idempotent) ahead of claiming a controlling terminal.
        posix_setsid();

        // Open the boot console tty (pty0-backed) and make it this
        // session's controlling terminal. TIOCSCTTY records the session as
        // pty0's ctty owner and seeds the foreground pgrp from our pgid.
        let console_fd = posix_open(b"/dev/console\0".as_ptr(), O_RDWR as i32, 0);
        if console_fd < 0 {
            trona_runtime::debug::serial::serial_puts(
                b"[posix_getty] FATAL: cannot open /dev/console\n",
            );
            posix_exit(1);
        }
        if posix_ioctl(console_fd, TIOCSCTTY, 0) < 0 {
            trona_runtime::debug::serial::serial_puts(b"[posix_getty] FATAL: TIOCSCTTY failed\n");
            posix_exit(1);
        }

        // Wire stdin/stdout/stderr to the controlling console tty.
        posix_dup2(console_fd, 0);
        posix_dup2(console_fd, 1);
        posix_dup2(console_fd, 2);

        let mut tty_env_buf = [0u8; 40];
        if !build_tty_env_var(&mut tty_env_buf, TTY_DEV_CONSOLE) {
            trona_runtime::debug::serial::serial_puts(
                b"[posix_getty] FATAL: tty env build failed\n",
            );
            posix_exit(1);
        }

        // Type=notify readiness — init resolves the caller's manifest
        // entry from the per-client MP context.
        trona_runtime::init_notify_ready();

        let mut path_buf = [0u8; 48];
        let prefix = b"PATH=";
        let path_val = trona_posix::consts::DEFAULT_PATH;
        let mut i = 0usize;
        while i < prefix.len() {
            path_buf[i] = prefix[i];
            i += 1;
        }
        let mut j = 0usize;
        while j < path_val.len() && i < path_buf.len() - 1 {
            path_buf[i] = path_val[j];
            i += 1;
            j += 1;
        }
        path_buf[i] = 0;

        let new_envp: [*const u8; 5] = [
            path_buf.as_ptr(),
            b"HOME=/\0".as_ptr(),
            b"TERM=vt100\0".as_ptr(),
            tty_env_buf.as_ptr(),
            core::ptr::null(),
        ];

        trona_runtime::debug::serial::serial_puts(b"[posix_getty] tty ready, exec login\n");

        let login_argv: [*const u8; 2] = [b"login\0".as_ptr(), core::ptr::null()];
        posix_execve(
            b"/bin/login\0".as_ptr(),
            login_argv.as_ptr(),
            new_envp.as_ptr(),
        );

        trona_runtime::debug::serial::serial_puts(
            b"[posix_getty] login exec failed, falling back to bash\n",
        );

        let bash_envp: [*const u8; 7] = [
            path_buf.as_ptr(),
            b"HOME=/\0".as_ptr(),
            b"TERM=vt100\0".as_ptr(),
            b"SHELL=/usr/bin/bash\0".as_ptr(),
            b"PS1=$ \0".as_ptr(),
            tty_env_buf.as_ptr(),
            core::ptr::null(),
        ];

        let bash_argv: [*const u8; 3] = [b"bash\0".as_ptr(), b"-i\0".as_ptr(), core::ptr::null()];
        posix_execve(
            b"/usr/bin/bash\0".as_ptr(),
            bash_argv.as_ptr(),
            bash_envp.as_ptr(),
        );

        trona_runtime::debug::serial::serial_puts(
            b"[posix_getty] FATAL: all exec attempts failed\n",
        );
        posix_exit(1);
    }
}
