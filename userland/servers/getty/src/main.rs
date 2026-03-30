//! SaltyOS getty — terminal session setup program
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Analogous to agetty(8). Opens a PTY slave, creates a new session,
//! acquires the controlling terminal, then execs the shell.
//!
//! Lifecycle:
//!   init spawns getty (SPAWN_FLAG_RESPAWN) →
//!   getty: close fds → setsid → open /dev/pts/0 → dup → TIOCSCTTY → exec bash →
//!   bash exits → procmgr respawns getty → new session cycle

#![no_std]
#![no_main]

extern crate trona;

use trona_posix::*;

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    unsafe {
        trona::serial::serial_puts(b"[getty] starting session setup\n");

        // 1. Close CRT-opened /dev/console fds
        posix_close(0);
        posix_close(1);
        posix_close(2);

        // 2. Create new session (sid=pid, pgid=pid)
        let sid = posix_setsid();
        if sid < 0 {
            trona::serial::serial_puts(b"[getty] setsid failed\n");
        }

        // 3. Open PTY slave as fd 0 — retry with backoff if TTYD/VFS not ready
        let mut fd0 = -1i32;
        let mut delay_ns: u64 = 100_000_000; // 100ms
        for _attempt in 0..5u32 {
            fd0 = posix_open(b"/dev/pts/0\0".as_ptr(), 2, 0); // O_RDWR
            if fd0 >= 0 { break; }
            trona::serial::serial_puts(b"[getty] /dev/pts/0 open failed, retrying\n");
            trona::syscall::syscall(trona::SYS_NANOSLEEP, 0, delay_ns, 0, 0, 0, 0);
            delay_ns *= 2;
        }
        if fd0 < 0 {
            trona::serial::serial_puts(b"[getty] /dev/pts/0 open failed after retries\n");
            posix_exit(1);
        }

        // 4. Dup to stdout/stderr
        posix_dup(fd0); // fd 1
        posix_dup(fd0); // fd 2

        // 5. Acquire controlling terminal
        let tio = posix_ioctl(fd0, 0x540E, 0); // TIOCSCTTY
        if tio < 0 {
            trona::serial::serial_puts(b"[getty] TIOCSCTTY failed\n");
        }

        // 5b. Set foreground process group for the controlling tty.
        // Some shells defer prompt/input until tcgetpgrp() matches getpgrp().
        let fg_pgid: u64 = if sid > 0 {
            sid as u64
        } else {
            let pid = posix_getpid();
            if pid > 0 { pid as u64 } else { 0 }
        };
        if fg_pgid != 0 {
            let pgrp = posix_ioctl(fd0, 0x5410, fg_pgid); // TIOCSPGRP
            if pgrp < 0 {
                trona::serial::serial_puts(b"[getty] TIOCSPGRP failed\n");
            }
        }

        trona::serial::serial_puts(b"[getty] session ready, exec bash\n");

        // 6. Exec bash — replaces this process image
        let new_argv: [*const u8; 3] = [
            b"bash\0".as_ptr(),
            b"-i\0".as_ptr(),
            core::ptr::null(),
        ];
        let mut path_buf = [0u8; 48];
        let prefix = b"PATH=";
        let path_val = trona::DEFAULT_PATH;
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

        let new_envp: [*const u8; 7] = [
            path_buf.as_ptr(),
            b"HOME=/\0".as_ptr(),
            b"TERM=vt100\0".as_ptr(),
            b"SHELL=/bin/sh\0".as_ptr(),
            b"PS1=$ \0".as_ptr(),
            b"TTY=/dev/pts/0\0".as_ptr(),
            core::ptr::null(),
        ];

        posix_execve(
            b"bash\0".as_ptr(),
            new_argv.as_ptr(),
            new_envp.as_ptr(),
        );

        // If exec fails
        trona::serial::serial_puts(b"[getty] exec failed\n");
        posix_exit(1);
    }
}
