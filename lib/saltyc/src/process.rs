//! Process management
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! POSIX process management wrappers that call into salty::posix::* functions.

use crate::errno;

const SIGABRT: i32 = 6;

// Maximum number of varargs we support for execl/execlp argv construction
const MAX_EXEC_ARGS: usize = 64;

// ---------------------------------------------------------------------------
// Fork / exec
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fork() -> i32 {
    let ret = salty::posix::posix_fork();
    if ret < 0 {
        errno::set_errno(errno::EAGAIN);
    }
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execve(
    path: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> i32 {
    unsafe {
        let ret = salty::posix::posix_execve(path, argv, envp);
        if ret < 0 {
            errno::set_errno(errno::ENOENT);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvp(file: *const u8, argv: *const *const u8) -> i32 {
    if file.is_null() {
        errno::set_errno(errno::ENOENT);
        return -1;
    }
    unsafe {
        // If file contains '/', treat as absolute/relative path
        let mut i = 0;
        let mut has_slash = false;
        while *file.add(i) != 0 {
            if *file.add(i) == b'/' {
                has_slash = true;
                break;
            }
            i += 1;
        }

        if has_slash {
            return execve(file, argv, core::ptr::null());
        }

        let file_len = crate::string::strlen(file);

        // Get PATH from environment
        let path_env = crate::env::getenv(b"PATH\0".as_ptr());
        let default_path = b"/bin:/usr/bin\0".as_ptr();
        let path = if path_env.is_null() || *path_env == 0 {
            default_path
        } else {
            path_env
        };

        // Walk PATH components separated by ':'
        let mut start = 0;
        loop {
            let mut end = start;
            while *path.add(end) != 0 && *path.add(end) != b':' {
                end += 1;
            }

            let comp_len = end - start;
            if comp_len > 0 {
                let mut path_buf = [0u8; 512];
                let mut pos = 0;

                for k in 0..comp_len {
                    if pos < 510 {
                        path_buf[pos] = *path.add(start + k);
                        pos += 1;
                    }
                }

                if pos > 0 && path_buf[pos - 1] != b'/' && pos < 510 {
                    path_buf[pos] = b'/';
                    pos += 1;
                }

                for k in 0..file_len {
                    if pos < 511 {
                        path_buf[pos] = *file.add(k);
                        pos += 1;
                    }
                }
                path_buf[pos] = 0;

                let ret = execve(path_buf.as_ptr(), argv, core::ptr::null());
                // execve only returns on error
                let _ = ret;
            }

            if *path.add(end) == 0 {
                break;
            }
            start = end + 1;
        }

        errno::set_errno(errno::ENOENT);
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvpe(
    file: *const u8,
    argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    // Ignore custom envp for now; delegate to execvp
    unsafe { execvp(file, argv) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execv(path: *const u8, argv: *const *const u8) -> i32 {
    unsafe { execve(path, argv, core::ptr::null()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execl(path: *const u8, arg0: *const u8, mut args: ...) -> i32 {
    unsafe {
        let mut argv_buf: [*const u8; MAX_EXEC_ARGS + 1] = [core::ptr::null(); MAX_EXEC_ARGS + 1];
        argv_buf[0] = arg0;
        let mut argc = 1;

        // Collect varargs until NULL
        loop {
            let arg: *const u8 = args.arg();
            if arg.is_null() || argc >= MAX_EXEC_ARGS {
                break;
            }
            argv_buf[argc] = arg;
            argc += 1;
        }
        argv_buf[argc] = core::ptr::null();

        execve(path, argv_buf.as_ptr(), core::ptr::null())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execlp(file: *const u8, arg0: *const u8, mut args: ...) -> i32 {
    unsafe {
        let mut argv_buf: [*const u8; MAX_EXEC_ARGS + 1] = [core::ptr::null(); MAX_EXEC_ARGS + 1];
        argv_buf[0] = arg0;
        let mut argc = 1;

        loop {
            let arg: *const u8 = args.arg();
            if arg.is_null() || argc >= MAX_EXEC_ARGS {
                break;
            }
            argv_buf[argc] = arg;
            argc += 1;
        }
        argv_buf[argc] = core::ptr::null();

        execvp(file, argv_buf.as_ptr())
    }
}

// ---------------------------------------------------------------------------
// Process termination / PID
// ---------------------------------------------------------------------------

/// Immediate process exit (no cleanup).
/// Note: crt.rs also defines _exit; this wrapper simply delegates to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _exit_process(status: i32) -> ! {
    unsafe {
        salty::posix::posix_exit(status);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpid() -> i32 {
    unsafe { salty::posix::posix_getpid() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getppid() -> i32 {
    unsafe { salty::posix::posix_getppid() }
}

// ---------------------------------------------------------------------------
// Wait
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_waitpid3(pid, status, options);
        if ret < 0 {
            errno::set_errno(errno::ECHILD);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wait(status: *mut i32) -> i32 {
    unsafe { waitpid(-1, status, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wait3(status: *mut i32, options: i32, _rusage: *mut u8) -> i32 {
    unsafe { waitpid(-1, status, options) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wait4(
    pid: i32,
    status: *mut i32,
    options: i32,
    _rusage: *mut u8,
) -> i32 {
    unsafe { waitpid(pid, status, options) }
}

// ---------------------------------------------------------------------------
// Wait status inspection (C-callable function versions of the macros)
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn WIFEXITED(status: i32) -> i32 {
    ((status & 0x7f) == 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn WEXITSTATUS(status: i32) -> i32 {
    (status >> 8) & 0xff
}

#[unsafe(no_mangle)]
pub extern "C" fn WIFSIGNALED(status: i32) -> i32 {
    (((status & 0x7f) + 1) >> 1 > 0) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn WTERMSIG(status: i32) -> i32 {
    status & 0x7f
}

#[unsafe(no_mangle)]
pub extern "C" fn WIFSTOPPED(status: i32) -> i32 {
    ((status & 0xff) == 0x7f) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn WSTOPSIG(status: i32) -> i32 {
    (status >> 8) & 0xff
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kill(pid: i32, sig: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_kill(pid, sig);
        if ret < 0 {
            errno::set_errno(errno::ESRCH);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn killpg(pgrp: i32, sig: i32) -> i32 {
    unsafe { kill(-pgrp, sig) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn raise(sig: i32) -> i32 {
    unsafe {
        let pid = getpid();
        kill(pid, sig)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn abort() -> ! {
    unsafe {
        raise(SIGABRT);
        // If raise returns (handler caught it or ignored), force exit
        salty::posix::posix_exit(134);
    }
}

// ---------------------------------------------------------------------------
// UID / GID
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getuid() -> u32 {
    unsafe { salty::posix::posix_getuid() as u32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn geteuid() -> u32 {
    unsafe { salty::posix::posix_geteuid() as u32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgid() -> u32 {
    unsafe { salty::posix::posix_getgid() as u32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getegid() -> u32 {
    unsafe { salty::posix::posix_getegid() as u32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgroups(size: i32, list: *mut u32) -> i32 {
    unsafe { salty::posix::posix_getgroups(size, list as *mut i32) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setuid(_uid: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setgid(_gid: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn seteuid(_uid: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setegid(_gid: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setreuid(_ruid: u32, _euid: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setregid(_rgid: u32, _egid: u32) -> i32 {
    0
}
