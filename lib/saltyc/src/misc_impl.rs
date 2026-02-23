//! Core POSIX miscellaneous functions
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Functions that don't fit in a specific POSIX header category:
//! `getprogname`/`setprogname` (BSD program name), `dirname`/`basename`
//! (path decomposition), `sched_yield`, `getpagesize`, `fsync`/`fdatasync`
//! (no-ops for ramfs), `utime`/`utimes`, `user_from_uid`/`group_from_gid`,
//! `getentropy` (pseudo-random fill), and various stubs (semaphores, popen).
//!
//! BSD/FreeBSD-specific functions live in `compat::freebsd`.

use crate::errno;
use core::ptr::addr_of_mut;

// ---------------------------------------------------------------------------
// dirname / basename — POSIX string manipulation
// ---------------------------------------------------------------------------

static mut DIRNAME_BUF: [u8; 4096] = [0; 4096];
static mut BASENAME_DOT: [u8; 2] = [b'.', 0];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dirname(path: *mut u8) -> *mut u8 {
    unsafe {
        let buf = addr_of_mut!(DIRNAME_BUF) as *mut u8;

        // NULL or empty → "."
        if path.is_null() || *path == 0 {
            *buf.add(0) = b'.';
            *buf.add(1) = 0;
            return buf;
        }

        // Measure length
        let mut len = 0usize;
        while *path.add(len) != 0 {
            len += 1;
        }

        // Strip trailing slashes
        while len > 1 && *path.add(len - 1) == b'/' {
            len -= 1;
        }

        // Find last slash
        let mut last_slash: isize = -1;
        for i in (0..len).rev() {
            if *path.add(i) == b'/' {
                last_slash = i as isize;
                break;
            }
        }

        if last_slash < 0 {
            // No slash → "."
            *buf.add(0) = b'.';
            *buf.add(1) = 0;
            return buf;
        }

        if last_slash == 0 {
            // Only root slash → "/"
            *buf.add(0) = b'/';
            *buf.add(1) = 0;
            return buf;
        }

        // Strip trailing slashes from parent
        let mut end = last_slash as usize;
        while end > 1 && *path.add(end - 1) == b'/' {
            end -= 1;
        }

        let copy_len = if end < 4095 { end } else { 4095 };
        for i in 0..copy_len {
            *buf.add(i) = *path.add(i);
        }
        *buf.add(copy_len) = 0;
        buf
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn basename(path: *mut u8) -> *mut u8 {
    unsafe {
        let dot = addr_of_mut!(BASENAME_DOT) as *mut u8;

        // NULL or empty → "."
        if path.is_null() || *path == 0 {
            *dot.add(0) = b'.';
            *dot.add(1) = 0;
            return dot;
        }

        let mut len = 0usize;
        while *path.add(len) != 0 {
            len += 1;
        }

        // Strip trailing slashes
        while len > 1 && *path.add(len - 1) == b'/' {
            len -= 1;
        }

        // All slashes → "/"
        if len == 1 && *path == b'/' {
            return path;
        }

        // Find last slash
        let mut last_slash: isize = -1;
        for i in (0..len).rev() {
            if *path.add(i) == b'/' {
                last_slash = i as isize;
                break;
            }
        }

        if last_slash < 0 {
            // Null-terminate at len (strip trailing slashes)
            *path.add(len) = 0;
            return path;
        }

        let start = (last_slash + 1) as usize;
        *path.add(len) = 0;
        path.add(start)
    }
}

// ---------------------------------------------------------------------------
// sched_yield — maps to SYS_YIELD (syscall 8)
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_yield() -> i32 {
    salty::syscall::syscall(salty::consts::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    0
}

// ---------------------------------------------------------------------------
// getpagesize — always 4096
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpagesize() -> i32 {
    4096
}

// ---------------------------------------------------------------------------
// fsync / fdatasync — correct no-ops for ramfs
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsync(_fd: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fdatasync(_fd: i32) -> i32 {
    0
}

// ---------------------------------------------------------------------------
// utime / utimes — thin wrappers over utimensat
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Utimbuf {
    pub actime: i64,
    pub modtime: i64,
}

#[repr(C)]
pub struct CTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn utime(filename: *const u8, times: *const Utimbuf) -> i32 {
    unsafe {
        if filename.is_null() {
            errno::set_errno(errno::EINVAL);
            return -1;
        }
        let (atime_sec, atime_nsec, mtime_sec, mtime_nsec) = if times.is_null() {
            // NULL → set both to current time
            let utime_now: i64 = (1 << 30) - 1;
            (0i64, utime_now, 0i64, utime_now)
        } else {
            // Utimbuf has seconds only, nsec = 0
            ((*times).actime, 0i64, (*times).modtime, 0i64)
        };
        let ret = salty::posix::posix_utimensat(
            salty::consts::AT_FDCWD,
            filename,
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            0,
        );
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn utimes(filename: *const u8, times: *const CTimeval) -> i32 {
    unsafe {
        if filename.is_null() {
            errno::set_errno(errno::EINVAL);
            return -1;
        }
        let (atime_sec, atime_nsec, mtime_sec, mtime_nsec) = if times.is_null() {
            let utime_now: i64 = (1 << 30) - 1;
            (0i64, utime_now, 0i64, utime_now)
        } else {
            // CTimeval has sec + usec, convert usec → nsec
            (
                (*times).tv_sec,
                (*times).tv_usec * 1000,
                (*times.add(1)).tv_sec,
                (*times.add(1)).tv_usec * 1000,
            )
        };
        let ret = salty::posix::posix_utimensat(
            salty::consts::AT_FDCWD,
            filename,
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            0,
        );
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// user_from_uid / group_from_gid — user/group name lookup
// ---------------------------------------------------------------------------

static mut UID_BUF: [u8; 32] = [0; 32];
static mut GID_BUF: [u8; 32] = [0; 32];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn user_from_uid(uid: u32, noname: i32) -> *const u8 {
    unsafe {
        let pw = crate::pwd_impl::getpwuid(uid);
        if !pw.is_null() {
            return (*pw).pw_name;
        }
        if noname != 0 {
            return core::ptr::null();
        }
        // Format UID as decimal string into static buffer
        let buf = core::ptr::addr_of_mut!(UID_BUF) as *mut u8;
        format_u32(uid, buf, 32);
        buf
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn group_from_gid(gid: u32, noname: i32) -> *const u8 {
    unsafe {
        let gr = crate::pwd_impl::getgrgid(gid);
        if !gr.is_null() {
            return (*gr).gr_name;
        }
        if noname != 0 {
            return core::ptr::null();
        }
        let buf = core::ptr::addr_of_mut!(GID_BUF) as *mut u8;
        format_u32(gid, buf, 32);
        buf
    }
}

/// Format a u32 as a decimal string into a buffer, NUL-terminated.
unsafe fn format_u32(mut val: u32, buf: *mut u8, buflen: usize) {
    unsafe {
        if buflen == 0 {
            return;
        }
        let mut tmp = [0u8; 12]; // max 10 digits + NUL
        let mut i = 0usize;
        if val == 0 {
            tmp[0] = b'0';
            i = 1;
        } else {
            while val > 0 && i < 11 {
                tmp[i] = b'0' + (val % 10) as u8;
                val /= 10;
                i += 1;
            }
        }
        // Reverse into buf
        let copy_len = if i < buflen - 1 { i } else { buflen - 1 };
        for j in 0..copy_len {
            *buf.add(j) = tmp[i - 1 - j];
        }
        *buf.add(copy_len) = 0;
    }
}

// ---------------------------------------------------------------------------
// getentropy — fill buffer with pseudo-random bytes
// ---------------------------------------------------------------------------

static mut ENTROPY_COUNTER: u64 = 0;

/// Fill a buffer with pseudo-random bytes.
///
/// **WARNING: NOT cryptographically secure.** Uses a simple xorshift64 PRNG
/// seeded from the monotonic clock, PID, and a static counter. Suitable for
/// non-security purposes (e.g. hash table seeding). `buflen` must be <= 256
/// per POSIX.
///
/// Returns 0 on success, -1 on error (null buffer or buflen > 256).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getentropy(buf: *mut u8, buflen: usize) -> i32 {
    if buf.is_null() || buflen > 256 {
        errno::set_errno(errno::EINVAL);
        return -1;
    }

    unsafe {
        // Mix clock time, PID, and a monotonic counter
        let mut ts = salty::types::Timespec::zeroed();
        salty::posix::posix_clock_gettime(0, &mut ts);

        let pid = salty::posix::posix_getpid() as u64;
        let ctr = &raw mut ENTROPY_COUNTER;
        *ctr = (*ctr).wrapping_add(1);

        // Simple xorshift-based mixing
        let mut state: u64 = ts
            .tv_sec
            .wrapping_mul(6364136223846793005)
            .wrapping_add(ts.tv_nsec)
            .wrapping_mul(1442695040888963407)
            .wrapping_add(pid)
            .wrapping_mul(2862933555777941757)
            .wrapping_add(*ctr);

        let mut i = 0usize;
        while i < buflen {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);

            // Extract bytes from state
            let bytes = state.to_le_bytes();
            let mut j = 0usize;
            while j < 8 && i < buflen {
                *buf.add(i) = bytes[j];
                i += 1;
                j += 1;
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// copy_file_range — not supported
// ---------------------------------------------------------------------------

/// copy_file_range — copy data between file descriptors
///
/// Copies up to `len` bytes from `fd_in` to `fd_out`.  If `off_in` or
/// `off_out` are non-null, they specify (and are updated with) the offset to
/// use instead of the current file position.  `flags` is reserved and must be 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_file_range(
    fd_in: i32,
    off_in: *mut i64,
    fd_out: i32,
    off_out: *mut i64,
    len: usize,
    _flags: u32,
) -> isize {
    unsafe {
        // If off_in is provided, seek to that offset (saving current pos)
        let saved_in: i64 = if !off_in.is_null() {
            let cur = salty::posix::posix_lseek(fd_in, 0, salty::consts::SEEK_CUR as i32);
            if cur < 0 {
                errno::set_errno(errno::EBADF);
                return -1;
            }
            let ret = salty::posix::posix_lseek(fd_in, *off_in, salty::consts::SEEK_SET as i32);
            if ret < 0 {
                errno::set_errno(errno::EINVAL);
                return -1;
            }
            cur
        } else {
            -1
        };

        let saved_out: i64 = if !off_out.is_null() {
            let cur = salty::posix::posix_lseek(fd_out, 0, salty::consts::SEEK_CUR as i32);
            if cur < 0 {
                // Restore fd_in if we moved it
                if !off_in.is_null() {
                    salty::posix::posix_lseek(fd_in, saved_in, salty::consts::SEEK_SET as i32);
                }
                errno::set_errno(errno::EBADF);
                return -1;
            }
            let ret = salty::posix::posix_lseek(fd_out, *off_out, salty::consts::SEEK_SET as i32);
            if ret < 0 {
                if !off_in.is_null() {
                    salty::posix::posix_lseek(fd_in, saved_in, salty::consts::SEEK_SET as i32);
                }
                errno::set_errno(errno::EINVAL);
                return -1;
            }
            cur
        } else {
            -1
        };

        // Read/write loop with stack buffer
        let mut buf = [0u8; 4096];
        let mut total: usize = 0;

        while total < len {
            let chunk = if len - total < 4096 {
                len - total
            } else {
                4096
            };
            let nr = salty::posix::posix_read(fd_in, buf.as_mut_ptr(), chunk as u64);
            if nr < 0 {
                if total == 0 {
                    // Restore positions and report error
                    if !off_in.is_null() {
                        salty::posix::posix_lseek(fd_in, saved_in, salty::consts::SEEK_SET as i32);
                    }
                    if !off_out.is_null() {
                        salty::posix::posix_lseek(
                            fd_out,
                            saved_out,
                            salty::consts::SEEK_SET as i32,
                        );
                    }
                    errno::set_errno(errno::EIO);
                    return -1;
                }
                break;
            }
            if nr == 0 {
                break; // EOF
            }

            let mut written: usize = 0;
            while written < nr as usize {
                let nw = salty::posix::posix_write(
                    fd_out,
                    buf.as_ptr().add(written),
                    (nr as usize - written) as u64,
                );
                if nw < 0 {
                    if total == 0 && written == 0 {
                        if !off_in.is_null() {
                            salty::posix::posix_lseek(
                                fd_in,
                                saved_in,
                                salty::consts::SEEK_SET as i32,
                            );
                        }
                        if !off_out.is_null() {
                            salty::posix::posix_lseek(
                                fd_out,
                                saved_out,
                                salty::consts::SEEK_SET as i32,
                            );
                        }
                        errno::set_errno(errno::EIO);
                        return -1;
                    }
                    // Partial copy — update offsets and return what we have
                    total += written;
                    if !off_in.is_null() {
                        *off_in += total as i64;
                        salty::posix::posix_lseek(fd_in, saved_in, salty::consts::SEEK_SET as i32);
                    }
                    if !off_out.is_null() {
                        *off_out += total as i64;
                        salty::posix::posix_lseek(
                            fd_out,
                            saved_out,
                            salty::consts::SEEK_SET as i32,
                        );
                    }
                    return total as isize;
                }
                if nw == 0 {
                    break;
                }
                written += nw as usize;
            }
            total += written;
        }

        // Update offset pointers and restore file positions
        if !off_in.is_null() {
            *off_in += total as i64;
            salty::posix::posix_lseek(fd_in, saved_in, salty::consts::SEEK_SET as i32);
        }
        if !off_out.is_null() {
            *off_out += total as i64;
            salty::posix::posix_lseek(fd_out, saved_out, salty::consts::SEEK_SET as i32);
        }

        total as isize
    }
}

// ---------------------------------------------------------------------------
// POSIX semaphores — backed by salty::sync::Semaphore
// ---------------------------------------------------------------------------

/// Timespec for timed semaphore operations (matches pthread_impl.rs layout)
#[repr(C)]
struct SemTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn sem_timespec_to_relative_ns(abstime: &SemTimespec) -> u64 {
    let now = salty::syscall::syscall(salty::consts::SYS_CLOCK_GETTIME, 0, 0, 0, 0, 0, 0);
    let now_ns = now.value;
    let target_ns = (abstime.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(abstime.tv_nsec as u64);
    target_ns.saturating_sub(now_ns)
}

#[inline]
fn sem_validate_timespec(ts: &SemTimespec) -> bool {
    ts.tv_sec >= 0 && ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_init(sem: *mut u8, pshared: i32, value: u32) -> i32 {
    if sem.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    if pshared != 0 {
        errno::set_errno(errno::ENOSYS);
        return -1;
    }
    if value > salty::sync::SEM_VALUE_MAX {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        core::ptr::write(
            sem as *mut salty::sync::Semaphore,
            salty::sync::Semaphore::new(value),
        );
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_destroy(_sem: *mut u8) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_wait(sem: *mut u8) -> i32 {
    if sem.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let s = &*(sem as *const salty::sync::Semaphore);
        s.wait();
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_trywait(sem: *mut u8) -> i32 {
    if sem.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let s = &*(sem as *const salty::sync::Semaphore);
        if s.try_wait() {
            0
        } else {
            errno::set_errno(errno::EAGAIN);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_timedwait(sem: *mut u8, abstime: *const SemTimespec) -> i32 {
    if sem.is_null() || abstime.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        if !sem_validate_timespec(&*abstime) {
            errno::set_errno(errno::EINVAL);
            return -1;
        }
        let s = &*(sem as *const salty::sync::Semaphore);
        let timeout_ns = sem_timespec_to_relative_ns(&*abstime);
        if timeout_ns == 0 {
            if s.try_wait() {
                return 0;
            }
            errno::set_errno(errno::ETIMEDOUT);
            return -1;
        }
        let ret = s.wait_timeout(timeout_ns);
        if ret != 0 {
            errno::set_errno(errno::ETIMEDOUT);
            return -1;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_post(sem: *mut u8) -> i32 {
    if sem.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let s = &*(sem as *const salty::sync::Semaphore);
        let ret = s.post();
        if ret < 0 {
            errno::set_errno(errno::EOVERFLOW);
            return -1;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_getvalue(sem: *mut u8, sval: *mut i32) -> i32 {
    if sem.is_null() || sval.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let s = &*(sem as *const salty::sync::Semaphore);
        *sval = s.get_value();
    }
    0
}

// ---------------------------------------------------------------------------
// popen / pclose — pipe to process via fork+exec
// ---------------------------------------------------------------------------

const MAX_POPEN_ENTRIES: usize = 8;

struct PopenEntry {
    fp: *mut crate::stdio::FILE,
    pid: i32,
}

static mut POPEN_TABLE: [PopenEntry; MAX_POPEN_ENTRIES] = {
    const EMPTY: PopenEntry = PopenEntry {
        fp: core::ptr::null_mut(),
        pid: 0,
    };
    [EMPTY; MAX_POPEN_ENTRIES]
};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn popen(cmd: *const u8, mode: *const u8) -> *mut crate::stdio::FILE {
    unsafe {
        if cmd.is_null() || mode.is_null() {
            errno::set_errno(errno::EINVAL);
            return core::ptr::null_mut();
        }

        let m = *mode;
        let is_read = m == b'r';
        let is_write = m == b'w';
        if !is_read && !is_write {
            errno::set_errno(errno::EINVAL);
            return core::ptr::null_mut();
        }

        let mut fds = [0i32; 2];
        if crate::unistd::pipe(fds.as_mut_ptr()) < 0 {
            return core::ptr::null_mut();
        }

        let pid = crate::process::fork();
        if pid < 0 {
            salty::posix::posix_close(fds[0]);
            salty::posix::posix_close(fds[1]);
            return core::ptr::null_mut();
        }

        if pid == 0 {
            // Child
            if is_read {
                salty::posix::posix_close(fds[0]);
                crate::unistd::dup2(fds[1], 1); // stdout → pipe write end
                salty::posix::posix_close(fds[1]);
            } else {
                salty::posix::posix_close(fds[1]);
                crate::unistd::dup2(fds[0], 0); // stdin → pipe read end
                salty::posix::posix_close(fds[0]);
            }
            crate::process::execl(
                b"/bin/sh\0".as_ptr(),
                b"sh\0".as_ptr(),
                b"-c\0".as_ptr(),
                cmd,
                core::ptr::null::<u8>(),
            );
            crate::crt::_exit(127);
        }

        // Parent
        let (parent_fd, close_fd) = if is_read {
            (fds[0], fds[1])
        } else {
            (fds[1], fds[0])
        };
        salty::posix::posix_close(close_fd);

        let mode_str = if is_read {
            b"r\0".as_ptr()
        } else {
            b"w\0".as_ptr()
        };
        let fp = crate::stdio::fdopen(parent_fd, mode_str);
        if fp.is_null() {
            salty::posix::posix_close(parent_fd);
            return core::ptr::null_mut();
        }

        // Record in popen table for pclose
        for entry in &mut *addr_of_mut!(POPEN_TABLE) {
            if entry.fp.is_null() {
                entry.fp = fp;
                entry.pid = pid;
                break;
            }
        }

        fp
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pclose(stream: *mut crate::stdio::FILE) -> i32 {
    unsafe {
        if stream.is_null() {
            errno::set_errno(errno::EINVAL);
            return -1;
        }

        let mut pid: i32 = -1;
        for entry in &mut *addr_of_mut!(POPEN_TABLE) {
            if entry.fp == stream {
                pid = entry.pid;
                entry.fp = core::ptr::null_mut();
                entry.pid = 0;
                break;
            }
        }

        crate::stdio::fclose(stream);

        if pid < 0 {
            errno::set_errno(errno::ECHILD);
            return -1;
        }

        let mut status: i32 = 0;
        crate::process::waitpid(pid, &mut status, 0);
        status
    }
}
