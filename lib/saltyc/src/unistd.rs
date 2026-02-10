//! POSIX unistd wrappers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Each function calls the corresponding salty::posix::* or salty::posix_mm::*
//! function and sets errno on failure.

use crate::errno;

// ---------------------------------------------------------------------------
// C-compatible structures
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
}

#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

// ---------------------------------------------------------------------------
// Helper: translate SaltyStat -> Stat
// ---------------------------------------------------------------------------

unsafe fn translate_stat(salty_stat: &salty::types::SaltyStat, out: *mut Stat) {
    unsafe {
        (*out).st_dev = 0;
        (*out).st_ino = salty_stat.st_ino;
        (*out).st_mode = salty_stat.st_mode as u32;
        (*out).st_nlink = salty_stat.st_nlink as u32;
        (*out).st_uid = salty_stat.st_uid as u32;
        (*out).st_gid = salty_stat.st_gid as u32;
        (*out).st_rdev = 0;
        (*out).st_size = salty_stat.st_size as i64;
        (*out).st_blksize = 0;
        (*out).st_blocks = 0;
        (*out).st_atime = 0;
        (*out).st_atime_nsec = 0;
        (*out).st_mtime = salty_stat.st_mtime as i64;
        (*out).st_mtime_nsec = 0;
        (*out).st_ctime = 0;
        (*out).st_ctime_nsec = 0;
    }
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(path: *const u8, flags: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_open(path, flags);
        if ret < 0 {
            errno::set_errno(errno::ENOENT);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_close(fd);
        if ret < 0 {
            errno::set_errno(errno::EBADF);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, count: usize) -> isize {
    unsafe {
        let ret = salty::posix::posix_read(fd, buf, count as u64);
        if ret < 0 {
            errno::set_errno(errno::EIO);
        }
        ret as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    unsafe {
        let ret = salty::posix::posix_write(fd, buf, count as u64);
        if ret < 0 {
            errno::set_errno(errno::EIO);
        }
        ret as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe {
        let ret = salty::posix::posix_lseek(fd, offset, whence);
        if ret < 0 {
            errno::set_errno(errno::EINVAL);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup(oldfd: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_dup(oldfd);
        if ret < 0 {
            errno::set_errno(errno::EBADF);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup2(oldfd: i32, newfd: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_dup2(oldfd, newfd);
        if ret < 0 {
            errno::set_errno(errno::EBADF);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe(fds: *mut i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_pipe(fds);
        if ret < 0 {
            errno::set_errno(errno::ENOMEM);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe2(fds: *mut i32, flags: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_pipe2(fds, flags);
        if ret < 0 {
            errno::set_errno(errno::ENOMEM);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl(fd: i32, cmd: i32, mut args: ...) -> i32 {
    unsafe {
        let arg: i64 = args.arg();
        let ret = salty::posix::posix_fcntl(fd, cmd, arg);
        if ret < 0 {
            errno::set_errno(errno::EINVAL);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isatty(fd: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_isatty(fd);
        if ret == 0 {
            errno::set_errno(errno::ENOTTY);
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// Directory operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn chdir(path: *const u8) -> i32 {
    unsafe {
        let ret = salty::posix::posix_chdir(path);
        if ret < 0 {
            errno::set_errno(errno::ENOENT);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fchdir(_fd: i32) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
    if buf.is_null() || size == 0 {
        errno::set_errno(errno::EINVAL);
        return core::ptr::null_mut();
    }
    unsafe {
        let ret = salty::posix::posix_getcwd(buf, size as u64);
        if ret < 0 {
            errno::set_errno(errno::ERANGE);
            return core::ptr::null_mut();
        }
        buf
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn access(path: *const u8, mode: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_access(path, mode);
        if ret < 0 {
            errno::set_errno(errno::ENOENT);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(path: *const u8) -> i32 {
    unsafe {
        let ret = salty::posix::posix_unlink(path);
        if ret < 0 {
            errno::set_errno(errno::ENOENT);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(path: *const u8) -> i32 {
    unsafe {
        let ret = salty::posix::posix_rmdir(path);
        if ret < 0 {
            errno::set_errno(errno::ENOENT);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdir(path: *const u8, mode: u32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_mkdir(path, mode as i32);
        if ret < 0 {
            errno::set_errno(errno::ENOENT);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn link(_old: *const u8, _new: *const u8) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn symlink(_target: *const u8, _linkpath: *const u8) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readlink(
    _path: *const u8,
    _buf: *mut u8,
    _bufsiz: usize,
) -> isize {
    errno::set_errno(errno::ENOSYS);
    -1
}

// ---------------------------------------------------------------------------
// Stat
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stat(path: *const u8, buf: *mut Stat) -> i32 {
    if buf.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let mut salty_st = salty::types::SaltyStat::zeroed();
        let ret = salty::posix::posix_stat(path, &raw mut salty_st);
        if ret < 0 {
            errno::set_errno(errno::ENOENT);
            return -1;
        }
        translate_stat(&salty_st, buf);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lstat(path: *const u8, buf: *mut Stat) -> i32 {
    // No symlink support; identical to stat
    unsafe { stat(path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstat(fd: i32, buf: *mut Stat) -> i32 {
    if buf.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let mut salty_st = salty::types::SaltyStat::zeroed();
        let ret = salty::posix::posix_fstat(fd, &raw mut salty_st);
        if ret < 0 {
            errno::set_errno(errno::EBADF);
            return -1;
        }
        translate_stat(&salty_st, buf);
        0
    }
}

// ---------------------------------------------------------------------------
// File mode / truncate
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn umask(_mask: u32) -> u32 {
    0o022
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncate(_path: *const u8, _length: i64) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftruncate(fd: i32, length: i64) -> i32 {
    unsafe {
        let ret = salty::posix::posix_ftruncate(fd, length as u64);
        if ret < 0 {
            errno::set_errno(errno::EINVAL);
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// Path/file configuration
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pathconf(_path: *const u8, name: i32) -> i64 {
    // Return sensible defaults for common pathconf names
    match name {
        // _PC_LINK_MAX
        0 => 127,
        // _PC_MAX_CANON
        1 => 255,
        // _PC_MAX_INPUT
        2 => 255,
        // _PC_NAME_MAX
        3 => 255,
        // _PC_PATH_MAX
        4 => 4096,
        // _PC_PIPE_BUF
        5 => 4096,
        _ => -1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fpathconf(_fd: i32, name: i32) -> i64 {
    unsafe { pathconf(core::ptr::null(), name) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn confstr(_name: i32, _buf: *mut u8, _len: usize) -> usize {
    0
}

// ---------------------------------------------------------------------------
// Sleep / time
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sleep(seconds: u32) -> u32 {
    unsafe { salty::posix::posix_sleep(seconds as u64) as u32 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn usleep(usec: u32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_usleep(usec as u64);
        if ret < 0 {
            errno::set_errno(errno::EINVAL);
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> i32 {
    if req.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        // Convert from our i64-based Timespec to salty's u64-based Timespec
        let salty_req = salty::types::Timespec {
            tv_sec: (*req).tv_sec as u64,
            tv_nsec: (*req).tv_nsec as u64,
        };
        let mut salty_rem = salty::types::Timespec::zeroed();
        let ret = salty::posix::posix_nanosleep(
            &raw const salty_req,
            &raw mut salty_rem,
        );
        if !rem.is_null() {
            (*rem).tv_sec = salty_rem.tv_sec as i64;
            (*rem).tv_nsec = salty_rem.tv_nsec as i64;
        }
        if ret < 0 {
            errno::set_errno(errno::EINTR);
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// Signals / timer stubs
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn alarm(_seconds: u32) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pause() -> i32 {
    errno::set_errno(errno::EINTR);
    -1
}
