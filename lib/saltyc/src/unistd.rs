//! POSIX unistd wrappers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Thin wrappers around `salty::posix::*` and `salty::posix_mm::*` functions.
//! Each wrapper translates negative return values into `errno` settings.
//! Includes file I/O (`open`, `close`, `read`, `write`, `lseek`), directory
//! operations (`mkdir`, `rmdir`, `unlink`, `rename`), stat family, `mmap`,
//! `pipe`, `dup`/`dup2`, and the `*at()` family (`openat`, `fstatat`, etc.).

use crate::errno;

// ---------------------------------------------------------------------------
// C-compatible structures
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u16,
    pub st_padding0: i16,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_padding1: i32,
    pub st_rdev: u64,
    pub st_atim: Timespec,
    pub st_mtim: Timespec,
    pub st_ctim: Timespec,
    pub st_birthtim: Timespec,
    pub st_size: i64,
    pub st_blocks: i64,
    pub st_blksize: i32,
    pub st_flags: u32,
    pub st_gen: u64,
    pub st_spare: [u64; 10],
}

// ---------------------------------------------------------------------------
// Helper: translate SaltyStat -> Stat
// ---------------------------------------------------------------------------

unsafe fn translate_stat(salty_stat: &salty::types::SaltyStat, out: *mut Stat) {
    unsafe {
        core::ptr::write_bytes(out, 0, 1);

        (*out).st_dev = 0;
        (*out).st_ino = salty_stat.st_ino;
        (*out).st_nlink = salty_stat.st_nlink;
        (*out).st_mode = (salty_stat.st_mode & 0xffff) as u16;
        (*out).st_padding0 = 0;
        (*out).st_uid = salty_stat.st_uid as u32;
        (*out).st_gid = salty_stat.st_gid as u32;
        (*out).st_padding1 = 0;
        (*out).st_rdev = 0;
        (*out).st_size = salty_stat.st_size as i64;

        let blocks = salty_stat.st_size.saturating_add(511) / 512;
        (*out).st_blocks = if blocks > i64::MAX as u64 {
            i64::MAX
        } else {
            blocks as i64
        };
        (*out).st_blksize = 4096;

        let mtime = salty_stat.st_mtime as i64;
        (*out).st_atim.tv_sec = mtime;
        (*out).st_atim.tv_nsec = 0;
        (*out).st_mtim.tv_sec = mtime;
        (*out).st_mtim.tv_nsec = 0;
        (*out).st_ctim.tv_sec = mtime;
        (*out).st_ctim.tv_nsec = 0;
        (*out).st_birthtim.tv_sec = mtime;
        (*out).st_birthtim.tv_nsec = 0;

        (*out).st_flags = 0;
        (*out).st_gen = 0;
    }
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(path: *const u8, flags: i32, mut args: ...) -> i32 {
    unsafe {
        let mode: u32 = if (flags & salty::O_CREAT as i32) != 0 {
            args.arg::<u32>()
        } else {
            0
        };
        let ret = salty::posix::posix_open(path, flags, mode);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat(path: *const u8, _mode: u32) -> i32 {
    // creat(path, mode) == open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)
    unsafe { open(path, (salty::O_WRONLY | salty::O_CREAT | salty::O_TRUNC) as i32) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_close(fd);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, count: usize) -> isize {
    unsafe {
        let ret = salty::posix::posix_read(fd, buf, count as u64);
        if ret < 0 {
            errno::set_errno((-ret) as i32);
            return -1;
        }
        ret as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    unsafe {
        let ret = salty::posix::posix_write(fd, buf, count as u64);
        if ret < 0 {
            errno::set_errno((-ret) as i32);
            return -1;
        }
        ret as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe {
        let ret = salty::posix::posix_lseek(fd, offset, whence);
        if ret < 0 {
            errno::set_errno((-ret) as i32);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup(oldfd: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_dup(oldfd);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup2(oldfd: i32, newfd: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_dup2(oldfd, newfd);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe(fds: *mut i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_pipe(fds);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe2(fds: *mut i32, flags: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_pipe2(fds, flags);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
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
            errno::set_errno(-ret);
            return -1;
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
            errno::set_errno(-ret);
            return -1;
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
    unsafe {
        if buf.is_null() {
            // GNU extension: allocate buffer
            let alloc_size = if size == 0 { 4096 } else { size };
            let p = crate::malloc::malloc(alloc_size);
            if p.is_null() {
                errno::set_errno(errno::ENOMEM);
                return core::ptr::null_mut();
            }
            let ret = salty::posix::posix_getcwd(p, alloc_size as u64);
            if ret < 0 {
                crate::malloc::free(p);
                errno::set_errno(-ret);
                return core::ptr::null_mut();
            }
            return p;
        }
        if size == 0 {
            errno::set_errno(errno::EINVAL);
            return core::ptr::null_mut();
        }
        let ret = salty::posix::posix_getcwd(buf, size as u64);
        if ret < 0 {
            errno::set_errno(-ret);
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
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(path: *const u8) -> i32 {
    unsafe {
        let ret = salty::posix::posix_unlink(path);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(path: *const u8) -> i32 {
    unsafe {
        let ret = salty::posix::posix_rmdir(path);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdir(path: *const u8, mode: u32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_mkdir(path, mode as i32);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn link(old: *const u8, new: *const u8) -> i32 {
    unsafe {
        let ret = salty::posix::posix_link(old, new);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn symlink(target: *const u8, linkpath: *const u8) -> i32 {
    unsafe {
        let ret = salty::posix::posix_symlink(target, linkpath);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    unsafe {
        let ret = salty::posix::posix_readlink(path, buf, bufsiz);
        if ret < 0 {
            errno::set_errno((-ret) as i32);
            return -1;
        }
        ret as isize
    }
}

// ---------------------------------------------------------------------------
// Positioned I/O
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pread(fd: i32, buf: *mut u8, count: usize, offset: i64) -> isize {
    unsafe {
        let ret = salty::posix::posix_pread(fd, buf, count as u64, offset);
        if ret < 0 {
            errno::set_errno((-ret) as i32);
            return -1;
        }
        ret as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwrite(fd: i32, buf: *const u8, count: usize, offset: i64) -> isize {
    unsafe {
        let ret = salty::posix::posix_pwrite(fd, buf, count as u64, offset);
        if ret < 0 {
            errno::set_errno((-ret) as i32);
            return -1;
        }
        ret as isize
    }
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
            errno::set_errno(-ret);
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
            errno::set_errno(-ret);
            return -1;
        }
        translate_stat(&salty_st, buf);
        0
    }
}

// ---------------------------------------------------------------------------
// Scatter/gather I/O
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Iovec {
    pub iov_base: *const u8,
    pub iov_len: usize,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn writev(fd: i32, iov: *const Iovec, iovcnt: i32) -> isize {
    if iov.is_null() || iovcnt <= 0 {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let mut total: isize = 0;
        for i in 0..iovcnt as usize {
            let v = &*iov.add(i);
            if v.iov_len == 0 {
                continue;
            }
            let ret = salty::posix::posix_write(fd, v.iov_base, v.iov_len as u64);
            if ret < 0 {
                if total > 0 {
                    return total;
                }
                errno::set_errno((-ret) as i32);
                return -1;
            }
            total += ret as isize;
            if (ret as usize) < v.iov_len {
                break;
            }
        }
        total
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readv(fd: i32, iov: *const Iovec, iovcnt: i32) -> isize {
    if iov.is_null() || iovcnt <= 0 {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let mut total: isize = 0;
        for i in 0..iovcnt as usize {
            let v = &*iov.add(i);
            if v.iov_len == 0 {
                continue;
            }
            let ret = salty::posix::posix_read(fd, v.iov_base as *mut u8, v.iov_len as u64);
            if ret < 0 {
                if total > 0 {
                    return total;
                }
                errno::set_errno((-ret) as i32);
                return -1;
            }
            total += ret as isize;
            if ret == 0 || (ret as usize) < v.iov_len {
                break;
            }
        }
        total
    }
}

// ---------------------------------------------------------------------------
// File mode / truncate
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn umask(mask: u32) -> u32 {
    unsafe { salty::posix::posix_umask(mask) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncate(path: *const u8, length: i64) -> i32 {
    unsafe {
        let fd = salty::posix::posix_open(path, salty::O_WRONLY as i32, 0);
        if fd < 0 {
            errno::set_errno(-fd);
            return -1;
        }
        let ret = salty::posix::posix_ftruncate(fd, length as u64);
        salty::posix::posix_close(fd);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftruncate(fd: i32, length: i64) -> i32 {
    unsafe {
        let ret = salty::posix::posix_ftruncate(fd, length as u64);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
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
            errno::set_errno(-ret);
            return -1;
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
        let ret = salty::posix::posix_nanosleep(&raw const salty_req, &raw mut salty_rem);
        if !rem.is_null() {
            (*rem).tv_sec = salty_rem.tv_sec as i64;
            (*rem).tv_nsec = salty_rem.tv_nsec as i64;
        }
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
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

// ---------------------------------------------------------------------------
// Memory mapping (wrappers for libsalty posix_mm)
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(
    addr: *mut u8,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> *mut u8 {
    unsafe {
        let ret = salty::posix_mm::posix_mmap(addr, length as u64, prot, flags, fd, offset);
        if ret as usize == usize::MAX {
            errno::set_errno(errno::ENOMEM);
            return usize::MAX as *mut u8; // MAP_FAILED
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn madvise(_addr: *mut u8, _length: usize, _advice: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn munmap(addr: *mut u8, length: usize) -> i32 {
    unsafe {
        let ret = salty::posix_mm::posix_munmap(addr, length as u64);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// FIFO
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkfifo(path: *const u8, mode: u32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_mkfifo(path, mode);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// TTY name
// ---------------------------------------------------------------------------

static TTY_NAME: [u8; 9] = *b"/dev/tty\0";

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ttyname(fd: i32) -> *mut u8 {
    unsafe {
        if isatty(fd) == 0 {
            return core::ptr::null_mut();
        }
        TTY_NAME.as_ptr() as *mut u8
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ttyname_r(fd: i32, buf: *mut u8, len: usize) -> i32 {
    unsafe {
        if isatty(fd) == 0 {
            return errno::ENOTTY;
        }
        if buf.is_null() || len < 9 {
            return errno::ERANGE;
        }
        core::ptr::copy_nonoverlapping(TTY_NAME.as_ptr(), buf, 9);
        0
    }
}

// ---------------------------------------------------------------------------
// File permission — route through VFS
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn chmod(path: *const u8, mode: u32) -> i32 {
    unsafe { fchmodat(salty::consts::AT_FDCWD, path, mode, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fchmod(fd: i32, mode: u32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_fchmod(fd, mode);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn chown(path: *const u8, owner: u32, group: u32) -> i32 {
    unsafe { fchownat(salty::consts::AT_FDCWD, path, owner, group, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fchown(fd: i32, owner: u32, group: u32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_fchown(fd, owner, group);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lchown(path: *const u8, owner: u32, group: u32) -> i32 {
    unsafe {
        fchownat(
            salty::consts::AT_FDCWD,
            path,
            owner,
            group,
            salty::consts::AT_SYMLINK_NOFOLLOW,
        )
    }
}

// ---------------------------------------------------------------------------
// File locking — not implemented
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn flock(_fd: i32, _operation: i32) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

// ---------------------------------------------------------------------------
// *at() family — dirfd-relative file operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn openat(dirfd: i32, path: *const u8, flags: i32, mut args: ...) -> i32 {
    unsafe {
        let mode: u32 = if (flags & salty::O_CREAT as i32) != 0 {
            args.arg::<u32>()
        } else {
            0
        };
        let ret = salty::posix::posix_openat(dirfd, path, flags, mode);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatat(dirfd: i32, path: *const u8, buf: *mut Stat, flags: i32) -> i32 {
    if buf.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    unsafe {
        let mut salty_st = salty::types::SaltyStat::zeroed();
        let ret = salty::posix::posix_fstatat(dirfd, path, &raw mut salty_st, flags);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        translate_stat(&salty_st, buf);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlinkat(dirfd: i32, path: *const u8, flags: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_unlinkat(dirfd, path, flags);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn renameat(
    old_dirfd: i32,
    old_path: *const u8,
    new_dirfd: i32,
    new_path: *const u8,
) -> i32 {
    unsafe {
        let ret = salty::posix::posix_renameat(old_dirfd, old_path, new_dirfd, new_path);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdirat(dirfd: i32, path: *const u8, mode: u32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_mkdirat(dirfd, path, mode as i32);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mknodat(_dirfd: i32, _path: *const u8, _mode: u32, _dev: u64) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn faccessat(dirfd: i32, path: *const u8, mode: i32, flags: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_faccessat(dirfd, path, mode, flags);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fchmodat(dirfd: i32, path: *const u8, mode: u32, flags: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_fchmodat(dirfd, path, mode, flags);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fchownat(
    dirfd: i32,
    path: *const u8,
    owner: u32,
    group: u32,
    flags: i32,
) -> i32 {
    unsafe {
        let ret = salty::posix::posix_fchownat(dirfd, path, owner, group, flags);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkat(
    old_dirfd: i32,
    old_path: *const u8,
    new_dirfd: i32,
    new_path: *const u8,
    flags: i32,
) -> i32 {
    unsafe {
        let ret = salty::posix::posix_linkat(old_dirfd, old_path, new_dirfd, new_path, flags);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn symlinkat(target: *const u8, new_dirfd: i32, linkpath: *const u8) -> i32 {
    unsafe {
        let ret = salty::posix::posix_symlinkat(target, new_dirfd, linkpath);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readlinkat(
    dirfd: i32,
    path: *const u8,
    buf: *mut u8,
    bufsiz: usize,
) -> isize {
    unsafe {
        let ret = salty::posix::posix_readlinkat(dirfd, path, buf, bufsiz);
        if ret < 0 {
            errno::set_errno((-ret) as i32);
            return -1;
        }
        ret as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn utimensat(
    dirfd: i32,
    path: *const u8,
    times: *const Timespec,
    flags: i32,
) -> i32 {
    unsafe {
        let (atime_sec, atime_nsec, mtime_sec, mtime_nsec) = if times.is_null() {
            // NULL times means set both to current time
            let utime_now: i64 = (1 << 30) - 1;
            (0i64, utime_now, 0i64, utime_now)
        } else {
            (
                (*times).tv_sec,
                (*times).tv_nsec,
                (*times.add(1)).tv_sec,
                (*times.add(1)).tv_nsec,
            )
        };
        let ret = salty::posix::posix_utimensat(
            dirfd, path, atime_sec, atime_nsec, mtime_sec, mtime_nsec, flags,
        );
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn futimens(fd: i32, times: *const Timespec) -> i32 {
    unsafe {
        // futimens(fd, times) = utimensat(fd, "", times, AT_EMPTY_PATH)
        let empty = b"\0";
        let (atime_sec, atime_nsec, mtime_sec, mtime_nsec) = if times.is_null() {
            let utime_now: i64 = (1 << 30) - 1;
            (0i64, utime_now, 0i64, utime_now)
        } else {
            (
                (*times).tv_sec,
                (*times).tv_nsec,
                (*times.add(1)).tv_sec,
                (*times.add(1)).tv_nsec,
            )
        };
        let at_empty_path: i32 = 0x1000;
        let ret = salty::posix::posix_utimensat(
            fd,
            empty.as_ptr(),
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            at_empty_path,
        );
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup3(oldfd: i32, newfd: i32, flags: i32) -> i32 {
    unsafe {
        let ret = salty::posix::posix_dup3(oldfd, newfd, flags);
        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }
        ret
    }
}
