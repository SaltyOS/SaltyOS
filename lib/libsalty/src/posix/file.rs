// SPDX-License-Identifier: GPL-2.0-only
//! POSIX file operations (open, read, write, close, stat, lseek, access, unlink).

use super::{pack_path, CAP_VFS_EP};
use crate::consts::*;
use crate::types::*;

/// Open a file at `path` with the given `flags` (O_RDONLY, O_CREAT, etc.).
/// `mode` specifies permission bits when creating a file (masked with 0o777).
///
/// Returns the new file descriptor on success, or -1 on error.
pub unsafe fn posix_open(path: *const u8, flags: i32, mode: u32) -> i32 {
    unsafe {
        let mode = mode & !super::misc::get_umask();
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_OPEN;
        msg.regs[0] = mode as u64;
        msg.regs[1] = flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 2, path, 128);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Read up to `count` bytes from file descriptor `fd` into `buf`.
///
/// Performs chunked IPC reads (max 152 bytes per round-trip) in a loop.
/// Returns the total bytes read, or -1 on error.
pub unsafe fn posix_read(fd: i32, buf: *mut u8, count: u64) -> i64 {
    unsafe {
        let mut total: u64 = 0;

        while total < count {
            let mut chunk = count - total;
            if chunk > 152 {
                chunk = 152;
            }

            let mut msg = SaltyMsg::zeroed();
            let mut reply = SaltyMsg::zeroed();
            msg.label = POSIX_VFS_READ;
            msg.length = 2;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;

            let err = crate::ipc::call_ctx(
                crate::tls::current_ipc_ctx(),
                CAP_VFS_EP,
                &raw const msg,
                &raw mut reply,
            );
            if err != 0 || reply.label != SALTY_OK {
                if total > 0 {
                    return total as i64;
                }
                return if err != 0 {
                    -5
                } else {
                    super::salty_err_to_posix(reply.label) as i64
                };
            }

            let actual = reply.regs[0];
            if actual == 0 {
                break;
            }

            let src = &reply.regs[1] as *const u64 as *const u8;
            for i in 0..actual as usize {
                if total as usize + i < count as usize {
                    *buf.add(total as usize + i) = *src.add(i);
                }
            }

            total += actual;
            if actual < chunk {
                break;
            }
        }

        total as i64
    }
}

/// Write up to `count` bytes from `buf` to file descriptor `fd`.
///
/// Performs chunked IPC writes (max 144 bytes per round-trip) in a loop.
/// Returns the total bytes written, or -1 on error.
pub unsafe fn posix_write(fd: i32, buf: *const u8, count: u64) -> i64 {
    unsafe {
        let mut total: u64 = 0;

        while total < count {
            let mut chunk = count - total;
            if chunk > 144 {
                chunk = 144;
            }

            let mut msg = SaltyMsg::zeroed();
            let mut reply = SaltyMsg::zeroed();
            msg.label = POSIX_VFS_WRITE;
            msg.length = 2 + ((chunk + 7) / 8);
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;

            let dst = &mut msg.regs[2] as *mut u64 as *mut u8;
            for i in 0..chunk as usize {
                *dst.add(i) = *buf.add(total as usize + i);
            }

            let err = crate::ipc::call_ctx(
                crate::tls::current_ipc_ctx(),
                CAP_VFS_EP,
                &raw const msg,
                &raw mut reply,
            );
            if err != 0 || reply.label != SALTY_OK {
                if total > 0 {
                    return total as i64;
                }
                return if err != 0 {
                    -5
                } else {
                    super::salty_err_to_posix(reply.label) as i64
                };
            }

            let actual = reply.regs[0];
            total += actual;
            if actual < chunk {
                break;
            }
        }

        total as i64
    }
}

/// Read up to `count` bytes from `fd` at `offset` without changing the file offset.
///
/// Uses a dedicated VFS PREAD protocol so the server handles the offset
/// atomically without touching the fd cursor.
/// Returns the number of bytes read, or a negative errno on error.
pub unsafe fn posix_pread(fd: i32, buf: *mut u8, count: u64, offset: i64) -> i64 {
    if offset < 0 {
        return -22; // EINVAL
    }
    unsafe {
        let mut total: u64 = 0;

        while total < count {
            let mut chunk = count - total;
            if chunk > 152 {
                chunk = 152;
            }

            let mut msg = SaltyMsg::zeroed();
            let mut reply = SaltyMsg::zeroed();
            msg.label = POSIX_VFS_PREAD;
            msg.length = 3;
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;
            let cur_off = match (offset as u64).checked_add(total) {
                Some(v) => v,
                None => return if total > 0 { total as i64 } else { -22 }, // EINVAL
            };
            msg.regs[2] = cur_off;

            let err = crate::ipc::call_ctx(
                crate::tls::current_ipc_ctx(),
                CAP_VFS_EP,
                &raw const msg,
                &raw mut reply,
            );
            if err != 0 || reply.label != SALTY_OK {
                if total > 0 {
                    return total as i64;
                }
                return if err != 0 {
                    -5
                } else {
                    super::salty_err_to_posix(reply.label) as i64
                };
            }

            let actual = reply.regs[0];
            if actual == 0 {
                break;
            }

            let src = &reply.regs[1] as *const u64 as *const u8;
            for i in 0..actual as usize {
                if total as usize + i < count as usize {
                    *buf.add(total as usize + i) = *src.add(i);
                }
            }

            total += actual;
            if actual < chunk {
                break;
            }
        }

        total as i64
    }
}

/// Write up to `count` bytes to `fd` at `offset` without changing the file offset.
///
/// Uses a dedicated VFS PWRITE protocol so the server handles the offset
/// atomically without touching the fd cursor.
/// Returns the number of bytes written, or a negative errno on error.
pub unsafe fn posix_pwrite(fd: i32, buf: *const u8, count: u64, offset: i64) -> i64 {
    if offset < 0 {
        return -22; // EINVAL
    }
    unsafe {
        let mut total: u64 = 0;

        while total < count {
            let mut chunk = count - total;
            if chunk > 136 {
                chunk = 136;
            }

            let mut msg = SaltyMsg::zeroed();
            let mut reply = SaltyMsg::zeroed();
            msg.label = POSIX_VFS_PWRITE;
            msg.length = 3 + ((chunk + 7) / 8);
            msg.regs[0] = fd as u64;
            msg.regs[1] = chunk;
            let cur_off = match (offset as u64).checked_add(total) {
                Some(v) => v,
                None => return if total > 0 { total as i64 } else { -22 }, // EINVAL
            };
            msg.regs[2] = cur_off;

            let dst = &mut msg.regs[3] as *mut u64 as *mut u8;
            for i in 0..chunk as usize {
                *dst.add(i) = *buf.add(total as usize + i);
            }

            let err = crate::ipc::call_ctx(
                crate::tls::current_ipc_ctx(),
                CAP_VFS_EP,
                &raw const msg,
                &raw mut reply,
            );
            if err != 0 || reply.label != SALTY_OK {
                if total > 0 {
                    return total as i64;
                }
                return if err != 0 {
                    -5
                } else {
                    super::salty_err_to_posix(reply.label) as i64
                };
            }

            let actual = reply.regs[0];
            total += actual;
            if actual < chunk {
                break;
            }
        }

        total as i64
    }
}

/// Close a file descriptor. Returns 0 on success, -1 on error.
pub unsafe fn posix_close(fd: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_CLOSE;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Get file status by path. Populates `*st` with inode, mode, size, etc.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_stat(path: *const u8, st: *mut SaltyStat) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_STAT;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }

        if !st.is_null() {
            (*st).st_ino = reply.regs[0];
            (*st).st_mode = reply.regs[1];
            (*st).st_nlink = reply.regs[2];
            (*st).st_size = reply.regs[3];
            (*st).st_uid = reply.regs[4];
            (*st).st_gid = reply.regs[5];
            (*st).st_mtime = reply.regs[6];
            (*st).st_type = reply.regs[7];
        }
        0
    }
}

/// Get file status by path (symlink-aware). Currently identical to `posix_stat`.
pub unsafe fn posix_lstat(path: *const u8, st: *mut SaltyStat) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_LSTAT;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }

        if !st.is_null() {
            (*st).st_ino = reply.regs[0];
            (*st).st_mode = reply.regs[1];
            (*st).st_nlink = reply.regs[2];
            (*st).st_size = reply.regs[3];
            (*st).st_uid = reply.regs[4];
            (*st).st_gid = reply.regs[5];
            (*st).st_mtime = reply.regs[6];
            (*st).st_type = reply.regs[7];
        }
        0
    }
}

/// Get file status by open file descriptor. Returns 0 on success, -1 on error.
pub unsafe fn posix_fstat(fd: i32, st: *mut SaltyStat) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FSTAT;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }

        if !st.is_null() {
            (*st).st_ino = reply.regs[0];
            (*st).st_mode = reply.regs[1];
            (*st).st_nlink = reply.regs[2];
            (*st).st_size = reply.regs[3];
            (*st).st_uid = reply.regs[4];
            (*st).st_gid = reply.regs[5];
            (*st).st_mtime = reply.regs[6];
            (*st).st_type = reply.regs[7];
        }
        0
    }
}

/// Reposition the file offset of `fd`. `whence` is SEEK_SET/CUR/END.
/// Returns the new offset on success, -1 on error.
pub unsafe fn posix_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_LSEEK;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = offset as u64;
        msg.regs[2] = whence as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label) as i64;
        }
        reply.regs[0] as i64
    }
}

/// Check file accessibility. `mode` is a bitmask of R_OK/W_OK/X_OK/F_OK.
/// Returns 0 if access is permitted, -1 on error.
pub unsafe fn posix_access(path: *const u8, mode: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_ACCESS;
        let path_len = pack_path(&raw mut msg, 1, path, 128);
        msg.regs[0] = mode as u64;
        msg.length = 2 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Remove (unlink) a file by path. Returns 0 on success, -1 on error.
pub unsafe fn posix_unlink(path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_UNLINK;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Rename a file from `old_path` to `new_path`.
///
/// Both paths are packed into message registers (old_len, new_len, then
/// path bytes). Returns 0 on success, -1 on error.
pub unsafe fn posix_rename(old_path: *const u8, new_path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_RENAME;

        let mut old_len: u8 = 0;
        while *old_path.add(old_len as usize) != 0 && old_len < 64 {
            old_len += 1;
        }
        let mut new_len: u8 = 0;
        while *new_path.add(new_len as usize) != 0 && new_len < 64 {
            new_len += 1;
        }

        msg.regs[0] = old_len as u64;
        msg.regs[1] = new_len as u64;
        for i in 2..20 {
            msg.regs[i] = 0;
        }
        let dst = &mut msg.regs[2] as *mut u64 as *mut u8;
        for i in 0..old_len as usize {
            *dst.add(i) = *old_path.add(i);
        }
        let dst2 = (&mut msg.regs[2 + ((old_len as usize + 7) / 8)]) as *mut u64 as *mut u8;
        for i in 0..new_len as usize {
            *dst2.add(i) = *new_path.add(i);
        }
        msg.length = 2 + ((old_len as u64 + 7) / 8) + ((new_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Create a directory at `path` with permissions `mode`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_mkdir(path: *const u8, mode: i32) -> i32 {
    unsafe {
        let mode = (mode as u32) & !super::misc::get_umask();
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_MKDIR;
        let path_len = pack_path(&raw mut msg, 1, path, 128);
        msg.regs[0] = mode as u64;
        msg.length = 2 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Remove an empty directory. Returns 0 on success, -1 on error.
pub unsafe fn posix_rmdir(path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_RMDIR;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Open a directory for iteration. Returns a directory fd on success, -1 on error.
pub unsafe fn posix_opendir(path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_OPENDIR;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Read the next directory entry from `dir_fd` into `*entry`.
///
/// Returns 1 if an entry was read, 0 at end-of-directory or on error.
/// The entry name is unpacked from IPC registers and null-terminated.
pub unsafe fn posix_readdir(dir_fd: i32, entry: *mut SaltyDirent) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_READDIR;
        msg.length = 1;
        msg.regs[0] = dir_fd as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return 0;
        }

        let name_len = reply.regs[0] as u8;
        if name_len == 0 {
            return 0;
        }

        if !entry.is_null() {
            (*entry).d_namlen = name_len;
            (*entry).d_ino = reply.regs[2];
            (*entry).d_type = reply.regs[3] as u8;
            let src = &reply.regs[4] as *const u64 as *const u8;
            let max_copy = if name_len < 127 { name_len } else { 127 };
            for i in 0..max_copy as usize {
                (*entry).d_name[i] = *src.add(i);
            }
            (*entry).d_name[max_copy as usize] = 0;
        }
        1
    }
}

/// Close a directory fd. Delegates to `posix_close`.
pub unsafe fn posix_closedir(dir_fd: i32) -> i32 {
    unsafe { posix_close(dir_fd) }
}

/// Truncate file `fd` to `length` bytes. Returns 0 on success, -1 on error.
pub unsafe fn posix_ftruncate(fd: i32, length: u64) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FTRUNCATE;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = length;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Create a symbolic link at `linkpath` pointing to `target`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_symlink(target: *const u8, linkpath: *const u8) -> i32 {
    unsafe { super::at::posix_symlinkat(target, -100, linkpath) }
}

/// Read the target of a symbolic link at `path`.
/// Returns the number of bytes placed in `buf`, or -1 on error.
pub unsafe fn posix_readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> i64 {
    unsafe { super::at::posix_readlinkat(-100, path, buf, bufsiz) }
}

/// Create a hard link: `newpath` becomes an additional name for `oldpath`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_link(oldpath: *const u8, newpath: *const u8) -> i32 {
    unsafe { super::at::posix_linkat(-100, oldpath, -100, newpath, 0) }
}
