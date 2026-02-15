//! POSIX file I/O and process management wrappers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Every POSIX operation is implemented as an IPC `Call` to either the VFS
//! server (`CAP_VFS_EP`) or the process manager (`CAP_PROCMGR_EP`). The
//! client packs arguments into a `SaltyMsg`, sends it, and unpacks the
//! reply. No kernel objects are created -- all state lives in the servers.
//!
//! # Data transfer chunking
//!
//! `posix_read` and `posix_write` transfer data in chunks of up to 152/144
//! bytes per IPC round-trip (limited by the 20-register message buffer).
//! Large reads/writes loop until the full count is transferred or EOF.
//!
//! # Path encoding
//!
//! Filesystem paths are packed into message registers by `pack_path()`:
//! `regs[offset]` = path length (max 64), followed by the path bytes
//! packed into subsequent u64 registers.

use crate::consts::*;
use crate::types::*;

/// Pack a null-terminated path into message registers starting at `offset`.
///
/// Writes the path length into `regs[offset]` and the path bytes (up to 64)
/// into `regs[offset+1..]`. Returns the path length.
unsafe fn pack_path(msg: *mut SaltyMsg, offset: usize, path: *const u8) -> u8 {
    unsafe {
        let mut path_len: u8 = 0;
        while *path.add(path_len as usize) != 0 && path_len < 64 {
            path_len += 1;
        }
        (*msg).regs[offset] = path_len as u64;
        for i in (offset + 1)..20 {
            (*msg).regs[i] = 0;
        }
        let dst = &mut (*msg).regs[offset + 1] as *mut u64 as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path.add(i);
        }
        path_len
    }
}

/// Open a file at `path` with the given `flags` (O_RDONLY, O_CREAT, etc.).
///
/// Returns the new file descriptor on success, or -1 on error.
pub unsafe fn posix_open(path: *const u8, flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_OPEN;
        msg.regs[0] = 0;
        msg.regs[1] = flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
                &raw mut crate::__salty_ipc_ctx,
                CAP_VFS_EP,
                &raw const msg,
                &raw mut reply,
            );
            if err != 0 || reply.label != SALTY_OK {
                return if total > 0 { total as i64 } else { -1 };
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
                &raw mut crate::__salty_ipc_ctx,
                CAP_VFS_EP,
                &raw const msg,
                &raw mut reply,
            );
            if err != 0 || reply.label != SALTY_OK {
                return if total > 0 { total as i64 } else { -1 };
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
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Terminate the current process with `status`.
///
/// Sends `PM_EXIT` to the process manager via blocking Call. The procmgr
/// never replies -- the child stays in ReplyWait until TCB_SUSPEND moves
/// it to Inactive. This avoids the yield-loop that starves SCHED_IPC_LOCK
/// on SMP.
pub unsafe fn posix_exit(status: i32) -> ! {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        msg.label = POSIX_PM_EXIT;
        msg.length = 1;
        msg.regs[0] = status as u64;

        // Call blocks waiting for reply; procmgr never replies for PM_EXIT,
        // so the child stays in ReplyWait until TCB_SUSPEND moves it to Inactive.
        // This avoids the yield-loop that starves SCHED_IPC_LOCK on SMP.
        let mut reply = SaltyMsg::zeroed();
        crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
    }
    // Unreachable: call never returns since procmgr never replies
    loop {
        crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

/// Return the process ID of the calling process.
pub unsafe fn posix_getpid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETPID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Return the parent process ID of the calling process.
pub unsafe fn posix_getppid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETPPID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Wait for a child process to change state.
///
/// `pid` selects which child (-1 = any). `options` may include WNOHANG.
/// On success, writes the wait status to `*status` and returns the child PID.
/// Returns -1 on error.
pub unsafe fn posix_waitpid3(pid: i32, status: *mut i32, options: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_WAIT;
        msg.length = 2;
        msg.regs[0] = pid as u32 as u64;
        msg.regs[1] = options as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        if !status.is_null() {
            *status = reply.regs[0] as i32;
        }
        reply.regs[1] as i32
    }
}

/// Convenience wrapper for `posix_waitpid3` with `options=0` (blocking).
pub unsafe fn posix_waitpid(pid: i32, status: *mut i32) -> i32 {
    unsafe { posix_waitpid3(pid, status, 0) }
}

/// Get file status by path. Populates `*st` with inode, mode, size, etc.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_stat(path: *const u8, st: *mut SaltyStat) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_STAT;
        let path_len = pack_path(&raw mut msg, 0, path);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
    unsafe { posix_stat(path, st) }
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
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
        let path_len = pack_path(&raw mut msg, 1, path);
        msg.regs[0] = mode as u64;
        msg.length = 2 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
        let path_len = pack_path(&raw mut msg, 0, path);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Create a directory at `path` with permissions `mode`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_mkdir(path: *const u8, mode: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_MKDIR;
        let path_len = pack_path(&raw mut msg, 1, path);
        msg.regs[0] = mode as u64;
        msg.length = 2 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
        let path_len = pack_path(&raw mut msg, 0, path);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
        let path_len = pack_path(&raw mut msg, 0, path);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
            &raw mut crate::__salty_ipc_ctx,
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
            let max_copy = if name_len < 61 { name_len } else { 61 };
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

/// Replace the current process image with a new program.
///
/// Packs the executable path, argv, and envp into a single IPC message to
/// the process manager. Arguments and environment strings are packed
/// contiguously (null-terminated) into the remaining message registers.
/// Returns 0 on success (caller is replaced), -1 on error.
pub unsafe fn posix_execve(
    path: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_EXEC;

        let mut path_len: u8 = 0;
        while *path.add(path_len as usize) != 0 && path_len < 64 {
            path_len += 1;
        }

        // regs[0] = path_len
        msg.regs[0] = path_len as u64;
        let dst = &mut msg.regs[1] as *mut u64 as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path.add(i);
        }
        let path_regs = 1 + ((path_len as u64 + 7) / 8) as usize;

        // Count argc and envc, and total string data length
        let mut argc: u32 = 0;
        let mut envc: u32 = 0;
        let mut total_str_len: usize = 0;

        if !argv.is_null() {
            let mut i = 0;
            while !(*argv.add(i)).is_null() {
                let mut slen = 0usize;
                while *(*argv.add(i)).add(slen) != 0 {
                    slen += 1;
                }
                total_str_len += slen + 1; // include null terminator
                argc += 1;
                i += 1;
            }
        }
        if !envp.is_null() {
            let mut i = 0;
            while !(*envp.add(i)).is_null() {
                let mut slen = 0usize;
                while *(*envp.add(i)).add(slen) != 0 {
                    slen += 1;
                }
                total_str_len += slen + 1;
                envc += 1;
                i += 1;
            }
        }

        // regs[path_regs] = (argc << 32) | envc
        let next = path_regs;
        msg.regs[next] = ((argc as u64) << 32) | (envc as u64);

        // Pack null-terminated strings contiguously into regs[next+1..]
        let str_start = next + 1;
        let avail_bytes = (20 - str_start) * 8;
        let copy_len = if total_str_len > avail_bytes { avail_bytes } else { total_str_len };

        let str_dst = &mut msg.regs[str_start] as *mut u64 as *mut u8;
        let mut pos = 0usize;

        if !argv.is_null() {
            let mut i = 0;
            while !(*argv.add(i)).is_null() && pos < copy_len {
                let arg = *argv.add(i);
                let mut j = 0usize;
                while *arg.add(j) != 0 && pos < copy_len {
                    *str_dst.add(pos) = *arg.add(j);
                    pos += 1;
                    j += 1;
                }
                if pos < copy_len {
                    *str_dst.add(pos) = 0;
                    pos += 1;
                }
                i += 1;
            }
        }
        if !envp.is_null() {
            let mut i = 0;
            while !(*envp.add(i)).is_null() && pos < copy_len {
                let env = *envp.add(i);
                let mut j = 0usize;
                while *env.add(j) != 0 && pos < copy_len {
                    *str_dst.add(pos) = *env.add(j);
                    pos += 1;
                    j += 1;
                }
                if pos < copy_len {
                    *str_dst.add(pos) = 0;
                    pos += 1;
                }
                i += 1;
            }
        }

        let str_regs = (pos + 7) / 8;
        msg.length = (str_start + str_regs) as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Send signal `sig` to process `pid`. Returns 0 on success, -1 on error.
pub unsafe fn posix_kill(pid: i32, sig: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_KILL;
        msg.length = 2;
        msg.regs[0] = pid as u32 as u64;
        msg.regs[1] = sig as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Fork the current process, returning the child PID to the parent and 0
/// to the child. Defined in `fork.S` (assembly trampoline that issues the
/// PM_FORK IPC and re-initializes the child's IPC context).
unsafe extern "C" {
    pub safe fn posix_fork() -> i32;
}

// ======================================================================
// Socket operations
// ======================================================================

/// Create a socket. `domain` is AF_UNIX, `sock_type` is SOCK_STREAM/DGRAM.
/// Returns the socket fd on success, -1 on error.
pub unsafe fn posix_socket(domain: i32, sock_type: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SOCKET;
        msg.length = 2;
        msg.regs[0] = domain as u64;
        msg.regs[1] = sock_type as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Bind a Unix domain socket `fd` to the filesystem `path`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_bind(fd: i32, path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_BIND;
        msg.regs[0] = fd as u64;
        let path_len = pack_path(&raw mut msg, 1, path);
        msg.length = 2 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Mark socket `fd` as a passive socket with `backlog` pending connections.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_listen(fd: i32, backlog: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_LISTEN;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = backlog as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Accept a connection on listening socket `fd`.
/// Returns the new connected socket fd, or -1 on error.
pub unsafe fn posix_accept(fd: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_ACCEPT;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Connect socket `fd` to the Unix domain address at `path`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_connect(fd: i32, path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_CONNECT;
        msg.regs[0] = fd as u64;
        let path_len = pack_path(&raw mut msg, 1, path);
        msg.length = 2 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Shut down part of a socket connection. `how`: SHUT_RD/WR/RDWR.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_shutdown(fd: i32, how: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SHUTDOWN;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = how as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Create a pair of connected Unix domain sockets.
/// On success, writes `fds[0]` and `fds[1]` and returns 0.
pub unsafe fn posix_socketpair(fds: *mut i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SOCKPAIR;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        if !fds.is_null() {
            *fds = reply.regs[0] as i32;
            *fds.add(1) = reply.regs[1] as i32;
        }
        0
    }
}

/// Send a message with optional file descriptor passing (ancillary data).
///
/// `data`/`data_len` is the payload (max 120 bytes per call).
/// `fds_to_send`/`fd_count` lists file descriptors to pass via SCM_RIGHTS
/// (max 4 per call). Returns bytes sent on success, -1 on error.
pub unsafe fn posix_sendmsg(fd: i32, data: *const u8, data_len: u64, fds_to_send: *const i32, fd_count: u32) -> i64 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SENDMSG;
        msg.regs[0] = fd as u64;
        msg.regs[1] = data_len;
        msg.regs[2] = fd_count as u64;

        // Pack data starting at regs[3]
        let mut actual_data = data_len;
        if actual_data > 120 {
            actual_data = 120;
        }
        let dst = &mut msg.regs[3] as *mut u64 as *mut u8;
        for i in 0..actual_data as usize {
            *dst.add(i) = *data.add(i);
        }

        let data_regs = (actual_data + 7) / 8;
        // Pack fd numbers after data
        let fd_dst = &mut msg.regs[3 + data_regs as usize] as *mut u64 as *mut i32;
        let actual_fds = if fd_count > 4 { 4 } else { fd_count };
        for i in 0..actual_fds as usize {
            *fd_dst.add(i) = *fds_to_send.add(i);
        }

        msg.length = 3 + data_regs + ((actual_fds as u64 * 4 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i64
    }
}

/// Receive a message with optional file descriptor passing (ancillary data).
///
/// Reads up to `data_len` bytes into `data`. Received file descriptors
/// (SCM_RIGHTS) are written to `fds_out`, with `*fd_count` updated to the
/// actual number received. Returns bytes received, -1 on error.
pub unsafe fn posix_recvmsg(fd: i32, data: *mut u8, data_len: u64, fds_out: *mut i32, fd_count: *mut u32) -> i64 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_RECVMSG;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = data_len;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        let actual_data = reply.regs[0];
        let actual_fds = reply.regs[1] as u32;

        // Unpack data from regs[2..]
        let src = &reply.regs[2] as *const u64 as *const u8;
        for i in 0..actual_data as usize {
            if i < data_len as usize {
                *data.add(i) = *src.add(i);
            }
        }

        // Unpack fd numbers
        let data_regs = (actual_data + 7) / 8;
        let fd_src = &reply.regs[2 + data_regs as usize] as *const u64 as *const i32;
        if !fds_out.is_null() && !fd_count.is_null() {
            let max_fds = *fd_count;
            let copy_fds = if actual_fds < max_fds { actual_fds } else { max_fds };
            for i in 0..copy_fds as usize {
                *fds_out.add(i) = *fd_src.add(i);
            }
            *fd_count = actual_fds;
        }

        actual_data as i64
    }
}

// ======================================================================
// Poll / Select / Epoll
// ======================================================================

/// Wait for events on a set of file descriptors (max 8 per call).
///
/// Packs (fd, events) pairs into IPC registers. On return, `revents` in each
/// `PollFd` is populated with the triggered event mask. `timeout` is in
/// milliseconds (-1 = block indefinitely). Returns the number of ready fds,
/// or -1 on error.
pub unsafe fn posix_poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_POLL;

        let actual_nfds = if nfds > 8 { 8 } else { nfds };
        msg.regs[0] = actual_nfds as u64;
        msg.regs[1] = timeout as u64;

        // Pack (fd, events) pairs into regs[2..]
        for i in 0..actual_nfds as usize {
            msg.regs[2 + i * 2] = (*fds.add(i)).fd as u64;
            msg.regs[2 + i * 2 + 1] = (*fds.add(i)).events as u64;
        }
        msg.length = 2 + actual_nfds as u64 * 2;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        let ready_count = reply.regs[0] as i32;
        // Unpack revents from regs[1..]
        for i in 0..actual_nfds as usize {
            (*fds.add(i)).revents = reply.regs[1 + i] as i16;
        }

        ready_count
    }
}

/// Synchronous I/O multiplexing via fd_set bitmasks.
///
/// Implemented by converting `readfds`/`writefds` bitmasks to a poll array,
/// calling `posix_poll`, then rebuilding the bitmasks from results. Supports
/// up to 64 fds (single u64 bitmask). Returns the number of ready fds, or
/// -1 on error.
pub unsafe fn posix_select(nfds: i32, readfds: *mut u64, writefds: *mut u64, timeout: i32) -> i32 {
    unsafe {
        // Simple implementation: convert fd_sets to poll array
        let mut poll_fds: [PollFd; 8] = [PollFd::zeroed(); 8];
        let mut count: u32 = 0;

        let max_fd = if nfds > 64 { 64 } else { nfds };
        for fd in 0..max_fd {
            let mut events: i16 = 0;
            if !readfds.is_null() && (*readfds & (1u64 << fd)) != 0 {
                events |= crate::consts::POLLIN;
            }
            if !writefds.is_null() && (*writefds & (1u64 << fd)) != 0 {
                events |= crate::consts::POLLOUT;
            }
            if events != 0 && count < 8 {
                poll_fds[count as usize].fd = fd;
                poll_fds[count as usize].events = events;
                count += 1;
            }
        }

        if count == 0 {
            return 0;
        }

        let ret = posix_poll(poll_fds.as_mut_ptr(), count, timeout);
        if ret < 0 {
            return ret;
        }

        // Clear and rebuild fd_sets from revents
        if !readfds.is_null() { *readfds = 0; }
        if !writefds.is_null() { *writefds = 0; }

        let mut ready = 0;
        for i in 0..count as usize {
            if poll_fds[i].revents != 0 {
                let fd = poll_fds[i].fd;
                let mut counted = false;
                if !readfds.is_null()
                    && (poll_fds[i].revents & (crate::consts::POLLIN | crate::consts::POLLHUP | crate::consts::POLLERR)) != 0
                {
                    *readfds |= 1u64 << fd;
                    if !counted { ready += 1; counted = true; }
                }
                if !writefds.is_null() && (poll_fds[i].revents & crate::consts::POLLOUT) != 0 {
                    *writefds |= 1u64 << fd;
                    if !counted { ready += 1; }
                }
            }
        }
        ready
    }
}

/// Get terminal attributes for fd into `*termios_p`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_tcgetattr(fd: i32, termios_p: *mut crate::types::Termios) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_TCGETATTR;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        // Unpack: regs[0]=c_iflag, regs[1]=c_oflag, regs[2]=c_cflag, regs[3]=c_lflag
        // regs[4]=c_ispeed, regs[5]=c_ospeed, regs[6..9]=c_cc[0..31] packed as 4 u64s
        (*termios_p).c_iflag = reply.regs[0] as u32;
        (*termios_p).c_oflag = reply.regs[1] as u32;
        (*termios_p).c_cflag = reply.regs[2] as u32;
        (*termios_p).c_lflag = reply.regs[3] as u32;
        (*termios_p).c_ispeed = reply.regs[4] as u32;
        (*termios_p).c_ospeed = reply.regs[5] as u32;
        (*termios_p).c_line = 0;
        // Unpack c_cc from regs[6..9] (4 u64s = 32 bytes)
        let src = &reply.regs[6] as *const u64 as *const u8;
        for i in 0..32 {
            (*termios_p).c_cc[i] = *src.add(i);
        }
        0
    }
}

/// Set terminal attributes for fd from `*termios_p`.
/// `action` controls when changes take effect (TCSANOW/TCSADRAIN/TCSAFLUSH).
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_tcsetattr(fd: i32, action: i32, termios_p: *const crate::types::Termios) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_TCSETATTR;
        msg.length = 11;
        msg.regs[0] = fd as u64;
        msg.regs[1] = action as u64;
        msg.regs[2] = (*termios_p).c_iflag as u64;
        msg.regs[3] = (*termios_p).c_oflag as u64;
        msg.regs[4] = (*termios_p).c_cflag as u64;
        msg.regs[5] = (*termios_p).c_lflag as u64;
        msg.regs[6] = (*termios_p).c_ispeed as u64;
        msg.regs[7] = (*termios_p).c_ospeed as u64;
        // Pack c_cc into regs[8..11] (4 u64s = 32 bytes)
        let dst = &mut msg.regs[8] as *mut u64 as *mut u8;
        for i in 0..32 {
            *dst.add(i) = (*termios_p).c_cc[i];
        }

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Create an epoll instance. Returns the epoll fd, or -1 on error.
pub unsafe fn posix_epoll_create() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_EPOLL_CREATE;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Control an epoll instance: add/modify/delete `fd` with `events`/`data`.
/// `op` is EPOLL_CTL_ADD/MOD/DEL. Returns 0 on success, -1 on error.
pub unsafe fn posix_epoll_ctl(epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_EPOLL_CTL;
        msg.length = 5;
        msg.regs[0] = epfd as u64;
        msg.regs[1] = op as u64;
        msg.regs[2] = fd as u64;
        msg.regs[3] = events as u64;
        msg.regs[4] = data;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Wait for events on an epoll instance.
///
/// Blocks until at least one event is ready or `timeout` milliseconds elapse.
/// Returns the number of ready events written to `events`, or -1 on error.
pub unsafe fn posix_epoll_wait(
    epfd: i32,
    events: *mut crate::types::EpollEvent,
    maxevents: i32,
    timeout: i32,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_EPOLL_WAIT;
        msg.length = 3;
        msg.regs[0] = epfd as u64;
        msg.regs[1] = maxevents as u64;
        msg.regs[2] = timeout as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        let count = reply.regs[0] as i32;
        // Unpack events: reply.regs[1+i*2] = events, reply.regs[2+i*2] = data
        for i in 0..count as usize {
            if !events.is_null() {
                (*events.add(i)).events = reply.regs[1 + i * 2] as u32;
                (*events.add(i)).data = reply.regs[2 + i * 2];
            }
        }
        count
    }
}

// ======================================================================
// POSIX shared memory
// ======================================================================

/// Open a POSIX shared memory object by `name` (e.g. "/myshm").
///
/// Strips the leading '/' per POSIX convention before sending to VFS.
/// Returns the shm fd on success, -1 on error.
pub unsafe fn posix_shm_open(name: *const u8, flags: i32) -> i32 {
    unsafe {
        // POSIX: shm names are "/name"; strip leading '/' before sending bare name to VFS
        let bare = if !name.is_null() && *name == b'/' { name.add(1) } else { name };
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SHM_OPEN;
        msg.regs[0] = flags as u64;
        let name_len = pack_path(&raw mut msg, 1, bare);
        msg.length = 2 + ((name_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Remove a POSIX shared memory object by name.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_shm_unlink(name: *const u8) -> i32 {
    unsafe {
        // POSIX: shm names are "/name"; strip leading '/' before sending bare name to VFS
        let bare = if !name.is_null() && *name == b'/' { name.add(1) } else { name };
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SHM_UNLINK;
        let name_len = pack_path(&raw mut msg, 0, bare);
        msg.length = 1 + ((name_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

// ======================================================================
// Pipe / dup
// ======================================================================

/// Create a pipe. Convenience wrapper for `posix_pipe2(fds, 0)`.
pub unsafe fn posix_pipe(fds: *mut i32) -> i32 {
    unsafe { posix_pipe2(fds, 0) }
}

/// Create a pipe with `flags` (e.g. O_CLOEXEC, O_NONBLOCK).
/// On success, `fds[0]` is the read end, `fds[1]` is the write end.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_pipe2(fds: *mut i32, flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_PIPE;
        msg.length = 1;
        msg.regs[0] = flags as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        *fds = reply.regs[0] as i32;       // read fd
        *fds.add(1) = reply.regs[1] as i32; // write fd
        0
    }
}

/// Duplicate file descriptor `oldfd`. Returns the new fd, or -1 on error.
pub unsafe fn posix_dup(oldfd: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_DUP;
        msg.length = 1;
        msg.regs[0] = oldfd as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Duplicate `oldfd` to `newfd`, closing `newfd` first if open.
/// Returns `newfd` on success, -1 on error.
pub unsafe fn posix_dup2(oldfd: i32, newfd: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_DUP2;
        msg.length = 2;
        msg.regs[0] = oldfd as u64;
        msg.regs[1] = newfd as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Duplicate `oldfd` to `newfd` with `flags` (e.g. O_CLOEXEC).
/// Returns `newfd` on success, -1 on error.
pub unsafe fn posix_dup3(oldfd: i32, newfd: i32, flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_DUP3;
        msg.length = 3;
        msg.regs[0] = oldfd as u64;
        msg.regs[1] = newfd as u64;
        msg.regs[2] = flags as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Create a named pipe (FIFO) at `path`. Returns 0 on success, -1 on error.
pub unsafe fn posix_mkfifo(path: *const u8, _mode: u32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_MKFIFO;
        msg.regs[0] = 0; // reserved
        let path_len = pack_path(&raw mut msg, 1, path);
        msg.length = 2 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

// ======================================================================
// Time API
// ======================================================================

/// Read the monotonic clock, writing seconds and nanoseconds into `*ts`.
/// Uses the kernel `SYS_CLOCK_GETTIME` syscall directly (no IPC).
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_clock_gettime(clock_id: i32, ts: *mut crate::types::Timespec) -> i32 {
    unsafe {
        let res = crate::syscall::syscall(SYS_CLOCK_GETTIME, clock_id as u64, 0, 0, 0, 0, 0);
        if res.error != 0 {
            return -1;
        }
        let ns = res.value;
        (*ts).tv_sec = ns / 1_000_000_000;
        (*ts).tv_nsec = ns % 1_000_000_000;
        0
    }
}

/// Get the current time as seconds + microseconds into `*tv`.
/// Uses the kernel clock syscall, converting nanoseconds to microseconds.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_gettimeofday(tv: *mut crate::types::Timeval) -> i32 {
    unsafe {
        let res = crate::syscall::syscall(SYS_CLOCK_GETTIME, 0, 0, 0, 0, 0, 0);
        if res.error != 0 {
            return -1;
        }
        let ns = res.value;
        (*tv).tv_sec = ns / 1_000_000_000;
        (*tv).tv_usec = (ns % 1_000_000_000) / 1_000;
        0
    }
}

/// Sleep for the duration specified in `*req`.
/// If `rem` is non-null, any remaining time after interruption is written
/// there (always zero in current implementation). Returns 0 on success.
pub unsafe fn posix_nanosleep(req: *const crate::types::Timespec, rem: *mut crate::types::Timespec) -> i32 {
    unsafe {
        let seconds = (*req).tv_sec;
        let nanos = (*req).tv_nsec;
        let res = crate::syscall::syscall(SYS_NANOSLEEP, seconds, nanos, 0, 0, 0, 0);
        if !rem.is_null() {
            (*rem).tv_sec = 0;
            (*rem).tv_nsec = 0;
        }
        if res.error != 0 {
            return -1;
        }
        0
    }
}

/// Sleep for `usec` microseconds. Returns 0 on success, -1 on error.
pub unsafe fn posix_usleep(usec: u64) -> i32 {
    let seconds = usec / 1_000_000;
    let nanos = (usec % 1_000_000) * 1_000;
    let res = crate::syscall::syscall(SYS_NANOSLEEP, seconds, nanos, 0, 0, 0, 0);
    if res.error != 0 { -1 } else { 0 }
}

/// Sleep for `seconds`. Returns 0 on success, or remaining seconds on error.
pub unsafe fn posix_sleep(seconds: u64) -> u64 {
    let res = crate::syscall::syscall(SYS_NANOSLEEP, seconds, 0, 0, 0, 0, 0);
    if res.error != 0 { seconds } else { 0 }
}

/// Set the process group ID of process `pid` to `pgid`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_setpgid(pid: i32, pgid: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_SETPGID;
        msg.length = 2;
        msg.regs[0] = pid as u32 as u64;
        msg.regs[1] = pgid as u32 as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Get the process group ID of process `pid`. Returns pgid or -1 on error.
pub unsafe fn posix_getpgid(pid: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETPGID;
        msg.length = 1;
        msg.regs[0] = pid as u32 as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Create a new session and set the process as session leader.
/// Returns the new session ID, or -1 on error.
pub unsafe fn posix_setsid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_SETSID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Get the session ID of process `pid` (or caller when `pid==0`).
/// Returns sid on success, -1 on error.
pub unsafe fn posix_getsid(pid: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETSID;
        msg.length = 1;
        msg.regs[0] = pid as u32 as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Return the real user ID of the calling process.
pub unsafe fn posix_getuid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETUID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Return the effective user ID of the calling process.
pub unsafe fn posix_geteuid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETEUID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Return the real group ID of the calling process.
pub unsafe fn posix_getgid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETGID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Return the effective group ID of the calling process.
pub unsafe fn posix_getegid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETEGID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Get supplementary group IDs. Returns the number of groups, or -1 on error.
pub unsafe fn posix_getgroups(size: i32, _list: *mut i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETGROUPS;
        msg.length = 1;
        msg.regs[0] = size as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
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
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

// ======================================================================
// fcntl / isatty / chdir / getcwd / ioctl
// ======================================================================

/// File control operations (F_GETFL, F_SETFL, F_DUPFD, etc.).
/// Returns the result value on success, -1 on error.
pub unsafe fn posix_fcntl(fd: i32, cmd: i32, arg: i64) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCNTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = cmd as u64;
        msg.regs[2] = arg as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Test whether `fd` refers to a terminal. Returns 1 if yes, 0 if not.
pub unsafe fn posix_isatty(fd: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_ISATTY;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return 0;
        }
        reply.regs[0] as i32
    }
}

/// Generic device I/O control. Returns the result value, or -1 on error.
pub unsafe fn posix_ioctl(fd: i32, request: u64, arg: u64) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_IOCTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = request;
        msg.regs[2] = arg;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// Change the current working directory to `path`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_chdir(path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_CHDIR;
        let path_len = pack_path(&raw mut msg, 0, path);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Get the current working directory, writing the null-terminated path
/// into `buf` (up to `size` bytes). Returns 0 on success, -1 on error.
pub unsafe fn posix_getcwd(buf: *mut u8, size: u64) -> i32 {
    unsafe {
        if buf.is_null() || size == 0 {
            return -1;
        }

        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_GETCWD;
        msg.length = 1;
        msg.regs[0] = size;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        let path_len = reply.regs[0] as usize;
        let size_usize = size as usize;
        if path_len + 1 > size_usize {
            return -1;
        }
        let reply_data_bytes = (reply.length.saturating_sub(1) * 8) as usize;
        if path_len > reply_data_bytes {
            return -1;
        }

        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..path_len {
            *buf.add(i) = *src.add(i);
        }
        *buf.add(path_len) = 0;
        0
    }
}

// ======================================================================
// *at() family — dirfd-relative file operations
// ======================================================================

/// openat(dirfd, path, flags)
/// IPC: reg[0]=dirfd, reg[1]=open_flags, reg[2..]=path(len+data)
pub unsafe fn posix_openat(dirfd: i32, path: *const u8, flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_OPENAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        reply.regs[0] as i32
    }
}

/// fstatat(dirfd, path, statbuf, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub unsafe fn posix_fstatat(dirfd: i32, path: *const u8, st: *mut SaltyStat, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FSTATAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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

/// unlinkat(dirfd, path, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub unsafe fn posix_unlinkat(dirfd: i32, path: *const u8, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_UNLINKAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// renameat(old_dirfd, old_path, new_dirfd, new_path)
/// IPC: reg[0]=old_dirfd, reg[1]=new_dirfd, reg[2]=old_len, reg[3]=new_len, reg[4..]=paths
pub unsafe fn posix_renameat(
    old_dirfd: i32,
    old_path: *const u8,
    new_dirfd: i32,
    new_path: *const u8,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_RENAMEAT;

        let mut old_len: u8 = 0;
        while *old_path.add(old_len as usize) != 0 && old_len < 64 {
            old_len += 1;
        }
        let mut new_len: u8 = 0;
        while *new_path.add(new_len as usize) != 0 && new_len < 64 {
            new_len += 1;
        }

        msg.regs[0] = old_dirfd as u32 as u64;
        msg.regs[1] = new_dirfd as u32 as u64;
        msg.regs[2] = old_len as u64;
        msg.regs[3] = new_len as u64;
        for i in 4..20 {
            msg.regs[i] = 0;
        }
        let dst = &mut msg.regs[4] as *mut u64 as *mut u8;
        for i in 0..old_len as usize {
            *dst.add(i) = *old_path.add(i);
        }
        let dst2 = (&mut msg.regs[4 + ((old_len as usize + 7) / 8)]) as *mut u64 as *mut u8;
        for i in 0..new_len as usize {
            *dst2.add(i) = *new_path.add(i);
        }
        msg.length = 4 + ((old_len as u64 + 7) / 8) + ((new_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// mkdirat(dirfd, path, mode)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2..]=path(len+data)
pub unsafe fn posix_mkdirat(dirfd: i32, path: *const u8, mode: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_MKDIRAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        let path_len = pack_path(&raw mut msg, 2, path);
        msg.length = 3 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// faccessat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
pub unsafe fn posix_faccessat(dirfd: i32, path: *const u8, mode: i32, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FACCESSAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        msg.regs[2] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 3, path);
        msg.length = 4 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// fchmodat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
pub unsafe fn posix_fchmodat(dirfd: i32, path: *const u8, mode: u32, at_flags: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCHMODAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = mode as u64;
        msg.regs[2] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 3, path);
        msg.length = 4 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// fchownat(dirfd, path, uid, gid, flags)
/// IPC: reg[0]=dirfd, reg[1]=uid, reg[2]=gid, reg[3]=at_flags, reg[4..]=path(len+data)
pub unsafe fn posix_fchownat(
    dirfd: i32,
    path: *const u8,
    uid: u32,
    gid: u32,
    at_flags: i32,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCHOWNAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = uid as u64;
        msg.regs[2] = gid as u64;
        msg.regs[3] = at_flags as u32 as u64;
        let path_len = pack_path(&raw mut msg, 4, path);
        msg.length = 5 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// utimensat(dirfd, path, times, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..5]=times, reg[6..]=path(len+data)
pub unsafe fn posix_utimensat(
    dirfd: i32,
    path: *const u8,
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    at_flags: i32,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_UTIMENSAT;
        msg.regs[0] = dirfd as u32 as u64;
        msg.regs[1] = at_flags as u32 as u64;
        msg.regs[2] = atime_sec as u64;
        msg.regs[3] = atime_nsec as u64;
        msg.regs[4] = mtime_sec as u64;
        msg.regs[5] = mtime_nsec as u64;
        let path_len = pack_path(&raw mut msg, 6, path);
        msg.length = 7 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// fchmod(fd, mode) — change mode on open fd
/// IPC: reg[0]=fd, reg[1]=mode
pub unsafe fn posix_fchmod(fd: i32, mode: u32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCHMOD;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = mode as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// fchown(fd, uid, gid) — change owner on open fd
/// IPC: reg[0]=fd, reg[1]=uid, reg[2]=gid
pub unsafe fn posix_fchown(fd: i32, uid: u32, gid: u32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCHOWN;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = uid as u64;
        msg.regs[2] = gid as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        0
    }
}

/// Framebuffer ioctl wrapper.
///
/// Sends POSIX_VFS_IOCTL with an fb-specific command and unpacks up to 5 result registers.
pub unsafe fn posix_fb_ioctl(fd: i32, cmd: u64, result: *mut [u64; 5]) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_IOCTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = cmd;
        msg.regs[2] = 0;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }
        if !result.is_null() {
            for i in 0..5 {
                (*result)[i] = reply.regs[i];
            }
        }
        0
    }
}
