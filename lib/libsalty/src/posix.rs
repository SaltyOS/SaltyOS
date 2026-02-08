//! POSIX file I/O and process management wrappers
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::types::*;

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

pub unsafe fn posix_exit(status: i32) -> ! {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        msg.label = POSIX_PM_EXIT;
        msg.length = 1;
        msg.regs[0] = status as u64;

        crate::ipc::send_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
        );
    }
    loop {
        crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

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

pub unsafe fn posix_waitpid(pid: i32, status: *mut i32) -> i32 {
    unsafe { posix_waitpid3(pid, status, 0) }
}

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

pub unsafe fn posix_lstat(path: *const u8, st: *mut SaltyStat) -> i32 {
    unsafe { posix_stat(path, st) }
}

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

pub unsafe fn posix_closedir(dir_fd: i32) -> i32 {
    unsafe { posix_close(dir_fd) }
}

pub unsafe fn posix_execve(path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_EXEC;

        let mut path_len: u8 = 0;
        while *path.add(path_len as usize) != 0 && path_len < 64 {
            path_len += 1;
        }

        msg.regs[0] = path_len as u64;
        for i in 1..20 {
            msg.regs[i] = 0;
        }
        let dst = &mut msg.regs[1] as *mut u64 as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path.add(i);
        }
        msg.length = 1 + ((path_len as u64 + 7) / 8);

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

// posix_fork is defined in fork.S (assembly trampoline)
unsafe extern "C" {
    pub safe fn posix_fork() -> i32;
}
