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

// ======================================================================
// Socket operations
// ======================================================================

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

pub unsafe fn posix_pipe(fds: *mut i32) -> i32 {
    unsafe { posix_pipe2(fds, 0) }
}

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

pub unsafe fn posix_usleep(usec: u64) -> i32 {
    let seconds = usec / 1_000_000;
    let nanos = (usec % 1_000_000) * 1_000;
    let res = crate::syscall::syscall(SYS_NANOSLEEP, seconds, nanos, 0, 0, 0, 0);
    if res.error != 0 { -1 } else { 0 }
}

pub unsafe fn posix_sleep(seconds: u64) -> u64 {
    let res = crate::syscall::syscall(SYS_NANOSLEEP, seconds, 0, 0, 0, 0, 0);
    if res.error != 0 { seconds } else { 0 }
}

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

pub unsafe fn posix_getcwd(buf: *mut u8, size: u64) -> i32 {
    unsafe {
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
        let src = &reply.regs[1] as *const u64 as *const u8;
        let copy_len = if path_len < size as usize { path_len } else { size as usize - 1 };
        for i in 0..copy_len {
            *buf.add(i) = *src.add(i);
        }
        *buf.add(copy_len) = 0;
        0
    }
}
