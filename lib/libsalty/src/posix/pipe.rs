// SPDX-License-Identifier: GPL-2.0-only
//! POSIX pipe, pipe2, dup/dup2/dup3, mkfifo operations.

use crate::consts::*;
use crate::types::*;
use super::{pack_path, CAP_VFS_EP};

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

/// Create a named pipe (FIFO) at `path`. Returns 0 on success, -1 on error.
pub unsafe fn posix_mkfifo(path: *const u8, mode: u32) -> i32 {
    unsafe {
        let mode = mode & !super::misc::get_umask();
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_MKFIFO;
        msg.regs[0] = mode as u64;
        let path_len = pack_path(&raw mut msg, 1, path, 128);
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
