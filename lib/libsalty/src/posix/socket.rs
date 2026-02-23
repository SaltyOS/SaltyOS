// SPDX-License-Identifier: GPL-2.0-only
//! POSIX socket operations (socket, bind, listen, accept, connect, shutdown).

use crate::consts::*;
use crate::types::*;
use super::{pack_path, CAP_VFS_EP};

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

/// Create a pair of connected Unix domain sockets.
/// On success, writes `fds[0]` and `fds[1]` and returns 0.
pub unsafe fn posix_socketpair(fds: *mut i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SOCKPAIR;
        msg.length = 0;

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
