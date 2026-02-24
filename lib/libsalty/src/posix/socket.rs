// SPDX-License-Identifier: GPL-2.0-only
//! POSIX socket operations (socket, bind, listen, accept, connect, shutdown).
//!
//! Supports both AF_UNIX (path-based) and AF_INET (ip+port-based) sockets.

use crate::consts::*;
use crate::types::*;
use super::{pack_path, CAP_VFS_EP};

/// Create a socket. `domain` is AF_UNIX or AF_INET, `sock_type` is SOCK_STREAM/DGRAM.
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

/// Bind a socket `fd` to an address.
///
/// For AF_UNIX: `addr` points to a `SockAddrUn` (path-based).
/// For AF_INET: `addr` points to a `SockAddrIn` (ip+port).
/// Returns 0 on success, negative errno on error.
pub unsafe fn posix_bind(fd: i32, addr: *const u8, addr_len: u32) -> i32 {
    unsafe {
        if addr.is_null() {
            return -14; // EFAULT
        }
        if addr_len < 2 {
            return -22; // EINVAL
        }
        let family = *(addr as *const u16);
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_BIND;
        msg.regs[0] = fd as u64;

        if family == AF_INET as u16 {
            if addr_len < 8 {
                return -22; // EINVAL
            }
            let sa = &*(addr as *const SockAddrIn);
            msg.regs[1] = AF_INET as u64;
            msg.regs[2] = sa.addr as u64;
            msg.regs[3] = sa.port as u64;
            msg.length = 4;
        } else {
            // AF_UNIX: pack path from SockAddrUn.sun_path (offset 2 in struct)
            let path = addr.add(2);
            let max = (addr_len - 2) as usize;
            let path_len = pack_path(&raw mut msg, 1, path, max);
            msg.length = 2 + ((path_len as u64 + 7) / 8);
        }

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
/// Returns 0 on success, negative errno on error.
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
/// Returns the new connected socket fd, or negative errno on error.
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

/// Connect socket `fd` to an address.
///
/// For AF_UNIX: `addr` points to a path (null-terminated byte string).
/// For AF_INET: `addr` points to a `SockAddrIn`.
/// Returns 0 on success, negative errno on error.
pub unsafe fn posix_connect(fd: i32, addr: *const u8, addr_len: u32) -> i32 {
    unsafe {
        if addr.is_null() {
            return -14; // EFAULT
        }
        if addr_len < 2 {
            return -22; // EINVAL
        }
        let family = *(addr as *const u16);
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_CONNECT;
        msg.regs[0] = fd as u64;

        if family == AF_INET as u16 {
            if addr_len < 8 {
                return -22; // EINVAL
            }
            let sa = &*(addr as *const SockAddrIn);
            msg.regs[1] = sa.addr as u64;
            msg.regs[2] = sa.port as u64;
            msg.length = 3;
        } else {
            // AF_UNIX: pack path from SockAddrUn.sun_path (offset 2 in struct)
            let path = addr.add(2);
            let max = (addr_len - 2) as usize;
            let path_len = pack_path(&raw mut msg, 1, path, max);
            msg.length = 2 + ((path_len as u64 + 7) / 8);
        }

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
/// Returns 0 on success, negative errno on error.
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
/// (max 4 per call). Returns bytes sent on success, negative errno on error.
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
/// actual number received. Returns bytes received, negative errno on error.
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

/// Send data to a specific address (UDP sendto).
///
/// `addr` points to a `SockAddrIn` for AF_INET.
/// Returns bytes sent on success, negative errno on error.
pub unsafe fn posix_sendto(
    fd: i32,
    data: *const u8,
    data_len: usize,
    _flags: i32,
    addr: *const u8,
    addr_len: u32,
) -> i64 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SENDMSG;
        msg.regs[0] = fd as u64;

        let actual = if data_len > 120 { 120 } else { data_len };
        msg.regs[1] = actual as u64;
        msg.regs[2] = 0; // no fds

        // Check if this is an AF_INET sendto
        if !addr.is_null() && addr_len >= 8 {
            let family = *(addr as *const u16);
            if family == AF_INET as u16 {
                let sa = &*(addr as *const SockAddrIn);
                // Pack: regs[3]=dst_ip, regs[4]=dst_port, regs[5..]=data
                msg.regs[3] = sa.addr as u64;
                msg.regs[4] = sa.port as u64;
                let dst = &mut msg.regs[5] as *mut u64 as *mut u8;
                for i in 0..actual {
                    *dst.add(i) = *data.add(i);
                }
                msg.length = 5 + ((actual as u64 + 7) / 8);

                let err = crate::ipc::call_ctx(
                    crate::tls::current_ipc_ctx(),
                    CAP_VFS_EP,
                    &raw const msg,
                    &raw mut reply,
                );
                if err != 0 {
                    return -5;
                }
                if reply.label != SALTY_OK {
                    return super::salty_err_to_posix(reply.label) as i64;
                }
                return reply.regs[0] as i64;
            }
        }

        // Fallback: regular sendmsg (no address, no fds)
        let dst = &mut msg.regs[3] as *mut u64 as *mut u8;
        for i in 0..actual {
            *dst.add(i) = *data.add(i);
        }
        msg.length = 3 + ((actual as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5;
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label) as i64;
        }
        reply.regs[0] as i64
    }
}

/// Receive data and sender address (UDP recvfrom).
///
/// If `addr` is non-null and points to a `SockAddrIn`, fills in the sender's
/// address. Returns bytes received on success, negative errno on error.
pub unsafe fn posix_recvfrom(
    fd: i32,
    data: *mut u8,
    data_len: usize,
    _flags: i32,
    addr: *mut u8,
    addr_len: *mut u32,
) -> i64 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_RECVMSG;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = data_len as u64;
        // regs[2] = 1 signals "recvfrom" (wants sender address back)
        msg.regs[2] = if !addr.is_null() { 1 } else { 0 };

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5;
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label) as i64;
        }

        let actual_data = reply.regs[0] as usize;
        let src_ip = reply.regs[1] as u32;
        let src_port = reply.regs[2] as u16;

        // Unpack data from regs[3..]
        let src = &reply.regs[3] as *const u64 as *const u8;
        let copy_len = if actual_data < data_len { actual_data } else { data_len };
        for i in 0..copy_len {
            *data.add(i) = *src.add(i);
        }

        // Fill in sender address if requested
        if !addr.is_null() && !addr_len.is_null() && *addr_len >= 8 {
            let sa = &mut *(addr as *mut SockAddrIn);
            sa.family = AF_INET as u16;
            sa.port = src_port;
            sa.addr = src_ip;
            *addr_len = 8;
        }

        actual_data as i64
    }
}
