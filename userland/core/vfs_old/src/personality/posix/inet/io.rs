// SPDX-License-Identifier: GPL-2.0-only
//! Data I/O: write/read/sendto/recvfrom.

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_posix::types::*;
use trona_protocol::posix::posix::*;
use trona_protocol::posix::server::*;
use trona_protocol::posix::vfs::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::owner::op::{OpKind, OwnerPostOp};
use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::server::types::*;

use super::callback::{
    alloc_pending, ensure_inet_callback_registered, has_pending_capacity, has_pending_for_conn_op,
    log_inet_op, log_inet_recv_result,
};

pub(crate) unsafe fn handle_inet_write(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if !ensure_inet_callback_registered(state) {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let conn_id = state
            .open_object_at(cli_handle, fd as usize)
            .and_then(|obj| obj.inet_socket_id())
            .unwrap_or(0);

        let count = (*msg).regs[1] as usize;
        let actual = if count > 144 { 144 } else { count };

        let mut req = TronaMsg::zeroed();
        req.label = NET_SEND;
        req.regs[0] = conn_id as u64;
        req.regs[1] = actual as u64;
        let src = &(*msg).regs[2] as *const u64 as *const u8;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..actual {
            *dst.add(i) = *src.add(i);
        }
        req.length = 2 + ((actual as u64 + 7) / 8);

        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
        } else {
            (*reply).label = resp.label;
            (*reply).regs[0] = resp.regs[0];
            (*reply).length = 1;
        }
        false
    }
}

pub(crate) unsafe fn handle_inet_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if !ensure_inet_callback_registered(state) {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let badge = match state.clients.get(cli_handle) {
            Some(c) => c.badge,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let (conn_id, nonblocking) = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) => (obj.inet_socket_id().unwrap_or(0), obj.nonblocking != 0),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let max_len = (*msg).regs[1] as u16;
        let recv_flags = (*msg).regs[2] as u32;
        let capped = if max_len > 152 { 152 } else { max_len };

        let mut req = TronaMsg::zeroed();
        req.label = NET_RECV;
        req.regs[0] = conn_id as u64;
        req.regs[1] = capped as u64;
        req.regs[2] = recv_flags as u64;
        req.length = 3;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const req, &raw mut resp);

        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        if resp.label == TRONA_PENDING {
            if nonblocking {
                (*reply).label = TRONA_WOULD_BLOCK;
                return false;
            }

            if has_pending_for_conn_op(state, conn_id, INET_OP_RECV) {
                (*reply).label = TRONA_BUSY;
                return false;
            }

            if !has_pending_capacity(state) {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            let op = match state.begin_op_for_client(cli_handle, OpKind::InetRecv) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    return false;
                }
            };

            // Register pending BEFORE firing NET_RECV_WAIT. netsrv may
            // push a completion the moment it processes the request
            // (buffered data path); without prior registration, the
            // `find_pending(conn_id, op)` lookup on the callback side
            // would miss and the reply would be dropped.
            let Some(handle) = alloc_pending(state, conn_id, INET_OP_RECV, op, badge) else {
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_OUT_OF_MEMORY;
                state.complete_op(op, OwnerPostOp::None, &raw const client_reply);
                return true;
            };

            let mut wait_req = TronaMsg::zeroed();
            wait_req.label = NET_RECV_WAIT;
            wait_req.regs[0] = conn_id as u64;
            wait_req.regs[1] = capped as u64;
            wait_req.regs[2] = recv_flags as u64;
            wait_req.length = 3;
            let wait_err = ipc::send_ctx(ipc_ctx(), netsrv_ep(), &raw const wait_req);
            if wait_err != 0 {
                let _ = state.pending_ops.release(handle);
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_INVALID_OPERATION;
                state.complete_op(op, OwnerPostOp::None, &raw const client_reply);
                return true;
            }
            true
        } else {
            (*reply).label = resp.label;
            (*reply).regs[0] = resp.regs[0];
            let data_len = resp.regs[0] as usize;
            if data_len > 0 {
                let src = &resp.regs[1] as *const u64 as *const u8;
                let dst = &raw mut (*reply).regs[1] as *mut u8;
                let copy_len = if data_len > 152 { 152 } else { data_len };
                for i in 0..copy_len {
                    *dst.add(i) = *src.add(i);
                }
            }
            (*reply).length = 1 + ((data_len as u64 + 7) / 8);
            false
        }
    }
}

pub(crate) unsafe fn handle_inet_sendto(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if !ensure_inet_callback_registered(state) {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let data_len = (*msg).regs[1] as usize;
        let dst_ip = (*msg).regs[3] as u32;
        let dst_port = (*msg).regs[4] as u16;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.kind() == ObjectKind::InetSocket => obj.inet_socket_id().unwrap_or(0),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let actual = if data_len > 120 { 120 } else { data_len };
        log_inet_op(state, b"sendto", fd, conn_id, dst_ip, dst_port, actual);

        let mut req = TronaMsg::zeroed();
        req.label = NET_SENDTO;
        req.regs[0] = conn_id as u64;
        req.regs[1] = dst_ip as u64;
        req.regs[2] = dst_port as u64;
        req.regs[3] = actual as u64;
        let src = &(*msg).regs[5] as *const u64 as *const u8;
        let dst = &raw mut req.regs[4] as *mut u8;
        for i in 0..actual {
            *dst.add(i) = *src.add(i);
        }
        req.length = 4 + ((actual as u64 + 7) / 8);

        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
        } else {
            (*reply).label = resp.label;
            (*reply).regs[0] = resp.regs[0];
            (*reply).length = 1;
        }
        false
    }
}

pub(crate) unsafe fn handle_inet_recvfrom(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if !ensure_inet_callback_registered(state) {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let max_len = (*msg).regs[1] as u16;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let badge = match state.clients.get(cli_handle) {
            Some(c) => c.badge,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let (conn_id, nonblocking) = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.kind() == ObjectKind::InetSocket => {
                (obj.inet_socket_id().unwrap_or(0), obj.nonblocking != 0)
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let capped = if max_len > 128 { 128 } else { max_len };
        log_inet_op(state, b"recvfrom", fd, conn_id, 0, 0, capped as usize);

        let mut req = TronaMsg::zeroed();
        req.label = NET_RECVFROM;
        req.regs[0] = conn_id as u64;
        req.regs[1] = capped as u64;
        req.regs[2] = (*msg).regs[2];
        req.length = 3;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const req, &raw mut resp);

        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        if resp.label == TRONA_PENDING {
            if nonblocking {
                (*reply).label = TRONA_WOULD_BLOCK;
                return false;
            }

            if has_pending_for_conn_op(state, conn_id, INET_OP_RECVFROM) {
                (*reply).label = TRONA_BUSY;
                return false;
            }

            if !has_pending_capacity(state) {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            let op = match state.begin_op_for_client(cli_handle, OpKind::InetRecvFrom) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    return false;
                }
            };

            // Register pending before firing NET_RECVFROM_WAIT so an
            // immediate completion from netsrv lands in the callback
            // path with a matching entry.
            let Some(handle) = alloc_pending(state, conn_id, INET_OP_RECVFROM, op, badge) else {
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_OUT_OF_MEMORY;
                state.complete_op(op, OwnerPostOp::None, &raw const client_reply);
                return true;
            };

            let mut wait_req = TronaMsg::zeroed();
            wait_req.label = NET_RECVFROM_WAIT;
            wait_req.regs[0] = conn_id as u64;
            wait_req.regs[1] = capped as u64;
            wait_req.regs[2] = (*msg).regs[2];
            wait_req.length = 3;
            let wait_err = ipc::send_ctx(ipc_ctx(), netsrv_ep(), &raw const wait_req);
            if wait_err != 0 {
                let _ = state.pending_ops.release(handle);
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_INVALID_OPERATION;
                state.complete_op(op, OwnerPostOp::None, &raw const client_reply);
                return true;
            }
            true
        } else {
            (*reply).label = resp.label;
            (*reply).regs[0] = resp.regs[0];
            (*reply).regs[1] = resp.regs[1];
            (*reply).regs[2] = resp.regs[2];
            (*reply).regs[3] = resp.regs[3];
            let data_len = resp.regs[0] as usize;
            if data_len > 0 {
                let src = &resp.regs[4] as *const u64 as *const u8;
                let dst = &raw mut (*reply).regs[4] as *mut u8;
                let copy_len = if data_len > 128 { 128 } else { data_len };
                for i in 0..copy_len {
                    *dst.add(i) = *src.add(i);
                }
                log_inet_recv_result(state, fd, conn_id, resp.regs[1] as u32, copy_len, unsafe {
                    core::slice::from_raw_parts(src, copy_len)
                });
            }
            (*reply).length = 4 + ((data_len as u64 + 7) / 8);
            false
        }
    }
}
