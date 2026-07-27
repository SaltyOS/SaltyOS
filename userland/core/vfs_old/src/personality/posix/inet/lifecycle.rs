// SPDX-License-Identifier: GPL-2.0-only
//! Socket creation, connect, bind, listen, accept.

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
    alloc_inet_fd, alloc_pending, ensure_inet_callback_registered, has_pending_capacity,
    has_pending_for_conn_op, log_inet_op,
};

/// Helper: extract conn_id from a client's inet socket fd.
unsafe fn inet_conn_id(state: &VfsState, cli_handle: ClientHandle, fd: i32) -> Option<u32> {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return None;
    }
    let obj = state.open_object_at(cli_handle, fd as usize)?;
    if obj.kind() != ObjectKind::InetSocket {
        return None;
    }
    obj.inet_socket_id()
}

pub(crate) unsafe fn handle_inet_socket(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    _msg: *const TronaMsg,
    reply: *mut TronaMsg,
    sock_type: i32,
    protocol: i32,
) -> bool {
    unsafe {
        if !ensure_inet_callback_registered(state) {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let mut req = TronaMsg::zeroed();
        req.label = NET_SOCKET;
        req.regs[0] = sock_type as u64;
        req.regs[1] = protocol as u64;
        req.length = 2;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const req, &raw mut resp);
        if err != 0 || resp.label != TRONA_OK {
            (*reply).label = if err != 0 {
                TRONA_INVALID_OPERATION
            } else {
                resp.label
            };
            return false;
        }
        let conn_id = resp.regs[0] as u32;
        log_inet_op(state, b"socket", -1, conn_id, 0, 0, 0);

        // Allocate fd
        let Some(fd) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
            let mut close_req = TronaMsg::zeroed();
            close_req.label = NET_CLOSE;
            close_req.regs[0] = conn_id as u64;
            close_req.length = 1;
            let mut close_resp = TronaMsg::zeroed();
            let _ = ipc::call_ctx(
                ipc_ctx(),
                netsrv_ep(),
                &raw const close_req,
                &raw mut close_resp,
            );
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        if let Some(obj) = state.open_object_at_mut(cli_handle, fd as usize) {
            obj.set_inet_socket(conn_id);
            obj.offset = 0;
            obj.flags = 0;
            obj.nonblocking = 0;
        } else {
            state.slot_release(cli_handle, fd as usize);
            let mut close_req = TronaMsg::zeroed();
            close_req.label = NET_CLOSE;
            close_req.regs[0] = conn_id as u64;
            close_req.length = 1;
            let mut close_resp = TronaMsg::zeroed();
            let _ = ipc::call_ctx(
                ipc_ctx(),
                netsrv_ep(),
                &raw const close_req,
                &raw mut close_resp,
            );
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
        false
    }
}

pub(crate) unsafe fn handle_inet_connect(
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
        let ip = (*msg).regs[1] as u32;
        let port = (*msg).regs[2] as u16;

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

        log_inet_op(state, b"connect", fd, conn_id, ip, port, 0);

        let mut req = TronaMsg::zeroed();
        req.label = NET_CONNECT;
        req.regs[0] = conn_id as u64;
        req.regs[1] = ip as u64;
        req.regs[2] = port as u64;
        req.length = 3;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const req, &raw mut resp);

        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        if resp.label == TRONA_PENDING {
            if nonblocking {
                (*reply).label = TRONA_IN_PROGRESS;
                return false;
            }

            let op = match state.begin_op_for_client(cli_handle, OpKind::InetConnect) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    return false;
                }
            };

            if alloc_pending(state, conn_id, INET_OP_CONNECT, op, badge).is_none() {
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_OUT_OF_MEMORY;
                state.complete_op(op, OwnerPostOp::None, &raw const client_reply);
            }
            return true;
        }

        (*reply).label = resp.label;
        false
    }
}

pub(crate) unsafe fn handle_inet_bind(
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
        let ip = (*msg).regs[2] as u32;
        let port = (*msg).regs[3] as u16;

        let conn_id = match inet_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let mut req = TronaMsg::zeroed();
        req.label = NET_BIND;
        req.regs[0] = conn_id as u64;
        req.regs[1] = ip as u64;
        req.regs[2] = port as u64;
        req.length = 3;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        };
        false
    }
}

pub(crate) unsafe fn handle_inet_listen(
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
        let backlog = (*msg).regs[1] as u8;

        let conn_id = match inet_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let mut req = TronaMsg::zeroed();
        req.label = NET_LISTEN;
        req.regs[0] = conn_id as u64;
        req.regs[1] = backlog as u64;
        req.length = 2;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        };
        false
    }
}

pub(crate) unsafe fn handle_inet_accept(
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

        let mut req = TronaMsg::zeroed();
        req.label = NET_ACCEPT;
        req.regs[0] = conn_id as u64;
        req.length = 1;
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

            if has_pending_for_conn_op(state, conn_id, INET_OP_ACCEPT) {
                (*reply).label = TRONA_BUSY;
                return false;
            }

            if !has_pending_capacity(state) {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            let op = match state.begin_op_for_client(cli_handle, OpKind::InetAccept) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    return false;
                }
            };

            // Register pending before firing NET_ACCEPT_WAIT. The
            // callback handler (`handle_netsrv_callback`) completes the
            // parked client by allocating a new inet fd when it
            // receives the matching `INET_OP_ACCEPT` completion.
            let Some(handle) = alloc_pending(state, conn_id, INET_OP_ACCEPT, op, badge) else {
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_OUT_OF_MEMORY;
                state.complete_op(op, OwnerPostOp::None, &raw const client_reply);
                return true;
            };

            let mut wait_req = TronaMsg::zeroed();
            wait_req.label = NET_ACCEPT_WAIT;
            wait_req.regs[0] = conn_id as u64;
            wait_req.length = 1;
            let wait_err = ipc::send_ctx(ipc_ctx(), netsrv_ep(), &raw const wait_req);
            if wait_err != 0 {
                let _ = state.pending_ops.release(handle);
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_INVALID_OPERATION;
                state.complete_op(op, OwnerPostOp::None, &raw const client_reply);
                return true;
            }
            true
        } else if resp.label == TRONA_OK {
            let new_conn_id = resp.regs[0] as u32;
            let remote_ip = resp.regs[1] as u32;
            let remote_port = resp.regs[2] as u16;
            match alloc_inet_fd(state, badge, new_conn_id) {
                Some(new_fd) => {
                    (*reply).label = TRONA_OK;
                    (*reply).regs[0] = new_fd as u64;
                    (*reply).regs[1] = remote_ip as u64;
                    (*reply).regs[2] = remote_port as u64;
                    (*reply).length = 3;
                }
                None => {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                }
            }
            false
        } else {
            (*reply).label = resp.label;
            false
        }
    }
}
