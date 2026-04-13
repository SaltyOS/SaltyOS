// SPDX-License-Identifier: GPL-2.0-only
//! Socket creation, connect, bind, listen, accept.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::posix::*;
use trona::protocol::server::*;
use trona::protocol::vfs::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::ipc_ctx;

use super::callback::{
    alloc_inet_fd, alloc_pending, ensure_inet_callback_registered, has_pending_capacity,
    log_inet_op,
};

/// Helper: extract conn_id from a client's inet socket fd.
unsafe fn inet_conn_id(state: &VfsState, cli_handle: ClientHandle, fd: i32) -> Option<u32> {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS { return None; }
    let cli = state.clients.get(cli_handle)?;
    let s = &cli.objects[fd as usize];
    if !s.is_live() || s.kind() != ObjectKind::InetSocket { return None; }
    s.inet_socket_id()
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
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let mut req = TronaMsg::zeroed();
        req.label = NET_SOCKET;
        req.regs[0] = sock_type as u64;
        req.regs[1] = protocol as u64;
        req.length = 2;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        if err != 0 || resp.label != TRONA_OK {
            (*reply).label = if err != 0 { TRONA_INVALID_OPERATION } else { resp.label };
            return false;
        }
        let conn_id = resp.regs[0] as u32;
        log_inet_op(b"socket", -1, conn_id, 0, 0, 0);

        // Allocate fd
        let Some(fd) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
            let mut close_req = TronaMsg::zeroed();
            close_req.label = NET_CLOSE;
            close_req.regs[0] = conn_id as u64;
            close_req.length = 1;
            let mut close_resp = TronaMsg::zeroed();
            let _ = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const close_req, &raw mut close_resp);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => {
                if let Some(c2) = state.clients.get_mut(cli_handle) {
                    c2.objects[fd as usize].clear();
                    c2.obj_count = c2.obj_count.saturating_sub(1);
                }
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        };
        let slot = &mut cli.objects[fd as usize];
        slot.set_inet_socket(conn_id);
        slot.offset = 0;
        slot.flags = 0;
        slot.nonblocking = 0;

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
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let ip = (*msg).regs[1] as u32;
        let port = (*msg).regs[2] as u16;

        let (conn_id, nonblocking, badge) = match state.clients.get(cli_handle) {
            Some(cli) => {
                if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::InetSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (s.inet_socket_id().unwrap_or(0), s.nonblocking != 0, cli.badge)
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        log_inet_op(b"connect", fd, conn_id, ip, port, 0);

        let mut req = TronaMsg::zeroed();
        req.label = NET_CONNECT;
        req.regs[0] = conn_id as u64;
        req.regs[1] = ip as u64;
        req.regs[2] = port as u64;
        req.length = 3;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);

        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        if resp.label == TRONA_PENDING {
            if nonblocking {
                (*reply).label = TRONA_IN_PROGRESS;
                return false;
            }

            let client_slot = state.alloc_reply_slot();
            let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, client_slot);
            if err != 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            if !alloc_pending(conn_id, INET_OP_CONNECT, client_slot, badge) {
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_OUT_OF_MEMORY;
                ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
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
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let ip = (*msg).regs[2] as u32;
        let port = (*msg).regs[3] as u16;

        let conn_id = match inet_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let mut req = TronaMsg::zeroed();
        req.label = NET_BIND;
        req.regs[0] = conn_id as u64;
        req.regs[1] = ip as u64;
        req.regs[2] = port as u64;
        req.length = 3;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 { TRONA_INVALID_OPERATION } else { resp.label };
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
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let backlog = (*msg).regs[1] as u8;

        let conn_id = match inet_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let mut req = TronaMsg::zeroed();
        req.label = NET_LISTEN;
        req.regs[0] = conn_id as u64;
        req.regs[1] = backlog as u64;
        req.length = 2;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 { TRONA_INVALID_OPERATION } else { resp.label };
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
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let (conn_id, nonblocking, badge) = match state.clients.get(cli_handle) {
            Some(cli) => {
                if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::InetSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (s.inet_socket_id().unwrap_or(0), s.nonblocking != 0, cli.badge)
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let mut req = TronaMsg::zeroed();
        req.label = NET_ACCEPT;
        req.regs[0] = conn_id as u64;
        req.length = 1;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);

        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        if resp.label == TRONA_PENDING {
            if nonblocking {
                (*reply).label = TRONA_WOULD_BLOCK;
                return false;
            }

            if !has_pending_capacity() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            let client_slot = state.alloc_reply_slot();
            let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, client_slot);
            if err != 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            let mut wait_req = TronaMsg::zeroed();
            wait_req.label = NET_ACCEPT_WAIT;
            wait_req.regs[0] = conn_id as u64;
            wait_req.length = 1;
            let mut wait_resp = TronaMsg::zeroed();
            let wait_err = ipc::call_ctx(
                ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const wait_req, &raw mut wait_resp,
            );

            if wait_err != 0 {
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_INVALID_OPERATION;
                ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
                return true;
            }

            if wait_resp.label == TRONA_PENDING {
                if !alloc_pending(conn_id, INET_OP_ACCEPT, client_slot, badge) {
                    let mut client_reply = TronaMsg::zeroed();
                    client_reply.label = TRONA_OUT_OF_MEMORY;
                    ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
                }
                return true;
            }

            let mut client_reply = TronaMsg::zeroed();
            if wait_resp.label == TRONA_OK {
                let new_conn_id = wait_resp.regs[0] as u32;
                let remote_ip = wait_resp.regs[1] as u32;
                let remote_port = wait_resp.regs[2] as u16;
                match alloc_inet_fd(badge, new_conn_id) {
                    Some(new_fd) => {
                        client_reply.label = TRONA_OK;
                        client_reply.regs[0] = new_fd as u64;
                        client_reply.regs[1] = remote_ip as u64;
                        client_reply.regs[2] = remote_port as u64;
                        client_reply.length = 3;
                    }
                    None => {
                        client_reply.label = TRONA_OUT_OF_MEMORY;
                    }
                }
            } else {
                client_reply.label = wait_resp.label;
            }
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            true
        } else if resp.label == TRONA_OK {
            let new_conn_id = resp.regs[0] as u32;
            let remote_ip = resp.regs[1] as u32;
            let remote_port = resp.regs[2] as u16;
            match alloc_inet_fd(badge, new_conn_id) {
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
