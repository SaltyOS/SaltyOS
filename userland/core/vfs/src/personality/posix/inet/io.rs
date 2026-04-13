// SPDX-License-Identifier: GPL-2.0-only
//! Data I/O: write/read/sendto/recvfrom.

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
    alloc_pending, ensure_inet_callback_registered, has_pending_capacity,
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
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let conn_id = match state.clients.get(cli_handle) {
            Some(cli) => cli.objects[fd as usize].inet_socket_id().unwrap_or(0),
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

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
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
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
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let (conn_id, nonblocking, badge) = match state.clients.get(cli_handle) {
            Some(cli) => {
                let s = &cli.objects[fd as usize];
                (s.inet_socket_id().unwrap_or(0), s.nonblocking != 0, cli.badge)
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
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
            wait_req.label = NET_RECV_WAIT;
            wait_req.regs[0] = conn_id as u64;
            wait_req.regs[1] = capped as u64;
            wait_req.regs[2] = recv_flags as u64;
            wait_req.length = 3;
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
                if !alloc_pending(conn_id, INET_OP_RECV, client_slot, badge) {
                    let mut client_reply = TronaMsg::zeroed();
                    client_reply.label = TRONA_OUT_OF_MEMORY;
                    ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
                }
                return true;
            }

            ipc::send_ctx(ipc_ctx(), client_slot, &raw const wait_resp);
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
        if !ensure_inet_callback_registered() {
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

        let conn_id = match state.clients.get(cli_handle) {
            Some(cli) => {
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::InetSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                s.inet_socket_id().unwrap_or(0)
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let actual = if data_len > 120 { 120 } else { data_len };
        log_inet_op(b"sendto", fd, conn_id, dst_ip, dst_port, actual);

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
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
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
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let max_len = (*msg).regs[1] as u16;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let (conn_id, nonblocking, badge) = match state.clients.get(cli_handle) {
            Some(cli) => {
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::InetSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (s.inet_socket_id().unwrap_or(0), s.nonblocking != 0, cli.badge)
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let capped = if max_len > 128 { 128 } else { max_len };
        log_inet_op(b"recvfrom", fd, conn_id, 0, 0, capped as usize);

        let mut req = TronaMsg::zeroed();
        req.label = NET_RECVFROM;
        req.regs[0] = conn_id as u64;
        req.regs[1] = capped as u64;
        req.regs[2] = (*msg).regs[2];
        req.length = 3;
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
            wait_req.label = NET_RECVFROM_WAIT;
            wait_req.regs[0] = conn_id as u64;
            wait_req.regs[1] = capped as u64;
            wait_req.regs[2] = (*msg).regs[2];
            wait_req.length = 3;
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
                if !alloc_pending(conn_id, INET_OP_RECVFROM, client_slot, badge) {
                    let mut client_reply = TronaMsg::zeroed();
                    client_reply.label = TRONA_OUT_OF_MEMORY;
                    ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
                }
                return true;
            }

            ipc::send_ctx(ipc_ctx(), client_slot, &raw const wait_resp);
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
                log_inet_recv_result(fd, conn_id, resp.regs[1] as u32, copy_len, unsafe {
                    core::slice::from_raw_parts(src, copy_len)
                });
            }
            (*reply).length = 4 + ((data_len as u64 + 7) / 8);
            false
        }
    }
}
