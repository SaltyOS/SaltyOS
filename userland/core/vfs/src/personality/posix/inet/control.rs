// SPDX-License-Identifier: GPL-2.0-only
//! Socket control: shutdown, getsockname, getpeername, setsockopt, getsockopt, close.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
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

use super::callback::ensure_inet_callback_registered;

/// Helper: extract conn_id (sock_id) from a client's fd.
unsafe fn inet_fd_conn_id(state: &VfsState, cli_handle: ClientHandle, fd: i32) -> Option<u32> {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return None;
    }
    let cli = state.clients.get(cli_handle)?;
    let s = &cli.objects[fd as usize];
    if !s.is_live() || s.kind() != ObjectKind::InetSocket {
        return None;
    }
    s.inet_socket_id()
}

pub(crate) unsafe fn handle_inet_shutdown(
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
        let how = (*msg).regs[1] as i32;
        let conn_id = match inet_fd_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let mut req = TronaMsg::zeroed();
        req.label = NET_SHUTDOWN;
        req.regs[0] = conn_id as u64;
        req.regs[1] = how as u64;
        req.length = 2;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 { TRONA_INVALID_OPERATION } else { resp.label };
        false
    }
}

pub(crate) unsafe fn handle_inet_getsockname(
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
        let conn_id = match inet_fd_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_GETSOCKNAME;
        req.length = 1;
        req.regs[0] = conn_id as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        (*reply).label = resp.label;
        (*reply).regs[0] = resp.regs[0];
        (*reply).regs[1] = resp.regs[1];
        (*reply).length = 2;
        false
    }
}

pub(crate) unsafe fn handle_inet_getpeername(
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
        let conn_id = match inet_fd_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_GETPEERNAME;
        req.length = 1;
        req.regs[0] = conn_id as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        (*reply).label = resp.label;
        (*reply).regs[0] = resp.regs[0];
        (*reply).regs[1] = resp.regs[1];
        (*reply).length = if resp.label == TRONA_OK { 2 } else { 0 };
        false
    }
}

pub(crate) unsafe fn handle_inet_setsockopt(
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
        let level = (*msg).regs[1] as i32;
        let optname = (*msg).regs[2] as i32;
        let optval = (*msg).regs[3];
        let optlen = (*msg).regs[4] as u32;

        let conn_id = match inet_fd_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_SETSOCKOPT;
        req.length = 5;
        req.regs[0] = conn_id as u64;
        req.regs[1] = level as u64;
        req.regs[2] = optname as u64;
        req.regs[3] = optval;
        req.regs[4] = optlen as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 { TRONA_INVALID_OPERATION } else { resp.label };
        false
    }
}

pub(crate) unsafe fn handle_inet_getsockopt(
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
        let level = (*msg).regs[1] as i32;
        let optname = (*msg).regs[2] as i32;

        let conn_id = match inet_fd_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_GETSOCKOPT;
        req.length = 3;
        req.regs[0] = conn_id as u64;
        req.regs[1] = level as u64;
        req.regs[2] = optname as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        (*reply).label = resp.label;
        (*reply).regs[0] = resp.regs[0];
        (*reply).regs[1] = resp.regs[1];
        (*reply).length = if resp.label == TRONA_OK { 2 } else { 0 };
        false
    }
}

/// Close an inet socket fd.
pub(crate) unsafe fn close_inet_socket(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) {
    unsafe {
        let conn_id = match inet_fd_conn_id(state, cli_handle, fd) {
            Some(id) => id,
            None => return,
        };
        let mut req = TronaMsg::zeroed();
        req.label = NET_CLOSE;
        req.regs[0] = conn_id as u64;
        req.length = 1;
        let mut resp = TronaMsg::zeroed();
        let _ = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
    }
}
