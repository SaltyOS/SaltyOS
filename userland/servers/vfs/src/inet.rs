// SPDX-License-Identifier: GPL-2.0-only
//! AF_INET socket forwarding to netsrv.
//!
//! VFS acts as a proxy between userland POSIX socket calls and netsrv's
//! TCP/UDP stack. Non-blocking operations (socket, bind, listen, send,
//! getsockname, close) are forwarded synchronously. Blocking operations
//! (connect, recv, accept) save the client's reply cap and return
//! asynchronously via netsrv's badged callback EP.

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::types::*;

use crate::client::get_client;
use crate::consts::*;
use crate::ipc_ctx;
use crate::socket::alloc_reply_slot;
use crate::types::*;

// ======================================================================
// Pending operations table
// ======================================================================

const MAX_PENDING_INET: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingInetOp {
    active: u8,
    client_reply_slot: u64,
    client_badge: u64,
    conn_id: u32,
    op_type: u8,
}

impl PendingInetOp {
    const fn zeroed() -> Self {
        PendingInetOp {
            active: 0,
            client_reply_slot: 0,
            client_badge: 0,
            conn_id: 0,
            op_type: 0,
        }
    }
}

static mut PENDING_INET: [PendingInetOp; MAX_PENDING_INET] =
    [PendingInetOp::zeroed(); MAX_PENDING_INET];

unsafe fn alloc_pending(
    conn_id: u32,
    op_type: u8,
    client_reply_slot: u64,
    client_badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS server; only this module accesses PENDING_INET.
    unsafe {
        let table = &mut *(&raw mut PENDING_INET);
        for entry in table.iter_mut() {
            if entry.active == 0 {
                entry.active = 1;
                entry.conn_id = conn_id;
                entry.op_type = op_type;
                entry.client_reply_slot = client_reply_slot;
                entry.client_badge = client_badge;
                return true;
            }
        }
        false
    }
}

unsafe fn find_pending(conn_id: u32, op_type: u8) -> Option<(u64, u64)> {
    // SAFETY: Single-threaded VFS server.
    unsafe {
        let table = &mut *(&raw mut PENDING_INET);
        for entry in table.iter_mut() {
            if entry.active != 0 && entry.conn_id == conn_id && entry.op_type == op_type {
                let slot = entry.client_reply_slot;
                let badge = entry.client_badge;
                entry.active = 0;
                return Some((slot, badge));
            }
        }
        None
    }
}

// ======================================================================
// Initialization
// ======================================================================

/// Create badged EP and register with netsrv.
///
/// Called from VFS _start() before the event loop.
pub(crate) unsafe fn inet_init() {
    // SAFETY: Minting a badged copy of our server EP for netsrv callbacks.
    unsafe {
        let err = invoke::cnode_mint(
            CAP_SELF_CSPACE,
            CAP_SERVER_EP,
            CAP_SELF_CSPACE,
            VFS_CAP_NETSRV_CALLBACK_EP,
            NETSRV_CALLBACK_BADGE,
        );
        if err != 0 {
            crate::puts(b"[VFS] inet: failed to mint callback EP\n");
            return;
        }

        // Call netsrv with NET_REGISTER_VFS, transferring the badged EP
        ipc::set_send_cap_ctx(ipc_ctx(), 0, VFS_CAP_NETSRV_CALLBACK_EP);

        let mut msg = SaltyMsg::zeroed();
        msg.label = NET_REGISTER_VFS;
        msg.length = 0;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const msg, &raw mut resp);
        if err != 0 || resp.label != SALTY_OK {
            crate::puts(b"[VFS] inet: failed to register with netsrv\n");
        } else {
            crate::puts(b"[VFS] inet: registered callback EP with netsrv\n");
        }
    }
}

// ======================================================================
// Non-blocking forwarding: socket
// ======================================================================

/// Forward NET_SOCKET to netsrv, create FD_TYPE_INET_SOCKET fd.
pub(crate) unsafe fn handle_inet_socket(
    _msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
    badge: u64,
    sock_type: i32,
) -> bool {
    // SAFETY: IPC context is valid; making synchronous RPC to netsrv.
    unsafe {
        let mut req = SaltyMsg::zeroed();
        req.label = NET_SOCKET;
        req.regs[0] = sock_type as u64;
        req.length = 1;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        if err != 0 || resp.label != SALTY_OK {
            (*reply).label = if err != 0 {
                SALTY_INVALID_OPERATION
            } else {
                resp.label
            };
            return false;
        }
        let conn_id = resp.regs[0] as u32;

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_INET_SOCKET;
                (*(*cli).fds.add(fd)).sock_id = conn_id;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).flags = 0;
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return false;
            }
        }

        // No free fd — close the netsrv conn
        let mut close_req = SaltyMsg::zeroed();
        close_req.label = NET_CLOSE;
        close_req.regs[0] = conn_id as u64;
        close_req.length = 1;
        let mut close_resp = SaltyMsg::zeroed();
        let _ = ipc::call_ctx(
            ipc_ctx(),
            VFS_CAP_NETSRV_EP,
            &raw const close_req,
            &raw mut close_resp,
        );
        (*reply).label = SALTY_OUT_OF_MEMORY;
        false
    }
}

// ======================================================================
// Blocking forwarding: connect (async — TCP handshake)
// ======================================================================

pub(crate) unsafe fn handle_inet_connect(
    msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let ip = (*msg).regs[1] as u32;
        let port = (*msg).regs[2] as u16;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

        // Save client's reply cap BEFORE calling netsrv
        let client_slot = alloc_reply_slot();
        let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, client_slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Call netsrv synchronously
        let mut req = SaltyMsg::zeroed();
        req.label = NET_CONNECT;
        req.regs[0] = conn_id as u64;
        req.regs[1] = ip as u64;
        req.regs[2] = port as u64;
        req.length = 3;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);

        if err != 0 {
            let mut client_reply = SaltyMsg::zeroed();
            client_reply.label = SALTY_INVALID_OPERATION;
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            return true;
        }

        if resp.label == SALTY_PENDING {
            // TCP SYN sent, handshake pending — record and wait for callback
            if !alloc_pending(conn_id, INET_OP_CONNECT, client_slot, badge) {
                let mut client_reply = SaltyMsg::zeroed();
                client_reply.label = SALTY_OUT_OF_MEMORY;
                ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            }
            true // skip_reply
        } else {
            // Immediate result (UDP connect or error)
            let mut client_reply = SaltyMsg::zeroed();
            client_reply.label = resp.label;
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            true // skip_reply (already replied)
        }
    }
}

// ======================================================================
// Non-blocking forwarding: bind
// ======================================================================

pub(crate) unsafe fn handle_inet_bind(
    msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let ip = (*msg).regs[2] as u32;
        let port = (*msg).regs[3] as u16;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

        let mut req = SaltyMsg::zeroed();
        req.label = NET_BIND;
        req.regs[0] = conn_id as u64;
        req.regs[1] = ip as u64;
        req.regs[2] = port as u64;
        req.length = 3;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            SALTY_INVALID_OPERATION
        } else {
            resp.label
        };
        false
    }
}

// ======================================================================
// Non-blocking forwarding: listen
// ======================================================================

pub(crate) unsafe fn handle_inet_listen(
    msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let backlog = (*msg).regs[1] as u8;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

        let mut req = SaltyMsg::zeroed();
        req.label = NET_LISTEN;
        req.regs[0] = conn_id as u64;
        req.regs[1] = backlog as u64;
        req.length = 2;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            SALTY_INVALID_OPERATION
        } else {
            resp.label
        };
        false
    }
}

// ======================================================================
// Blocking forwarding: accept (async — waits for connection)
// ======================================================================

pub(crate) unsafe fn handle_inet_accept(
    msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

        let client_slot = alloc_reply_slot();
        let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, client_slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let mut req = SaltyMsg::zeroed();
        req.label = NET_ACCEPT;
        req.regs[0] = conn_id as u64;
        req.length = 1;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);

        if err != 0 {
            let mut client_reply = SaltyMsg::zeroed();
            client_reply.label = SALTY_INVALID_OPERATION;
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            return true;
        }

        if resp.label == SALTY_PENDING {
            // No pending connections — wait for callback
            if !alloc_pending(conn_id, INET_OP_ACCEPT, client_slot, badge) {
                let mut client_reply = SaltyMsg::zeroed();
                client_reply.label = SALTY_OUT_OF_MEMORY;
                ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            }
            true
        } else if resp.label == SALTY_OK {
            // Connection already queued — allocate new fd
            let new_conn_id = resp.regs[0] as u32;
            let remote_ip = resp.regs[1] as u32;
            let remote_port = resp.regs[2] as u16;

            let mut client_reply = SaltyMsg::zeroed();
            match alloc_inet_fd(badge, new_conn_id) {
                Some(new_fd) => {
                    client_reply.label = SALTY_OK;
                    client_reply.regs[0] = new_fd as u64;
                    client_reply.regs[1] = remote_ip as u64;
                    client_reply.regs[2] = remote_port as u64;
                    client_reply.length = 3;
                }
                None => {
                    client_reply.label = SALTY_OUT_OF_MEMORY;
                }
            }
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            true
        } else {
            let mut client_reply = SaltyMsg::zeroed();
            client_reply.label = resp.label;
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            true
        }
    }
}

// ======================================================================
// Non-blocking forwarding: write (send)
// ======================================================================

pub(crate) unsafe fn handle_inet_write(
    msg: *const SaltyMsg,
    fde: *mut FdEntry,
    reply: *mut SaltyMsg,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let conn_id = (*fde).sock_id;
        let count = (*msg).regs[1] as usize;
        let actual = if count > 144 { 144 } else { count };

        let mut req = SaltyMsg::zeroed();
        req.label = NET_SEND;
        req.regs[0] = conn_id as u64;
        req.regs[1] = actual as u64;
        let src = &(*msg).regs[2] as *const u64 as *const u8;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..actual {
            *dst.add(i) = *src.add(i);
        }
        req.length = 2 + ((actual as u64 + 7) / 8);

        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
        } else {
            (*reply).label = resp.label;
            (*reply).regs[0] = resp.regs[0];
            (*reply).length = 1;
        }
        false
    }
}

// ======================================================================
// Blocking forwarding: read (recv)
// ======================================================================

pub(crate) unsafe fn handle_inet_read(
    msg: *const SaltyMsg,
    fde: *mut FdEntry,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let conn_id = (*fde).sock_id;
        let max_len = (*msg).regs[1] as u16;
        let capped = if max_len > 152 { 152 } else { max_len };

        // Save client reply cap first
        let client_slot = alloc_reply_slot();
        let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, client_slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let mut req = SaltyMsg::zeroed();
        req.label = NET_RECV;
        req.regs[0] = conn_id as u64;
        req.regs[1] = capped as u64;
        req.length = 2;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);

        if err != 0 {
            let mut client_reply = SaltyMsg::zeroed();
            client_reply.label = SALTY_INVALID_OPERATION;
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            return true;
        }

        if resp.label == SALTY_PENDING {
            // No data yet — record pending
            if !alloc_pending(conn_id, INET_OP_RECV, client_slot, badge) {
                let mut client_reply = SaltyMsg::zeroed();
                client_reply.label = SALTY_OUT_OF_MEMORY;
                ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            }
            true
        } else {
            // Data available immediately
            let mut client_reply = SaltyMsg::zeroed();
            client_reply.label = resp.label;
            client_reply.regs[0] = resp.regs[0]; // byte count
            let data_len = resp.regs[0] as usize;
            if data_len > 0 {
                let src = &resp.regs[1] as *const u64 as *const u8;
                let dst = &raw mut client_reply.regs[1] as *mut u8;
                let copy_len = if data_len > 152 { 152 } else { data_len };
                for i in 0..copy_len {
                    *dst.add(i) = *src.add(i);
                }
            }
            client_reply.length = 1 + ((data_len as u64 + 7) / 8);
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            true
        }
    }
}

// ======================================================================
// Non-blocking forwarding: sendto (UDP)
// ======================================================================

pub(crate) unsafe fn handle_inet_sendto(
    msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_len = (*msg).regs[1] as usize;
        let dst_ip = (*msg).regs[3] as u32;
        let dst_port = (*msg).regs[4] as u16;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
        let actual = if data_len > 120 { 120 } else { data_len };

        let mut req = SaltyMsg::zeroed();
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

        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
        } else {
            (*reply).label = resp.label;
            (*reply).regs[0] = resp.regs[0]; // bytes sent
            (*reply).length = 1;
        }
        false
    }
}

// ======================================================================
// Blocking forwarding: recvfrom (UDP — may defer)
// ======================================================================

pub(crate) unsafe fn handle_inet_recvfrom(
    msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let max_len = (*msg).regs[1] as u16;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
        let capped = if max_len > 128 { 128 } else { max_len };

        let client_slot = alloc_reply_slot();
        let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, client_slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let mut req = SaltyMsg::zeroed();
        req.label = NET_RECVFROM;
        req.regs[0] = conn_id as u64;
        req.regs[1] = capped as u64;
        req.length = 2;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);

        if err != 0 {
            let mut client_reply = SaltyMsg::zeroed();
            client_reply.label = SALTY_INVALID_OPERATION;
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            return true;
        }

        if resp.label == SALTY_PENDING {
            if !alloc_pending(conn_id, INET_OP_RECVFROM, client_slot, badge) {
                let mut client_reply = SaltyMsg::zeroed();
                client_reply.label = SALTY_OUT_OF_MEMORY;
                ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            }
            true
        } else {
            // Data available
            let mut client_reply = SaltyMsg::zeroed();
            client_reply.label = resp.label;
            client_reply.regs[0] = resp.regs[0]; // data_len
            client_reply.regs[1] = resp.regs[1]; // src_ip
            client_reply.regs[2] = resp.regs[2]; // src_port
            let data_len = resp.regs[0] as usize;
            if data_len > 0 {
                let src = &resp.regs[3] as *const u64 as *const u8;
                let dst = &raw mut client_reply.regs[3] as *mut u8;
                let copy_len = if data_len > 128 { 128 } else { data_len };
                for i in 0..copy_len {
                    *dst.add(i) = *src.add(i);
                }
            }
            client_reply.length = 3 + ((data_len as u64 + 7) / 8);
            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            true
        }
    }
}

// ======================================================================
// Non-blocking forwarding: shutdown
// ======================================================================

pub(crate) unsafe fn handle_inet_shutdown(
    msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let how = (*msg).regs[1] as i32;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

        let mut req = SaltyMsg::zeroed();
        req.label = NET_SHUTDOWN;
        req.regs[0] = conn_id as u64;
        req.regs[1] = how as u64;
        req.length = 2;
        let mut resp = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            SALTY_INVALID_OPERATION
        } else {
            resp.label
        };
        false
    }
}

// ======================================================================
// Non-blocking forwarding: close
// ======================================================================

pub(crate) unsafe fn close_inet_socket(fde: *mut FdEntry) {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let conn_id = (*fde).sock_id;
        let mut req = SaltyMsg::zeroed();
        req.label = NET_CLOSE;
        req.regs[0] = conn_id as u64;
        req.length = 1;
        let mut resp = SaltyMsg::zeroed();
        let _ = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
    }
}

// ======================================================================
// Helper: allocate a new fd for an inet socket
// ======================================================================

unsafe fn alloc_inet_fd(badge: u64, conn_id: u32) -> Option<i32> {
    // SAFETY: Single-threaded VFS.
    unsafe {
        let cli = get_client(badge);
        if cli.is_null() {
            return None;
        }
        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_INET_SOCKET;
                (*(*cli).fds.add(fd)).sock_id = conn_id;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).flags = 0;
                return Some(fd as i32);
            }
        }
        None
    }
}

// ======================================================================
// Callback handler: NET_COMPLETE from netsrv
// ======================================================================

/// Handle async completion callback from netsrv.
///
/// Called when VFS receives IPC with badge == NETSRV_CALLBACK_BADGE.
pub(crate) unsafe fn handle_netsrv_callback(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let conn_id = (*msg).regs[0] as u32;
        let result = (*msg).regs[1];
        let op_type = (*msg).regs[2] as u8;

        if let Some((client_slot, client_badge)) = find_pending(conn_id, op_type) {
            let mut client_reply = SaltyMsg::zeroed();

            match op_type {
                INET_OP_CONNECT => {
                    client_reply.label = result;
                }
                INET_OP_RECV => {
                    client_reply.label = result;
                    if result == SALTY_OK {
                        let data_len = (*msg).regs[3] as usize;
                        // Cap to max bytes that fit in regs[4..20] (16 regs * 8 = 128)
                        let actual_len = if data_len > 128 { 128 } else { data_len };
                        client_reply.regs[0] = actual_len as u64;
                        if actual_len > 0 {
                            let src = &(*msg).regs[4] as *const u64 as *const u8;
                            let dst = &raw mut client_reply.regs[1] as *mut u8;
                            for i in 0..actual_len {
                                *dst.add(i) = *src.add(i);
                            }
                        }
                        client_reply.length = 1 + ((actual_len as u64 + 7) / 8);
                    } else {
                        client_reply.regs[0] = 0;
                        client_reply.length = 1;
                    }
                }
                INET_OP_RECVFROM => {
                    client_reply.label = result;
                    if result == SALTY_OK {
                        let data_len = (*msg).regs[3] as usize;
                        // Cap to max bytes that fit in regs[6..20] (14 regs * 8 = 112)
                        let actual_len = if data_len > 112 { 112 } else { data_len };
                        let src_ip = (*msg).regs[4] as u32;
                        let src_port = (*msg).regs[5] as u16;
                        client_reply.regs[0] = actual_len as u64;
                        client_reply.regs[1] = src_ip as u64;
                        client_reply.regs[2] = src_port as u64;
                        if actual_len > 0 {
                            let src = &(*msg).regs[6] as *const u64 as *const u8;
                            let dst = &raw mut client_reply.regs[3] as *mut u8;
                            for i in 0..actual_len {
                                *dst.add(i) = *src.add(i);
                            }
                        }
                        client_reply.length = 3 + ((actual_len as u64 + 7) / 8);
                    } else {
                        client_reply.regs[0] = 0;
                        client_reply.length = 1;
                    }
                }
                INET_OP_ACCEPT => {
                    client_reply.label = result;
                    if result == SALTY_OK {
                        let new_conn_id = (*msg).regs[3] as u32;
                        let remote_ip = (*msg).regs[4] as u32;
                        let remote_port = (*msg).regs[5] as u16;

                        match alloc_inet_fd(client_badge, new_conn_id) {
                            Some(new_fd) => {
                                client_reply.regs[0] = new_fd as u64;
                                client_reply.regs[1] = remote_ip as u64;
                                client_reply.regs[2] = remote_port as u64;
                                client_reply.length = 3;
                            }
                            None => {
                                client_reply.label = SALTY_OUT_OF_MEMORY;
                            }
                        }
                    }
                }
                _ => {
                    client_reply.label = SALTY_INVALID_OPERATION;
                }
            }

            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
        }

        // Reply OK to netsrv (completing the callback IPC)
        (*reply).label = SALTY_OK;
    }
}
