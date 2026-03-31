// SPDX-License-Identifier: GPL-2.0-only
//! AF_INET socket forwarding to netsrv.
//!
//! VFS acts as a proxy between userland POSIX socket calls and netsrv's
//! TCP/UDP stack. Non-blocking operations (socket, bind, listen, send,
//! getsockname, close) are forwarded synchronously. Blocking operations
//! (connect, recv, accept) save the client's reply cap and return
//! asynchronously via netsrv's badged callback EP.

use trona::consts::*;
use trona::invoke;
use trona::ipc;
use trona::types::*;

use crate::client::get_client;
use crate::consts::*;
use crate::ipc_ctx;
use crate::poll::wake_poll_waiters;
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
static mut INET_CALLBACK_EP_PREPARED: bool = false;
static mut INET_CALLBACK_EP_REGISTERED: bool = false;
static mut LOGGED_INET_OPS: u8 = 0;
static mut LOGGED_INET_CALLBACKS: u8 = 0;
static mut LOGGED_INET_RECV_RESULTS: u8 = 0;

unsafe fn has_pending_capacity() -> bool {
    unsafe {
        let table = &raw const PENDING_INET;
        for i in 0..MAX_PENDING_INET {
            if (*table)[i].active == 0 {
                return true;
            }
        }
        false
    }
}

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

fn log_ipv4(lb: &mut trona::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

fn log_inet_op(op: &[u8], fd: i32, conn_id: u32, ip: u32, port: u16, len: usize) {
    unsafe {
        if *(&raw const LOGGED_INET_OPS) >= 20 {
            return;
        }
        *(&raw mut LOGGED_INET_OPS) += 1;
    }
    trona::udebug!(|_lb| {
        _lb.str(b"[VFS] inet ");
        _lb.str(op);
        if fd >= 0 {
            _lb.str(b" fd=");
            _lb.dec(fd as u64);
        }
        _lb.str(b" conn=");
        _lb.dec(conn_id as u64);
        if ip != 0 || port != 0 {
            _lb.str(b" ip=");
            log_ipv4(&mut _lb, ip);
            _lb.str(b" port=");
            _lb.dec(port as u64);
        }
        if len != 0 {
            _lb.str(b" len=");
            _lb.dec(len as u64);
        }
        _lb.putc(b'\n');
    });
}

fn log_inet_recv_result(fd: i32, conn_id: u32, src_ip: u32, len: usize, data: &[u8]) {
    unsafe {
        if *(&raw const LOGGED_INET_RECV_RESULTS) >= 24 {
            return;
        }
        *(&raw mut LOGGED_INET_RECV_RESULTS) += 1;
    }
    trona::udebug!(|_lb| {
        _lb.str(b"[VFS] inet recvfrom result fd=");
        _lb.dec(fd as u64);
        _lb.str(b" conn=");
        _lb.dec(conn_id as u64);
        _lb.str(b" src=");
        log_ipv4(&mut _lb, src_ip);
        _lb.str(b" len=");
        _lb.dec(len as u64);
        let preview_len = core::cmp::min(data.len(), 8);
        if preview_len > 0 {
            _lb.str(b" bytes=");
            let mut i = 0;
            while i < preview_len {
                if i != 0 {
                    _lb.putc(b':');
                }
                _lb.hex(data[i] as u64);
                i += 1;
            }
        }
        _lb.putc(b'\n');
    });
}

#[inline]
unsafe fn fd_is_nonblocking(cli: *mut ClientState, fd: i32) -> bool {
    unsafe { ((*(*cli).fds.add(fd as usize)).flags & O_NONBLOCK) != 0 }
}

unsafe fn find_inet_fd_by_conn(badge: u64, conn_id: u32) -> Option<i32> {
    unsafe {
        let cli = get_client(badge);
        if cli.is_null() {
            return None;
        }
        for fd in 0..(*cli).fds_cap as usize {
            let fde = &*(*cli).fds.add(fd);
            if fde.active != 0 && fde.fd_type == FD_TYPE_INET_SOCKET && fde.sock_id == conn_id {
                return Some(fd as i32);
            }
        }
        None
    }
}

// ======================================================================

/// Ensure VFS has registered its callback EP with netsrv.
///
/// This is intentionally lazy so VFS startup does not block on netsrv/network
/// availability (e.g. `--no-net` runs).
unsafe fn ensure_inet_callback_registered() -> bool {
    // SAFETY: Single-threaded VFS server initialization/dispatch.
    unsafe {
        if *(&raw const INET_CALLBACK_EP_REGISTERED) {
            return true;
        }

        if !prepare_inet_callback_endpoint() {
            return false;
        }

        // Call netsrv with NET_REGISTER_VFS, transferring a plain copy of our
        // dedicated callback endpoint. netsrv rebadges that cap locally for
        // callback sends.
        ipc::set_send_cap_ctx(ipc_ctx(), 0, VFS_CAP_NETSRV_CALLBACK_EP);

        let mut msg = TronaMsg::zeroed();
        msg.label = NET_REGISTER_VFS;
        msg.length = 0;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const msg, &raw mut resp);
        if err != 0 || resp.label != TRONA_OK {
            crate::puts(b"[VFS] inet: failed to register with netsrv\n");
            return false;
        }

        *(&raw mut INET_CALLBACK_EP_REGISTERED) = true;
        true
    }
}

pub(crate) unsafe fn prepare_inet_callback_endpoint() -> bool {
    unsafe {
        if *(&raw const INET_CALLBACK_EP_PREPARED) {
            return true;
        }

        // init provisions this endpoint via CreateEP=63 during spawn/restart.
        *(&raw mut INET_CALLBACK_EP_PREPARED) = true;
        true
    }
}

// ======================================================================
// Non-blocking forwarding: socket
// ======================================================================

/// Forward NET_SOCKET to netsrv, create FD_TYPE_INET_SOCKET fd.
pub(crate) unsafe fn handle_inet_socket(
    _msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
    sock_type: i32,
    protocol: i32,
) -> bool {
    // SAFETY: IPC context is valid; making synchronous RPC to netsrv.
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
            (*reply).label = if err != 0 {
                TRONA_INVALID_OPERATION
            } else {
                resp.label
            };
            return false;
        }
        let conn_id = resp.regs[0] as u32;
        log_inet_op(b"socket", -1, conn_id, 0, 0, 0);

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_INET_SOCKET;
                (*(*cli).fds.add(fd)).sock_id = conn_id;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).flags = 0;
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return false;
            }
        }

        // No free fd — close the netsrv conn
        let mut close_req = TronaMsg::zeroed();
        close_req.label = NET_CLOSE;
        close_req.regs[0] = conn_id as u64;
        close_req.length = 1;
        let mut close_resp = TronaMsg::zeroed();
        let _ = ipc::call_ctx(
            ipc_ctx(),
            VFS_CAP_NETSRV_EP,
            &raw const close_req,
            &raw mut close_resp,
        );
        (*reply).label = TRONA_OUT_OF_MEMORY;
        false
    }
}

// ======================================================================
// Blocking forwarding: connect (async — TCP handshake)
// ======================================================================

pub(crate) unsafe fn handle_inet_connect(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

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
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
        log_inet_op(b"connect", fd, conn_id, ip, port, 0);

        // Call netsrv synchronously
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
            if fd_is_nonblocking(cli, fd) {
                (*reply).label = TRONA_IN_PROGRESS;
                return false;
            }

            let client_slot = alloc_reply_slot();
            let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, client_slot);
            if err != 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            // TCP SYN sent, handshake pending — record and wait for callback
            if !alloc_pending(conn_id, INET_OP_CONNECT, client_slot, badge) {
                let mut client_reply = TronaMsg::zeroed();
                client_reply.label = TRONA_OUT_OF_MEMORY;
                ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
            }
            return true; // skip_reply
        }

        // Immediate result (UDP connect or synchronous error)
        (*reply).label = resp.label;
        false
    }
}

// ======================================================================
// Non-blocking forwarding: bind
// ======================================================================

pub(crate) unsafe fn handle_inet_bind(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

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
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

        let mut req = TronaMsg::zeroed();
        req.label = NET_BIND;
        req.regs[0] = conn_id as u64;
        req.regs[1] = ip as u64;
        req.regs[2] = port as u64;
        req.length = 3;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
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
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let backlog = (*msg).regs[1] as u8;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

        let mut req = TronaMsg::zeroed();
        req.label = NET_LISTEN;
        req.regs[0] = conn_id as u64;
        req.regs[1] = backlog as u64;
        req.length = 2;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
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
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

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
            if fd_is_nonblocking(cli, fd) {
                (*reply).label = TRONA_WOULD_BLOCK;
                return false;
            }

            if !has_pending_capacity() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            let client_slot = alloc_reply_slot();
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
                ipc_ctx(),
                VFS_CAP_NETSRV_EP,
                &raw const wait_req,
                &raw mut wait_resp,
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
            // Connection already queued — allocate new fd
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

// ======================================================================
// Non-blocking forwarding: write (send)
// ======================================================================

pub(crate) unsafe fn handle_inet_write(
    msg: *const TronaMsg,
    fde: *mut FdEntry,
    reply: *mut TronaMsg,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let conn_id = (*fde).sock_id;
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

// ======================================================================
// Blocking forwarding: read (recv)
// ======================================================================

pub(crate) unsafe fn handle_inet_read(
    msg: *const TronaMsg,
    fde: *mut FdEntry,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let conn_id = (*fde).sock_id;
        let max_len = (*msg).regs[1] as u16;
        let capped = if max_len > 152 { 152 } else { max_len };

        let mut req = TronaMsg::zeroed();
        req.label = NET_RECV;
        req.regs[0] = conn_id as u64;
        req.regs[1] = capped as u64;
        req.length = 2;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);

        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        if resp.label == TRONA_PENDING {
            if ((*fde).flags & O_NONBLOCK) != 0 {
                (*reply).label = TRONA_WOULD_BLOCK;
                return false;
            }

            if !has_pending_capacity() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            let client_slot = alloc_reply_slot();
            let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, client_slot);
            if err != 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            let mut wait_req = TronaMsg::zeroed();
            wait_req.label = NET_RECV_WAIT;
            wait_req.regs[0] = conn_id as u64;
            wait_req.regs[1] = capped as u64;
            wait_req.length = 2;
            let mut wait_resp = TronaMsg::zeroed();
            let wait_err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_NETSRV_EP,
                &raw const wait_req,
                &raw mut wait_resp,
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
            // Data available immediately
            (*reply).label = resp.label;
            (*reply).regs[0] = resp.regs[0]; // byte count
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

// ======================================================================
// Non-blocking forwarding: sendto (UDP)
// ======================================================================

pub(crate) unsafe fn handle_inet_sendto(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

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
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
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
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let max_len = (*msg).regs[1] as u16;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
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
            if fd_is_nonblocking(cli, fd) {
                (*reply).label = TRONA_WOULD_BLOCK;
                return false;
            }

            if !has_pending_capacity() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            let client_slot = alloc_reply_slot();
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
                ipc_ctx(),
                VFS_CAP_NETSRV_EP,
                &raw const wait_req,
                &raw mut wait_resp,
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
            // Data available
            (*reply).label = resp.label;
            (*reply).regs[0] = resp.regs[0]; // data_len
            (*reply).regs[1] = resp.regs[1]; // src_ip
            (*reply).regs[2] = resp.regs[2]; // src_port
            (*reply).regs[3] = resp.regs[3]; // timestamp_ns_or_none
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

// ======================================================================
// Non-blocking forwarding: shutdown
// ======================================================================

pub(crate) unsafe fn handle_inet_shutdown(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let how = (*msg).regs[1] as i32;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;

        let mut req = TronaMsg::zeroed();
        req.label = NET_SHUTDOWN;
        req.regs[0] = conn_id as u64;
        req.regs[1] = how as u64;
        req.length = 2;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        };
        false
    }
}

// ======================================================================
// Non-blocking forwarding: getsockname / getpeername / socket options
// ======================================================================

pub(crate) unsafe fn handle_inet_getsockname(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
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
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
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
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
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

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
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
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        };
        false
    }
}

pub(crate) unsafe fn handle_inet_getsockopt(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        if !ensure_inet_callback_registered() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let fd = (*msg).regs[0] as i32;
        let level = (*msg).regs[1] as i32;
        let optname = (*msg).regs[2] as i32;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_INET_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let conn_id = (*(*cli).fds.add(fd as usize)).sock_id;
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

// ======================================================================
// Non-blocking forwarding: close
// ======================================================================

pub(crate) unsafe fn close_inet_socket(fde: *mut FdEntry) {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let conn_id = (*fde).sock_id;
        let mut req = TronaMsg::zeroed();
        req.label = NET_CLOSE;
        req.regs[0] = conn_id as u64;
        req.length = 1;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut resp);
        if err != 0 || resp.label != TRONA_OK {
            crate::puts(b"[VFS] inet: close_inet_socket failed\n");
        }
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
pub(crate) unsafe fn handle_netsrv_callback(msg: *const TronaMsg, reply: *mut TronaMsg) {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let conn_id = (*msg).regs[0] as u32;
        let result = (*msg).regs[1];
        let op_type = (*msg).regs[2] as u8;
        let mut replied_to_pending = false;
        let mut woke_poll_fd: i32 = -1;

        if let Some((client_slot, client_badge)) = find_pending(conn_id, op_type) {
            replied_to_pending = true;
            let mut client_reply = TronaMsg::zeroed();

            match op_type {
                INET_OP_CONNECT => {
                    client_reply.label = result;
                }
                INET_OP_RECV => {
                    client_reply.label = result;
                    if result == TRONA_OK {
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
                    if result == TRONA_OK {
                        let data_len = (*msg).regs[3] as usize;
                        // Cap to max bytes that fit in regs[7..20] (13 regs * 8 = 104)
                        let actual_len = if data_len > 104 { 104 } else { data_len };
                        let src_ip = (*msg).regs[4] as u32;
                        let src_port = (*msg).regs[5] as u16;
                        let timestamp_ns = (*msg).regs[6];
                        client_reply.regs[0] = actual_len as u64;
                        client_reply.regs[1] = src_ip as u64;
                        client_reply.regs[2] = src_port as u64;
                        client_reply.regs[3] = timestamp_ns;
                        if actual_len > 0 {
                            let src = &(*msg).regs[7] as *const u64 as *const u8;
                            let dst = &raw mut client_reply.regs[4] as *mut u8;
                            for i in 0..actual_len {
                                *dst.add(i) = *src.add(i);
                            }
                        }
                        client_reply.length = 4 + ((actual_len as u64 + 7) / 8);
                    } else {
                        client_reply.regs[0] = 0;
                        client_reply.length = 1;
                    }
                }
                INET_OP_ACCEPT => {
                    client_reply.label = result;
                    if result == TRONA_OK {
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
                                client_reply.label = TRONA_OUT_OF_MEMORY;
                            }
                        }
                    }
                }
                _ => {
                    client_reply.label = TRONA_INVALID_OPERATION;
                }
            }

            ipc::send_ctx(ipc_ctx(), client_slot, &raw const client_reply);
        }

        if op_type == INET_OP_CONNECT {
            // Non-blocking connect uses poll/getsockopt rather than a saved caller.
            // Wake waiters on the fd that owns this conn_id.
            for ci in 0..crate::max_clients() {
                let c = &*(&raw const crate::CLIENTS!()[ci]);
                if c.active == 0 {
                    continue;
                }
                if let Some(fd) = find_inet_fd_by_conn(c.badge, conn_id) {
                    let revents = if result == TRONA_OK { 0x004 } else { 0x008 };
                    wake_poll_waiters(c.badge, fd, revents);
                    woke_poll_fd = fd;
                    break;
                }
            }
        } else if !replied_to_pending
            && result == TRONA_OK
            && (op_type == INET_OP_RECV || op_type == INET_OP_RECVFROM)
        {
            for ci in 0..crate::max_clients() {
                let c = &*(&raw const crate::CLIENTS!()[ci]);
                if c.active == 0 {
                    continue;
                }
                if let Some(fd) = find_inet_fd_by_conn(c.badge, conn_id) {
                    wake_poll_waiters(c.badge, fd, 0x001);
                    woke_poll_fd = fd;
                    break;
                }
            }
        }

        if *(&raw const LOGGED_INET_CALLBACKS) < 32 {
            *(&raw mut LOGGED_INET_CALLBACKS) += 1;
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] inet callback conn=");
                _lb.dec(conn_id as u64);
                _lb.str(b" op=");
                _lb.dec(op_type as u64);
                _lb.str(b" result=");
                _lb.hex(result);
                _lb.str(b" pending=");
                _lb.dec(replied_to_pending as u64);
                _lb.str(b" wake_fd=");
                if woke_poll_fd >= 0 {
                    _lb.dec(woke_poll_fd as u64);
                } else {
                    _lb.str(b"none");
                }
                _lb.putc(b'\n');
            });
        }

        // Reply OK to netsrv (completing the callback IPC)
        (*reply).label = TRONA_OK;
    }
}
