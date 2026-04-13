// SPDX-License-Identifier: GPL-2.0-only
//! netsrv async callback table and completion handler.

use trona::sync::Mutex;
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

use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::ipc_ctx;

// ======================================================================
// Pending operations table
// ======================================================================

pub(super) const MAX_PENDING_INET: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct PendingInetOp {
    pub(super) active: u8,
    pub(super) client_reply_slot: u64,
    pub(super) client_badge: u64,
    pub(super) conn_id: u32,
    pub(super) op_type: u8,
}

impl PendingInetOp {
    pub(super) const fn zeroed() -> Self {
        PendingInetOp {
            active: 0,
            client_reply_slot: 0,
            client_badge: 0,
            conn_id: 0,
            op_type: 0,
        }
    }
}

pub(super) static mut PENDING_INET: [PendingInetOp; MAX_PENDING_INET] =
    [PendingInetOp::zeroed(); MAX_PENDING_INET];
static PENDING_INET_LOCK: Mutex = Mutex::new();
pub(super) static mut NETSRV_CALLBACK_REGISTERED: bool = false;
pub(super) static mut LOGGED_INET_OPS: u8 = 0;
pub(super) static mut LOGGED_INET_CALLBACKS: u8 = 0;
pub(super) static mut LOGGED_INET_RECV_RESULTS: u8 = 0;

pub(super) unsafe fn has_pending_capacity() -> bool {
    unsafe {
        PENDING_INET_LOCK.lock();
        let table = &raw const PENDING_INET;
        for i in 0..MAX_PENDING_INET {
            if (*table)[i].active == 0 {
                PENDING_INET_LOCK.unlock();
                return true;
            }
        }
        PENDING_INET_LOCK.unlock();
        false
    }
}

pub(super) unsafe fn alloc_pending(
    conn_id: u32,
    op_type: u8,
    client_reply_slot: u64,
    client_badge: u64,
) -> bool {
    unsafe {
        PENDING_INET_LOCK.lock();
        let table = &mut *(&raw mut PENDING_INET);
        for entry in table.iter_mut() {
            if entry.active == 0 {
                entry.active = 1;
                entry.conn_id = conn_id;
                entry.op_type = op_type;
                entry.client_reply_slot = client_reply_slot;
                entry.client_badge = client_badge;
                PENDING_INET_LOCK.unlock();
                return true;
            }
        }
        PENDING_INET_LOCK.unlock();
        false
    }
}

pub(super) unsafe fn find_pending(conn_id: u32, op_type: u8) -> Option<(u64, u64)> {
    unsafe {
        PENDING_INET_LOCK.lock();
        let table = &mut *(&raw mut PENDING_INET);
        for entry in table.iter_mut() {
            if entry.active != 0 && entry.conn_id == conn_id && entry.op_type == op_type {
                let slot = entry.client_reply_slot;
                let badge = entry.client_badge;
                entry.active = 0;
                PENDING_INET_LOCK.unlock();
                return Some((slot, badge));
            }
        }
        PENDING_INET_LOCK.unlock();
        None
    }
}

pub(crate) unsafe fn dump_pending_inet() {
    unsafe {
        PENDING_INET_LOCK.lock();
        let table = &*(&raw const PENDING_INET);
        let mut active = 0u32;
        for entry in table.iter() {
            if entry.active != 0 {
                active += 1;
                trona::uinfo!(|_lb| {
                    _lb.str(b"  inet pending: conn=");
                    _lb.dec(entry.conn_id as u64);
                    _lb.str(b" op=");
                    _lb.dec(entry.op_type as u64);
                    _lb.str(b" reply_slot=");
                    _lb.hex(entry.client_reply_slot);
                    _lb.str(b" badge=");
                    _lb.hex(entry.client_badge);
                    _lb.str(b"\n");
                });
            }
        }
        trona::uinfo!(|_lb| {
            _lb.str(b"[VFS] pending inet: ");
            _lb.dec(active as u64);
            _lb.str(b"/");
            _lb.dec(MAX_PENDING_INET as u64);
            _lb.str(b"\n");
        });
        PENDING_INET_LOCK.unlock();
    }
}

pub(super) fn log_ipv4(lb: &mut trona::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

pub(super) fn log_inet_op(op: &[u8], fd: i32, conn_id: u32, ip: u32, port: u16, len: usize) {
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

pub(super) fn log_inet_recv_result(fd: i32, conn_id: u32, src_ip: u32, len: usize, data: &[u8]) {
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

// fd_is_nonblocking removed — callers now read flags from ObjectSlot directly.

pub(super) unsafe fn find_inet_fd_by_conn_badge(badge: u64, conn_id: u32) -> Option<i32> {
    unsafe {
        // Use static VFS_STATE_PTR set by owner loop (callback runs in owner context).
        let state_ptr = crate::owner::loop_::OWNER_STATE_PTR;
        if state_ptr.is_null() { return None; }
        let state = &*state_ptr;
        let (slot, epoch) = state.badge_map.lookup(badge)?;
        let h = ClientHandle::new(slot, epoch);
        let cli = state.clients.get(h)?;
        for fd in 0..MAX_CLIENT_OBJECTS {
            let s = &cli.objects[fd];
            if s.is_live() && s.kind() == ObjectKind::InetSocket && s.inet_socket_id() == Some(conn_id) {
                return Some(fd as i32);
            }
        }
        None
    }
}

// ======================================================================

/// Ensure VFS has registered its shared backend callback EP with netsrv.
///
/// This is intentionally lazy so VFS startup does not block on netsrv/network
/// availability (e.g. `--no-net` runs).
pub(super) unsafe fn ensure_inet_callback_registered() -> bool {
    // SAFETY: Single-threaded VFS server initialization/dispatch.
    unsafe {
        if *(&raw const NETSRV_CALLBACK_REGISTERED) {
            return true;
        }

        if !crate::backend::prepare_backend_callback_endpoint() {
            return false;
        }

        // Call netsrv with NET_REGISTER_VFS, transferring a plain copy of our
        // shared backend callback endpoint. netsrv rebadges that cap locally for
        // callback sends.
        ipc::set_send_cap_ctx(ipc_ctx(), 0, VFS_CAP_BACKEND_CALLBACK_EP);

        let mut msg = TronaMsg::zeroed();
        msg.label = NET_REGISTER_VFS;
        msg.length = 0;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const msg, &raw mut resp);
        if err != 0 || resp.label != TRONA_OK {
            crate::puts(b"[VFS] inet: failed to register with netsrv\n");
            return false;
        }

        *(&raw mut NETSRV_CALLBACK_REGISTERED) = true;
        true
    }
}

// ======================================================================
// Helper: allocate a new fd for an inet socket
// ======================================================================

pub(super) unsafe fn alloc_inet_fd(badge: u64, conn_id: u32) -> Option<i32> {
    unsafe {
        let state_ptr = crate::owner::loop_::OWNER_STATE_PTR;
        if state_ptr.is_null() { return None; }
        let state = &mut *state_ptr;
        let (slot, epoch) = state.badge_map.lookup(badge)?;
        let h = ClientHandle::new(slot, epoch);
        let fd = crate::fileops::open::reserve_fd_owned(state, h)?;
        let cli = state.clients.get_mut(h)?;
        let s = &mut cli.objects[fd as usize];
        s.set_inet_socket(conn_id);
        s.offset = 0;
        s.flags = 0;
        s.nonblocking = 0;
        Some(fd)
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

        // Poll wakeup for non-blocking connect and unsolicited data-ready.
        // Uses badge_map iteration via OWNER_STATE_PTR.
        let _ = woke_poll_fd; // poll wakeup deferred to poll.rs integration

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
