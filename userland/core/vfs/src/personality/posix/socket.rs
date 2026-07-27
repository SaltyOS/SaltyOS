// SPDX-License-Identifier: GPL-2.0-only
//
//! Socket dispatch — `VFS_SOCKET` / `VFS_SOCKETPAIR` / `VFS_BIND`
//! / `VFS_LISTEN` / `VFS_ACCEPT` / `VFS_CONNECT` / `VFS_SHUTDOWN`
//! / `VFS_SEND` / `VFS_RECV`.
//!
//! Two socket families are supported. **UNIX-domain** sockets
//! (`AF_UNIX`) live entirely inside vfs: a [`SocketState`] arena
//! entry holds the rx / tx rings, the listener backlog, and the
//! peer-pointer that connect / accept set up. **INET sockets**
//! (`AF_INET` / `AF_INET6`) project onto netsrv via the per-mount
//! `BackendSessionSlot` machinery in [`crate::personality::posix::inet`]; vfs
//! still keeps a [`SocketState`] entry so the caller's fd has a
//! handle, but every IO call parks on a netsrv RPC.
//!
//! Wire layout follows POSIX-shaped wrappers — the personality
//! layer marshals (sockaddr, length) tuples into the inline regs
//! and the backend driver decodes them. SCM_RIGHTS payloads ride
//! `caps[..]` with the receiver's fd-table install handled by
//! [`crate::personality::posix::scm_rights`] on the `VFS_RECV` arm.

use trona_kernel::core_types::TronaMsg;

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::socket::{SCM_RIGHTS_MAX_FDS, SocketState};
use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::open_object::{OpenObject, OpenObjectAccess, OpenObjectFlags, OpenObjectKind};
use crate::server::types::{ClientHandle, OpenObjectHandle};
use trona_protocol::vfs::public::{
    VFS_ACCEPT, VFS_BIND, VFS_CONNECT, VFS_GETPEERNAME, VFS_GETSOCKNAME, VFS_GETSOCKOPT,
    VFS_LISTEN, VFS_RECV, VFS_RECVMSG_FLAG_WANT_ADDR, VFS_RECVMSG_FLAG_WANT_RIGHTS, VFS_SEND,
    VFS_SENDMSG_FLAG_LOCAL_ADDR, VFS_SETSOCKOPT, VFS_SHUTDOWN, VFS_SOCKET, VFS_SOCKETPAIR,
};

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const SOCK_STREAM: u16 = 1;
const SOCK_DGRAM: u16 = 2;
const SOCK_SEQPACKET: u16 = 5;

const SOCK_NONBLOCK: u32 = 0o4000;
const SOCK_CLOEXEC: u32 = 0o2_000_000;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        match msg.label {
            VFS_SOCKET => handle_socket(state, client, msg, reply_lease),
            VFS_SOCKETPAIR => handle_socketpair(state, client, msg, reply_lease),
            VFS_BIND => handle_bind(state, client, msg, reply_lease),
            VFS_LISTEN => handle_listen(state, client, msg, reply_lease),
            VFS_ACCEPT => handle_accept(state, client, msg, reply_lease),
            VFS_CONNECT => handle_connect(state, client, msg, reply_lease),
            VFS_SHUTDOWN => handle_shutdown(state, client, msg, reply_lease),
            VFS_SEND => handle_send(state, client, msg, reply_lease),
            VFS_RECV => handle_recv(state, client, msg, reply_lease),
            VFS_GETSOCKNAME => handle_getsockname(state, client, msg, reply_lease),
            VFS_GETPEERNAME => handle_getpeername(state, client, msg, reply_lease),
            VFS_SETSOCKOPT => handle_setsockopt(state, client, msg, reply_lease),
            VFS_GETSOCKOPT => handle_getsockopt(state, client, msg, reply_lease),
            _ => send_reply_err_for_client(state, client, reply_lease, VfsError::Inval),
        }
    }
}

// ---------------------------------------------------------------------------
// VFS_SOCKET
// ---------------------------------------------------------------------------

unsafe fn handle_socket(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let domain = msg.regs[0] as u16;
    let sock_type_raw = msg.regs[1] as u32;
    let sock_type = (sock_type_raw & 0xFFFF) as u16;
    let protocol = msg.regs[2] as u32;

    if !is_supported_domain(domain) || !is_supported_type(sock_type) {
        send_reply_err_for_client(state, client, reply_lease, VfsError::NotSup);
        return;
    }

    let inet_conn = if is_inet(domain) {
        match crate::personality::posix::inet::create_socket(state, sock_type, protocol) {
            Ok(v) => Some(v),
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        }
    } else {
        None
    };

    let sock_h = match alloc_socket(state, domain, sock_type, protocol as u16) {
        Some(h) => h,
        None => {
            if let Some((conn_id, _)) = inet_conn {
                crate::personality::posix::inet::close_conn(state, conn_id);
            }
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };
    if let Some((conn_id, netsrv_gen)) = inet_conn {
        if let Some(s) = state.sockets.get_mut(sock_h) {
            s.conn_id = conn_id;
            s.netsrv_gen = netsrv_gen;
        }
    }

    let cloexec = (sock_type_raw & SOCK_CLOEXEC) != 0;
    let nonblock = (sock_type_raw & SOCK_NONBLOCK) != 0;

    match install_socket_fd(state, client, sock_h, cloexec, nonblock) {
        Ok(fd) => send_reply_ok_for_client(state, client, reply_lease, &[fd as u64]),
        Err(e) => {
            release_socket(state, sock_h);
            send_reply_err_for_client(state, client, reply_lease, e);
        }
    }
}

// ---------------------------------------------------------------------------
// VFS_SOCKETPAIR
// ---------------------------------------------------------------------------

unsafe fn handle_socketpair(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let domain = msg.regs[0] as u16;
    let sock_type_raw = msg.regs[1] as u32;
    let sock_type = (sock_type_raw & 0xFFFF) as u16;

    if domain != AF_UNIX || !is_supported_type(sock_type) {
        // socketpair is UNIX-only.
        send_reply_err_for_client(state, client, reply_lease, VfsError::NotSup);
        return;
    }

    let sock_a = match alloc_socket(state, domain, sock_type, 0) {
        Some(h) => h,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };
    let sock_b = match alloc_socket(state, domain, sock_type, 0) {
        Some(h) => h,
        None => {
            release_socket(state, sock_a);
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };

    bind_unix_pair(state, sock_a, sock_b);

    let cloexec = (sock_type_raw & SOCK_CLOEXEC) != 0;
    let nonblock = (sock_type_raw & SOCK_NONBLOCK) != 0;

    let fd_a = match install_socket_fd(state, client, sock_a, cloexec, nonblock) {
        Ok(fd) => fd,
        Err(e) => {
            release_socket(state, sock_a);
            release_socket(state, sock_b);
            send_reply_err_for_client(state, client, reply_lease, e);
            return;
        }
    };
    let fd_b = match install_socket_fd(state, client, sock_b, cloexec, nonblock) {
        Ok(fd) => fd,
        Err(e) => {
            // Detach fd_a too so we leave no half-open fd.
            if let Some(cli) = state.clients.get_mut(client) {
                cli.slot_table.clear(fd_a);
            }
            release_socket(state, sock_a);
            release_socket(state, sock_b);
            send_reply_err_for_client(state, client, reply_lease, e);
            return;
        }
    };
    send_reply_ok_for_client(state, client, reply_lease, &[fd_a as u64, fd_b as u64]);
}

// ---------------------------------------------------------------------------
// VFS_BIND / LISTEN / ACCEPT / CONNECT / SHUTDOWN
// ---------------------------------------------------------------------------

unsafe fn handle_bind(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    // regs[1] carries the abstract-namespace marker in bit 63;
    // decode_unix_wire_addr masks it off for the byte length and reconstructs the
    // leading-NUL marker for abstract names (Linux convention).
    let addr = decode_unix_wire_addr(msg, 2, msg.regs[1]);
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        // Inet path — `inet::handle_bind` issues the netsrv RPC,
        // stamps `Resume::Net`, and the net completion router
        // emits the reply when netsrv answers.
        crate::personality::posix::inet::handle_bind(state, client, msg, reply_lease);
        return;
    }
    match unix_bind(state, sock_h, &addr) {
        Ok(_) => send_reply_ok_for_client(state, client, reply_lease, &[]),
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
}

unsafe fn handle_listen(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let backlog = msg.regs[1] as u32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_listen(state, client, msg, reply_lease);
        return;
    }
    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.state = crate::core::socket::SocketLifeState::Listening;
        s.listen_backlog = backlog.max(1);
    }
    send_reply_ok_for_client(state, client, reply_lease, &[]);
}

unsafe fn handle_accept(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_accept(state, client, msg, reply_lease);
        return;
    }
    match unix_accept(state, sock_h, client) {
        Ok(fd) => send_reply_ok_for_client(state, client, reply_lease, &[fd as u64]),
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
}

unsafe fn handle_connect(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    // regs[1] carries the abstract-namespace marker in bit 63;
    // decode_unix_wire_addr masks it off for the byte length and reconstructs the
    // leading-NUL marker for abstract names (Linux convention).
    let addr = decode_unix_wire_addr(msg, 2, msg.regs[1]);
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_connect(state, client, msg, reply_lease);
        return;
    }
    match unix_connect(state, sock_h, &addr) {
        Ok(_) => send_reply_ok_for_client(state, client, reply_lease, &[]),
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
}

unsafe fn handle_shutdown(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let how = msg.regs[1] as u32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_shutdown(state, client, msg, reply_lease);
        return;
    }
    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.shutdown_flags |= how as u8;
    }
    crate::personality::posix::socket_wait::drain_all(state, sock_h);
    send_reply_ok_for_client(state, client, reply_lease, &[]);
}

unsafe fn handle_send(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let data_len = msg.regs[1] as usize;
    let flags = msg.regs[2] as u32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_send(state, client, msg, reply_lease);
        return;
    }
    match unix_send_from_msg(state, client, sock_h, msg, data_len, flags) {
        Ok(bytes) => send_reply_ok_for_client(state, client, reply_lease, &[bytes as u64]),
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
}

unsafe fn handle_recv(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_recv(state, client, msg, reply_lease);
        return;
    }
    let data_len = msg.regs[1] as usize;
    let flags = msg.regs[2] as u32;
    match unix_recv_to_reply(state, client, sock_h, data_len, flags, reply_lease) {
        Ok(()) => {}
        Err((e, reply_lease)) => send_reply_err_for_client(state, client, reply_lease, e),
    }
}

unsafe fn handle_getsockname(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_getsockname(state, client, msg, reply_lease);
        return;
    }
    emit_unix_name(state, sock_h, true, reply_lease);
}

unsafe fn handle_getpeername(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_getpeername(state, client, msg, reply_lease);
        return;
    }
    emit_unix_name(state, sock_h, false, reply_lease);
}

unsafe fn handle_setsockopt(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_setsockopt(state, client, msg, reply_lease);
    } else {
        send_reply_ok_for_client(state, client, reply_lease, &[]);
    }
}

unsafe fn handle_getsockopt(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    let sock_h = match resolve_socket_fd(state, client, fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        crate::personality::posix::inet::handle_getsockopt(state, client, msg, reply_lease);
    } else {
        send_reply_ok_for_client(state, client, reply_lease, &[0, 0]);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_supported_domain(domain: u16) -> bool {
    matches!(domain, AF_UNIX | AF_INET | AF_INET6)
}

fn is_supported_type(t: u16) -> bool {
    matches!(t, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET)
}

fn is_inet(domain: u16) -> bool {
    matches!(domain, AF_INET | AF_INET6)
}

fn alloc_socket(
    state: &mut VfsState,
    domain: u16,
    sock_type: u16,
    protocol: u16,
) -> Option<Handle<SocketState>> {
    use crate::core::socket::SocketBacking;

    let backing = match domain {
        AF_UNIX => SocketBacking::Unix,
        AF_INET | AF_INET6 => SocketBacking::Inet,
        _ => SocketBacking::Unset,
    };

    // For inet sockets snapshot the current netsrv generation so
    // future `recv` / `accept` completions can drop replies that
    // crossed a netsrv re-registration boundary.
    let netsrv_gen = if matches!(backing, SocketBacking::Inet) {
        crate::owner::session::default_inet_session(state)
            .ok()
            .and_then(|h| state.backend_sessions.get(h).map(|s| s.live_gen as u32))
            .unwrap_or(0)
    } else {
        0
    };

    let h = state.sockets.alloc()?;
    if let Some(s) = state.sockets.get_mut(h) {
        *s = SocketState::zeroed();
        s.active = 1;
        s.backing = backing;
        s.domain = domain;
        s.sock_type = sock_type;
        s.protocol = protocol;
        s.netsrv_gen = netsrv_gen;
    }
    Some(h)
}

pub(crate) fn release_socket(state: &mut VfsState, sock_h: Handle<SocketState>) {
    let conn_id = state
        .sockets
        .get(sock_h)
        .filter(|s| s.is_inet())
        .map(|s| s.conn_id)
        .unwrap_or(u32::MAX);
    crate::personality::posix::socket_wait::drain_all(state, sock_h);
    crate::personality::posix::inet_wait::drain_all(state, sock_h);
    drain_unix_accept_queue(state, sock_h);
    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.accept_head = u32::MAX;
        s.accept_tail = u32::MAX;
        s.accept_count = 0;
        s.accept_next = u32::MAX;
        s.active = 0;
    }
    let _ = state.sockets.release(sock_h);
    if conn_id != u32::MAX {
        crate::personality::posix::inet::close_conn(state, conn_id);
    }
}

pub(crate) fn install_accepted_inet_socket(
    state: &mut VfsState,
    client_id: u32,
    listener_h: Handle<SocketState>,
    conn_id: u32,
    peer_addr: &[u8],
) -> Result<u32, VfsError> {
    let mut client = None;
    state.clients.for_each_active(|h, c| {
        if c.client_id == client_id {
            client = Some(h);
            false
        } else {
            true
        }
    });
    let client = match client {
        Some(h) => h,
        None => {
            crate::personality::posix::inet::close_conn(state, conn_id);
            return Err(VfsError::BadF);
        }
    };
    let (domain, sock_type, protocol, netsrv_gen) = match state
        .sockets
        .get(listener_h)
        .map(|s| (s.domain, s.sock_type, s.protocol, s.netsrv_gen))
    {
        Some(v) => v,
        None => {
            crate::personality::posix::inet::close_conn(state, conn_id);
            return Err(VfsError::BadF);
        }
    };
    let sock_h = match alloc_socket(state, domain, sock_type, protocol) {
        Some(h) => h,
        None => {
            crate::personality::posix::inet::close_conn(state, conn_id);
            return Err(VfsError::NoMem);
        }
    };
    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.state = crate::core::socket::SocketLifeState::Connected;
        s.conn_id = conn_id;
        s.netsrv_gen = netsrv_gen;
        let n = peer_addr.len().min(s.peer_addr.len());
        let mut i = 0usize;
        while i < n {
            s.peer_addr[i] = peer_addr[i];
            i += 1;
        }
        s.peer_addr_len = n as u32;
    }
    match install_socket_fd(state, client, sock_h, false, false) {
        Ok(fd) => Ok(fd),
        Err(e) => {
            release_socket(state, sock_h);
            Err(e)
        }
    }
}

pub(crate) fn resolve_socket_fd(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<Handle<SocketState>, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get(client).ok_or(VfsError::Io)?;
    let oh = cli.slot_table.lookup(fd as u32).ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(oh).ok_or(VfsError::BadF)?;
    let sock_h = state
        .sockets
        .handle_from_slot(obj.personality_aux)
        .ok_or(VfsError::BadF)?;
    if state
        .sockets
        .get(sock_h)
        .map(|s| s.active != 0)
        .unwrap_or(false)
    {
        Ok(sock_h)
    } else {
        Err(VfsError::BadF)
    }
}

fn install_socket_fd(
    state: &mut VfsState,
    client: ClientHandle,
    sock_h: Handle<SocketState>,
    cloexec: bool,
    nonblock: bool,
) -> Result<u32, VfsError> {
    let obj_h = state.open_objects.alloc().ok_or(VfsError::NoMem)?;
    if let Some(obj) = state.open_objects.get_mut(obj_h) {
        *obj = OpenObject::EMPTY;
        obj.refcount = 1;
        obj.kind = OpenObjectKind::Socket;
        obj.personality_aux = sock_h.slot();
        let mut f = OpenObjectFlags::READABLE | OpenObjectFlags::WRITABLE;
        if nonblock {
            f |= OpenObjectFlags::O_NONBLOCK;
        }
        obj.flags = f;
        obj.access = OpenObjectAccess::READ | OpenObjectAccess::WRITE;
        obj.share = crate::ops::SharePolicy::permissive().bits();
    }
    let cli = state.clients.get_mut(client).ok_or_else(|| {
        let _ = state.open_objects.release(obj_h);
        VfsError::Io
    })?;
    let fd = cli.slot_table.find_first_empty_from(0).map_err(|_| {
        let _ = state.open_objects.release(obj_h);
        VfsError::NoMem
    })?;
    cli.slot_table.set(fd, obj_h).map_err(|_| {
        let _ = state.open_objects.release(obj_h);
        VfsError::NoMem
    })?;
    if cloexec {
        cli.slot_table.set_slot_flag_bit(
            fd,
            crate::personality::posix::consts::POSIX_FD_CLOEXEC,
            true,
        );
    }
    Ok(fd)
}

/// Decode an inline wire UNIX address into the 32-byte `local_addr` form.
/// `encoded_len` carries the abstract-namespace marker in bit 63. Following
/// Linux's convention, an abstract address is stored with a reconstructed
/// leading NUL byte (`[0, name…]`) — the wire carries only the name. The name
/// is length-bounded (not NUL-terminated), so it may contain embedded NULs.
/// Pathname addresses are stored verbatim. This makes `local_addr` itself the
/// single source of truth for abstract-vs-pathname (`local_addr[0] == 0`).
fn decode_unix_wire_addr(msg: &TronaMsg, base_reg: usize, encoded_len: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let is_abstract = (encoded_len & (1u64 << 63)) != 0;
    let name_len = (encoded_len & !(1u64 << 63)) as usize;
    let off = if is_abstract { 1 } else { 0 };
    let cap = name_len.min(32 - off);
    let src = (&raw const msg.regs[base_reg]) as *const u8;
    for i in 0..cap {
        buf[off + i] = unsafe { *src.add(i) };
    }
    buf
}

fn bind_unix_pair(state: &mut VfsState, a: Handle<SocketState>, b: Handle<SocketState>) {
    use crate::core::socket::SocketLifeState;
    let (a_slot, a_epoch) = (a.slot(), a.epoch());
    let (b_slot, b_epoch) = (b.slot(), b.epoch());
    if let Some(s) = state.sockets.get_mut(a) {
        s.remote = b_slot;
        s.remote_epoch = b_epoch;
        s.state = SocketLifeState::Connected;
    }
    if let Some(s) = state.sockets.get_mut(b) {
        s.remote = a_slot;
        s.remote_epoch = a_epoch;
        s.state = SocketLifeState::Connected;
    }
}

fn unix_bind(
    state: &mut VfsState,
    sock_h: Handle<SocketState>,
    addr: &[u8; 32],
) -> Result<(), VfsError> {
    use crate::core::socket::SocketLifeState;
    if let Some(s) = state.sockets.get_mut(sock_h) {
        // UNIX-domain bind copies the inline 32-byte truncation of
        // sun_path into local_addr; sockaddr_un's full 108-byte
        // payload is reachable via the longer wire path used by
        // SCM_RIGHTS-bearing senders, but VFS_BIND's inline regs
        // already cap addresses at the truncated form.
        for i in 0..32usize {
            s.local_addr[i] = addr[i];
        }
        s.local_addr_len = 32;
        // bind alone does not transition past Bound; listen / accept
        // / connect drive subsequent transitions.
        if matches!(s.state, SocketLifeState::Initial) {
            s.state = SocketLifeState::Bound;
        }
    }
    Ok(())
}

fn unix_connect(
    state: &mut VfsState,
    sock_h: Handle<SocketState>,
    addr: &[u8; 32],
) -> Result<(), VfsError> {
    use crate::core::socket::SocketLifeState;
    // Locate a listening peer whose local_addr matches the inline
    // 32-byte truncation of the supplied sun_path. The match must
    // be against a UNIX-domain socket in the Listening state.
    let mut listener: Option<Handle<SocketState>> = None;
    state.sockets.for_each_active(|h, s| {
        if !matches!(s.state, SocketLifeState::Listening) {
            return true;
        }
        if !s.is_unix() {
            return true;
        }
        let cap = s.local_addr_len.min(32) as usize;
        let mut eq = cap == 32;
        if eq {
            for i in 0..32 {
                if s.local_addr[i] != addr[i] {
                    eq = false;
                    break;
                }
            }
        }
        if eq {
            listener = Some(h);
            false
        } else {
            true
        }
    });
    let listener_h = listener.ok_or(VfsError::NoEnt)?;

    let (domain, sock_type, protocol, listener_addr, listener_addr_len, backlog, queued) = state
        .sockets
        .get(listener_h)
        .map(|s| {
            (
                s.domain,
                s.sock_type,
                s.protocol,
                s.local_addr,
                s.local_addr_len,
                s.listen_backlog,
                s.accept_count,
            )
        })
        .ok_or(VfsError::BadF)?;
    if backlog != 0 && queued >= backlog {
        return Err(VfsError::Busy);
    }
    let accepted_h = alloc_socket(state, domain, sock_type, protocol).ok_or(VfsError::NoMem)?;
    let (client_slot, client_epoch) = (sock_h.slot(), sock_h.epoch());
    let (accepted_slot, accepted_epoch) = (accepted_h.slot(), accepted_h.epoch());

    let client_addr = state
        .sockets
        .get(sock_h)
        .map(|s| (s.local_addr, s.local_addr_len))
        .unwrap_or(([0u8; crate::core::socket::SOCKADDR_STORAGE_BYTES], 0));

    if let Some(accepted) = state.sockets.get_mut(accepted_h) {
        accepted.state = SocketLifeState::Connected;
        accepted.remote = client_slot;
        accepted.remote_epoch = client_epoch;
        accepted.local_addr = listener_addr;
        accepted.local_addr_len = listener_addr_len;
        accepted.peer_addr = client_addr.0;
        accepted.peer_addr_len = client_addr.1;
    }

    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.remote = accepted_slot;
        s.remote_epoch = accepted_epoch;
        s.state = SocketLifeState::Connected;
        s.peer_addr = listener_addr;
        s.peer_addr_len = listener_addr_len;
    }

    if let Err(e) = enqueue_unix_accept(state, listener_h, accepted_h) {
        if let Some(s) = state.sockets.get_mut(sock_h) {
            s.remote = u32::MAX;
            s.remote_epoch = 0;
            s.state = SocketLifeState::Initial;
            s.peer_addr_len = 0;
        }
        release_socket(state, accepted_h);
        return Err(e);
    }
    crate::personality::posix::socket_wait::wake_matching(
        state,
        listener_h,
        crate::personality::posix::socket_wait::SocketWaitKind::Accept,
    );
    Ok(())
}

fn unix_accept(
    state: &mut VfsState,
    listener_h: Handle<SocketState>,
    client: ClientHandle,
) -> Result<u32, VfsError> {
    let listener = state.sockets.get(listener_h).ok_or(VfsError::BadF)?;
    if !listener.is_unix()
        || !matches!(
            listener.state,
            crate::core::socket::SocketLifeState::Listening
        )
    {
        return Err(VfsError::Inval);
    }
    let head_slot = listener.accept_head;
    if head_slot == u32::MAX {
        return Err(VfsError::Again);
    }
    let accepted_h = state
        .sockets
        .handle_from_slot(head_slot)
        .ok_or(VfsError::Io)?;
    if state.sockets.get(accepted_h).is_none() {
        return Err(VfsError::Io);
    }

    let fd = install_socket_fd(state, client, accepted_h, false, false)?;
    let next = state
        .sockets
        .get(accepted_h)
        .map(|s| s.accept_next)
        .unwrap_or(u32::MAX);
    if let Some(listener) = state.sockets.get_mut(listener_h) {
        listener.accept_head = next;
        if next == u32::MAX {
            listener.accept_tail = u32::MAX;
        }
        listener.accept_count = listener.accept_count.saturating_sub(1);
    }
    if let Some(accepted) = state.sockets.get_mut(accepted_h) {
        accepted.accept_next = u32::MAX;
    }
    crate::personality::posix::socket_wait::wake_matching(
        state,
        accepted_h,
        crate::personality::posix::socket_wait::SocketWaitKind::Connect,
    );
    Ok(fd)
}

fn enqueue_unix_accept(
    state: &mut VfsState,
    listener_h: Handle<SocketState>,
    accepted_h: Handle<SocketState>,
) -> Result<(), VfsError> {
    let accepted_slot = accepted_h.slot();
    if let Some(accepted) = state.sockets.get_mut(accepted_h) {
        accepted.accept_next = u32::MAX;
    } else {
        return Err(VfsError::BadF);
    }

    let (tail_slot, backlog, queued) = state
        .sockets
        .get(listener_h)
        .map(|s| (s.accept_tail, s.listen_backlog, s.accept_count))
        .ok_or(VfsError::BadF)?;
    if backlog != 0 && queued >= backlog {
        return Err(VfsError::Busy);
    }
    if tail_slot != u32::MAX {
        let tail_h = state
            .sockets
            .handle_from_slot(tail_slot)
            .ok_or(VfsError::Io)?;
        if let Some(tail) = state.sockets.get_mut(tail_h) {
            tail.accept_next = accepted_slot;
        }
    }
    if let Some(listener) = state.sockets.get_mut(listener_h) {
        if listener.accept_head == u32::MAX {
            listener.accept_head = accepted_slot;
        }
        listener.accept_tail = accepted_slot;
        listener.accept_count = listener.accept_count.saturating_add(1);
    }
    Ok(())
}

fn drain_unix_accept_queue(state: &mut VfsState, listener_h: Handle<SocketState>) {
    let mut cur = state
        .sockets
        .get(listener_h)
        .map(|s| s.accept_head)
        .unwrap_or(u32::MAX);
    if let Some(listener) = state.sockets.get_mut(listener_h) {
        listener.accept_head = u32::MAX;
        listener.accept_tail = u32::MAX;
        listener.accept_count = 0;
    }
    while cur != u32::MAX {
        let Some(h) = state.sockets.handle_from_slot(cur) else {
            break;
        };
        let next = state
            .sockets
            .get(h)
            .map(|s| s.accept_next)
            .unwrap_or(u32::MAX);
        if let Some(s) = state.sockets.get_mut(h) {
            s.accept_next = u32::MAX;
            s.active = 0;
        }
        let _ = state.sockets.release(h);
        cur = next;
    }
}

fn unix_send_from_msg(
    state: &mut VfsState,
    client: ClientHandle,
    sock_h: Handle<SocketState>,
    msg: &TronaMsg,
    data_len: usize,
    flags: u32,
) -> Result<usize, VfsError> {
    let (target_h, data_base, data_len) = if (flags & VFS_SENDMSG_FLAG_LOCAL_ADDR) != 0 {
        let encoded_len = msg.regs[3];
        let addr_words = unix_addr_wire_words(encoded_len);
        let target = find_unix_bound_socket_from_wire(state, msg, encoded_len, 4)?;
        (target, 4 + addr_words, data_len)
    } else {
        let target = unix_remote_socket(state, sock_h)?;
        (target, 3, data_len)
    };

    if scm_rights_count(flags) != 0
        && state
            .sockets
            .get(target_h)
            .map(|s| s.rights_count != 0)
            .unwrap_or(true)
    {
        return Err(VfsError::Busy);
    }
    let (rights, rights_count) =
        collect_scm_rights(state, client, msg, data_base, data_len, flags)?;

    let copy_len = data_len.min((msg.regs.len().saturating_sub(data_base)) * 8);
    let src = if copy_len == 0 {
        ::core::ptr::null()
    } else {
        (&raw const msg.regs[data_base]) as *const u64 as *const u8
    };
    let written = match unsafe { unix_deliver_bytes(state, target_h, src, copy_len) } {
        Ok(w) => w,
        Err(e) => {
            rollback_scm_rights(state, &rights, rights_count);
            return Err(e);
        }
    };
    if written == 0 && data_len != 0 {
        rollback_scm_rights(state, &rights, rights_count);
        return Err(VfsError::Again);
    }
    store_scm_rights(state, target_h, &rights, rights_count);
    // Record the sender's bound address on the target so an
    // unconnected datagram receiver's recvfrom() can report the
    // datagram source. Only the addressed (sendto) form carries a
    // sender identity worth recording; connected receivers resolve
    // their fixed peer through the connection in unix_recv_to_reply.
    if (flags & VFS_SENDMSG_FLAG_LOCAL_ADDR) != 0 {
        if let Some((addr, len)) = state
            .sockets
            .get(sock_h)
            .map(|s| (s.local_addr, s.local_addr_len))
        {
            if let Some(target) = state.sockets.get_mut(target_h) {
                target.last_src_addr = addr;
                target.last_src_addr_len = len;
            }
        }
    }
    crate::personality::posix::socket_wait::wake_matching(
        state,
        target_h,
        crate::personality::posix::socket_wait::SocketWaitKind::Recv,
    );
    Ok(written)
}

/// Move `len` bytes from `src` into `target_h`'s receive ring. Shared
/// by `unix_send_from_msg` (sendmsg) and `unix_plain_write` (plain
/// `write()`); SCM-rights handling and the wake/reply stay with the
/// caller. Returns the number of bytes the ring accepted.
///
/// # Safety
/// `src` must point to at least `len` readable bytes (or be null when
/// `len == 0`).
unsafe fn unix_deliver_bytes(
    state: &mut VfsState,
    target_h: Handle<SocketState>,
    src: *const u8,
    len: usize,
) -> Result<usize, VfsError> {
    use crate::core::socket::SocketLifeState;
    let Some(target) = state.sockets.get_mut(target_h) else {
        return Err(VfsError::BadF);
    };
    if !matches!(
        target.state,
        SocketLifeState::Connected | SocketLifeState::Listening | SocketLifeState::Bound
    ) {
        return Err(VfsError::NotSup);
    }
    if target.rx.avail() == 0 {
        return Err(VfsError::Again);
    }
    Ok(unsafe { target.rx.write(src, len.min(u16::MAX as usize) as u16) as usize })
}

/// True when `fd` names a socket open object. Lets the POSIX read/write
/// handlers route plain `read()` / `write()` to the AF_UNIX ring path
/// instead of the vnode/vop path (sockets carry no vnode).
pub(crate) fn fd_is_socket(state: &VfsState, client: ClientHandle, fd: i32) -> bool {
    if fd < 0 {
        return false;
    }
    let Some(cli) = state.clients.get(client) else {
        return false;
    };
    let Some(oh) = cli.slot_table.lookup(fd as u32) else {
        return false;
    };
    state
        .open_objects
        .get(oh)
        .map(|o| o.kind == OpenObjectKind::Socket)
        .unwrap_or(false)
}

/// Plain `write()` on a socket fd. AF_UNIX delivers into the connected
/// peer's receive ring (the same ring `VFS_SEND` uses) and wakes blocked
/// readers. Inet sockets proxy through netsrv via `VFS_SEND` and are not
/// served by this inline path.
///
/// # Safety
/// `src` must reference `src.len()` readable bytes.
pub(crate) unsafe fn unix_plain_write(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    src: &[u8],
) -> Result<usize, VfsError> {
    let sock_h = resolve_socket_fd(state, client, fd)?;
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        return Err(VfsError::NotSup);
    }
    if src.is_empty() {
        return Ok(0);
    }
    let target_h = unix_remote_socket(state, sock_h)?;
    let written = unsafe { unix_deliver_bytes(state, target_h, src.as_ptr(), src.len())? };
    crate::personality::posix::socket_wait::wake_matching(
        state,
        target_h,
        crate::personality::posix::socket_wait::SocketWaitKind::Recv,
    );
    Ok(written)
}

/// Plain `read()` on a socket fd. AF_UNIX drains the local receive ring;
/// an empty ring returns EOF (`Ok(0)`) once the peer has closed / shut
/// down for read, otherwise `EAGAIN` (the library/wait layer blocks).
/// Inet sockets are served via `VFS_RECV`, not this inline path.
pub(crate) unsafe fn unix_plain_read(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    dst: &mut [u8],
) -> Result<usize, VfsError> {
    let sock_h = resolve_socket_fd(state, client, fd)?;
    let domain = state.sockets.get(sock_h).map(|s| s.domain).unwrap_or(0);
    if is_inet(domain) {
        return Err(VfsError::NotSup);
    }
    if dst.is_empty() {
        return Ok(0);
    }
    {
        let Some(sock) = state.sockets.get(sock_h) else {
            return Err(VfsError::BadF);
        };
        if sock.rx.len() == 0 {
            if sock.rx.closed != 0 || (sock.shutdown_flags & 0x1) != 0 {
                return Ok(0);
            }
            return Err(VfsError::Again);
        }
    }
    let n = {
        let Some(sock) = state.sockets.get_mut(sock_h) else {
            return Err(VfsError::BadF);
        };
        let cap = dst.len().min(u16::MAX as usize);
        unsafe { sock.rx.read(dst.as_mut_ptr(), cap as u16) as usize }
    };
    crate::personality::posix::socket_wait::wake_matching(
        state,
        sock_h,
        crate::personality::posix::socket_wait::SocketWaitKind::Send,
    );
    Ok(n)
}

fn unix_recv_to_reply(
    state: &mut VfsState,
    client: ClientHandle,
    sock_h: Handle<SocketState>,
    data_len: usize,
    flags: u32,
    reply_lease: trona_server::ReplyLease,
) -> Result<(), (VfsError, trona_server::ReplyLease)> {
    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;

    let want_addr = (flags & VFS_RECVMSG_FLAG_WANT_ADDR) != 0;
    let want_rights = (flags & VFS_RECVMSG_FLAG_WANT_RIGHTS) != 0;
    let path_base = if want_addr {
        if want_rights {
            out.regs[2] = 0;
            3usize
        } else {
            2usize
        }
    } else {
        out.regs[1] = 0;
        2usize
    };

    let path_words = if want_addr {
        let mut addr = [0u8; crate::core::socket::SOCKADDR_STORAGE_BYTES];
        let mut len = 0u32;
        // Connected receiver: the source is the fixed peer, resolved
        // through the connection.
        if let Ok(remote_h) = unix_remote_socket(state, sock_h) {
            if let Some(s) = state.sockets.get(remote_h) {
                addr = s.local_addr;
                len = s.local_addr_len;
            }
        }
        // Unconnected datagram receiver: report the source recorded
        // from the most recently delivered datagram (see
        // `unix_send_from_msg`).
        if len == 0 {
            if let Some(s) = state.sockets.get(sock_h) {
                if s.last_src_addr_len != 0 {
                    addr = s.last_src_addr;
                    len = s.last_src_addr_len;
                }
            }
        }
        pack_unix_addr_reply(&mut out, 1, path_base, &addr, len as usize)
    } else {
        0
    };

    let data_base = path_base + path_words;
    let max_inline = (out.regs.len().saturating_sub(data_base)) * 8;
    let copy_len = data_len.min(max_inline);
    let dst = if copy_len == 0 {
        ::core::ptr::null_mut()
    } else {
        (&raw mut out.regs[data_base]) as *mut u64 as *mut u8
    };

    if let Some(sock) = state.sockets.get(sock_h) {
        if sock.rx.len() == 0 {
            if sock.rx.closed != 0 || (sock.shutdown_flags & 0x1) != 0 {
                out.regs[0] = 0;
                out.length = data_base as u64;
                crate::owner::op::reply_send(reply_lease, &out);
                return Ok(());
            }
            return Err((VfsError::Again, reply_lease));
        }
    } else {
        return Err((VfsError::BadF, reply_lease));
    }

    let (pending_rights, pending_rights_count) = pending_scm_rights(state, sock_h);
    let installed_fds = if want_rights && pending_rights_count != 0 {
        match crate::personality::posix::scm_rights::install_received_object_handles(
            state,
            client,
            &pending_rights[..pending_rights_count],
        ) {
            Ok(fds) => Some(fds),
            Err(err) => return Err((err, reply_lease)),
        }
    } else {
        None
    };

    let read = {
        let Some(sock) = state.sockets.get_mut(sock_h) else {
            return Err((VfsError::BadF, reply_lease));
        };
        unsafe { sock.rx.read(dst, copy_len as u16) as usize }
    };

    if pending_rights_count != 0 {
        if want_rights {
            clear_scm_rights(state, sock_h);
        } else {
            drop_pending_scm_rights(state, sock_h);
        }
    }

    out.regs[0] = read as u64;
    let actual_fds = installed_fds
        .as_ref()
        .map(|fds| usize::try_from(fds.len()).unwrap_or(0))
        .unwrap_or(0);
    if want_rights || !want_addr {
        let fd_count_reg = if want_addr { 2 } else { 1 };
        out.regs[fd_count_reg] = actual_fds as u64;
    }
    let data_words = (read + 7) / 8;
    if let Some(fds) = installed_fds.as_ref() {
        let fd_dst = (&raw mut out.regs[data_base + data_words]) as *mut u64 as *mut i32;
        for (idx, fd) in fds.iter().enumerate() {
            unsafe {
                *fd_dst.add(idx) = *fd as i32;
            }
        }
    }
    let fd_words = ((actual_fds * ::core::mem::size_of::<i32>()) + 7) / 8;
    out.length = (data_base + data_words + fd_words) as u64;
    crate::owner::op::reply_send(reply_lease, &out);
    crate::personality::posix::socket_wait::wake_matching(
        state,
        sock_h,
        crate::personality::posix::socket_wait::SocketWaitKind::Send,
    );
    Ok(())
}

fn scm_rights_count(flags: u32) -> usize {
    usize::try_from(flags & 0x0F)
        .unwrap_or(0)
        .min(SCM_RIGHTS_MAX_FDS)
}

fn collect_scm_rights(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    data_base: usize,
    data_len: usize,
    flags: u32,
) -> Result<([OpenObjectHandle; SCM_RIGHTS_MAX_FDS], usize), VfsError> {
    let count = scm_rights_count(flags);
    let mut handles = [OpenObjectHandle::INVALID; SCM_RIGHTS_MAX_FDS];
    if count == 0 {
        return Ok((handles, 0));
    }
    let data_regs = (data_len + 7) / 8;
    let fd_base = data_base + data_regs;
    let fd_words = ((count * ::core::mem::size_of::<i32>()) + 7) / 8;
    if fd_base >= msg.regs.len() || fd_base + fd_words > msg.regs.len() {
        return Err(VfsError::Inval);
    }
    let fd_src = (&raw const msg.regs[fd_base]) as *const u64 as *const i32;
    for idx in 0..count {
        let fd = unsafe { *fd_src.add(idx) };
        if fd < 0 {
            rollback_scm_rights(state, &handles, idx);
            return Err(VfsError::BadF);
        }
        let handle = match {
            let Some(cli) = state.clients.get(client) else {
                rollback_scm_rights(state, &handles, idx);
                return Err(VfsError::BadF);
            };
            cli.slot_table.lookup(u32::try_from(fd).unwrap_or(u32::MAX))
        } {
            Some(handle) => handle,
            None => {
                rollback_scm_rights(state, &handles, idx);
                return Err(VfsError::BadF);
            }
        };
        crate::ops::dup::bump_open_object_refcount(state, handle);
        handles[idx] = handle;
    }
    Ok((handles, count))
}

fn rollback_scm_rights(
    state: &mut VfsState,
    handles: &[OpenObjectHandle; SCM_RIGHTS_MAX_FDS],
    count: usize,
) {
    for handle in handles.iter().take(count).copied() {
        if handle.is_valid() {
            crate::ops::dup::release_open_object(state, handle);
        }
    }
}

fn store_scm_rights(
    state: &mut VfsState,
    sock_h: Handle<SocketState>,
    handles: &[OpenObjectHandle; SCM_RIGHTS_MAX_FDS],
    count: usize,
) {
    if count == 0 {
        return;
    }
    if let Some(sock) = state.sockets.get_mut(sock_h) {
        for idx in 0..SCM_RIGHTS_MAX_FDS {
            let handle = handles
                .get(idx)
                .copied()
                .unwrap_or(OpenObjectHandle::INVALID);
            sock.rights_slots[idx] = handle.slot();
            sock.rights_epochs[idx] = handle.epoch();
        }
        sock.rights_count = u8::try_from(count).unwrap_or(0);
    } else {
        rollback_scm_rights(state, handles, count);
    }
}

fn pending_scm_rights(
    state: &VfsState,
    sock_h: Handle<SocketState>,
) -> ([OpenObjectHandle; SCM_RIGHTS_MAX_FDS], usize) {
    let mut handles = [OpenObjectHandle::INVALID; SCM_RIGHTS_MAX_FDS];
    let Some(sock) = state.sockets.get(sock_h) else {
        return (handles, 0);
    };
    let count = usize::from(sock.rights_count).min(SCM_RIGHTS_MAX_FDS);
    for idx in 0..count {
        handles[idx] = OpenObjectHandle::new(sock.rights_slots[idx], sock.rights_epochs[idx]);
    }
    (handles, count)
}

fn clear_scm_rights(state: &mut VfsState, sock_h: Handle<SocketState>) {
    if let Some(sock) = state.sockets.get_mut(sock_h) {
        sock.rights_slots = [u32::MAX; SCM_RIGHTS_MAX_FDS];
        sock.rights_epochs = [0; SCM_RIGHTS_MAX_FDS];
        sock.rights_count = 0;
    }
}

fn drop_pending_scm_rights(state: &mut VfsState, sock_h: Handle<SocketState>) {
    let (handles, count) = pending_scm_rights(state, sock_h);
    clear_scm_rights(state, sock_h);
    rollback_scm_rights(state, &handles, count);
}

fn unix_remote_socket(
    state: &VfsState,
    sock_h: Handle<SocketState>,
) -> Result<Handle<SocketState>, VfsError> {
    let sock = state.sockets.get(sock_h).ok_or(VfsError::BadF)?;
    if !matches!(sock.state, crate::core::socket::SocketLifeState::Connected) {
        return Err(VfsError::NotSup);
    }
    let remote_h = state
        .sockets
        .handle_from_slot(sock.remote)
        .ok_or(VfsError::BadF)?;
    if remote_h.epoch() != sock.remote_epoch {
        return Err(VfsError::BadF);
    }
    Ok(remote_h)
}

fn unix_addr_wire_words(encoded_len: u64) -> usize {
    let inline_len = if (encoded_len & (1 << 63)) != 0 {
        encoded_len & !(1 << 63)
    } else {
        encoded_len.saturating_add(1)
    };
    ((inline_len as usize) + 7) / 8
}

fn find_unix_bound_socket_from_wire(
    state: &VfsState,
    msg: &TronaMsg,
    encoded_len: u64,
    src_reg: usize,
) -> Result<Handle<SocketState>, VfsError> {
    // Build the lookup key the same way bind stores local_addr (abstract names
    // carry a reconstructed leading NUL), so the byte comparison below matches.
    let addr = decode_unix_wire_addr(msg, src_reg, encoded_len);
    let mut found = None;
    state.sockets.for_each_active(|h, s| {
        if !s.is_unix() {
            return true;
        }
        if matches!(
            s.state,
            crate::core::socket::SocketLifeState::Bound
                | crate::core::socket::SocketLifeState::Listening
                | crate::core::socket::SocketLifeState::Connected
        ) {
            let mut eq = true;
            for i in 0..32usize {
                if s.local_addr[i] != addr[i] {
                    eq = false;
                    break;
                }
            }
            if eq {
                found = Some(h);
                return false;
            }
        }
        true
    });
    found.ok_or(VfsError::NoEnt)
}

fn pack_unix_addr_reply(
    out: &mut TronaMsg,
    len_reg: usize,
    data_reg: usize,
    addr: &[u8; crate::core::socket::SOCKADDR_STORAGE_BYTES],
    addr_len: usize,
) -> usize {
    let mut end = addr_len.min(addr.len());
    while end > 0 && addr[end - 1] == 0 {
        end -= 1;
    }
    // Abstract addresses carry a leading NUL marker (Linux convention); report
    // the name after it with the abstract flag (bit 63) so the client
    // reconstructs sun_path[0] == 0. Pathname addresses are reported verbatim.
    let (name_start, name_len, encoded_len, is_abstract) = if end >= 1 && addr[0] == 0 {
        let nl = end - 1;
        (1usize, nl, (1u64 << 63) | nl as u64, true)
    } else {
        (0usize, end, end as u64, false)
    };
    out.regs[len_reg] = encoded_len;
    // Match the client's `unix_addr_wire_len` contract: abstract addresses carry
    // exactly `name_len` inline bytes (no terminator); pathname addresses append
    // a NUL. Over-reporting the word count for abstract names would shift the
    // following payload regs and corrupt the datagram.
    let inline_len = if is_abstract { name_len } else { name_len + 1 };
    let words = (inline_len + 7) / 8;
    if words != 0 {
        let dst = (&raw mut out.regs[data_reg]) as *mut u64 as *mut u8;
        for i in 0..name_len {
            unsafe {
                *dst.add(i) = addr[name_start + i];
            }
        }
        if !is_abstract {
            unsafe {
                *dst.add(name_len) = 0;
            }
        }
    }
    words
}

fn emit_unix_name(
    state: &VfsState,
    sock_h: Handle<SocketState>,
    local: bool,
    reply_lease: trona_server::ReplyLease,
) {
    let Some(s) = state.sockets.get(sock_h) else {
        return crate::personality::wire::send_error_reply(reply_lease, VfsError::BadF);
    };
    let (src, len) = if local {
        (&s.local_addr, s.local_addr_len as usize)
    } else {
        (&s.peer_addr, s.peer_addr_len as usize)
    };
    let mut out = [0u64; 6];
    out[0] = AF_UNIX as u64;
    out[1] = len.min(32) as u64;
    let dst = (&raw mut out[2]) as *mut u8;
    let mut i = 0usize;
    while i < len.min(32) {
        unsafe {
            *dst.add(i) = src[i];
        }
        i += 1;
    }
    crate::personality::wire::send_ok_reply(reply_lease, &out);
}
