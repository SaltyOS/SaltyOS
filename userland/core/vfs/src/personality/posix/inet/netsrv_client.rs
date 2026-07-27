// SPDX-License-Identifier: GPL-2.0-only
//
//! INET socket issue side for the netsrv backend session.
//!
//! `NET_*` remains the canonical socket ABI owned by
//! `trona_protocol::netsrv`. VFS reaches it through the same
//! `BackendSessionSlot` contract as saltyfs / pty / fb: session
//! attach negotiates the callback endpoint, async operations stamp
//! the shared correlation header, and completions return through
//! `owner::net_completion`.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::{
    TRONA_ALREADY_EXISTS, TRONA_BUSY, TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION,
    TRONA_NOT_FOUND, TRONA_NOT_SUPPORTED, TRONA_OK, TRONA_OUT_OF_MEMORY, TRONA_PENDING,
    TRONA_TIMED_OUT, TRONA_WOULD_BLOCK,
};
use trona_protocol::netsrv::{
    NET_ACCEPT_WAIT, NET_BIND, NET_CLOSE, NET_CONNECT, NET_GETPEERNAME, NET_GETSOCKNAME,
    NET_GETSOCKOPT, NET_LISTEN, NET_POLL_STATUS, NET_RECV_WAIT, NET_RECVFROM_WAIT, NET_SEND,
    NET_SENDTO, NET_SETSOCKOPT, NET_SHUTDOWN, NET_SOCKET,
};
use trona_protocol::posix::{
    INET_RECV_FLAG_PEEK, INET_RECV_FLAG_WANT_ADDR, INET_RECV_FLAG_WANT_TIMESTAMP,
    TRONA_ADDR_IN_USE, TRONA_ALREADY_BOUND, TRONA_CONN_REFUSED, TRONA_CONN_RESET,
    TRONA_HOST_UNREACHABLE, TRONA_NET_UNREACHABLE, TRONA_NO_BUFS, TRONA_NO_SPACE,
    TRONA_NOT_CONNECTED, TRONA_PROTO_NOT_SUPPORTED, TRONA_SERVER_DIED, TRONA_STALE,
};
use trona_protocol::posix_abi::socket::AF_INET;
use trona_protocol::vfs::public::{
    VFS_RECVMSG_FLAG_WANT_ADDR, VFS_SENDMSG_FLAG_INET_ADDR, VFS_SENDMSG_FLAG_LOCAL_ADDR,
};

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::socket::{
    NETRESUME_OP_ACCEPT, NETRESUME_OP_BIND, NETRESUME_OP_CONNECT, NETRESUME_OP_LISTEN,
    NETRESUME_OP_RECV, NETRESUME_OP_SEND, NETRESUME_OP_SHUTDOWN, SocketLifeState, SocketState,
};
use crate::ipc::protocol::correlation::{
    CORRELATION_BACKEND_NETSRV, CORRELATION_CLASS_NET, CORRELATION_HEADER_REG_START,
    CORRELATION_KIND_REQUEST, CorrelationHeader, ensure_correlation_wire_length,
};
use crate::owner::VfsState;
use crate::owner::resume::{NetResume, Resume};
use crate::owner::session::BackendSessionHandle;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

const MAX_SEND_INLINE: usize = 144;
const MAX_SENDTO_INLINE: usize = 128;

pub(crate) fn create_socket(
    state: &mut VfsState,
    sock_type: u16,
    protocol: u32,
) -> Result<(u32, u32), VfsError> {
    let (cap, _session_id, live_gen) = session_wire(state)?;
    let mut req = TronaMsg::default();
    req.label = NET_SOCKET;
    req.regs[0] = sock_type as u64;
    req.regs[1] = protocol as u64;
    req.length = 2;

    let reply = call_session(cap, &req)?;
    status_to_vfs(reply.label)?;
    let conn_id = u32::try_from(reply.regs[0]).map_err(|_| VfsError::Io)?;
    Ok((conn_id, live_gen))
}

pub(crate) fn close_conn(state: &mut VfsState, conn_id: u32) {
    if conn_id == u32::MAX {
        return;
    }
    let Ok((cap, _, _)) = session_wire(state) else {
        return;
    };
    let mut req = TronaMsg::default();
    req.label = NET_CLOSE;
    req.regs[0] = conn_id as u64;
    req.length = 1;
    let _ = call_session(cap, &req);
}

pub(crate) fn poll_status(
    state: &mut VfsState,
    conn_id: u32,
    events: u16,
) -> Result<u16, VfsError> {
    let reply = call_conn_option(state, NET_POLL_STATUS, conn_id, &[events as u64])?;
    status_to_vfs(reply.label)?;
    Ok(reply.regs[0] as u16)
}

pub(crate) fn handle_bind(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let (ip, port) = match decode_inet_addr(msg) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };

    let mut req = TronaMsg::default();
    req.label = NET_BIND;
    req.regs[0] = conn_id as u64;
    req.regs[1] = ip as u64;
    req.regs[2] = port as u64;
    req.length = 3;
    issue_request(
        state,
        client,
        sock_h,
        conn_id,
        NETRESUME_OP_BIND,
        req,
        reply_lease,
    );
}

pub(crate) fn handle_listen(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let backlog = msg.regs[1] as u32;

    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.listen_backlog = backlog;
    }

    let mut req = TronaMsg::default();
    req.label = NET_LISTEN;
    req.regs[0] = conn_id as u64;
    req.regs[1] = backlog as u64;
    req.length = 2;
    issue_request(
        state,
        client,
        sock_h,
        conn_id,
        NETRESUME_OP_LISTEN,
        req,
        reply_lease,
    );
}

pub(crate) fn handle_accept(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };

    let mut req = TronaMsg::default();
    req.label = NET_ACCEPT_WAIT;
    req.regs[0] = conn_id as u64;
    req.length = 1;
    issue_request(
        state,
        client,
        sock_h,
        conn_id,
        NETRESUME_OP_ACCEPT,
        req,
        reply_lease,
    );
}

pub(crate) fn handle_connect(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let (ip, port) = match decode_inet_addr(msg) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };

    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.state = SocketLifeState::Connecting;
        store_sockaddr_in(&mut s.peer_addr, &mut s.peer_addr_len, ip, port);
    }

    let mut req = TronaMsg::default();
    req.label = NET_CONNECT;
    req.regs[0] = conn_id as u64;
    req.regs[1] = ip as u64;
    req.regs[2] = port as u64;
    req.length = 3;
    issue_request(
        state,
        client,
        sock_h,
        conn_id,
        NETRESUME_OP_CONNECT,
        req,
        reply_lease,
    );
}

pub(crate) fn handle_send(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let data_len = msg.regs[1] as usize;
    let wire_flags = msg.regs[2] as u32;
    if (wire_flags & VFS_SENDMSG_FLAG_LOCAL_ADDR) != 0 {
        send_reply_err_for_client(state, client, reply_lease, VfsError::NotSup);
        return;
    }

    let mut req = TronaMsg::default();
    if (wire_flags & VFS_SENDMSG_FLAG_INET_ADDR) != 0 {
        let actual = data_len.min(MAX_SENDTO_INLINE);
        req.label = NET_SENDTO;
        req.regs[0] = conn_id as u64;
        req.regs[1] = msg.regs[3];
        req.regs[2] = msg.regs[4];
        req.regs[3] = actual as u64;
        copy_msg_bytes(msg, 5, &mut req, 4, actual);
        req.length = 4 + words_for_bytes(actual);
    } else {
        let actual = data_len.min(MAX_SEND_INLINE);
        req.label = NET_SEND;
        req.regs[0] = conn_id as u64;
        req.regs[1] = actual as u64;
        copy_msg_bytes(msg, 3, &mut req, 2, actual);
        req.length = 2 + words_for_bytes(actual);
    }

    issue_request(
        state,
        client,
        sock_h,
        conn_id,
        NETRESUME_OP_SEND,
        req,
        reply_lease,
    );
}

pub(crate) fn handle_recv(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let max_len = msg.regs[1] as u16;
    let flags = msg.regs[2] as u32;
    let want_addr =
        (flags & VFS_RECVMSG_FLAG_WANT_ADDR) != 0 || (flags & INET_RECV_FLAG_WANT_ADDR) != 0;
    let mut netsrv_flags = flags & (INET_RECV_FLAG_PEEK | INET_RECV_FLAG_WANT_TIMESTAMP);
    if want_addr {
        netsrv_flags |= INET_RECV_FLAG_WANT_ADDR;
    }

    let mut req = TronaMsg::default();
    req.label = if want_addr {
        NET_RECVFROM_WAIT
    } else {
        NET_RECV_WAIT
    };
    req.regs[0] = conn_id as u64;
    req.regs[1] = max_len as u64;
    req.regs[2] = netsrv_flags as u64;
    req.length = 3;

    issue_request(
        state,
        client,
        sock_h,
        conn_id,
        NETRESUME_OP_RECV,
        req,
        reply_lease,
    );
}

pub(crate) fn handle_shutdown(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let how = msg.regs[1] as u32;

    let mut req = TronaMsg::default();
    req.label = NET_SHUTDOWN;
    req.regs[0] = conn_id as u64;
    req.regs[1] = how as u64;
    req.length = 2;
    issue_request(
        state,
        client,
        sock_h,
        conn_id,
        NETRESUME_OP_SHUTDOWN,
        req,
        reply_lease,
    );
}

pub(crate) fn handle_getsockname(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    handle_name_query(state, client, msg, reply_lease, NET_GETSOCKNAME, true);
}

pub(crate) fn handle_getpeername(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    handle_name_query(state, client, msg, reply_lease, NET_GETPEERNAME, false);
}

pub(crate) fn handle_setsockopt(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (_sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let reply = call_conn_option(state, NET_SETSOCKOPT, conn_id, &msg.regs[1..5]);
    match reply.and_then(|r| status_to_vfs(r.label)) {
        Ok(()) => send_reply_ok_for_client(state, client, reply_lease, &[]),
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
}

pub(crate) fn handle_getsockopt(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (_sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let reply = call_conn_option(state, NET_GETSOCKOPT, conn_id, &msg.regs[1..3]);
    match reply.and_then(|r| {
        status_to_vfs(r.label)?;
        Ok([r.regs[0], r.regs[1]])
    }) {
        Ok(words) => send_reply_ok_for_client(state, client, reply_lease, &words),
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
}

fn issue_request(
    state: &mut VfsState,
    client: ClientHandle,
    sock_h: Handle<SocketState>,
    conn_id: u32,
    op_type: u8,
    mut req: TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (session, send_cap, session_id, live_gen, request_seq) =
        match async_session_issue_parts(state) {
            Ok(v) => v,
            Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
        };
    if !state.backend_credit_reserve_for_session(session) {
        return send_reply_err_for_client(state, client, reply_lease, VfsError::Busy);
    }

    let Some((handle, tx_id)) = state.reserve_pending_for_net(session, sock_h) else {
        state.backend_credit_release_for_session(session);
        return send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
    };

    let opcode = req.label;
    stamp_netsrv_async_request(&mut req, session_id, opcode, tx_id.raw(), request_seq);
    let send_err = unsafe { trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &req) };
    if send_err != 0 {
        let _ = state.pending_ops.release(handle);
        state.backend_credit_release_for_session(session);
        return send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
    }

    let resume = Resume::Net(NetResume {
        conn_id,
        netsrv_gen: live_gen as u32,
        op_type,
    });
    if let Err(lease) =
        state.stamp_resume_ctx(handle, reply_lease.epoch(), Some(reply_lease), resume)
    {
        let _ = state.pending_ops.release(handle);
        state.backend_credit_release_for_session(session);
        if let Some(l) = lease {
            send_reply_err_for_client(state, client, l, VfsError::Io);
        }
    }
}

fn handle_name_query(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
    label: u64,
    local: bool,
) {
    let (sock_h, conn_id) = match resolve_conn(state, client, msg.regs[0] as i32) {
        Ok(v) => v,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let reply = call_conn_option(state, label, conn_id, &[]);
    match reply.and_then(|r| {
        status_to_vfs(r.label)?;
        Ok([r.regs[0], r.regs[1]])
    }) {
        Ok(words) => {
            if let Some(s) = state.sockets.get_mut(sock_h) {
                if local {
                    store_sockaddr_in(
                        &mut s.local_addr,
                        &mut s.local_addr_len,
                        words[0] as u32,
                        words[1] as u16,
                    );
                } else {
                    store_sockaddr_in(
                        &mut s.peer_addr,
                        &mut s.peer_addr_len,
                        words[0] as u32,
                        words[1] as u16,
                    );
                }
            }
            send_reply_ok_for_client(state, client, reply_lease, &words);
        }
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
}

fn call_conn_option(
    state: &mut VfsState,
    label: u64,
    conn_id: u32,
    args: &[u64],
) -> Result<TronaMsg, VfsError> {
    let (cap, _, _) = session_wire(state)?;
    let mut req = TronaMsg::default();
    req.label = label;
    req.regs[0] = conn_id as u64;
    let mut i = 0usize;
    while i < args.len() && (i + 1) < req.regs.len() {
        req.regs[i + 1] = args[i];
        i += 1;
    }
    req.length = (1 + i) as u64;
    call_session(cap, &req)
}

fn resolve_conn(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<(Handle<SocketState>, u32), VfsError> {
    let sock_h = crate::personality::posix::socket::resolve_socket_fd(state, client, fd)?;
    let s = state.sockets.get(sock_h).ok_or(VfsError::BadF)?;
    if !s.is_inet() || s.conn_id == u32::MAX {
        return Err(VfsError::NotSup);
    }
    Ok((sock_h, s.conn_id))
}

fn session_issue_parts(
    state: &mut VfsState,
) -> Result<(BackendSessionHandle, u64, u32, u32), VfsError> {
    let session = crate::owner::session::default_inet_session(state)?;
    let slot = state
        .backend_sessions
        .get(session)
        .ok_or(VfsError::SessionTornDown)?;
    if slot.send_cap.as_raw() == 0 || slot.is_empty() {
        return Err(VfsError::SessionTornDown);
    }
    Ok((
        session,
        slot.send_cap.as_raw(),
        slot.session_id,
        slot.live_gen,
    ))
}

fn async_session_issue_parts(
    state: &mut VfsState,
) -> Result<(BackendSessionHandle, u64, u32, u32, u32), VfsError> {
    let session = crate::owner::session::default_inet_session(state)?;
    let slot = state
        .backend_sessions
        .get_mut(session)
        .ok_or(VfsError::SessionTornDown)?;
    if slot.send_cap.as_raw() == 0 || slot.is_empty() {
        return Err(VfsError::SessionTornDown);
    }
    let request_seq = slot.alloc_target_seq();
    Ok((
        session,
        slot.send_cap.as_raw(),
        slot.session_id,
        slot.live_gen,
        request_seq,
    ))
}

fn session_wire(state: &mut VfsState) -> Result<(u64, u32, u32), VfsError> {
    let (_, cap, session_id, live_gen) = session_issue_parts(state)?;
    Ok((cap, session_id, live_gen))
}

fn call_session(cap: u64, req: &TronaMsg) -> Result<TronaMsg, VfsError> {
    if cap == 0 {
        return Err(VfsError::SessionTornDown);
    }
    let mut reply = TronaMsg::default();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            crate::ipc_ctx(),
            cap,
            req as *const _,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(VfsError::Io);
    }
    Ok(reply)
}

fn stamp_netsrv_async_request(
    req: &mut TronaMsg,
    session_id: u32,
    opcode: u64,
    tx_id: u64,
    request_seq: u32,
) {
    let words = CorrelationHeader {
        class: CORRELATION_CLASS_NET,
        backend: CORRELATION_BACKEND_NETSRV,
        kind: CORRELATION_KIND_REQUEST,
        flags: 0,
        session: session_id,
        opcode: opcode as u16,
        _reserved0: 0,
        token: tx_id,
        request_seq,
        request_seq_secondary: 0,
    }
    .encode_words();
    req.regs[CORRELATION_HEADER_REG_START] = words[0];
    req.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    req.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    req.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    ensure_correlation_wire_length(&mut req.length);
}

fn decode_inet_addr(msg: &TronaMsg) -> Result<(u32, u16), VfsError> {
    if msg.length < 4 || msg.regs[1] != AF_INET as u64 {
        return Err(VfsError::NotSup);
    }
    Ok((msg.regs[2] as u32, msg.regs[3] as u16))
}

fn status_to_vfs(label: u64) -> Result<(), VfsError> {
    match label {
        TRONA_OK => Ok(()),
        TRONA_PENDING | TRONA_WOULD_BLOCK => Err(VfsError::Again),
        TRONA_INVALID_ARGUMENT => Err(VfsError::Inval),
        TRONA_INVALID_OPERATION | TRONA_NOT_SUPPORTED | TRONA_PROTO_NOT_SUPPORTED => {
            Err(VfsError::NotSup)
        }
        TRONA_OUT_OF_MEMORY | TRONA_NO_BUFS | TRONA_NO_SPACE => Err(VfsError::NoMem),
        TRONA_NOT_FOUND | TRONA_NOT_CONNECTED => Err(VfsError::NoEnt),
        TRONA_BUSY | TRONA_ALREADY_EXISTS | TRONA_ADDR_IN_USE | TRONA_ALREADY_BOUND => {
            Err(VfsError::Busy)
        }
        TRONA_TIMED_OUT => Err(VfsError::TimedOut),
        TRONA_SERVER_DIED => Err(VfsError::SessionTornDown),
        TRONA_STALE => Err(VfsError::StaleIncarnation),
        TRONA_CONN_REFUSED | TRONA_CONN_RESET | TRONA_HOST_UNREACHABLE | TRONA_NET_UNREACHABLE => {
            Err(VfsError::Io)
        }
        _ => Err(VfsError::Io),
    }
}

fn copy_msg_bytes(
    src: &TronaMsg,
    src_word: usize,
    dst: &mut TronaMsg,
    dst_word: usize,
    len: usize,
) {
    let src_ptr = (&raw const src.regs[src_word]) as *const u8;
    let dst_ptr = (&raw mut dst.regs[dst_word]) as *mut u8;
    let mut i = 0usize;
    while i < len {
        unsafe {
            *dst_ptr.add(i) = *src_ptr.add(i);
        }
        i += 1;
    }
}

#[inline]
fn words_for_bytes(len: usize) -> u64 {
    ((len + 7) / 8) as u64
}

fn store_sockaddr_in(dst: &mut [u8], len: &mut u32, ip: u32, port: u16) {
    if dst.len() < 8 {
        return;
    }
    dst[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    dst[2..4].copy_from_slice(&port.to_be_bytes());
    dst[4..8].copy_from_slice(&ip.to_be_bytes());
    *len = 8;
}
