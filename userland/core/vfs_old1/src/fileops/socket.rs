// SPDX-License-Identifier: GPL-2.0-only
//! Socket operations.
//!
//! AF_INET sockets are proxied synchronously to `netsrv`. AF_UNIX
//! sockets stay entirely inside the owner as local ring-buffer-backed
//! endpoints so the new VFS stays callback-free.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::server::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::fileops::inet_wait::{arm_or_cancel_head, defer_inet_op};
use crate::fileops::socket_wait::{
    DeferContext, INLINE_SEND_MAX, TryOutcome, UNIX_OP_ACCEPT, UNIX_OP_CONNECT_STREAM,
    UNIX_OP_DGRAM_READ, UNIX_OP_DGRAM_SEND, UNIX_OP_RECVMSG_DGRAM, UNIX_OP_RECVMSG_STREAM,
    UNIX_OP_SENDMSG_STREAM, UNIX_OP_STREAM_READ, UNIX_OP_STREAM_WRITE, defer_unix_socket_op,
};
use crate::owner::VfsState;
use crate::server::client::{MAX_PATH_LEN, extract_path, normalize_path_owned};
use crate::server::open_file::OpenFile;
use crate::server::types::{ClientHandle, OBJ_SOCKET};
use crate::server::unix_socket_object::{
    UNIX_DGRAM_MAX_PAYLOAD, UNIX_DGRAM_QUEUE_CAP, UNIX_SOCKET_ACCEPT_CAP, UNIX_SOCKET_ADDR_MAX,
    UNIX_SOCKET_MAX_RIGHTS, UnixSocketHandle,
};

const INLINE_SENDTO_MAX: usize = 120;
const INLINE_RECV_MAX: usize = 152;
const POSIX_MSG_PEEK: i32 = 0x02;
const SOCK_SEQPACKET: i32 = 5;
const UNIX_ADDR_ABSTRACT_FLAG: u64 = 1 << 63;
const VFS_SENDMSG_FLAG_LOCAL_ADDR: i32 = 1 << 31;
const VFS_RECVMSG_FLAG_WANT_ADDR: i32 = 1 << 29;
const VFS_RECVMSG_FLAG_WANT_RIGHTS: i32 = 1 << 30;

enum LocalSocketAddrKind {
    Path(usize),
    Abstract(usize),
}

#[inline]
fn local_addr_wire_len(encoded_len: u64) -> (usize, bool) {
    let is_abstract = (encoded_len & UNIX_ADDR_ABSTRACT_FLAG) != 0;
    (
        (encoded_len & !UNIX_ADDR_ABSTRACT_FLAG) as usize,
        is_abstract,
    )
}

#[inline]
fn local_addr_payload_regs(encoded_len: u64) -> u64 {
    let (path_len, is_abstract) = local_addr_wire_len(encoded_len);
    if is_abstract {
        ((path_len as u64) + 7) / 8
    } else {
        (((path_len + 1) as u64) + 7) / 8
    }
}

fn inet_socket_fd_view(
    state: &VfsState,
    cli_handle: ClientHandle,
    fd: usize,
) -> Option<(u32, u32)> {
    let of = state.client_open_file(cli_handle, fd)?;
    if of.kind != OBJ_SOCKET || of.socket_conn_id == 0 {
        return None;
    }
    Some((of.socket_conn_id, of.status_flags))
}

fn socket_conn_id(state: &VfsState, cli_handle: ClientHandle, fd: usize) -> Option<u32> {
    inet_socket_fd_view(state, cli_handle, fd).map(|(conn_id, _)| conn_id)
}

fn socket_nonblocking(state: &VfsState, cli_handle: ClientHandle, fd: usize) -> bool {
    inet_socket_fd_view(state, cli_handle, fd)
        .map(|(_, flags)| (flags & O_NONBLOCK) != 0)
        .unwrap_or(false)
}

fn local_socket_fd_view(
    state: &VfsState,
    cli_handle: ClientHandle,
    fd: usize,
) -> Option<(UnixSocketHandle, u32)> {
    let of = state.client_open_file(cli_handle, fd)?;
    if of.kind != OBJ_SOCKET || !of.unix_socket.is_valid() {
        return None;
    }
    Some((of.unix_socket, of.status_flags))
}

fn local_socket_bound_handle(
    state: &VfsState,
    path_vnode: crate::vfs_core::vnode::VnodeHandle,
) -> Option<UnixSocketHandle> {
    let mut found = UnixSocketHandle::INVALID;
    state.unix_sockets.for_each_active(|handle, socket| {
        if socket.bound_vnode == path_vnode {
            found = handle;
            return false;
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

fn local_socket_bound_handle_abstract(state: &VfsState, name: &[u8]) -> Option<UnixSocketHandle> {
    let mut found = UnixSocketHandle::INVALID;
    state.unix_sockets.for_each_active(|handle, socket| {
        if socket.bound_abstract_len as usize == name.len()
            && socket.bound_abstract_name[..name.len()] == name[..]
        {
            found = handle;
            return false;
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

fn local_listener_bound_handle_typed(
    state: &VfsState,
    path_vnode: crate::vfs_core::vnode::VnodeHandle,
    socket_type: i32,
) -> Option<UnixSocketHandle> {
    let mut found = UnixSocketHandle::INVALID;
    state.unix_sockets.for_each_active(|handle, socket| {
        if socket.bound_vnode == path_vnode
            && socket.listener != 0
            && socket.socket_type as i32 == socket_type
        {
            found = handle;
            return false;
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

fn local_listener_bound_handle_abstract_typed(
    state: &VfsState,
    name: &[u8],
    socket_type: i32,
) -> Option<UnixSocketHandle> {
    let mut found = UnixSocketHandle::INVALID;
    state.unix_sockets.for_each_active(|handle, socket| {
        if socket.bound_abstract_len as usize == name.len()
            && socket.bound_abstract_name[..name.len()] == name[..]
            && socket.listener != 0
            && socket.socket_type as i32 == socket_type
        {
            found = handle;
            return false;
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

#[inline]
fn local_socket_type(state: &VfsState, socket: UnixSocketHandle) -> i32 {
    state
        .unix_socket_state(socket)
        .map(|sock| sock.socket_type as i32)
        .unwrap_or(0)
}

#[inline]
fn local_socket_is_packet_type(socket_type: i32) -> bool {
    socket_type == SOCK_DGRAM || socket_type == SOCK_SEQPACKET
}

#[inline]
fn local_socket_is_connection_oriented(socket_type: i32) -> bool {
    socket_type == SOCK_STREAM || socket_type == SOCK_SEQPACKET
}

unsafe fn extract_local_addr_from_msg(
    msg: *const TronaMsg,
    len_reg: usize,
    bytes_reg: usize,
    raw_path: &mut [u8; MAX_PATH_LEN],
    abstract_name: &mut [u8; UNIX_SOCKET_ADDR_MAX],
) -> Option<LocalSocketAddrKind> {
    unsafe {
        let (name_len, is_abstract) = local_addr_wire_len((*msg).regs[len_reg]);
        if is_abstract {
            if name_len > abstract_name.len() {
                return None;
            }
            if name_len != 0 {
                let src = &(*msg).regs[bytes_reg] as *const u64 as *const u8;
                core::ptr::copy_nonoverlapping(src, abstract_name.as_mut_ptr(), name_len);
            }
            Some(LocalSocketAddrKind::Abstract(name_len))
        } else {
            let copied = extract_path(msg, len_reg, raw_path.as_mut_ptr()) as usize;
            Some(LocalSocketAddrKind::Path(copied))
        }
    }
}

fn fill_local_sockaddr_reply(
    state: &VfsState,
    vnode: crate::vfs_core::vnode::VnodeHandle,
    path_len: usize,
    path: &[u8; UNIX_SOCKET_ADDR_MAX],
    abstract_len: usize,
    abstract_name: &[u8; UNIX_SOCKET_ADDR_MAX],
    reply: *mut TronaMsg,
) {
    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = AF_UNIX as u64;
        let abstract_len = core::cmp::min(abstract_len, abstract_name.len());
        if abstract_len != 0 {
            (*reply).regs[1] = UNIX_ADDR_ABSTRACT_FLAG | abstract_len as u64;
            let dst = &raw mut (*reply).regs[2] as *mut u8;
            core::ptr::copy_nonoverlapping(abstract_name.as_ptr(), dst, abstract_len);
            (*reply).length = 2 + (((abstract_len as u64) + 7) / 8);
            return;
        }
        let path_len = core::cmp::min(path_len, path.len());
        if path_len != 0 {
            (*reply).regs[1] = path_len as u64;
            let dst = &raw mut (*reply).regs[2] as *mut u8;
            core::ptr::copy_nonoverlapping(path.as_ptr(), dst, path_len);
            *dst.add(path_len) = 0;
            (*reply).length = 2 + (((path_len + 1) as u64 + 7) / 8);
            return;
        }
        if !vnode.is_valid() {
            (*reply).regs[1] = 0;
            (*reply).regs[2] = 0;
            (*reply).length = 3;
            return;
        }

        let mut path = [0u8; MAX_PATH_LEN];
        let Some(anchor) = state.anchor_for_vnode(vnode) else {
            (*reply).regs[1] = 0;
            (*reply).regs[2] = 0;
            (*reply).length = 3;
            return;
        };
        let Some(path_len) = state.render_anchor_path(anchor, &mut path) else {
            (*reply).regs[1] = 0;
            (*reply).regs[2] = 0;
            (*reply).length = 3;
            return;
        };
        (*reply).regs[1] = path_len as u64;
        let dst = &raw mut (*reply).regs[2] as *mut u8;
        core::ptr::copy_nonoverlapping(path.as_ptr(), dst, path_len);
        *dst.add(path_len) = 0;
        (*reply).length = 2 + (((path_len + 1) as u64 + 7) / 8);
    }
}

fn netsrv_call(req: *const TronaMsg, reply: *mut TronaMsg) -> i32 {
    unsafe { ipc::call_ctx(crate::ipc_ctx(), crate::netsrv_ep(), req, reply) }
}

fn socket_so_error(conn_id: u32) -> u64 {
    let mut req = TronaMsg::zeroed();
    let mut resp = TronaMsg::zeroed();
    req.label = NET_GETSOCKOPT;
    req.length = 3;
    req.regs[0] = conn_id as u64;
    req.regs[1] = SOL_SOCKET as u64;
    req.regs[2] = SO_ERROR as u64;
    let err = netsrv_call(&raw const req, &raw mut resp);
    if err != 0 || resp.label != TRONA_OK {
        TRONA_INVALID_OPERATION
    } else if resp.regs[0] == 0 {
        TRONA_OK
    } else {
        resp.regs[0]
    }
}

fn send_ok_or_error(reply: *mut TronaMsg, resp: &TronaMsg) {
    unsafe {
        (*reply).label = resp.label;
        if resp.label == TRONA_OK {
            (*reply).length = 1;
            (*reply).regs[0] = resp.regs[0];
        } else {
            (*reply).length = 0;
        }
    }
}

fn fill_recv_reply(reply: *mut TronaMsg, resp: &TronaMsg) {
    unsafe {
        let data_len = core::cmp::min(resp.regs[0] as usize, INLINE_RECV_MAX);
        (*reply).label = resp.label;
        if resp.label != TRONA_OK {
            (*reply).length = 0;
            return;
        }
        (*reply).regs[0] = data_len as u64;
        if data_len != 0 {
            let src = &raw const resp.regs[1] as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, data_len);
        }
        (*reply).length = 1 + ((data_len as u64 + 7) / 8);
    }
}

fn fill_recvfrom_reply(reply: *mut TronaMsg, resp: &TronaMsg) {
    unsafe {
        let data_len = core::cmp::min(resp.regs[0] as usize, INLINE_RECV_MAX);
        (*reply).label = resp.label;
        if resp.label != TRONA_OK {
            (*reply).length = 0;
            return;
        }
        (*reply).regs[0] = data_len as u64;
        (*reply).regs[1] = resp.regs[1];
        (*reply).regs[2] = resp.regs[2];
        (*reply).regs[3] = resp.regs[3];
        if data_len != 0 {
            let src = &raw const resp.regs[4] as *const u8;
            let dst = &raw mut (*reply).regs[4] as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, data_len);
        }
        (*reply).length = 4 + ((data_len as u64 + 7) / 8);
    }
}

fn local_dgram_front_meta(
    state: &VfsState,
    socket: UnixSocketHandle,
) -> Option<(
    usize,
    crate::vfs_core::vnode::VnodeHandle,
    [u8; UNIX_SOCKET_ADDR_MAX],
    usize,
    [u8; UNIX_SOCKET_ADDR_MAX],
    usize,
    [crate::server::open_file::OpenFileHandle; UNIX_SOCKET_MAX_RIGHTS],
    usize,
)> {
    let sock = state.unix_socket_state(socket)?;
    if sock.pending_dgram_count == 0 {
        return None;
    }
    let slot = sock.pending_dgram_head as usize;
    let mut rights = [crate::server::open_file::OpenFileHandle::INVALID; UNIX_SOCKET_MAX_RIGHTS];
    let right_count = sock.pending_dgram_right_count[slot] as usize;
    rights[..right_count].copy_from_slice(&sock.pending_dgram_rights[slot][..right_count]);
    Some((
        sock.pending_dgram_len[slot] as usize,
        sock.pending_dgram_src_vnode[slot],
        sock.pending_dgram_src_path[slot],
        sock.pending_dgram_src_path_len[slot] as usize,
        sock.pending_dgram_src_abstract_name[slot],
        sock.pending_dgram_src_abstract_len[slot] as usize,
        rights,
        right_count,
    ))
}

fn local_dgram_copy_front(
    state: &VfsState,
    socket: UnixSocketHandle,
    dst: *mut u8,
    len: usize,
) -> Option<usize> {
    let sock = state.unix_socket_state(socket)?;
    if sock.pending_dgram_count == 0 {
        return None;
    }
    let slot = sock.pending_dgram_head as usize;
    let actual = core::cmp::min(len, sock.pending_dgram_len[slot] as usize);
    for idx in 0..actual {
        unsafe {
            *dst.add(idx) = sock.pending_dgram_data[slot][idx];
        }
    }
    Some(actual)
}

fn local_dgram_drop_front(state: &mut VfsState, socket: UnixSocketHandle) -> bool {
    let Some(sock) = state.unix_socket_state_mut(socket) else {
        return false;
    };
    if sock.pending_dgram_count == 0 {
        return false;
    }
    let slot = sock.pending_dgram_head as usize;
    sock.pending_dgram_head = (slot + 1).wrapping_rem(UNIX_DGRAM_QUEUE_CAP) as u8;
    sock.pending_dgram_count = sock.pending_dgram_count.saturating_sub(1);
    sock.pending_dgram_len[slot] = 0;
    sock.pending_dgram_src_vnode[slot] = crate::vfs_core::vnode::VnodeHandle::INVALID;
    sock.pending_dgram_src_path_len[slot] = 0;
    sock.pending_dgram_src_abstract_len[slot] = 0;
    sock.pending_dgram_right_count[slot] = 0;
    true
}

unsafe fn rollback_local_dgram_rights(
    state: &mut VfsState,
    src_vnode: crate::vfs_core::vnode::VnodeHandle,
    handles: &[crate::server::open_file::OpenFileHandle],
) {
    if src_vnode.is_valid() {
        state.release_socket_name_vnode(src_vnode);
    }
    unsafe {
        rollback_local_socket_rights(state, handles);
    }
}

/// Single-shot NET_RECV attempt. Returns `Some(())` (Filled) when the
/// reply is fully populated (success or terminal error). Returns
/// `None` (WouldBlock) when netsrv answered TRONA_PENDING — caller is
/// responsible for parking the saved caller via `defer_inet_op`.
unsafe fn try_inet_recv_once(
    conn_id: u32,
    max_len: u16,
    flags: u32,
    reply: *mut TronaMsg,
) -> Option<()> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_RECV;
        req.length = 3;
        req.regs[0] = conn_id as u64;
        req.regs[1] = core::cmp::min(max_len as usize, INLINE_RECV_MAX) as u64;
        req.regs[2] = flags as u64;

        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return Some(());
        }
        if resp.label == TRONA_PENDING {
            return None;
        }
        fill_recv_reply(reply, &resp);
        Some(())
    }
}

/// Single-shot NET_RECVFROM attempt. Same Filled/WouldBlock contract
/// as `try_inet_recv_once`.
unsafe fn try_inet_recvfrom_once(
    conn_id: u32,
    max_len: u16,
    flags: u32,
    reply: *mut TronaMsg,
) -> Option<()> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_RECVFROM;
        req.length = 3;
        req.regs[0] = conn_id as u64;
        req.regs[1] = core::cmp::min(max_len as usize, INLINE_RECV_MAX) as u64;
        req.regs[2] = flags as u64;

        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return Some(());
        }
        if resp.label == TRONA_PENDING {
            return None;
        }
        fill_recvfrom_reply(reply, &resp);
        Some(())
    }
}

/// Owner-side glue: try NET_RECV once; on Filled, write reply and
/// return. On WouldBlock with nonblocking flag, return TRONA_WOULD_BLOCK.
/// Otherwise park the saved caller via `defer_inet_op` and arm
/// `NET_RECV_WAIT` if this is the first waiter for the
/// `(conn_id, INET_OP_RECV)` key.
unsafe fn handle_inet_recv(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    conn_id: u32,
    max_len: u16,
    flags: u32,
    nonblocking: bool,
    reply: *mut TronaMsg,
) {
    unsafe {
        if try_inet_recv_once(conn_id, max_len, flags, reply).is_some() {
            return;
        }
        if nonblocking {
            (*reply).label = TRONA_WOULD_BLOCK;
            (*reply).length = 0;
            return;
        }
        match defer_inet_op(
            state,
            cli_handle,
            conn_id,
            INET_OP_RECV,
            max_len,
            flags,
            reply,
        ) {
            Some(true) => {
                arm_or_cancel_head(state, conn_id, INET_OP_RECV);
            }
            Some(false) => {}
            None => {}
        }
    }
}

unsafe fn handle_inet_recvfrom(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    conn_id: u32,
    max_len: u16,
    flags: u32,
    nonblocking: bool,
    reply: *mut TronaMsg,
) {
    unsafe {
        if try_inet_recvfrom_once(conn_id, max_len, flags, reply).is_some() {
            return;
        }
        if nonblocking {
            (*reply).label = TRONA_WOULD_BLOCK;
            (*reply).length = 0;
            return;
        }
        match defer_inet_op(
            state,
            cli_handle,
            conn_id,
            INET_OP_RECVFROM,
            max_len,
            flags,
            reply,
        ) {
            Some(true) => {
                arm_or_cancel_head(state, conn_id, INET_OP_RECVFROM);
            }
            Some(false) => {}
            None => {}
        }
    }
}

fn poll_bits_for_inet_socket(conn_id: u32, events: i16) -> i16 {
    let mut req = TronaMsg::zeroed();
    let mut resp = TronaMsg::zeroed();
    req.label = NET_POLL_STATUS;
    req.length = 2;
    req.regs[0] = conn_id as u64;
    req.regs[1] = events as u16 as u64;
    let err = netsrv_call(&raw const req, &raw mut resp);
    if err != 0 || resp.label != TRONA_OK {
        POLLERR
    } else {
        resp.regs[0] as i16
    }
}

fn poll_bits_for_local_socket(state: &VfsState, socket: UnixSocketHandle, events: i16) -> i16 {
    let Some(sock) = state.unix_socket_state(socket) else {
        return POLLNVAL;
    };
    let socket_type = sock.socket_type as i32;

    if sock.listener != 0 {
        let mut revents = 0i16;
        if (events & POLLIN) != 0 && sock.pending_accept_count != 0 {
            revents |= POLLIN;
        }
        if sock.listener_backlog != 0
            && (events & POLLOUT) != 0
            && sock.pending_accept_count < sock.listener_backlog as u8
        {
            revents |= POLLOUT;
        }
        return revents;
    }

    let mut revents = 0i16;
    let readable = if local_socket_is_packet_type(socket_type) {
        state.unix_socket_dgram_count(socket).unwrap_or(0) != 0
    } else {
        state.unix_socket_buffer_len(socket).unwrap_or(0) != 0 || sock.pending_right_count != 0
    };
    if (events & POLLIN) != 0 && readable {
        revents |= POLLIN;
    }
    if local_socket_is_connection_oriented(socket_type) && sock.peer_closed != 0 {
        revents |= POLLHUP;
    }

    if (events & POLLOUT) != 0 && sock.shut_wr == 0 && sock.peer_closed == 0 {
        let writable = if local_socket_is_packet_type(socket_type) {
            if !sock.peer.is_valid() {
                socket_type == SOCK_DGRAM
            } else {
                sock.peer.is_valid()
                    && state
                        .unix_socket_state(sock.peer)
                        .map(|peer| peer.shut_rd == 0)
                        .unwrap_or(false)
                    && state
                        .unix_socket_dgram_has_space(sock.peer)
                        .unwrap_or(false)
            }
        } else {
            sock.peer.is_valid()
                && state
                    .unix_socket_state(sock.peer)
                    .map(|peer| peer.shut_rd == 0)
                    .unwrap_or(false)
                && state.unix_socket_buffer_free(sock.peer).unwrap_or(0) != 0
        };
        if writable {
            revents |= POLLOUT;
        }
    }
    if (local_socket_is_connection_oriented(socket_type) && sock.peer_closed != 0)
        || sock.shut_wr != 0
    {
        revents |= POLLERR;
    }
    revents
}

pub(crate) fn poll_bits_for_socket(of: &OpenFile, state: &VfsState, events: i16) -> i16 {
    if of.unix_socket.is_valid() {
        poll_bits_for_local_socket(state, of.unix_socket, events)
    } else if of.socket_conn_id != 0 {
        poll_bits_for_inet_socket(of.socket_conn_id, events)
    } else {
        POLLNVAL
    }
}

/// Try to consume the front dgram. Returns Filled when reply is
/// written (success or terminal error), WouldBlock when the queue is
/// empty and the caller may park as a UNIX_OP_DGRAM_READ waiter.
pub(crate) unsafe fn try_unix_dgram_read_to_reply(
    state: &mut VfsState,
    socket: UnixSocketHandle,
    want_count: usize,
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let Some(sock) = state.unix_socket_state(socket) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        let socket_type = sock.socket_type as i32;
        if sock.listener != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        if sock.shut_rd != 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return TryOutcome::Filled;
        }
        if state.unix_socket_dgram_count(socket).unwrap_or(0) == 0 {
            if socket_type == SOCK_SEQPACKET && sock.peer_closed != 0 {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
                return TryOutcome::Filled;
            }
            return TryOutcome::WouldBlock;
        }

        let Some((packet_len, src_vnode, _, _, _, _, rights, right_count)) =
            local_dgram_front_meta(state, socket)
        else {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        let actual = core::cmp::min(want_count, packet_len);
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = actual as u64;
        (*reply).length = 1 + ((actual as u64 + 7) / 8);
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        let _ = local_dgram_copy_front(state, socket, dst, actual);
        let _ = local_dgram_drop_front(state, socket);
        if src_vnode.is_valid() {
            state.release_socket_name_vnode(src_vnode);
        }
        for handle in rights.into_iter().take(right_count) {
            if handle.is_valid() {
                state.release_shared_open_file(handle);
            }
        }
        TryOutcome::Filled
    }
}

unsafe fn handle_local_dgram_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    nonblocking: bool,
    want_count: usize,
    reply: *mut TronaMsg,
) {
    unsafe {
        match try_unix_dgram_read_to_reply(state, socket, want_count, reply) {
            TryOutcome::Filled => {}
            TryOutcome::WouldBlock => {
                if nonblocking {
                    (*reply).label = TRONA_WOULD_BLOCK;
                    (*reply).length = 0;
                    return;
                }
                let ctx = DeferContext::for_read(cli_handle, socket, want_count);
                defer_unix_socket_op(state, UNIX_OP_DGRAM_READ, ctx, reply);
            }
        }
    }
}

/// Try to enqueue a single Unix-domain datagram on `target`. Returns
/// Filled (success or terminal error) or WouldBlock (target queue
/// full / enqueue failed). Caller (`handle_unix_dgram_send` /
/// `drive_unix_socket_waiters`) decides whether to park the saved
/// caller as a UNIX_OP_DGRAM_SEND waiter.
///
/// `deferred = true` means we are being re-tried from the drive path
/// where fd numbers were stashed at park time and must now be looked
/// up + retained against the current client fd table. `deferred =
/// false` is the synchronous path where retain-then-yield was the
/// existing behaviour.
pub(crate) unsafe fn try_unix_dgram_send_to_reply(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    target: UnixSocketHandle,
    source_name_vnode: crate::vfs_core::vnode::VnodeHandle,
    source_path: &[u8],
    source_path_len: usize,
    source_abstract_name: &[u8],
    source_abstract_len: usize,
    data: &[u8],
    fd_numbers: &[i32],
    deferred: bool,
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let Some(sock) = state.unix_socket_state(socket) else {
            if source_name_vnode.is_valid() {
                state.release_socket_name_vnode(source_name_vnode);
            }
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        let sender_type = sock.socket_type as i32;
        if sock.listener != 0 || sock.shut_wr != 0 {
            if source_name_vnode.is_valid() {
                state.release_socket_name_vnode(source_name_vnode);
            }
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        let Some(peer_state) = state.unix_socket_state(target) else {
            if source_name_vnode.is_valid() {
                state.release_socket_name_vnode(source_name_vnode);
            }
            (*reply).label = TRONA_NOT_CONNECTED;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        if peer_state.listener != 0
            || peer_state.socket_type as i32 != sender_type
            || peer_state.shut_rd != 0
        {
            if source_name_vnode.is_valid() {
                state.release_socket_name_vnode(source_name_vnode);
            }
            (*reply).label = TRONA_NOT_CONNECTED;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        if !state.unix_socket_dgram_has_space(target).unwrap_or(false) {
            return TryOutcome::WouldBlock;
        }

        let mut rights =
            [crate::server::open_file::OpenFileHandle::INVALID; UNIX_SOCKET_MAX_RIGHTS];
        let fd_count = core::cmp::min(fd_numbers.len(), UNIX_SOCKET_MAX_RIGHTS);
        for (idx, slot) in rights.iter_mut().enumerate().take(fd_count) {
            let sent_fd = fd_numbers[idx];
            if sent_fd < 0 {
                rollback_local_dgram_rights(state, source_name_vnode, &rights);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
            let Some(open_file) = state.client_open_file_handle(cli_handle, sent_fd as usize)
            else {
                rollback_local_dgram_rights(state, source_name_vnode, &rights);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return TryOutcome::Filled;
            };
            if !state.retain_open_file_handle(open_file) {
                rollback_local_dgram_rights(state, source_name_vnode, &rights);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
            *slot = open_file;
        }

        let actual = core::cmp::min(data.len(), UNIX_DGRAM_MAX_PAYLOAD);
        let rights_slice = &rights[..fd_count];
        let mut abstract_buf = [0u8; UNIX_SOCKET_ADDR_MAX];
        let abstract_len = core::cmp::min(source_abstract_len, UNIX_SOCKET_ADDR_MAX);
        if abstract_len > 0 {
            let take = core::cmp::min(abstract_len, source_abstract_name.len());
            abstract_buf[..take].copy_from_slice(&source_abstract_name[..take]);
        }
        if !state
            .unix_socket_dgram_enqueue(
                target,
                source_name_vnode,
                source_path,
                source_path_len,
                &abstract_buf,
                abstract_len,
                rights_slice,
                data.as_ptr(),
                actual,
            )
            .unwrap_or(false)
        {
            rollback_local_dgram_rights(state, source_name_vnode, &rights);
            return TryOutcome::WouldBlock;
        }

        let _ = deferred; // placeholder so the parameter remains documented
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual as u64;
        TryOutcome::Filled
    }
}

unsafe fn send_local_dgram_to_target(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    target: UnixSocketHandle,
    source_name_vnode: crate::vfs_core::vnode::VnodeHandle,
    source_path: &[u8; UNIX_SOCKET_ADDR_MAX],
    source_path_len: usize,
    source_abstract_name: &[u8; UNIX_SOCKET_ADDR_MAX],
    source_abstract_len: usize,
    nonblocking: bool,
    src: *const u8,
    data_len: usize,
    fd_src: *const i32,
    fd_count: usize,
    reply: *mut TronaMsg,
) {
    unsafe {
        // Materialize fd numbers and inline data so the try helper and
        // the parked-waiter path share one entry shape.
        let mut fd_numbers = [-1i32; UNIX_SOCKET_MAX_RIGHTS];
        let actual_fd_count = core::cmp::min(fd_count, UNIX_SOCKET_MAX_RIGHTS);
        for idx in 0..actual_fd_count {
            fd_numbers[idx] = *fd_src.add(idx);
        }
        let inline_len = core::cmp::min(data_len, UNIX_DGRAM_MAX_PAYLOAD);
        let mut inline = [0u8; INLINE_SEND_MAX];
        let copy_len = core::cmp::min(inline_len, INLINE_SEND_MAX);
        if copy_len > 0 {
            core::ptr::copy_nonoverlapping(src, inline.as_mut_ptr(), copy_len);
        }

        match try_unix_dgram_send_to_reply(
            state,
            cli_handle,
            socket,
            target,
            source_name_vnode,
            source_path,
            source_path_len,
            source_abstract_name,
            source_abstract_len,
            &inline[..copy_len],
            &fd_numbers[..actual_fd_count],
            /* deferred = */ false,
            reply,
        ) {
            TryOutcome::Filled => {}
            TryOutcome::WouldBlock => {
                if nonblocking {
                    if source_name_vnode.is_valid() {
                        state.release_socket_name_vnode(source_name_vnode);
                    }
                    (*reply).label = TRONA_WOULD_BLOCK;
                    (*reply).length = 0;
                    return;
                }
                // Park: fd retains happen at drive time (per plan).
                // Source name vnode stays retained on the waiter.
                let ctx = DeferContext {
                    client: cli_handle,
                    socket,
                    target,
                    source_name_vnode,
                    source_path: &source_path[..source_path_len.min(source_path.len())],
                    source_abstract_name: &source_abstract_name
                        [..source_abstract_len.min(source_abstract_name.len())],
                    want_count: 0,
                    data: &inline[..copy_len],
                    fd_numbers: &fd_numbers[..actual_fd_count],
                    msg_flags: 0,
                    msg_aux: 0,
                };
                if !defer_unix_socket_op(state, UNIX_OP_DGRAM_SEND, ctx, reply) {
                    // defer_unix_socket_op populated reply with an
                    // error label; release retained source_name_vnode
                    // so we don't leak it.
                    if source_name_vnode.is_valid() {
                        state.release_socket_name_vnode(source_name_vnode);
                    }
                }
            }
        }
    }
}

/// Try a single iteration of `handle_local_socket_read`'s stream
/// branch. Returns Filled (success or terminal error) or WouldBlock
/// (buffer empty and peer still alive).
pub(crate) unsafe fn try_unix_stream_read_to_reply(
    state: &mut VfsState,
    socket: UnixSocketHandle,
    want_count: usize,
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let Some(sock) = state.unix_socket_state(socket) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        if sock.listener != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        if sock.shut_rd != 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return TryOutcome::Filled;
        }
        if !sock.peer.is_valid() {
            (*reply).label = TRONA_NOT_CONNECTED;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }

        let available = state.unix_socket_buffer_len(socket).unwrap_or(0) as usize;
        if available == 0 {
            if sock.peer_closed != 0 {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
                return TryOutcome::Filled;
            }
            return TryOutcome::WouldBlock;
        }

        let actual = core::cmp::min(want_count, available);
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = actual as u64;
        (*reply).length = 1 + ((actual as u64 + 7) / 8);
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        let _ = state.unix_socket_read(socket, dst, actual);
        TryOutcome::Filled
    }
}

unsafe fn handle_local_socket_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    nonblocking: bool,
    want_count: usize,
    reply: *mut TronaMsg,
) {
    unsafe {
        if local_socket_is_packet_type(local_socket_type(state, socket)) {
            handle_local_dgram_read(state, cli_handle, socket, nonblocking, want_count, reply);
            return;
        }
        match try_unix_stream_read_to_reply(state, socket, want_count, reply) {
            TryOutcome::Filled => {}
            TryOutcome::WouldBlock => {
                if nonblocking {
                    (*reply).label = TRONA_WOULD_BLOCK;
                    (*reply).length = 0;
                    return;
                }
                let ctx = DeferContext::for_read(cli_handle, socket, want_count);
                defer_unix_socket_op(state, UNIX_OP_STREAM_READ, ctx, reply);
            }
        }
    }
}

unsafe fn handle_local_socket_write(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    nonblocking: bool,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let _ = cli_handle;
        if local_socket_is_packet_type(local_socket_type(state, socket)) {
            let data_len = core::cmp::min((*msg).regs[1] as usize, INLINE_SEND_MAX);
            let Some(sock) = state.unix_socket_state(socket) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            let peer = sock.peer;
            let source_name_vnode = if sock.bound_vnode.is_valid() {
                sock.bound_vnode
            } else {
                crate::vfs_core::vnode::VnodeHandle::INVALID
            };
            let source_abstract_name = sock.bound_abstract_name;
            let source_abstract_len = sock.bound_abstract_len as usize;
            let source_path = sock.bound_path;
            let source_path_len = sock.bound_path_len as usize;
            if source_name_vnode.is_valid() && !state.retain_socket_name_vnode(source_name_vnode) {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return;
            }
            if !peer.is_valid() {
                if source_name_vnode.is_valid() {
                    state.release_socket_name_vnode(source_name_vnode);
                }
                (*reply).label = TRONA_NOT_CONNECTED;
                (*reply).length = 0;
                return;
            }
            let src = &raw const (*msg).regs[2] as *const u8;
            send_local_dgram_to_target(
                state,
                ClientHandle::INVALID,
                socket,
                peer,
                source_name_vnode,
                &source_path,
                source_path_len,
                &source_abstract_name,
                source_abstract_len,
                nonblocking,
                src,
                data_len,
                core::ptr::null(),
                0,
                reply,
            );
            return;
        }
        let want_count = core::cmp::min((*msg).regs[1] as usize, INLINE_SEND_MAX);
        if want_count == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }
        let src = &raw const (*msg).regs[2] as *const u8;
        let mut data = [0u8; INLINE_SEND_MAX];
        core::ptr::copy_nonoverlapping(src, data.as_mut_ptr(), want_count);
        match try_unix_stream_write_to_reply(state, socket, &data[..want_count], reply) {
            TryOutcome::Filled => {}
            TryOutcome::WouldBlock => {
                if nonblocking {
                    (*reply).label = TRONA_WOULD_BLOCK;
                    (*reply).length = 0;
                    return;
                }
                let ctx = DeferContext {
                    client: ClientHandle::INVALID,
                    socket,
                    target: UnixSocketHandle::INVALID,
                    source_name_vnode: crate::vfs_core::vnode::VnodeHandle::INVALID,
                    source_path: &[],
                    source_abstract_name: &[],
                    want_count,
                    data: &data[..want_count],
                    fd_numbers: &[],
                    msg_flags: 0,
                    msg_aux: 0,
                };
                defer_unix_socket_op(state, UNIX_OP_STREAM_WRITE, ctx, reply);
            }
        }
    }
}

/// Try-once kernel for stream write. Filled on success (partial-write
/// permitted: actual = min(want, free)), error label, or peer-closed
/// EPIPE-equivalent (TRONA_NOT_CONNECTED). WouldBlock when peer's
/// buffer is full but the connection is otherwise healthy.
pub(crate) unsafe fn try_unix_stream_write_to_reply(
    state: &mut VfsState,
    socket: UnixSocketHandle,
    data: &[u8],
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let Some(sock) = state.unix_socket_state(socket) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        if sock.listener != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        if sock.shut_wr != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        let peer = sock.peer;
        if !peer.is_valid()
            || state
                .unix_socket_state(peer)
                .map(|s| s.shut_rd != 0)
                .unwrap_or(true)
            || sock.peer_closed != 0
        {
            (*reply).label = TRONA_NOT_CONNECTED;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }

        let free = state.unix_socket_buffer_free(peer).unwrap_or(0) as usize;
        if free == 0 {
            return TryOutcome::WouldBlock;
        }

        let actual = core::cmp::min(data.len(), free);
        let _ = state.unix_socket_write(peer, data.as_ptr(), actual);
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual as u64;
        TryOutcome::Filled
    }
}

unsafe fn rollback_local_socket_rights(
    state: &mut VfsState,
    handles: &[crate::server::open_file::OpenFileHandle],
) {
    for handle in handles {
        if handle.is_valid() {
            state.release_shared_open_file(*handle);
        }
    }
}

unsafe fn handle_local_sendmsg(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    nonblocking: bool,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let encoded = (*msg).regs[2] as i32;
        let fd_count = core::cmp::min((encoded as usize) & 0xff, UNIX_SOCKET_MAX_RIGHTS);
        let has_local_addr = (encoded & VFS_SENDMSG_FLAG_LOCAL_ADDR) != 0;
        let data_len = core::cmp::min((*msg).regs[1] as usize, INLINE_SEND_MAX);
        let socket_type = local_socket_type(state, socket);
        if has_local_addr && socket_type != SOCK_DGRAM {
            (*reply).label = match state.unix_socket_state(socket) {
                Some(sock) if sock.listener != 0 => TRONA_INVALID_OPERATION,
                Some(sock) if sock.peer.is_valid() => TRONA_IS_CONNECTED,
                Some(_) => TRONA_NOT_CONNECTED,
                None => TRONA_INVALID_ARGUMENT,
            };
            (*reply).length = 0;
            return;
        }
        if local_socket_is_packet_type(socket_type) {
            let Some((
                peer,
                source_name_vnode,
                source_path,
                source_path_len,
                source_abstract_name,
                source_abstract_len,
            )) = state.unix_socket_state(socket).map(|sock| {
                (
                    sock.peer,
                    if sock.bound_vnode.is_valid() {
                        sock.bound_vnode
                    } else {
                        crate::vfs_core::vnode::VnodeHandle::INVALID
                    },
                    sock.bound_path,
                    sock.bound_path_len as usize,
                    sock.bound_abstract_name,
                    sock.bound_abstract_len as usize,
                )
            })
            else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            if source_name_vnode.is_valid() && !state.retain_socket_name_vnode(source_name_vnode) {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return;
            }
            let (target, src_ptr) = if has_local_addr {
                let mut raw_path = [0u8; MAX_PATH_LEN];
                let mut abs_path = [0u8; MAX_PATH_LEN];
                let mut abstract_name = [0u8; UNIX_SOCKET_ADDR_MAX];
                let encoded_len = (*msg).regs[3];
                let (name_len, is_abstract) = local_addr_wire_len(encoded_len);
                let Some(addr_kind) =
                    extract_local_addr_from_msg(msg, 3, 4, &mut raw_path, &mut abstract_name)
                else {
                    if source_name_vnode.is_valid() {
                        state.release_socket_name_vnode(source_name_vnode);
                    }
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                let path_regs = if is_abstract {
                    ((name_len as u64) + 7) / 8
                } else {
                    (((name_len + 1) as u64) + 7) / 8
                };
                let target = match addr_kind {
                    LocalSocketAddrKind::Path(raw_len) => {
                        let Some(abs_len) = normalize_path_owned(
                            state,
                            cli_handle,
                            raw_path.as_ptr(),
                            raw_len as u8,
                            abs_path.as_mut_ptr(),
                        ) else {
                            if source_name_vnode.is_valid() {
                                state.release_socket_name_vnode(source_name_vnode);
                            }
                            (*reply).label = TRONA_INVALID_ARGUMENT;
                            (*reply).length = 0;
                            return;
                        };
                        let target_vnode = match state.lookup_path_dynamic_for_client(
                            cli_handle,
                            &abs_path[..abs_len],
                            false,
                        ) {
                            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
                            _ => {
                                if source_name_vnode.is_valid() {
                                    state.release_socket_name_vnode(source_name_vnode);
                                }
                                (*reply).label = TRONA_CONN_REFUSED;
                                (*reply).length = 0;
                                return;
                            }
                        };
                        local_socket_bound_handle(state, target_vnode)
                    }
                    LocalSocketAddrKind::Abstract(name_len) => {
                        if name_len == 0 {
                            None
                        } else {
                            local_socket_bound_handle_abstract(state, &abstract_name[..name_len])
                        }
                    }
                };
                let Some(target) = target else {
                    if source_name_vnode.is_valid() {
                        state.release_socket_name_vnode(source_name_vnode);
                    }
                    (*reply).label = TRONA_CONN_REFUSED;
                    (*reply).length = 0;
                    return;
                };
                (
                    target,
                    (&raw const (*msg).regs[4] as *const u8).add((path_regs * 8) as usize),
                )
            } else {
                let Some(target) = peer.is_valid().then_some(peer) else {
                    if source_name_vnode.is_valid() {
                        state.release_socket_name_vnode(source_name_vnode);
                    }
                    (*reply).label = TRONA_NOT_CONNECTED;
                    (*reply).length = 0;
                    return;
                };
                (target, &raw const (*msg).regs[3] as *const u8)
            };
            let data_regs = (data_len as u64 + 7) / 8;
            let fd_src = if has_local_addr {
                let (path_len, is_abstract) = local_addr_wire_len((*msg).regs[3]);
                let path_regs = if is_abstract {
                    ((path_len as u64) + 7) / 8
                } else {
                    (((path_len + 1) as u64) + 7) / 8
                };
                let data_base = 4usize + path_regs as usize;
                &raw const (*msg).regs[data_base + data_regs as usize] as *const i32
            } else {
                &raw const (*msg).regs[3 + data_regs as usize] as *const i32
            };
            send_local_dgram_to_target(
                state,
                cli_handle,
                socket,
                target,
                source_name_vnode,
                &source_path,
                source_path_len,
                &source_abstract_name,
                source_abstract_len,
                nonblocking,
                src_ptr,
                data_len,
                fd_src,
                fd_count,
                reply,
            );
            return;
        }
        let data_regs = (data_len as u64 + 7) / 8;
        let fd_src = &raw const (*msg).regs[3 + data_regs as usize] as *const i32;
        let mut data_buf = [0u8; INLINE_SEND_MAX];
        let copy_len = core::cmp::min(data_len, INLINE_SEND_MAX);
        if copy_len > 0 {
            let src = &raw const (*msg).regs[3] as *const u8;
            core::ptr::copy_nonoverlapping(src, data_buf.as_mut_ptr(), copy_len);
        }
        let mut fd_numbers = [-1i32; UNIX_SOCKET_MAX_RIGHTS];
        let actual_fd_count = core::cmp::min(fd_count, UNIX_SOCKET_MAX_RIGHTS);
        for idx in 0..actual_fd_count {
            fd_numbers[idx] = *fd_src.add(idx);
        }
        match try_unix_sendmsg_stream_to_reply(
            state,
            cli_handle,
            socket,
            &data_buf[..copy_len],
            &fd_numbers[..actual_fd_count],
            /* deferred = */ false,
            reply,
        ) {
            TryOutcome::Filled => {}
            TryOutcome::WouldBlock => {
                if nonblocking {
                    (*reply).label = TRONA_WOULD_BLOCK;
                    (*reply).length = 0;
                    return;
                }
                let ctx = DeferContext {
                    client: cli_handle,
                    socket,
                    target: UnixSocketHandle::INVALID,
                    source_name_vnode: crate::vfs_core::vnode::VnodeHandle::INVALID,
                    source_path: &[],
                    source_abstract_name: &[],
                    want_count: 0,
                    data: &data_buf[..copy_len],
                    fd_numbers: &fd_numbers[..actual_fd_count],
                    msg_flags: 0,
                    msg_aux: 0,
                };
                defer_unix_socket_op(state, UNIX_OP_SENDMSG_STREAM, ctx, reply);
            }
        }
    }
}

/// Try-once kernel for stream sendmsg. Wakes on either pending_rights
/// drained by the peer's recvmsg or on peer buffer free space — the
/// drive path simply re-evaluates this whole helper, so the WouldBlock
/// reason is implicit.
pub(crate) unsafe fn try_unix_sendmsg_stream_to_reply(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    data: &[u8],
    fd_numbers: &[i32],
    deferred: bool,
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let _ = deferred;
        let Some(sock) = state.unix_socket_state(socket) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        if sock.listener != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        if sock.shut_wr != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        let peer = sock.peer;
        if !peer.is_valid()
            || state
                .unix_socket_state(peer)
                .map(|s| s.shut_rd != 0)
                .unwrap_or(true)
            || sock.peer_closed != 0
        {
            (*reply).label = TRONA_NOT_CONNECTED;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        let fd_count = fd_numbers.len();
        if fd_count != 0
            && state
                .unix_socket_state(peer)
                .map(|s| s.pending_right_count != 0)
                .unwrap_or(true)
        {
            return TryOutcome::WouldBlock;
        }

        let free = state.unix_socket_buffer_free(peer).unwrap_or(0) as usize;
        if !data.is_empty() && free == 0 {
            return TryOutcome::WouldBlock;
        }

        let mut rights =
            [crate::server::open_file::OpenFileHandle::INVALID; UNIX_SOCKET_MAX_RIGHTS];
        for (idx, slot) in rights.iter_mut().enumerate().take(fd_count) {
            let sent_fd = fd_numbers[idx];
            if sent_fd < 0 {
                rollback_local_socket_rights(state, &rights);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
            let Some(open_file) = state.client_open_file_handle(cli_handle, sent_fd as usize)
            else {
                rollback_local_socket_rights(state, &rights);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return TryOutcome::Filled;
            };
            if !state.retain_open_file_handle(open_file) {
                rollback_local_socket_rights(state, &rights);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
            *slot = open_file;
        }

        if fd_count != 0 {
            let Some(peer_state) = state.unix_socket_state_mut(peer) else {
                rollback_local_socket_rights(state, &rights);
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return TryOutcome::Filled;
            };
            peer_state.pending_right_count = fd_count as u8;
            peer_state.pending_rights[..fd_count].copy_from_slice(&rights[..fd_count]);
        }

        let actual = core::cmp::min(data.len(), free);
        if actual != 0 {
            let _ = state.unix_socket_write(peer, data.as_ptr(), actual);
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual as u64;
        TryOutcome::Filled
    }
}

/// Try-once kernel for the dgram branch of recvmsg. Mirrors the
/// original spinning loop body: reads the head queue entry, builds the
/// reply, drains rights and address bytes per the flags, and pops the
/// front entry unless MSG_PEEK was set.
///
/// `msg_flags` is the original `regs[2]` flags word (MSG_PEEK,
/// VFS_RECVMSG_FLAG_WANT_ADDR, etc). `msg_aux` carries
/// `FD_CLOEXEC` when the caller passed MSG_CMSG_CLOEXEC; zero
/// otherwise.
pub(crate) unsafe fn try_unix_recvmsg_dgram_to_reply(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    msg_flags: i32,
    want_count: usize,
    msg_aux: u64,
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let peek = (msg_flags & POSIX_MSG_PEEK) != 0;
        let want_addr = (msg_flags & VFS_RECVMSG_FLAG_WANT_ADDR) != 0;
        let want_rights = (msg_flags & VFS_RECVMSG_FLAG_WANT_RIGHTS) != 0;
        let cloexec = msg_aux as u32;

        let Some(sock) = state.unix_socket_state(socket) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        if sock.listener != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        if sock.shut_rd != 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 2;
            (*reply).regs[0] = 0;
            (*reply).regs[1] = 0;
            return TryOutcome::Filled;
        }
        if state.unix_socket_dgram_count(socket).unwrap_or(0) == 0 {
            return TryOutcome::WouldBlock;
        }

        let Some((
            packet_len,
            src_vnode,
            src_path,
            src_path_len,
            src_abstract_name,
            src_abstract_len,
            rights,
            right_count,
        )) = local_dgram_front_meta(state, socket)
        else {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        let actual = core::cmp::min(want_count, packet_len);
        let mut payload = [0u8; INLINE_RECV_MAX];
        let _ = local_dgram_copy_front(state, socket, payload.as_mut_ptr(), actual);

        let mut delivered = 0usize;
        if want_addr {
            let (path_len, is_abstract) = if src_abstract_len != 0 {
                (src_abstract_len, true)
            } else if src_path_len != 0 {
                (src_path_len, false)
            } else if src_vnode.is_valid() {
                (0, false)
            } else {
                (0, false)
            };
            let path_regs = if is_abstract {
                ((path_len as u64) + 7) / 8
            } else {
                (((path_len + 1) as u64) + 7) / 8
            };
            let data_regs = ((actual as u64) + 7) / 8;
            let path_base = if want_rights { 3usize } else { 2usize };
            (*reply).label = TRONA_OK;
            (*reply).regs[0] = actual as u64;
            (*reply).regs[1] = if is_abstract {
                UNIX_ADDR_ABSTRACT_FLAG | path_len as u64
            } else {
                path_len as u64
            };
            if want_rights {
                (*reply).regs[2] = 0;
            }
            let path_dst = (&raw mut (*reply).regs[path_base]) as *mut u64 as *mut u8;
            if path_len != 0 {
                if is_abstract {
                    core::ptr::copy_nonoverlapping(src_abstract_name.as_ptr(), path_dst, path_len);
                } else {
                    core::ptr::copy_nonoverlapping(src_path.as_ptr(), path_dst, path_len);
                    *path_dst.add(path_len) = 0;
                }
            } else if !is_abstract {
                *path_dst = 0;
            }
            if actual != 0 {
                let data_dst = path_dst.add((path_regs * 8) as usize);
                core::ptr::copy_nonoverlapping(payload.as_ptr(), data_dst, actual);
            }
            (*reply).length = path_base as u64 + path_regs + data_regs;
        } else {
            (*reply).label = TRONA_OK;
            (*reply).regs[0] = actual as u64;
        }
        if !want_addr && actual != 0 {
            let data_dst = (&raw mut (*reply).regs[2]) as *mut u64 as *mut u8;
            core::ptr::copy_nonoverlapping(payload.as_ptr(), data_dst, actual);
        }

        if want_rights {
            let data_regs = if want_addr {
                let path_regs = local_addr_payload_regs((*reply).regs[1]);
                path_regs + (((actual as u64) + 7) / 8)
            } else {
                ((actual as u64) + 7) / 8
            };
            let fd_base = if want_addr { 3 } else { 2 };
            let fd_dst = &raw mut (*reply).regs[fd_base + data_regs as usize] as *mut i32;
            for handle in rights.into_iter().take(right_count) {
                let Some(new_fd) = state.alloc_shared_fd_for_client(cli_handle, handle, cloexec)
                else {
                    if handle.is_valid() && !peek {
                        state.release_shared_open_file(handle);
                    }
                    continue;
                };
                *fd_dst.add(delivered) = new_fd as i32;
                delivered += 1;
                if !peek {
                    state.release_shared_open_file(handle);
                }
            }
            if want_addr {
                (*reply).regs[2] = delivered as u64;
                (*reply).length += ((delivered * core::mem::size_of::<i32>()) as u64 + 7) / 8;
            } else {
                (*reply).regs[1] = delivered as u64;
                (*reply).length = 2
                    + (((actual as u64) + 7) / 8)
                    + (((delivered * core::mem::size_of::<i32>()) as u64 + 7) / 8);
            }
        } else if !peek {
            for handle in rights.into_iter().take(right_count) {
                if handle.is_valid() {
                    state.release_shared_open_file(handle);
                }
            }
        }

        if !peek {
            let _ = local_dgram_drop_front(state, socket);
            if src_vnode.is_valid() {
                state.release_socket_name_vnode(src_vnode);
            }
        }
        if !want_addr && !want_rights {
            (*reply).regs[1] = 0;
            (*reply).length = 2 + (((actual as u64) + 7) / 8);
        } else if !want_addr {
            (*reply).regs[1] = delivered as u64;
        }
        TryOutcome::Filled
    }
}

/// Try-once kernel for the stream branch of recvmsg. WouldBlock when
/// the receive buffer is empty and there are no pending fd-rights
/// AND the peer hasn't been closed (in which case we surface 0-byte
/// EOF synchronously). Any error or successful read closes out
/// Filled.
pub(crate) unsafe fn try_unix_recvmsg_stream_to_reply(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    msg_flags: i32,
    want_count: usize,
    msg_aux: u64,
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let peek = (msg_flags & POSIX_MSG_PEEK) != 0;
        let want_addr = (msg_flags & VFS_RECVMSG_FLAG_WANT_ADDR) != 0;
        let want_rights = (msg_flags & VFS_RECVMSG_FLAG_WANT_RIGHTS) != 0;
        let cloexec = msg_aux as u32;

        let Some(sock) = state.unix_socket_state(socket) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        if sock.listener != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        if sock.shut_rd != 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 2;
            (*reply).regs[0] = 0;
            (*reply).regs[1] = 0;
            return TryOutcome::Filled;
        }
        if !sock.peer.is_valid() {
            (*reply).label = TRONA_NOT_CONNECTED;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }

        let available = state.unix_socket_buffer_len(socket).unwrap_or(0) as usize;
        let pending_rights = sock.pending_right_count as usize;
        if available == 0 && pending_rights == 0 {
            if sock.peer_closed != 0 {
                (*reply).label = TRONA_OK;
                (*reply).length = 2;
                (*reply).regs[0] = 0;
                (*reply).regs[1] = 0;
                return TryOutcome::Filled;
            }
            return TryOutcome::WouldBlock;
        }

        let max_data = core::cmp::min(want_count, INLINE_SENDTO_MAX);
        let actual = core::cmp::min(max_data, available);
        let data_base = if want_addr {
            let mut source_abstract_name = [0u8; UNIX_SOCKET_ADDR_MAX];
            let mut source_path = [0u8; UNIX_SOCKET_ADDR_MAX];
            let (_source_vnode, source_path_len, source_abstract_len) = if sock
                .peer_name_abstract_len
                != 0
            {
                source_abstract_name[..sock.peer_name_abstract_len as usize].copy_from_slice(
                    &sock.peer_name_abstract_name[..sock.peer_name_abstract_len as usize],
                );
                (
                    crate::vfs_core::vnode::VnodeHandle::INVALID,
                    0usize,
                    sock.peer_name_abstract_len as usize,
                )
            } else if sock.peer_name_path_len != 0 {
                source_path[..sock.peer_name_path_len as usize]
                    .copy_from_slice(&sock.peer_name_path[..sock.peer_name_path_len as usize]);
                (
                    sock.peer_name_vnode,
                    sock.peer_name_path_len as usize,
                    0usize,
                )
            } else if sock.peer_name_vnode.is_valid() {
                (sock.peer_name_vnode, 0usize, 0usize)
            } else if sock.peer.is_valid() {
                state
                    .unix_socket_state(sock.peer)
                    .map(|peer| {
                        if peer.bound_abstract_len != 0 {
                            source_abstract_name[..peer.bound_abstract_len as usize]
                                .copy_from_slice(
                                    &peer.bound_abstract_name[..peer.bound_abstract_len as usize],
                                );
                            (
                                crate::vfs_core::vnode::VnodeHandle::INVALID,
                                0usize,
                                peer.bound_abstract_len as usize,
                            )
                        } else if peer.bound_path_len != 0 {
                            source_path[..peer.bound_path_len as usize]
                                .copy_from_slice(&peer.bound_path[..peer.bound_path_len as usize]);
                            (peer.bound_vnode, peer.bound_path_len as usize, 0usize)
                        } else {
                            (peer.bound_vnode, 0usize, 0usize)
                        }
                    })
                    .unwrap_or((crate::vfs_core::vnode::VnodeHandle::INVALID, 0usize, 0usize))
            } else {
                (crate::vfs_core::vnode::VnodeHandle::INVALID, 0usize, 0usize)
            };
            let (path_len, is_abstract) = if source_abstract_len != 0 {
                (source_abstract_len, true)
            } else if source_path_len != 0 {
                (source_path_len, false)
            } else {
                (0, false)
            };
            let path_regs = if is_abstract {
                ((path_len as u64) + 7) / 8
            } else {
                (((path_len + 1) as u64) + 7) / 8
            };
            let path_base = if want_rights { 3usize } else { 2usize };
            (*reply).label = TRONA_OK;
            (*reply).regs[0] = actual as u64;
            (*reply).regs[1] = if is_abstract {
                UNIX_ADDR_ABSTRACT_FLAG | path_len as u64
            } else {
                path_len as u64
            };
            if want_rights {
                (*reply).regs[2] = 0;
            }
            let path_dst = (&raw mut (*reply).regs[path_base]) as *mut u64 as *mut u8;
            if path_len != 0 {
                if is_abstract {
                    core::ptr::copy_nonoverlapping(
                        source_abstract_name.as_ptr(),
                        path_dst,
                        path_len,
                    );
                } else {
                    core::ptr::copy_nonoverlapping(source_path.as_ptr(), path_dst, path_len);
                    *path_dst.add(path_len) = 0;
                }
            } else if !is_abstract {
                *path_dst = 0;
            }
            (*reply).length = path_base as u64 + path_regs + (((actual as u64) + 7) / 8);
            path_base + path_regs as usize
        } else {
            (*reply).label = TRONA_OK;
            2usize
        };
        if actual != 0 {
            let dst = &raw mut (*reply).regs[data_base] as *mut u64 as *mut u8;
            if peek {
                let _ = state.unix_socket_peek(socket, dst, actual);
            } else {
                let _ = state.unix_socket_read(socket, dst, actual);
            }
        }
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = actual as u64;

        let (rights, right_count) = {
            let mut rights =
                [crate::server::open_file::OpenFileHandle::INVALID; UNIX_SOCKET_MAX_RIGHTS];
            let mut count = 0usize;
            if let Some(sock_state) = state.unix_socket_state_mut(socket) {
                count = sock_state.pending_right_count as usize;
                rights[..count].copy_from_slice(&sock_state.pending_rights[..count]);
                if !peek {
                    for idx in 0..count {
                        sock_state.pending_rights[idx] =
                            crate::server::open_file::OpenFileHandle::INVALID;
                    }
                    sock_state.pending_right_count = 0;
                }
            }
            (rights, count)
        };

        let mut delivered = 0usize;
        let data_regs = (actual as u64 + 7) / 8;
        let fd_base = if want_addr { data_base } else { 2usize };
        let fd_dst = &raw mut (*reply).regs[fd_base + data_regs as usize] as *mut i32;
        for handle in rights.into_iter().take(right_count) {
            if !want_rights {
                if handle.is_valid() && !peek {
                    state.release_shared_open_file(handle);
                }
                continue;
            }
            let Some(new_fd) = state.alloc_shared_fd_for_client(cli_handle, handle, cloexec) else {
                if handle.is_valid() && !peek {
                    state.release_shared_open_file(handle);
                }
                continue;
            };
            *fd_dst.add(delivered) = new_fd as i32;
            delivered += 1;
            if !peek {
                state.release_shared_open_file(handle);
            }
        }

        if want_addr {
            if want_rights {
                (*reply).regs[2] = delivered as u64;
                (*reply).length += ((delivered * core::mem::size_of::<i32>()) as u64 + 7) / 8;
            }
        } else {
            (*reply).regs[1] = delivered as u64;
            (*reply).length =
                2 + data_regs + (((delivered * core::mem::size_of::<i32>()) as u64 + 7) / 8);
        }
        TryOutcome::Filled
    }
}

unsafe fn handle_local_recvmsg(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    nonblocking: bool,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let flags = (*msg).regs[2] as i32;
        let want_count = (*msg).regs[1] as usize;
        let cloexec = if (flags & MSG_CMSG_CLOEXEC) != 0 {
            FD_CLOEXEC as u64
        } else {
            0
        };

        let is_packet = local_socket_is_packet_type(local_socket_type(state, socket));
        let outcome = if is_packet {
            try_unix_recvmsg_dgram_to_reply(
                state, cli_handle, socket, flags, want_count, cloexec, reply,
            )
        } else {
            try_unix_recvmsg_stream_to_reply(
                state, cli_handle, socket, flags, want_count, cloexec, reply,
            )
        };
        match outcome {
            TryOutcome::Filled => {}
            TryOutcome::WouldBlock => {
                if nonblocking {
                    (*reply).label = TRONA_WOULD_BLOCK;
                    (*reply).length = 0;
                    return;
                }
                let kind = if is_packet {
                    UNIX_OP_RECVMSG_DGRAM
                } else {
                    UNIX_OP_RECVMSG_STREAM
                };
                let ctx = DeferContext {
                    client: cli_handle,
                    socket,
                    target: UnixSocketHandle::INVALID,
                    source_name_vnode: crate::vfs_core::vnode::VnodeHandle::INVALID,
                    source_path: &[],
                    source_abstract_name: &[],
                    want_count,
                    data: &[],
                    fd_numbers: &[],
                    msg_flags: flags,
                    msg_aux: cloexec,
                };
                defer_unix_socket_op(state, kind, ctx, reply);
            }
        }
    }
}

pub(crate) unsafe fn handle_socket_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let domain = (*msg).regs[0] as i32;
        let sock_type = (*msg).regs[1] as i32;
        let protocol = (*msg).regs[2] as i32;
        if domain == AF_UNIX {
            if (sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM && sock_type != SOCK_SEQPACKET)
                || protocol != 0
            {
                (*reply).label = TRONA_PROTO_NOT_SUPPORTED;
                (*reply).length = 0;
                return;
            }
            let Some(socket) = state.alloc_unix_socket() else {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return;
            };
            if let Some(sock) = state.unix_socket_state_mut(socket) {
                sock.socket_type = sock_type as u16;
            }
            let Some(fd) = state.alloc_unix_socket_client_slot(cli_handle, socket, O_RDWR) else {
                let _ = state.unix_sockets.release(socket);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return;
            };
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = fd as u64;
            return;
        }
        if domain != AF_INET {
            (*reply).label = TRONA_PROTO_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if crate::netsrv_ep() == 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_SOCKET;
        req.length = 2;
        req.regs[0] = sock_type as u64;
        req.regs[1] = protocol as u64;
        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        if resp.label != TRONA_OK {
            (*reply).label = resp.label;
            (*reply).length = 0;
            return;
        }

        let conn_id = resp.regs[0] as u32;
        let Some(fd) = state.alloc_socket_client_slot(cli_handle, conn_id, 0) else {
            let mut close_req = TronaMsg::zeroed();
            let mut close_resp = TronaMsg::zeroed();
            close_req.label = NET_CLOSE;
            close_req.length = 1;
            close_req.regs[0] = conn_id as u64;
            let _ = netsrv_call(&raw const close_req, &raw mut close_resp);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

pub(crate) unsafe fn handle_bind_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, _)) = local_socket_fd_view(state, cli_handle, fd) {
            let mut raw_path = [0u8; MAX_PATH_LEN];
            let mut abs_path = [0u8; MAX_PATH_LEN];
            let mut abstract_name = [0u8; UNIX_SOCKET_ADDR_MAX];
            let Some(addr_kind) =
                extract_local_addr_from_msg(msg, 1, 2, &mut raw_path, &mut abstract_name)
            else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            if let Some(sock) = state.unix_socket_state(socket) {
                if sock.bound_vnode.is_valid() || sock.bound_abstract_len != 0 {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return;
                }
                if sock.listener != 0
                    || (sock.peer.is_valid()
                        && local_socket_is_connection_oriented(sock.socket_type as i32))
                {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return;
                }
            }
            match addr_kind {
                LocalSocketAddrKind::Path(raw_len) => {
                    let Some(path_len) = normalize_path_owned(
                        state,
                        cli_handle,
                        raw_path.as_ptr(),
                        raw_len as u8,
                        abs_path.as_mut_ptr(),
                    ) else {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        (*reply).length = 0;
                        return;
                    };
                    if path_len > UNIX_SOCKET_ADDR_MAX {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        (*reply).length = 0;
                        return;
                    }
                    let abs_path = &abs_path[..path_len];
                    let vh = match state.bootstrap_create_socket_path_for_personality(
                        abs_path,
                        (S_IFSOCK as u32) | 0o777,
                        state.client_personality(cli_handle),
                    ) {
                        Ok(vh) => vh,
                        Err(TRONA_ALREADY_EXISTS) => {
                            (*reply).label = TRONA_ADDR_IN_USE;
                            (*reply).length = 0;
                            return;
                        }
                        Err(err) => {
                            (*reply).label = err;
                            (*reply).length = 0;
                            return;
                        }
                    };
                    if !state.retain_socket_name_vnode(vh) {
                        let _ = state.bootstrap_remove_path(abs_path, false);
                        (*reply).label = TRONA_OUT_OF_MEMORY;
                        (*reply).length = 0;
                        return;
                    }
                    let Some(sock) = state.unix_socket_state_mut(socket) else {
                        state.release_socket_name_vnode(vh);
                        let _ = state.bootstrap_remove_path(abs_path, false);
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        (*reply).length = 0;
                        return;
                    };
                    sock.bound_vnode = vh;
                    sock.bound_path_len = path_len as u8;
                    sock.bound_path[..path_len].copy_from_slice(abs_path);
                    sock.bound_abstract_len = 0;
                }
                LocalSocketAddrKind::Abstract(name_len) => {
                    if name_len == 0
                        || local_socket_bound_handle_abstract(state, &abstract_name[..name_len])
                            .is_some()
                    {
                        (*reply).label = if name_len == 0 {
                            TRONA_INVALID_ARGUMENT
                        } else {
                            TRONA_ADDR_IN_USE
                        };
                        (*reply).length = 0;
                        return;
                    }
                    let Some(sock) = state.unix_socket_state_mut(socket) else {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        (*reply).length = 0;
                        return;
                    };
                    sock.bound_vnode = crate::vfs_core::vnode::VnodeHandle::INVALID;
                    sock.bound_path_len = 0;
                    sock.bound_abstract_len = name_len as u8;
                    sock.bound_abstract_name[..name_len]
                        .copy_from_slice(&abstract_name[..name_len]);
                }
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
            return;
        }
        let family = (*msg).regs[1] as i32;
        if family != AF_INET {
            (*reply).label = TRONA_PROTO_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_BIND;
        req.length = 3;
        req.regs[0] = conn_id as u64;
        req.regs[1] = (*msg).regs[2];
        req.regs[2] = (*msg).regs[3];
        let err = netsrv_call(&raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        };
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_listen_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, _)) = local_socket_fd_view(state, cli_handle, fd) {
            let backlog = (*msg).regs[1].clamp(1, UNIX_SOCKET_ACCEPT_CAP as u64) as u16;
            let Some(sock) = state.unix_socket_state_mut(socket) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            if !local_socket_is_connection_oriented(sock.socket_type as i32) {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return;
            }
            if (!sock.bound_vnode.is_valid() && sock.bound_abstract_len == 0)
                || sock.peer.is_valid()
            {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return;
            }
            sock.listener = 1;
            sock.listener_backlog = backlog;
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_LISTEN;
        req.length = 2;
        req.regs[0] = conn_id as u64;
        req.regs[1] = (*msg).regs[1];
        let err = netsrv_call(&raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        };
        (*reply).length = 0;
    }
}

/// Try-once kernel for the Unix listener accept path. WouldBlock when
/// the pending_accept queue is empty and the listener is otherwise
/// healthy. Filled on success (new fd allocated for the client) or any
/// terminal error. The fd-alloc rollback path here is identical to the
/// original spinning version, including peer_closed = 1 on the peer
/// when fd-alloc OOMs after the queue was already drained.
pub(crate) unsafe fn try_unix_accept_to_reply(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    socket: UnixSocketHandle,
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let accepted = {
            let Some(listener) = state.unix_socket_state_mut(socket) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return TryOutcome::Filled;
            };
            if listener.listener == 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
            if listener.pending_accept_count == 0 {
                return TryOutcome::WouldBlock;
            }
            let handle = listener.pending_accept[listener.pending_accept_head as usize];
            listener.pending_accept[listener.pending_accept_head as usize] =
                UnixSocketHandle::INVALID;
            listener.pending_accept_head = (listener.pending_accept_head as usize + 1)
                .wrapping_rem(UNIX_SOCKET_ACCEPT_CAP)
                as u8;
            listener.pending_accept_count = listener.pending_accept_count.saturating_sub(1);
            handle
        };
        let Some(new_fd) = state.alloc_unix_socket_client_slot(cli_handle, accepted, O_RDWR) else {
            let (peer, bound_vnode, peer_name_vnode) = state
                .unix_socket_state(accepted)
                .map(|sock| (sock.peer, sock.bound_vnode, sock.peer_name_vnode))
                .unwrap_or((
                    UnixSocketHandle::INVALID,
                    crate::vfs_core::vnode::VnodeHandle::INVALID,
                    crate::vfs_core::vnode::VnodeHandle::INVALID,
                ));
            if peer.is_valid() {
                if let Some(peer_sock) = state.unix_socket_state_mut(peer) {
                    peer_sock.peer_closed = 1;
                }
            }
            if bound_vnode.is_valid() {
                state.release_socket_name_vnode(bound_vnode);
            }
            if peer_name_vnode.is_valid() && peer_name_vnode != bound_vnode {
                state.release_socket_name_vnode(peer_name_vnode);
            }
            let _ = state.unix_sockets.release(accepted);
            // The peer_closed mark we just set may unblock a parked
            // peer waiter. Drive once to surface that synchronously.
            crate::fileops::socket_wait::drive_unix_socket_waiters(state);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_fd as u64;
        TryOutcome::Filled
    }
}

pub(crate) unsafe fn handle_accept_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, flags)) = local_socket_fd_view(state, cli_handle, fd) {
            match try_unix_accept_to_reply(state, cli_handle, socket, reply) {
                TryOutcome::Filled => {}
                TryOutcome::WouldBlock => {
                    if (flags & O_NONBLOCK) != 0 {
                        (*reply).label = TRONA_WOULD_BLOCK;
                        (*reply).length = 0;
                        return;
                    }
                    let ctx = DeferContext::for_read(cli_handle, socket, 0);
                    defer_unix_socket_op(state, UNIX_OP_ACCEPT, ctx, reply);
                }
            }
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let nonblocking = socket_nonblocking(state, cli_handle, fd);
        handle_inet_accept(state, cli_handle, conn_id, nonblocking, reply);
    }
}

/// Single-shot NET_ACCEPT attempt, mirroring the Filled/WouldBlock
/// contract used by `try_inet_recv_once`. On success the new conn_id
/// is allocated to a client fd; on failure we tell netsrv to close the
/// orphan and surface OOM.
unsafe fn try_inet_accept_once(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    conn_id: u32,
    reply: *mut TronaMsg,
) -> Option<()> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_ACCEPT;
        req.length = 1;
        req.regs[0] = conn_id as u64;
        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return Some(());
        }
        if resp.label == TRONA_PENDING {
            return None;
        }
        if resp.label != TRONA_OK {
            (*reply).label = resp.label;
            (*reply).length = 0;
            return Some(());
        }

        let new_conn_id = resp.regs[0] as u32;
        let Some(new_fd) = state.alloc_socket_client_slot(cli_handle, new_conn_id, 0) else {
            let mut close_req = TronaMsg::zeroed();
            let mut close_resp = TronaMsg::zeroed();
            close_req.label = NET_CLOSE;
            close_req.length = 1;
            close_req.regs[0] = new_conn_id as u64;
            let _ = netsrv_call(&raw const close_req, &raw mut close_resp);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return Some(());
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_fd as u64;
        Some(())
    }
}

unsafe fn handle_inet_accept(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    conn_id: u32,
    nonblocking: bool,
    reply: *mut TronaMsg,
) {
    unsafe {
        if try_inet_accept_once(state, cli_handle, conn_id, reply).is_some() {
            return;
        }
        if nonblocking {
            (*reply).label = TRONA_WOULD_BLOCK;
            (*reply).length = 0;
            return;
        }
        match defer_inet_op(state, cli_handle, conn_id, INET_OP_ACCEPT, 0, 0, reply) {
            Some(true) => {
                arm_or_cancel_head(state, conn_id, INET_OP_ACCEPT);
            }
            Some(false) => {}
            None => {}
        }
    }
}

pub(crate) unsafe fn handle_connect_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, flags)) = local_socket_fd_view(state, cli_handle, fd) {
            let mut raw_path = [0u8; MAX_PATH_LEN];
            let mut abs_path = [0u8; MAX_PATH_LEN];
            let mut target_abstract_name = [0u8; UNIX_SOCKET_ADDR_MAX];
            let mut target_path = [0u8; UNIX_SOCKET_ADDR_MAX];
            let (target_vnode, target_path_len, target_abstract_len) =
                match extract_local_addr_from_msg(
                    msg,
                    1,
                    2,
                    &mut raw_path,
                    &mut target_abstract_name,
                ) {
                    Some(LocalSocketAddrKind::Path(raw_len)) => {
                        let Some(path_len) = normalize_path_owned(
                            state,
                            cli_handle,
                            raw_path.as_ptr(),
                            raw_len as u8,
                            abs_path.as_mut_ptr(),
                        ) else {
                            (*reply).label = TRONA_INVALID_ARGUMENT;
                            (*reply).length = 0;
                            return;
                        };
                        if path_len > UNIX_SOCKET_ADDR_MAX {
                            (*reply).label = TRONA_INVALID_ARGUMENT;
                            (*reply).length = 0;
                            return;
                        }
                        let abs_path = &abs_path[..path_len];
                        let target_vnode = match state
                            .lookup_path_dynamic_for_client(cli_handle, abs_path, false)
                        {
                            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
                            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                                (*reply).label = TRONA_NOT_FOUND;
                                (*reply).length = 0;
                                return;
                            }
                            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(_op_id)) => {
                                (*reply).label = TRONA_CONN_REFUSED;
                                (*reply).length = 0;
                                return;
                            }
                            Err(err) => {
                                (*reply).label = err;
                                (*reply).length = 0;
                                return;
                            }
                        };
                        target_path[..path_len].copy_from_slice(abs_path);
                        (target_vnode, path_len, 0usize)
                    }
                    Some(LocalSocketAddrKind::Abstract(name_len)) => {
                        if name_len == 0 {
                            (*reply).label = TRONA_INVALID_ARGUMENT;
                            (*reply).length = 0;
                            return;
                        }
                        (
                            crate::vfs_core::vnode::VnodeHandle::INVALID,
                            0usize,
                            name_len,
                        )
                    }
                    None => {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        (*reply).length = 0;
                        return;
                    }
                };
            let socket_type = local_socket_type(state, socket);
            if let Some(sock) = state.unix_socket_state(socket) {
                if sock.listener != 0 {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return;
                }
                if local_socket_is_connection_oriented(socket_type) && sock.peer.is_valid() {
                    (*reply).label = TRONA_IS_CONNECTED;
                    (*reply).length = 0;
                    return;
                }
            }

            if socket_type == SOCK_DGRAM {
                let target = if target_abstract_len != 0 {
                    local_socket_bound_handle_abstract(
                        state,
                        &target_abstract_name[..target_abstract_len],
                    )
                } else {
                    local_socket_bound_handle(state, target_vnode)
                };
                let Some(target) = target else {
                    (*reply).label = TRONA_CONN_REFUSED;
                    (*reply).length = 0;
                    return;
                };
                let Some(target_state) = state.unix_socket_state(target) else {
                    (*reply).label = TRONA_CONN_REFUSED;
                    (*reply).length = 0;
                    return;
                };
                if target_state.listener != 0 || target_state.socket_type as i32 != SOCK_DGRAM {
                    (*reply).label = TRONA_CONN_REFUSED;
                    (*reply).length = 0;
                    return;
                }
                let old_peer_name = state
                    .unix_socket_state(socket)
                    .map(|sock| sock.peer_name_vnode)
                    .unwrap_or(crate::vfs_core::vnode::VnodeHandle::INVALID);
                let old_peer_abstract_len = state
                    .unix_socket_state(socket)
                    .map(|sock| sock.peer_name_abstract_len as usize)
                    .unwrap_or(0);
                let needs_new_ref = target_vnode.is_valid() && old_peer_name != target_vnode;
                if needs_new_ref && !state.retain_socket_name_vnode(target_vnode) {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                    return;
                }
                if let Some(client_sock) = state.unix_socket_state_mut(socket) {
                    client_sock.peer = target;
                    client_sock.peer_closed = 0;
                    client_sock.shut_rd = 0;
                    client_sock.shut_wr = 0;
                    client_sock.peer_name_vnode = target_vnode;
                    client_sock.peer_name_path_len = target_path_len as u8;
                    if target_path_len != 0 {
                        client_sock.peer_name_path[..target_path_len]
                            .copy_from_slice(&target_path[..target_path_len]);
                    }
                    client_sock.peer_name_abstract_len = target_abstract_len as u8;
                    if target_abstract_len != 0 {
                        client_sock.peer_name_abstract_name[..target_abstract_len]
                            .copy_from_slice(&target_abstract_name[..target_abstract_len]);
                        client_sock.peer_name_path_len = 0;
                    } else {
                        client_sock.peer_name_abstract_len = 0;
                    }
                }
                if old_peer_name.is_valid() && old_peer_name != target_vnode {
                    state.release_socket_name_vnode(old_peer_name);
                }
                if old_peer_abstract_len != 0 && target_abstract_len == 0 {
                    if let Some(client_sock) = state.unix_socket_state_mut(socket) {
                        client_sock.peer_name_abstract_len = 0;
                    }
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 0;
                return;
            }
            // Stream / seqpacket connect: parked as UNIX_OP_CONNECT_STREAM
            // when the listener's backlog is full. The waiter does NOT
            // pre-allocate the accepted socket; allocation happens when
            // backlog space is observed in `try_unix_connect_stream_to_reply`.
            match try_unix_connect_stream_to_reply(
                state,
                socket,
                UnixSocketHandle::INVALID,
                target_vnode,
                &target_path,
                target_path_len,
                &target_abstract_name,
                target_abstract_len,
                socket_type,
                reply,
            ) {
                TryOutcome::Filled => {}
                TryOutcome::WouldBlock => {
                    if (flags & O_NONBLOCK) != 0 {
                        (*reply).label = TRONA_WOULD_BLOCK;
                        (*reply).length = 0;
                        return;
                    }
                    // Park: target identity is preserved on the waiter
                    // via source_name_vnode + source_abstract_name; the
                    // socket_type is stashed in msg_flags so drive can
                    // resolve the listener again after backlog drains.
                    if target_vnode.is_valid() && !state.retain_socket_name_vnode(target_vnode) {
                        (*reply).label = TRONA_OUT_OF_MEMORY;
                        (*reply).length = 0;
                        return;
                    }
                    let ctx = DeferContext {
                        client: cli_handle,
                        socket,
                        target: UnixSocketHandle::INVALID,
                        source_name_vnode: target_vnode,
                        source_path: &target_path[..target_path_len],
                        source_abstract_name: &target_abstract_name[..target_abstract_len],
                        want_count: 0,
                        data: &[],
                        fd_numbers: &[],
                        msg_flags: socket_type,
                        msg_aux: 0,
                    };
                    if !defer_unix_socket_op(state, UNIX_OP_CONNECT_STREAM, ctx, reply) {
                        if target_vnode.is_valid() {
                            state.release_socket_name_vnode(target_vnode);
                        }
                    }
                }
            }
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let nonblocking = socket_nonblocking(state, cli_handle, fd);
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_CONNECT;
        req.length = 3;
        req.regs[0] = conn_id as u64;
        req.regs[1] = (*msg).regs[1];
        req.regs[2] = (*msg).regs[2];
        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        if resp.label == TRONA_PENDING {
            if nonblocking {
                (*reply).label = TRONA_IN_PROGRESS;
                (*reply).length = 0;
                return;
            }
            // Park the saved caller. NET_CONNECT itself sets
            // pending_connect on the netsrv side, so no NET_*_WAIT arm
            // is required — completion arrives via NET_COMPLETE with
            // INET_OP_CONNECT.
            match defer_inet_op(state, cli_handle, conn_id, INET_OP_CONNECT, 0, 0, reply) {
                Some(_) => {}
                None => {}
            }
            return;
        }
        (*reply).label = resp.label;
        (*reply).length = 0;
    }
}

/// Try-once kernel for AF_UNIX stream/seqpacket connect against a
/// listening peer. WouldBlock when the listener exists but its
/// pending_accept queue is full. Filled on success (peer linkage
/// established, listener queue extended) or any terminal error
/// (TRONA_CONN_REFUSED, TRONA_OUT_OF_MEMORY).
///
/// The `target_vnode` + `target_abstract_name` pair re-identifies the
/// listening socket by name so the helper can be re-invoked from
/// `drive_unix_socket_waiters` after the listener drains an accept
/// slot. `socket_type` discriminates SOCK_STREAM vs SOCK_SEQPACKET so
/// the typed lookup picks the correct listener.
pub(crate) unsafe fn try_unix_connect_stream_to_reply(
    state: &mut VfsState,
    socket: UnixSocketHandle,
    _ignored_target: UnixSocketHandle,
    target_vnode: crate::vfs_core::vnode::VnodeHandle,
    target_path: &[u8],
    target_path_len: usize,
    target_abstract_name: &[u8],
    target_abstract_len: usize,
    socket_type: i32,
    reply: *mut TronaMsg,
) -> TryOutcome {
    unsafe {
        let target_path_len = core::cmp::min(
            core::cmp::min(target_path_len, target_path.len()),
            UNIX_SOCKET_ADDR_MAX,
        );
        let target_abstract_len = core::cmp::min(
            core::cmp::min(target_abstract_len, target_abstract_name.len()),
            UNIX_SOCKET_ADDR_MAX,
        );
        let listener = if target_abstract_len != 0 {
            local_listener_bound_handle_abstract_typed(
                state,
                &target_abstract_name[..target_abstract_len],
                socket_type,
            )
        } else {
            local_listener_bound_handle_typed(state, target_vnode, socket_type)
        };
        let Some(listener) = listener else {
            (*reply).label = TRONA_CONN_REFUSED;
            (*reply).length = 0;
            return TryOutcome::Filled;
        };

        // Backlog precheck — if the queue is full we park without
        // touching state. Pre-allocating an `accepted` socket and then
        // releasing it on each retry would have been wasted work.
        let backlog_full = state
            .unix_socket_state(listener)
            .map(|listener_state| {
                listener_state.listener == 0
                    || listener_state.pending_accept_count >= listener_state.listener_backlog as u8
            })
            .unwrap_or(true);
        if backlog_full {
            // Distinguish "listener vanished" (terminal CONN_REFUSED)
            // from "queue is full" (WouldBlock).
            let listener_alive = state
                .unix_socket_state(listener)
                .map(|listener_state| listener_state.listener != 0)
                .unwrap_or(false);
            if !listener_alive {
                (*reply).label = TRONA_CONN_REFUSED;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
            return TryOutcome::WouldBlock;
        }

        let accepted = match state.alloc_unix_socket() {
            Some(handle) => handle,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
        };
        let queue_idx = {
            let Some(listener_state) = state.unix_socket_state_mut(listener) else {
                let _ = state.unix_sockets.release(accepted);
                (*reply).label = TRONA_CONN_REFUSED;
                (*reply).length = 0;
                return TryOutcome::Filled;
            };
            if listener_state.listener == 0 {
                let _ = state.unix_sockets.release(accepted);
                (*reply).label = TRONA_CONN_REFUSED;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
            // Re-check backlog with the mutable borrow held — could
            // race with a concurrent connect on a different waiter
            // having drained the queue between the precheck and now.
            if listener_state.pending_accept_count >= listener_state.listener_backlog as u8 {
                let _ = state.unix_sockets.release(accepted);
                return TryOutcome::WouldBlock;
            }
            let idx = listener_state.pending_accept_tail as usize;
            listener_state.pending_accept_tail = (listener_state.pending_accept_tail as usize + 1)
                .wrapping_rem(UNIX_SOCKET_ACCEPT_CAP)
                as u8;
            listener_state.pending_accept_count =
                listener_state.pending_accept_count.saturating_add(1);
            idx
        };
        if target_vnode.is_valid() {
            if !state.retain_socket_name_vnode(target_vnode) {
                let _ = state.unix_sockets.release(accepted);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
            if !state.retain_socket_name_vnode(target_vnode) {
                state.release_socket_name_vnode(target_vnode);
                let _ = state.unix_sockets.release(accepted);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return TryOutcome::Filled;
            }
        }
        let client_bound_vnode = state
            .unix_socket_state(socket)
            .map(|sock| sock.bound_vnode)
            .unwrap_or(crate::vfs_core::vnode::VnodeHandle::INVALID);
        let (
            client_bound_path,
            client_bound_path_len,
            client_bound_abstract_name,
            client_bound_abstract_len,
        ) = state
            .unix_socket_state(socket)
            .map(|sock| {
                (
                    sock.bound_path,
                    sock.bound_path_len as usize,
                    sock.bound_abstract_name,
                    sock.bound_abstract_len as usize,
                )
            })
            .unwrap_or(([0; UNIX_SOCKET_ADDR_MAX], 0, [0; UNIX_SOCKET_ADDR_MAX], 0));
        if client_bound_vnode.is_valid() && !state.retain_socket_name_vnode(client_bound_vnode) {
            if target_vnode.is_valid() {
                state.release_socket_name_vnode(target_vnode);
                state.release_socket_name_vnode(target_vnode);
            }
            let _ = state.unix_sockets.release(accepted);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return TryOutcome::Filled;
        }
        if let Some(client_sock) = state.unix_socket_state_mut(socket) {
            client_sock.peer = accepted;
            client_sock.peer_closed = 0;
            client_sock.shut_rd = 0;
            client_sock.shut_wr = 0;
            client_sock.peer_name_vnode = target_vnode;
            client_sock.peer_name_path_len = target_path_len as u8;
            if target_path_len != 0 {
                client_sock.peer_name_path[..target_path_len]
                    .copy_from_slice(&target_path[..target_path_len]);
            }
            client_sock.peer_name_abstract_len = target_abstract_len as u8;
            if target_abstract_len != 0 {
                client_sock.peer_name_abstract_name[..target_abstract_len]
                    .copy_from_slice(&target_abstract_name[..target_abstract_len]);
                client_sock.peer_name_path_len = 0;
            } else {
                client_sock.peer_name_abstract_len = 0;
            }
        }
        if let Some(server_sock) = state.unix_socket_state_mut(accepted) {
            server_sock.peer = socket;
            server_sock.bound_vnode = target_vnode;
            server_sock.peer_name_vnode = client_bound_vnode;
            server_sock.bound_path_len = target_path_len as u8;
            if target_path_len != 0 {
                server_sock.bound_path[..target_path_len]
                    .copy_from_slice(&target_path[..target_path_len]);
            }
            server_sock.bound_abstract_len = target_abstract_len as u8;
            if target_abstract_len != 0 {
                server_sock.bound_abstract_name[..target_abstract_len]
                    .copy_from_slice(&target_abstract_name[..target_abstract_len]);
                server_sock.bound_path_len = 0;
            }
            server_sock.peer_name_path_len = client_bound_path_len as u8;
            if client_bound_path_len != 0 {
                server_sock.peer_name_path[..client_bound_path_len]
                    .copy_from_slice(&client_bound_path[..client_bound_path_len]);
            }
            server_sock.peer_name_abstract_len = client_bound_abstract_len as u8;
            if client_bound_abstract_len != 0 {
                server_sock.peer_name_abstract_name[..client_bound_abstract_len]
                    .copy_from_slice(&client_bound_abstract_name[..client_bound_abstract_len]);
                server_sock.peer_name_path_len = 0;
            }
            server_sock.socket_type = socket_type as u16;
        }
        if let Some(listener_state) = state.unix_socket_state_mut(listener) {
            listener_state.pending_accept[queue_idx] = accepted;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
        TryOutcome::Filled
    }
}

pub(crate) unsafe fn handle_shutdown_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, _)) = local_socket_fd_view(state, cli_handle, fd) {
            let how = (*msg).regs[1] as i32;
            let Some(sock_state) = state.unix_socket_state(socket) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            };
            let socket_type = sock_state.socket_type as i32;
            if sock_state.listener != 0 || !sock_state.peer.is_valid() {
                (*reply).label = TRONA_NOT_CONNECTED;
                (*reply).length = 0;
                return;
            }
            let peer = Some(sock_state.peer);
            match how {
                SHUT_RD => {
                    if let Some(sock) = state.unix_socket_state_mut(socket) {
                        sock.shut_rd = 1;
                    }
                }
                SHUT_WR => {
                    if let Some(sock) = state.unix_socket_state_mut(socket) {
                        sock.shut_wr = 1;
                    }
                    if local_socket_is_connection_oriented(socket_type) {
                        if let Some(peer_handle) = peer {
                            if let Some(peer_sock) = state.unix_socket_state_mut(peer_handle) {
                                peer_sock.peer_closed = 1;
                            }
                        }
                    }
                }
                SHUT_RDWR => {
                    if let Some(sock) = state.unix_socket_state_mut(socket) {
                        sock.shut_rd = 1;
                        sock.shut_wr = 1;
                    }
                    if local_socket_is_connection_oriented(socket_type) {
                        if let Some(peer_handle) = peer {
                            if let Some(peer_sock) = state.unix_socket_state_mut(peer_handle) {
                                peer_sock.peer_closed = 1;
                            }
                        }
                    }
                }
                _ => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                }
            }
            // SHUT_WR / SHUT_RDWR may have just woken peer waiters
            // (their stream-read returns 0-byte EOF, their stream-write
            // returns TRONA_NOT_CONNECTED). Drive once so the wakeup
            // ride along with our reply rather than waiting for the
            // next outer drive trigger.
            crate::fileops::socket_wait::drive_unix_socket_waiters(state);
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_SHUTDOWN;
        req.length = 2;
        req.regs[0] = conn_id as u64;
        req.regs[1] = (*msg).regs[1];
        let err = netsrv_call(&raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        };
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_getsockname_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, _)) = local_socket_fd_view(state, cli_handle, fd) {
            let (vnode, path_len, path, abstract_len, abstract_name) = state
                .unix_socket_state(socket)
                .map(|sock| {
                    (
                        sock.bound_vnode,
                        sock.bound_path_len as usize,
                        sock.bound_path,
                        sock.bound_abstract_len as usize,
                        sock.bound_abstract_name,
                    )
                })
                .unwrap_or((
                    crate::vfs_core::vnode::VnodeHandle::INVALID,
                    0usize,
                    [0; UNIX_SOCKET_ADDR_MAX],
                    0usize,
                    [0; UNIX_SOCKET_ADDR_MAX],
                ));
            fill_local_sockaddr_reply(
                state,
                vnode,
                path_len,
                &path,
                abstract_len,
                &abstract_name,
                reply,
            );
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_GETSOCKNAME;
        req.length = 1;
        req.regs[0] = conn_id as u64;
        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        (*reply).label = resp.label;
        if resp.label == TRONA_OK {
            (*reply).length = 2;
            (*reply).regs[0] = resp.regs[0];
            (*reply).regs[1] = resp.regs[1];
        } else {
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_getpeername_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, _)) = local_socket_fd_view(state, cli_handle, fd) {
            let (vnode, path_len, path, abstract_len, abstract_name, peer_valid) = state
                .unix_socket_state(socket)
                .map(|sock| {
                    let (
                        peer_bound,
                        peer_path_len,
                        peer_path,
                        peer_abstract_len,
                        peer_abstract_name,
                    ) = if sock.peer.is_valid() {
                        state
                            .unix_socket_state(sock.peer)
                            .map(|peer| {
                                (
                                    peer.bound_vnode,
                                    peer.bound_path_len as usize,
                                    peer.bound_path,
                                    peer.bound_abstract_len as usize,
                                    peer.bound_abstract_name,
                                )
                            })
                            .unwrap_or((
                                crate::vfs_core::vnode::VnodeHandle::INVALID,
                                0usize,
                                [0; UNIX_SOCKET_ADDR_MAX],
                                0usize,
                                [0; UNIX_SOCKET_ADDR_MAX],
                            ))
                    } else {
                        (
                            crate::vfs_core::vnode::VnodeHandle::INVALID,
                            0usize,
                            [0; UNIX_SOCKET_ADDR_MAX],
                            0usize,
                            [0; UNIX_SOCKET_ADDR_MAX],
                        )
                    };
                    (
                        if sock.peer_name_abstract_len != 0 {
                            crate::vfs_core::vnode::VnodeHandle::INVALID
                        } else if sock.peer_name_vnode.is_valid() {
                            sock.peer_name_vnode
                        } else {
                            peer_bound
                        },
                        if sock.peer_name_abstract_len != 0 {
                            0usize
                        } else if sock.peer_name_path_len != 0 {
                            sock.peer_name_path_len as usize
                        } else {
                            peer_path_len
                        },
                        if sock.peer_name_abstract_len != 0 {
                            [0; UNIX_SOCKET_ADDR_MAX]
                        } else if sock.peer_name_path_len != 0 {
                            sock.peer_name_path
                        } else {
                            peer_path
                        },
                        if sock.peer_name_abstract_len != 0 {
                            sock.peer_name_abstract_len as usize
                        } else {
                            peer_abstract_len
                        },
                        if sock.peer_name_abstract_len != 0 {
                            sock.peer_name_abstract_name
                        } else {
                            peer_abstract_name
                        },
                        sock.peer.is_valid(),
                    )
                })
                .unwrap_or((
                    crate::vfs_core::vnode::VnodeHandle::INVALID,
                    0usize,
                    [0; UNIX_SOCKET_ADDR_MAX],
                    0usize,
                    [0; UNIX_SOCKET_ADDR_MAX],
                    false,
                ));
            if !vnode.is_valid() && path_len == 0 && abstract_len == 0 && !peer_valid {
                (*reply).label = TRONA_NOT_CONNECTED;
                (*reply).length = 0;
                return;
            }
            fill_local_sockaddr_reply(
                state,
                vnode,
                path_len,
                &path,
                abstract_len,
                &abstract_name,
                reply,
            );
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_GETPEERNAME;
        req.length = 1;
        req.regs[0] = conn_id as u64;
        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        (*reply).label = resp.label;
        if resp.label == TRONA_OK {
            (*reply).length = 2;
            (*reply).regs[0] = resp.regs[0];
            (*reply).regs[1] = resp.regs[1];
        } else {
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_setsockopt_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if local_socket_fd_view(state, cli_handle, fd).is_some() {
            if (*msg).regs[1] == SOL_SOCKET as u64 {
                match (*msg).regs[2] as i32 {
                    SO_ERROR | SO_SNDBUF | SO_RCVBUF | SO_REUSEADDR => {
                        (*reply).label = TRONA_OK;
                        (*reply).length = 0;
                        return;
                    }
                    _ => {}
                }
            }
            (*reply).label = TRONA_PROTO_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_SETSOCKOPT;
        req.length = 5;
        req.regs[0] = conn_id as u64;
        req.regs[1] = (*msg).regs[1];
        req.regs[2] = (*msg).regs[2];
        req.regs[3] = (*msg).regs[3];
        req.regs[4] = (*msg).regs[4];
        let err = netsrv_call(&raw const req, &raw mut resp);
        (*reply).label = if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        };
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_getsockopt_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, _)) = local_socket_fd_view(state, cli_handle, fd) {
            if (*msg).regs[1] == SOL_SOCKET as u64 {
                let (socket_type, acceptconn) = state
                    .unix_socket_state(socket)
                    .map(|sock| (sock.socket_type as u64, sock.listener as u64))
                    .unwrap_or((SOCK_STREAM as u64, 0));
                (*reply).label = TRONA_OK;
                (*reply).length = 2;
                (*reply).regs[1] = core::mem::size_of::<i32>() as u64;
                (*reply).regs[0] = match (*msg).regs[2] as i32 {
                    SO_TYPE => socket_type,
                    SO_ERROR => 0,
                    SO_REUSEADDR => 0,
                    SO_ACCEPTCONN => acceptconn,
                    SO_DOMAIN => AF_UNIX as u64,
                    SO_PROTOCOL => 0,
                    SO_SNDBUF | SO_RCVBUF => {
                        crate::server::unix_socket_object::UNIX_SOCKET_BUF_SIZE as u64
                    }
                    _ => {
                        (*reply).label = TRONA_PROTO_NOT_SUPPORTED;
                        (*reply).length = 0;
                        return;
                    }
                };
                return;
            }
            (*reply).label = TRONA_PROTO_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_GETSOCKOPT;
        req.length = 3;
        req.regs[0] = conn_id as u64;
        req.regs[1] = (*msg).regs[1];
        req.regs[2] = (*msg).regs[2];
        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        (*reply).label = resp.label;
        if resp.label == TRONA_OK {
            (*reply).length = 2;
            (*reply).regs[0] = resp.regs[0];
            (*reply).regs[1] = resp.regs[1];
        } else {
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_sockpair_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let domain = (*msg).regs[0] as i32;
        let sock_type = (*msg).regs[1] as i32;
        let protocol = (*msg).regs[2] as i32;
        if domain != AF_UNIX
            || (sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM && sock_type != SOCK_SEQPACKET)
            || protocol != 0
        {
            (*reply).label = TRONA_PROTO_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }

        let Some(left) = state.alloc_unix_socket() else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        let Some(right) = state.alloc_unix_socket() else {
            let _ = state.unix_sockets.release(left);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };

        if let Some(sock) = state.unix_socket_state_mut(left) {
            sock.peer = right;
            sock.socket_type = sock_type as u16;
        }
        if let Some(sock) = state.unix_socket_state_mut(right) {
            sock.peer = left;
            sock.socket_type = sock_type as u16;
        }

        let Some(left_fd) = state.alloc_unix_socket_client_slot(cli_handle, left, O_RDWR) else {
            let _ = state.unix_sockets.release(left);
            let _ = state.unix_sockets.release(right);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        let Some(right_fd) = state.alloc_unix_socket_client_slot(cli_handle, right, O_RDWR) else {
            let _ = state.release_client_slot(cli_handle, left_fd);
            let _ = state.unix_sockets.release(right);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 2;
        (*reply).regs[0] = left_fd as u64;
        (*reply).regs[1] = right_fd as u64;
    }
}

pub(crate) unsafe fn handle_socket_read_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, flags)) = local_socket_fd_view(state, cli_handle, fd) {
            handle_local_socket_read(
                state,
                cli_handle,
                socket,
                (flags & O_NONBLOCK) != 0,
                (*msg).regs[1] as usize,
                reply,
            );
            return true;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            return false;
        };
        let nonblocking = socket_nonblocking(state, cli_handle, fd);
        handle_inet_recv(
            state,
            cli_handle,
            conn_id,
            (*msg).regs[1] as u16,
            0,
            nonblocking,
            reply,
        );
        true
    }
}

pub(crate) unsafe fn handle_socket_write_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, flags)) = local_socket_fd_view(state, cli_handle, fd) {
            handle_local_socket_write(
                state,
                cli_handle,
                socket,
                (flags & O_NONBLOCK) != 0,
                msg,
                reply,
            );
            return true;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            return false;
        };
        let actual = core::cmp::min((*msg).regs[1] as usize, INLINE_SEND_MAX);
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = NET_SEND;
        req.length = 2 + ((actual as u64 + 7) / 8);
        req.regs[0] = conn_id as u64;
        req.regs[1] = actual as u64;
        if actual != 0 {
            let src = &raw const (*msg).regs[2] as *const u8;
            let dst = &raw mut req.regs[2] as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, actual);
        }
        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return true;
        }
        send_ok_or_error(reply, &resp);
        true
    }
}

pub(crate) unsafe fn handle_sendmsg_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, flags)) = local_socket_fd_view(state, cli_handle, fd) {
            handle_local_sendmsg(
                state,
                cli_handle,
                socket,
                (flags & O_NONBLOCK) != 0,
                msg,
                reply,
            );
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        if (*msg).regs[2] != 0 {
            (*reply).label = TRONA_PROTO_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }

        let data_len = (*msg).regs[1] as usize;
        let data_regs = ((*msg).regs[1] + 7) / 8;
        let is_sendto = (*msg).length == 5 + data_regs;
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();

        if is_sendto {
            let actual = core::cmp::min(data_len, INLINE_SENDTO_MAX);
            req.label = NET_SENDTO;
            req.length = 4 + ((actual as u64 + 7) / 8);
            req.regs[0] = conn_id as u64;
            req.regs[1] = (*msg).regs[3];
            req.regs[2] = (*msg).regs[4];
            req.regs[3] = actual as u64;
            if actual != 0 {
                let src = &raw const (*msg).regs[5] as *const u8;
                let dst = &raw mut req.regs[4] as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, actual);
            }
        } else {
            let actual = core::cmp::min(data_len, INLINE_SEND_MAX);
            req.label = NET_SEND;
            req.length = 2 + ((actual as u64 + 7) / 8);
            req.regs[0] = conn_id as u64;
            req.regs[1] = actual as u64;
            if actual != 0 {
                let src = &raw const (*msg).regs[3] as *const u8;
                let dst = &raw mut req.regs[2] as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, actual);
            }
        }

        let err = netsrv_call(&raw const req, &raw mut resp);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        send_ok_or_error(reply, &resp);
    }
}

pub(crate) unsafe fn handle_recvmsg_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if let Some((socket, flags)) = local_socket_fd_view(state, cli_handle, fd) {
            handle_local_recvmsg(
                state,
                cli_handle,
                socket,
                (flags & O_NONBLOCK) != 0,
                msg,
                reply,
            );
            return;
        }
        let Some(conn_id) = socket_conn_id(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let flags = (*msg).regs[2] as u32;
        let nonblocking = socket_nonblocking(state, cli_handle, fd);
        if (flags & INET_RECV_FLAG_WANT_ADDR) != 0 {
            handle_inet_recvfrom(
                state,
                cli_handle,
                conn_id,
                (*msg).regs[1] as u16,
                flags,
                nonblocking,
                reply,
            );
        } else {
            handle_inet_recv(
                state,
                cli_handle,
                conn_id,
                (*msg).regs[1] as u16,
                flags,
                nonblocking,
                reply,
            );
        }
    }
}

/// Backend RPC completion routing for netsrv non-wait sync ops.
///
/// Returns `true` only when this dispatcher has shipped the saved
/// reply. Returns `false` so the cascade falls through to the default
/// arm; per-op routing for `BACKEND_OP_NETSRV_*` (open / connect /
/// listen / bind / send / sendto / get_sockname / get_peername) lands
/// here.
pub(crate) unsafe fn complete_netsrv_op(
    _state: &mut VfsState,
    _completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    false
}
