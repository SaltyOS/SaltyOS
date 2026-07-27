// SPDX-License-Identifier: GPL-2.0-only
//! Socket lifecycle: socket, bind, listen, accept, connect, shutdown, sockpair, close.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_posix::types::*;
use trona_protocol::posix::posix::*;
use trona_protocol::posix::vfs::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, root_vnode_for};
use crate::owner::op::{OpCore, OpKind, OwnerPostOp};
use crate::personality::posix::consts::*;
use crate::personality::posix::types::*;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_WANTPARENT, NameiArgs};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::VT_SOCK;

use super::state::{alloc_socket, find_socket, release_socket};

fn find_listening_socket_by_bound_ino(
    state: &VfsState,
    bound_ino: u32,
) -> crate::arena::Handle<SocketState> {
    let mut found = crate::arena::Handle::<SocketState>::INVALID;
    state.sockets.for_each_active(|handle, socket| {
        if socket.active != 0 && socket.state == SOCK_LISTENING && socket.bound_ino == bound_ino {
            found = handle;
            false
        } else {
            true
        }
    });
    found
}

pub(crate) unsafe fn handle_socket(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let domain = (*msg).regs[0] as i32;
        let sock_type = (*msg).regs[1] as i32;
        let protocol = (*msg).regs[2] as i32;

        if domain == AF_INET {
            return super::super::inet::handle_inet_socket(
                state, cli_handle, msg, reply, sock_type, protocol,
            );
        }

        let Some(sock_handle) = alloc_socket(state) else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };
        let sock = find_socket(state, sock_handle);

        let Some(fd) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
            release_socket(state, sock_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        if let Some(obj) = state.open_object_at_mut(cli_handle, fd as usize) {
            obj.set_unix_socket(sock_handle);
            obj.offset = 0;
        } else {
            state.slot_release(cli_handle, fd as usize);
            release_socket(state, sock_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
        false
    }
}

pub(crate) unsafe fn handle_bind(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let socket_handle = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.kind() == ObjectKind::UnixSocket => obj.unix_socket_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let sock = find_socket(state, socket_handle);
        if sock.is_null() || (*sock).state != SOCK_UNBOUND {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let mut path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let root = root_vnode_for(state, cli_handle);
        let cred = VfsCred::root();

        let mut namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start: root,
            path: path.as_ptr(),
            path_len: raw_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT | NAMEI_CREATE,
            cred,
            root,
        };
        let ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &args) {
            Ok(r) => r,
            Err(_) => {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
        };

        if ni.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return false;
        }
        if !ni.dvp.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, ni.dvp) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_NOT_SUPPORTED;
                return false;
            }
        };
        let ops = &*(*ctx.vnode).ops;
        let new_vh = match (ops.meta.create)(
            &mut ctx,
            ni.last_name,
            ni.last_name_len,
            S_IFSOCK_L | 0o777,
            &raw const cred,
        ) {
            Ok(Ready(vh)) => vh,
            Ok(Parked(_)) => {
                (*reply).label = TRONA_BUSY;
                return false;
            }
            Err(_) => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        };

        if let Some(vn) = state.vnodes.get_mut(new_vh) {
            vn.vtype = VT_SOCK;
            (*sock).bound_ino = vn.id as u32;
        }
        (*sock).state = SOCK_BOUND;

        (*reply).label = TRONA_OK;
        false
    }
}

pub(crate) unsafe fn handle_listen(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let backlog = (*msg).regs[1] as u8;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let socket_handle = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.kind() == ObjectKind::UnixSocket => obj.unix_socket_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let sock = find_socket(state, socket_handle);
        if sock.is_null() || (*sock).state != SOCK_BOUND {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        (*sock).state = SOCK_LISTENING;
        (*sock).backlog = if backlog > (*sock).pending_cap {
            (*sock).pending_cap
        } else {
            backlog
        };
        (*reply).label = TRONA_OK;
        false
    }
}

pub(crate) unsafe fn handle_accept(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
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
        let socket_handle = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.kind() == ObjectKind::UnixSocket => obj.unix_socket_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let listen_sock = find_socket(state, socket_handle);
        if listen_sock.is_null() || (*listen_sock).state != SOCK_LISTENING {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // Check for pending connection
        for i in 0..(*listen_sock).pending_cap as usize {
            if (*(*listen_sock).pending.add(i)).active != 0 {
                let pend = *(*listen_sock).pending.add(i);
                (*(*listen_sock).pending.add(i)).active = 0;
                (*listen_sock).pending_count -= 1;

                let Some(srv_sock_handle) = alloc_socket(state) else {
                    if pend.op.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_OUT_OF_MEMORY;
                        state.complete_op(pend.op, OwnerPostOp::None, &raw const err_reply);
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                };
                let srv_sock = find_socket(state, srv_sock_handle);
                (*srv_sock).state = SOCK_CONNECTED;

                let cli_sock = find_socket(state, pend.socket);
                if cli_sock.is_null() {
                    release_socket(state, srv_sock_handle);
                    if pend.op.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_INVALID_OPERATION;
                        state.complete_op(pend.op, OwnerPostOp::None, &raw const err_reply);
                    }
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return false;
                }

                (*srv_sock).peer_socket = pend.socket;
                (*srv_sock).peer_badge = pend.client_badge;
                (*cli_sock).peer_socket = srv_sock_handle;
                (*cli_sock).peer_badge = badge;
                (*cli_sock).state = SOCK_CONNECTED;

                // Allocate fd for accepted socket
                let Some(new_fd) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
                    release_socket(state, srv_sock_handle);
                    if pend.op.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_OUT_OF_MEMORY;
                        state.complete_op(pend.op, OwnerPostOp::None, &raw const err_reply);
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                };

                if let Some(obj) = state.open_object_at_mut(cli_handle, new_fd as usize) {
                    obj.set_unix_socket(srv_sock_handle);
                } else {
                    state.slot_release(cli_handle, new_fd as usize);
                    release_socket(state, srv_sock_handle);
                    if pend.op.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_OUT_OF_MEMORY;
                        state.complete_op(pend.op, OwnerPostOp::None, &raw const err_reply);
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                }

                if pend.op.reply_slot != 0 {
                    let mut wake_reply = TronaMsg::zeroed();
                    wake_reply.label = TRONA_OK;
                    state.complete_op(pend.op, OwnerPostOp::None, &raw const wake_reply);
                }

                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = new_fd as u64;
                return false;
            }
        }

        // No pending — block accepter
        let op = match state.begin_op_for_client(cli_handle, OpKind::SocketAccept) {
            Ok(op) => op,
            Err(err) => {
                (*reply).label = err.to_trona();
                return false;
            }
        };
        (*listen_sock).accept_op = op;
        (*listen_sock).accept_badge = badge;
        true
    }
}

pub(crate) unsafe fn handle_connect(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
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
        let socket_handle = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.kind() == ObjectKind::UnixSocket => obj.unix_socket_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let cli_sock = find_socket(state, socket_handle);
        if cli_sock.is_null() || (*cli_sock).state != SOCK_UNBOUND {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // Resolve path to find listening socket
        let mut path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let root = root_vnode_for(state, cli_handle);
        let cred = VfsCred::root();

        let mut namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start: root,
            path: path.as_ptr(),
            path_len: raw_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };
        let ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &args) {
            Ok(r) => r,
            Err(_) => {
                (*reply).label = TRONA_NOT_FOUND;
                return false;
            }
        };

        if !ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        let bound_ino = match state.vnodes.get(ni.vp) {
            Some(vn) => {
                if vn.vtype != VT_SOCK {
                    (*reply).label = TRONA_NOT_FOUND;
                    return false;
                }
                vn.id as u32
            }
            None => {
                (*reply).label = TRONA_NOT_FOUND;
                return false;
            }
        };

        // Find listener by bound_ino
        let listen_handle = find_listening_socket_by_bound_ino(state, bound_ino);
        let listen_sock = find_socket(state, listen_handle);

        if listen_sock.is_null() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // If accepter is waiting, connect immediately
        if (*listen_sock).accept_op.reply_slot != 0 {
            let Some(srv_sock_handle) = alloc_socket(state) else {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            };
            let srv_sock = find_socket(state, srv_sock_handle);
            (*srv_sock).state = SOCK_CONNECTED;
            (*cli_sock).state = SOCK_CONNECTED;
            (*srv_sock).peer_socket = socket_handle;
            (*srv_sock).peer_badge = badge;
            (*cli_sock).peer_socket = srv_sock_handle;
            (*cli_sock).peer_badge = (*listen_sock).accept_badge;

            // Allocate fd for accepted socket on accepter's side
            let accept_badge = (*listen_sock).accept_badge;
            let accept_handle = match state.badge_map.lookup(accept_badge) {
                Some((slot, epoch)) => ClientHandle::new(slot, epoch),
                None => ClientHandle::new(0, 0),
            };
            let mut new_fd: i32 = -1;
            if let Some(fd_reserved) = state.reserve_fd_owned(accept_handle) {
                new_fd = fd_reserved;
                if let Some(obj) = state.open_object_at_mut(accept_handle, new_fd as usize) {
                    obj.set_unix_socket(srv_sock_handle);
                } else {
                    state.slot_release(accept_handle, new_fd as usize);
                    new_fd = -1;
                }
            }

            let mut wake_reply = TronaMsg::zeroed();
            wake_reply.label = TRONA_OK;
            wake_reply.length = 1;
            wake_reply.regs[0] = if new_fd >= 0 { new_fd as u64 } else { u64::MAX };
            state.complete_op(
                (*listen_sock).accept_op,
                OwnerPostOp::None,
                &raw const wake_reply,
            );
            (*listen_sock).accept_op = OpCore::INVALID;
            (*listen_sock).accept_badge = 0;

            (*reply).label = TRONA_OK;
            return false;
        }

        // Queue as pending
        if (*listen_sock).pending_count >= (*listen_sock).backlog {
            (*reply).label = TRONA_BUSY;
            return false;
        }

        let op = match state.begin_op_for_client(cli_handle, OpKind::SocketConnect) {
            Ok(op) => op,
            Err(err) => {
                (*reply).label = err.to_trona();
                return false;
            }
        };

        (*cli_sock).state = SOCK_CONNECTING;
        for i in 0..(*listen_sock).pending_cap as usize {
            if (*(*listen_sock).pending.add(i)).active == 0 {
                (*(*listen_sock).pending.add(i)).active = 1;
                (*(*listen_sock).pending.add(i)).client_badge = badge;
                (*(*listen_sock).pending.add(i)).socket = socket_handle;
                (*(*listen_sock).pending.add(i)).op = op;
                (*listen_sock).pending_count += 1;
                break;
            }
        }

        true
    }
}

pub(crate) unsafe fn handle_shutdown(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let how = (*msg).regs[1] as i32;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let socket_handle = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) if obj.kind() == ObjectKind::UnixSocket => obj.unix_socket_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let sock = find_socket(state, socket_handle);
        if sock.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        if how == 0 || how == 2 {
            (*sock).shut_rd = 1;
        }
        if how == 1 || how == 2 {
            (*sock).shut_wr = 1;
            if (*sock).peer_socket.is_valid() {
                let peer = find_socket(state, (*sock).peer_socket);
                if !peer.is_null() {
                    (*peer).peer_closed = 1;
                    if (*peer).recv_op.reply_slot != 0 {
                        let mut wake = TronaMsg::zeroed();
                        wake.label = TRONA_OK;
                        wake.length = 1;
                        wake.regs[0] = 0;
                        state.complete_op((*peer).recv_op, OwnerPostOp::None, &raw const wake);
                        (*peer).recv_op = OpCore::INVALID;
                        (*peer).recv_badge = 0;
                    }
                }
            }
        }

        (*reply).label = TRONA_OK;
        false
    }
}

pub(crate) unsafe fn handle_sockpair(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let s1_handle = alloc_socket(state);
        let s2_handle = alloc_socket(state);
        if s1_handle.is_none() || s2_handle.is_none() {
            if let Some(handle) = s1_handle {
                release_socket(state, handle);
            }
            if let Some(handle) = s2_handle {
                release_socket(state, handle);
            }
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        let s1_handle = s1_handle.unwrap();
        let s2_handle = s2_handle.unwrap();
        let s1 = find_socket(state, s1_handle);
        let s2 = find_socket(state, s2_handle);

        let badge = match state.clients.get(cli_handle) {
            Some(c) => c.badge,
            None => 0,
        };

        (*s1).state = SOCK_CONNECTED;
        (*s2).state = SOCK_CONNECTED;
        (*s1).peer_socket = s2_handle;
        (*s1).peer_badge = badge;
        (*s2).peer_socket = s1_handle;
        (*s2).peer_badge = badge;

        let Some(fd1) = state.reserve_fd_owned(cli_handle) else {
            release_socket(state, s1_handle);
            release_socket(state, s2_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };
        let Some(fd2) = state.reserve_fd_owned(cli_handle) else {
            state.slot_release(cli_handle, fd1 as usize);
            release_socket(state, s1_handle);
            release_socket(state, s2_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        if let Some(obj) = state.open_object_at_mut(cli_handle, fd1 as usize) {
            obj.set_unix_socket(s1_handle);
        } else {
            state.slot_release(cli_handle, fd1 as usize);
            state.slot_release(cli_handle, fd2 as usize);
            release_socket(state, s1_handle);
            release_socket(state, s2_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        if let Some(obj) = state.open_object_at_mut(cli_handle, fd2 as usize) {
            obj.set_unix_socket(s2_handle);
        } else {
            state.slot_release(cli_handle, fd1 as usize);
            state.slot_release(cli_handle, fd2 as usize);
            release_socket(state, s1_handle);
            release_socket(state, s2_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 2;
        (*reply).regs[0] = fd1 as u64;
        (*reply).regs[1] = fd2 as u64;
        false
    }
}
