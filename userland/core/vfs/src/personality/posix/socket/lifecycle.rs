// SPDX-License-Identifier: GPL-2.0-only
//! Socket lifecycle: socket, bind, listen, accept, connect, shutdown, sockpair, close.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::posix::*;
use trona::protocol::vfs::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, root_vnode_for};
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::personality::posix::types::*;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NameiArgs, NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_WANTPARENT};
use crate::vfs_core::vnode::VT_SOCK;
use crate::ipc_ctx;

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
            return super::super::inet::handle_inet_socket(state, cli_handle, msg, reply, sock_type, protocol);
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

        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => { release_socket(state, sock_handle); (*reply).label = TRONA_OUT_OF_MEMORY; return false; }
        };
        let slot = &mut cli.objects[fd as usize];
        slot.set_unix_socket(sock_handle);
        slot.offset = 0;

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

        let socket_handle = match state.clients.get(cli_handle) {
            Some(cli) => {
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::UnixSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                s.unix_socket_handle()
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
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

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start: root,
            path: path.as_ptr(),
            path_len: raw_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT | NAMEI_CREATE,
            cred,
            root,
        };
        let ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(r) => r,
            Err(_) => {
                mount_ctl::clear_trampolines();
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
        };
        mount_ctl::clear_trampolines();

        if ni.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return false;
        }
        if !ni.dvp.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let ctx = match mount_ctl::build_vop_context(state, ni.dvp) {
            Some(c) => c,
            None => { (*reply).label = TRONA_NOT_SUPPORTED; return false; }
        };
        let ops = &*(*ctx.vnode).ops;
        let new_vh = match (ops.meta.create)(
            &ctx, ni.last_name, ni.last_name_len,
            S_IFSOCK_L | 0o777, &raw const cred,
        ) {
            Ok(vh) => vh,
            Err(_) => {
                mount_ctl::clear_trampolines();
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        };
        mount_ctl::clear_trampolines();

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

        let socket_handle = match state.clients.get(cli_handle) {
            Some(cli) => {
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::UnixSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                s.unix_socket_handle()
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let sock = find_socket(state, socket_handle);
        if sock.is_null() || (*sock).state != SOCK_BOUND {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        (*sock).state = SOCK_LISTENING;
        (*sock).backlog = if backlog > (*sock).pending_cap { (*sock).pending_cap } else { backlog };
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

        let (socket_handle, badge) = match state.clients.get(cli_handle) {
            Some(cli) => {
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::UnixSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (s.unix_socket_handle(), cli.badge)
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
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
                    if pend.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_OUT_OF_MEMORY;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                };
                let srv_sock = find_socket(state, srv_sock_handle);
                (*srv_sock).state = SOCK_CONNECTED;

                let cli_sock = find_socket(state, pend.socket);
                if cli_sock.is_null() {
                    release_socket(state, srv_sock_handle);
                    if pend.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_INVALID_OPERATION;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
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
                    if pend.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_OUT_OF_MEMORY;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                };

                let cli = match state.clients.get_mut(cli_handle) {
                    Some(c) => c,
                    None => {
                        if let Some(c2) = state.clients.get_mut(cli_handle) {
                            c2.objects[new_fd as usize].clear();
                            c2.obj_count = c2.obj_count.saturating_sub(1);
                        }
                        release_socket(state, srv_sock_handle);
                        (*reply).label = TRONA_OUT_OF_MEMORY;
                        return false;
                    }
                };
                let slot = &mut cli.objects[new_fd as usize];
                slot.set_unix_socket(srv_sock_handle);

                if pend.reply_slot != 0 {
                    let mut wake_reply = TronaMsg::zeroed();
                    wake_reply.label = TRONA_OK;
                    ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const wake_reply);
                }

                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = new_fd as u64;
                return false;
            }
        }

        // No pending — block accepter
        let slot = state.alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        (*listen_sock).accept_reply_slot = slot;
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

        let (socket_handle, badge) = match state.clients.get(cli_handle) {
            Some(cli) => {
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::UnixSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (s.unix_socket_handle(), cli.badge)
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
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

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start: root,
            path: path.as_ptr(),
            path_len: raw_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };
        let ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(r) => r,
            Err(_) => {
                mount_ctl::clear_trampolines();
                (*reply).label = TRONA_NOT_FOUND;
                return false;
            }
        };
        mount_ctl::clear_trampolines();

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
            None => { (*reply).label = TRONA_NOT_FOUND; return false; }
        };

        // Find listener by bound_ino
        let listen_handle = find_listening_socket_by_bound_ino(state, bound_ino);
        let listen_sock = find_socket(state, listen_handle);

        if listen_sock.is_null() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // If accepter is waiting, connect immediately
        if (*listen_sock).accept_reply_slot != 0 {
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
            if let Some(fd_reserved) = crate::fileops::open::reserve_fd_owned(state, accept_handle) {
                new_fd = fd_reserved;
                if let Some(acli) = state.clients.get_mut(accept_handle) {
                    let slot = &mut acli.objects[new_fd as usize];
                    slot.set_unix_socket(srv_sock_handle);
                } else if let Some(acli2) = state.clients.get_mut(accept_handle) {
                    acli2.objects[new_fd as usize].clear();
                    acli2.obj_count = acli2.obj_count.saturating_sub(1);
                    new_fd = -1;
                }
            }

            let mut wake_reply = TronaMsg::zeroed();
            wake_reply.label = TRONA_OK;
            wake_reply.length = 1;
            wake_reply.regs[0] = if new_fd >= 0 { new_fd as u64 } else { u64::MAX };
            ipc::send_ctx(ipc_ctx(), (*listen_sock).accept_reply_slot, &raw const wake_reply);
            (*listen_sock).accept_reply_slot = 0;
            (*listen_sock).accept_badge = 0;

            (*reply).label = TRONA_OK;
            return false;
        }

        // Queue as pending
        if (*listen_sock).pending_count >= (*listen_sock).backlog {
            (*reply).label = TRONA_BUSY;
            return false;
        }

        let reply_slot = state.alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        (*cli_sock).state = SOCK_CONNECTING;
        for i in 0..(*listen_sock).pending_cap as usize {
            if (*(*listen_sock).pending.add(i)).active == 0 {
                (*(*listen_sock).pending.add(i)).active = 1;
                (*(*listen_sock).pending.add(i)).client_badge = badge;
                (*(*listen_sock).pending.add(i)).socket = socket_handle;
                (*(*listen_sock).pending.add(i)).reply_slot = reply_slot;
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

        let socket_handle = match state.clients.get(cli_handle) {
            Some(cli) => {
                let s = &cli.objects[fd as usize];
                if !s.is_live() || s.kind() != ObjectKind::UnixSocket {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                s.unix_socket_handle()
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let sock = find_socket(state, socket_handle);
        if sock.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        if how == 0 || how == 2 { (*sock).shut_rd = 1; }
        if how == 1 || how == 2 {
            (*sock).shut_wr = 1;
            if (*sock).peer_socket.is_valid() {
                let peer = find_socket(state, (*sock).peer_socket);
                if !peer.is_null() {
                    (*peer).peer_closed = 1;
                    if (*peer).recv_reply_slot != 0 {
                        let mut wake = TronaMsg::zeroed();
                        wake.label = TRONA_OK;
                        wake.length = 1;
                        wake.regs[0] = 0;
                        ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
                        (*peer).recv_reply_slot = 0;
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
            if let Some(handle) = s1_handle { release_socket(state, handle); }
            if let Some(handle) = s2_handle { release_socket(state, handle); }
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

        let Some(fd1) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
            release_socket(state, s1_handle);
            release_socket(state, s2_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };
        let Some(fd2) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
            if let Some(cli) = state.clients.get_mut(cli_handle) {
                cli.objects[fd1 as usize].clear();
                cli.obj_count = cli.obj_count.saturating_sub(1);
            }
            release_socket(state, s1_handle);
            release_socket(state, s2_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => {
                if let Some(cli2) = state.clients.get_mut(cli_handle) {
                    cli2.objects[fd1 as usize].clear();
                    cli2.objects[fd2 as usize].clear();
                    cli2.obj_count = cli2.obj_count.saturating_sub(2);
                }
                release_socket(state, s1_handle);
                release_socket(state, s2_handle);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        };
        cli.objects[fd1 as usize].set_unix_socket(s1_handle);
        cli.objects[fd2 as usize].set_unix_socket(s2_handle);

        (*reply).label = TRONA_OK;
        (*reply).length = 2;
        (*reply).regs[0] = fd1 as u64;
        (*reply).regs[1] = fd2 as u64;
        false
    }
}

/// Close a socket fd — follow the ObjectSlot socket handle and decrement refcount.
pub(crate) unsafe fn close_socket(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) {
    unsafe {
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            return;
        }
        let socket_handle = match state.clients.get(cli_handle) {
            Some(cli) => cli.objects[fd as usize].unix_socket_handle(),
            None => return,
        };

        let sock = find_socket(state, socket_handle);
        if sock.is_null() {
            return;
        }

        (*sock).refcount = (*sock).refcount.saturating_sub(1);
        if (*sock).refcount > 0 {
            return;
        }

        if (*sock).peer_socket.is_valid() {
            let peer = find_socket(state, (*sock).peer_socket);
            if !peer.is_null() {
                (*peer).peer_closed = 1;
                if (*peer).recv_reply_slot != 0 {
                    let mut wake = TronaMsg::zeroed();
                    wake.label = TRONA_OK;
                    wake.length = 1;
                    wake.regs[0] = 0;
                    ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
                    (*peer).recv_reply_slot = 0;
                }
            }
        }

        if (*sock).accept_reply_slot != 0 {
            let mut wake = TronaMsg::zeroed();
            wake.label = TRONA_INVALID_OPERATION;
            ipc::send_ctx(ipc_ctx(), (*sock).accept_reply_slot, &raw const wake);
            (*sock).accept_reply_slot = 0;
        }

        for i in 0..(*sock).pending_cap as usize {
            if (*(*sock).pending.add(i)).active != 0 && (*(*sock).pending.add(i)).reply_slot != 0 {
                let mut wake = TronaMsg::zeroed();
                wake.label = TRONA_INVALID_OPERATION;
                ipc::send_ctx(ipc_ctx(), (*(*sock).pending.add(i)).reply_slot, &raw const wake);
                (*(*sock).pending.add(i)).active = 0;
            }
        }
        (*sock).pending_count = 0;
        (*sock).state = SOCK_CLOSED;
        release_socket(state, socket_handle);
    }
}
