// SPDX-License-Identifier: GPL-2.0-only
//! Data I/O: socket read/write, sendmsg, recvmsg.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::posix::*;
use trona::protocol::vfs::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::ipc_ctx;

use super::state::{find_socket, sock_buf_len, sock_buf_read, sock_buf_write};

/// Handle read on a socket fd
pub(crate) unsafe fn handle_socket_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let (socket_handle, badge) = match state.clients.get(cli_handle) {
            Some(cli) => (cli.objects[fd as usize].unix_socket_handle(), cli.badge),
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let sock = find_socket(state, socket_handle);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        if (*sock).shut_rd != 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return false;
        }

        let avail = sock_buf_len(sock);
        if avail > 0 {
            let mut count = avail;
            if count > 152 { count = 152; }
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            let actual = sock_buf_read(sock, dst, count);
            (*reply).label = TRONA_OK;
            (*reply).length = 1 + ((actual as u64 + 7) / 8);
            (*reply).regs[0] = actual as u64;
            return false;
        }

        if (*sock).peer_closed != 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return false;
        }

        // Block reader
        let slot = state.alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        (*sock).recv_reply_slot = slot;
        (*sock).recv_badge = badge;
        true
    }
}

/// Handle write on a socket fd
pub(crate) unsafe fn handle_socket_write(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let socket_handle = match state.clients.get(cli_handle) {
            Some(cli) => cli.objects[fd as usize].unix_socket_handle(),
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };

        let sock = find_socket(state, socket_handle);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED || (*sock).shut_wr != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let peer = find_socket(state, (*sock).peer_socket);
        if peer.is_null() || (*peer).peer_closed != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let count = (*msg).regs[1];
        let src = &(*msg).regs[2] as *const u64 as *const u8;
        let mut actual_count = count;
        if actual_count > 144 { actual_count = 144; }

        let written = sock_buf_write(peer, src, actual_count as u16);

        // Wake blocked reader on peer
        if written > 0 && (*peer).recv_reply_slot != 0 {
            let mut wake = TronaMsg::zeroed();
            let avail = sock_buf_len(peer);
            let mut rcount = avail;
            if rcount > 152 { rcount = 152; }
            let dst = &raw mut wake.regs[1] as *mut u8;
            let actual = sock_buf_read(peer, dst, rcount);
            wake.label = TRONA_OK;
            wake.length = 1 + ((actual as u64 + 7) / 8);
            wake.regs[0] = actual as u64;
            ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
            (*peer).recv_reply_slot = 0;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}

pub(crate) unsafe fn handle_sendmsg(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_len = (*msg).regs[1];

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

        let sock = find_socket(state, socket_handle);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED || (*sock).shut_wr != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let peer = find_socket(state, (*sock).peer_socket);
        if peer.is_null() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let mut actual_data = data_len;
        if actual_data > 120 { actual_data = 120; }
        let src = &(*msg).regs[3] as *const u64 as *const u8;
        let written = sock_buf_write(peer, src, actual_data as u16);

        // Store SCM_RIGHTS fd numbers
        let fd_count = (*msg).regs[2] as u32;
        let actual_fds = if fd_count > 4 { 4 } else { fd_count };
        (*peer).pending_cap_count = actual_fds as u8;
        let data_regs = (actual_data + 7) / 8;
        let fd_src = &(*msg).regs[3 + data_regs as usize] as *const u64 as *const i32;
        for i in 0..actual_fds as usize {
            (*peer).pending_caps[i] =
                ((badge << 32) | (*fd_src.add(i) as u32 as u64)) & 0xFFFF_FFFF_FFFF_FFFF;
        }

        // Wake blocked reader on peer
        if written > 0 && (*peer).recv_reply_slot != 0 {
            let mut wake = TronaMsg::zeroed();
            let avail = sock_buf_len(peer);
            let mut rcount = avail;
            if rcount > 120 { rcount = 120; }
            let dst = &raw mut wake.regs[2] as *mut u8;
            let actual = sock_buf_read(peer, dst, rcount);
            wake.label = TRONA_OK;
            wake.regs[0] = actual as u64;
            wake.regs[1] = 0;
            wake.length = 2 + ((actual as u64 + 7) / 8);
            ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
            (*peer).recv_reply_slot = 0;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}

pub(crate) unsafe fn handle_recvmsg(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let max_data = (*msg).regs[1];

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

        let sock = find_socket(state, socket_handle);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let avail = sock_buf_len(sock);
        if avail == 0 && (*sock).pending_cap_count == 0 {
            if (*sock).peer_closed != 0 {
                (*reply).label = TRONA_OK;
                (*reply).length = 2;
                (*reply).regs[0] = 0;
                (*reply).regs[1] = 0;
                return false;
            }

            let slot = state.alloc_reply_slot();
            let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
            if err != 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
            (*sock).recv_reply_slot = slot;
            (*sock).recv_badge = badge;
            return true;
        }

        // Read data
        let mut count = if avail > 120 { 120 } else { avail };
        if count as u64 > max_data { count = max_data as u16; }
        let dst = &raw mut (*reply).regs[2] as *mut u8;
        let actual = sock_buf_read(sock, dst, count);

        // Handle pending SCM_RIGHTS
        let cap_count = (*sock).pending_cap_count;
        let mut new_fd_count: u32 = 0;
        let data_regs = (actual as u64 + 7) / 8;

        if cap_count > 0 {
            let fd_dst = &raw mut (*reply).regs[2 + data_regs as usize] as *mut i32;
            for i in 0..cap_count as usize {
                let packed = (*sock).pending_caps[i];
                let src_badge = packed >> 32;
                let src_fd = (packed & 0xFFFF_FFFF) as i32;

                // Look up source client by badge
                let src_handle = match state.badge_map.lookup(src_badge) {
                    Some((slot, epoch)) => ClientHandle::new(slot, epoch),
                    None => continue,
                };
                let src_slot = match state.clients.get(src_handle) {
                    Some(c) => {
                        if src_fd < 0 || src_fd as usize >= MAX_CLIENT_OBJECTS || !c.objects[src_fd as usize].is_live() {
                            continue;
                        }
                        c.objects[src_fd as usize]
                    }
                    None => continue,
                };

                // Find free fd in receiver
                let Some(new_fd) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
                    continue;
                };

                let cli = match state.clients.get_mut(cli_handle) {
                    Some(c) => c,
                    None => {
                        if let Some(c2) = state.clients.get_mut(cli_handle) {
                            c2.objects[new_fd as usize].clear();
                            c2.obj_count = c2.obj_count.saturating_sub(1);
                        }
                        continue;
                    }
                };
                cli.objects[new_fd as usize] = src_slot;

                *fd_dst.add(new_fd_count as usize) = new_fd;
                new_fd_count += 1;
            }
            (*sock).pending_cap_count = 0;
        }

        (*reply).label = TRONA_OK;
        (*reply).regs[0] = actual as u64;
        (*reply).regs[1] = new_fd_count as u64;
        (*reply).length = 2 + data_regs + ((new_fd_count as u64 * 4 + 7) / 8);
        false
    }
}
