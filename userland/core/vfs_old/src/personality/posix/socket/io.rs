// SPDX-License-Identifier: GPL-2.0-only
//! Data I/O: socket read/write, sendmsg, recvmsg.

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
use crate::owner::op::{OpCore, OpKind, OwnerPostOp};
use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::server::types::*;

use super::state::{find_socket, sock_buf_len, sock_buf_read, sock_buf_write};

/// Handle read on a socket fd
pub(crate) unsafe fn handle_socket_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let badge = match state.clients.get(cli_handle) {
            Some(c) => c.badge,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let socket_handle = state
            .open_object_at(cli_handle, fd as usize)
            .map(|obj| obj.unix_socket_handle())
            .unwrap_or_else(|| {
                crate::arena::Handle::<crate::personality::posix::types::SocketState>::INVALID
            });

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
            if count > 152 {
                count = 152;
            }
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
        let op = match state.begin_op_for_client(cli_handle, OpKind::SocketRecv) {
            Ok(op) => op,
            Err(err) => {
                (*reply).label = err.to_trona();
                return false;
            }
        };
        (*sock).recv_op = op;
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
        let socket_handle = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) => obj.unix_socket_handle(),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
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
        if actual_count > 144 {
            actual_count = 144;
        }

        let written = sock_buf_write(peer, src, actual_count as u16);

        // Wake blocked reader on peer
        if written > 0 && (*peer).recv_op.reply_slot != 0 {
            let mut wake = TronaMsg::zeroed();
            let avail = sock_buf_len(peer);
            let mut rcount = avail;
            if rcount > 152 {
                rcount = 152;
            }
            let dst = &raw mut wake.regs[1] as *mut u8;
            let actual = sock_buf_read(peer, dst, rcount);
            wake.label = TRONA_OK;
            wake.length = 1 + ((actual as u64 + 7) / 8);
            wake.regs[0] = actual as u64;
            state.complete_op((*peer).recv_op, OwnerPostOp::None, &raw const wake);
            (*peer).recv_op = OpCore::INVALID;
            (*peer).recv_badge = 0;
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
        if actual_data > 120 {
            actual_data = 120;
        }
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
        if written > 0 && (*peer).recv_op.reply_slot != 0 {
            let mut wake = TronaMsg::zeroed();
            let avail = sock_buf_len(peer);
            let mut rcount = avail;
            if rcount > 120 {
                rcount = 120;
            }
            let dst = &raw mut wake.regs[2] as *mut u8;
            let actual = sock_buf_read(peer, dst, rcount);
            wake.label = TRONA_OK;
            wake.regs[0] = actual as u64;
            wake.regs[1] = 0;
            wake.length = 2 + ((actual as u64 + 7) / 8);
            state.complete_op((*peer).recv_op, OwnerPostOp::None, &raw const wake);
            (*peer).recv_op = OpCore::INVALID;
            (*peer).recv_badge = 0;
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
        let recv_flags = (*msg).regs[2] as i32;
        let cloexec_on_new_fds: u8 = if (recv_flags & MSG_CMSG_CLOEXEC) != 0 {
            1
        } else {
            0
        };

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

            let op = match state.begin_op_for_client(cli_handle, OpKind::SocketRecv) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    return false;
                }
            };
            (*sock).recv_op = op;
            (*sock).recv_badge = badge;
            return true;
        }

        // Read data
        let mut count = if avail > 120 { 120 } else { avail };
        if count as u64 > max_data {
            count = max_data as u16;
        }
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
                let src_client = match state.badge_map.lookup(src_badge) {
                    Some((slot, epoch)) => ClientHandle::new(slot, epoch),
                    None => continue,
                };
                if src_fd < 0 || src_fd as usize >= MAX_CLIENT_OBJECTS {
                    continue;
                }
                let src_handle = match state.clients.get(src_client) {
                    Some(c) => {
                        let r = c.slots[src_fd as usize];
                        if r.is_free() {
                            continue;
                        }
                        r.open_object
                    }
                    None => continue,
                };

                // Find a free slot on the receiver side. No
                // `reserve_fd_owned` placeholder is needed because
                // `slot_share` installs a shared reference to the
                // sender's existing `OpenObject` in one step.
                let mut new_fd: i32 = -1;
                if let Some(cli) = state.clients.get(cli_handle) {
                    for slot_idx in 0..MAX_CLIENT_OBJECTS {
                        if cli.slots[slot_idx].is_free() {
                            new_fd = slot_idx as i32;
                            break;
                        }
                    }
                }
                if new_fd < 0 {
                    continue;
                }

                if state
                    .slot_share(
                        cli_handle,
                        new_fd as usize,
                        src_handle,
                        cloexec_on_new_fds,
                        badge,
                    )
                    .is_none()
                {
                    continue;
                }

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
