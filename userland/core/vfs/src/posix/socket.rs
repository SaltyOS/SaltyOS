// SPDX-License-Identifier: GPL-2.0-only
//! Unix domain socket subsystem.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::posix::*;
use trona::protocol::vfs::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::client::{extract_path, get_client};
use crate::consts::*;
use crate::fileops::normalize_path_for_client;
use crate::path::{resolve_parent, resolve_path};
use crate::ramfs::{alloc_inode, dir_add_entry, inode_by_ino};
use crate::types::*;
use crate::{
    ipc_ctx, max_sockets, vfs_alloc_array, vfs_grow_pool, NEXT_REPLY_SLOT, NEXT_SOCK_ID, SOCKETS,
    SOCKETS_CAP, SOCKETS_PTR,
};

pub(crate) unsafe fn alloc_socket() -> *mut SocketState {
    unsafe {
        for i in 0..max_sockets() {
            if SOCKETS!()[i].active == 0 {
                let s = &raw mut SOCKETS!()[i];
                (*s).active = 1;
                (*s).sock_id = NEXT_SOCK_ID;
                NEXT_SOCK_ID += 1;
                (*s).state = SOCK_UNBOUND;
                (*s).bound_ino = 0;
                (*s).backlog = 0;
                (*s).pending_count = 0;
                // Allocate pending array if not yet allocated
                if (*s).pending.is_null() {
                    let ptr = vfs_alloc_array::<PendingConn>(INITIAL_PENDING_CONN);
                    if ptr.is_null() {
                        (*s).active = 0;
                        return core::ptr::null_mut();
                    }
                    (*s).pending = ptr;
                    (*s).pending_cap = INITIAL_PENDING_CONN as u8;
                }
                for j in 0..(*s).pending_cap as usize {
                    (*(*s).pending.add(j)).active = 0;
                }
                (*s).peer_sock_id = 0;
                (*s).peer_badge = 0;
                (*s).data_head = 0;
                (*s).data_tail = 0;
                (*s).accept_reply_slot = 0;
                (*s).accept_badge = 0;
                (*s).recv_reply_slot = 0;
                (*s).recv_badge = 0;
                (*s).pending_cap_count = 0;
                (*s).shut_rd = 0;
                (*s).shut_wr = 0;
                (*s).peer_closed = 0;
                (*s).refcount = 1;
                return s;
            }
        }
        // No free slot: grow the pool and retry
        if vfs_grow_pool(
            &raw mut SOCKETS_PTR as *mut *mut u8,
            &raw mut SOCKETS_CAP,
            core::mem::size_of::<SocketState>(),
        ) != 0
        {
            return core::ptr::null_mut();
        }
        alloc_socket()
    }
}

pub(crate) unsafe fn find_socket(sock_id: u32) -> *mut SocketState {
    unsafe {
        for i in 0..max_sockets() {
            if SOCKETS!()[i].active != 0 && SOCKETS!()[i].sock_id == sock_id {
                return &raw mut SOCKETS!()[i];
            }
        }
        core::ptr::null_mut()
    }
}

pub(crate) unsafe fn sock_buf_len(s: *const SocketState) -> u16 {
    unsafe {
        let h = (*s).data_head;
        let t = (*s).data_tail;
        if h >= t {
            h - t
        } else {
            SOCK_BUF_SIZE as u16 - t + h
        }
    }
}

pub(crate) unsafe fn sock_buf_free(s: *const SocketState) -> u16 {
    (SOCK_BUF_SIZE as u16 - 1) - unsafe { sock_buf_len(s) }
}

pub(crate) unsafe fn sock_buf_write(s: *mut SocketState, data: *const u8, len: u16) -> u16 {
    unsafe {
        let free = sock_buf_free(s);
        let actual = if len < free { len } else { free };
        for i in 0..actual as usize {
            (*s).data_buf[(*s).data_head as usize] = *data.add(i);
            (*s).data_head = ((*s).data_head + 1) % SOCK_BUF_SIZE as u16;
        }
        actual
    }
}

pub(crate) unsafe fn sock_buf_read(s: *mut SocketState, data: *mut u8, len: u16) -> u16 {
    unsafe {
        let avail = sock_buf_len(s);
        let actual = if len < avail { len } else { avail };
        for i in 0..actual as usize {
            *data.add(i) = (*s).data_buf[(*s).data_tail as usize];
            (*s).data_tail = ((*s).data_tail + 1) % SOCK_BUF_SIZE as u16;
        }
        actual
    }
}

pub(crate) unsafe fn alloc_reply_slot() -> u64 {
    unsafe {
        let slot = NEXT_REPLY_SLOT;
        NEXT_REPLY_SLOT += 1;
        if NEXT_REPLY_SLOT > CAP_REPLY_LIMIT {
            NEXT_REPLY_SLOT = CAP_REPLY_BASE;
        }
        slot
    }
}

pub(crate) unsafe fn handle_socket(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) -> bool {
    unsafe {
        let domain = (*msg).regs[0] as i32;
        let sock_type = (*msg).regs[1] as i32;
        let protocol = (*msg).regs[2] as i32;

        // AF_INET sockets are forwarded to the internet stack via crate::inet
        if domain == trona::consts::posix::AF_INET {
            return super::inet::handle_inet_socket(msg, reply, badge, sock_type, protocol);
        }

        let sock = alloc_socket();
        if sock.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*sock).active = 0;
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..(*cli).objects_cap as usize {
            if (*(*cli).objects.add(fd)).active == 0 {
                (*(*cli).objects.add(fd)).active = 1;
                (*(*cli).objects.add(fd)).obj_type = OBJ_TYPE_SOCKET;
                (*(*cli).posix_ext.add(fd)).sock_id = (*sock).sock_id;
                (*(*cli).objects.add(fd)).offset = 0;
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return false;
            }
        }

        (*sock).active = 0;
        (*reply).label = TRONA_OUT_OF_MEMORY;
        false
    }
}

pub(crate) unsafe fn handle_bind(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
            || (*(*cli).objects.add(fd as usize)).obj_type != OBJ_TYPE_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).posix_ext.add(fd as usize)).sock_id);
        if sock.is_null() || (*sock).state != SOCK_UNBOUND {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // Extract path
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };

        // Create a socket inode at this path
        let existing = resolve_path(path_ptr, path_len);
        if !existing.is_null() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return false;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let inode = alloc_inode();
        if inode.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        (*inode).ftype = FTYPE_SOCKET;
        (*inode).mode = S_IFSOCK_L | 0o777;
        (*inode).parent_ino = (*parent).ino;
        dir_add_entry(parent, child_name, child_len, (*inode).ino);

        (*sock).bound_ino = (*inode).ino;
        (*sock).state = SOCK_BOUND;

        (*reply).label = TRONA_OK;
        false
    }
}

pub(crate) unsafe fn handle_listen(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let backlog = (*msg).regs[1] as u8;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
            || (*(*cli).objects.add(fd as usize)).obj_type != OBJ_TYPE_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).posix_ext.add(fd as usize)).sock_id);
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

pub(crate) unsafe fn handle_accept(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
            || (*(*cli).objects.add(fd as usize)).obj_type != OBJ_TYPE_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let listen_sock = find_socket((*(*cli).posix_ext.add(fd as usize)).sock_id);
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

                // Create server-side socket
                let srv_sock = alloc_socket();
                if srv_sock.is_null() {
                    // Wake blocked connect caller with error
                    if pend.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_OUT_OF_MEMORY;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                }
                (*srv_sock).state = SOCK_CONNECTED;

                // Find the connecting socket
                let cli_sock = find_socket(pend.sock_id);
                if cli_sock.is_null() {
                    (*srv_sock).active = 0;
                    // Wake blocked connect caller with error
                    if pend.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_INVALID_OPERATION;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
                    }
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return false;
                }

                // Link peers
                (*srv_sock).peer_sock_id = (*cli_sock).sock_id;
                (*srv_sock).peer_badge = pend.client_badge;
                (*cli_sock).peer_sock_id = (*srv_sock).sock_id;
                (*cli_sock).peer_badge = badge;
                (*cli_sock).state = SOCK_CONNECTED;

                // Allocate fd for accepted socket
                let mut new_fd: i32 = -1;
                for fdn in 0..(*cli).objects_cap as usize {
                    if (*(*cli).objects.add(fdn)).active == 0 {
                        (*(*cli).objects.add(fdn)).active = 1;
                        (*(*cli).objects.add(fdn)).obj_type = OBJ_TYPE_SOCKET;
                        (*(*cli).posix_ext.add(fdn)).sock_id = (*srv_sock).sock_id;
                        new_fd = fdn as i32;
                        break;
                    }
                }

                if new_fd < 0 {
                    (*srv_sock).active = 0;
                    // Wake blocked connect caller with error
                    if pend.reply_slot != 0 {
                        let mut err_reply = TronaMsg::zeroed();
                        err_reply.label = TRONA_OUT_OF_MEMORY;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                }

                // Wake the blocked connect() caller
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

        // No pending connections — block accepter
        let slot = alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        (*listen_sock).accept_reply_slot = slot;
        (*listen_sock).accept_badge = badge;
        true // deferred reply
    }
}

pub(crate) unsafe fn handle_connect(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
            || (*(*cli).objects.add(fd as usize)).obj_type != OBJ_TYPE_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let cli_sock = find_socket((*(*cli).posix_ext.add(fd as usize)).sock_id);
        if cli_sock.is_null() || (*cli_sock).state != SOCK_UNBOUND {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // Resolve path to find listening socket
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() || (*inode).ftype != FTYPE_SOCKET {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Find the listener
        let mut listen_sock: *mut SocketState = core::ptr::null_mut();
        for i in 0..max_sockets() {
            if SOCKETS!()[i].active != 0
                && SOCKETS!()[i].state == SOCK_LISTENING
                && SOCKETS!()[i].bound_ino == (*inode).ino
            {
                listen_sock = &raw mut SOCKETS!()[i];
                break;
            }
        }

        if listen_sock.is_null() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // If accepter is waiting, connect immediately
        if (*listen_sock).accept_reply_slot != 0 {
            let srv_sock = alloc_socket();
            if srv_sock.is_null() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
            (*srv_sock).state = SOCK_CONNECTED;
            (*cli_sock).state = SOCK_CONNECTED;

            (*srv_sock).peer_sock_id = (*cli_sock).sock_id;
            (*srv_sock).peer_badge = badge;
            (*cli_sock).peer_sock_id = (*srv_sock).sock_id;
            (*cli_sock).peer_badge = (*listen_sock).accept_badge;

            // Allocate fd for accepted socket on accepter's side
            let accepter_cli = get_client((*listen_sock).accept_badge);
            let mut new_fd: i32 = -1;
            if !accepter_cli.is_null() {
                for fdn in 0..(*accepter_cli).objects_cap as usize {
                    if (*(*accepter_cli).objects.add(fdn)).active == 0 {
                        (*(*accepter_cli).objects.add(fdn)).active = 1;
                        (*(*accepter_cli).objects.add(fdn)).obj_type = OBJ_TYPE_SOCKET;
                        (*(*accepter_cli).posix_ext.add(fdn)).sock_id = (*srv_sock).sock_id;
                        new_fd = fdn as i32;
                        break;
                    }
                }
            }

            // Wake blocked accept() caller
            let mut wake_reply = TronaMsg::zeroed();
            wake_reply.label = TRONA_OK;
            wake_reply.length = 1;
            wake_reply.regs[0] = if new_fd >= 0 { new_fd as u64 } else { u64::MAX };
            ipc::send_ctx(
                ipc_ctx(),
                (*listen_sock).accept_reply_slot,
                &raw const wake_reply,
            );
            (*listen_sock).accept_reply_slot = 0;
            (*listen_sock).accept_badge = 0;

            (*reply).label = TRONA_OK;
            return false;
        }

        // No accepter waiting — queue as pending and block
        if (*listen_sock).pending_count >= (*listen_sock).backlog {
            (*reply).label = TRONA_BUSY;
            return false;
        }

        let slot = alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        (*cli_sock).state = SOCK_CONNECTING;

        for i in 0..(*listen_sock).pending_cap as usize {
            if (*(*listen_sock).pending.add(i)).active == 0 {
                (*(*listen_sock).pending.add(i)).active = 1;
                (*(*listen_sock).pending.add(i)).client_badge = badge;
                (*(*listen_sock).pending.add(i)).sock_id = (*cli_sock).sock_id;
                (*(*listen_sock).pending.add(i)).reply_slot = slot;
                (*listen_sock).pending_count += 1;
                break;
            }
        }

        true // deferred reply
    }
}

pub(crate) unsafe fn handle_shutdown(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let how = (*msg).regs[1] as i32;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
            || (*(*cli).objects.add(fd as usize)).obj_type != OBJ_TYPE_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).posix_ext.add(fd as usize)).sock_id);
        if sock.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        if how == 0 || how == 2 {
            (*sock).shut_rd = 1;
        }
        if how == 1 || how == 2 {
            (*sock).shut_wr = 1;
            // Signal peer
            if (*sock).peer_sock_id != 0 {
                let peer = find_socket((*sock).peer_sock_id);
                if !peer.is_null() {
                    (*peer).peer_closed = 1;
                    // Wake blocked reader on peer
                    if (*peer).recv_reply_slot != 0 {
                        let mut wake = TronaMsg::zeroed();
                        wake.label = TRONA_OK;
                        wake.length = 1;
                        wake.regs[0] = 0; // EOF
                        ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
                        (*peer).recv_reply_slot = 0;
                    }
                    super::poll::wake_poll_waiters((*peer).peer_badge, -1, 0x010);
                    // POLLHUP
                }
            }
        }

        (*reply).label = TRONA_OK;
        false
    }
}

pub(crate) unsafe fn handle_sockpair(
    _msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        let s1 = alloc_socket();
        let s2 = alloc_socket();
        if s1.is_null() || s2.is_null() {
            if !s1.is_null() {
                (*s1).active = 0;
            }
            if !s2.is_null() {
                (*s2).active = 0;
            }
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        (*s1).state = SOCK_CONNECTED;
        (*s2).state = SOCK_CONNECTED;
        (*s1).peer_sock_id = (*s2).sock_id;
        (*s1).peer_badge = badge;
        (*s2).peer_sock_id = (*s1).sock_id;
        (*s2).peer_badge = badge;

        let mut fd1: i32 = -1;
        let mut fd2: i32 = -1;
        for fdn in 0..(*cli).objects_cap as usize {
            if (*(*cli).objects.add(fdn)).active == 0 {
                if fd1 < 0 {
                    (*(*cli).objects.add(fdn)).active = 1;
                    (*(*cli).objects.add(fdn)).obj_type = OBJ_TYPE_SOCKET;
                    (*(*cli).posix_ext.add(fdn)).sock_id = (*s1).sock_id;
                    fd1 = fdn as i32;
                } else if fd2 < 0 {
                    (*(*cli).objects.add(fdn)).active = 1;
                    (*(*cli).objects.add(fdn)).obj_type = OBJ_TYPE_SOCKET;
                    (*(*cli).posix_ext.add(fdn)).sock_id = (*s2).sock_id;
                    fd2 = fdn as i32;
                    break;
                }
            }
        }

        if fd1 < 0 || fd2 < 0 {
            (*s1).active = 0;
            (*s2).active = 0;
            if fd1 >= 0 {
                (*(*cli).objects.add(fd1 as usize)).active = 0;
            }
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

/// Handle read on a socket fd
pub(crate) unsafe fn handle_socket_read(
    fde: *mut ObjectEntry,
    ext: *mut PosixObjExt,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let sock = find_socket((*ext).sock_id);
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

            // Wake peer's blocked writer poll watchers
            if (*sock).peer_sock_id != 0 {
                super::poll::wake_poll_waiters((*sock).peer_badge, -1, 0x004); // POLLOUT
            }
            return false;
        }

        if (*sock).peer_closed != 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0; // EOF
            return false;
        }

        // Block reader — save caller
        let slot = alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        (*sock).recv_reply_slot = slot;
        (*sock).recv_badge = badge;
        true // deferred
    }
}

/// Handle write on a socket fd
pub(crate) unsafe fn handle_socket_write(
    msg: *const TronaMsg,
    fde: *mut ObjectEntry,
    ext: *mut PosixObjExt,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let sock = find_socket((*ext).sock_id);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED || (*sock).shut_wr != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let peer = find_socket((*sock).peer_sock_id);
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
        if written > 0 && (*peer).recv_reply_slot != 0 {
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
            ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
            (*peer).recv_reply_slot = 0;
        }

        // Wake poll waiters watching this peer for POLLIN
        if written > 0 {
            super::poll::wake_poll_waiters((*peer).peer_badge, -1, 0x001); // POLLIN
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}

/// Close a socket fd — decrement refcount, only destroy when last reference closed
pub(crate) unsafe fn close_socket(fde: *mut ObjectEntry, ext: *mut PosixObjExt) {
    unsafe {
        let sock = find_socket((*ext).sock_id);
        if sock.is_null() {
            return;
        }

        // Decrement refcount — only destroy socket when last fd is closed
        (*sock).refcount = (*sock).refcount.saturating_sub(1);
        if (*sock).refcount > 0 {
            return;
        }

        // Signal peer
        if (*sock).peer_sock_id != 0 {
            let peer = find_socket((*sock).peer_sock_id);
            if !peer.is_null() {
                (*peer).peer_closed = 1;
                // Wake blocked reader
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

        // Wake blocked accept() caller
        if (*sock).accept_reply_slot != 0 {
            let mut wake = TronaMsg::zeroed();
            wake.label = TRONA_INVALID_OPERATION;
            ipc::send_ctx(ipc_ctx(), (*sock).accept_reply_slot, &raw const wake);
            (*sock).accept_reply_slot = 0;
        }

        // Wake pending connect() callers
        for i in 0..(*sock).pending_cap as usize {
            if (*(*sock).pending.add(i)).active != 0 && (*(*sock).pending.add(i)).reply_slot != 0 {
                let mut wake = TronaMsg::zeroed();
                wake.label = TRONA_INVALID_OPERATION;
                ipc::send_ctx(
                    ipc_ctx(),
                    (*(*sock).pending.add(i)).reply_slot,
                    &raw const wake,
                );
                (*(*sock).pending.add(i)).active = 0;
            }
        }
        (*sock).pending_count = 0;

        // Remove bound inode
        if (*sock).bound_ino != 0 {
            let inode = inode_by_ino((*sock).bound_ino);
            if !inode.is_null() {
                (*inode).active = 0;
            }
        }

        (*sock).state = SOCK_CLOSED;
        (*sock).active = 0;
    }
}

pub(crate) unsafe fn handle_sendmsg(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_len = (*msg).regs[1];
        let fd_count = (*msg).regs[2] as u32;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
            || (*(*cli).objects.add(fd as usize)).obj_type != OBJ_TYPE_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).posix_ext.add(fd as usize)).sock_id);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED || (*sock).shut_wr != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let peer = find_socket((*sock).peer_sock_id);
        if peer.is_null() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // Write data to peer's buffer
        let mut actual_data = data_len;
        if actual_data > 120 {
            actual_data = 120;
        }
        let src = &(*msg).regs[3] as *const u64 as *const u8;
        let written = sock_buf_write(peer, src, actual_data as u16);

        // Store SCM_RIGHTS fd numbers for peer to receive.
        // For simplicity we store the fd numbers; recvmsg will
        // duplicate them from sender's client state into receiver's.
        let actual_fds = if fd_count > 4 { 4 } else { fd_count };
        (*peer).pending_cap_count = actual_fds as u8;
        let data_regs = (actual_data + 7) / 8;
        let fd_src = &(*msg).regs[3 + data_regs as usize] as *const u64 as *const i32;
        for i in 0..actual_fds as usize {
            // Store as (badge, fd) pair: badge of sender and fd index
            (*peer).pending_caps[i] =
                ((badge << 32) | (*fd_src.add(i) as u32 as u64)) & 0xFFFF_FFFF_FFFF_FFFF;
        }

        // Wake blocked reader on peer
        if written > 0 && (*peer).recv_reply_slot != 0 {
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
            wake.regs[1] = 0; // no caps in wake path
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
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let max_data = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(fd as usize)).active == 0
            || (*(*cli).objects.add(fd as usize)).obj_type != OBJ_TYPE_SOCKET
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).posix_ext.add(fd as usize)).sock_id);
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

            // Block
            let slot = alloc_reply_slot();
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
        if count as u64 > max_data {
            count = max_data as u16;
        }
        let dst = &raw mut (*reply).regs[2] as *mut u8;
        let actual = sock_buf_read(sock, dst, count);

        // Handle pending SCM_RIGHTS objects
        let cap_count = (*sock).pending_cap_count;
        let mut new_fd_count: u32 = 0;
        let data_regs = (actual as u64 + 7) / 8;

        if cap_count > 0 {
            let fd_dst = &raw mut (*reply).regs[2 + data_regs as usize] as *mut i32;
            for i in 0..cap_count as usize {
                let packed = (*sock).pending_caps[i];
                let src_badge = packed >> 32;
                let src_fd = (packed & 0xFFFF_FFFF) as i32;

                // Look up source client and fd
                let src_cli = get_client(src_badge);
                if src_cli.is_null() || src_fd < 0 || src_fd >= (*src_cli).objects_cap as i32 {
                    continue;
                }
                let src_fde = *(*src_cli).objects.add(src_fd as usize);
                let src_ext = *(*src_cli).posix_ext.add(src_fd as usize);
                if src_fde.active == 0 {
                    continue;
                }

                // Duplicate the sender's object slot into the receiver table.
                let mut new_fd: i32 = -1;
                for fdn in 0..(*cli).objects_cap as usize {
                    if (*(*cli).objects.add(fdn)).active == 0 {
                        *(*cli).objects.add(fdn) = src_fde;
                        *(*cli).posix_ext.add(fdn) = src_ext;
                        new_fd = fdn as i32;
                        break;
                    }
                }

                if new_fd >= 0 {
                    *fd_dst.add(new_fd_count as usize) = new_fd;
                    new_fd_count += 1;
                }
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
