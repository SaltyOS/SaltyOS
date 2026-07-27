// SPDX-License-Identifier: GPL-2.0-only
//! Local AF_UNIX socket backing storage.
//!
//! The new VFS keeps Unix-domain endpoints as owner-managed in-memory
//! objects. There is no separate callback/pending layer here:
//! `read`/`write`/`sendmsg`/`recvmsg` all operate synchronously against
//! the endpoint ring buffer and the pending SCM_RIGHTS batch.

use crate::arena::Handle;
use crate::server::open_file::OpenFileHandle;
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) const UNIX_SOCKET_BUF_SIZE: usize = 4096;
pub(crate) const UNIX_SOCKET_MAX_RIGHTS: usize = 4;
pub(crate) const UNIX_SOCKET_ACCEPT_CAP: usize = 16;
pub(crate) const UNIX_DGRAM_QUEUE_CAP: usize = 16;
pub(crate) const UNIX_DGRAM_MAX_PAYLOAD: usize = 152;
pub(crate) const UNIX_SOCKET_ADDR_MAX: usize = 63;

pub(crate) type UnixSocketHandle = Handle<UnixSocketState>;

#[repr(C)]
pub(crate) struct UnixSocketState {
    pub(crate) active: u8,
    pub(crate) peer_closed: u8,
    pub(crate) shut_rd: u8,
    pub(crate) shut_wr: u8,
    pub(crate) listener: u8,
    pub(crate) pending_accept_count: u8,
    pub(crate) bound_abstract_len: u8,
    pub(crate) peer_name_abstract_len: u8,
    pub(crate) bound_path_len: u8,
    pub(crate) peer_name_path_len: u8,
    _pad_addr: [u8; 2],
    pub(crate) refcount: u32,
    pub(crate) peer: UnixSocketHandle,
    pub(crate) bound_vnode: VnodeHandle,
    pub(crate) peer_name_vnode: VnodeHandle,
    pub(crate) listener_backlog: u16,
    pub(crate) socket_type: u16,
    pub(crate) head: u16,
    pub(crate) tail: u16,
    pub(crate) pending_accept_head: u8,
    pub(crate) pending_accept_tail: u8,
    pub(crate) pending_dgram_head: u8,
    pub(crate) pending_dgram_tail: u8,
    pub(crate) pending_right_count: u8,
    pub(crate) pending_dgram_count: u8,
    _pad0: [u8; 2],
    pub(crate) pending_rights: [OpenFileHandle; UNIX_SOCKET_MAX_RIGHTS],
    pub(crate) pending_accept: [UnixSocketHandle; UNIX_SOCKET_ACCEPT_CAP],
    pub(crate) pending_dgram_len: [u16; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) pending_dgram_src_vnode: [VnodeHandle; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) pending_dgram_right_count: [u8; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) pending_dgram_src_abstract_len: [u8; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) pending_dgram_src_path_len: [u8; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) pending_dgram_rights:
        [[OpenFileHandle; UNIX_SOCKET_MAX_RIGHTS]; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) bound_path: [u8; UNIX_SOCKET_ADDR_MAX],
    pub(crate) peer_name_path: [u8; UNIX_SOCKET_ADDR_MAX],
    pub(crate) bound_abstract_name: [u8; UNIX_SOCKET_ADDR_MAX],
    pub(crate) peer_name_abstract_name: [u8; UNIX_SOCKET_ADDR_MAX],
    pub(crate) pending_dgram_src_path: [[u8; UNIX_SOCKET_ADDR_MAX]; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) pending_dgram_src_abstract_name: [[u8; UNIX_SOCKET_ADDR_MAX]; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) pending_dgram_data: [[u8; UNIX_DGRAM_MAX_PAYLOAD]; UNIX_DGRAM_QUEUE_CAP],
    pub(crate) data: [u8; UNIX_SOCKET_BUF_SIZE],
}

impl UnixSocketState {
    pub(crate) const fn zeroed() -> Self {
        UnixSocketState {
            active: 0,
            peer_closed: 0,
            shut_rd: 0,
            shut_wr: 0,
            listener: 0,
            pending_accept_count: 0,
            bound_abstract_len: 0,
            peer_name_abstract_len: 0,
            bound_path_len: 0,
            peer_name_path_len: 0,
            _pad_addr: [0; 2],
            refcount: 0,
            peer: UnixSocketHandle::INVALID,
            bound_vnode: VnodeHandle::INVALID,
            peer_name_vnode: VnodeHandle::INVALID,
            listener_backlog: 0,
            socket_type: 0,
            head: 0,
            tail: 0,
            pending_accept_head: 0,
            pending_accept_tail: 0,
            pending_dgram_head: 0,
            pending_dgram_tail: 0,
            pending_right_count: 0,
            pending_dgram_count: 0,
            _pad0: [0; 2],
            pending_rights: [const { OpenFileHandle::INVALID }; UNIX_SOCKET_MAX_RIGHTS],
            pending_accept: [const { UnixSocketHandle::INVALID }; UNIX_SOCKET_ACCEPT_CAP],
            pending_dgram_len: [0; UNIX_DGRAM_QUEUE_CAP],
            pending_dgram_src_vnode: [const { VnodeHandle::INVALID }; UNIX_DGRAM_QUEUE_CAP],
            pending_dgram_right_count: [0; UNIX_DGRAM_QUEUE_CAP],
            pending_dgram_src_abstract_len: [0; UNIX_DGRAM_QUEUE_CAP],
            pending_dgram_src_path_len: [0; UNIX_DGRAM_QUEUE_CAP],
            pending_dgram_rights: [[const { OpenFileHandle::INVALID }; UNIX_SOCKET_MAX_RIGHTS];
                UNIX_DGRAM_QUEUE_CAP],
            bound_path: [0; UNIX_SOCKET_ADDR_MAX],
            peer_name_path: [0; UNIX_SOCKET_ADDR_MAX],
            bound_abstract_name: [0; UNIX_SOCKET_ADDR_MAX],
            peer_name_abstract_name: [0; UNIX_SOCKET_ADDR_MAX],
            pending_dgram_src_path: [[0; UNIX_SOCKET_ADDR_MAX]; UNIX_DGRAM_QUEUE_CAP],
            pending_dgram_src_abstract_name: [[0; UNIX_SOCKET_ADDR_MAX]; UNIX_DGRAM_QUEUE_CAP],
            pending_dgram_data: [[0; UNIX_DGRAM_MAX_PAYLOAD]; UNIX_DGRAM_QUEUE_CAP],
            data: [0; UNIX_SOCKET_BUF_SIZE],
        }
    }
}
