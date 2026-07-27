// SPDX-License-Identifier: GPL-2.0-only
//! Shared open-file descriptions.
//!
//! POSIX `dup`/`fork` semantics share file offset and status flags across
//! descriptors that reference the same open-file description.

use crate::arena::Handle;
use crate::server::epoll_object::EpollHandle;
use crate::server::pipe_object::PipeHandle;
use crate::server::shm_object::ShmHandle;
use crate::server::types::OBJ_NONE;
use crate::server::unix_socket_object::UnixSocketHandle;
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) type OpenFileHandle = Handle<OpenFile>;

pub(crate) const DIR_CURSOR_BOOTSTRAP: u8 = 0;
pub(crate) const DIR_CURSOR_BACKEND: u8 = 1;
pub(crate) const DIR_CURSOR_EOF: u8 = 2;

#[repr(C)]
pub(crate) struct OpenFile {
    pub(crate) vnode: VnodeHandle,
    pub(crate) pipe: PipeHandle,
    pub(crate) shm: ShmHandle,
    pub(crate) epoll: EpollHandle,
    pub(crate) unix_socket: UnixSocketHandle,
    pub(crate) kind: u8,
    _pad0: [u8; 3],
    pub(crate) status_flags: u32,
    pub(crate) dir_cursor: u64,
    pub(crate) dir_cursor_state: u8,
    pub(crate) device_dev_type: u8,
    _pad1: [u8; 2],
    pub(crate) device_pty_id: u32,
    pub(crate) device_generation: u32,
    pub(crate) offset: u64,
    pub(crate) refcount: u32,
    pub(crate) socket_conn_id: u32,
}

impl OpenFile {
    pub(crate) const fn zeroed() -> Self {
        OpenFile {
            vnode: VnodeHandle::INVALID,
            pipe: PipeHandle::INVALID,
            shm: ShmHandle::INVALID,
            epoll: EpollHandle::INVALID,
            unix_socket: UnixSocketHandle::INVALID,
            kind: OBJ_NONE,
            _pad0: [0; 3],
            status_flags: 0,
            dir_cursor: 0,
            dir_cursor_state: DIR_CURSOR_BOOTSTRAP,
            device_dev_type: 0,
            _pad1: [0; 2],
            device_pty_id: 0,
            device_generation: 0,
            offset: 0,
            refcount: 0,
            socket_conn_id: 0,
        }
    }
}
