// SPDX-License-Identifier: GPL-2.0-only
//! Owner-managed client state.

use crate::arena::Handle;
use crate::server::open_file::OpenFileHandle;
use crate::vfs_core::mount_ns::MountNsHandle;
use crate::vfs_core::namei::PathAnchor;

pub(crate) type ClientHandle = Handle<ClientState>;
pub(crate) const MAX_CLIENT_OBJECTS: usize = 64;

pub(crate) const PERS_POSIX: u8 = 0;
pub(crate) const PERS_WIN32: u8 = 1;

pub(crate) const OBJ_NONE: u8 = 0;
pub(crate) const OBJ_FILE: u8 = 1;
pub(crate) const OBJ_DIRECTORY: u8 = 2;
pub(crate) const OBJ_PIPE: u8 = 3;
pub(crate) const OBJ_SHM: u8 = 4;
pub(crate) const OBJ_EPOLL: u8 = 5;
pub(crate) const OBJ_SOCKET: u8 = 6;
pub(crate) const OBJ_DEVICE: u8 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OpenSlot {
    pub(crate) active: u8,
    _pad0: [u8; 3],
    pub(crate) fd_flags: u32,
    pub(crate) open_file: OpenFileHandle,
}

impl OpenSlot {
    pub(crate) const fn empty() -> Self {
        OpenSlot {
            active: 0,
            _pad0: [0; 3],
            fd_flags: 0,
            open_file: OpenFileHandle::INVALID,
        }
    }
}

#[repr(C)]
pub(crate) struct ClientState {
    pub(crate) badge: u64,
    pub(crate) personality: u8,
    _pad0: [u8; 7],
    pub(crate) mount_ns: MountNsHandle,
    pub(crate) cwd_anchor: PathAnchor,
    pub(crate) bulk_shm_vaddr: u64,
    pub(crate) bulk_shm_id: u64,
    pub(crate) bulk_shm_pages: u32,
    _pad1: [u8; 4],
    pub(crate) slots: [OpenSlot; MAX_CLIENT_OBJECTS],
}

impl ClientState {
    pub(crate) const fn zeroed() -> Self {
        ClientState {
            badge: 0,
            personality: PERS_POSIX,
            _pad0: [0; 7],
            mount_ns: MountNsHandle::INVALID,
            cwd_anchor: PathAnchor::INVALID,
            bulk_shm_vaddr: 0,
            bulk_shm_id: 0,
            bulk_shm_pages: 0,
            _pad1: [0; 4],
            slots: [const { OpenSlot::empty() }; MAX_CLIENT_OBJECTS],
        }
    }
}
