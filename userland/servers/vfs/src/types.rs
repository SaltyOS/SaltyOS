// SPDX-License-Identifier: GPL-2.0-only
//! VFS data structures: inodes, file descriptors, sockets, and pipes.

use crate::consts::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RamfsDirent {
    pub(crate) active: u8,
    pub(crate) ino: u32,
    pub(crate) name: [u8; MAX_NAME_LEN],
    pub(crate) name_len: u8,
}

impl RamfsDirent {
    pub(crate) const fn zeroed() -> Self {
        RamfsDirent {
            active: 0,
            ino: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct RamfsInode {
    pub(crate) active: u8,
    pub(crate) readonly: u8,
    pub(crate) ino: u32,
    pub(crate) mode: u32,
    pub(crate) nlink: u32,
    pub(crate) size: u64,
    pub(crate) mtime: u32,
    pub(crate) parent_ino: u32,
    pub(crate) ftype: u8,
    pub(crate) dev_type: u8,
    pub(crate) dirents: *mut RamfsDirent,
    pub(crate) dirents_cap: u16,
    pub(crate) ro_data: *const u8,
    pub(crate) rw_data: *mut u8,
    pub(crate) open_count: u32,
}

impl RamfsInode {
    pub(crate) const fn zeroed() -> Self {
        RamfsInode {
            active: 0,
            readonly: 0,
            ino: 0,
            mode: 0,
            nlink: 0,
            size: 0,
            mtime: 0,
            parent_ino: 0,
            ftype: FTYPE_NONE,
            dev_type: 0,
            dirents: core::ptr::null_mut(),
            dirents_cap: 0,
            ro_data: core::ptr::null(),
            rw_data: core::ptr::null_mut(),
            open_count: 0,
        }
    }
}

unsafe impl Sync for RamfsInode {}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MountReaddirEntry {
    pub(crate) ino: u64,
    pub(crate) d_type: u8,
    pub(crate) name_len: u8,
    pub(crate) name: [u8; 32],
}

impl MountReaddirEntry {
    pub(crate) const fn zeroed() -> Self {
        MountReaddirEntry {
            ino: 0,
            d_type: 0,
            name_len: 0,
            name: [0; 32],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct FdEntry {
    pub(crate) active: u8,
    pub(crate) fd_type: u8,
    pub(crate) inode: u32,
    pub(crate) offset: u64,
    pub(crate) dir_cursor: u32,
    pub(crate) dev_type: u8,
    pub(crate) flags: u32,
    pub(crate) sock_id: u32,
    pub(crate) mount_batch_count: u8,
    pub(crate) mount_batch_index: u8,
    pub(crate) mount_batch_next_cursor: u32,
    pub(crate) mount_batch: [MountReaddirEntry; MOUNT_READDIR_BATCH_MAX],
}

impl FdEntry {
    pub(crate) const fn zeroed() -> Self {
        FdEntry {
            active: 0,
            fd_type: FD_TYPE_NONE,
            inode: 0,
            offset: 0,
            dir_cursor: 0,
            dev_type: 0,
            flags: 0,
            sock_id: 0,
            mount_batch_count: 0,
            mount_batch_index: 0,
            mount_batch_next_cursor: 0,
            mount_batch: [MountReaddirEntry::zeroed(); MOUNT_READDIR_BATCH_MAX],
        }
    }

    /// Get pipe_id (aliases sock_id for pipe FDs)
    pub(crate) fn pipe_id(&self) -> u32 {
        self.sock_id
    }
}

#[repr(C)]
pub(crate) struct ClientState {
    pub(crate) badge: u64,
    pub(crate) active: u8,
    pub(crate) fds: *mut FdEntry,
    pub(crate) fds_cap: u16,
    pub(crate) cwd: [u8; 128],
    pub(crate) fd_flags: *mut u8,
}

impl ClientState {
    pub(crate) const fn zeroed() -> Self {
        ClientState {
            badge: 0,
            active: 0,
            fds: core::ptr::null_mut(),
            fds_cap: 0,
            cwd: [0; 128],
            fd_flags: core::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PendingConn {
    pub(crate) active: u8,
    pub(crate) client_badge: u64,
    pub(crate) sock_id: u32,
    pub(crate) reply_slot: u64,
}

impl PendingConn {
    pub(crate) const fn zeroed() -> Self {
        PendingConn {
            active: 0,
            client_badge: 0,
            sock_id: 0,
            reply_slot: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct SocketState {
    pub(crate) active: u8,
    pub(crate) state: u8,
    pub(crate) sock_id: u32,
    pub(crate) bound_ino: u32,
    pub(crate) backlog: u8,
    pub(crate) pending_count: u8,
    pub(crate) pending: *mut PendingConn,
    pub(crate) pending_cap: u8,
    pub(crate) peer_sock_id: u32,
    pub(crate) peer_badge: u64,
    pub(crate) data_buf: [u8; SOCK_BUF_SIZE],
    pub(crate) data_head: u16,
    pub(crate) data_tail: u16,
    pub(crate) accept_reply_slot: u64,
    pub(crate) accept_badge: u64,
    pub(crate) recv_reply_slot: u64,
    pub(crate) recv_badge: u64,
    pub(crate) pending_caps: [u64; 4],
    pub(crate) pending_cap_count: u8,
    pub(crate) shut_rd: u8,
    pub(crate) shut_wr: u8,
    pub(crate) peer_closed: u8,
    pub(crate) refcount: u16,
}

impl SocketState {
    pub(crate) const fn zeroed() -> Self {
        SocketState {
            active: 0,
            state: SOCK_UNBOUND,
            sock_id: 0,
            bound_ino: 0,
            backlog: 0,
            pending_count: 0,
            pending: core::ptr::null_mut(),
            pending_cap: 0,
            peer_sock_id: 0,
            peer_badge: 0,
            data_buf: [0; SOCK_BUF_SIZE],
            data_head: 0,
            data_tail: 0,
            accept_reply_slot: 0,
            accept_badge: 0,
            recv_reply_slot: 0,
            recv_badge: 0,
            pending_caps: [0; 4],
            pending_cap_count: 0,
            shut_rd: 0,
            shut_wr: 0,
            peer_closed: 0,
            refcount: 0,
        }
    }
}

unsafe impl Sync for SocketState {}

#[repr(C)]
pub(crate) struct PollWaiter {
    pub(crate) active: u8,
    pub(crate) badge: u64,
    pub(crate) reply_slot: u64,
    pub(crate) fds: [(i32, u16); 8],
    pub(crate) nfds: u8,
}

impl PollWaiter {
    pub(crate) const fn zeroed() -> Self {
        PollWaiter {
            active: 0,
            badge: 0,
            reply_slot: 0,
            fds: [(-1, 0); 8],
            nfds: 0,
        }
    }
}

pub(crate) struct EpollEntry {
    pub(crate) active: u8,
    pub(crate) fd: i32,
    pub(crate) events: u32,
    pub(crate) data: u64,
}

impl EpollEntry {
    pub(crate) const fn zeroed() -> Self {
        EpollEntry {
            active: 0,
            fd: -1,
            events: 0,
            data: 0,
        }
    }
}

pub(crate) struct EpollInstance {
    pub(crate) active: u8,
    pub(crate) owner_badge: u64,
    pub(crate) entries: *mut EpollEntry,
    pub(crate) entries_cap: u16,
}

impl EpollInstance {
    pub(crate) const fn zeroed() -> Self {
        EpollInstance {
            active: 0,
            owner_badge: 0,
            entries: core::ptr::null_mut(),
            entries_cap: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct ShmData {
    pub(crate) active: u8,
    pub(crate) num_pages: u16,
}

impl ShmData {
    pub(crate) const fn zeroed() -> Self {
        ShmData {
            active: 0,
            num_pages: 0,
        }
    }
}

unsafe impl Sync for ShmData {}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PipeReadWaiter {
    pub(crate) reply_slot: u64,
    pub(crate) badge: u64,
    pub(crate) requested_len: u16,
}

impl PipeReadWaiter {
    pub(crate) const fn zeroed() -> Self {
        PipeReadWaiter {
            reply_slot: 0,
            badge: 0,
            requested_len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PipeWriteWaiter {
    pub(crate) reply_slot: u64,
    pub(crate) badge: u64,
    pub(crate) data: [u8; 144],
    pub(crate) data_len: u16,
}

impl PipeWriteWaiter {
    pub(crate) const fn zeroed() -> Self {
        PipeWriteWaiter {
            reply_slot: 0,
            badge: 0,
            data: [0; 144],
            data_len: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct PipeState {
    pub(crate) active: u8,
    pub(crate) pipe_id: u32,
    pub(crate) read_refcount: u16,
    pub(crate) write_refcount: u16,
    pub(crate) data_buf: [u8; PIPE_BUF_SIZE],
    pub(crate) data_head: u16,
    pub(crate) data_tail: u16,
    pub(crate) recv_waiters: *mut PipeReadWaiter,
    pub(crate) recv_waiter_cap: u8,
    pub(crate) recv_waiter_count: u8,
    pub(crate) write_waiters: *mut PipeWriteWaiter,
    pub(crate) write_waiter_cap: u8,
    pub(crate) write_waiter_count: u8,
}

impl PipeState {
    pub(crate) const fn zeroed() -> Self {
        PipeState {
            active: 0,
            pipe_id: 0,
            read_refcount: 0,
            write_refcount: 0,
            data_buf: [0; PIPE_BUF_SIZE],
            data_head: 0,
            data_tail: 0,
            recv_waiters: core::ptr::null_mut(),
            recv_waiter_cap: 0,
            recv_waiter_count: 0,
            write_waiters: core::ptr::null_mut(),
            write_waiter_cap: 0,
            write_waiter_count: 0,
        }
    }
}

unsafe impl Sync for PipeState {}

#[derive(Clone, Copy)]
pub(crate) struct PtyPendingReader {
    pub(crate) active: u8,
    pub(crate) badge: u64,
    pub(crate) reply_slot: u64,
    pub(crate) max_count: u64,
}

impl PtyPendingReader {
    pub(crate) const fn zeroed() -> Self {
        PtyPendingReader {
            active: 0,
            badge: 0,
            reply_slot: 0,
            max_count: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MountEntry {
    pub(crate) active: u8,
    pub(crate) mount_ino: u32, // VFS inode for the mount point directory
    pub(crate) fs_cap: u64,    // Cap slot of mounted FS server endpoint
    pub(crate) root_ino: u32,  // Root inode number in the mounted FS
}

impl MountEntry {
    pub(crate) const fn zeroed() -> Self {
        MountEntry {
            active: 0,
            mount_ino: 0,
            fs_cap: 0,
            root_ino: 0,
        }
    }
}
