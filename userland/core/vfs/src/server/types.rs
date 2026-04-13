// SPDX-License-Identifier: GPL-2.0-only
//! VFS data structures: personality-neutral client state and object slots.
//!
//! `ClientState` tracks per-client VFS state (fds, credentials, cwd, mount
//! namespace). `ObjectSlot` is the unified inline per-fd record.
//!
//! All raw pointers to VFS objects (`*mut Vnode`, `*mut Mount`,
//! `*mut MountNamespace`) are replaced by arena handles.

use crate::arena::Handle;
use crate::personality::posix::types::EpollInstance;
use crate::personality::posix::types::PipeState;
use crate::personality::posix::types::SocketState;
use crate::vfs_core::mount_ns::{MountNamespace, MountNsHandle};
use crate::vfs_core::vnode::{Vnode, VnodeHandle};

/// Type alias for handle-based client identity.
pub(crate) type ClientHandle = Handle<ClientState>;

/// Maximum number of open file descriptors per client.
///
/// Inline array avoids a separate allocation and pointer indirection.
/// 128 slots × ~64 bytes/slot ≈ 8 KiB per client — acceptable since the
/// arena segment allocates clients in pages.
pub(crate) const MAX_CLIENT_OBJECTS: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectKind {
    None,
    File,
    Directory,
    Device,
    Shm,
    Pipe,
    UnixSocket,
    InetSocket,
    Epoll,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeviceInfo {
    pub(crate) dev_type: u8,
    pub(crate) pty_id: u32,
}

#[derive(Clone, Copy)]
pub(crate) enum ObjectBacking {
    None,
    Reserved,
    Vnode {
        vnode: VnodeHandle,
        inode: u32,
        kind: ObjectKind,
        device: Option<DeviceInfo>,
    },
    Pipe {
        pipe: Handle<PipeState>,
        vnode: VnodeHandle,
        inode: u32,
    },
    UnixSocket {
        socket: Handle<SocketState>,
    },
    InetSocket {
        sock_id: u32,
    },
    Epoll {
        epoll: Handle<EpollInstance>,
    },
}

// =========================================================================
// ObjectSlot — merged per-fd state
// =========================================================================

/// Per-fd slot within a client.
///
/// All per-fd state lives in one contiguous struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ObjectSlot {
    /// Access rights.
    pub(crate) rights: u8,
    _pad0: [u8; 3],
    /// Open flags (POSIX `O_*` or translated Win32 equivalent).
    pub(crate) flags: u32,
    /// Current sequential read/write offset.
    pub(crate) offset: u64,
    /// Readdir cursor position.
    pub(crate) dir_cursor: u32,

    /// Neutral backing state for this fd.
    pub(crate) backing: ObjectBacking,

    /// Arbitration: access modes held by this open.
    pub(crate) held_access: u8,
    /// Arbitration: deny modes held by this open.
    pub(crate) held_deny: u8,
    /// Close-on-exec flag.
    pub(crate) cloexec: u8,
    /// Neutral append-on-write state for sequential writes.
    pub(crate) append_on_write: u8,
    /// Neutral nonblocking I/O state.
    pub(crate) nonblocking: u8,
    /// Delete-on-close flag (Win32 FILE_FLAG_DELETE_ON_CLOSE).
    pub(crate) delete_on_close: u8,
}

impl ObjectSlot {
    pub(crate) const fn zeroed() -> Self {
        ObjectSlot {
            rights: 0,
            _pad0: [0; 3],
            flags: 0,
            offset: 0,
            dir_cursor: 0,
            backing: ObjectBacking::None,
            held_access: 0,
            held_deny: 0,
            cloexec: 0,
            append_on_write: 0,
            nonblocking: 0,
            delete_on_close: 0,
        }
    }

    pub(crate) fn is_free(&self) -> bool {
        matches!(self.backing, ObjectBacking::None)
    }

    pub(crate) fn is_reserved(&self) -> bool {
        matches!(self.backing, ObjectBacking::Reserved)
    }

    pub(crate) fn is_live(&self) -> bool {
        !self.is_free() && !self.is_reserved()
    }

    pub(crate) fn reserve(&mut self) {
        *self = ObjectSlot::zeroed();
        self.backing = ObjectBacking::Reserved;
    }

    pub(crate) fn clear(&mut self) {
        *self = ObjectSlot::zeroed();
    }

    pub(crate) fn kind(&self) -> ObjectKind {
        match self.backing {
            ObjectBacking::None | ObjectBacking::Reserved => ObjectKind::None,
            ObjectBacking::Vnode { kind, .. } => kind,
            ObjectBacking::Pipe { .. } => ObjectKind::Pipe,
            ObjectBacking::UnixSocket { .. } => ObjectKind::UnixSocket,
            ObjectBacking::InetSocket { .. } => ObjectKind::InetSocket,
            ObjectBacking::Epoll { .. } => ObjectKind::Epoll,
        }
    }

    pub(crate) fn vnode_handle(&self) -> VnodeHandle {
        match self.backing {
            ObjectBacking::Vnode { vnode, .. } => vnode,
            ObjectBacking::Pipe { vnode, .. } => vnode,
            _ => VnodeHandle::INVALID,
        }
    }

    pub(crate) fn inode(&self) -> u32 {
        match self.backing {
            ObjectBacking::Vnode { inode, .. } => inode,
            ObjectBacking::Pipe { inode, .. } => inode,
            _ => 0,
        }
    }

    pub(crate) fn device_info(&self) -> Option<DeviceInfo> {
        match self.backing {
            ObjectBacking::Vnode { device, .. } => device,
            _ => None,
        }
    }

    pub(crate) fn pipe_handle(&self) -> Handle<PipeState> {
        match self.backing {
            ObjectBacking::Pipe { pipe, .. } => pipe,
            _ => Handle::<PipeState>::INVALID,
        }
    }

    pub(crate) fn unix_socket_handle(&self) -> Handle<SocketState> {
        match self.backing {
            ObjectBacking::UnixSocket { socket } => socket,
            _ => Handle::<SocketState>::INVALID,
        }
    }

    pub(crate) fn inet_socket_id(&self) -> Option<u32> {
        match self.backing {
            ObjectBacking::InetSocket { sock_id } => Some(sock_id),
            _ => None,
        }
    }

    pub(crate) fn epoll_handle(&self) -> Handle<EpollInstance> {
        match self.backing {
            ObjectBacking::Epoll { epoll } => epoll,
            _ => Handle::<EpollInstance>::INVALID,
        }
    }

    pub(crate) fn set_file(&mut self, vnode: VnodeHandle, inode: u32) {
        self.backing = ObjectBacking::Vnode {
            vnode,
            inode,
            kind: ObjectKind::File,
            device: None,
        };
    }

    pub(crate) fn set_directory(&mut self, vnode: VnodeHandle, inode: u32) {
        self.backing = ObjectBacking::Vnode {
            vnode,
            inode,
            kind: ObjectKind::Directory,
            device: None,
        };
    }

    pub(crate) fn set_device(&mut self, vnode: VnodeHandle, inode: u32, dev_type: u8, pty_id: u32) {
        self.backing = ObjectBacking::Vnode {
            vnode,
            inode,
            kind: ObjectKind::Device,
            device: Some(DeviceInfo { dev_type, pty_id }),
        };
    }

    pub(crate) fn set_shm(&mut self, vnode: VnodeHandle, inode: u32) {
        self.backing = ObjectBacking::Vnode {
            vnode,
            inode,
            kind: ObjectKind::Shm,
            device: None,
        };
    }

    pub(crate) fn set_pipe(&mut self, pipe: Handle<PipeState>) {
        self.backing = ObjectBacking::Pipe {
            pipe,
            vnode: VnodeHandle::INVALID,
            inode: 0,
        };
    }

    pub(crate) fn set_fifo_pipe(
        &mut self,
        pipe: Handle<PipeState>,
        vnode: VnodeHandle,
        inode: u32,
    ) {
        self.backing = ObjectBacking::Pipe { pipe, vnode, inode };
    }

    pub(crate) fn set_unix_socket(&mut self, socket: Handle<SocketState>) {
        self.backing = ObjectBacking::UnixSocket { socket };
    }

    pub(crate) fn set_inet_socket(&mut self, sock_id: u32) {
        self.backing = ObjectBacking::InetSocket { sock_id };
    }

    pub(crate) fn set_epoll(&mut self, epoll: Handle<EpollInstance>) {
        self.backing = ObjectBacking::Epoll { epoll };
    }
}

// =========================================================================
// ClientState
// =========================================================================

/// Per-client VFS state.
///
/// Allocated from `Arena<ClientState>` in `VfsState`. Looked up by badge
/// via `BadgeMap`.
///
/// All raw pointers (`*mut Vnode`, `*mut MountNamespace`) are replaced by
/// arena handles or inline arrays.
/// The `obj_lock: Mutex` is eliminated — the single-owner loop serializes
/// all access.
#[repr(C)]
pub(crate) struct ClientState {
    /// Client badge from IPC (lower 16 bits = PID).
    pub(crate) badge: u64,

    /// Personality identifier: `PERS_POSIX` (0) or `PERS_WIN32` (1).
    pub(crate) personality: u8,
    /// Number of occupied object slots.
    pub(crate) obj_count: u16,
    _pad0: [u8; 5],

    /// Handle-based current working directory (replaces `*mut Vnode`).
    pub(crate) cwd_vnode: VnodeHandle,
    /// Handle-based mount namespace (replaces `*mut MountNamespace`).
    pub(crate) mount_ns: MountNsHandle,

    /// Inline fd table.
    pub(crate) objects: [ObjectSlot; MAX_CLIENT_OBJECTS],

    /// Current working directory path (for introspection).
    pub(crate) cwd: [u8; 128],

    /// Credentials.
    pub(crate) cred_uid: u32,
    pub(crate) cred_gid: u32,
    pub(crate) cred_groups: [u32; 32],
    pub(crate) cred_ngroups: u8,
    pub(crate) creds_valid: u8,
    _pad1: [u8; 2],

    /// Bulk SHM region (mapped into VFS address space for large transfers).
    pub(crate) bulk_shm_vaddr: u64,
    pub(crate) bulk_shm_id: u64,

    /// Win32: current drive letter index (0=A, 1=B, 2=C, ..., 25=Z).
    pub(crate) win32_current_drive: u8,
    _pad2: [u8; 3],
    /// Win32: per-drive current working directory, stored as vnode inode ids.
    pub(crate) win32_drive_cwd: [u32; 26],
}

impl ClientState {
    pub(crate) const fn zeroed() -> Self {
        ClientState {
            badge: 0,
            personality: 0,
            obj_count: 0,
            _pad0: [0; 5],
            cwd_vnode: VnodeHandle::INVALID,
            mount_ns: MountNsHandle::INVALID,
            objects: [ObjectSlot::zeroed(); MAX_CLIENT_OBJECTS],
            cwd: [0; 128],
            cred_uid: 0,
            cred_gid: 0,
            cred_groups: [0; 32],
            cred_ngroups: 0,
            creds_valid: 0,
            _pad1: [0; 2],
            bulk_shm_vaddr: 0,
            bulk_shm_id: 0,
            win32_current_drive: 0,
            _pad2: [0; 3],
            win32_drive_cwd: [0; 26],
        }
    }
}
