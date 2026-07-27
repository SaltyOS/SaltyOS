// SPDX-License-Identifier: GPL-2.0-only
//! Open object description layer — personality-neutral.
//!
//! `OpenObject` describes one live instance of an opened resource (file,
//! pipe, socket, device, epoll, shm). It owns the mutable, sharable
//! state — backing, offset, status flags, readdir cursor, arbitration
//! hold, reference count — and lives in `VfsState.open_objects`.
//!
//! `ObjectRef` is the per-slot entry stored inline in `ClientState.slots`.
//! It is a thin handle + per-slot metadata (`cloexec`). Sharing rules
//! between slots are imposed by the personality layer:
//!
//! * POSIX `dup`/`dup2`/`dup3` / `F_DUPFD` / `clone_fds` / SCM_RIGHTS
//!   share one `OpenObject` across slots; `refcount` tracks the number
//!   of referencing `ObjectRef` slots and the arena entry is reclaimed
//!   (and backing torn down via `server::release::release_backing`) only
//!   when `refcount` reaches zero.
//! * Win32 `DuplicateHandle` semantics can be layered on top of the
//!   same `OpenObject` by the `personality/win32` code.
//!
//! Intentionally no POSIX-only terms (`fd`, "file description") leak
//! into this module — those belong in `personality/posix/` just like
//! the existing `ObjectBacking` neutral surface.

use crate::arena::Handle;
use crate::ipc_objects::{EpollInstance, PipeState, SocketState};
use crate::server::types::{DeviceInfo, ObjectBacking, ObjectKind};
use crate::vfs_core::vnode::VnodeHandle;

/// Stable identity for an `OpenObject` in `VfsState.open_objects`.
pub(crate) type OpenObjectHandle = Handle<OpenObject>;

/// Live description of one opened resource instance.
///
/// One `OpenObject` corresponds to one logical "open" of a backing.
/// Multiple `ObjectRef` slots can reference the same `OpenObject` under
/// rules defined by the personality (POSIX `dup`, Win32 `DuplicateHandle`,
/// etc.). `refcount` tracks the number of referencing `ObjectRef` slots;
/// the arena slot is released when `refcount` drops to zero.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OpenObject {
    /// Access rights (read / write / execute bits).
    pub(crate) rights: u8,
    _pad0: [u8; 3],
    /// Open flags (POSIX `O_*` or translated Win32 equivalent).
    pub(crate) flags: u32,
    /// Current sequential read/write offset.
    pub(crate) offset: u64,
    /// Readdir cursor position.
    pub(crate) dir_cursor: u32,
    /// Reference count — number of `ObjectRef` slots pointing at this
    /// `OpenObject`. Incremented by `VfsState::slot_share` and
    /// decremented by `VfsState::close_open_object`; when it reaches
    /// zero the backing is torn down via
    /// `server::release::release_backing` and the arena entry is
    /// released.
    pub(crate) refcount: u16,
    _pad1: [u8; 2],

    /// Backing state (neutral).
    pub(crate) backing: ObjectBacking,

    /// Arbitration: access modes held by this open.
    pub(crate) held_access: u8,
    /// Arbitration: deny modes held by this open.
    pub(crate) held_deny: u8,
    /// Append-on-write state for sequential writes.
    pub(crate) append_on_write: u8,
    /// Nonblocking I/O state.
    pub(crate) nonblocking: u8,
    /// Delete-on-close flag (Win32 `FILE_FLAG_DELETE_ON_CLOSE`).
    pub(crate) delete_on_close: u8,
    _pad2: [u8; 3],

    /// Cached readdir batch state. Populated by the backend's async
    /// readdir resume handler from a `BACKEND_READDIR` completion,
    /// drained one entry at a time by subsequent POSIX `readdir`
    /// calls before a fresh batch is requested. `entries_total == 0`
    /// marks an empty cache (no live batch). Currently only
    /// saltyfs populates this field; other backends leave it zeroed
    /// and never hit the cache-drain path.
    pub(crate) readdir_batch: ReaddirBatch,
}

/// Per-open cached readdir batch — saves a backend round-trip for
/// every directory entry by amortising one fetch across many POSIX
/// `readdir` calls. The record layout is backend-defined; today
/// saltyfs writes fixed 96-byte records into VFS↔saltyfs SHM at
/// `shm_offset`, and `entries_total` records how many the backend
/// returned. The resume emits entry `[entries_consumed]`, increments
/// `entries_consumed`, and leaves the rest for subsequent drain
/// calls. `cookie` is the backend's next cursor — used when the
/// cache runs dry to fetch the next batch.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ReaddirBatch {
    /// Backend's opaque cursor carried to the next `BACKEND_READDIR`
    /// request when the current batch is drained. `0` on a fresh
    /// cache and after an EOF-marking completion.
    pub(crate) cookie: u64,
    /// Byte offset into the backend's SHM region where the batch's
    /// first entry record resides. Saltyfs uses `0`; reserved so
    /// future backends can pack multiple live batches into one SHM.
    pub(crate) shm_offset: u32,
    /// Total entries written into SHM by the completion handler.
    /// Zero means "no cached batch".
    pub(crate) entries_total: u16,
    /// Entries already emitted to the client. When this reaches
    /// `entries_total` the cache is reset.
    pub(crate) entries_consumed: u16,
}

impl ReaddirBatch {
    #[inline]
    pub(crate) const fn zeroed() -> Self {
        ReaddirBatch {
            cookie: 0,
            shm_offset: 0,
            entries_total: 0,
            entries_consumed: 0,
        }
    }

    /// True when the batch has at least one entry remaining to emit.
    #[inline]
    pub(crate) const fn has_pending(&self) -> bool {
        self.entries_total > 0 && self.entries_consumed < self.entries_total
    }
}

impl OpenObject {
    pub(crate) const fn zeroed() -> Self {
        OpenObject {
            rights: 0,
            _pad0: [0; 3],
            flags: 0,
            offset: 0,
            dir_cursor: 0,
            refcount: 0,
            _pad1: [0; 2],
            backing: ObjectBacking::None,
            held_access: 0,
            held_deny: 0,
            append_on_write: 0,
            nonblocking: 0,
            delete_on_close: 0,
            _pad2: [0; 3],
            readdir_batch: ReaddirBatch::zeroed(),
        }
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

/// Per-slot entry inside a `ClientState.slots` array.
///
/// A thin reference: one handle into `VfsState.open_objects` plus
/// per-slot metadata. `cloexec` is the only field that is per-slot
/// (and not shared) — duplication of a slot may keep or clear this
/// flag independently of the referenced `OpenObject`'s state.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ObjectRef {
    /// Handle to the `OpenObject` this slot references. `INVALID` if
    /// the slot is free.
    pub(crate) open_object: OpenObjectHandle,
    /// Close-on-exec flag (per-slot; duplication-controlled).
    pub(crate) cloexec: u8,
    _pad: [u8; 3],
}

impl ObjectRef {
    pub(crate) const fn empty() -> Self {
        ObjectRef {
            open_object: OpenObjectHandle::INVALID,
            cloexec: 0,
            _pad: [0; 3],
        }
    }

    /// Construct a populated reference. The private padding is zeroed
    /// here so callers outside this module do not need to name the
    /// field.
    pub(crate) const fn new(open_object: OpenObjectHandle, cloexec: u8) -> Self {
        ObjectRef {
            open_object,
            cloexec,
            _pad: [0; 3],
        }
    }

    pub(crate) fn is_free(&self) -> bool {
        !self.open_object.is_valid()
    }
}
