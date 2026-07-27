// SPDX-License-Identifier: GPL-2.0-only
//! VFS data structures: personality-neutral client state.
//!
//! `ClientState` tracks per-client VFS state (fds, credentials, cwd, mount
//! namespace). Per-fd open state lives in `OpenObject` (see
//! `server/open_object.rs`); `ClientState.slots` holds lightweight
//! `ObjectRef` handles into `VfsState.open_objects`.
//!
//! All raw pointers to VFS objects (`*mut Vnode`, `*mut Mount`,
//! `*mut MountNamespace`) are replaced by arena handles.

use crate::arena::Handle;
use crate::ipc_objects::{EpollInstance, PipeState, SocketState};
use crate::server::open_object::ObjectRef;
use crate::vfs_core::mount_ns::MountNsHandle;
use crate::vfs_core::vnode::VnodeHandle;

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

    /// Current working directory as a stable identity + cached
    /// handle hint pair. Authoritative identity lives in the `id()`
    /// side; the handle hint is kept valid by the pin held on the
    /// cwd vnode (see `misc::cwd::handle_chdir_owned` and
    /// `fd_ops::handle_clone_fds_owned`). Readers that need a live
    /// handle resolve via `CachedRef::resolve(&state)` which falls
    /// back to the resolve cache on hint staleness. Named `cwd_ref`
    /// to avoid colliding with the byte-array `cwd` path below.
    pub(crate) cwd_ref:
        crate::vfs_core::cached_ref::CachedRef<crate::vfs_core::identity::VnodeKey, VnodeHandle>,
    /// Handle-based mount namespace (replaces `*mut MountNamespace`).
    pub(crate) mount_ns: MountNsHandle,

    /// Per-slot references into `VfsState.open_objects`. Each occupied
    /// entry points at one live `OpenObject` that owns the shared
    /// backing, offset, status flags, arbitration hold, etc. Sharing
    /// rules (POSIX `dup` duplicates a reference vs deep-copies) are
    /// imposed by the personality layer. Commit 1 preserves per-slot
    /// semantics by deep-copying into a fresh `OpenObject` per
    /// duplication; commit 2 introduces shared references + refcounting.
    pub(crate) slots: [ObjectRef; MAX_CLIENT_OBJECTS],

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

    _pad2: [u8; 4],
    // Win32-specific CWD state (current drive letter + per-drive
    // CWD) previously lived here as two fields. It has moved to the
    // `personality/win32/cwd_table.rs` sidecar keyed by the client's
    // `Handle<ClientState>` so the generic `server/` layer carries
    // no Win32-specific fields.
}

impl ClientState {
    pub(crate) const fn zeroed() -> Self {
        ClientState {
            badge: 0,
            personality: 0,
            obj_count: 0,
            _pad0: [0; 5],
            cwd_ref: crate::vfs_core::cached_ref::CachedRef::<
                crate::vfs_core::identity::VnodeKey,
                VnodeHandle,
            >::INVALID,
            mount_ns: MountNsHandle::INVALID,
            slots: [ObjectRef::empty(); MAX_CLIENT_OBJECTS],
            cwd: [0; 128],
            cred_uid: 0,
            cred_gid: 0,
            cred_groups: [0; 32],
            cred_ngroups: 0,
            creds_valid: 0,
            _pad1: [0; 2],
            bulk_shm_vaddr: 0,
            bulk_shm_id: 0,
            _pad2: [0; 4],
        }
    }
}
