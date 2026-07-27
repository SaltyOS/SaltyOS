// SPDX-License-Identifier: GPL-2.0-only
//
//! `OpenObject` — personality-neutral open-file table entry.
//!
//! One `OpenObject` per `open()` (or `socket()`, `pipe()`, etc.).
//! Multiple fds (via `dup` / `dup2` / `fcntl(F_DUPFD)` / SCM_RIGHTS)
//! reference the same object — they all point at the same Arena
//! handle, refcount tracks the alias count.
//!
//! POSIX `fd_flags`, `O_NONBLOCK`, file offset, dir cursor all live
//! here; the personality layer projects on top.

use crate::arena::handle::Handle;
use crate::core::identity::VnodeKey;
use crate::core::vnode::Vnode;

/// Maximum final component bytes stored on a named-open record.
/// Kept in sync with the async namei walker's component buffer.
pub(crate) const OPEN_OBJECT_NAME_MAX: usize = 144;

/// Per-fd close-on-exec bit stored in the client fd table, not in
/// [`OpenObjectFlags`].
pub(crate) const FD_FLAG_CLOEXEC: u8 = 0x01;

/// `OpenObject` flags packed into a single byte. These describe
/// the open file *description* — properties shared by every fd
/// that aliases the same `OpenObject` (via `dup`-class operations
/// or `fork`). Per-fd state — `FD_CLOEXEC` — lives in the fd
/// table itself ([`crate::arena::segmented_slot_table::FdFlags`])
/// so duplicates carry independent values.
pub(crate) struct OpenObjectFlags;

impl OpenObjectFlags {
    pub(crate) const O_NONBLOCK: u8 = 0x02;
    pub(crate) const O_APPEND: u8 = 0x04;
    pub(crate) const O_DIRECTORY: u8 = 0x08;
    pub(crate) const READABLE: u8 = 0x10;
    pub(crate) const WRITABLE: u8 = 0x20;
}

/// Access bits used for cross-open sharing arbitration. These are
/// distinct from [`OpenObjectFlags`] because sharing cares about
/// the access the handle requested, not about fd-local behavioural
/// flags such as append or nonblocking.
pub(crate) struct OpenObjectAccess;

impl OpenObjectAccess {
    pub(crate) const READ: u8 = 1 << 0;
    pub(crate) const WRITE: u8 = 1 << 1;
    pub(crate) const DELETE: u8 = 1 << 2;
}

/// Internal finalizer selector for non-regular open objects. Most
/// opens point at a live vnode and tear down through vnode
/// refcounts. A few POSIX/NT synthetic descriptors instead pin
/// side arenas (`PipeState`, `SocketState`, `ShmData`, `EpollInstance`)
/// through `personality_aux`; `close` uses this tag to drop that
/// side state exactly once when the open-object refcount reaches 0.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenObjectKind {
    Vnode = 0,
    Pipe = 1,
    Socket = 2,
    Shm = 3,
    Epoll = 4,
}

/// Stable parent/name projection for handle-based operations.
///
/// POSIX mostly reaches mutations by path, but NT exposes several
/// handle-based operations (`NtRenameFile`,
/// `FileDispositionInformation`, security queries) that need to
/// recover the directory entry the open object was created from.
/// This anchor is stored only when the open path resolved through
/// a normal named component; anonymous objects and namespace roots
/// carry [`Self::EMPTY`].
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OpenObjectAnchor {
    pub parent_vkey: VnodeKey,
    pub name: [u8; OPEN_OBJECT_NAME_MAX],
    pub name_len: u8,
    _pad: [u8; 7],
}

impl OpenObjectAnchor {
    pub(crate) const EMPTY: Self = Self {
        parent_vkey: VnodeKey::NONE,
        name: [0u8; OPEN_OBJECT_NAME_MAX],
        name_len: 0,
        _pad: [0; 7],
    };

    #[inline]
    pub(crate) const fn is_valid(self) -> bool {
        self.parent_vkey.is_valid() && self.name_len != 0
    }

    pub(crate) fn from_component(parent_vkey: VnodeKey, name: &[u8], name_len: u8) -> Self {
        let n = (name_len as usize)
            .min(name.len())
            .min(OPEN_OBJECT_NAME_MAX);
        if !parent_vkey.is_valid() || n == 0 {
            return Self::EMPTY;
        }
        let mut out = Self::EMPTY;
        out.parent_vkey = parent_vkey;
        out.name_len = n as u8;
        out.name[..n].copy_from_slice(&name[..n]);
        out
    }
}

/// Optional named-open metadata for an open file description.
///
/// This is personality-neutral: the parent/name anchor is useful
/// to any handle-based operation that needs to recover the opened
/// directory entry, and deferred unlink is the generic
/// remove-on-last-close policy. NT access masks and handle flags
/// live in the Win32 personality's handle-state arena.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OpenObjectNamedState {
    pub anchor: OpenObjectAnchor,
    /// Remove this anchor when the final fd alias closes.
    pub deferred_unlink: u8,
    _pad: [u8; 7],
}

impl OpenObjectNamedState {
    pub(crate) const EMPTY: Self = Self {
        anchor: OpenObjectAnchor::EMPTY,
        deferred_unlink: 0,
        _pad: [0; 7],
    };
}

/// Open-object body. Field set widens as posix handlers and the
/// page-cache layer attach their own state (offset cursor, dir
/// cursor, page-cache pin, MAP_SHARED tracking).
#[repr(C)]
pub(crate) struct OpenObject {
    /// Handle to the underlying vnode.
    pub vnode: Handle<Vnode>,
    /// File offset for read/write/seek. Bytes.
    pub offset: u64,
    /// Aliased reference count — bumps on `dup`-class operations,
    /// drops on `close`.
    pub refcount: u32,
    /// `OpenObjectFlags` bitmask.
    pub flags: u8,
    /// Requested data/name access bits for share arbitration.
    pub access: u8,
    pub kind: OpenObjectKind,
    _pad: u8,
    /// Share policy bits copied from `VfsOpenSpec.share`.
    pub share: u32,
    /// Full personality-neutral `OpenOptions` bitmap. `flags`
    /// keeps hot POSIX-style read/write/nonblock/append bits; this
    /// word preserves the rest of the open-mode state for fcntl,
    /// NT mode queries, and later direct/sync I/O paths.
    pub options: u32,
    /// Kind/private state slot. For synthetic objects the arena is
    /// selected by [`OpenObjectKind`] (pipe/socket/shm/epoll). For
    /// vnode-backed Win32 handles this stores the Win32 handle-state
    /// slot. Vnode-backed POSIX opens keep `u32::MAX`.
    pub personality_aux: u32,
    /// Optional named-open metadata such as parent/name anchor and
    /// deferred-unlink disposition.
    pub named_state: Handle<OpenObjectNamedState>,
    /// For `/dev/tty` opens: the pty id of the caller session's
    /// controlling terminal, resolved at open time via posix_ttysrv.
    /// `u32::MAX` means "not a bound controlling-tty handle".
    pub ctty_pty: u32,
}

impl OpenObject {
    pub(crate) const EMPTY: Self = Self {
        vnode: Handle::INVALID,
        offset: 0,
        refcount: 0,
        flags: 0,
        access: 0,
        kind: OpenObjectKind::Vnode,
        _pad: 0,
        share: 0,
        options: 0,
        personality_aux: u32::MAX,
        named_state: Handle::INVALID,
        ctty_pty: u32::MAX,
    };
}
