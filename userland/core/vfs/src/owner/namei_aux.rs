// SPDX-License-Identifier: GPL-2.0-only
//
//! Async namei walker scratch state.
//!
//! Some `NameiTerminal` variants need scratch storage that does
//! not fit alongside the small inline values most terminals
//! carry — symlink target bytes, dual-path rename / link
//! state — so the walker stamps a `NameiAuxHandle` onto the
//! terminal and parks the actual bytes in this arena.
//!
//! Lifetime: the aux entry is allocated by the posix handler at
//! walk start, threaded through `NameiTerminal::{Symlink, Rename,
//! Link}`, and released by the terminal callback once the final
//! mutation completes (sync or parked) or by `cancel_for_badge`
//! when the client tears down mid-walk. The arena is owner-thread
//! only, like every other vfs arena.

use crate::arena::Handle;
use crate::core::identity::VnodeKey;
use crate::owner::pending::{WALK_NAME_MAX, WALK_PATH_MAX, WALK_SYMLINK_TARGET_MAX};

/// Opaque arena handle. Stable across walker park / resume.
pub(crate) type NameiAuxHandle = Handle<NameiAuxState>;

/// Per-walker scratch entry. The discriminant pins which posix
/// path this slot is feeding (symlink, rename, link) — the
/// terminal callback inspects the variant before reading the
/// fields it expects.
#[derive(Clone, Copy)]
pub(crate) enum NameiAuxState {
    /// Slot is on the free list; reading the contents is undefined.
    Empty,
    /// `VFS_SYMLINK` — the walker resolved the parent and the
    /// terminal callback now needs the original target bytes
    /// supplied by the client to invoke `meta.symlink(parent,
    /// name, target, ...)`.
    Symlink {
        target: [u8; WALK_SYMLINK_TARGET_MAX],
        target_len: u16,
    },
    /// `VFS_RENAME` — two-stage walker. The source stage walks
    /// the *old* path with `StopAtParent`; the terminal stashes
    /// the old parent's `VnodeKey` plus the consumed `old_name`
    /// here and kicks the dest stage with the new path. The dest
    /// terminal reads both halves and invokes
    /// `meta.rename(old_parent, old_name, new_parent, new_name)`.
    ///
    /// `new_anchor_vkey` carries the resolved `anchor_fd_new`
    /// (renameat's `newdirfd`) so the dest walk can root at the
    /// caller-specified directory rather than always falling back
    /// to the namespace root.
    Rename {
        stage: RenameStage,
        new_path: [u8; WALK_PATH_MAX],
        new_path_len: u16,
        old_dir_vkey: VnodeKey,
        old_name: [u8; WALK_NAME_MAX],
        old_name_len: u8,
        new_anchor_vkey: VnodeKey,
    },
    /// `VFS_LINK` — two-stage walker. The source-lookup stage
    /// walks the *target* path with `FinalMustExist` and stashes
    /// the resolved target's `VnodeKey` here. The dest-parent
    /// stage walks the *new path* with `StopAtParent` and invokes
    /// `meta.link(new_parent, new_name, target_vnode)`.
    ///
    /// `new_anchor_vkey` carries the resolved `anchor_fd_new`
    /// (linkat's `newdirfd`) so the dest-parent walk roots at the
    /// caller-specified directory.
    Link {
        stage: LinkStage,
        new_path: [u8; WALK_PATH_MAX],
        new_path_len: u16,
        target_vkey: VnodeKey,
        new_anchor_vkey: VnodeKey,
    },
}

/// Rename two-stage state marker. The walker terminal inspects
/// this to decide whether the current invocation is the source
/// walk or the dest walk.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenameStage {
    /// Walking the old path — terminal will stash old parent +
    /// old name then advance to `DestWalk`.
    SourceWalk,
    /// Walking the new path — terminal will dispatch
    /// `meta.rename`.
    DestWalk,
}

/// Link two-stage state marker.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkStage {
    /// Walking the target path with `FinalMustExist` — terminal
    /// will stash the resolved target's `VnodeKey` then advance to
    /// `DestParent`.
    SourceLookup,
    /// Walking the new path with `StopAtParent` — terminal will
    /// dispatch `meta.link`.
    DestParent,
}

impl NameiAuxState {
    /// Free-slot sentinel. The arena writes this back on release
    /// so a stale handle observe a deterministic placeholder.
    pub(crate) const EMPTY: Self = NameiAuxState::Empty;
}

impl Default for NameiAuxState {
    #[inline]
    fn default() -> Self {
        NameiAuxState::EMPTY
    }
}
