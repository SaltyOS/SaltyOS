// SPDX-License-Identifier: GPL-2.0-only
//
//! `dirfd` resolution + AT flag constants — shared by every
//! personality entry that takes an `anchor_fd` register on its
//! wire. Centralises three concerns:
//!
//! 1. The `AT_*` flag set every personality wire encodes in the
//!    `at_flags` slot.
//! 2. Resolving `(client, dirfd)` to either an anchor `VnodeKey`
//!    (for the namei walker) or a `VnodeHandle` (for handlers
//!    that pre-walk the parent directly).
//! 3. The single-source mapping for `AT_FDCWD` so its sentinel
//!    value (`-100`) lives in one place rather than being
//!    re-defined per-handler.
//!
//! All public helpers are owner-thread only — they read
//! `ClientState.cwd_vnode_*` and `ClientState.slot_table` which
//! are mutated only on the owner.

use crate::core::error::VfsError;
use crate::core::identity::VnodeKey;
use crate::core::vnode::VnodeHandle;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

/// `AT_FDCWD` sentinel — the personality wire passes this in the
/// `anchor_fd` register to mean "resolve `path` relative to the
/// caller's recorded current working directory."
pub(crate) const AT_FDCWD: i32 = -100;

/// `at_flags` bit set on `unlinkat` / `linkat` / `fstatat` to
/// force the walker to skip following the final-component
/// symlink. Mirrors the Linux ABI value.
pub(crate) const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// `at_flags` bit on `unlinkat` selecting `rmdir` semantics
/// rather than the default `unlink` semantics. The handler
/// dispatches to `meta.rmdir` when set.
pub(crate) const AT_REMOVEDIR: i32 = 0x200;

/// `at_flags` bit on `linkat` selecting "follow final component
/// of `oldpath`" (POSIX default for `linkat` is `nofollow`).
pub(crate) const AT_SYMLINK_FOLLOW: i32 = 0x400;

/// `at_flags` bit on `fstatat` / `fchownat` / `utimensat` /
/// `linkat` requesting an operation against the open fd
/// referenced by `dirfd` itself when `path` is empty. The
/// handler must short-circuit the namei walk in this case.
pub(crate) const AT_EMPTY_PATH: i32 = 0x1000;

pub(crate) fn resolve_dirfd_vkey(state: &VfsState, client: ClientHandle, dirfd: i32) -> VnodeKey {
    if dirfd == AT_FDCWD {
        let Some(cli) = state.clients.get(client) else {
            return VnodeKey::NONE;
        };
        if cli.cwd_vnode_slot == u32::MAX {
            return VnodeKey::NONE;
        }
        let h: VnodeHandle =
            crate::arena::handle::Handle::new(cli.cwd_vnode_slot, cli.cwd_vnode_epoch);
        return state.vnodes.get(h).map(|v| v.key).unwrap_or(VnodeKey::NONE);
    }
    if dirfd < 0 {
        return VnodeKey::NONE;
    }
    let Some(cli) = state.clients.get(client) else {
        return VnodeKey::NONE;
    };
    let Some(oh) = cli.slot_table.lookup(dirfd as u32) else {
        return VnodeKey::NONE;
    };
    let Some(obj) = state.open_objects.get(oh) else {
        return VnodeKey::NONE;
    };
    state
        .vnodes
        .get(obj.vnode)
        .map(|v| v.key)
        .unwrap_or(VnodeKey::NONE)
}

pub(crate) fn resolve_dirfd_handle(
    state: &VfsState,
    client: ClientHandle,
    dirfd: i32,
) -> Result<VnodeHandle, VfsError> {
    if dirfd == AT_FDCWD {
        let cli = state.clients.get(client).ok_or(VfsError::Io)?;
        if cli.cwd_vnode_slot == u32::MAX {
            return Err(VfsError::NoEnt);
        }
        return Ok(crate::arena::handle::Handle::new(
            cli.cwd_vnode_slot,
            cli.cwd_vnode_epoch,
        ));
    }
    if dirfd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get(client).ok_or(VfsError::Io)?;
    let oh = cli.slot_table.lookup(dirfd as u32).ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(oh).ok_or(VfsError::BadF)?;
    Ok(obj.vnode)
}

#[inline]
pub(crate) fn namei_follow_flags_from_at(at_flags: i32) -> u32 {
    if (at_flags & AT_SYMLINK_NOFOLLOW) != 0 {
        crate::core::namei_common::NAMEI_NOFOLLOW_FINAL
    } else {
        crate::core::namei_common::NAMEI_FOLLOW
    }
}
