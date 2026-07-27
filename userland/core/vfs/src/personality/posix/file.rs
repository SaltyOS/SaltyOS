// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX file-mode helpers — `mode_t` projection, umask
//! application, `st_mode` construction, and the
//! permission-check matrix used by the POSIX dispatch entry
//! when an inbound request lands on a vnode whose attribute
//! cache is populated.
//!
//! The `Vnode.attr` field carries the personality-neutral
//! (uid, gid, perm-bits, vtype) tuple; this module projects
//! that tuple onto the POSIX-shaped `st_mode` and applies the
//! POSIX access-check rules. Win32 has its own ACL-based path
//! in `personality::win32::file`.
#![allow(dead_code)]

use super::consts::{
    S_IFBLK_L, S_IFCHR_L, S_IFDIR_L, S_IFIFO_L, S_IFLNK_L, S_IFMT_L, S_IFREG_L, S_IFSOCK_L,
    S_IRGRP, S_IROTH, S_IRUSR, S_ISGID, S_ISUID, S_ISVTX, S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP,
    S_IXOTH, S_IXUSR,
};

/// POSIX `mode_t` — file-mode bit field. Linux uses `unsigned
/// int` (32 bit); SaltyOS keeps the same width.
pub(crate) type ModeT = u32;

/// POSIX `uid_t` / `gid_t` — 32-bit unsigned identifiers.
pub(crate) type UidT = u32;
pub(crate) type GidT = u32;

/// Default umask if the calling process has not supplied one
/// through `INIT_UMASK_*`. POSIX-conventional 022 — owner
/// keeps full perms, group / other lose write.
pub(crate) const DEFAULT_UMASK: ModeT = 0o022;

/// Mask of permission bits that `umask` is allowed to clear.
/// `S_ISUID` / `S_ISGID` / `S_ISVTX` (high triple) are
/// preserved across the mask.
pub(crate) const UMASK_BITS: ModeT = 0o777;

/// Apply `umask` to a caller-supplied `mode` argument the way
/// POSIX `open(O_CREAT, mode)` and `mkdir(mode)` do.
#[inline]
pub(crate) const fn apply_umask(mode: ModeT, umask: ModeT) -> ModeT {
    let cleared = mode & !(umask & UMASK_BITS);
    cleared
}

/// Compose a POSIX `st_mode` from the personality-neutral
/// (vtype, perm) pair the vnode core carries. `vtype` comes
/// from `Vnode.kind` (the `VT_*` byte); `perm` is the lower
/// 12 bits (suid/sgid/sticky + rwx triple).
#[inline]
pub(crate) const fn compose_st_mode(vtype: u8, perm: ModeT) -> ModeT {
    super::consts::vtype_to_mode(vtype) | (perm & 0o7777)
}

/// Decompose `st_mode` into `(vtype, perm)`.
#[inline]
pub(crate) const fn split_st_mode(st_mode: ModeT) -> (u8, ModeT) {
    let vtype = super::consts::mode_to_vtype(st_mode);
    let perm = st_mode & 0o7777;
    (vtype, perm)
}

/// Quick test for the `S_IFMT` bucket of an `st_mode`. Returns
/// `true` when the mode is one of the recognised POSIX file
/// types.
#[inline]
pub(crate) const fn is_known_filetype(st_mode: ModeT) -> bool {
    matches!(
        st_mode & S_IFMT_L,
        S_IFREG_L | S_IFDIR_L | S_IFLNK_L | S_IFIFO_L | S_IFCHR_L | S_IFBLK_L | S_IFSOCK_L
    )
}

/// Permission-check input: which classes of access the caller
/// requested (read / write / execute).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct AccessRequest {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl AccessRequest {
    pub(crate) const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }

    pub(crate) const fn write_only() -> Self {
        Self {
            read: false,
            write: true,
            execute: false,
        }
    }

    pub(crate) const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    pub(crate) const fn execute_only() -> Self {
        Self {
            read: false,
            write: false,
            execute: true,
        }
    }
}

/// POSIX permission-check decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccessDecision {
    /// Caller has all requested rights — proceed.
    Allow,
    /// Caller is missing at least one requested right.
    DenyEAcces,
}

/// Run the POSIX permission-check matrix:
///
/// 1. Root (uid 0) bypasses the read / write check unconditionally
///    and bypasses the execute check unless **no** execute bit
///    is set anywhere in the mode (matches Linux's `generic_permission`
///    semantics).
/// 2. Otherwise the caller is matched against owner / group /
///    other tier and the corresponding rwx triple is consulted.
#[inline]
pub(crate) fn posix_perm_check(
    file_uid: UidT,
    file_gid: GidT,
    file_mode: ModeT,
    caller_uid: UidT,
    caller_gid: GidT,
    req: AccessRequest,
) -> AccessDecision {
    if caller_uid == 0 {
        if req.execute {
            let any_execute = (file_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
            if !any_execute {
                return AccessDecision::DenyEAcces;
            }
        }
        return AccessDecision::Allow;
    }
    let (rmask, wmask, xmask) = if caller_uid == file_uid {
        (S_IRUSR, S_IWUSR, S_IXUSR)
    } else if caller_gid == file_gid {
        (S_IRGRP, S_IWGRP, S_IXGRP)
    } else {
        (S_IROTH, S_IWOTH, S_IXOTH)
    };
    if req.read && (file_mode & rmask) == 0 {
        return AccessDecision::DenyEAcces;
    }
    if req.write && (file_mode & wmask) == 0 {
        return AccessDecision::DenyEAcces;
    }
    if req.execute && (file_mode & xmask) == 0 {
        return AccessDecision::DenyEAcces;
    }
    AccessDecision::Allow
}

/// Sticky-bit override for unlink / rename inside a directory.
/// When `+t` is set on a directory and the caller is not root /
/// not the owner of the directory itself / not the owner of the
/// target, deletion is denied even if write permission would
/// otherwise allow it. Used by `posix/unlink.rs` and
/// `posix/rename.rs` after the basic `posix_perm_check` pass.
#[inline]
pub(crate) fn sticky_bit_blocks_delete(
    dir_mode: ModeT,
    dir_uid: UidT,
    target_uid: UidT,
    caller_uid: UidT,
) -> bool {
    if caller_uid == 0 {
        return false;
    }
    if (dir_mode & S_ISVTX) == 0 {
        return false;
    }
    caller_uid != dir_uid && caller_uid != target_uid
}

/// SUID / SGID propagation rule for `creat()` / `mkdir()`. POSIX
/// prescribes: when the parent directory has SGID set, new
/// entries inherit the parent's gid. Used by the dispatch entry
/// after the inbound mode has been reconciled with umask.
#[inline]
pub(crate) const fn inherit_sgid(parent_mode: ModeT, parent_gid: GidT, caller_gid: GidT) -> GidT {
    if (parent_mode & S_ISGID) != 0 {
        parent_gid
    } else {
        caller_gid
    }
}

/// Strip SUID / SGID after a write that does not preserve the
/// privilege bits. POSIX says: writing to an executable that
/// was SUID / SGID strips both bits (unless the caller is root
/// AND the binary's exec bit is for the owner only — the kernel
/// version Linux uses).
///
/// vfs follows the simpler "non-root caller writing → strip"
/// rule; the more nuanced kernel test sits at the trona-side
/// `chown` / `chmod` paths.
#[inline]
pub(crate) const fn strip_setid_after_write(current_mode: ModeT, caller_uid: UidT) -> ModeT {
    if caller_uid == 0 {
        return current_mode;
    }
    let mask = if (current_mode & S_IXGRP) != 0 {
        !(S_ISUID | S_ISGID)
    } else {
        // POSIX: non-group-executable files retain SGID for use
        // as mandatory-locking marker.
        !S_ISUID
    };
    current_mode & mask
}
