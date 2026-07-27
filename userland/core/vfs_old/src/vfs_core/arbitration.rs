// SPDX-License-Identifier: GPL-2.0-only
//! Unified access arbitration — cross-personality share-mode enforcement.
//!
//! This module provides a personality-neutral primitive for rejecting opens
//! that would violate a share-mode restriction declared by another open.
//! It makes SaltyOS a strict superset of both POSIX (which historically
//! ignores share modes) and Win32 (which enforces them internally):
//!
//! - Each `OpenFile` records the **access** modes it exercises (READ,
//!   WRITE, EXEC, UNLINK_NAME) and the modes it **denies** to others
//!   (READ, WRITE, UNLINK_NAME).
//! - `Vnode` aggregates the running totals of both vectors.
//! - Before admitting a new open, [`check_open`] checks that:
//!     1. No existing open denies the modes the newcomer requests; **and**
//!     2. The newcomer's deny set does not conflict with modes existing
//!        opens already hold.
//! - If both checks pass, [`install_open`] adjusts the aggregate counters.
//! - [`release_open`] reverses the counters at close time.
//!
//! ## Delete semantics
//!
//! `ACCESS_UNLINK_NAME` controls dirent removal (name → inode binding),
//! NOT object lifetime. The split is crucial for cross-personality
//! coexistence:
//!
//! - **POSIX `unlink`**: Always removes the dirent — `denies_unlink_name`
//!   is ignored. This preserves tmpfile patterns, atomic replace, and
//!   write-rename idioms. The vnode stays alive while `open_count > 0`.
//! - **Win32 `DeleteFile` / `MoveFileEx(REPLACE_EXISTING)`**: Checks
//!   `denies_unlink_name` via [`check_unlink_name`]. If any Win32 handle
//!   lacks `FILE_SHARE_DELETE`, the delete is refused with
//!   `SharingViolation`.
//!
//! See [`check_unlink_name`] for the per-personality gate.
//!
//! ## Personality policies
//!
//! Each personality layer chooses what to populate in `(access, deny)`:
//!
//! - **POSIX** (`personality/posix/policy.rs`): `open(2)` yields `(READ | WRITE, 0)`
//!   by default — POSIX reads and writes are freely shared. `flock(LOCK_EX)`
//!   additively installs `(0, READ | WRITE)` at lock time.
//! - **Win32** (`personality/win32/policy.rs`): `CreateFileA(dwDesiredAccess,
//!   dwShareMode)` maps directly — the deny set is the inverse of `dwShareMode`.
//! - Future subsystems apply their own mapping.
//!
//! The arbitration primitive itself is ignorant of which subsystem drove it
//! — it just arbitrates between the aggregate vectors.
//!
//! All public functions are called from the owner loop (single-threaded).

use super::error::{VfsError, VfsResult};
use super::vnode::Vnode;

// =========================================================================
// Access / deny bit flags
// =========================================================================

/// Read access (POSIX O_RDONLY/O_RDWR, Win32 GENERIC_READ).
pub(crate) const ACCESS_READ: u8 = 1 << 0;
/// Write access (POSIX O_WRONLY/O_RDWR, Win32 GENERIC_WRITE).
pub(crate) const ACCESS_WRITE: u8 = 1 << 1;
/// Execute / traverse access (Win32 GENERIC_EXECUTE, POSIX exec of binaries).
pub(crate) const ACCESS_EXEC: u8 = 1 << 2;
/// Dirent removal access — controls whether the name→inode binding can
/// be removed. POSIX `unlink`/`rename` ignores denies on this bit;
/// Win32 `DeleteFile`/`MoveFileEx(REPLACE_EXISTING)` checks it.
pub(crate) const ACCESS_UNLINK_NAME: u8 = 1 << 3;

// =========================================================================
// Compatibility check
// =========================================================================

/// Validate that a prospective open with `(want_access, want_deny)` can
/// coexist with the opens already installed on `vp`.
///
/// # Preconditions
///
/// The caller must hold `vp.lock`.
///
/// # Errors
///
/// - [`VfsError::SharingViolation`] — a conflict exists with an existing
///   open's deny set or with the new open's deny set vs existing accesses.
#[inline]
pub(crate) fn check_open(vp: &Vnode, want_access: u8, want_deny: u8) -> VfsResult<()> {
    // 1. Some existing open denies this new open's requested access.
    if (want_access & ACCESS_READ) != 0 && vp.denies_read > 0 {
        return Err(VfsError::SharingViolation);
    }
    if (want_access & ACCESS_WRITE) != 0 && vp.denies_write > 0 {
        return Err(VfsError::SharingViolation);
    }
    // ACCESS_UNLINK_NAME is NOT checked at open time — it is checked
    // only at unlink/rename time via `check_unlink_name`. This is because
    // POSIX unlink must always succeed (ignoring denies) while Win32
    // DeleteFile must be gated.

    // 2. This new open's deny set conflicts with existing accesses.
    if (want_deny & ACCESS_READ) != 0 && vp.opens_read > 0 {
        return Err(VfsError::SharingViolation);
    }
    if (want_deny & ACCESS_WRITE) != 0 && vp.opens_write > 0 {
        return Err(VfsError::SharingViolation);
    }
    // UNLINK_NAME denies do not interact with opens_* — they only
    // gate dirent removal at unlink time, per personality.

    Ok(())
}

/// Bump the aggregate open/deny counters to reflect a newly admitted open.
///
/// # Preconditions
///
/// The caller must hold `vp.lock` and must have already called
/// [`check_open`] with the same `(access, deny)` and received `Ok(())`.
#[inline]
pub(crate) fn install_open(vp: &mut Vnode, access: u8, deny: u8) {
    if (access & ACCESS_READ) != 0 {
        vp.opens_read += 1;
    }
    if (access & ACCESS_WRITE) != 0 {
        vp.opens_write += 1;
    }
    if (access & ACCESS_EXEC) != 0 {
        vp.opens_exec += 1;
    }
    if (deny & ACCESS_READ) != 0 {
        vp.denies_read += 1;
    }
    if (deny & ACCESS_WRITE) != 0 {
        vp.denies_write += 1;
    }
    if (deny & ACCESS_UNLINK_NAME) != 0 {
        vp.denies_unlink_name += 1;
    }
    vp.open_count += 1;
}

/// Undo an earlier [`install_open`] — called at close time.
///
/// # Preconditions
///
/// The caller must hold `vp.lock`. `access` and `deny` must match the
/// values passed to the original [`install_open`].
#[inline]
pub(crate) fn release_open(vp: &mut Vnode, access: u8, deny: u8) {
    if (access & ACCESS_READ) != 0 {
        vp.opens_read = vp.opens_read.saturating_sub(1);
    }
    if (access & ACCESS_WRITE) != 0 {
        vp.opens_write = vp.opens_write.saturating_sub(1);
    }
    if (access & ACCESS_EXEC) != 0 {
        vp.opens_exec = vp.opens_exec.saturating_sub(1);
    }
    if (deny & ACCESS_READ) != 0 {
        vp.denies_read = vp.denies_read.saturating_sub(1);
    }
    if (deny & ACCESS_WRITE) != 0 {
        vp.denies_write = vp.denies_write.saturating_sub(1);
    }
    if (deny & ACCESS_UNLINK_NAME) != 0 {
        vp.denies_unlink_name = vp.denies_unlink_name.saturating_sub(1);
    }
    vp.open_count = vp.open_count.saturating_sub(1);
}

// =========================================================================
// Personality-gated unlink check
// =========================================================================

/// Personality identifiers for arbitration decisions.
pub(crate) const PERS_POSIX: u8 = 0;
pub(crate) const PERS_WIN32: u8 = 1;

/// Check whether the caller's personality is allowed to remove this
/// vnode's dirent (name → inode binding).
///
/// - **POSIX**: Always returns `Ok(())` — POSIX `unlink` ignores
///   `denies_unlink_name`. This preserves tmpfile patterns (`open` +
///   `unlink`), atomic replace (`rename` over existing), and
///   write-rename idioms.
/// - **Win32**: Returns `Err(SharingViolation)` if any existing open
///   has denied unlink (i.e. opened without `FILE_SHARE_DELETE`).
///
/// # Preconditions
///
/// The caller must hold `vp.lock`.
#[inline]
pub(crate) fn check_unlink_name(vp: &Vnode, personality: u8) -> VfsResult<()> {
    if personality == PERS_WIN32 && vp.denies_unlink_name > 0 {
        return Err(VfsError::SharingViolation);
    }
    Ok(())
}
