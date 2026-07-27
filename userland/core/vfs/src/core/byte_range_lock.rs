// SPDX-License-Identifier: GPL-2.0-only
//
//! Byte-range advisory lock storage — shared by Win32
//! `NtLockFile` / `NtUnlockFile` and POSIX `fcntl(F_SETLK)` /
//! `fcntl(F_SETLKW)` / `fcntl(F_GETLK)`.
//!
//! Each `ByteRangeLock` is an arena-allocated record threaded onto
//! the owning vnode via `Vnode.locks_head`. The list is intrusive
//! (singly linked through `next`) so the lock table never needs an
//! external map keyed by vnode.
//!
//! Owner identity is the `OpenObject` handle. NT byte-range locks
//! are per-handle by design; POSIX fcntl locks are per-process by
//! ABI but every fd that aliases the same `OpenObject` shares the
//! description, which is sufficient for the saltyos invariant
//! (one `OpenObject` per logical open, fork duplicates the table
//! by handle copy). Cross-process POSIX semantics fold onto this
//! by treating each client's `OpenObject` as the owner.

use crate::arena::handle::Handle;
use crate::core::identity::VnodeKey;
use crate::server::open_object::OpenObject;

/// Lock kind. `Empty` is the arena-free sentinel.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ByteRangeLockKind {
    Empty = 0,
    /// Shared / read lock — multiple concurrent owners allowed.
    /// Maps to NT `ExclusiveLock=FALSE` and POSIX `F_RDLCK`.
    Shared = 1,
    /// Exclusive / write lock — at most one owner. Maps to NT
    /// `ExclusiveLock=TRUE` and POSIX `F_WRLCK`.
    Exclusive = 2,
}

/// One byte-range lock record.
#[repr(C)]
pub(crate) struct ByteRangeLock {
    /// Composite identity of the owning vnode. Mirrors
    /// `Vnode.key`; used to defend against arena slot reuse if a
    /// stale handle ever reaches a teardown helper.
    pub vnode_key: VnodeKey,
    /// `OpenObject` that took the lock. Lock auto-releases when
    /// the open object's last fd closes.
    pub owner_open: Handle<OpenObject>,
    /// Lock starts at this byte offset.
    pub start: u64,
    /// Lock length in bytes. `0` is the NT / POSIX sentinel for
    /// "to end of file"; conflict checks treat it as `u64::MAX`.
    pub length: u64,
    pub kind: ByteRangeLockKind,
    _pad: [u8; 7],
    /// Next record on the owning vnode's lock list, or
    /// `Handle::INVALID` for the tail.
    pub next: Handle<ByteRangeLock>,
}

impl ByteRangeLock {
    pub(crate) const EMPTY: Self = Self {
        vnode_key: VnodeKey::NONE,
        owner_open: Handle::INVALID,
        start: 0,
        length: 0,
        kind: ByteRangeLockKind::Empty,
        _pad: [0; 7],
        next: Handle::INVALID,
    };

    pub(crate) const fn new(
        vnode_key: VnodeKey,
        owner_open: Handle<OpenObject>,
        start: u64,
        length: u64,
        kind: ByteRangeLockKind,
        next: Handle<ByteRangeLock>,
    ) -> Self {
        Self {
            vnode_key,
            owner_open,
            start,
            length,
            kind,
            _pad: [0; 7],
            next,
        }
    }

    /// Return `true` when the lock covers byte index `idx`.
    #[inline]
    pub(crate) fn covers(&self, idx: u64) -> bool {
        let end = if self.length == 0 {
            u64::MAX
        } else {
            self.start.saturating_add(self.length)
        };
        idx >= self.start && idx < end
    }

    /// Return `true` when this lock overlaps the requested range.
    ///
    /// `length == 0` means "to EOF" on both the POSIX and NT
    /// surfaces. The implementation deliberately routes through
    /// [`Self::covers`] for endpoint checks so point containment
    /// and range overlap stay in one place.
    #[inline]
    pub(crate) fn overlaps_range(&self, start: u64, length: u64) -> bool {
        if self.kind == ByteRangeLockKind::Empty {
            return false;
        }
        if self.covers(start) {
            return true;
        }
        if length != 0 {
            let last = start.saturating_add(length.saturating_sub(1));
            if self.covers(last) {
                return true;
            }
        }
        Self::range_covers(start, length, self.start)
    }

    /// Return `true` when range `[start, start+length)` covers
    /// byte `idx`, with `length == 0` extending to EOF.
    #[inline]
    fn range_covers(start: u64, length: u64, idx: u64) -> bool {
        let end = if length == 0 {
            u64::MAX
        } else {
            start.saturating_add(length)
        };
        idx >= start && idx < end
    }
}
