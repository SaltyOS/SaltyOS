// SPDX-License-Identifier: GPL-2.0-only
//
//! Byte-range advisory lock helpers shared by Win32 lock entries
//! and POSIX `fcntl(F_SETLK)` / `fcntl(F_SETLKW)` /
//! `fcntl(F_GETLK)`.
//!
//! Conflict policy:
//! - Two `Shared` locks on the same range never conflict.
//! - A `Shared` lock and an `Exclusive` lock from different owners
//!   conflict.
//! - Two `Exclusive` locks from different owners conflict.
//! - Two locks on the same range from the same `OpenObject` owner
//!   never conflict — the second silently upgrades / overwrites
//!   the first (Windows and POSIX both permit this).
//!
//! Wait semantics:
//! - `fail_immediately = true` (Windows `FailImmediately = TRUE` /
//!   POSIX `F_SETLK`) refuses with `Again` on conflict.
//! - `fail_immediately = false` (Windows `FailImmediately = FALSE` /
//!   POSIX `F_SETLKW`) currently maps to the same refusal — the
//!   wait queue is wired in once the owner-reactor block-on-lock
//!   waiter list lands.

use trona_server::ReplyLease;

use crate::arena::handle::Handle;
use crate::core::byte_range_lock::{ByteRangeLock, ByteRangeLockKind};
use crate::core::error::VfsError;
use crate::core::vnode::Vnode;
use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::server::open_object::OpenObject;
use crate::server::types::ClientHandle;

/// Take a byte-range lock on the file backing `fd`.
///
/// Each personality projects success or lock conflict into its own
/// reply convention.
pub(crate) unsafe fn do_byte_range_lock(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    start: u64,
    length: u64,
    kind: ByteRangeLockKind,
    fail_immediately: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 || matches!(kind, ByteRangeLockKind::Empty) {
            return emit_err(reply_lease, reply_intent, VfsError::Inval);
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            return emit_err(reply_lease, reply_intent, VfsError::BadF);
        };
        let Some(vnode_h) = state.open_objects.get(open_h).map(|o| o.vnode) else {
            return emit_err(reply_lease, reply_intent, VfsError::BadF);
        };
        let Some(vnode_key) = state.vnodes.get(vnode_h).map(|v| v.key) else {
            return emit_err(reply_lease, reply_intent, VfsError::StaleIncarnation);
        };

        // Walk the existing lock list on this vnode for conflicts.
        let mut cursor = match state.vnodes.get(vnode_h) {
            Some(v) => v.locks_head,
            None => return emit_err(reply_lease, reply_intent, VfsError::StaleIncarnation),
        };
        let mut existing_same_owner: Handle<ByteRangeLock> = Handle::INVALID;
        while cursor.is_valid() {
            let Some(lk) = state.byte_range_locks.get(cursor) else {
                break;
            };
            let next = lk.next;
            if !lk.overlaps_range(start, length) {
                cursor = next;
                continue;
            }
            if lk.owner_open == open_h {
                // Same owner overlap: we will overwrite the kind /
                // range on this slot rather than allocate a second.
                existing_same_owner = cursor;
                cursor = next;
                continue;
            }
            // Different owner. Conflict matrix.
            let conflicts = match (lk.kind, kind) {
                (ByteRangeLockKind::Shared, ByteRangeLockKind::Shared) => false,
                _ => true,
            };
            if conflicts {
                let err = if fail_immediately {
                    VfsError::Again
                } else {
                    // Wait queue not yet wired — surface the same
                    // error so the caller observes a deterministic
                    // refusal rather than a silent hang.
                    VfsError::Again
                };
                return emit_err(reply_lease, reply_intent, err);
            }
            cursor = next;
        }

        if existing_same_owner.is_valid() {
            // Replace the existing same-owner lock on this range
            // with the new kind (Windows and POSIX both permit silent
            // upgrade / downgrade by the same owner).
            if let Some(lk) = state.byte_range_locks.get_mut(existing_same_owner) {
                lk.start = start;
                lk.length = length;
                lk.kind = kind;
            }
            return crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
        }

        // Allocate a new lock record and push it on the vnode list.
        let Some(lock_h) = state.byte_range_locks.alloc() else {
            return emit_err(reply_lease, reply_intent, VfsError::NoMem);
        };
        let head = match state.vnodes.get(vnode_h) {
            Some(v) => v.locks_head,
            None => return emit_err(reply_lease, reply_intent, VfsError::StaleIncarnation),
        };
        if let Some(lk) = state.byte_range_locks.get_mut(lock_h) {
            *lk = ByteRangeLock::new(vnode_key, open_h, start, length, kind, head);
        }
        if let Some(v) = state.vnodes.get_mut(vnode_h) {
            v.locks_head = lock_h;
        }
        crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
    }
}

/// Release a byte-range lock on the file backing `fd`. Matches by
/// owner + exact range; partial-range unlock surfaces `Inval`
/// (split / merge of existing records lands once the wait queue
/// is wired).
pub(crate) unsafe fn do_byte_range_unlock(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    start: u64,
    length: u64,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            return emit_err(reply_lease, reply_intent, VfsError::Inval);
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            return emit_err(reply_lease, reply_intent, VfsError::BadF);
        };
        let Some(vnode_h) = state.open_objects.get(open_h).map(|o| o.vnode) else {
            return emit_err(reply_lease, reply_intent, VfsError::BadF);
        };
        let removed = remove_lock_for_range(state, vnode_h, open_h, start, length);
        if !removed {
            return emit_err(reply_lease, reply_intent, VfsError::Inval);
        }
        crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
    }
}

/// Drop every byte-range lock owned by `open_h` on `vnode_h`.
/// Called from the close path so locks auto-release when the
/// owning `OpenObject` reaches `refcount=0`.
pub(crate) unsafe fn release_locks_for_open(
    state: &mut VfsState,
    open_h: Handle<OpenObject>,
    vnode_h: Handle<Vnode>,
) {
    let mut prev: Handle<ByteRangeLock> = Handle::INVALID;
    let mut cursor = match state.vnodes.get(vnode_h) {
        Some(v) => v.locks_head,
        None => return,
    };
    while cursor.is_valid() {
        let Some(lk) = state.byte_range_locks.get(cursor) else {
            break;
        };
        let next = lk.next;
        if lk.owner_open == open_h {
            if prev.is_valid() {
                if let Some(p) = state.byte_range_locks.get_mut(prev) {
                    p.next = next;
                }
            } else if let Some(v) = state.vnodes.get_mut(vnode_h) {
                v.locks_head = next;
            }
            if let Some(lk) = state.byte_range_locks.get_mut(cursor) {
                *lk = ByteRangeLock::EMPTY;
            }
            state.byte_range_locks.release(cursor);
            cursor = next;
        } else {
            prev = cursor;
            cursor = next;
        }
    }
}

unsafe fn remove_lock_for_range(
    state: &mut VfsState,
    vnode_h: Handle<Vnode>,
    open_h: Handle<OpenObject>,
    start: u64,
    length: u64,
) -> bool {
    let mut prev: Handle<ByteRangeLock> = Handle::INVALID;
    let mut cursor = match state.vnodes.get(vnode_h) {
        Some(v) => v.locks_head,
        None => return false,
    };
    while cursor.is_valid() {
        let Some(lk) = state.byte_range_locks.get(cursor) else {
            return false;
        };
        let next = lk.next;
        let matches_owner = lk.owner_open == open_h;
        let matches_range = lk.start == start && lk.length == length;
        if matches_owner && matches_range {
            if prev.is_valid() {
                if let Some(p) = state.byte_range_locks.get_mut(prev) {
                    p.next = next;
                }
            } else if let Some(v) = state.vnodes.get_mut(vnode_h) {
                v.locks_head = next;
            }
            if let Some(lk) = state.byte_range_locks.get_mut(cursor) {
                *lk = ByteRangeLock::EMPTY;
            }
            state.byte_range_locks.release(cursor);
            return true;
        }
        prev = cursor;
        cursor = next;
    }
    false
}

unsafe fn emit_err(reply_lease: ReplyLease, intent: AckReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, intent, 0, Err(err));
    }
}
