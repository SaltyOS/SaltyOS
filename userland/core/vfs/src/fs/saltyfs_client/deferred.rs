// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyFS-specific deferred-issue glue.
//!
//! The generic deferred FIFO lives on `BackendSessionSlot.wait_q`
//! (`crate::owner::deferred`); this module carries the saltyfs-
//! specific xattr SHM ownership tracking. Backend xattr ops
//! (`getxattr` / `setxattr` / `listxattr`) take exclusive use
//! of the SHM region for their value bytes; only one xattr op
//! may be in flight per mount until its completion runs and
//! releases the claim.

use super::types::SaltyfsMountData;
use crate::owner::VfsState;
use crate::owner::pending::TxId;
use crate::server::types::OpenObjectHandle;

/// Claim the per-mount readdir SHM window for `open_handle`.
///
/// Readdir replies are staged in the session SHM region before the
/// completion router copies records into the caller-facing reply. Only
/// one live open-object may own that window at a time; stale owners are
/// cleared when their open object has already been reclaimed.
pub(crate) unsafe fn acquire_readdir_shm(
    state: &VfsState,
    md: *mut SaltyfsMountData,
    open_handle: OpenObjectHandle,
) -> bool {
    unsafe {
        if md.is_null() || !(*md).shm_active {
            return false;
        }
        if (*md).xattr_shm_owner != TxId::INVALID {
            return false;
        }
        let owner = (*md).readdir_shm_owner;
        if owner.is_valid() {
            if owner == open_handle {
                return true;
            }
            if state.open_objects.is_alive(owner) {
                return false;
            }
            (*md).readdir_shm_owner = OpenObjectHandle::INVALID;
        }
        (*md).readdir_shm_owner = open_handle;
        true
    }
}

/// Drop the xattr SHM claim *iff* the recorded owner matches
/// the supplied `tx_id`. No-op when the slot is unowned, owned
/// by a different op, or the mount has been torn down between
/// park and completion.
///
/// Conditional release lets the completion router invoke this
/// helper unconditionally without checking ownership at the
/// call site — the helper short-circuits when the in-flight
/// op was not the SHM owner (set/get/list each acquire a
/// claim, but truncate / unlink completions also pass through
/// here and must not stomp the active xattr op's claim).
pub(crate) unsafe fn release_xattr_shm_if_owner(md: *mut SaltyfsMountData, tx_id: TxId) {
    unsafe {
        if md.is_null() {
            return;
        }
        if (*md).xattr_shm_owner == tx_id {
            (*md).xattr_shm_owner = TxId::INVALID;
        }
    }
}
