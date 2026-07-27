// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-mount SaltyFS vdata cache.
//!
//! Each mount carries an array of [`SaltyfsVnodeData`] slots
//! (`vdata_ptr` + `vdata_cap`) backed by an mmap-anonymous
//! region. Lookup hits scan the array linearly; backend round
//! trips are amortised against the cache so re-resolves of the
//! same inode reuse the cached attrs.
//!
//! The cache is owner-thread-only; data VOPs reach it only through
//! ctx-carried raw pointers already validated at the dispatch
//! boundary. Slot reuse is FIFO over inactive entries — not LRU —
//! because the dominant access pattern is "fresh inode just
//! allocated by the backend, immediately cached on the next lookup".

use super::types::{SaltyfsMountData, SaltyfsVnodeData};

/// Find an existing vdata entry for `(remote_ino, remote_seq)`.
/// `seq` is checked because saltyfs may reuse an inode number
/// after unlink + re-create; the reused entry has a higher seq
/// and the cache must drop the stale slot rather than honour it.
/// Returns null when no live match exists.
pub(crate) unsafe fn find_vdata_by_node(
    md: *mut SaltyfsMountData,
    remote_ino: u64,
    remote_seq: u32,
) -> *mut SaltyfsVnodeData {
    unsafe {
        if md.is_null() {
            return ::core::ptr::null_mut();
        }
        let cap = (*md).vdata_cap;
        let base = (*md).vdata_ptr;
        if base.is_null() || cap == 0 {
            return ::core::ptr::null_mut();
        }
        for i in 0..cap {
            let slot = base.add(i);
            if (*slot).active != 0
                && (*slot).remote_ino == remote_ino
                && (*slot).remote_seq == remote_seq
            {
                return slot;
            }
        }
        ::core::ptr::null_mut()
    }
}

/// Allocate a fresh vdata slot. Returns null when the pool is
/// exhausted; callers escalate to `VfsError::NoMem`. Caller must
/// fully populate the returned slot before any other code reads
/// from it (the slot's `active = 1` flag is set here, so a
/// concurrent `find_vdata_by_node` would observe the half-
/// initialised slot otherwise — which the single-mutator
/// invariant prevents on the owner thread).
pub(crate) unsafe fn alloc_vdata(md: *mut SaltyfsMountData) -> *mut SaltyfsVnodeData {
    unsafe {
        if md.is_null() {
            return ::core::ptr::null_mut();
        }
        let cap = (*md).vdata_cap;
        let base = (*md).vdata_ptr;
        if base.is_null() || cap == 0 {
            return ::core::ptr::null_mut();
        }
        for i in 0..cap {
            let slot = base.add(i);
            if (*slot).active == 0 {
                *slot = SaltyfsVnodeData::zeroed();
                return slot;
            }
        }
        ::core::ptr::null_mut()
    }
}

/// Release a vdata slot back to the pool. No-op on null. The
/// slot is rewritten to zero so a subsequent allocation cannot
/// observe stale fields. Called by `vops::saltyfs_inactive`
/// when the last reference to the matching vnode drops.
pub(crate) unsafe fn release_vdata(md: *mut SaltyfsMountData, vdata: *mut SaltyfsVnodeData) {
    unsafe {
        if md.is_null() || vdata.is_null() {
            return;
        }
        *vdata = SaltyfsVnodeData::zeroed();
    }
}
