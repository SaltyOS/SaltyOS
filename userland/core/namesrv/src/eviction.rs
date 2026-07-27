// SPDX-License-Identifier: GPL-2.0-only
//
//! Entry teardown — runs from three trigger paths:
//!
//! * UNREGISTER (publisher voluntary) — `evict_one(idx)`
//! * OWNER_EXITED (init-driven mass evict) — `evict_for_owner(tcb_id)`
//! * Owner-cap STATE_PEER_CLOSED watch fired — `evict_one(idx)` after
//!   the EQ dispatcher resolves `cookie -> registry_idx`.
//!
//! Each path delegates to `evict_one`, which: deletes the registered
//! cap from namesrv's CSpace, disarms the owner-close Watch, releases
//! the WatchSlab slot, vacates the registry slot, and notifies any
//! pending SUBSCRIBE entries waiting on the same name with a
//! peer-closed reply.

use trona_kernel::{invoke, syscall};
use trona_server::event_loop::CookieTable;

use crate::entry::COOKIE_SLOT_NONE;
use crate::main_loop::{NAMESRV_KIND_REGISTERED_CAP, NamesrvTarget};
use crate::owner::{MAX_NAMES_PER_OWNER, OwnerTable};
use crate::registry::NameRegistry;
use crate::slots::CAP_SELF_CSPACE;
use crate::watch::WatchSlab;

pub fn evict_one(
    registry: &mut NameRegistry,
    owners: &mut OwnerTable,
    watches: &mut WatchSlab,
    cookie_table: &mut CookieTable<NamesrvTarget>,
    idx: usize,
) {
    let entry = registry.entry(idx);
    if entry.active == 0 {
        return;
    }
    let owner_tcb = entry.owner_tcb;
    let cap_slot = entry.cap_slot;
    let watch_idx = entry.watch_idx;
    let cookie_slot = entry.cookie_slot;

    // Tombstone the cookie-table entry first — the cookie's
    // `live_gen` advances on the next reuse, so any in-flight
    // EventRecord that races us is dropped on `lookup`. Then
    // cancel the kernel-side Watch so no further records enqueue,
    // and free the WatchSlab slot for re-arm.
    if cookie_slot != COOKIE_SLOT_NONE {
        if let Some(watch_cap) = cookie_table.cancel(NAMESRV_KIND_REGISTERED_CAP, cookie_slot) {
            if watch_cap != 0 {
                let _ = invoke::watch_cancel(trona_runtime::core::slot_alloc::resolved_cap_ref(
                    watch_cap,
                ));
            }
        }
    } else if watch_idx != u8::MAX {
        // Cookie-table entry was never armed (slab saturation at
        // REGISTER time) but the WatchSlab still tracks a slot —
        // disarm it directly.
        if let Some(watch_slot) = watches.slot(watch_idx) {
            let _ = syscall::invoke(
                watch_slot,
                uapi::KERNITE_INV_WATCH_DISARM as u64,
                0,
                0,
                0,
                0,
            );
        }
    }
    if watch_idx != u8::MAX {
        watches.free(watch_idx);
    }

    // Delete the registered cap from our CSpace. The publisher's
    // own copy of the cap is unaffected — we held only a stash
    // slot for re-mint to lookup callers.
    if cap_slot != 0 {
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, cap_slot);
    }

    let (_name_len, _, _, _) = registry.vacate(idx);
    owners.forget(owner_tcb, idx as u8);
}

pub fn evict_for_owner(
    registry: &mut NameRegistry,
    owners: &mut OwnerTable,
    watches: &mut WatchSlab,
    cookie_table: &mut CookieTable<NamesrvTarget>,
    tcb_id: u32,
) -> usize {
    let mut indices = [0u8; MAX_NAMES_PER_OWNER];
    let n = owners.drain(tcb_id, &mut indices);
    for &idx in &indices[..n] {
        evict_one(registry, owners, watches, cookie_table, idx as usize);
    }
    n
}
