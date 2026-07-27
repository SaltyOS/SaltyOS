// SPDX-License-Identifier: GPL-2.0-only
//
//! Periodic reclaim sweep — frees Arena slots (vnodes,
//! open_objects, pending_ops, mounts, sockets, pipes,
//! page_cache, ...) whose lifecycle has reached its terminal
//! state without any in-flight worker reference.
//!
//! Driven from the owner reactor's idle-tick path. The sweep is
//! incremental: [`sweep_once`] advances a round-robin cursor and
//! processes a single reclaim group per call (two under memory
//! pressure), so one pass never walks every arena and the reactor
//! stays free to service the next inbound IPC. State that an
//! in-flight worker still references (`flight_count > 0`) stays
//! pinned; a later sweep retries.

use crate::owner::VfsState;

/// Number of round-robin reclaim groups [`sweep_once`] cycles through.
const SWEEP_GROUPS: u32 = 5;

/// True when a spine arena is running low on free slots. The reactor
/// raises its sweep cadence and [`sweep_once`] widens its per-tick group
/// and page-eviction budgets while this holds.
pub(crate) fn under_pressure(state: &VfsState) -> bool {
    state.pending_ops.free_count() < (state.pending_ops.total_cap() / 4)
        || state.open_objects.free_count() < (state.open_objects.total_cap() / 4)
        || state.clients.free_count() < (state.clients.total_cap() / 4)
}

/// One incremental reclaim pass. Advances the round-robin cursor and
/// processes one reclaim group (two under pressure). Returns the number
/// of slots reclaimed; the reactor uses this as a back-pressure signal
/// (a fully drained pass schedules the next tick further out).
pub(crate) fn sweep_once(state: &mut VfsState) -> u32 {
    let pressure = under_pressure(state);
    let groups = if pressure { 2 } else { 1 };
    let page_evict_budget = if pressure { 4 } else { 1 };
    let mut freed = 0u32;
    for _ in 0..groups {
        let group = state.sweep_cursor % SWEEP_GROUPS;
        state.sweep_cursor = (state.sweep_cursor + 1) % SWEEP_GROUPS;
        freed += match group {
            0 => sweep_pending_ops(state),
            1 => sweep_open_objects(state),
            2 => sweep_page_cache(state, page_evict_budget),
            3 => sweep_vnodes(state),
            _ => sweep_lifecycle_arenas(state),
        };
    }
    freed
}

/// Page-cache reclaim group: evict up to `page_evict_budget` clean LRU
/// tail pages (each consulting the kernel dirty authority before drop),
/// then reclaim any released metadata slots.
fn sweep_page_cache(state: &mut VfsState, page_evict_budget: usize) -> u32 {
    let mut freed = 0u32;
    for _ in 0..page_evict_budget {
        if unsafe { crate::owner::page_cache::evict_one_clean(state) } {
            freed += 1;
        } else {
            break;
        }
    }
    freed += state.page_cache.sweep();
    freed
}

fn sweep_pending_ops(state: &mut VfsState) -> u32 {
    let mut freed = 0u32;
    let mut victims: [crate::owner::pending::PendingOpHandle; 32] =
        [crate::owner::pending::PendingOpHandle::INVALID; 32];
    let mut count = 0usize;
    state.pending_ops.for_each_active(|h, op| {
        if op.core.cancelled
            && matches!(
                op.core.state,
                crate::owner::op::OpState::Cancelled | crate::owner::op::OpState::Free
            )
        {
            if count < victims.len() {
                victims[count] = h;
                count += 1;
            }
        }
        true
    });
    for i in 0..count {
        if state.pending_ops.release(victims[i]) {
            freed += 1;
        }
    }
    // `ContinuationArena::release` frees the slot immediately (no
    // deferred sweep phase), so the reclaim pass is complete here.
    freed
}

fn sweep_open_objects(state: &mut VfsState) -> u32 {
    let mut freed = 0u32;
    let mut victims: [crate::server::types::OpenObjectHandle; 32] =
        [crate::server::types::OpenObjectHandle::INVALID; 32];
    let mut count = 0usize;
    state.open_objects.for_each_active(|h, obj| {
        if obj.refcount == 0 {
            if count < victims.len() {
                victims[count] = h;
                count += 1;
            }
        }
        true
    });
    for i in 0..count {
        if state.open_objects.release(victims[i]) {
            freed += 1;
        }
    }
    state.open_objects.sweep();
    freed
}

fn sweep_vnodes(state: &mut VfsState) -> u32 {
    let mut freed = 0u32;
    let mut release_now: [crate::core::vnode::VnodeHandle; 32] =
        [crate::core::vnode::VnodeHandle::INVALID; 32];
    let mut retire_now: [crate::core::vnode::VnodeHandle; 32] =
        [crate::core::vnode::VnodeHandle::INVALID; 32];
    let mut finish_retired: [crate::core::vnode::VnodeHandle; 32] =
        [crate::core::vnode::VnodeHandle::INVALID; 32];
    let mut release_count = 0usize;
    let mut retire_count = 0usize;
    let mut retired_count = 0usize;

    state.vnodes.for_each_active(|h, vn| {
        if vn.open_refcount == 0 && vn.cache_pin == 0 {
            if vn.flight_count == 0 {
                if release_count < release_now.len() {
                    release_now[release_count] = h;
                    release_count += 1;
                }
            } else if retire_count < retire_now.len() {
                retire_now[retire_count] = h;
                retire_count += 1;
            }
        }
        true
    });

    for slot in 0..state.vnodes.total_cap() {
        let Some(h) = state.vnodes.handle_from_slot(slot) else {
            continue;
        };
        if state.vnodes.slot_state(h) != Some(crate::arena::SlotState::Retired) {
            continue;
        }
        let flight_count = unsafe {
            state
                .vnodes
                .raw_ptr(h)
                .map(|ptr| (*ptr).flight_count)
                .unwrap_or(1)
        };
        if flight_count == 0 && retired_count < finish_retired.len() {
            finish_retired[retired_count] = h;
            retired_count += 1;
        }
    }

    for handle in retire_now.iter().take(retire_count).copied() {
        let _ = state.vnodes.retire(handle);
    }

    for handle in release_now.iter().take(release_count).copied() {
        if finalize_vnode_inactive(state, handle) && state.vnodes.release(handle) {
            freed += 1;
        }
    }

    for handle in finish_retired.iter().take(retired_count).copied() {
        if finalize_vnode_inactive(state, handle) {
            state.vnodes.mark_reclaimable(handle);
            freed += 1;
        }
    }
    state
        .vnodes
        .sweep_with(|v| v.cache_pin > 0 || v.flight_count > 0);
    freed
}

fn finalize_vnode_inactive(state: &mut VfsState, vnode_h: crate::core::vnode::VnodeHandle) -> bool {
    use crate::core::outcome::{Parked, Ready};

    let ops = match state.vnodes.get(vnode_h) {
        Some(vn) => vn.ops,
        None => unsafe {
            state
                .vnodes
                .raw_ptr(vnode_h)
                .map(|ptr| (*ptr).ops)
                .unwrap_or(::core::ptr::null())
        },
    };
    if ops.is_null() {
        return true;
    }
    let Some(mut ctx) =
        (unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h) })
    else {
        return false;
    };
    match unsafe { ((*ops).meta.inactive)(&mut ctx) } {
        Ok(Ready(())) => true,
        Ok(Parked(_)) => false,
        Err(_) => true,
    }
}

fn sweep_lifecycle_arenas(state: &mut VfsState) -> u32 {
    let mut freed = 0u32;
    freed += state.mounts.sweep();
    freed += state.clients.sweep();
    freed += state.backend_sessions.sweep();
    freed += state.pipes.sweep();
    freed += state.sockets.sweep();
    freed += state.shm_data.sweep();
    freed += state.epolls.sweep();
    freed += state.poll_waiters.sweep();
    freed += state.byte_range_locks.sweep();
    freed += state.namei_aux.sweep();
    freed += state.client_shm_regions.sweep();
    freed
}
