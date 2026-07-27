// SPDX-License-Identifier: GPL-2.0-only
//
//! Startup sequence:
//! 1. Resolve namesrv-private cap_table entries (master EQ, master MP,
//!    fault MP recv, Watch slab base, park Timer) via
//!    `cap_table::lookup` — init has retyped each object
//!    and delivered the slot via the cap table.
//! 2. Reserve namesrv-private CSpace zones (recv-scratch + a 256-slot
//!    block for registered cap stash).
//! 3. Arm baseline EQ Watch: master MP `STATE_READABLE`.
//! 4. Signal core readiness to init over `ROLE_INIT_CONTROL`.

use trona_kernel::invoke;
use trona_runtime::spawn::cap_table::{find_in_auxv, lookup};
use trona_runtime::spawn::role_consts::{
    ROLE_INIT_CONTROL, ROLE_NAMESRV_BOOT_UNTYPED, ROLE_NAMESRV_MASTER_EQ, ROLE_NAMESRV_MASTER_MP,
    ROLE_NAMESRV_PARK_TIMER, ROLE_NAMESRV_WATCH_BASE,
};
use uapi::{KERNITE_ERR_NOT_FOUND, KERNITE_STATE_READABLE};

use crate::main_loop::{NAMESRV_KIND_MASTER_MP, NamesrvTarget, ServerState};
use crate::registry::MAX_NAMES;
use crate::slots::{CAP_RECV_SCRATCH_SLOT, REGISTERED_CAP_BASE};

/// Read the namesrv cap_table delivered through auxv and populate the
/// `ServerState.startup` snapshot. Returns `false` if any required
/// role is absent (the caller idles in `main`).
pub fn read_startup_caps(state: &mut ServerState) -> bool {
    let auxv = unsafe { core::ptr::read_volatile(&raw const trona_runtime::__trona_saved_auxv) };
    let table = unsafe { find_in_auxv(auxv) };
    if table.is_null() {
        return false;
    }
    let lookup_role =
        |role: u32| -> u64 { lookup(table, role).map(|e| e.slot as u64).unwrap_or(0) };
    state.startup.master_eq = lookup_role(ROLE_NAMESRV_MASTER_EQ);
    state.startup.master_mp = lookup_role(ROLE_NAMESRV_MASTER_MP);
    state.startup.watch_base = lookup_role(ROLE_NAMESRV_WATCH_BASE);
    state.startup.park_timer = lookup_role(ROLE_NAMESRV_PARK_TIMER);
    state.startup.init_ep = lookup_role(ROLE_INIT_CONTROL);
    state.startup.boot_untyped = lookup_role(ROLE_NAMESRV_BOOT_UNTYPED);
    // Now that boot_untyped is in hand, point the SegmentAllocator
    // at it so the first cookie-table grow can retype frames out
    // of the namesrv-private chunk.
    state
        .segment_allocator
        .rebind_untyped(state.startup.boot_untyped);
    state.startup.master_eq != 0
        && state.startup.master_mp != 0
        && state.startup.watch_base != 0
        && state.startup.park_timer != 0
        && state.startup.init_ep != 0
        && state.startup.boot_untyped != 0
}

/// Reserve namesrv-private CSpace zones. The recv-scratch is a 2-slot
/// payload-cap window. The registered-cap block covers the full
/// registry capacity.
pub fn reserve_internal_slots() -> bool {
    unsafe {
        let scratch = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
            2,
            b"namesrv recv-scratch payload caps",
        );
        if scratch == 0 {
            return false;
        }
        let stash = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
            MAX_NAMES as u64,
            b"namesrv registered cap stash",
        );
        if stash == 0 {
            return false;
        }
        core::ptr::write_volatile(&raw mut CAP_RECV_SCRATCH_SLOT, scratch);
        core::ptr::write_volatile(&raw mut REGISTERED_CAP_BASE, stash);
    }
    true
}

/// Bind WatchSlab to its cap_table-delivered base slots, then arm the
/// master MP `STATE_READABLE` Watch against `state.startup.master_eq`.
/// Returns `false` on any kernel error or cookie-table allocation
/// failure.
///
/// Park Timer fires arrive as `EVENT_TYPE_TIMER` records (the
/// kernel publishes them directly when the deadline expires) and
/// are routed through `EqDispatcher::handle_timer`, so no Watch on
/// the Timer's `STATE_TIMED_OUT` flag is needed here.
pub fn arm_baseline_watches(state: &mut ServerState) -> bool {
    state.watches.bind(state.startup.watch_base);

    // Reserve one Watch from the slab for the master MP -> EQ
    // wiring.
    let Some((mp_watch_idx, mp_watch_slot)) = state.watches.alloc() else {
        return false;
    };
    let _ = mp_watch_idx;

    // Register the master MP entry in the reactor's cookie table
    // — the resulting cookie carries `(kind=0, slot, live_gen)`
    // and the kernel publishes it back unchanged on every fire,
    // letting the dispatcher tag stale records via
    // `live_gen` mismatch on `lookup`.
    let cookie = match unsafe {
        state.cookie_table.arm(
            &mut state.segment_allocator,
            NAMESRV_KIND_MASTER_MP,
            state.startup.master_mp,
            mp_watch_slot,
            NamesrvTarget::MasterMp,
        )
    } {
        Ok(c) => c,
        Err(_) => return false,
    };

    let err = invoke::watch_register(
        trona_runtime::core::slot_alloc::resolved_cap_ref(mp_watch_slot),
        trona_runtime::core::slot_alloc::resolved_cap_ref(state.startup.master_mp),
        trona_runtime::core::slot_alloc::resolved_cap_ref(state.startup.master_eq),
        KERNITE_STATE_READABLE as u64,
        cookie,
    );
    if err != 0 {
        return false;
    }

    true
}

/// Signal init that namesrv has armed its own reactor input.
pub fn signal_core_ready(state: &ServerState) -> i32 {
    if state.startup.init_ep == 0 {
        return KERNITE_ERR_NOT_FOUND as i32;
    }
    let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
    msg.label = trona_protocol::init::INIT_CORE_READY;
    msg.length = 0;
    let ctx = trona_posix::tls::current_ipc_ctx();
    unsafe { trona_kernel::ipc::mp_write_ctx(ctx, state.startup.init_ep, &raw const msg) }
}
