// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyOS rsrcsrv — kernel-object retype factory + per-owner quota
//! broker. Single-threaded reactor; init delivers a private untyped
//! pool plus initial system caps via the startup cap_table, and every
//! client thereafter calls in via the master MP for `RSRC_ALLOC` /
//! `RSRC_FREE` / `RSRC_BATCH_ALLOC` / pair-retype labels.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;
extern crate uapi;

mod authz;
mod caps;
mod dispatch;
mod expand;
mod labels;
mod main_loop;
mod objects;
mod pairs;
mod quotas;
mod segment_alloc;
mod selfmem;
mod untyped;

use trona_runtime::spawn::cap_table::{find_in_auxv, lookup};
use trona_runtime::spawn::role_consts::{
    ROLE_INIT_CONTROL, ROLE_NAMESRV_CLIENT, ROLE_RSRCSRV_AUTHORITY_RAW, ROLE_RSRCSRV_SERVICE_EQ,
    ROLE_SERVICE_EP,
};
use uapi::{
    KERNITE_CAP_SELF_TCB, KERNITE_ERR_NOT_FOUND, KERNITE_INV_TCB_SET_FAULT_PIPE,
    KERNITE_INV_TCB_YIELD, KERNITE_OBJ_UNTYPED, KERNITE_OBJ_WATCH, KERNITE_STATE_READABLE,
};

use crate::caps::{
    OBJECT_BACK_REF_BASE, OBJECT_BACK_REF_LEN, RECV_BASE_SLOT, SELF_EXPAND_TEMP_SLOT,
};
use crate::main_loop::state_mut;

const AUTHORITY_ARENA_SIZE_BITS: u8 = 22;

fn untyped_size_bits(cap: u64) -> Option<u8> {
    let stats =
        trona_kernel::syscall::invoke(cap, uapi::KERNITE_INV_UNTYPED_GET_STATS as u64, 1, 0, 0, 0);
    if stats.error != 0 {
        return None;
    }
    unsafe {
        let ctx = trona_runtime::current_ipc_ctx();
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            return None;
        }
        let words = (*ctx).ipc_buffer as *const u64;
        Some((63 - words.read_volatile().leading_zeros()) as u8)
    }
}

fn idle() -> ! {
    loop {
        trona_kernel::syscall::invoke(
            KERNITE_CAP_SELF_TCB as u64,
            KERNITE_INV_TCB_YIELD as u64,
            0,
            0,
            0,
            0,
        );
    }
}

fn authority_arena_bits(size_bits: u8) -> u8 {
    if size_bits <= AUTHORITY_ARENA_SIZE_BITS {
        return size_bits;
    }
    let mut bits = AUTHORITY_ARENA_SIZE_BITS;
    while (1usize << (size_bits - bits)) > crate::untyped::MAX_CHUNKS {
        bits += 1;
    }
    bits
}

/// Partition the boot authority into several child untypeds. A single
/// kernel UntypedMemory can host only a bounded number of distinct
/// object-size buckets; multiple arenas keep rsrcsrv from reporting
/// OUT_OF_MEMORY when bytes remain but one source has hit that bucket
/// limit.
fn adopt_authority_seed(
    state: &mut crate::main_loop::ServerState,
    seed: u64,
    size_bits: u8,
) -> bool {
    let arena_bits = authority_arena_bits(size_bits);
    if arena_bits == size_bits {
        return state.untyped.adopt(seed, size_bits);
    }

    let arena_count = 1usize << (size_bits - arena_bits);
    let Some(arena_base) =
        trona_runtime::core::slot_alloc::slot_alloc_consecutive(arena_count as u64)
    else {
        return state.untyped.adopt(seed, size_bits);
    };

    let mut adopted = 0usize;
    for i in 0..arena_count {
        let slot = arena_base + i as u64;
        let r = trona_kernel::invoke::untyped_retype(
            trona_runtime::core::slot_alloc::resolved_cap_ref(seed),
            KERNITE_OBJ_UNTYPED as u64,
            arena_bits as u64,
            slot,
        );
        if r != 0 {
            break;
        }
        if !state.untyped.adopt(slot, arena_bits) {
            let _ = trona_kernel::invoke::cnode_delete(
                trona_kernel::core_types::CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
                slot,
            );
            break;
        }
        adopted += 1;
    }
    for i in adopted..arena_count {
        // SAFETY: these tail slots of the consecutive arena were never adopted
        // (the loop broke before retyping into them), so each is empty; allocated
        // from this process's arena and reclaimed exactly once here.
        unsafe {
            trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(
                arena_base + i as u64,
            );
        }
    }

    if adopted == 0 {
        state.untyped.adopt(seed, size_bits)
    } else {
        true
    }
}

fn read_startup_caps() -> bool {
    let auxv = unsafe { core::ptr::read_volatile(&raw const trona_runtime::__trona_saved_auxv) };
    let table = unsafe { find_in_auxv(auxv) };
    if table.is_null() {
        return false;
    }
    let lookup_role =
        |role: u32| -> u64 { lookup(table, role).map(|e| e.slot as u64).unwrap_or(0) };
    let state = state_mut();
    state.startup.init_ep = lookup_role(ROLE_INIT_CONTROL);
    state.startup.namesrv_ep = lookup_role(ROLE_NAMESRV_CLIENT);
    state.startup.master_mp_recv = lookup_role(ROLE_SERVICE_EP);
    state.startup.service_eq = lookup_role(ROLE_RSRCSRV_SERVICE_EQ);
    let untyped_seed = lookup_role(ROLE_RSRCSRV_AUTHORITY_RAW);
    if untyped_seed != 0 {
        let Some(size_bits) = untyped_size_bits(untyped_seed) else {
            return false;
        };
        if !adopt_authority_seed(state, untyped_seed, size_bits) {
            return false;
        }
    }
    state.startup.master_mp_recv != 0 && state.startup.init_ep != 0 && state.startup.service_eq != 0
}

fn reserve_internal_slots() -> bool {
    unsafe {
        let recv = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
            crate::caps::RECV_WINDOW_LEN,
            b"rsrcsrv recv window",
        );
        if recv == 0 {
            return false;
        }
        let object_base = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
            crate::objects::MAX_OBJECTS as u64,
            b"rsrcsrv object back-ref zone",
        );
        if object_base == 0 {
            return false;
        }
        let Some(temp) = trona_runtime::core::slot_alloc::slot_alloc_no_expand() else {
            return false;
        };
        core::ptr::write_volatile(&raw mut RECV_BASE_SLOT, recv);
        core::ptr::write_volatile(&raw mut OBJECT_BACK_REF_BASE, object_base);
        core::ptr::write_volatile(
            &raw mut OBJECT_BACK_REF_LEN,
            crate::objects::MAX_OBJECTS as u64,
        );
        core::ptr::write_volatile(&raw mut SELF_EXPAND_TEMP_SLOT, temp);
    }
    true
}

fn install_self_expand_handler() {
    // SAFETY: rsrcsrv is still in single-threaded bootstrap; no allocator
    // expansion can race this handler install.
    unsafe {
        trona_runtime::core::slot_alloc::install_expand_handler(crate::expand::rsrcsrv_self_expand);
    }
}

/// Retype one `OBJ_WATCH` from rsrcsrv's untyped pool, register the
/// (kind, slot, live_epoch) cookie in the reactor's cookie table as
/// [`RsrcsrvTarget::MasterMp`], and arm the Watch over the master MP
/// recv side's `STATE_READABLE` bit on `service_eq`. Returns `false`
/// if the untyped pool is exhausted, the cookie-table grow fails, or
/// the kernel rejects `WATCH_REGISTER` — any of those means rsrcsrv
/// cannot dispatch RPCs and must fail-fast.
fn arm_master_mp_watch() -> bool {
    let state = state_mut();
    if state.startup.master_mp_recv == 0 || state.startup.service_eq == 0 {
        return false;
    }
    // Borrow a transient CSpace slot for the new Watch cap.
    let watch = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"rsrcsrv master MP watch");
    if state
        .untyped
        .try_retype(KERNITE_OBJ_WATCH, 0, watch.addr())
        .is_none()
    {
        // retype failed: `watch` (OwnedSlot, empty) Drop frees the slot.
        return false;
    }
    // The Watch cap now occupies the slot; hand it off raw for the arm / register
    // / retain steps below (whose cap-bearing failure paths use delete).
    let watch_slot = watch.into_raw();
    // Register the cookie first — the kernel needs the cookie value
    // when WATCH_REGISTER fires, and the cookie table tracks (kind,
    // slot, live_epoch) for stale-detection on dispatch.
    let cookie = match unsafe {
        state.cookie_table.arm(
            &mut state.segment_allocator,
            crate::main_loop::RSRCSRV_KIND_MASTER_MP,
            state.startup.master_mp_recv,
            watch_slot,
            crate::main_loop::RsrcsrvTarget::MasterMp,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            // The Watch object was retyped but never armed; deleting
            // the cap returns the underlying memory to the untyped's
            // children_live count via the kernel's CDT.
            // SAFETY: watch_slot is the Watch cap just retyped for the master-MP
            // arm, solely owned here; torn down + freed once on this failure path.
            unsafe { trona_runtime::core::slot_alloc::delete_and_free(watch_slot) };
            return false;
        }
    };
    let watch_err = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_slot),
        trona_kernel::core_types::CapRef::flat(state.startup.master_mp_recv),
        trona_kernel::core_types::CapRef::flat(state.startup.service_eq),
        KERNITE_STATE_READABLE,
        cookie,
    );
    if watch_err != 0 {
        // Roll back the cookie-table slot — the Watch was never armed
        // kernel-side, so no WATCH_CANCEL is needed.
        let (_kind, slot, _epoch) = trona_server::event_loop::decode_cookie(cookie);
        let _ = state
            .cookie_table
            .cancel(crate::main_loop::RSRCSRV_KIND_MASTER_MP, slot);
        // SAFETY: watch_slot is the Watch cap just retyped for the master-MP arm,
        // solely owned here; torn down + freed once on this arm-failure path.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(watch_slot) };
        return false;
    }
    state.master_mp_watch_cap = watch_slot;
    state.master_mp_cookie = cookie;
    true
}

fn bind_initial_fault_pipe() {
    let state = state_mut();
    if state.startup.fault_pipe_send == 0 {
        return;
    }
    let _ = trona_kernel::syscall::invoke(
        KERNITE_CAP_SELF_TCB as u64,
        KERNITE_INV_TCB_SET_FAULT_PIPE as u64,
        state.startup.fault_pipe_send,
        0,
        0,
        0,
    );
}

fn signal_core_ready() -> i32 {
    let state = state_mut();
    if state.startup.init_ep == 0 {
        return KERNITE_ERR_NOT_FOUND as i32;
    }
    let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
    msg.label = trona_protocol::init::INIT_CORE_READY;
    msg.length = 0;
    unsafe {
        trona_kernel::ipc::mp_write_ctx(
            trona_posix::tls::current_ipc_ctx(),
            state.startup.init_ep,
            &raw const msg,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[RSRCSRV] starting\n");
    });

    if !read_startup_caps() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[RSRCSRV] startup cap_table missing required roles\n");
        });
        idle();
    }
    if !reserve_internal_slots() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[RSRCSRV] failed to reserve internal CSpace zones\n");
        });
        idle();
    }
    install_self_expand_handler();
    if !arm_master_mp_watch() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[RSRCSRV] failed to arm master-MP Watch\n");
        });
        idle();
    }
    bind_initial_fault_pipe();
    let ready_err = signal_core_ready();
    if ready_err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[RSRCSRV] failed to signal core ready err=");
            _lb.hex(ready_err as u64);
            _lb.str(b"\n");
        });
        idle();
    }

    main_loop::run_loop();
}
