// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyOS mmsrv — frame allocator + MO registry + per-client region
//! tables + page-fault dispatcher. Two TCBs: the main reactor handles
//! init-only and self-only IPC tiers; the fault dispatcher drains
//! per-TCB fault MPs and resolves PAGE_FAULT / OOM in-place,
//! forwarding crashes to init via `INIT_REPORT_FAULT`.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;
extern crate uapi;

mod caps;
mod client;
mod dispatch;
mod fault;
mod file_backed_registry;
mod kernel_vm;
mod labels;
mod main_loop;
mod mmap;
mod mo_registry;
mod region;
mod segment_alloc;
mod self_vm;
mod txn;
mod va_alloc;
mod watch_pool;

use trona_runtime::spawn::cap_table::{find_in_auxv, lookup};
use trona_runtime::spawn::role_consts::{
    ROLE_INIT_CONTROL, ROLE_MMSRV_AUTHORITY_RAW, ROLE_MMSRV_FAULT_EQ,
    ROLE_MMSRV_FAULT_MP_MASTER_RECV, ROLE_MMSRV_FAULT_SC, ROLE_MMSRV_FAULT_STACK_FRAME,
    ROLE_MMSRV_FAULT_TCB, ROLE_MMSRV_SERVICE_EQ, ROLE_NAMESRV_CLIENT, ROLE_RSRCSRV_CLIENT,
    ROLE_SERVICE_CLIENT_EP, ROLE_SERVICE_EP,
};
use uapi::{
    KERNITE_CAP_SELF_CSPACE, KERNITE_CAP_SELF_TCB, KERNITE_CAP_SELF_VSPACE, KERNITE_ERR_NOT_FOUND,
    KERNITE_INV_SC_BIND, KERNITE_INV_SC_CONFIGURE, KERNITE_INV_TCB_CONFIGURE,
    KERNITE_INV_TCB_SET_SPACE, KERNITE_INV_TCB_START, KERNITE_INV_TCB_YIELD,
    KERNITE_INV_UNTYPED_GET_STATS, KERNITE_PAGE_BYTES as KERNITE_PAGE_BYTES_U32,
    KERNITE_PAGE_FLAG_USER, KERNITE_PAGE_FLAG_WRITABLE,
};

use crate::caps::{FAULT_RECV_BASE_SLOT, MAIN_RECV_BASE_SLOT, WATCH_POOL_BASE};
use crate::main_loop::state_mut;
use crate::watch_pool::WATCH_POOL_LEN;

const KERNITE_PAGE_BYTES: u64 = KERNITE_PAGE_BYTES_U32 as u64;

fn untyped_size_bits(cap: u64) -> Option<u8> {
    let stats =
        trona_kernel::syscall::invoke(cap, KERNITE_INV_UNTYPED_GET_STATS as u64, 1, 0, 0, 0);
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
    state.startup.rsrcsrv_ep = lookup_role(ROLE_RSRCSRV_CLIENT);
    state.startup.master_service_mp_recv = lookup_role(ROLE_SERVICE_EP);
    state.startup.master_service_mp_send = lookup_role(ROLE_SERVICE_CLIENT_EP);
    state.startup.service_eq = lookup_role(ROLE_MMSRV_SERVICE_EQ);
    state.startup.fault_eq = lookup_role(ROLE_MMSRV_FAULT_EQ);
    state.startup.fault_mp_master_recv = lookup_role(ROLE_MMSRV_FAULT_MP_MASTER_RECV);
    state.startup.fault_tcb = lookup_role(ROLE_MMSRV_FAULT_TCB);
    state.startup.fault_sc = lookup_role(ROLE_MMSRV_FAULT_SC);
    state.startup.fault_stack_frame = lookup_role(ROLE_MMSRV_FAULT_STACK_FRAME);
    let untyped_seed = lookup_role(ROLE_MMSRV_AUTHORITY_RAW);
    if untyped_seed != 0 {
        let Some(size_bits) = untyped_size_bits(untyped_seed) else {
            return false;
        };
        state.frames.adopt(untyped_seed, size_bits);
    }
    state.startup.master_service_mp_recv != 0
        && state.startup.master_service_mp_send != 0
        && state.startup.init_ep != 0
}

fn reserve_internal_slots() -> bool {
    unsafe {
        let main_recv = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
            crate::caps::RECV_WINDOW_LEN,
            b"mmsrv main recv window",
        );
        if main_recv == 0 {
            return false;
        }
        let fault_recv = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
            crate::caps::RECV_WINDOW_LEN,
            b"mmsrv fault recv window",
        );
        if fault_recv == 0 {
            return false;
        }
        let watch_base = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
            WATCH_POOL_LEN as u64,
            b"mmsrv watch slab",
        );
        if watch_base == 0 {
            return false;
        }
        core::ptr::write_volatile(&raw mut MAIN_RECV_BASE_SLOT, main_recv);
        core::ptr::write_volatile(&raw mut FAULT_RECV_BASE_SLOT, fault_recv);
        core::ptr::write_volatile(&raw mut WATCH_POOL_BASE, watch_base);
    }
    true
}

/// Retype `WATCH_POOL_LEN` `OBJ_WATCH` objects out of mmsrv's
/// untyped pool into the reserved CSpace window. Returns `false` if
/// not a single Watch could be retyped — which would mean every
/// untyped chunk is exhausted.
fn populate_watch_pool() -> bool {
    let state = state_mut();
    let base = caps::watch_pool_base();
    state
        .watches
        .populate(&mut state.frames, base, WATCH_POOL_LEN)
}

/// Allocate one Watch from the pool, register it in the main
/// reactor's cookie table as `MmsrvMainTarget::MasterServiceEp`,
/// and arm it on the master service-EP MP recv side. The cookie
/// returned by `main_cookie_table.arm` is what the kernel publishes
/// back through `EventRecord.cookie` whenever the Watch fires; the
/// reactor decodes `(kind, slot, live_gen)` to dispatch. Returns
/// `false` if the Watch pool is empty, the cookie-table grow fails,
/// or the kernel rejects WATCH_REGISTER — any of those means mmsrv
/// cannot dispatch admin labels and must fail-fast.
fn arm_master_service_watch() -> bool {
    let state = state_mut();
    if state.startup.master_service_mp_recv == 0 || state.startup.service_eq == 0 {
        return false;
    }
    let watch_cap = state.watches.alloc();
    if watch_cap == 0 {
        return false;
    }
    // Reserve a cookie-table slot first — the kernel needs the cookie
    // value when WATCH_REGISTER fires, and the table tracks the
    // (kind, slot, live_gen) triple for stale-detection on dispatch.
    let cookie = match unsafe {
        state.main_cookie_table.arm(
            &mut state.segment_allocator,
            crate::main_loop::MMSRV_KIND_MASTER_SERVICE,
            state.startup.master_service_mp_recv,
            watch_cap,
            crate::main_loop::MmsrvMainTarget::MasterServiceEp,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            state.watches.free(watch_cap);
            return false;
        }
    };
    let err = crate::watch_pool::arm(
        watch_cap,
        state.startup.master_service_mp_recv,
        state.startup.service_eq,
        cookie,
    );
    if err != 0 {
        // Roll back the cookie-table entry. The Watch was never
        // armed kernel-side, so no WATCH_CANCEL is needed — only
        // the slot tombstone.
        let (_kind, slot, _gen) = trona_server::event_loop::decode_cookie(cookie);
        let _ = state
            .main_cookie_table
            .cancel(crate::main_loop::MMSRV_KIND_MASTER_SERVICE, slot);
        state.watches.free(watch_cap);
        return false;
    }
    state.master_service_watch_cap = watch_cap;
    state.master_service_cookie = cookie;
    true
}

fn bind_dispatcher_caps() {
    let state = state_mut();
    state.fault.bind(
        state.startup.fault_eq,
        state.startup.fault_mp_master_recv,
        state.startup.init_ep,
    );
}

/// VSpace anchor for the fault dispatcher TCB's stack. Init pre-maps
/// the entire 16-page stack region at this VA in mmsrv's child
/// VSpace via the boot recipe (`boot_core::map_mmsrv_fault_stack`)
/// before mmsrv's `main` runs. The dispatcher's `_start` reads `RSP`
/// set to an ABI-correct entry SP within that stack.
use trona_runtime::spawn::layout::FAULT_STACK_VA;
const FAULT_STACK_PAGES: u64 = 16;
const FAULT_STACK_BYTES: u64 = FAULT_STACK_PAGES * KERNITE_PAGE_BYTES;
const FAULT_IPC_BUFFER_VA: u64 = FAULT_STACK_VA + FAULT_STACK_BYTES;

/// Bring up the fault dispatcher TCB. mmsrv runs as a two-TCB process;
/// the second TCB drains the fault EQ while the main reactor handles
/// the service EQ. Both share the same VSpace + CSpace; only the
/// stack and per-thread IPC buffer differ. The stack mapping is
/// already in place — Stage E of init's boot recipe maps the
/// `ROLE_MMSRV_FAULT_STACK_FRAME` at `FAULT_STACK_VA` before mmsrv
/// runs `main`. This routine provisions the dispatcher's private IPC
/// buffer, then configures and starts the TCB.
/// Those IPC resources are per-thread because the dispatcher runs
/// below the runtime thread/TLS layer and must not share the main
/// TCB's IPC context.
fn spawn_fault_dispatcher() -> bool {
    let state = state_mut();
    let slots = state.startup;
    if slots.fault_tcb == 0 || slots.fault_sc == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] fault dispatcher startup slots missing\n");
        });
        return false;
    }

    let ipc_frame = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"mmsrv fault ipc frame");
    if ipc_frame == 0 {
        return false;
    }
    if state.frames.alloc_frame(ipc_frame).is_none() {
        return false;
    }
    let map_err = crate::kernel_vm::vspace_map(
        KERNITE_CAP_SELF_VSPACE as u64,
        ipc_frame,
        FAULT_IPC_BUFFER_VA,
        (KERNITE_PAGE_FLAG_USER | KERNITE_PAGE_FLAG_WRITABLE) as u64,
    );
    if map_err != 0 {
        return false;
    }
    unsafe {
        main_loop::init_fault_ipc_context(FAULT_IPC_BUFFER_VA as *mut uapi::kernite_ipc_buffer);
    }

    // 1. Bind the dispatcher TCB's address space (same VSpace +
    //    CSpace as the main TCB). Kernel ABI:
    //    `syscall_tcb_set_space(cspace, vspace, depth)`.
    let r = trona_kernel::syscall::invoke(
        slots.fault_tcb,
        KERNITE_INV_TCB_SET_SPACE as u64,
        KERNITE_CAP_SELF_CSPACE as u64,
        KERNITE_CAP_SELF_VSPACE as u64,
        0,
        0,
    );
    if r.error != 0 {
        return false;
    }

    // 2. Configure entry, stack, and per-thread IPC buffer. The
    //    kernel-side TCB ABI allocates trampoline/kernel stacks here;
    //    `TCB_WRITE_REGISTERS` alone is not valid for a fresh TCB.
    let stack_top = FAULT_STACK_VA.wrapping_add(FAULT_STACK_BYTES);
    let entry_sp = trona_kernel::invoke::direct_entry_rsp(stack_top);
    let entry = main_loop::run_fault_dispatcher as *const () as u64;
    let r = trona_kernel::syscall::invoke(
        slots.fault_tcb,
        KERNITE_INV_TCB_CONFIGURE as u64,
        entry,
        entry_sp,
        FAULT_IPC_BUFFER_VA,
        0,
    );
    if r.error != 0 {
        return false;
    }

    // 3. Give the dispatcher an SC and make it schedulable.
    let r = trona_kernel::syscall::invoke(
        slots.fault_sc,
        KERNITE_INV_SC_CONFIGURE as u64,
        1_000_000,
        0,
        0,
        0,
    );
    if r.error != 0 {
        return false;
    }
    let r = trona_kernel::syscall::invoke(
        slots.fault_sc,
        KERNITE_INV_SC_BIND as u64,
        slots.fault_tcb,
        0,
        0,
        0,
    );
    if r.error != 0 {
        return false;
    }
    let r =
        trona_kernel::syscall::invoke(slots.fault_tcb, KERNITE_INV_TCB_START as u64, 0, 0, 0, 0);
    r.error == 0
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
        _lb.str(b"[MMSRV] starting\n");
    });

    if !read_startup_caps() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] startup cap_table missing required roles\n");
        });
        idle();
    }
    // Bind the SegmentAllocator to `state.frames` now that the
    // buddy has at least one untyped chunk adopted from the boot
    // pool. After this, cookie-table grows for the main and fault
    // reactors can retype frames out of the buddy without
    // re-entering mmsrv's own `MM_MMAP` path.
    let state = state_mut();
    let frames_ptr: *mut trona_server::frame_alloc::FrameAllocator = &raw mut state.frames;
    state.segment_allocator.rebind(frames_ptr);
    // Same buddy pointer drives the per-client region/reservation slab
    // backing; it carves a MemoryObject per buffer at a disjoint
    // scratch window (see `self_vm`).
    state.self_vm.rebind(frames_ptr);
    if !reserve_internal_slots() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] failed to reserve internal CSpace zones\n");
        });
        idle();
    }
    if !populate_watch_pool() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] failed to populate watch pool\n");
        });
        idle();
    }
    if !arm_master_service_watch() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] failed to arm master service-EP Watch\n");
        });
        idle();
    }
    bind_dispatcher_caps();
    if !spawn_fault_dispatcher() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] fault dispatcher TCB did not start\n");
        });
        // Continue anyway — the main reactor still serves init-only
        // and self-only RPC even without the fault TCB. Faults will
        // fail-fast (token drops escalate to begin_destroy).
    }
    let ready_err = signal_core_ready();
    if ready_err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] failed to signal core ready err=");
            _lb.hex(ready_err as u64);
            _lb.str(b"\n");
        });
        idle();
    }

    main_loop::run_main_reactor();
}
