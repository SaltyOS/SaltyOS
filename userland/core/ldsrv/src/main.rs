// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyOS code-loading authority (`ldsrv`).
//!
//! `ldsrv` is the steady-state minter of executable code MemoryObjects for
//! runtime processes. It owns one `READ|EXECUTE` code MO per distinct code
//! object (keyed by a 128-bit content digest) and serves it through
//! `resolve_library` to the runtime linker (for `DT_NEEDED`) and to `execve`
//! (for a main image the caller already opened under its own VFS authority).
//!
//! # Two boot phases
//!
//! 1. **Adopt.** Init holds a *private* adopt MP (never published to the name
//!    service). Over it PID 1 transfers the full set of initrd code MOs — each
//!    already `READ|EXECUTE`, with its content-digest identity — and **moves**
//!    the exec-authority cap, then seals. ldsrv drains this before it serves,
//!    so a public client can never forge an adoption or steal the authority.
//! 2. **Serve.** Only after the seal does ldsrv publish its service endpoint
//!    to the name service and answer `resolve_*`. A cache hit hands back a
//!    rights-preserving copy of the pinned code MO; a miss resolves the object
//!    through the VFS, digests it, and confers `EXECUTE` with the authority.
//!
//! The adopt phase (single private MP, sealed before serving) needs no
//! multiplexing; the serve phase then runs an [`EventLoop`](reactor) that
//! multiplexes the public resolve endpoint (`resolve_library`, any client) and
//! the private exec-control MP (`resolve_main`, init only) over one EventQueue.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_loader;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;
extern crate uapi;

mod boot;
mod cache;
mod dispatch;
mod reactor;
mod resolve;
mod segment_alloc;

use cache::Cache;
use trona_kernel::core_types::{IpcContext, TronaMsg};
use trona_kernel::ipc;
use trona_kernel::syscall;
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_server::recv_slot::{RecvSlotArena, SlotAllocator};

/// CSpace slots: `ldsrv` always roots receives at its own CNode.
const SELF_CSPACE: u64 = uapi::KERNITE_CAP_SELF_CSPACE as u64;

/// Captured-cap slots reserved per receive-arena segment. The arena grows a
/// fresh segment whenever a handler keeps a slot (every adopted / resolved
/// code MO is kept for the system lifetime), so this is the granularity, not
/// a ceiling.
const RECV_ARENA_SEGMENT: u64 = 64;

/// The shared content-digest cache (`identity -> code MO`, `soname -> identity`).
static mut CACHE: Cache = Cache::new();

/// Per-receive capability-destination arena. Captured code MOs and the moved
/// exec-authority stay in the arena slots the handlers keep.
static mut ARENA: RecvSlotArena = RecvSlotArena::new_empty();

/// CSpace slot holding the moved exec-authority cap once adoption delivers it
/// (`0` until then). ldsrv confers `EXECUTE` on VFS-resolved objects through
/// this cap; it is the only exec authority in the system after the handoff.
static mut EXEC_AUTHORITY_SLOT: u64 = 0;

const SLOT_ALLOCATOR: SlotAllocator = SlotAllocator {
    alloc_consecutive: trona_runtime::core::slot_alloc::slot_alloc_consecutive_cb,
    invoke_depth: trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
};

fn ipc_ctx() -> *mut IpcContext {
    trona_runtime::current_ipc_ctx()
}

fn idle() -> ! {
    loop {
        syscall::invoke(
            uapi::KERNITE_CAP_SELF_TCB as u64,
            uapi::KERNITE_INV_TCB_YIELD as u64,
            0,
            0,
            0,
            0,
        );
    }
}

/// Publish ldsrv's client-facing service endpoint to the name service. Init
/// treats the registration as readiness and distributes `ROLE_LDSRV_CLIENT`
/// from it. Mirrors the minimal-broker publish in `logsrv`.
fn register_namesrv() -> bool {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let name = b"ldsrv";
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_REGISTER;
    msg.regs[0] = name.len() as u64;
    let Some(publish_ep) = trona_runtime::client::caps::service_client_ep_for_transfer() else {
        return false;
    };
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_ep.slot());
    }
    msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    msg.length = (REGISTER_FLAGS_REG + 1) as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    drop(publish_ep);
    err == 0 && reply.label == trona_protocol::common::TRONA_OK
}

/// Drain the private adopt MP until the seal arrives. Each `mp_read` may carry
/// a transferred cap (a code MO, or the exec-authority) that the handler
/// captures into the arena and pins. Returns `false` on a fatal receive error.
fn adopt_phase(adopt_mp: u64) -> bool {
    let ctx = ipc_ctx();
    let cache = unsafe { &mut *(&raw mut CACHE) };
    let arena = unsafe { &mut *(&raw mut ARENA) };
    loop {
        let mut msg = TronaMsg::zeroed();
        let mut badge = 0u64;
        let err = unsafe { ipc::mp_read_ctx(ctx, adopt_mp, &raw mut msg, &raw mut badge) };
        if err != 0 {
            if err == uapi::KERNITE_ERR_WOULD_BLOCK as i32 {
                let _ = syscall::yield_now();
                continue;
            }
            return false;
        }
        // Drop any send-cap staged by the previous reply before this turn's
        // reply / downstream call reads `send_cap_count` (received caps live in
        // the receive CNode slot, not the send `caps[]`, so this is safe).
        unsafe { ipc::clear_send_caps_ctx(ctx) };
        let txid = unsafe { (*(*ctx).ipc_buffer).mp_txid };
        let sealed = unsafe {
            dispatch::handle_adopt(
                ctx,
                &msg,
                txid,
                adopt_mp,
                cache,
                arena,
                &raw mut EXEC_AUTHORITY_SLOT,
            )
        };
        unsafe { arena.recycle_for_next_recv(ctx, SELF_CSPACE) };
        if sealed {
            return true;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let adopt_mp = boot::adopt_recv_slot();
    let control_mp = boot::exec_control_recv_slot();
    let untyped = boot::plumbing_untyped_slot();
    if adopt_mp == 0 || control_mp == 0 || untyped == 0 {
        idle();
    }

    let ctx = ipc_ctx();
    let arena = unsafe { &mut *(&raw mut ARENA) };
    if !unsafe { arena.init_with_allocator(SLOT_ALLOCATOR, RECV_ARENA_SEGMENT) } {
        idle();
    }
    unsafe { arena.arm_first(ctx, SELF_CSPACE) };

    if !adopt_phase(adopt_mp) {
        idle();
    }
    if !register_namesrv() {
        idle();
    }
    reactor::run(
        control_mp,
        untyped,
        &raw mut CACHE,
        &raw mut ARENA,
        &raw const EXEC_AUTHORITY_SLOT,
    )
}
