// SPDX-License-Identifier: GPL-2.0-only
//
//! Boot sequence for PID 1's kernel handoff, core services, and manifest spawn.
//!
//! Stage A. Read kernel-installed startup metadata and reserve init's
//!          fixed CSpace slots.
//! Stage B. Split the boot untyped into 4 chunks (init / namesrv /
//!          rsrcsrv / mmsrv).
//! Stage C. Install init's private support objects from init-private
//!          untyped (control EQ, control Timer, worker EQ, watches).
//! Stage D. Spawn namesrv (init retypes its objects directly from
//!          namesrv-quota).
//! Stage E. Spawn rsrcsrv (cap_transfer the rsrcsrv-untyped
//!          authority).
//! Stage F. Spawn mmsrv (rsrcsrv now alive, BATCH_ALLOC available).
//! Stage G. Retroactively bind per-TCB fault MP for every pre-mmsrv
//!          TCB (init main + namesrv + rsrcsrv + worker pool).
//! Stage H. Walk the manifest's spawn order; spawn each remaining
//!          service via `lifecycle::handle_spawn`.

use trona_kernel::core_types::{CapRef, SaltyOSFramebufferInfoV1};
use trona_kernel::invoke;
use trona_loader::common::cpio;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::event_loop::decode_cookie;
use trona_server::frame_alloc::FrameAllocator;
use uapi::{
    KERNITE_ERR_OUT_OF_MEMORY, KERNITE_OBJ_EVENT_QUEUE, KERNITE_OBJ_FRAME,
    KERNITE_OBJ_MESSAGE_PIPE, KERNITE_OBJ_MESSAGE_PIPE_CORE, KERNITE_OBJ_TIMER,
    KERNITE_OBJ_UNTYPED, KERNITE_OBJ_WATCH, KERNITE_STATE_READABLE, KERNITE_STATE_TIMED_OUT,
};

use crate::internal_slots::{
    SLOT_BOOTINFO_FRAME, SLOT_CONTROL_EQ, SLOT_CONTROL_EQ_WATCH_SERVICE_MP,
    SLOT_CONTROL_EQ_WATCH_TIMER, SLOT_CONTROL_EQ_WATCH_WORKER, SLOT_CONTROL_TIMER,
    SLOT_MASTER_SERVICE_MP_CORE, SLOT_MASTER_SERVICE_MP_RECV, SLOT_MASTER_SERVICE_MP_SEND,
    SLOT_RECV_SCRATCH_BASE, SLOT_WORKER_COMPLETION_EQ, assert_fixed_slot_layout,
};
use crate::supervisor::SupervisorState;
use crate::supervisor::boot_budget::{INIT_SLAB_POOL_SIZE_BITS, plan_boot_untyped_split};
use crate::supervisor::state::InitTarget;
use crate::supervisor::untyped_split::{boot_untyped_size_bits, split};
use crate::wire::{
    INIT_COOKIE_KIND_CONTROL_TIMER, INIT_COOKIE_KIND_MASTER_MP,
    INIT_COOKIE_KIND_NAMESRV_REGISTER_EVENT, INIT_COOKIE_KIND_WORKER_COMPLETION,
};

pub fn run_full_sequence(state: &mut SupervisorState) -> Result<(), i32> {
    stage_a_read_kernel_handoff(state)?;
    // Manifest must be parsed after Stage A (initrd VA / length are
    // populated) and before any core-service spawn so `stage_h_*` has
    // a topo-sorted list to walk.
    load_manifest(state)?;
    stage_b_split_untyped(state)?;
    // Bind init's `SegmentAllocator` to the init-private untyped now
    // that stage B has split it out. The cookie-table grows that
    // `arm_control_eq_watches` triggers below all retype FRAMEs out
    // of this chunk.
    state.segment_allocator.rebind(
        state
            .untyped
            .init_private
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr(),
    );
    // Carve a dedicated untyped chunk for init's slab page source (PID
    // table / lifecycle / extras) and bind `self_vm` to it. The chunk is
    // distinct from the cookie-table FRAMEs `segment_allocator` retypes
    // out of `init_private`, so the FrameAllocator's exhaustion-reset
    // never recycles a chunk holding live cookie tables.
    bind_slab_backing(state)?;
    // PID 1 (init) is the first slab record and must follow
    // `bind_slab_backing` so its slot_alloc + signal-default install have
    // live backing. Its slot lands at index 1 = PID 1.
    // SAFETY: backing bound on the line above; single-threaded owner.
    if !unsafe { state.procs.install_init(&mut state.self_vm) } {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    stage_c_install_init_caps(state)?;
    // Arm the baseline Watches on the control EQ. Must run before
    // namesrv/rsrcsrv/mmsrv spawn so their INIT_CORE_READY messages
    // on the master service MP are observed.
    arm_control_eq_watches(state)?;
    stage_d_spawn_namesrv(state)?;
    // namesrv is alive — wire up the unit_mgr ↔ namesrv subscribe
    // channel so subsequent publisher REGISTERs (rsrcsrv, mmsrv, and
    // every Stage H service) feed unit_mgr's readiness graph.
    setup_unit_mgr_namesrv_channel(state)?;
    stage_e_spawn_rsrcsrv(state)?;
    // rsrcsrv is alive — wire init's slot allocator for self-expansion
    // and pin init's quota before any subsequent alloc. Must run
    // immediately after spawn_rsrcsrv returns; doing it later risks
    // rsrcsrv hitting the uninitialised `runtime_authority_ep == 0`
    // path on the first child spawn.
    crate::supervisor::boot_core::wire_init_self_expand(state)?;
    stage_f_spawn_mmsrv(state)?;
    stage_g_retroactive_fault_bind(state)?;
    stage_h_spawn_remaining_services(state)?;
    state.runtime_ready = true;
    Ok(())
}

/// Carve init's dedicated slab page-backing untyped out of
/// `init_private`, adopt it into `state.frames`, and bind `state.self_vm`
/// to the running allocator. Runs right after `segment_allocator` binds,
/// before any path can grow a slab — `self_vm` fails loudly while
/// unbound, so an early grow can never silently leak.
fn bind_slab_backing(state: &mut SupervisorState) -> Result<(), i32> {
    let slab = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"init slab untyped pool");
    let r = invoke::untyped_retype(
        state
            .untyped
            .init_private
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default(),
        KERNITE_OBJ_UNTYPED as u64,
        INIT_SLAB_POOL_SIZE_BITS,
        slab.addr(),
    );
    if r != 0 {
        // retype failed: `slab` (OwnedSlot) Drop frees the empty slot.
        return Err(r);
    }
    let slab = slab.assume_filled();
    if !state
        .frames
        .adopt(slab.as_raw(), INIT_SLAB_POOL_SIZE_BITS as u8)
    {
        // adopt failed: `slab` (OwnedCap) Drop deletes the cap and frees the slot.
        return Err(KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    // frames now owns the untyped for the process lifetime; retain the slot.
    core::mem::forget(slab);
    let frames_ptr: *mut FrameAllocator = &raw mut state.frames;
    state.self_vm.rebind(frames_ptr);
    Ok(())
}

/// Allocate a MessagePipe pair, hand the send side to namesrv via
/// `NAMESRV_SUBSCRIBE_REGISTER`, arm a Watch on the recv side that
/// surfaces every namesrv REGISTER as a `NamesrvRegisterEvent` on the
/// control EQ. Run after Stage C — namesrv must be ready to accept
/// admin labels.
fn setup_unit_mgr_namesrv_channel(state: &mut SupervisorState) -> Result<(), i32> {
    use trona_protocol::namesrv::NAMESRV_SUBSCRIBE_REGISTER;

    let core = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"unit_mgr namesrv mp core");
    let send = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"unit_mgr namesrv mp send");
    let recv = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"unit_mgr namesrv mp recv");
    let watch = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"unit_mgr namesrv watch");

    let untyped = state
        .untyped
        .init_private
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    // Retype each object into its slot. Any failure drops the OwnedSlot/OwnedCap
    // handles, freeing every slot allocated so far (the pre-owned code leaked the
    // already-allocated slots on these early returns).
    let r = invoke::untyped_retype(
        untyped,
        KERNITE_OBJ_MESSAGE_PIPE_CORE as u64,
        0,
        core.addr(),
    );
    if r != 0 {
        return Err(r);
    }
    let core = core.assume_filled();
    let r = invoke::untyped_retype(untyped, KERNITE_OBJ_MESSAGE_PIPE as u64, 0, send.addr());
    if r != 0 {
        return Err(r);
    }
    let send = send.assume_filled();
    let r = invoke::untyped_retype(untyped, KERNITE_OBJ_MESSAGE_PIPE as u64, 0, recv.addr());
    if r != 0 {
        return Err(r);
    }
    let recv = recv.assume_filled();
    let r = invoke::untyped_retype(untyped, KERNITE_OBJ_WATCH as u64, 0, watch.addr());
    if r != 0 {
        return Err(r);
    }
    let watch = watch.assume_filled();
    let r = invoke::mp_core_pair(core.borrow(), send.borrow(), recv.borrow());
    if r != 0 {
        return Err(r);
    }

    // Arm the Watch so STATE_READABLE on the recv side surfaces as
    // a `NamesrvRegisterEvent` on the control EQ. Register the
    // cookie in the reactor's table first so the dispatcher can
    // resolve it back to `InitTarget::NamesrvRegisterEvent`.
    let cookie = unsafe {
        state
            .cookie_table
            .arm(
                &mut state.segment_allocator,
                INIT_COOKIE_KIND_NAMESRV_REGISTER_EVENT,
                recv.as_raw(),
                watch.as_raw(),
                InitTarget::NamesrvRegisterEvent,
            )
            .map_err(|_| uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as i32)?
    };
    let r = invoke::watch_register(
        watch.borrow(),
        recv.borrow(),
        state
            .caps
            .control_eq
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default(),
        KERNITE_STATE_READABLE,
        cookie,
    );
    if r != 0 {
        let (_kind, slot, _epoch) = decode_cookie(cookie);
        let _ = state
            .cookie_table
            .cancel(INIT_COOKIE_KIND_NAMESRV_REGISTER_EVENT, slot);
        return Err(r);
    }
    state.caps.namesrv_register_event_watch_cookie = cookie;

    // Stage the send slot into caps[0] and issue the admin call.
    // Transfer the send side to namesrv: the kernel MOVEs the cap out of our
    // CSpace on the call, and the TransferCap reclaims the now-empty slot.
    let send_tc = send.into_transfer();
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    unsafe {
        trona_kernel::ipc::set_send_cap_ctx(ipc_ctx, 0, send_tc.slot());
    }
    let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
    msg.label = NAMESRV_SUBSCRIBE_REGISTER;
    msg.length = 0;
    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
    let r = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ipc_ctx,
            state
                .caps
                .namesrv_client_mp
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if r != 0 || reply.label != trona_protocol::common::TRONA_OK {
        // Roll the armed cookie back before the owned handles drop, so the cookie
        // table never references a reclaimed slot. `core` (delete+free), `send_tc`
        // (reclaim), `recv` and `watch` (delete+free) all drop on return.
        let (_kind, slot, _epoch) = decode_cookie(cookie);
        let _ = state
            .cookie_table
            .cancel(INIT_COOKIE_KIND_NAMESRV_REGISTER_EVENT, slot);
        return Err(reply.label as i32);
    }

    // namesrv took the send side; `send_tc` drop reclaims the now-empty slot.
    // The core object is no longer needed by either side; `core` drop deletes
    // and frees it.
    drop(send_tc);
    drop(core);
    state.caps.unit_mgr_namesrv_event_mp_recv = Some(recv);
    state.caps.unit_mgr_namesrv_event_watch = Some(watch);
    Ok(())
}

fn stage_a_read_kernel_handoff(state: &mut SupervisorState) -> Result<(), i32> {
    assert_fixed_slot_layout();
    let bits = boot_untyped_size_bits();
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[INIT] boot untyped size_bits=");
        _lb.dec(bits as u64);
        _lb.str(b"\n");
    });

    // Initrd MO base + size both live in the bootinfo TLV stream
    // (`KERNITE_BOOTINFO_TAG_INITRD`). The kernel maps the bootinfo
    // frame at a fixed VA before init starts; `trona_kernel::bootinfo` walks
    // it.
    match unsafe {
        trona_kernel::bootinfo::read_typed::<uapi::kernite_bootinfo_initrd>(
            uapi::KERNITE_BOOTINFO_TAG_INITRD as u16,
        )
    } {
        Some(rec) => {
            state.caps.initrd_va = rec.user_va;
            state.caps.initrd_len = rec.length as usize;
        }
        None => {
            state.caps.initrd_va = 0;
            state.caps.initrd_len = 0;
        }
    }

    state.caps.framebuffer = match unsafe {
        trona_kernel::bootinfo::read_typed::<uapi::kernite_bootinfo_framebuffer>(
            uapi::KERNITE_BOOTINFO_TAG_FRAMEBUFFER as u16,
        )
    } {
        Some(rec) => SaltyOSFramebufferInfoV1 {
            phys_addr: rec.phys_addr,
            width: rec.width,
            height: rec.height,
            pitch: rec.pitch,
            bpp: rec.bpp,
            red_pos: rec.red_pos,
            red_size: rec.red_size,
            green_pos: rec.green_pos,
            green_size: rec.green_size,
            blue_pos: rec.blue_pos,
            blue_size: rec.blue_size,
            reserved: 0,
        },
        None => SaltyOSFramebufferInfoV1::zeroed(),
    };

    // Reserve init slot 0..=71 and 16..=24 (kernel-installed) so
    // `slot_alloc` skips them before Stage B allocates the four
    // destination slots for the boot-untyped split. Slot 256 is the
    // permanent self-expansion temp slot reserved for `cnode_move`
    // during slot_alloc self-expansion — see `wire_init_self_expand`.
    trona_runtime::core::slot_alloc::install_skip_range(0, 72);
    trona_runtime::core::slot_alloc::install_skip_range(
        crate::internal_slots::SLOT_SELF_EXPAND_TEMP,
        1,
    );

    Ok(())
}

fn stage_c_install_init_caps(state: &mut SupervisorState) -> Result<(), i32> {
    let init_private = state
        .untyped
        .init_private
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();

    let r = invoke::untyped_retype(
        init_private,
        KERNITE_OBJ_FRAME as u64,
        0,
        SLOT_BOOTINFO_FRAME,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(
        init_private,
        KERNITE_OBJ_EVENT_QUEUE as u64,
        0,
        SLOT_CONTROL_EQ,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(
        init_private,
        KERNITE_OBJ_EVENT_QUEUE as u64,
        0,
        SLOT_WORKER_COMPLETION_EQ,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(
        init_private,
        KERNITE_OBJ_TIMER as u64,
        0,
        SLOT_CONTROL_TIMER,
    );
    if r != 0 {
        return Err(r);
    }

    // Master service-EP MP pair. Kernel `syscall_mp_pair` validates
    // the two side caps as already-retyped MessagePipes before
    // binding them to the core; retype core + 2 sides, then issue
    // `MP_CORE_PAIR`.
    let r = invoke::untyped_retype(
        init_private,
        KERNITE_OBJ_MESSAGE_PIPE_CORE as u64,
        0,
        SLOT_MASTER_SERVICE_MP_CORE,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(
        init_private,
        KERNITE_OBJ_MESSAGE_PIPE as u64,
        0,
        SLOT_MASTER_SERVICE_MP_SEND,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(
        init_private,
        KERNITE_OBJ_MESSAGE_PIPE as u64,
        0,
        SLOT_MASTER_SERVICE_MP_RECV,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::mp_core_pair(
        CapRef::flat(SLOT_MASTER_SERVICE_MP_CORE),
        CapRef::flat(SLOT_MASTER_SERVICE_MP_SEND),
        CapRef::flat(SLOT_MASTER_SERVICE_MP_RECV),
    );
    if r != 0 {
        return Err(r);
    }

    // Three Watch caps. The master service-MP Watch is also used
    // during Stage D/E/F core-ready waits, then re-armed for the
    // long-lived owner reactor path.
    for slot in [
        SLOT_CONTROL_EQ_WATCH_SERVICE_MP,
        SLOT_CONTROL_EQ_WATCH_TIMER,
        SLOT_CONTROL_EQ_WATCH_WORKER,
    ] {
        let r = invoke::untyped_retype(init_private, KERNITE_OBJ_WATCH as u64, 0, slot);
        if r != 0 {
            return Err(r);
        }
    }

    // SLOT_* constants are fixed kernel-installed slots — wrap as
    // OwnedCap (depth=0) so Drop will revoke+free them on teardown.
    // SAFETY: each SLOT_* is a distinct, well-known bootstrap slot the kernel
    // installed exactly one cap into, in init's flat root CSpace (depth 0);
    // adopted once here as the sole owner of each.
    unsafe {
        state.caps.bootinfo_frame = Some(OwnedCap::from_raw(SLOT_BOOTINFO_FRAME, 0));
        state.caps.control_eq = Some(OwnedCap::from_raw(SLOT_CONTROL_EQ, 0));
        state.caps.worker_completion_eq = Some(OwnedCap::from_raw(SLOT_WORKER_COMPLETION_EQ, 0));
        state.caps.control_timer = Some(OwnedCap::from_raw(SLOT_CONTROL_TIMER, 0));
        state.caps.recv_scratch_base = SLOT_RECV_SCRATCH_BASE;
        state.caps.master_service_mp_recv =
            Some(OwnedCap::from_raw(SLOT_MASTER_SERVICE_MP_RECV, 0));
        state.caps.master_service_mp_send =
            Some(OwnedCap::from_raw(SLOT_MASTER_SERVICE_MP_SEND, 0));
    }

    Ok(())
}

/// Arm the three baseline Watches on the control EQ. Each Watch's
/// cookie is registered in `state.cookie_table` first so the kernel
/// can publish back through `EventRecord.cookie` and the dispatcher
/// can route by `(kind, slot, live_gen)`. Cookie kinds:
/// * `INIT_COOKIE_KIND_MASTER_MP` — master service-EP MP recv
///   (admin-tier IPC arrival)
/// * `INIT_COOKIE_KIND_CONTROL_TIMER` — control timer fired (spawn
///   timeout / itimer expiry)
/// * `INIT_COOKIE_KIND_WORKER_COMPLETION` — worker_completion EQ
///   (lifecycle worker posted a result)
fn arm_control_eq_watches(state: &mut SupervisorState) -> Result<(), i32> {
    let control_eq = state
        .caps
        .control_eq
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();

    // Master service-EP MP recv — admin-tier RPCs.
    let cookie = unsafe {
        state
            .cookie_table
            .arm(
                &mut state.segment_allocator,
                INIT_COOKIE_KIND_MASTER_MP,
                SLOT_MASTER_SERVICE_MP_RECV,
                SLOT_CONTROL_EQ_WATCH_SERVICE_MP,
                InitTarget::MasterServiceMp,
            )
            .map_err(|_| uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as i32)?
    };
    let r = invoke::watch_register(
        CapRef::flat(SLOT_CONTROL_EQ_WATCH_SERVICE_MP),
        CapRef::flat(SLOT_MASTER_SERVICE_MP_RECV),
        control_eq,
        KERNITE_STATE_READABLE,
        cookie,
    );
    if r != 0 {
        let (_kind, slot, _epoch) = decode_cookie(cookie);
        let _ = state.cookie_table.cancel(INIT_COOKIE_KIND_MASTER_MP, slot);
        return Err(r);
    }
    state.caps.master_service_mp_watch_cookie = cookie;

    // control_timer STATE_TIMED_OUT — no MP body to drain on fire,
    // dispatcher's `resolve_mp_recv` returns None for the entry's
    // null `mp_recv` field and the handler executes against the
    // timer cap directly.
    let cookie = unsafe {
        state
            .cookie_table
            .arm(
                &mut state.segment_allocator,
                INIT_COOKIE_KIND_CONTROL_TIMER,
                0,
                SLOT_CONTROL_EQ_WATCH_TIMER,
                InitTarget::ControlTimer,
            )
            .map_err(|_| uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as i32)?
    };
    let r = invoke::watch_register(
        CapRef::flat(SLOT_CONTROL_EQ_WATCH_TIMER),
        CapRef::flat(SLOT_CONTROL_TIMER),
        control_eq,
        KERNITE_STATE_TIMED_OUT,
        cookie,
    );
    if r != 0 {
        let (_kind, slot, _epoch) = decode_cookie(cookie);
        let _ = state
            .cookie_table
            .cancel(INIT_COOKIE_KIND_CONTROL_TIMER, slot);
        return Err(r);
    }
    state.caps.control_timer_watch_cookie = cookie;

    // worker_completion EQ STATE_READABLE — fan-in from lifecycle
    // worker TCBs.
    let cookie = unsafe {
        state
            .cookie_table
            .arm(
                &mut state.segment_allocator,
                INIT_COOKIE_KIND_WORKER_COMPLETION,
                0,
                SLOT_CONTROL_EQ_WATCH_WORKER,
                InitTarget::WorkerCompletion,
            )
            .map_err(|_| uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as i32)?
    };
    let r = invoke::watch_register(
        CapRef::flat(SLOT_CONTROL_EQ_WATCH_WORKER),
        CapRef::flat(SLOT_WORKER_COMPLETION_EQ),
        control_eq,
        KERNITE_STATE_READABLE,
        cookie,
    );
    if r != 0 {
        let (_kind, slot, _epoch) = decode_cookie(cookie);
        let _ = state
            .cookie_table
            .cancel(INIT_COOKIE_KIND_WORKER_COMPLETION, slot);
        return Err(r);
    }
    state.caps.worker_completion_watch_cookie = cookie;

    Ok(())
}

fn stage_b_split_untyped(state: &mut SupervisorState) -> Result<(), i32> {
    // Allocate 4 fresh init slots for the 4 untyped chunks.
    let init_priv = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"init private untyped");
    let namesrv_quota =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"namesrv private untyped");
    let rsrcsrv_quota =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"rsrcsrv authority untyped");
    let mmsrv_pool =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"mmsrv frame pool untyped");
    if init_priv == 0 || namesrv_quota == 0 || rsrcsrv_quota == 0 || mmsrv_pool == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }

    let plan = plan_boot_untyped_split(state)?;
    let chunks = split(init_priv, namesrv_quota, rsrcsrv_quota, mmsrv_pool, plan)?;
    state.untyped = chunks;
    Ok(())
}

fn stage_d_spawn_namesrv(state: &mut SupervisorState) -> Result<(), i32> {
    crate::supervisor::boot_core::spawn_namesrv(state)
}

fn stage_e_spawn_rsrcsrv(state: &mut SupervisorState) -> Result<(), i32> {
    crate::supervisor::boot_core::spawn_rsrcsrv(state)
}

fn stage_f_spawn_mmsrv(state: &mut SupervisorState) -> Result<(), i32> {
    crate::supervisor::boot_core::spawn_mmsrv(state)
}

fn stage_g_retroactive_fault_bind(state: &mut SupervisorState) -> Result<(), i32> {
    crate::supervisor::boot_core::stage_f_retroactive_fault_bind(state)
}

fn stage_h_spawn_remaining_services(state: &mut SupervisorState) -> Result<(), i32> {
    // Mark the four boot-stage cores as ready before the first
    // `dispatch_ready` so their downstream consumers (vfs, posix_*,
    // drivers) can unblock immediately. The cores' own readiness
    // signals and namesrv REGISTER events arrive on the control EQ
    // *after* boot returns, but the supervisor knows boot succeeded
    // for them — anchoring the graph here keeps unit_mgr's invariants
    // consistent without a chicken-and-egg between Stage F and
    // Stage G.
    state.unit_graph.mark_core_ready(&state.manifest, b"init");
    state
        .unit_graph
        .mark_core_ready(&state.manifest, b"namesrv");
    state
        .unit_graph
        .mark_core_ready(&state.manifest, b"rsrcsrv");
    state.unit_graph.mark_core_ready(&state.manifest, b"mmsrv");

    // Drive the readiness graph's first pass — every service whose
    // dependencies are already satisfied launches now. Subsequent
    // dispatch passes happen inside `owner_loop` when INIT_NOTIFY_READY
    // messages or namesrv REGISTER events arrive.
    drive_dispatch_ready(state)
}

/// One pass of the readiness graph: collect every service whose
/// dependencies are satisfied and which has not yet been dispatched,
/// then invoke `lifecycle::handle_spawn` for each. Called both from
/// Stage G (initial pass) and from the owner loop (when a readiness
/// signal or namesrv REGISTER event unblocks new services).
pub fn drive_dispatch_ready(state: &mut SupervisorState) -> Result<(), i32> {
    use crate::supervisor::manifest::MAX_SERVICES;
    use crate::supervisor::manifest::ReadinessSource;
    loop {
        let mut buf = [0u8; MAX_SERVICES];
        let n = state.unit_graph.dispatch_ready(&state.manifest, &mut buf);
        if n == 0 {
            break;
        }
        for &svc_idx in &buf[..n] {
            let name = state.manifest.services[svc_idx as usize].name;
            let idx = svc_idx as usize;
            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"[INIT] spawning ");
                _lb.bytes(name.as_bytes());
                _lb.str(b"\n");
            });
            match spawn_service_named(state, idx) {
                Ok(pid) => {
                    trona_runtime::uinfo!(|_lb| {
                        _lb.str(b"[INIT] spawned ");
                        _lb.bytes(name.as_bytes());
                        _lb.str(b" pid=");
                        _lb.dec(pid as u64);
                        _lb.str(b"\n");
                    });
                    if matches!(
                        state.manifest.services[idx].readiness_source(),
                        ReadinessSource::Immediate
                    ) {
                        state.unit_graph.on_immediate_ready(&state.manifest, idx);
                    }

                    // If this was ldsrv, its bundle delivered the adopt-MP recv
                    // end and stashed the send end. Stream the boot code set and
                    // move the ExecAuthority now — the synchronous calls block
                    // until ldsrv seals, so no resolve client can run first.
                    if let Some(adopt_send) = state.ldsrv_adopt_send.take() {
                        if let Err(err) = crate::supervisor::ldsrv_adopt::send_adopt_set(
                            state,
                            adopt_send.as_raw(),
                        ) {
                            trona_runtime::uerror!(|_lb| {
                                _lb.str(b"[INIT] ldsrv adopt failed err=");
                                _lb.hex(err as u64);
                                _lb.str(b"\n");
                            });
                            return Err(err);
                        }
                    }
                }
                Err(err) => {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[INIT] failed to spawn ");
                        _lb.bytes(name.as_bytes());
                        _lb.str(b" err=");
                        _lb.hex(err as u64);
                        _lb.str(b"\n");
                    });
                }
            }
        }
    }
    Ok(())
}

fn spawn_service_named(state: &mut SupervisorState, idx: usize) -> Result<u32, i32> {
    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
    let mut request = trona_kernel::core_types::TronaMsg::zeroed();
    request.regs[0] = idx as u64;
    crate::supervisor::lifecycle::handle_spawn(state, &request, 1, &mut reply);
    if reply.label == trona_protocol::common::TRONA_OK {
        Ok(reply.regs[0] as u32)
    } else {
        Err(reply.label as i32)
    }
}

/// Walk the initrd `/services/` tree, parse every unit file (`.service`,
/// `.cap`, `.socket`, `.target`) into the manifest, validate
/// cross-references, and topo-sort the service graph. Called from
/// `main.rs` *before* `run_full_sequence`.
///
/// Manifest correctness is fail-loud: any individual unit file that
/// fails to parse, or a cross-reference / cycle detected by
/// `validate` / `topo_sort`, halts boot with `ERR_MANIFEST_INVALID`.
/// Silent absorption would let boot proceed against a graph the
/// supervisor cannot guarantee, so unit_mgr's readiness invariants
/// would not hold.
pub fn load_manifest(state: &mut SupervisorState) -> Result<(), i32> {
    if state.caps.initrd_len == 0 {
        return Ok(());
    }
    let initrd = unsafe {
        core::slice::from_raw_parts(state.caps.initrd_va as *const u8, state.caps.initrd_len)
    };
    // SAFETY: `initrd` is built from the bootinfo-provided initrd VA/length
    // and remains mapped for init's lifetime.
    let mut iter = unsafe { cpio::CpioIter::new(initrd.as_ptr(), initrd.len()) };
    while let Some(entry) = iter.next_entry() {
        let name = unsafe { core::slice::from_raw_parts(entry.name, entry.name_len) };
        if !name.starts_with(b"/services/") {
            continue;
        }
        let body = unsafe { core::slice::from_raw_parts(entry.data, entry.data_len) };
        let parsed = if name.ends_with(b".service") {
            state.manifest.parse_and_add(body).map(|_| ())
        } else if name.ends_with(b".cap") {
            state.manifest.parse_cap_and_add(name, body).map(|_| ())
        } else if name.ends_with(b".socket") {
            state.manifest.parse_socket_and_add(name, body).map(|_| ())
        } else if name.ends_with(b".target") {
            state.manifest.parse_target_and_add(name, body).map(|_| ())
        } else {
            continue;
        };
        if let Err(e) = parsed {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[INIT] manifest parse failed for ");
                _lb.bytes(name);
                _lb.str(b" - err=");
                _lb.dec(e as u64);
                _lb.str(b"\n");
            });
            return Err(ERR_MANIFEST_INVALID);
        }
    }
    if let Err(e) = state.manifest.validate() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] manifest validate failed - err=");
            _lb.dec(e as u64);
            _lb.str(b"\n");
        });
        return Err(ERR_MANIFEST_INVALID);
    }
    if let Err(e) = state.manifest.topo_sort() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] manifest topo_sort failed - err=");
            _lb.dec(e as u64);
            _lb.str(b"\n");
        });
        return Err(ERR_MANIFEST_INVALID);
    }
    if state.manifest.spawn_order_slice().len() != state.manifest.count {
        return Err(ERR_MANIFEST_INVALID);
    }
    if let Err(e) = state.unit_graph.build(&state.manifest) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] unit_graph build failed - err=");
            _lb.dec(e as u64);
            _lb.str(b"\n");
        });
        return Err(ERR_MANIFEST_INVALID);
    }
    Ok(())
}

/// Sentinel error returned when the manifest cannot be loaded into a
/// valid topo-sorted graph. Boot must not proceed past this.
pub const ERR_MANIFEST_INVALID: i32 = -32;
