// SPDX-License-Identifier: GPL-2.0-only
//
//! Pre-rsrcsrv / pre-mmsrv core service spawn recipes.
//!
//! Stages C, D, E, F of the boot sequence drive into this module. The
//! spawn pipeline they compose is:
//!
//! 1. Allocate per-TCB plumbing (TCB / VSpace / CNode / SC / IPC
//!    frame / stack frames / cap-table frame) from the spawning
//!    stage's untyped seed via [`spawn::alloc::DirectUntypedAllocator`].
//! 2. Retype service-specific objects from the same seed (or
//!    dedicated raw-untyped chunks transferred via
//!    `cnode_move`).
//! 3. Map the image (main ELF + `ldtrona-elf.so` interpreter +
//!    DT_NEEDED DSOs) into the child VSpace via
//!    [`loader::load_image_borrowed`], which backs each image with
//!    borrowed-frames code MemoryObjects conferred `R-X`.
//! 4. Build the cap-table on the cap-table frame, populate
//!    role-keyed entries from the spawning context, and map the
//!    frame read-only at `CHILD_CAP_TABLE_VA`.
//! 5. Configure + start the main TCB.
//! 6. Wait for the service's `INIT_CORE_READY` message on
//!    `ROLE_INIT_CONTROL`, delivered through init's master service MP
//!    and existing control EQ Watch.
//!
//! Stage F runs after every core service is up: for each TCB that
//! came up before mmsrv was registering fault pipes (init main /
//! namesrv main / rsrcsrv main / mmsrv main / mmsrv fault dispatcher
//! / lifecycle worker), allocate a fault MP pair through rsrcsrv,
//! register the recv side with mmsrv via `MM_REGISTER_FAULT_PIPE`,
//! then bind the fault MP send side on the target TCB.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::spawn::cap_table::CapTableBuilder;
use trona_runtime::spawn::role_consts::{
    ROLE_INIT_CONTROL, ROLE_MMSRV_AUTHORITY_RAW, ROLE_MMSRV_FAULT_EQ,
    ROLE_MMSRV_FAULT_MP_MASTER_RECV, ROLE_MMSRV_FAULT_SC, ROLE_MMSRV_FAULT_STACK_FRAME,
    ROLE_MMSRV_FAULT_TCB, ROLE_MMSRV_SERVICE_EQ, ROLE_NAMESRV_BOOT_UNTYPED, ROLE_NAMESRV_CLIENT,
    ROLE_NAMESRV_MASTER_EQ, ROLE_NAMESRV_MASTER_MP, ROLE_NAMESRV_PARK_TIMER,
    ROLE_NAMESRV_WATCH_BASE, ROLE_RSRCSRV_AUTHORITY_RAW, ROLE_RSRCSRV_SERVICE_EQ,
    ROLE_SERVICE_CLIENT_EP, ROLE_SERVICE_EP,
};
use trona_runtime::spawn::stack_plan::StackLayoutSpec;
use uapi::{
    KERNITE_ERR_INVALID_OPERATION, KERNITE_EVENT_TYPE_STATE, KERNITE_OBJ_FRAME,
    KERNITE_OBJ_UNTYPED, KERNITE_PAGE_BYTES, KERNITE_PAGE_FLAG_USER, KERNITE_PAGE_FLAG_WRITABLE,
    KERNITE_STATE_READABLE,
};

use crate::internal_slots::SLOT_CONTROL_EQ_WATCH_SERVICE_MP;
use crate::supervisor::SupervisorState;
use crate::supervisor::loader;
use crate::supervisor::manifest::{BinaryStr, NameStr, ServiceDef};
use crate::supervisor::proc_table::PID_INIT;
use crate::supervisor::retype::RetypeClass;
use crate::supervisor::spawn::cspace::{
    build_and_map_cap_table, deliver_cap, deliver_cap_minted, deliver_cap_moved, place_slab_moved,
    place_system_caps, seed_self_caps,
};
use crate::supervisor::spawn::plan::{ChildBundle, DEFAULT_CHILD_STACK_TOP};
use crate::supervisor::spawn::tcb::{SchedParams, configure_and_start_tcb};
use crate::supervisor::state::InitTarget;
use crate::wire::{INIT_BADGE_FROM_MMSRV, INIT_BADGE_FROM_NAMESRV, INIT_BADGE_FROM_RSRCSRV};

/// Stack pages each core service gets at boot. 16 pages = 64 KiB,
/// matching `STACK_PAGES` in substrate's layout planner. Sized to
/// cover startup + cap-table walk + first round-trip with namesrv +
/// core-ready signal.
pub(crate) const CORE_STACK_PAGES: usize = 16;

const NAMESRV_PID: u32 = 2;
const RSRCSRV_PID: u32 = 3;
const MMSRV_PID: u32 = 4;

/// Page protection flags used for the IPC-buffer + stack mappings —
/// USER + WRITABLE (no EXECUTABLE).
const PAGE_FLAGS_RW_USER: u64 =
    (KERNITE_PAGE_FLAG_USER as u64) | (KERNITE_PAGE_FLAG_WRITABLE as u64);

/// Child VA where each core service finds its IPC buffer. Substrate
/// reads it from `AT_SALTYOS_STARTUP.ipc_buffer_vaddr`.
use crate::supervisor::spawn::plan::CHILD_IPC_BUFFER_VA;

fn install_boot_core_proc_record(
    state: &mut SupervisorState,
    expected_pid: u32,
    name: &[u8],
) -> Result<(), i32> {
    let svc_idx = state
        .manifest
        .find_index_by_name(name)
        .ok_or(KERNITE_ERR_INVALID_OPERATION as i32)? as u8;
    let def = state.manifest.services[svc_idx as usize];
    let start_ns = trona_kernel::syscall::clock_read_monotonic(
        trona_runtime::client::caps::clock_cap().addr(),
    );
    let ok = unsafe {
        state.procs.install_boot_core_service(
            &mut state.self_vm,
            expected_pid,
            PID_INIT,
            svc_idx,
            def.name,
            def.binary,
            def.service_type,
            def.restart,
            start_ns,
        )
    };
    if ok {
        Ok(())
    } else {
        Err(KERNITE_ERR_INVALID_OPERATION as i32)
    }
}

/// Slot layout in the child's CNode. The supervisor assigns each
/// role a contiguous block; system caps land at slots 3..7 by
/// substrate convention, runtime caps start at 16.
const CHILD_RUNTIME_BASE_SLOT: u64 = 16;

/// Spawn `namesrv` from `state.untyped.namesrv_quota`. After this
/// returns successfully, `state.caps.namesrv_client_mp` carries the
/// init-side send for namesrv's master MP — every later spawn that
/// delivers `ROLE_NAMESRV_CLIENT` mints from this slot.
pub fn spawn_namesrv(state: &mut SupervisorState) -> Result<(), i32> {
    // Split state.untyped.namesrv_quota according to Stage B's
    // measured plan: `namesrv_plumbing` backs init's direct-loader
    // plumbing plus namesrv's ELF/DSO image frames;
    // `namesrv_boot` is handed to namesrv via ROLE_NAMESRV_BOOT_UNTYPED
    // for its SegmentAllocator backing (cookie-table segments + future
    // internal dynamic structures). Boot order puts namesrv ahead of
    // mmsrv, so namesrv cannot use mm::mmap_anon; rsrcsrv's vending
    // object set excludes OBJ_FRAME, so namesrv must own its own
    // untyped to retype frames itself.
    let namesrv_quota = state
        .untyped
        .namesrv_quota
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    let plumbing_bits = state.untyped.namesrv_plumbing_size_bits;
    let boot_bits = state.untyped.namesrv_boot_size_bits;
    if plumbing_bits == 0 || boot_bits == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let namesrv_plumbing_slot =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"namesrv_plumbing sub-untyped");
    let err = invoke::untyped_retype(
        namesrv_quota,
        KERNITE_OBJ_UNTYPED as u64,
        plumbing_bits,
        namesrv_plumbing_slot,
    );
    if err != 0 {
        return Err(err);
    }
    let namesrv_boot_slot =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"namesrv_boot sub-untyped");
    let err = invoke::untyped_retype(
        namesrv_quota,
        KERNITE_OBJ_UNTYPED as u64,
        boot_bits,
        namesrv_boot_slot,
    );
    if err != 0 {
        return Err(err);
    }
    // SAFETY: namesrv_boot_slot was just retyped (untyped_retype above, err
    // checked) into init's flat root CSpace (depth 0); this is its sole owner.
    let namesrv_boot = unsafe { OwnedCap::from_raw(namesrv_boot_slot, 0) };
    let untyped = CapRef::flat(namesrv_plumbing_slot);
    // plumbing owns tcb/vspace/cspace/sched_context/ipc_buffer_frame/cap_table_frame.
    // cap_table_frame and ipc_buffer_frame are needed by build_and_map_cap_table and
    // load_core_image (both borrow plumbing). tcb/vspace/cspace/sched_context are moved
    // into the bundle AFTER both calls, then from bundle into state.caps.
    let plumbing = retype_core_plumbing(untyped, b"namesrv plumbing")?;

    // namesrv-private objects: master EQ + master MP pair + park
    // Timer + 16 Watch slab.
    let master_eq = retype_one(untyped, RetypeClass::EventQueue, 8, b"namesrv master_eq")?;
    let (master_mp_send, master_mp_recv) = retype_mp_pair_direct(untyped, b"namesrv master MP")?;
    // SAFETY: recv side of a fresh MP pair just minted into init's flat root
    // CSpace (depth 0); sole owner of this slot.
    let master_mp_recv = unsafe { OwnedCap::from_raw(master_mp_recv, 0) };
    let park_timer = retype_one(untyped, RetypeClass::Timer, 0, b"namesrv park_timer")?;
    let watch_slab_base = retype_slab(untyped, RetypeClass::Watch, 0, 16, b"namesrv watch slab")?;
    let mut child_slot = CHILD_RUNTIME_BASE_SLOT;

    let cap_table_va = build_and_map_cap_table(
        plumbing.vspace.borrow(),
        plumbing.cap_table_frame.borrow(),
        |builder: &mut CapTableBuilder| -> Result<(), i32> {
            place_system_caps(plumbing.cspace.borrow(), builder, &mut child_slot)?;

            // ROLE_INIT_CONTROL — mint a per-child copy of init's
            // master service-EP send badged with `INIT_BADGE_FROM_NAMESRV`
            // so namesrv's server→init callbacks (e.g. `INIT_CORE_READY`)
            // are authenticated as coming from namesrv specifically. The
            // source MUST be `master_service_mp_send`; the recv side stays
            // inside init for `EQ_WAIT` consumption, and minting from a recv
            // side would produce the wrong direction (the child would receive
            // instead of send).
            let init_ep_dest = child_slot;
            child_slot += 1;
            deliver_cap_minted(
                plumbing.cspace.borrow(),
                builder,
                ROLE_INIT_CONTROL,
                state
                    .caps
                    .master_service_mp_send
                    .as_ref()
                    .map(OwnedCap::borrow),
                init_ep_dest,
                INIT_BADGE_FROM_NAMESRV as u64,
                0,
            )?;

            // ROLE_NAMESRV_MASTER_EQ — namesrv's master EQ.
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_NAMESRV_MASTER_EQ,
                Some(master_eq),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_NAMESRV_MASTER_MP — namesrv's recv side on the
            // master MP. Init keeps the send side
            // (state.caps.namesrv_client_mp).
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_NAMESRV_MASTER_MP,
                Some(master_mp_recv),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_NAMESRV_PARK_TIMER.
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_NAMESRV_PARK_TIMER,
                Some(park_timer),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_NAMESRV_WATCH_BASE — 16 pre-retyped Watch caps in
            // a contiguous range.
            let watch_dest_base = child_slot;
            place_slab_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_NAMESRV_WATCH_BASE,
                watch_slab_base,
                watch_dest_base,
                16,
            )?;
            child_slot += 16;

            // ROLE_NAMESRV_BOOT_UNTYPED — namesrv's own boot
            // allocator seed. namesrv retypes 4 KiB frames out of
            // this for its EventLoop cookie table and other
            // internal dynamic structures. Direction is move (cap
            // leaves init's CSpace) — init has no further use for the
            // boot sub-untyped.
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_NAMESRV_BOOT_UNTYPED,
                Some(namesrv_boot),
                child_slot,
                0,
            )?;
            child_slot += 1;

            Ok(())
        },
    )?;
    let _ = cap_table_va;
    let alloc_slot_base = child_slot;

    // Map the namesrv image and compose the startup stack after the
    // cap-table slots have been installed. The advertised allocator
    // base must start after those slots so runtime slot_alloc never
    // reuses boot-delivered caps or reserved empty ranges.
    let load = load_core_image(state, &plumbing, untyped, b"/bin/namesrv", alloc_slot_base)?;

    // Move plumbing identity caps into the bundle for seed_self_caps
    // and configure_and_start_tcb; cap_table_frame and ipc_buffer_frame
    // stay in plumbing (already mapped, no init-side use after this point).
    let bundle = ChildBundle {
        tcb: Some(plumbing.tcb),
        vspace: Some(plumbing.vspace),
        cspace: Some(plumbing.cspace),
        sched_context: Some(plumbing.sched_context),
        request_mp_send: None,
        request_mp_recv: None,
        signal_mp_send: None,
        signal_mp_recv: None,
        fault_mp_send: None,
        fault_mp_recv: None,
        mmsrv_request_mp_send: None,
        mmsrv_request_mp_recv: None,
        service_ep_send: None,
        service_ep_recv: None,
        adopt_recv: None,
        exec_control_recv: None,
        ldsrv_untyped: None,
    };

    seed_self_caps(&bundle)?;

    // Retain the unminted master MP send for per-child mints. Each
    // future spawn that delivers `ROLE_NAMESRV_CLIENT` must mint from
    // this slot with the per-child badge — `cnode_mint` strips Grant
    // from the destination, so `state.caps.namesrv_client_mp` (an
    // admin-class minted copy) cannot serve as a re-mint source.
    // SAFETY: master_mp_send is the send side of the fresh namesrv MP pair (its
    // recv side already adopted above), retained here for per-child re-mints;
    // init flat root CSpace (depth 0), sole owner.
    state.caps.namesrv_master_mp_send_raw = Some(unsafe { OwnedCap::from_raw(master_mp_send, 0) });
    // Mint init's own admin send into a separate slot (admin-class
    // badge `bit63-62 = 0b11` per `userland/core/namesrv/src/authz.rs`)
    // for `NAMESRV_GRANT_PUBLISHER` / `_OWNER_EXITED` etc.
    state.caps.namesrv_client_mp = Some(mint_from_raw_send(
        master_mp_send,
        NAMESRV_ADMIN_BADGE,
        b"namesrv admin send",
    )?);

    // Direct boot stacks are raw FRAME mappings, not mmsrv-tracked
    // stack VMAs. `TCB_SET_STACK_BOUNDS` only accepts the latter, so
    // skip bounds for pre-mmsrv core services.
    install_boot_core_proc_record(state, NAMESRV_PID, b"namesrv")?;
    configure_and_start_tcb(
        &bundle,
        CHILD_IPC_BUFFER_VA,
        load.entry_pc,
        load.child_sp,
        0,
        DEFAULT_CHILD_STACK_TOP,
        0,
        0,
        SchedParams::fair_default(),
    )?;

    // Retain the namesrv main TCB + VSpace caps so Stage F's
    // retroactive fault-binding loop can register namesrv with mmsrv
    // and bind a fault MP onto its main TCB. Bundle is consumed here.
    // Also retain the loader's `VmLayoutPlan` — Stage F passes its
    // `client_layout()` to mmsrv so the registered layout matches the
    // image windows the namesrv loader actually used.
    let ChildBundle { tcb, vspace, .. } = bundle;
    state.caps.namesrv_main_tcb = tcb;
    state.caps.namesrv_vspace = vspace;
    state.caps.namesrv_layout = Some(load.plan.client_layout());

    wait_for_core_ready(state, INIT_BADGE_FROM_NAMESRV as u64)?;
    Ok(())
}

/// Spawn `rsrcsrv` from `state.untyped.init_private` (plumbing) +
/// `state.untyped.rsrcsrv_quota` (the entire untyped chunk
/// transferred via `cnode_move` to `ROLE_RSRCSRV_AUTHORITY_RAW`).
/// After this returns, `state.caps.rsrcsrv_client_mp` carries
/// rsrcsrv's master MP send.
pub fn spawn_rsrcsrv(state: &mut SupervisorState) -> Result<(), i32> {
    let untyped = state
        .untyped
        .init_private
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    let plumbing = retype_core_plumbing(untyped, b"rsrcsrv plumbing")?;

    let (master_mp_send, master_mp_recv) = retype_mp_pair_direct(untyped, b"rsrcsrv master MP")?;
    // SAFETY: recv side of a fresh MP pair just minted into init's flat root
    // CSpace (depth 0); sole owner of this slot.
    let master_mp_recv = unsafe { OwnedCap::from_raw(master_mp_recv, 0) };
    // EventQueue for rsrcsrv's `EventLoop`. depth_bits=4 (16
    // entries) — rsrcsrv has only one armed source (the master MP),
    // so the queue carries at most one record at a time outside the
    // dispatcher's drain. A small ring saves untyped budget compared
    // to the depth=64 mmsrv service EQ uses for its per-client Watch
    // fan-in.
    let service_eq = retype_one(untyped, RetypeClass::EventQueue, 4, b"rsrcsrv service EQ")?;

    let mut child_slot = CHILD_RUNTIME_BASE_SLOT;

    let cap_table_va = build_and_map_cap_table(
        plumbing.vspace.borrow(),
        plumbing.cap_table_frame.borrow(),
        |builder: &mut CapTableBuilder| -> Result<(), i32> {
            place_system_caps(plumbing.cspace.borrow(), builder, &mut child_slot)?;

            // ROLE_INIT_CONTROL — mint a per-child copy of init's
            // master service-EP send (correct direction: send side, not
            // recv), badged `INIT_BADGE_FROM_RSRCSRV` so rsrcsrv's
            // server→init callbacks are authenticated as coming from rsrcsrv.
            deliver_cap_minted(
                plumbing.cspace.borrow(),
                builder,
                ROLE_INIT_CONTROL,
                state
                    .caps
                    .master_service_mp_send
                    .as_ref()
                    .map(OwnedCap::borrow),
                child_slot,
                INIT_BADGE_FROM_RSRCSRV as u64,
                0,
            )?;
            child_slot += 1;

            // ROLE_NAMESRV_CLIENT — query-only cap. Init publishes
            // core service endpoints before starting each child, so
            // rsrcsrv does not need publisher authority.
            deliver_cap_minted(
                plumbing.cspace.borrow(),
                builder,
                ROLE_NAMESRV_CLIENT,
                state
                    .caps
                    .namesrv_master_mp_send_raw
                    .as_ref()
                    .map(OwnedCap::borrow),
                child_slot,
                rsrcsrv_namesrv_badge(),
                0,
            )?;
            child_slot += 1;

            // ROLE_SERVICE_EP — rsrcsrv's master MP recv side.
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_SERVICE_EP,
                Some(master_mp_recv),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_RSRCSRV_SERVICE_EQ — the EventQueue rsrcsrv's
            // reactor blocks on. rsrcsrv arms its own master-MP
            // Watch on this queue at startup and dispatches the
            // resulting `EVENT_TYPE_STATE` records.
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_RSRCSRV_SERVICE_EQ,
                Some(service_eq),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_RSRCSRV_AUTHORITY_RAW — transfer the entire
            // rsrcsrv-quota untyped chunk to rsrcsrv. After this
            // move, init's slot is empty (state.untyped.rsrcsrv_quota
            // is consumed here via .take()).
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_RSRCSRV_AUTHORITY_RAW,
                state.untyped.rsrcsrv_quota.take(),
                child_slot,
                0,
            )?;
            child_slot += 1;

            Ok(())
        },
    )?;
    let _ = cap_table_va;
    let alloc_slot_base = child_slot;
    let load = load_core_image(state, &plumbing, untyped, b"/bin/rsrcsrv", alloc_slot_base)?;

    // Move plumbing identity caps into bundle for seed_self_caps and
    // configure_and_start_tcb; cap_table_frame/ipc_buffer_frame are
    // already used above (not in bundle).
    let bundle = ChildBundle {
        tcb: Some(plumbing.tcb),
        vspace: Some(plumbing.vspace),
        cspace: Some(plumbing.cspace),
        sched_context: Some(plumbing.sched_context),
        request_mp_send: None,
        request_mp_recv: None,
        signal_mp_send: None,
        signal_mp_recv: None,
        fault_mp_send: None,
        fault_mp_recv: None,
        mmsrv_request_mp_send: None,
        mmsrv_request_mp_recv: None,
        service_ep_send: None,
        service_ep_recv: None,
        adopt_recv: None,
        exec_control_recv: None,
        ldsrv_untyped: None,
    };
    seed_self_caps(&bundle)?;

    // Mint init's admin badge so rsrcsrv admin labels
    // (`RSRC_BATCH_ALLOC`, `RSRC_OWNER_EXITED`, quota setup) pass the
    // `require_admin(badge == 0xF...0001)` gate. Children obtain
    // per-client rsrcsrv sends through `NAMESRV_LOOKUP("rsrcsrv")`,
    // not from init. Publish the raw service send into namesrv while
    // it still carries Grant so namesrv can mint per-caller copies.
    state.caps.rsrcsrv_client_mp = Some(mint_from_raw_send(
        master_mp_send,
        RSRCSRV_ADMIN_BADGE,
        b"rsrcsrv admin send",
    )?);
    register_core_service_with_namesrv(
        state,
        core_namesrv_publish_badge(),
        b"rsrcsrv",
        master_mp_send,
    )?;
    // master_mp_send was published to namesrv via NAMESRV_REGISTER, whose IPC
    // cap transfer MOVED the send cap out of init's slot — the slot is now empty.
    // SAFETY: the publish moved the cap out, leaving this slot empty; it was
    // allocated for the master send and is reclaimed exactly once here.
    unsafe {
        trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(master_mp_send);
    }

    install_boot_core_proc_record(state, RSRCSRV_PID, b"rsrcsrv")?;
    configure_and_start_tcb(
        &bundle,
        CHILD_IPC_BUFFER_VA,
        load.entry_pc,
        load.child_sp,
        0,
        DEFAULT_CHILD_STACK_TOP,
        0,
        0,
        SchedParams::fair_default(),
    )?;

    // Retain the rsrcsrv main TCB + VSpace caps for Stage F retroactive
    // fault binding. Bundle is consumed here. Also retain the loader's
    // VmLayoutPlan so Stage F registers mmsrv with the actual image
    // windows instead of defaults.
    let ChildBundle { tcb, vspace, .. } = bundle;
    state.caps.rsrcsrv_main_tcb = tcb;
    state.caps.rsrcsrv_vspace = vspace;
    state.caps.rsrcsrv_layout = Some(load.plan.client_layout());

    wait_for_core_ready(state, INIT_BADGE_FROM_RSRCSRV as u64)?;
    Ok(())
}

/// Spawn `mmsrv`. Uses init_private for plumbing (rsrcsrv is up but
/// the boot pipeline gives mmsrv its own raw chunk transfer). The fault
/// dispatcher is a second TCB inside mmsrv's process; init pre-
/// retypes the FAULT_TCB / FAULT_SC / FAULT_STACK_FRAME and delivers
/// them through the cap-table along with the
/// `ROLE_MMSRV_FAULT_STACK_FRAME` (a single FRAME that init also
/// maps at `FAULT_STACK_VA` in mmsrv's child VSpace, see G).
pub fn spawn_mmsrv(state: &mut SupervisorState) -> Result<(), i32> {
    let untyped = state
        .untyped
        .init_private
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    let plumbing = retype_core_plumbing(untyped, b"mmsrv plumbing")?;

    let (master_mp_send, master_mp_recv) = retype_mp_pair_direct(untyped, b"mmsrv master MP")?;
    // SAFETY: recv side of a fresh MP pair just minted into init's flat root
    // CSpace (depth 0); sole owner of this slot.
    let master_mp_recv = unsafe { OwnedCap::from_raw(master_mp_recv, 0) };
    let service_eq = retype_one(untyped, RetypeClass::EventQueue, 6, b"mmsrv service EQ")?;
    let fault_eq = retype_one(untyped, RetypeClass::EventQueue, 8, b"mmsrv fault EQ")?;
    let (_fault_master_mp_send, fault_master_mp_recv) =
        retype_mp_pair_direct(untyped, b"mmsrv fault master MP")?;
    // SAFETY: recv side of a fresh fault MP pair just minted into init's flat
    // root CSpace (depth 0); sole owner of this slot.
    let fault_master_mp_recv = unsafe { OwnedCap::from_raw(fault_master_mp_recv, 0) };
    let fault_tcb = retype_one(untyped, RetypeClass::Tcb, 0, b"mmsrv fault TCB")?;
    let fault_sc = retype_one(untyped, RetypeClass::SchedContext, 0, b"mmsrv fault SC")?;
    // mmsrv's fault dispatcher TCB enters with `RSP = FAULT_STACK_VA
    // + 16 * PAGE_BYTES`; the entire 16-page region must be mapped
    // into mmsrv's child VSpace before the TCB starts or the first
    // push faults into a missing PTE. Allocate a 16-frame slab; init
    // maps all 16 pages contiguously below.
    const MMSRV_FAULT_STACK_PAGES: usize = 16;
    let fault_stack_frame_base = retype_slab(
        untyped,
        RetypeClass::Frame,
        12,
        MMSRV_FAULT_STACK_PAGES,
        b"mmsrv fault stack 16-page slab",
    )?;
    let fault_stack_frame = fault_stack_frame_base;

    // Pre-map the fault stack while init still owns the frame caps.
    // The cap-table later moves `fault_stack_frame` into mmsrv's
    // CSpace so the fault dispatcher can identify the backing slot.
    map_mmsrv_fault_stack(plumbing.vspace.borrow(), fault_stack_frame)?;

    let mut child_slot = CHILD_RUNTIME_BASE_SLOT;

    let cap_table_va = build_and_map_cap_table(
        plumbing.vspace.borrow(),
        plumbing.cap_table_frame.borrow(),
        |builder: &mut CapTableBuilder| -> Result<(), i32> {
            place_system_caps(plumbing.cspace.borrow(), builder, &mut child_slot)?;

            // ROLE_INIT_CONTROL — per-child mint of init's master
            // service-EP send (correct direction), badged
            // `INIT_BADGE_FROM_MMSRV` so mmsrv's server→init callbacks
            // (`INIT_REPORT_FAULT`, `INIT_CORE_READY`) are authenticated as
            // coming from mmsrv specifically.
            deliver_cap_minted(
                plumbing.cspace.borrow(),
                builder,
                ROLE_INIT_CONTROL,
                state
                    .caps
                    .master_service_mp_send
                    .as_ref()
                    .map(OwnedCap::borrow),
                child_slot,
                INIT_BADGE_FROM_MMSRV as u64,
                0,
            )?;
            child_slot += 1;

            // ROLE_NAMESRV_CLIENT — query-only cap. mmsrv resolves
            // rsrcsrv on first use through `NAMESRV_LOOKUP("rsrcsrv")`
            // rather than receiving a pre-minted cap here.
            deliver_cap_minted(
                plumbing.cspace.borrow(),
                builder,
                ROLE_NAMESRV_CLIENT,
                state
                    .caps
                    .namesrv_master_mp_send_raw
                    .as_ref()
                    .map(OwnedCap::borrow),
                child_slot,
                mmsrv_namesrv_badge(),
                0,
            )?;
            child_slot += 1;

            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_SERVICE_EP,
                Some(master_mp_recv),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_SERVICE_CLIENT_EP — GRANT-bearing send to mmsrv's own
            // master EP, retained by mmsrv to mint per-client control caps.
            // Delivered by a GRANT-preserving copy (not a mint, which strips
            // GRANT) so mmsrv can `cnode_mint` from it; init keeps the original
            // to mint the ROOT control cap and publish to namesrv below.
            deliver_cap(
                plumbing.cspace.borrow(),
                builder,
                ROLE_SERVICE_CLIENT_EP,
                Some(CapRef::flat(master_mp_send)),
                child_slot,
                0,
            )?;
            child_slot += 1;

            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_MMSRV_SERVICE_EQ,
                Some(service_eq),
                child_slot,
                0,
            )?;
            child_slot += 1;

            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_MMSRV_FAULT_EQ,
                Some(fault_eq),
                child_slot,
                0,
            )?;
            child_slot += 1;

            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_MMSRV_FAULT_MP_MASTER_RECV,
                Some(fault_master_mp_recv),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_MMSRV_FAULT_TCB / FAULT_SC: deliver via copy
            // (not move) so init retains its own cap. Stage F needs
            // the fault dispatcher TCB cap to run
            // `TCB_SET_FAULT_PIPE` on it after mmsrv is ready,
            // closing the fault-handling loop for mmsrv's second
            // TCB.
            deliver_cap(
                plumbing.cspace.borrow(),
                builder,
                ROLE_MMSRV_FAULT_TCB,
                Some(fault_tcb.borrow()),
                child_slot,
                0,
            )?;
            child_slot += 1;

            deliver_cap(
                plumbing.cspace.borrow(),
                builder,
                ROLE_MMSRV_FAULT_SC,
                Some(fault_sc.borrow()),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_MMSRV_FAULT_STACK_FRAME — single FRAME already
            // pre-mapped at `FAULT_STACK_VA` in mmsrv's VSpace.
            // mmsrv's `spawn_fault_dispatcher` reads this slot for
            // the FAULT TCB's stack-base mapping reference.
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_MMSRV_FAULT_STACK_FRAME,
                // SAFETY: fault_stack_frame is a freshly retyped FRAME in init's
                // flat root CSpace (depth 0); this temporary OwnedCap is consumed
                // by deliver_cap_moved (moved into the child), sole owner.
                Some(unsafe { OwnedCap::from_raw(fault_stack_frame, 0) }),
                child_slot,
                0,
            )?;
            child_slot += 1;

            // ROLE_MMSRV_AUTHORITY_RAW — mmsrv-pool untyped chunk.
            deliver_cap_moved(
                plumbing.cspace.borrow(),
                builder,
                ROLE_MMSRV_AUTHORITY_RAW,
                state.untyped.mmsrv_pool.take(),
                child_slot,
                0,
            )?;
            child_slot += 1;

            Ok(())
        },
    )?;
    let alloc_slot_base = child_slot;
    let load = load_core_image(state, &plumbing, untyped, b"/bin/mmsrv", alloc_slot_base)?;

    // Move plumbing identity caps into bundle for seed_self_caps and
    // configure_and_start_tcb.
    let bundle = ChildBundle {
        tcb: Some(plumbing.tcb),
        vspace: Some(plumbing.vspace),
        cspace: Some(plumbing.cspace),
        sched_context: Some(plumbing.sched_context),
        request_mp_send: None,
        request_mp_recv: None,
        signal_mp_send: None,
        signal_mp_recv: None,
        fault_mp_send: None,
        fault_mp_recv: None,
        mmsrv_request_mp_send: None,
        mmsrv_request_mp_recv: None,
        service_ep_send: None,
        service_ep_recv: None,
        adopt_recv: None,
        exec_control_recv: None,
        ldsrv_untyped: None,
    };
    seed_self_caps(&bundle)?;

    // Mint init's mmsrv per-server ROOT control cap from the master-EP
    // send. The ROOT cap authorizes only `MM_REGISTER_CLIENT`; every
    // per-client admin verb is driven on the control cap mmsrv mints and
    // returns at register, which mmsrv mints from the GRANT-bearing master
    // send delivered to it under `ROLE_SERVICE_CLIENT_EP`.
    // Children resolve their own per-client mmsrv send through
    // `NAMESRV_LOOKUP("mmsrv")` + `MM_BIND_CLIENT_SELF`, so init
    // publishes the raw master send and then releases its local slot.
    state.caps.mmsrv_root_control_cap = Some(mint_from_raw_send(
        master_mp_send,
        trona_protocol::control::encode_root(),
        b"mmsrv root control cap",
    )?);
    register_core_service_with_namesrv(
        state,
        core_namesrv_publish_badge(),
        b"mmsrv",
        master_mp_send,
    )?;
    // SAFETY: the publish above moved the send cap out via the NAMESRV_REGISTER
    // IPC transfer, leaving this slot empty; it was allocated for the master send
    // and is reclaimed exactly once here.
    unsafe {
        trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(master_mp_send);
    }
    // Retain fault TCB for Stage F; it was copied (not moved) into the
    // child, so init still holds it to run TCB_SET_FAULT_PIPE later.
    state.caps.mmsrv_fault_dispatcher_tcb = Some(fault_tcb);
    // fault_sc was copied into the child; init's copy is no longer needed.
    drop(fault_sc);

    install_boot_core_proc_record(state, MMSRV_PID, b"mmsrv")?;
    configure_and_start_tcb(
        &bundle,
        CHILD_IPC_BUFFER_VA,
        load.entry_pc,
        load.child_sp,
        0,
        DEFAULT_CHILD_STACK_TOP,
        0,
        0,
        SchedParams::fair_default(),
    )?;

    let _ = cap_table_va;

    // Retain the mmsrv main TCB + VSpace caps. Bundle is consumed here.
    let ChildBundle { tcb, vspace, .. } = bundle;
    state.caps.mmsrv_main_tcb = tcb;
    state.caps.mmsrv_vspace = vspace;
    state.caps.mmsrv_layout = Some(load.plan.client_layout());

    wait_for_core_ready(state, INIT_BADGE_FROM_MMSRV as u64)?;

    // Register init as mmsrv's first client so init can issue
    // self-only `MM_MMAP` calls during Stage G image staging.
    let init_client_id = state.alloc_client_id();
    state.caps.init_client_id = init_client_id;

    // Allocate an init self-tier MP pair via rsrcsrv. mmsrv arms a
    // Watch on the recv side keyed by client_id; init's
    // `mmsrv_self_mp` is what `mm_ipc::self_call` writes through for
    // `MM_MMAP_self`, `MM_MUNMAP_self`, etc. used by Stage G image
    // staging. The send cap does not need a badge: mmsrv resolves
    // self-tier identity from the Watch cookie armed on the recv side.
    let self_mp_recv_base = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
        2,
        b"init mmsrv self-tier MP pair",
    );
    if self_mp_recv_base == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let (self_mp_send, self_mp_recv) = crate::supervisor::rsrc_ipc::rsrc_alloc_mp_pair(
        state
            .caps
            .rsrcsrv_client_mp
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr(),
        self_mp_recv_base,
        ipc_ctx,
    )?;
    // SAFETY: rsrc_alloc_mp_pair just filled these receive-window slots.
    // adopt_received preserves the correct invoke depth after CSpace expansion.
    let self_mp_send = unsafe { OwnedCap::adopt_received(self_mp_send) };
    let self_mp_recv = unsafe { OwnedCap::adopt_received(self_mp_recv) };

    // init's own layout is derived from its initrd-resident image the
    // same way service-spawn and exec layouts are. The kernel loaded
    // `/bin/init` from the initrd at the address init is now running
    // from, so the same layout helper that drives service spawn covers
    // init's self-registration.
    let mut init_def = ServiceDef::empty_named(NameStr::from_bytes(b"init"));
    init_def.binary = BinaryStr::from_bytes(b"/bin/init");
    let init_layout = crate::supervisor::lifecycle::compute_spawn_layout(
        state,
        &init_def,
        init_def.stack_layout_spec(),
    )?;
    state.caps.init_layout = Some(init_layout);
    let init_control = crate::supervisor::mm_ipc::mm_register_client(
        state,
        init_client_id,
        1,
        CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64),
        Some(self_mp_recv),
        Some(self_mp_send.borrow()),
        init_layout,
    )?;
    state.caps.mmsrv_self_control_cap = Some(init_control);
    state.caps.mmsrv_self_mp = Some(self_mp_send);

    // Fence init's directly-mapped arena windows (slab backing, cookie
    // segment, loader scratch) so mmsrv's gap allocator / FIXED-mmap path
    // never hands init a VA colliding with them. They live in init's own
    // VSpace, outside the mmsrv-managed mmap range.
    let arena = trona_server::slab::ReservationKind::Arena.as_u8() as u64;
    let exclusion = trona_server::slab::ReservationKind::Exclusion.as_u8() as u64;
    crate::supervisor::mm_ipc::mm_reserve_range(
        state,
        trona_runtime::spawn::layout::INIT_SLAB_SCRATCH_BASE,
        trona_runtime::spawn::layout::INIT_SLAB_SCRATCH_LEN,
        arena,
    )?;
    crate::supervisor::mm_ipc::mm_reserve_range(
        state,
        trona_runtime::spawn::layout::INIT_SEGMENT_SCRATCH_BASE,
        trona_runtime::spawn::layout::INIT_SEGMENT_SCRATCH_LEN,
        arena,
    )?;
    crate::supervisor::mm_ipc::mm_reserve_range(
        state,
        crate::internal_slots::SCRATCH_FRAME_VA,
        uapi::KERNITE_PAGE_BYTES as u64,
        exclusion,
    )?;
    Ok(())
}

/// Stage F — for every TCB that came up before mmsrv was registering
/// fault pipes, allocate a fault MP pair via rsrcsrv, register the
/// recv side with mmsrv, and bind the send side on the target TCB.
///
/// Pre-mmsrv TCBs:
/// 1. init main TCB.
/// 2. namesrv main TCB.
/// 3. rsrcsrv main TCB.
/// 4. mmsrv main TCB.
/// 5. mmsrv fault dispatcher TCB.
///
/// The userland does not run lifecycle worker TCBs in init
/// (the owner-loop reactor handles every event serially), so
/// the 6th TCB the design originally enumerated is absent — its
/// slot is left for the future when init may grow per-thread
/// service shards.
///
/// For namesrv / rsrcsrv / mmsrv (whose main TCBs were spawned
/// before mmsrv was ready), init drives `MM_REGISTER_CLIENT` on
/// their behalf inside this routine so mmsrv has a `client_id` it
/// can key the fault-MP cookie against. Each server's substrate
/// startup path picks this client_id back up via the cap-table at
/// runtime.
/// Register core services as mmsrv clients so their self-tier
/// `MM_*` calls land with a known cookie, but **do not** wire fault
/// pipes for the core service main TCBs. Their `fault_pipe` stays at
/// the kernel-side NULL placeholder; a self-fault inside init,
/// namesrv, rsrcsrv, mmsrv main, or mmsrv's fault dispatcher escalates
/// to `begin_destroy` and halts the system. Recovery is intentionally
/// absent because internal-table corruption (region table,
/// NameRegistry, ObjectTable) cascades into every client's caps —
/// halting is safer than restarting these into an inconsistent world.
/// Stage F's retroactive bind step retains the function so user-
/// visible TCBs spawned later in Stage G can hook in here.
pub fn stage_f_retroactive_fault_bind(state: &mut SupervisorState) -> Result<(), i32> {
    // Each core service's layout is the one the direct-loader produced at
    // its spawn stage. Capturing `state.caps.<svc>_layout` there means
    // Stage F registers mmsrv with the actual image windows, not with
    // a parallel set of constants that could drift from the loader's
    // plan. A missing layout is a programming error — every spawn stage
    // sets one — and surfaces as a register failure rather than silently
    // widening the layout.
    let namesrv_layout = state
        .caps
        .namesrv_layout
        .ok_or_else(|| uapi::KERNITE_ERR_INVALID_OPERATION as i32)?;
    let rsrcsrv_layout = state
        .caps
        .rsrcsrv_layout
        .ok_or_else(|| uapi::KERNITE_ERR_INVALID_OPERATION as i32)?;
    let mmsrv_layout = state
        .caps
        .mmsrv_layout
        .ok_or_else(|| uapi::KERNITE_ERR_INVALID_OPERATION as i32)?;

    if state.caps.namesrv_main_tcb.is_some() && state.caps.namesrv_client_id == 0 {
        let client_id = state.alloc_client_id();
        if !unsafe {
            state
                .procs
                .set_client_id(NAMESRV_PID, client_id, &mut state.self_vm)
        } {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
        }
        state.caps.namesrv_client_id = client_id;
        let namesrv_control = crate::supervisor::mm_ipc::mm_register_client(
            state,
            client_id,
            NAMESRV_PID,
            state
                .caps
                .namesrv_vspace
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default(),
            None,
            None,
            namesrv_layout,
        )?;
        state.caps.namesrv_mmsrv_control_cap = Some(namesrv_control);
    }

    if state.caps.rsrcsrv_main_tcb.is_some() && state.caps.rsrcsrv_client_id == 0 {
        let client_id = state.alloc_client_id();
        if !unsafe {
            state
                .procs
                .set_client_id(RSRCSRV_PID, client_id, &mut state.self_vm)
        } {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
        }
        state.caps.rsrcsrv_client_id = client_id;
        let rsrcsrv_control = crate::supervisor::mm_ipc::mm_register_client(
            state,
            client_id,
            RSRCSRV_PID,
            state
                .caps
                .rsrcsrv_vspace
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default(),
            None,
            None,
            rsrcsrv_layout,
        )?;
        state.caps.rsrcsrv_mmsrv_control_cap = Some(rsrcsrv_control);
    }

    if state.caps.mmsrv_main_tcb.is_some() && state.caps.mmsrv_client_id == 0 {
        let client_id = state.alloc_client_id();
        if !unsafe {
            state
                .procs
                .set_client_id(MMSRV_PID, client_id, &mut state.self_vm)
        } {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
        }
        state.caps.mmsrv_client_id = client_id;
        // mmsrv registers as a client of itself only so its own libc
        // self-tier `MM_*` calls carry a known cookie. init never drives an
        // admin verb (deregister / fault-pipe) on mmsrv's own slot — mmsrv's
        // main TCB has no fault pipe and never exits — so the returned control
        // cap has no `mmsrv_control_addr` arm and is dropped here.
        let _ = crate::supervisor::mm_ipc::mm_register_client(
            state,
            client_id,
            MMSRV_PID,
            state
                .caps
                .mmsrv_vspace
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default(),
            None,
            None,
            mmsrv_layout,
        )?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

struct CorePlumbing {
    tcb: OwnedCap,
    vspace: OwnedCap,
    cspace: OwnedCap,
    sched_context: OwnedCap,
    ipc_buffer_frame: OwnedCap,
    cap_table_frame: OwnedCap,
    /// Stack frame slot range base in init's CSpace (raw slot — slab
    /// of consecutive frames, freed individually by `load_core_image`).
    stack_frame_base: u64,
}

/// Retype the per-TCB plumbing (TCB / VSpace / CNode (12-bit) / SC /
/// IPC frame / cap-table frame / stack frames) from `untyped` into a
/// freshly allocated consecutive receive window.
fn retype_core_plumbing(untyped: CapRef, label: &[u8]) -> Result<CorePlumbing, i32> {
    let total = (4 + 1 + 1 + CORE_STACK_PAGES) as u64;
    let base = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(total, label);
    if base == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let tcb_slot = base;
    let vspace_slot = base + 1;
    let cspace_slot = base + 2;
    let sc_slot = base + 3;
    let ipc_frame_slot = base + 4;
    let cap_frame_slot = base + 5;
    let stack_frame_base = base + 6;

    let r = invoke::untyped_retype(untyped, RetypeClass::Tcb.obj_type(), 0, tcb_slot);
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(untyped, RetypeClass::VSpace.obj_type(), 0, vspace_slot);
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(untyped, RetypeClass::CNode.obj_type(), 12, cspace_slot);
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(untyped, RetypeClass::SchedContext.obj_type(), 0, sc_slot);
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(untyped, KERNITE_OBJ_FRAME as u64, 12, ipc_frame_slot);
    if r != 0 {
        return Err(r);
    }
    let r = invoke::untyped_retype(untyped, KERNITE_OBJ_FRAME as u64, 12, cap_frame_slot);
    if r != 0 {
        return Err(r);
    }
    for i in 0..CORE_STACK_PAGES as u64 {
        let r = invoke::untyped_retype(untyped, KERNITE_OBJ_FRAME as u64, 12, stack_frame_base + i);
        if r != 0 {
            return Err(r);
        }
    }

    // SAFETY: every slot below was just retyped into init's flat root CSpace
    // (depth 0) by this function (errs checked), each holding its fresh cap and
    // owned solely by the CorePlumbing field adopting it.
    Ok(unsafe {
        CorePlumbing {
            tcb: OwnedCap::from_raw(tcb_slot, 0),
            vspace: OwnedCap::from_raw(vspace_slot, 0),
            cspace: OwnedCap::from_raw(cspace_slot, 0),
            sched_context: OwnedCap::from_raw(sc_slot, 0),
            ipc_buffer_frame: OwnedCap::from_raw(ipc_frame_slot, 0),
            cap_table_frame: OwnedCap::from_raw(cap_frame_slot, 0),
            stack_frame_base,
        }
    })
}

/// Retype a single fixed-size kernel object into a freshly allocated
/// init-CSpace slot. Returns the slot wrapped in `OwnedCap` so the
/// caller can move it into the child's CNode via `deliver_cap_moved`.
fn retype_one(
    untyped: CapRef,
    class: RetypeClass,
    size_bits: u64,
    label: &[u8],
) -> Result<OwnedCap, i32> {
    let slot = trona_runtime::core::slot_alloc::slot_alloc_or_idle(label);
    if slot == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let r = invoke::untyped_retype(untyped, class.obj_type(), size_bits, slot);
    if r != 0 {
        return Err(r);
    }
    // SAFETY: `slot` was just allocated (slot_alloc_or_idle) and retyped
    // (untyped_retype, err checked) in init's flat root CSpace (depth 0); sole owner.
    Ok(unsafe { OwnedCap::from_raw(slot, 0) })
}

/// Retype a contiguous slab of `count` fixed-size objects of `class`
/// into a freshly allocated consecutive init-CSpace range. `size_bits`
/// is forwarded to the kernel `untyped_retype` invoke (FRAME uses
/// `12` for 4 KiB pages; Watch / Timer / etc. accept `0`). Returns
/// the base slot as a raw `u64` because the slab is transferred en
/// masse via `place_slab_moved` which takes the raw base index.
fn retype_slab(
    untyped: CapRef,
    class: RetypeClass,
    size_bits: u64,
    count: usize,
    label: &[u8],
) -> Result<u64, i32> {
    let base = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(count as u64, label);
    if base == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    for i in 0..count as u64 {
        let r = invoke::untyped_retype(untyped, class.obj_type(), size_bits, base + i);
        if r != 0 {
            return Err(r);
        }
    }
    Ok(base)
}

/// Retype a fresh MP pair from `untyped`. Wraps
/// [`DirectUntypedAllocator::alloc_mp_pair`] so each spawn-stage call
/// site instantiates the allocator at exactly the point it has the
/// untyped seed in scope. Returns `(send_slot, recv_slot)` as raw
/// `u64` because the callers either move them into child CNodes
/// (via `deliver_cap_moved` with `OwnedCap::from_raw`) or retain
/// them for IPC (stored in `state.caps` as `OwnedCap::from_raw`).
fn retype_mp_pair_direct(untyped: CapRef, label: &[u8]) -> Result<(u64, u64), i32> {
    let core_temp = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"mp_core (transient)");
    let send_recv = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(2, label);
    if core_temp == 0 || send_recv == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let mut allocator = crate::supervisor::spawn::alloc::DirectUntypedAllocator {
        untyped,
        mp_core_temp_slot: core_temp,
    };
    use crate::supervisor::spawn::alloc::SpawnAllocator;
    let result = allocator.alloc_mp_pair(send_recv);
    // `alloc_mp_pair` cnode_deletes the transient core cap regardless of bind
    // outcome, so the slot is empty by here.
    // SAFETY: alloc_mp_pair deleted the transient core cap above, leaving this
    // slot empty; it was allocated for the transient core and is reclaimed once.
    unsafe {
        trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(core_temp);
    }
    result
}

/// Map the image into the child VSpace, compose the SysV stack on
/// the topmost stack frame, and return the entry PC + child SP.
/// `alloc_slot_base` is the cap-table high-water mark the child
/// runtime must use as its first dynamically allocatable CSpace slot.
fn load_core_image(
    state: &SupervisorState,
    plumbing: &CorePlumbing,
    untyped: CapRef,
    binary_name: &[u8],
    alloc_slot_base: u64,
) -> Result<loader::LoadedImage, i32> {
    let image =
        loader::cpio::find_file(state, binary_name).ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;

    // Map IPC buffer frame into the child at CHILD_IPC_BUFFER_VA.
    let r = invoke::vspace_map(
        plumbing.vspace.borrow(),
        plumbing.ipc_buffer_frame.borrow(),
        CHILD_IPC_BUFFER_VA,
        PAGE_FLAGS_RW_USER,
    );
    if r != 0 {
        return Err(r);
    }

    // Map stack frames into the child at the top of the stack
    // region. The top page (the one immediately below
    // DEFAULT_CHILD_STACK_TOP) hosts the SysV initial stack +
    // startup block; the lower pages are zero-initialized growth
    // headroom.
    for i in 0..(CORE_STACK_PAGES - 1) as u64 {
        let frame_slot = plumbing.stack_frame_base + i;
        let va = DEFAULT_CHILD_STACK_TOP - ((CORE_STACK_PAGES as u64 - i) * KERNITE_PAGE_BYTES);
        let r = invoke::vspace_map(
            plumbing.vspace.borrow(),
            CapRef::flat(frame_slot),
            va,
            PAGE_FLAGS_RW_USER,
        );
        if r != 0 {
            return Err(r);
        }
    }
    // The topmost stack frame is the one stack::compose maps after
    // populating it with argc/argv/envp/auxv + startup block.
    let stack_top_frame = plumbing.stack_frame_base + (CORE_STACK_PAGES - 1) as u64;

    // The cap-table is mapped separately by the caller; here we only stage the
    // image bytes + SysV stack and publish the resulting allocator floor in the
    // startup CSpace layout. The image maps run-by-run from borrowed-frames code
    // MemoryObjects conferred R-X, so no raw executable frame is ever retyped.
    let argv: [&[u8]; 1] = [binary_name];
    let envp: [&[u8]; 0] = [];
    let cap_table_va = trona_runtime::spawn::layout::CHILD_CAP_TABLE_VA;
    let stack_spec = StackLayoutSpec {
        reserve_pages: CORE_STACK_PAGES as u32,
        prefault_pages: CORE_STACK_PAGES as u16,
        guard_pages: 0,
    };
    loader::load_image_borrowed(
        state,
        plumbing.vspace.borrow().addr(),
        untyped.addr(),
        binary_name,
        image,
        &argv,
        &envp,
        stack_top_frame,
        DEFAULT_CHILD_STACK_TOP,
        stack_spec,
        cap_table_va,
        CHILD_IPC_BUFFER_VA,
        alloc_slot_base,
    )
}

/// Pre-map the 16-frame fault-stack slab at mmsrv's
/// `FAULT_STACK_VA`. mmsrv's `spawn_fault_dispatcher` configures the
/// fault dispatcher TCB with `RSP = FAULT_STACK_VA + 16 * PAGE_BYTES`
/// and trusts that init has set up the mapping; the kernel-side TCB
/// configure path uses the resulting RSP without re-validating the
/// VMA. The `FAULT_STACK_VA` / `FAULT_STACK_PAGES` constants here
/// match mmsrv's `main.rs`.
fn map_mmsrv_fault_stack(child_vspace: CapRef, frame_base: u64) -> Result<(), i32> {
    use trona_runtime::spawn::layout::FAULT_STACK_VA;
    const FAULT_STACK_PAGES: u64 = 16;
    for i in 0..FAULT_STACK_PAGES {
        let frame_slot = frame_base + i;
        let va = FAULT_STACK_VA + i * KERNITE_PAGE_BYTES;
        let r = invoke::vspace_map(
            child_vspace,
            CapRef::flat(frame_slot),
            va,
            PAGE_FLAGS_RW_USER,
        );
        if r != 0 {
            return Err(r);
        }
    }
    Ok(())
}

/// Block until the just-started core service sends `INIT_CORE_READY`
/// through `ROLE_INIT_CONTROL`. This uses the same master service MP
/// and control-EQ Watch as init's long-lived owner reactor; each fire is
/// one-shot, so a successful wait re-arms the Watch for the next core
/// service or for runtime owner-loop traffic.
/// namesrv REGISTER events may interleave while rsrcsrv/mmsrv boot; those
/// are drained, recorded in unit_mgr, and re-armed without dispatching
/// dependent services before Stage H.
fn wait_for_core_ready(state: &mut SupervisorState, expected_badge: u64) -> Result<(), i32> {
    loop {
        let r = invoke::eq_wait(
            state
                .caps
                .control_eq
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default(),
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if r != 0 {
            return Err(r);
        }

        let ctx = trona_runtime::current_ipc_ctx();
        if ctx.is_null() {
            return Err(KERNITE_ERR_INVALID_OPERATION as i32);
        }
        let ipc_buf = unsafe { (*ctx).ipc_buffer };
        if ipc_buf.is_null() {
            return Err(KERNITE_ERR_INVALID_OPERATION as i32);
        }
        let record = unsafe { trona_kernel::ipc_buffer::read_event_record(ipc_buf as *const _) };
        if record.kind != KERNITE_EVENT_TYPE_STATE {
            return Err(KERNITE_ERR_INVALID_OPERATION as i32);
        }
        if record.cookie != state.caps.master_service_mp_watch_cookie {
            drain_boot_control_event(state, ctx, record)?;
            continue;
        }

        let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
        let mut badge: u64 = 0;
        crate::supervisor::recv_window::arm(ctx);
        let r = unsafe {
            trona_kernel::ipc::mp_read_ctx(
                ctx,
                state
                    .caps
                    .master_service_mp_recv
                    .as_ref()
                    .map(OwnedCap::borrow)
                    .unwrap_or_default()
                    .addr(),
                &raw mut msg,
                &raw mut badge,
            )
        };
        if r != 0 {
            return Err(r);
        }
        if msg.label != trona_protocol::init::INIT_CORE_READY || badge != expected_badge {
            return Err(KERNITE_ERR_INVALID_OPERATION as i32);
        }
        return rearm_init_control_watch(state);
    }
}

fn rearm_init_control_watch(state: &SupervisorState) -> Result<(), i32> {
    let r = invoke::watch_register(
        CapRef::flat(SLOT_CONTROL_EQ_WATCH_SERVICE_MP),
        state
            .caps
            .master_service_mp_recv
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default(),
        state
            .caps
            .control_eq
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default(),
        KERNITE_STATE_READABLE,
        state.caps.master_service_mp_watch_cookie,
    );
    if r == 0 { Ok(()) } else { Err(r) }
}

fn drain_boot_control_event(
    state: &mut SupervisorState,
    ctx: *mut trona_kernel::core_types::IpcContext,
    record: uapi::kernite_event_record,
) -> Result<(), i32> {
    let Some(entry) = state.cookie_table.lookup(record.cookie) else {
        return Err(KERNITE_ERR_INVALID_OPERATION as i32);
    };
    let target = entry.target;
    let mp_recv = entry.mp_recv;
    match target {
        InitTarget::NamesrvRegisterEvent => {
            let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
            let mut badge: u64 = 0;
            crate::supervisor::recv_window::arm(ctx);
            let r = unsafe {
                trona_kernel::ipc::mp_read_ctx(ctx, mp_recv, &raw mut msg, &raw mut badge)
            };
            if r != 0 {
                return Err(r);
            }
            let _ = badge;
            note_namesrv_register_event(state, &msg);
            rearm_unit_mgr_namesrv_watch(state)
        }
        _ => Err(KERNITE_ERR_INVALID_OPERATION as i32),
    }
}

fn note_namesrv_register_event(
    state: &mut SupervisorState,
    msg: &trona_kernel::core_types::TronaMsg,
) {
    if msg.label != trona_protocol::namesrv::NAMESRV_REGISTER_EVENT {
        return;
    }
    let name_len = (msg.regs[0] as usize).min(64);
    let mut prefix = [0u8; 64];
    let mut written = 0usize;
    let mut word_idx = 1usize;
    while written < name_len && word_idx < 32 {
        let bytes = msg.regs[word_idx].to_le_bytes();
        for &b in bytes.iter() {
            if written == name_len {
                break;
            }
            prefix[written] = b;
            written += 1;
        }
        word_idx += 1;
    }
    state
        .unit_graph
        .on_namesrv_register(&state.manifest, &prefix[..written]);
}

fn rearm_unit_mgr_namesrv_watch(state: &SupervisorState) -> Result<(), i32> {
    let r = invoke::watch_register(
        state
            .caps
            .unit_mgr_namesrv_event_watch
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default(),
        state
            .caps
            .unit_mgr_namesrv_event_mp_recv
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default(),
        state
            .caps
            .control_eq
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default(),
        KERNITE_STATE_READABLE,
        state.caps.namesrv_register_event_watch_cookie,
    );
    if r == 0 { Ok(()) } else { Err(r) }
}

/// Badges minted on namesrv's master MP. The badge bit layout is
/// documented in `userland/core/namesrv/src/authz.rs`:
/// bits 63-62 = class, bits 47-32 = policy_id, bits 31-0 = tcb_id.
fn rsrcsrv_namesrv_badge() -> u64 {
    0
}

fn mmsrv_namesrv_badge() -> u64 {
    0
}

fn core_namesrv_publish_badge() -> u64 {
    // class=publisher (0b01), policy_id 0 is boot-only and granted by
    // init for core service endpoint registration.
    0b01u64 << 62
}

/// Admin badges init mints onto each core service's master MP send.
/// Each server's dispatcher gates admin-tier labels on the badge
/// matching these constants — without the mint, init's local pair
/// send carries badge 0 and every admin label is rejected.
const NAMESRV_ADMIN_BADGE: u64 = 0b11u64 << 62;
const RSRCSRV_ADMIN_BADGE: u64 = 0xF000_0000_0000_0001;

fn ensure_core_publish_policy(state: &SupervisorState) -> Result<(), i32> {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() {
        return Err(KERNITE_ERR_INVALID_OPERATION as i32);
    }
    let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
    msg.label = trona_protocol::namesrv::NAMESRV_GRANT_PUBLISHER;
    msg.length = 2;
    msg.regs[0] = 0;
    msg.regs[1] = 0;
    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
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
    if err != 0 {
        return Err(err);
    }
    if reply.label == trona_protocol::common::TRONA_OK
        || reply.label == uapi::KERNITE_ERR_ALREADY_EXISTS as u64
    {
        Ok(())
    } else {
        Err(reply.label as i32)
    }
}

fn register_core_service_with_namesrv(
    state: &mut SupervisorState,
    publisher_badge: u64,
    name: &[u8],
    service_send_slot: u64,
) -> Result<(), i32> {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    ensure_core_publish_policy(state)?;
    let publish_ep = mint_from_raw_send(
        state
            .caps
            .namesrv_master_mp_send_raw
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr(),
        publisher_badge,
        b"core service namesrv publish",
    )?;
    let result = (|| -> Result<(), i32> {
        let ctx = trona_runtime::current_ipc_ctx();
        if ctx.is_null() {
            return Err(KERNITE_ERR_INVALID_OPERATION as i32);
        }
        let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
        msg.label = trona_protocol::namesrv::NAMESRV_REGISTER;
        msg.regs[0] = name.len() as u64;
        let mut written = 0usize;
        let mut word_idx = 1usize;
        while written < name.len() && word_idx < REGISTER_FLAGS_REG {
            let mut word = [0u8; 8];
            let n = (name.len() - written).min(word.len());
            word[..n].copy_from_slice(&name[written..written + n]);
            msg.regs[word_idx] = u64::from_le_bytes(word);
            written += n;
            word_idx += 1;
        }
        msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
        msg.length = (REGISTER_FLAGS_REG + 1) as u64;

        let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
        unsafe {
            trona_kernel::ipc::clear_send_caps_ctx(ctx);
            trona_kernel::ipc::set_send_cap_ctx(ctx, 0, service_send_slot);
        }
        let err = unsafe {
            trona_kernel::ipc::mp_call_ctx(
                ctx,
                publish_ep.borrow().addr(),
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            )
        };
        if err != 0 {
            return Err(err);
        }
        if reply.label != trona_protocol::common::TRONA_OK {
            return Err(reply.label as i32);
        }
        Ok(())
    })();

    // publish_ep is OwnedCap — Drop handles delete_and_free.
    drop(publish_ep);
    result
}

/// Mint a badged copy of an unminted MP send cap into a fresh
/// init-CSpace slot. The original (unminted) `send` is preserved —
/// `cnode_mint` strips Grant from the resulting cap, so callers that
/// need to mint additional badges (per-child non-admin sends) MUST
/// always pass the unminted source here, never a previously-minted
/// copy.
pub(crate) fn mint_from_raw_send(send: u64, badge: u64, label: &[u8]) -> Result<OwnedCap, i32> {
    let self_cspace = CapRef::flat(crate::internal_slots::SLOT_SELF_CSPACE);
    let dest = trona_runtime::core::slot_alloc::slot_alloc_or_idle(label);
    if dest == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let r = invoke::cnode_mint(self_cspace, send, self_cspace, dest, badge);
    if r != 0 {
        return Err(r);
    }
    // SAFETY: `dest` was just allocated (slot_alloc_or_idle) and cnode_mint'd
    // (err checked) in init's flat root CSpace (depth 0); sole owner.
    Ok(unsafe { OwnedCap::from_raw(dest, 0) })
}

// ============================================================================
// Self-expand wiring + quota pin.
//
// Without these, init's slot allocator hands out slots from the initial
// envelope (a few hundred) and `fatal_slot_alloc` hangs the owner thread
// once `fork/exec` stress overruns it. Patch 2a wires init's allocator
// for self-expansion against rsrcsrv immediately after `spawn_rsrcsrv`
// returns, and pins init's quota to `u64::MAX` so a later RSRC_SET_QUOTA
// from another admin caller cannot quietly close init's cap.
// ============================================================================

/// Init's client_id once mmsrv hands it out — for self-expand authority
/// we use the rsrcsrv admin badge's client_id (low 32 bits of
/// `RSRCSRV_ADMIN_BADGE = 0xF000_0000_0000_0001` = 1). rsrcsrv keys
/// its OwnerTable on `client_id` parsed from the badge; init's
/// admin-badged send carries exactly that key.
const INIT_OWNER_ID: u32 = 1;

/// `RSRC_TYPE_AGGREGATE` (from `rsrcsrv/src/labels.rs`) — when passed
/// as the class/aggregate selector on `LABEL_SET_QUOTA`, sets the
/// per-owner byte cap rather than a per-class count.
const RSRC_TYPE_AGGREGATE: u64 = 0xFF;

/// `LABEL_SET_QUOTA = 0x304` — pin init's aggregate byte cap to
/// `u64::MAX`. We pass the badge raw (with admin class bits intact)
/// because rsrcsrv's `client_id_of` strips them; `RSRCSRV_ADMIN_BADGE`
/// works both as the mint source and as the caller's identity.
fn rsrcsrv_set_quota_unbounded(rsrcsrv_mp: u64) -> Result<(), i32> {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() {
        return Err(uapi::KERNITE_ERR_INVALID_OPERATION as i32);
    }
    let mut req = trona_kernel::core_types::TronaMsg::zeroed();
    req.label = 0x304; // LABEL_SET_QUOTA
    // regs[0] target_id: low 32 bits = client_id (admin class stripped by
    // rsrcsrv's `client_id_of`). Encode the badge directly — rsrcsrv masks
    // off the class bits, so passing the admin badge works.
    req.regs[0] = RSRCSRV_ADMIN_BADGE;
    req.regs[1] = RSRC_TYPE_AGGREGATE;
    req.regs[2] = u64::MAX;
    req.length = 3;
    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            rsrcsrv_mp,
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(err as i32);
    }
    if reply.label != trona_protocol::common::TRONA_OK {
        return Err(reply.label as i32);
    }
    Ok(())
}

/// Wire init's slot allocator for self-expansion via rsrcsrv and pin
/// init's quota. Run immediately after `spawn_rsrcsrv` returns — by
/// then `state.caps.rsrcsrv_client_mp` is the admin-badged send. The
/// first `slot_alloc` that exhausts the startup envelope triggers
/// `try_self_expand_locked`, which issues `RSRC_ALLOC(OBJ_CNODE)`
/// against this endpoint.
pub fn wire_init_self_expand(state: &SupervisorState) -> Result<(), i32> {
    let rsrcsrv_ep = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    if rsrcsrv_ep == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] wire_init_self_expand: rsrcsrv_client_mp == 0\n");
        });
        loop {
            trona_kernel::syscall::yield_now();
        }
    }
    // Pin the byte cap BEFORE wiring self-expand so the very first
    // RSRC_ALLOC already sees `bytes_max = u64::MAX`. Without this the
    // first RSRC_ALLOC creates an OwnerTable entry with `bytes_max = 0`
    // (no cap, default), and any later RSRC_SET_QUOTA call from another
    // admin path could close the cap mid-test.
    rsrcsrv_set_quota_unbounded(rsrcsrv_ep)?;
    // SAFETY: SLOT_SELF_EXPAND_TEMP was reserved via
    // `install_skip_range` in `boot::stage_a_read_kernel_handoff`; sole
    // owner across init's lifetime, dedicated to the `cnode_move`
    // destination of every expansion install.
    unsafe {
        trona_runtime::core::slot_alloc::reserve_expand_temp_slot(
            crate::internal_slots::SLOT_SELF_EXPAND_TEMP,
        );
        trona_runtime::core::slot_alloc::enable_self_expand(rsrcsrv_ep, INIT_OWNER_ID as u64);
    }
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[INIT] self-expand wired: ep=");
        _lb.hex(rsrcsrv_ep);
        _lb.str(b" temp=");
        _lb.hex(crate::internal_slots::SLOT_SELF_EXPAND_TEMP);
        _lb.str(b" quota=unbounded\n");
    });
    Ok(())
}
