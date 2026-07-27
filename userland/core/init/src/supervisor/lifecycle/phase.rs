// SPDX-License-Identifier: GPL-2.0-only
//
//! `realize_process`'s phase helpers. Each phase is a single
//! concern; the facade in `lifecycle.rs` composes them per
//! `SpawnKind` / `AddressSpacePlan`.
//!
//! 1. [`phase_proc_record`] — proc-table allocation / lookup.
//! 2. [`phase_alloc_bundle`] — kernel-object retype via rsrcsrv.
//! 3. [`phase_register_client`] — client registration with mmsrv.
//! 4. [`phase_register_vfs`] — client registration with VFS.
//! 5. [`phase_address_space`] — fresh image / fork-cow / exec-replace
//!    branching for the child VSpace (fork also drives the VFS FD clone).
//! 6. [`phase_fault_wire`] — per-TCB fault MP wiring.
//! 7. [`phase_stage`] — image staging via byte-signature loader
//!    dispatch + `loader::cap_table::populate_via_mmsrv`. `Exec`
//!    delegates to `lifecycle::exec::exec_in_place`.
//! 8. [`phase_start`] — TCB bring-up (SET_SPACE / SET_STACK_BOUNDS /
//!    TCB_CONFIGURE / SC_CONFIGURE / SC_BIND / START).
//! 9. [`phase_install_proc_record`] / [`phase_publish_lifecycle`] —
//!    proc-record install before start, lifecycle stream publish after
//!    start.

use crate::supervisor::SupervisorState;
use crate::supervisor::lifecycle_stream::{EVT_EXEC, EVT_SPAWN};
use crate::supervisor::loader;
use crate::supervisor::mm_ipc::{mm_fork_vspace, mm_register_client};
use crate::supervisor::namesrv_ipc::lookup_as_client;
use crate::supervisor::proc_table::{ExePath, ProcessState, ThreadRecord, ThreadState};
use crate::supervisor::retype::RetypeClass;
use crate::supervisor::rsrc_ipc::{rsrc_alloc_mp_pair_recorded, rsrc_alloc_recorded, rsrc_free};
use crate::supervisor::spawn::fault_wire::{bind_fault_caps, register_fault_pipe};
use crate::supervisor::spawn::plan::{
    AddressSpacePlan, BootstrapPlan, CHILD_IPC_BUFFER_VA, ChildBundle, ExecImage, SpawnKind,
    child_stack_materialization,
};
use crate::supervisor::spawn::tcb::{SchedParams, configure_tcb};
use crate::supervisor::state::InitTarget;
use crate::wire::INIT_COOKIE_KIND_REQUEST_MP;
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::spawn::layout::CHILD_CAP_TABLE_VA;
use uapi::KERNITE_STATE_READABLE;

fn monotonic_now_ns() -> u64 {
    trona_kernel::syscall::clock_read_monotonic(trona_runtime::client::caps::clock_cap().addr())
}

/// # Safety
/// `slot` is a cap slot the caller solely owns; torn down and its index freed
/// once here.
unsafe fn delete_and_free_slot(slot: u64) {
    // SAFETY: exclusive ownership of `slot` per this fn's `# Safety`.
    unsafe { trona_runtime::core::slot_alloc::delete_and_free(slot) };
}

/// # Safety
/// `[base, base + count)` is a consecutive cap run the caller solely
/// owns; each slot is torn down and freed once here.
unsafe fn delete_and_free_receive_window(base: u64, count: u64) {
    for offset in 0..count {
        // SAFETY: each slot in the run is solely owned per this fn's `# Safety`.
        unsafe { delete_and_free_slot(base + offset) };
    }
}

fn rollback_rsrc_records(
    rsrcsrv_mp: u64,
    ipc_ctx: *mut trona_kernel::core_types::IpcContext,
    records: &[u64],
    records_len: usize,
) {
    for record_id in records.iter().take(records_len).rev() {
        let _ = rsrc_free(rsrcsrv_mp, *record_id, ipc_ctx);
    }
}

/// Phase 1 — allocate the proc-table entry (or look up the existing
/// one for `Exec`). Stamps cred, exe path, service index, name, and
/// allocates a fresh `client_id` for `Service` / `Fork`. For `Exec`
/// the existing client_id is preserved.
pub fn phase_proc_record(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
) -> Result<(u32, u32), i32> {
    match plan.kind {
        SpawnKind::Service { .. } => {
            let client_id = state.alloc_client_id();
            let start_ns = monotonic_now_ns();
            let proc_pid = {
                // SAFETY: slab backing bound at boot; single-threaded owner.
                let proc_ref = unsafe { state.procs.alloc(&mut state.self_vm) }
                    .ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
                proc_ref.parent_pid = plan.parent_pid.unwrap_or(0);
                proc_ref.service_idx = state
                    .manifest
                    .find_index_by_name(plan.def.name.as_bytes())
                    .unwrap_or(255) as u8;
                proc_ref.restart = plan.def.restart;
                proc_ref.service_type = plan.def.service_type;
                proc_ref.name = plan.def.name;
                proc_ref.exe = ExePath::from_bytes(plan.def.binary.as_bytes());
                proc_ref.argv = crate::supervisor::proc_table::ArgvStore::from_argv(&[plan
                    .def
                    .binary
                    .as_bytes()]);
                proc_ref.start_ns = start_ns;
                proc_ref.signal_state.install_defaults();
                proc_ref.pid
            };
            // SAFETY: slab backing bound; single-threaded owner.
            if !unsafe {
                state
                    .procs
                    .set_client_id(proc_pid, client_id, &mut state.self_vm)
            } {
                state.procs.release(proc_pid);
                return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
            }
            Ok((proc_pid, client_id))
        }
        SpawnKind::Fork { parent_pid, .. } => {
            let parent = state
                .procs
                .get(parent_pid)
                .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
            let parent_cred = parent.cred;
            let parent_pgid = parent.pgid;
            let parent_sid = parent.sid;
            let parent_exe = parent.exe;
            let parent_name = parent.name;
            let parent_argv = parent.argv;
            let mut child_signal_state = parent.signal_state;
            child_signal_state.pending_mask = 0;

            let client_id = state.alloc_client_id();
            let start_ns = monotonic_now_ns();
            let child_pid = {
                // SAFETY: slab backing bound at boot; single-threaded owner.
                let proc_ref = unsafe { state.procs.alloc(&mut state.self_vm) }
                    .ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
                proc_ref.parent_pid = parent_pid;
                proc_ref.pgid = parent_pgid;
                proc_ref.sid = parent_sid;
                proc_ref.cred = parent_cred;
                proc_ref.exe = parent_exe;
                proc_ref.name = parent_name;
                proc_ref.argv = parent_argv;
                proc_ref.start_ns = start_ns;
                proc_ref.signal_state = child_signal_state;
                proc_ref.pid
            };
            // SAFETY: slab backing bound; single-threaded owner.
            if !unsafe {
                state
                    .procs
                    .set_client_id(child_pid, client_id, &mut state.self_vm)
            } {
                state.procs.release(child_pid);
                return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
            }
            Ok((child_pid, client_id))
        }
        SpawnKind::Exec { existing_pid } => {
            let proc = state
                .procs
                .get(existing_pid)
                .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
            let client_id = proc.client_id();
            if let Some(p) = state.procs.get_mut(existing_pid) {
                p.exe = ExePath::from_bytes(plan.def.binary.as_bytes());
                p.name = plan.def.name;
                p.argv = crate::supervisor::proc_table::ArgvStore::from_argv(&[plan
                    .def
                    .binary
                    .as_bytes()]);
            }
            Ok((existing_pid, client_id))
        }
    }
}

/// Phase 2 — allocate the per-spawn kernel object bundle through
/// rsrcsrv.
pub fn phase_alloc_bundle(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    child_client_id: u32,
) -> Result<ChildBundle, i32> {
    if matches!(plan.kind, SpawnKind::Exec { .. }) {
        // For Exec, the existing caps stay in the ProcessRecord and are
        // managed there. exec_in_place reads them from state.procs directly.
        // Return an empty bundle; all phase helpers skip their work for Exec.
        return Ok(ChildBundle::empty());
    }

    let child_rsrcsrv_mp =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"init child rsrcsrv client");
    if child_rsrcsrv_mp == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }

    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let child_rsrcsrv_result = lookup_as_client(
        state,
        child_client_id,
        b"rsrcsrv",
        child_rsrcsrv_mp,
        ipc_ctx,
    );
    if let Err(err) = child_rsrcsrv_result {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] alloc_bundle substep=lookup(rsrcsrv) err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        // SAFETY: child_rsrcsrv_mp is the slot alloc'd at the top of this fn,
        // solely owned here.
        unsafe { delete_and_free_slot(child_rsrcsrv_mp) };
        return Err(err);
    }

    let window_count = plan.receive_window_size();
    let receive_base = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
        window_count,
        b"init spawn receive window",
    );
    if receive_base == 0 {
        // SAFETY: child_rsrcsrv_mp is the slot alloc'd at the top of this fn,
        // solely owned here.
        unsafe { delete_and_free_slot(child_rsrcsrv_mp) };
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }

    let mut records = [0u64; 16];
    let mut records_len = 0usize;
    let result = (|| -> Result<ChildBundle, i32> {
        let mut bundle = ChildBundle::empty();

        // SAFETY (applies to every `OwnedCap::adopt_received` below): each
        // slot was just filled by rsrc_alloc_recorded / rsrc_alloc_mp_pair_recorded
        // into init's armed receive window. `adopt_received` resolves the actual
        // invoke depth, so this remains correct after CSpace expansion.
        let tcb =
            rsrc_alloc_recorded(child_rsrcsrv_mp, RetypeClass::Tcb, 0, receive_base, ipc_ctx)?;
        records[records_len] = tcb.record_id;
        records_len += 1;
        bundle.tcb = Some(unsafe { OwnedCap::adopt_received(tcb.cap_slot) });

        let vspace = rsrc_alloc_recorded(
            child_rsrcsrv_mp,
            RetypeClass::VSpace,
            0,
            receive_base + 1,
            ipc_ctx,
        )?;
        records[records_len] = vspace.record_id;
        records_len += 1;
        bundle.vspace = Some(unsafe { OwnedCap::adopt_received(vspace.cap_slot) });

        let cspace = rsrc_alloc_recorded(
            child_rsrcsrv_mp,
            RetypeClass::CNode,
            12,
            receive_base + 2,
            ipc_ctx,
        )?;
        records[records_len] = cspace.record_id;
        records_len += 1;
        bundle.cspace = Some(unsafe { OwnedCap::adopt_received(cspace.cap_slot) });

        let sched_context = rsrc_alloc_recorded(
            child_rsrcsrv_mp,
            RetypeClass::SchedContext,
            0,
            receive_base + 3,
            ipc_ctx,
        )?;
        records[records_len] = sched_context.record_id;
        records_len += 1;
        bundle.sched_context = Some(unsafe { OwnedCap::adopt_received(sched_context.cap_slot) });

        let req = rsrc_alloc_mp_pair_recorded(child_rsrcsrv_mp, receive_base + 4, ipc_ctx)?;
        records[records_len] = req.core_record_id;
        records_len += 1;
        bundle.request_mp_send = Some(unsafe { OwnedCap::adopt_received(req.send_slot) });
        bundle.request_mp_recv = Some(unsafe { OwnedCap::adopt_received(req.recv_slot) });

        let sig = rsrc_alloc_mp_pair_recorded(child_rsrcsrv_mp, receive_base + 6, ipc_ctx)?;
        records[records_len] = sig.core_record_id;
        records_len += 1;
        bundle.signal_mp_send = Some(unsafe { OwnedCap::adopt_received(sig.send_slot) });
        bundle.signal_mp_recv = Some(unsafe { OwnedCap::adopt_received(sig.recv_slot) });

        let flt = rsrc_alloc_mp_pair_recorded(child_rsrcsrv_mp, receive_base + 8, ipc_ctx)?;
        records[records_len] = flt.core_record_id;
        records_len += 1;
        bundle.fault_mp_send = Some(unsafe { OwnedCap::adopt_received(flt.send_slot) });
        bundle.fault_mp_recv = Some(unsafe { OwnedCap::adopt_received(flt.recv_slot) });

        let mm = rsrc_alloc_mp_pair_recorded(child_rsrcsrv_mp, receive_base + 10, ipc_ctx)?;
        records[records_len] = mm.core_record_id;
        records_len += 1;
        bundle.mmsrv_request_mp_send = Some(unsafe { OwnedCap::adopt_received(mm.send_slot) });
        bundle.mmsrv_request_mp_recv = Some(unsafe { OwnedCap::adopt_received(mm.recv_slot) });

        let svc = rsrc_alloc_mp_pair_recorded(child_rsrcsrv_mp, receive_base + 12, ipc_ctx)?;
        records[records_len] = svc.core_record_id;
        records_len += 1;
        bundle.service_ep_send = Some(unsafe { OwnedCap::adopt_received(svc.send_slot) });
        bundle.service_ep_recv = Some(unsafe { OwnedCap::adopt_received(svc.recv_slot) });

        // ldsrv additionally gets the recv end of a private adopt MP; init keeps
        // the send end to stream the boot code set + ExecAuthority over it after
        // ldsrv is up. No other service is on this channel, so no client can
        // forge an adoption or steal the authority.
        if plan.def.name.as_bytes() == b"ldsrv" {
            let adopt = rsrc_alloc_mp_pair_recorded(child_rsrcsrv_mp, receive_base + 14, ipc_ctx)?;
            records[records_len] = adopt.core_record_id;
            records_len += 1;
            bundle.adopt_recv = Some(unsafe { OwnedCap::adopt_received(adopt.recv_slot) });
            state.ldsrv_adopt_send = Some(unsafe { OwnedCap::adopt_received(adopt.send_slot) });

            // The dedicated steady-state exec-control channel: init keeps the
            // send for `resolve_main`, separate from the boot-only adopt MP.
            let control =
                rsrc_alloc_mp_pair_recorded(child_rsrcsrv_mp, receive_base + 16, ipc_ctx)?;
            records[records_len] = control.core_record_id;
            records_len += 1;
            bundle.exec_control_recv = Some(unsafe { OwnedCap::adopt_received(control.recv_slot) });
            state.ldsrv_exec_control_send =
                Some(unsafe { OwnedCap::adopt_received(control.send_slot) });

            // A small plumbing untyped ldsrv retypes its reactor objects
            // (EventQueue + per-EP Watches) from. Carved from init's pool, not
            // rsrcsrv, since EventQueues are not a rsrcsrv RetypeClass.
            let utyp = trona_runtime::core::slot_alloc::alloc_slot()
                .ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
            let utyp_slot = utyp.addr();
            state
                .frames
                .retype_child(uapi::KERNITE_OBJ_UNTYPED as u64, 16, utyp_slot)
                .ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
            bundle.ldsrv_untyped = Some(utyp.assume_filled());
        }
        Ok(bundle)
    })();

    match result {
        Ok(bundle) => {
            // SAFETY: child_rsrcsrv_mp is the slot alloc'd at the top of this fn,
            // solely owned here.
            unsafe { delete_and_free_slot(child_rsrcsrv_mp) };
            Ok(bundle)
        }
        Err(err) => {
            // `records_len` == count of objects retyped before the failing
            // call == the index of the failing substep, so it pinpoints
            // which kernel-object alloc returned `err`.
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[INIT] alloc_bundle substep=#");
                _lb.dec(records_len as u64);
                _lb.str(b" (0=tcb 1=vspace 2=cnode 3=sc 4=req 5=sig 6=flt 7=mm 8=svc) err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            rollback_rsrc_records(child_rsrcsrv_mp, ipc_ctx, &records, records_len);
            // SAFETY: child_rsrcsrv_mp + the receive_base run are alloc'd in this
            // fn and solely owned here; freed once on this error path.
            unsafe {
                delete_and_free_slot(child_rsrcsrv_mp);
                delete_and_free_receive_window(receive_base, window_count);
            }
            Err(err)
        }
    }
}

/// Phase 3 — populate the child VSpace per `AddressSpacePlan`.
pub fn phase_address_space(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    child_client_id: u32,
    bundle: &ChildBundle,
) -> Result<(), i32> {
    match plan.address_space {
        AddressSpacePlan::FreshImage => {
            let _ = (state, bundle);
            Ok(())
        }
        AddressSpacePlan::ForkCow { parent_client_id } => {
            // Exclude the cap-table region from the COW inherit so
            // `populate_via_mmsrv` can splice a fresh frame into the
            // child's CHILD_CAP_TABLE_VA without conflicting with the
            // parent's mapping.
            mm_fork_vspace(
                state,
                parent_client_id,
                child_client_id,
                &[CHILD_CAP_TABLE_VA],
            )?;
            // Inherit the parent's FD table into the freshly-registered child
            // via the two-step VFS admin clone — but only when the parent is a
            // VFS client. A parent that booted before vfs was never registered
            // and has no VFS FD state to clone. Fails the fork on a clone error
            // so the child never starts with a truncated FD table.
            let parent_is_vfs_client = state
                .procs
                .find_by_client_id(parent_client_id)
                .map(|p| p.vfs_control_cap.is_some())
                .unwrap_or(false);
            if parent_is_vfs_client {
                crate::supervisor::vfs_ipc::vfs_clone_fds(state, parent_client_id, child_client_id)
            } else {
                Ok(())
            }
        }
        AddressSpacePlan::ExecReplace { existing_client_id } => {
            let _ = (existing_client_id, state, bundle);
            Ok(())
        }
    }
}

/// Phase 4 — register the new client with mmsrv.
pub fn phase_register_client(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    client_id: u32,
    pid: u32,
    bundle: &mut ChildBundle,
) -> Result<(), i32> {
    if matches!(plan.kind, SpawnKind::Exec { .. }) {
        return Ok(());
    }
    let vspace = bundle
        .vspace
        .as_ref()
        .map(OwnedCap::borrow)
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    let request_mp_send = bundle.mmsrv_request_mp_send.as_ref().map(OwnedCap::borrow);
    let request_mp_recv = bundle.mmsrv_request_mp_recv.take();
    let control = mm_register_client(
        state,
        client_id,
        pid,
        vspace,
        request_mp_recv,
        request_mp_send,
        plan.client_layout,
    )?;
    // Retain the per-client mmsrv control cap so init can drive admin verbs
    // (fault-pipe, fork, exec-replace, deregister) against this client.
    if let Some(rec) = state.procs.find_by_client_id_mut(client_id) {
        rec.mmsrv_control_cap = Some(control);
    }
    Ok(())
}

/// Phase 4b — register the new client with VFS. Every spawned process is a VFS
/// client; init retains the returned per-client control cap in the
/// `ProcessRecord` so it can later drive the exec `FD_CLOEXEC` sweep and the
/// client's deregister. Exec reuses the existing VFS client, so it is skipped.
/// The fork FD-table clone is driven separately in [`phase_address_space`]
/// after `mm_fork_vspace`, once the child is registered here.
pub fn phase_register_vfs(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    client_id: u32,
    pid: u32,
) -> Result<(), i32> {
    if matches!(plan.kind, SpawnKind::Exec { .. }) {
        return Ok(());
    }
    // VFS clients only exist once vfs is up. The processes that boot before
    // vfs — logsrv, console, and vfs itself — declare no `vfs:process-client`
    // interface and are not VFS clients, so skip them until vfs's ROOT control
    // cap is minted. Every real VFS client boots `After=vfs` and registers.
    if state.caps.vfs_root_control_cap.is_none() {
        return Ok(());
    }
    let control = crate::supervisor::vfs_ipc::vfs_register_client(state, client_id, pid)?;
    if let Some(rec) = state.procs.find_by_client_id_mut(client_id) {
        rec.vfs_control_cap = Some(control);
    }
    Ok(())
}

/// Phase 5 — register the per-TCB fault MP recv side with mmsrv and
/// bind the send side onto the child TCB.
pub fn phase_fault_wire(
    state: &SupervisorState,
    plan: &BootstrapPlan,
    client_id: u32,
    bundle: &mut ChildBundle,
) -> Result<(), i32> {
    if matches!(plan.kind, SpawnKind::Exec { .. }) {
        return Ok(());
    }
    let fault_recv = bundle
        .fault_mp_recv
        .take()
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    let fault_send = bundle
        .fault_mp_send
        .as_ref()
        .map(OwnedCap::borrow)
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    let tcb = bundle
        .tcb
        .as_ref()
        .map(OwnedCap::borrow)
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    register_fault_pipe(state, client_id, client_id, fault_recv)?;
    bind_fault_caps(tcb, fault_send)
}

/// Arm init's owner reactor on the child's per-client request MP.
/// The Watch is registered before the TCB starts so a first syscall
/// from the child cannot race ahead of the supervisor.
pub fn phase_request_watch(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    pid: u32,
    client_id: u32,
    bundle: &ChildBundle,
) -> Result<(), i32> {
    if matches!(plan.kind, SpawnKind::Exec { .. }) {
        return Ok(());
    }

    let watch = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"init request MP watch");

    let ipc_ctx = trona_runtime::current_ipc_ctx();
    // OwnedCap-early: `lookup_as_client` fills this slot with the rsrcsrv client
    // MP cap. Adopting it as an OwnedCap now means every exit tears it down
    // (delete + free) on drop — including a lookup that left a partial
    // cap before failing (matching the prior defensive `delete_and_free_slot`).
    let child_rsrcsrv =
        trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"init child rsrcsrv watch")
            .assume_filled();
    if let Err(err) = lookup_as_client(
        state,
        client_id,
        b"rsrcsrv",
        child_rsrcsrv.as_raw(),
        ipc_ctx,
    ) {
        // `watch` (OwnedSlot, empty) and `child_rsrcsrv` (OwnedCap) drop here.
        return Err(err);
    }
    let watch_record = match rsrc_alloc_recorded(
        child_rsrcsrv.as_raw(),
        RetypeClass::Watch,
        0,
        watch.addr(),
        ipc_ctx,
    ) {
        Ok(record) => record,
        Err(err) => {
            // rsrc alloc failed: `watch` is still empty (its OwnedSlot Drop
            // frees it) and `child_rsrcsrv` (OwnedCap) drops.
            return Err(err);
        }
    };
    // The Watch object now occupies `watch`; adopt it as an OwnedCap.
    let watch = watch.assume_filled();

    let req_recv_ref = bundle
        .request_mp_recv
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    let req_recv_addr = req_recv_ref.addr();
    let control_eq = state
        .caps
        .control_eq
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();

    let result = (|| -> Result<u64, i32> {
        let cookie = unsafe {
            state.cookie_table.arm(
                &mut state.segment_allocator,
                INIT_COOKIE_KIND_REQUEST_MP,
                req_recv_addr,
                watch.as_raw(),
                InitTarget::Request { client_id },
            )
        }
        .map_err(|_| uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as i32)?;

        let r = invoke::watch_register(
            watch.borrow(),
            req_recv_ref,
            control_eq,
            KERNITE_STATE_READABLE,
            cookie,
        );
        if r != 0 {
            let (_kind, slot, _epoch) = trona_server::event_loop::decode_cookie(cookie);
            let _ = state.cookie_table.cancel(INIT_COOKIE_KIND_REQUEST_MP, slot);
            return Err(r);
        }
        Ok(cookie)
    })();

    match result {
        Ok(cookie) => {
            // `child_rsrcsrv` drops (delete + free) at the end of the function.
            if let Some(proc) = state.procs.get_mut(pid) {
                proc.request_watch = Some(watch);
                proc.request_watch_cookie = cookie;
            } else {
                drop(watch);
            }
            Ok(())
        }
        Err(err) => {
            // Roll the recorded Watch back, then `watch` (delete + free) and
            // `child_rsrcsrv` (delete + free, at function end) tear down.
            let _ = rsrc_free(child_rsrcsrv.as_raw(), watch_record.record_id, ipc_ctx);
            drop(watch);
            Err(err)
        }
    }
}

/// Phase 6 — image staging via the mmsrv-backed loader pipeline.
///
/// `Service` and `Exec` route through `loader::load_program_via_mmsrv`
/// (byte-signature dispatch + segments + SysV stack) followed by
/// `loader::cap_table::populate_via_mmsrv`. `Fork` inherits the
/// parent's image via `MM_FORK_VSPACE` (handled in `phase_address_
/// space`) and only needs a fresh cap-table for the child. `Exec`
/// delegates to `lifecycle::exec::exec_in_place`, which runs the
/// full transaction (begin → stage → bind → commit → start → kill
/// old) end-to-end and returns the new entry point; `phase_start`
/// is a no-op for `Exec`.
///
/// Returns the child VA the kernel writes into the new TCB's `RSP`
/// (Service / Fork) — for Fork the parent's stack pointer flows
/// through the child via the COW VSpace, so we return `0` and
/// `phase_start` reads the stack pointer from the bundle's parent
/// hand-off.
pub fn phase_stage(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    pid: u32,
    bundle: &ChildBundle,
    exec_image: Option<ExecImage>,
) -> Result<StagedImage, i32> {
    let dst_client_id = state
        .procs
        .get(pid)
        .map(|p| p.client_id())
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;

    match plan.kind {
        SpawnKind::Fork {
            parent_pid,
            saved_rsp,
            child_entry,
            ..
        } => {
            let parent = state
                .procs
                .get(parent_pid)
                .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
            if parent.stack_top == 0 || parent.stack_min == 0 {
                return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
            }
            let parent_stack_top = parent.stack_top;
            let parent_stack_min = parent.stack_min;
            let parent_guard_bottom = parent.stack_guard_bottom;
            // Parent's image already lives in the child VSpace via
            // `MM_FORK_VSPACE`, which inherits the IPC buffer and
            // stack mappings from the parent unchanged. Only the
            // cap-table is new — stage it through mmsrv so the
            // splice lands in the child's RegionTable.
            let _ = loader::cap_table::populate_via_mmsrv(
                state,
                dst_client_id,
                &plan.def,
                bundle,
                None,
                None,
            )?;
            Ok(StagedImage {
                entry_pc: child_entry,
                child_sp: saved_rsp,
                ipc_buffer_va: CHILD_IPC_BUFFER_VA,
                stack_top: parent_stack_top,
                stack_min: parent_stack_min,
                guard_bottom: parent_guard_bottom,
            })
        }
        SpawnKind::Service { .. } => {
            // Allocate a 1-page IPC buffer in init's scratch VSpace
            // and splice it into the child at `CHILD_IPC_BUFFER_VA`.
            // Without this the kernel's `TCB_CONFIGURE` cannot bind
            // a buffer for fastpath syscalls and every IPC round-trip
            // falls back to the slow path.
            let src_client_id = state.caps.init_client_id;
            let page_bytes = uapi::KERNITE_PAGE_BYTES as u64;
            let (ipc_scratch_va, ipc_region_packed) = crate::supervisor::mm_ipc::mm_mmap_self(
                state,
                crate::supervisor::mm_ipc::MMAP_KIND_ANON,
                0,
                page_bytes,
                crate::supervisor::mm_ipc::PROT_READ | crate::supervisor::mm_ipc::PROT_WRITE,
                0,
            )?;
            crate::supervisor::mm_ipc::mm_stage_image_region(
                state,
                src_client_id,
                ipc_region_packed,
                dst_client_id,
                CHILD_IPC_BUFFER_VA,
                0,
                page_bytes,
                page_bytes,
                crate::supervisor::mm_ipc::PROT_READ | crate::supervisor::mm_ipc::PROT_WRITE,
                crate::supervisor::mm_ipc::STAGE_IMAGE_KIND_NONE,
                0,
            )?;
            crate::supervisor::mm_ipc::mm_munmap_self(state, ipc_scratch_va, page_bytes)?;

            let image = loader::cpio::find_file(state, plan.def.binary.as_bytes())
                .ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
            let argv: [&[u8]; 1] = [plan.def.binary.as_bytes()];
            let envp: [&[u8]; 0] = [];
            let alloc_slot_base =
                loader::cap_table::planned_alloc_slot_base(&plan.def, &state.manifest);
            let stack = child_stack_materialization(plan.stack_spec)?;
            let loaded = loader::load_program_via_mmsrv(
                state,
                src_client_id,
                dst_client_id,
                plan.def.binary.as_bytes(),
                image,
                None,
                &argv,
                &envp,
                stack.stack_top,
                plan.stack_spec,
                CHILD_CAP_TABLE_VA,
                CHILD_IPC_BUFFER_VA,
                alloc_slot_base,
                loader::startup_framebuffer_for(state, &plan.def),
                None,
                // Service spawn is bootstrap (no vfs yet): init maps the full
                // DSO closure from the initrd.
                false,
            )?;
            let actual_alloc_slot_base = loader::cap_table::populate_via_mmsrv(
                state,
                dst_client_id,
                &plan.def,
                bundle,
                None,
                None,
            )?;
            if actual_alloc_slot_base != alloc_slot_base {
                return Err(uapi::KERNITE_ERR_INVALID_OPERATION as i32);
            }
            Ok(StagedImage {
                entry_pc: loaded.entry_pc,
                child_sp: loaded.child_sp,
                ipc_buffer_va: CHILD_IPC_BUFFER_VA,
                stack_top: stack.stack_top,
                stack_min: stack.reserve_base,
                guard_bottom: stack.guard_bottom,
            })
        }
        SpawnKind::Exec { .. } => {
            let entry = crate::supervisor::lifecycle::exec::exec_in_place(
                state,
                pid,
                bundle,
                &plan.def,
                exec_image,
                plan.client_layout,
            )?;
            let stack = child_stack_materialization(plan.stack_spec)?;
            Ok(StagedImage {
                entry_pc: entry,
                child_sp: 0,
                ipc_buffer_va: CHILD_IPC_BUFFER_VA,
                stack_top: stack.stack_top,
                stack_min: stack.reserve_base,
                guard_bottom: stack.guard_bottom,
            })
        }
    }
}

/// Result of [`phase_stage`]. `entry_pc` is the new TCB's RIP;
/// `child_sp` is its RSP. `stack_min` / `guard_bottom` are the
/// kernel parameters for `TCB_SET_STACK_BOUNDS`; `ipc_buffer_va` is
/// passed through `TCB_CONFIGURE`. For `Exec` the post-exec TCB has
/// already been started by `exec_in_place`, so `phase_start` skips
/// the configure/start sequence entirely.
pub struct StagedImage {
    pub entry_pc: u64,
    pub child_sp: u64,
    pub ipc_buffer_va: u64,
    pub stack_top: u64,
    pub stack_min: u64,
    pub guard_bottom: u64,
}

/// Phase 7 — TCB configuration. `initial_rsp` is the user-space RSP from
/// the SysV-composed stack (`StagedImage::child_sp`); `stack_top` is
/// the top of the stack VMA used by `TCB_SET_STACK_BOUNDS`.
///
/// Service and fork both return a non-zero configured TCB slot. Services are
/// started by the lifecycle facade after the proc record is installed; forks
/// stay deferred until the caller's `INIT_FORK` reply has been emitted.
#[allow(clippy::too_many_arguments)]
pub fn phase_start(
    plan: &BootstrapPlan,
    bundle: &ChildBundle,
    entry_point: u64,
    initial_rsp: u64,
    ipc_buffer_va: u64,
    stack_top: u64,
    stack_min: u64,
    guard_bottom: u64,
) -> Result<u64, i32> {
    let sched = SchedParams::fair_default();

    match plan.kind {
        SpawnKind::Exec { .. } => {
            let _ = (
                bundle,
                entry_point,
                initial_rsp,
                ipc_buffer_va,
                stack_top,
                stack_min,
                guard_bottom,
            );
            Ok(0)
        }
        SpawnKind::Service { .. } => {
            configure_tcb(
                bundle,
                ipc_buffer_va,
                entry_point,
                initial_rsp,
                0,
                stack_top,
                stack_min,
                guard_bottom,
                sched,
            )?;
            Ok(bundle
                .tcb
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr())
        }
        SpawnKind::Fork { tls_base, .. } => {
            configure_tcb(
                bundle,
                ipc_buffer_va,
                entry_point,
                initial_rsp,
                tls_base,
                stack_top,
                stack_min,
                guard_bottom,
                sched,
            )?;
            Ok(bundle
                .tcb
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr())
        }
    }
}

/// Phase 8a — publish the proc-record before the child can run.
///
/// The owner reactor routes early INIT IPC and mmsrv fault reports by
/// `client_id`, so the process table must contain the child's TCB,
/// CSpace/VSpace, request MP, and fault pipe slots before `TCB_START`.
/// This also closes the readiness/fault race: a freshly-started
/// service cannot notify init or fault into mmsrv before init has
/// installed the metadata those paths resolve through.
/// Takes ownership of `bundle` and installs its caps into the ProcessRecord.
/// The bundle caps are moved into the proc — bundle is consumed by this call.
/// Callers must extract any `CapRef` views they need (e.g. `service_ep_send`
/// for the vfs admin mint) before calling this function.
pub fn phase_install_proc_record(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    pid: u32,
    bundle: ChildBundle,
    staged: &StagedImage,
) {
    let is_fresh = !matches!(plan.kind, SpawnKind::Exec { .. });
    if let Some(p) = state.procs.get_mut(pid) {
        if is_fresh {
            p.main_tcb = bundle.tcb;
            p.vspace = bundle.vspace;
            p.cspace = bundle.cspace;
            p.sched_context = bundle.sched_context;
            p.request_mp_send = bundle.request_mp_send;
            p.request_mp_recv = bundle.request_mp_recv;
            p.signal_mp_send = bundle.signal_mp_send;
            p.signal_mp_recv = bundle.signal_mp_recv;
            p.mmsrv_request_mp_send = bundle.mmsrv_request_mp_send;
            p.mmsrv_request_mp_recv = bundle.mmsrv_request_mp_recv;
            p.fault_mp_recv = bundle.fault_mp_recv;
            p.fault_mp_send = bundle.fault_mp_send;
            p.service_ep_send = bundle.service_ep_send;
            p.service_ep_recv = bundle.service_ep_recv;
            p.ldsrv_adopt_recv = bundle.adopt_recv;
            p.ldsrv_exec_control_recv = bundle.exec_control_recv;
            p.ldsrv_plumbing_untyped = bundle.ldsrv_untyped;
        }
        p.stack_top = staged.stack_top;
        p.stack_min = staged.stack_min;
        p.stack_guard_bottom = staged.guard_bottom;
        // Stash the layout so a future INIT_FORK can hand it to the
        // child's BootstrapPlan (fork inherits the parent's current layout
        // exactly). For Exec the layout is the new image's — set even on
        // Exec so a subsequent fork sees it.
        p.layout = plan.client_layout;
        p.state = ProcessState::Active;
    }
    if is_fresh {
        // Main thread record carries None for all cap fields — the caps live
        // in the ProcessRecord and are reclaimed by owner_exited at exit.
        state.procs.set_single_thread(
            pid,
            ThreadRecord {
                state: ThreadState::Running,
                tcb: None,
                sc: None,
                fault_mp_recv: None,
                fault_mp_send: None,
                join_token: None,
                tid: 1,
                exit_status: 0,
                tcb_record_id: 0,
                sc_record_id: 0,
                fault_mp_record_id: 0,
            },
        );
    }
}

/// Phase 8b — publish lifecycle after the start/exec transition has
/// actually happened.
pub fn phase_publish_lifecycle(state: &mut SupervisorState, plan: &BootstrapPlan, pid: u32) {
    let parent_pid = plan.parent_pid.unwrap_or(0);
    match plan.kind {
        SpawnKind::Service { svc_idx } => {
            state.lifecycle.publish(
                trona_runtime::current_ipc_ctx(),
                EVT_SPAWN,
                pid,
                parent_pid,
                svc_idx as u64,
                0,
            );
        }
        SpawnKind::Fork { .. } => {
            state.lifecycle.publish(
                trona_runtime::current_ipc_ctx(),
                EVT_SPAWN,
                pid,
                parent_pid,
                0,
                0,
            );
        }
        SpawnKind::Exec { .. } => {
            state.lifecycle.publish(
                trona_runtime::current_ipc_ctx(),
                EVT_EXEC,
                pid,
                parent_pid,
                0,
                0,
            );
        }
    }
}
