// SPDX-License-Identifier: GPL-2.0-only
//
//! `execve` replaces the calling process's image in place via the
//! mmsrv exec transaction (Q2):
//!
//! 1. Snapshot the existing process record (`client_id`, old main
//!    TCB, sched-context, cspace, vspace, fault pipe).
//! 2. Retype a fresh kernel-object set for the new image — VSpace,
//!    main TCB, SchedContext, and a fresh CNode — under the *target
//!    client's* rsrcsrv identity (via `lookup_as_client`), so the
//!    objects are owned by `client_id` and reclaimed by
//!    `rsrc_owner_exited(client_id)` at process exit. The fault MP
//!    pair is process-level (keyed by `client_id`); exec keeps the
//!    existing one rather than minting a duplicate.
//! 3. `MM_BEGIN_EXEC_REPLACE(client_id, new_vspace)` → `txn_id`.
//! 4. Stage the new image's PT_LOAD segments + SysV stack +
//!    cap-table through the exec transaction (every
//!    `MM_STAGE_IMAGE_REGION` carries `txn_id` so it lands in the
//!    pending VSpace).
//! 5. Bind the existing fault MP send side onto the fresh main TCB.
//! 6. `MM_COMMIT_EXEC_REPLACE(client_id, txn_id)` swaps mmsrv's
//!    client `vspace_cap` to the new VSpace and decommits every
//!    pre-exec region.
//! 7. Start the new main TCB at the new entry point, then drop the
//!    old main TCB and release the superseded objects.
//!
//! A fresh CNode (rather than reusing the old image's) means
//! cap-table population targets empty runtime slots — no
//! `SLOT_OCCUPIED` — and the old image's CSpace stays intact until
//! commit, so any pre-commit failure rolls back to the original
//! running image with no half-built cap state. The process-level
//! request / signal / mmsrv / service endpoints and the fault pipe
//! are preserved so fd tables, lazy service clients, and fault
//! handling keep the same identity across the exec.
//!
//! Returns the new image's entry-point VA. The caller does NOT need
//! to run `phase_start` afterwards — `exec_in_place` has already
//! started the post-exec TCB; `phase_start` is a no-op for
//! `SpawnKind::Exec`.

use trona_kernel::core_types::IpcContext;
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::{OwnedCap, delete_and_free};
use trona_runtime::current_ipc_ctx;

use crate::supervisor::SupervisorState;
use crate::supervisor::loader;
use crate::supervisor::manifest::{NameStr, ServiceDef};
use crate::supervisor::mm_ipc::{
    MMAP_KIND_ANON, PROT_READ, PROT_WRITE, STAGE_IMAGE_KIND_NONE, mm_abort_exec_replace,
    mm_begin_exec_replace, mm_commit_exec_replace, mm_mmap_self, mm_munmap_self,
    mm_stage_image_region_exec,
};
use crate::supervisor::namesrv_ipc::lookup_as_client;
use crate::supervisor::retype::RetypeClass;
use crate::supervisor::rsrc_ipc::{rsrc_alloc_recorded, rsrc_free};
use crate::supervisor::spawn::fault_wire::bind_fault_caps;
use crate::supervisor::spawn::plan::{
    CHILD_IPC_BUFFER_VA, ChildBundle, ExecImage, child_stack_materialization,
};
use crate::supervisor::spawn::tcb::{SchedParams, configure_and_start_tcb};
use trona_runtime::spawn::layout::{CHILD_CAP_TABLE_VA, VmClientLayout};

/// Receive-window slots for the exec image's fresh objects:
/// VSpace, main TCB, SchedContext, CNode.
const EXEC_RECV_WINDOW: u64 = 4;

/// `execve` flow — see module-level doc-comment.
pub fn exec_in_place(
    state: &mut SupervisorState,
    pid: u32,
    _old_bundle: &ChildBundle,
    def: &ServiceDef,
    exec_image: Option<ExecImage>,
    client_layout: VmClientLayout,
) -> Result<u64, i32> {
    let ei = exec_image.ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;

    // Extract the client id and take ownership of the old image's objects
    // (tcb, sc, vspace, cspace) so they can be dropped on commit or rollback.
    // The fault pipe and all the process-level MPs are *not* taken — they
    // are retained in the ProcessRecord and referenced as CapRef throughout
    // the exec transaction.
    let client_id = state
        .procs
        .get(pid)
        .map(|p| p.client_id())
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;

    // Borrow CapRef views of the old objects for invoke call sites. These
    // borrows are short-lived (used inside the transaction closure) and safe
    // because state.procs is not mutated until after the closure completes.
    let (old_main_tcb_ref, old_fault_send_ref, old_fault_recv_ref, _old_vspace_addr, exec_fallback) = {
        let proc = state
            .procs
            .get(pid)
            .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        (
            proc.main_tcb
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default(),
            proc.fault_mp_send
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default(),
            proc.fault_mp_recv
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default(),
            proc.vspace
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr(),
            // Process-level MPs retained across exec; the new ChildBundle
            // carries None for these, so cap_table falls back to them.
            loader::cap_table::ExecMpFallback {
                request_mp_send: proc.request_mp_send.as_ref().map(OwnedCap::borrow),
                mmsrv_request_mp_send: proc.mmsrv_request_mp_send.as_ref().map(OwnedCap::borrow),
                signal_mp_recv: proc.signal_mp_recv.as_ref().map(OwnedCap::borrow),
                service_ep_recv: proc.service_ep_recv.as_ref().map(OwnedCap::borrow),
                service_ep_send: proc.service_ep_send.as_ref().map(OwnedCap::borrow),
            },
        )
    };
    let _ = old_fault_recv_ref; // retained in proc; used at ThreadRecord update only

    let ipc_ctx = current_ipc_ctx();

    // A receive window for the four fresh objects, plus a temporary
    // rsrcsrv MP badged with the *target client's* identity so the new
    // objects are owned by `client_id` (not init) and are reclaimed by
    // `rsrc_owner_exited(client_id)` at process exit.
    let receive_base = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
        EXEC_RECV_WINDOW,
        b"init exec receive window",
    );
    if receive_base == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let child_rsrcsrv_mp =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"init exec rsrcsrv client");
    if child_rsrcsrv_mp == 0 {
        // SAFETY: receive_base is the consecutive exec receive window alloc'd
        // above, solely owned here.
        unsafe { free_receive_window(receive_base) };
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    if let Err(e) = lookup_as_client(state, client_id, b"rsrcsrv", child_rsrcsrv_mp, ipc_ctx) {
        // SAFETY: child_rsrcsrv_mp + the receive_base run are alloc'd above and
        // solely owned here; freed once on this error path.
        unsafe {
            delete_and_free(child_rsrcsrv_mp);
            free_receive_window(receive_base);
        }
        return Err(e);
    }

    // Everything that can fail after the first kernel-object alloc runs
    // inside this closure. `records` / `records_len` accumulate the
    // rsrcsrv record ids for rollback, and `txn_id` is non-zero once the
    // exec transaction opens. On any error the cleanup below aborts the
    // transaction (if open), frees the new objects under the child
    // identity, and frees init's slots — leaving the old image running.
    let mut records = [0u64; EXEC_RECV_WINDOW as usize];
    let mut records_len = 0usize;
    let mut txn_id = 0u64;

    let result = (|| -> Result<(u64, u64, ChildBundle), i32> {
        let new_vspace = {
            let r = rsrc_alloc_recorded(
                child_rsrcsrv_mp,
                RetypeClass::VSpace,
                0,
                receive_base,
                ipc_ctx,
            )?;
            records[records_len] = r.record_id;
            records_len += 1;
            r.cap_slot
        };
        let new_tcb = {
            let r = rsrc_alloc_recorded(
                child_rsrcsrv_mp,
                RetypeClass::Tcb,
                0,
                receive_base + 1,
                ipc_ctx,
            )?;
            records[records_len] = r.record_id;
            records_len += 1;
            r.cap_slot
        };
        let new_sc = {
            let r = rsrc_alloc_recorded(
                child_rsrcsrv_mp,
                RetypeClass::SchedContext,
                0,
                receive_base + 2,
                ipc_ctx,
            )?;
            records[records_len] = r.record_id;
            records_len += 1;
            r.cap_slot
        };
        // Fresh CNode for the exec image (12-bit, matching the spawn-time CSpace).
        let new_cspace = {
            let r = rsrc_alloc_recorded(
                child_rsrcsrv_mp,
                RetypeClass::CNode,
                12,
                receive_base + 3,
                ipc_ctx,
            )?;
            records[records_len] = r.record_id;
            records_len += 1;
            r.cap_slot
        };

        // The fault MP pair is process-level (registered with mmsrv under
        // `(client_id, client_id)` at spawn); exec rebinds it onto the new
        // main TCB rather than minting a duplicate, so mmsrv's fault table
        // gains no stale or shadowing entry. The process-level MPs are
        // borrowed from the ProcessRecord — ChildBundle carries None for
        // those fields; configure_and_start_tcb and cap_table::populate
        // read them from the ProcessRecord directly for exec paths.
        // SAFETY: new_tcb/new_vspace/new_cspace/new_sc are the exec image's
        // freshly retyped plumbing caps delivered into init's receive window;
        // adopt_received preserves the correct invoke depth after CSpace expansion.
        let new_bundle = ChildBundle {
            tcb: Some(unsafe { OwnedCap::adopt_received(new_tcb) }),
            vspace: Some(unsafe { OwnedCap::adopt_received(new_vspace) }),
            cspace: Some(unsafe { OwnedCap::adopt_received(new_cspace) }),
            sched_context: Some(unsafe { OwnedCap::adopt_received(new_sc) }),
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

        let new_vspace_cap = new_bundle
            .vspace
            .as_ref()
            .map(OwnedCap::borrow)
            .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        txn_id =
            mm_begin_exec_replace(state, client_id, new_vspace_cap, ei.exec_mo, client_layout)?;

        // Allocate a fresh IPC buffer page for the exec'd image and stage
        // it via the exec transaction so it lands at `CHILD_IPC_BUFFER_VA`
        // in the pending VSpace.
        let src_client_id = state.caps.init_client_id;
        let page_bytes = uapi::KERNITE_PAGE_BYTES as u64;
        let (ipc_scratch_va, ipc_region_packed) = mm_mmap_self(
            state,
            MMAP_KIND_ANON,
            0,
            page_bytes,
            PROT_READ | PROT_WRITE,
            0,
        )?;
        let stage = mm_stage_image_region_exec(
            state,
            src_client_id,
            ipc_region_packed,
            client_id,
            CHILD_IPC_BUFFER_VA,
            0,
            page_bytes,
            page_bytes,
            PROT_READ | PROT_WRITE,
            STAGE_IMAGE_KIND_NONE,
            txn_id,
        );
        let _ = mm_munmap_self(state, ipc_scratch_va, page_bytes);
        stage?;

        // Image bytes and argv/envp were resolved from the path-based exec
        // request before this transaction opened. The stack startup block
        // receives the planned cap-table high-water mark, then the cap-table
        // staging below verifies the plan against the slots it installed.
        let alloc_slot_base = loader::cap_table::planned_alloc_slot_base(def, &state.manifest);
        let stack_spec = def.stack_layout_spec();
        let stack = child_stack_materialization(stack_spec)?;
        let loaded = loader::load_program_via_mmsrv(
            state,
            src_client_id,
            client_id,
            ei.name,
            ei.header_bytes,
            Some(ei.exec_mo),
            ei.argv,
            ei.envp,
            stack.stack_top,
            stack_spec,
            CHILD_CAP_TABLE_VA,
            CHILD_IPC_BUFFER_VA,
            alloc_slot_base,
            loader::startup_framebuffer_for(state, def),
            Some(txn_id),
            // Path-exec: the interpreter loads DT_NEEDED from vfs at runtime;
            // init maps only the main image and the interpreter.
            true,
        )?;

        let actual_alloc_slot_base = loader::cap_table::populate_via_mmsrv(
            state,
            client_id,
            def,
            &new_bundle,
            Some(exec_fallback),
            Some(txn_id),
        )?;
        if actual_alloc_slot_base != alloc_slot_base {
            return Err(uapi::KERNITE_ERR_INVALID_OPERATION as i32);
        }

        // Rebind the process fault pipe's send side onto the fresh TCB. The
        // mmsrv-side recv registration is unchanged, so faults from the new
        // image route through the existing pipe.
        let new_tcb_ref = new_bundle
            .tcb
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default();
        bind_fault_caps(new_tcb_ref, old_fault_send_ref)?;

        mm_commit_exec_replace(state, client_id, txn_id)?;

        Ok((loaded.entry_pc, loaded.child_sp, new_bundle))
    })();

    let (entry_pc, child_sp, new_bundle) = match result {
        Ok(v) => v,
        Err(e) => {
            // Old image is untouched and still mapped — roll back the
            // pending exec state and the freshly retyped objects, leaving
            // the caller running its original image (execve failure
            // semantics). Order: abort the mmsrv transaction first so its
            // pending-region teardown completes before rsrcsrv revokes the
            // backing objects, then free init's slots.
            if txn_id != 0 {
                let _ = mm_abort_exec_replace(state, client_id, txn_id);
            }
            rollback_records(child_rsrcsrv_mp, ipc_ctx, &records, records_len);
            // SAFETY: child_rsrcsrv_mp + the receive_base run are alloc'd above
            // and solely owned here; freed once on this error path.
            unsafe {
                delete_and_free(child_rsrcsrv_mp);
                free_receive_window(receive_base);
            }
            return Err(e);
        }
    };

    // Commit succeeded. The temporary child rsrcsrv MP has done its job
    // (the objects are recorded under `client_id`); drop init's copy.
    // SAFETY: child_rsrcsrv_mp is the slot alloc'd above, solely owned here.
    unsafe { delete_and_free(child_rsrcsrv_mp) };

    // Exec point of no return passed: drop the client's `FD_CLOEXEC`
    // descriptors in VFS. Best-effort — the exec is already committed, so a
    // sweep failure does not fail execve (inherited non-CLOEXEC fds survive).
    let _ = crate::supervisor::vfs_ipc::vfs_exec_sweep(state, client_id);

    let stack_spec = def.stack_layout_spec();
    let stack = child_stack_materialization(stack_spec)?;

    // Bring the new TCB up via the unified configure/start helper —
    // includes `TCB_SET_SPACE`, `TCB_SET_STACK_BOUNDS`, `TCB_CONFIGURE`,
    // `SC_CONFIGURE`, `SC_BIND`, and `TCB_START` in the order the kernel
    // requires.
    configure_and_start_tcb(
        &new_bundle,
        CHILD_IPC_BUFFER_VA,
        entry_pc,
        child_sp,
        0,
        stack.stack_top,
        stack.reserve_base,
        stack.guard_bottom,
        SchedParams::fair_default(),
    )?;

    let _ = invoke::tcb_kill(old_main_tcb_ref);
    // Commit succeeded: the old image's TCB, sched-context, CNode, and
    // VSpace are now superseded. Drop init's references via OwnedCap; their
    // rsrcsrv records are reclaimed by owner_exited at process exit, like
    // the other client-owned objects. The fault MP pair is retained — it is
    // reused by the new image.
    {
        let proc = state
            .procs
            .get_mut(pid)
            .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        // Take ownership of the superseded caps and drop them. slot_free
        // is sufficient here because rsrcsrv holds the back_ref that drives
        // untyped reclaim at owner_exited time.
        drop(proc.main_tcb.take());
        drop(proc.sched_context.take());
        drop(proc.cspace.take());
        drop(proc.vspace.take());
        // Install new caps from the bundle.
        proc.main_tcb = new_bundle.tcb;
        proc.vspace = new_bundle.vspace;
        proc.cspace = new_bundle.cspace;
        proc.sched_context = new_bundle.sched_context;
        proc.stack_top = stack.stack_top;
        proc.stack_min = stack.reserve_base;
        proc.stack_guard_bottom = stack.guard_bottom;
        // `execve` updates the process name (comm) to the new program's
        // basename, like a real Unix exec. Only after commit — a failed
        // exec keeps the caller's image and name.
        proc.name = NameStr::from_bytes(path_basename(ei.name));
        // Record the full argv so `/proc/<pid>/cmdline` reflects the
        // newly-exec'd command line (Linux replaces argv on exec).
        proc.argv = crate::supervisor::proc_table::ArgvStore::from_argv(ei.argv);
    }

    // The fault MP caps live in the ProcessRecord and are reused unchanged;
    // the new main thread record borrows them by record identity only.
    state.procs.set_single_thread(
        pid,
        crate::supervisor::proc_table::ThreadRecord {
            state: crate::supervisor::proc_table::ThreadState::Running,
            tcb: None,
            sc: None,
            fault_mp_recv: None,
            fault_mp_send: None,
            join_token: None,
            tid: 1,
            exit_status: 0,
            // Main thread objects are reclaimed by owner_exited, not the
            // init-owned per-thread reclaim path.
            tcb_record_id: 0,
            sc_record_id: 0,
            fault_mp_record_id: 0,
        },
    );

    Ok(entry_pc)
}

/// `RSRC_FREE` each recorded object through the child-badged rsrcsrv MP
/// (init's admin MP would fail rsrcsrv's owner check), newest first.
fn rollback_records(
    rsrcsrv_mp: u64,
    ipc_ctx: *mut IpcContext,
    records: &[u64],
    records_len: usize,
) {
    for record_id in records.iter().take(records_len).rev() {
        let _ = rsrc_free(rsrcsrv_mp, *record_id, ipc_ctx);
    }
}

/// Delete + free the `EXEC_RECV_WINDOW` consecutive cap slots.
/// # Safety
/// `[base, base + EXEC_RECV_WINDOW)` is a consecutive cap run the caller solely
/// owns; each slot is torn down and its index freed once here.
unsafe fn free_receive_window(base: u64) {
    for offset in 0..EXEC_RECV_WINDOW {
        // SAFETY: each slot in the run is solely owned per this fn's `# Safety`.
        unsafe { delete_and_free(base + offset) };
    }
}

/// The last path component of `path` — `execve`'s comm is the program's
/// basename, not the full path it was invoked by.
fn path_basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}
