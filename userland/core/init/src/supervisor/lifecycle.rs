// SPDX-License-Identifier: GPL-2.0-only
//
//! Process lifecycle facade.
//!
//! `realize_process` is the single in-place pipeline that brings a
//! process into existence. Service spawn, POSIX `fork`, and POSIX
//! `execve` all flow through it, diverging only on the
//! `AddressSpacePlan` variant and the `SpawnKind`.
//!
//! The pipeline composes from the phase helpers in
//! [`phase`]; entry points called from the dispatcher
//! ([`handle_spawn`], [`handle_fork`], [`handle_exec`],
//! [`handle_exit`], [`handle_wait`]) build a [`spawn::plan::
//! BootstrapPlan`] and hand it to `realize_process`. Exit teardown
//! lives in [`exit`]; waitpid bookkeeping lives in [`wait`].
//!
//! Plan types (`SpawnKind` / `AddressSpacePlan` / `BootstrapPlan` /
//! `RealizeOutcome` / `ChildBundle`) live in
//! [`crate::supervisor::spawn::plan`]. The `mm_*` / `rsrc_*` /
//! `namesrv_*` IPC wire helpers live in their respective `*_ipc`
//! modules.

pub mod exec;
pub mod exec_load;
pub mod exit;
pub mod phase;
pub mod wait;

use trona_kernel::core_types::{CapRef, TronaMsg};
use trona_kernel::invoke;
use trona_protocol::common::TRONA_OK;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::spawn::layout::{LayoutError, compute_vm_layout};
use trona_server::event_loop::decode_cookie;

use crate::supervisor::SupervisorState;
use crate::supervisor::manifest::ServiceDef;
use crate::supervisor::mm_ipc::mm_deregister_client;
use crate::supervisor::namesrv_ipc::{grant_publisher_if_needed, namesrv_owner_exited};
use crate::supervisor::rsrc_ipc::rsrc_owner_exited;
use crate::supervisor::spawn::plan::{
    AddressSpacePlan, BootstrapPlan, ChildBundle, ExecImage, RealizeOutcome, SpawnKind,
};
use crate::supervisor::thread::PostReplyAction;
use crate::supervisor::vfs_ipc::vfs_deregister_client;
use crate::wire::INIT_COOKIE_KIND_REQUEST_MP;
use trona_runtime::spawn::layout::VmClientLayout;

// Re-exports — external callers reference these through
// `lifecycle::*` rather than the submodule paths so the public
// surface stays compact.
pub use crate::supervisor::lifecycle::exit::finalize_exit;
pub use crate::supervisor::lifecycle::wait::{WaitOutcome, handle_wait};

// ---------------------------------------------------------------------------
// The unified pipeline.
// ---------------------------------------------------------------------------

fn log_phase_failure(plan: &BootstrapPlan, phase: &[u8], err: i32) -> i32 {
    trona_runtime::uerror!(|_lb| {
        _lb.str(b"[INIT] spawn ");
        _lb.bytes(plan.def.name.as_bytes());
        _lb.str(b" failed phase=");
        _lb.bytes(phase);
        _lb.str(b" err=");
        _lb.hex(err as u64);
        _lb.str(b"\n");
    });
    err
}

fn drop_request_watch_if_armed(state: &mut SupervisorState, pid: u32) {
    let Some(proc) = state.procs.get_mut(pid) else {
        return;
    };
    if proc.request_watch.is_none() {
        return;
    }

    let watch_slot = proc
        .request_watch
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    let watch_cookie = proc.request_watch_cookie;
    let _ = proc.request_watch.take();
    proc.request_watch_cookie = 0;

    let (_kind, slot, _epoch) = decode_cookie(watch_cookie);
    let watch = state
        .cookie_table
        .cancel(INIT_COOKIE_KIND_REQUEST_MP, slot)
        .unwrap_or(watch_slot);
    let _ = invoke::watch_cancel(CapRef::flat(watch));
}

fn drop_unstarted_bundle_caps(bundle: ChildBundle) {
    // Kill the TCB before dropping the bundle so the kernel does not
    // refuse the untyped-reclaim with HasChildren. Dropping `bundle`
    // afterwards runs OwnedCap::drop on every non-None field, which
    // calls delete_and_free on each slot.
    if let Some(tcb) = bundle.tcb.as_ref() {
        let _ = invoke::tcb_kill(tcb.borrow());
    }
    drop(bundle);
}

fn rollback_unpublished_process(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    pid: u32,
    client_id: u32,
    bundle: ChildBundle,
) {
    if matches!(plan.kind, SpawnKind::Exec { .. }) {
        return;
    }

    // Same teardown order as `finalize_exit`: drop every reference to the
    // half-built bundle (init's cap copies + the unstarted TCB) before the
    // synchronous rsrcsrv reclaim, so each drained untyped chunk resets on
    // the first try instead of being refused HasChildren. mmsrv deregister
    // stays async to avoid the INIT_REPORT_FAULT deadlock.
    drop_request_watch_if_armed(state, pid);
    mm_deregister_client(state, client_id);
    // VFS deregister is likewise async (MP_WRITE): a half-built fork may have
    // registered the child with VFS and cloned its FD table, so drop those
    // refs on rollback. A no-op when the client was never VFS-registered.
    vfs_deregister_client(state, client_id);
    namesrv_owner_exited(state, client_id);
    drop_unstarted_bundle_caps(bundle);
    let rsrcsrv_mp = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    rsrc_owner_exited(rsrcsrv_mp, client_id, trona_runtime::current_ipc_ctx());
    state.procs.release(pid);
}

fn release_unpublished_proc_record(state: &mut SupervisorState, plan: &BootstrapPlan, pid: u32) {
    if !matches!(plan.kind, SpawnKind::Exec { .. }) {
        state.procs.release(pid);
    }
}

/// Execute every phase of the lifecycle plan in order. Each phase
/// rolls back local allocations on its own failure path; once a
/// child client has cross-service state, this facade performs the
/// owner-level rollback before surfacing the error to the dispatcher.
pub fn realize_process(
    state: &mut SupervisorState,
    plan: &BootstrapPlan,
    exec_image: Option<ExecImage>,
) -> Result<RealizeOutcome, i32> {
    let (pid, client_id) = match phase::phase_proc_record(state, plan) {
        Ok(v) => v,
        Err(err) => return Err(log_phase_failure(plan, b"proc_record", err)),
    };
    let mut bundle = match phase::phase_alloc_bundle(state, plan, client_id) {
        Ok(v) => v,
        Err(err) => {
            release_unpublished_proc_record(state, plan, pid);
            return Err(log_phase_failure(plan, b"alloc_bundle", err));
        }
    };
    if let Err(err) = phase::phase_register_client(state, plan, client_id, pid, &mut bundle) {
        rollback_unpublished_process(state, plan, pid, client_id, bundle);
        return Err(log_phase_failure(plan, b"register_client", err));
    }
    if let Err(err) = phase::phase_register_vfs(state, plan, client_id, pid) {
        rollback_unpublished_process(state, plan, pid, client_id, bundle);
        return Err(log_phase_failure(plan, b"register_vfs", err));
    }
    if let Err(err) = phase::phase_address_space(state, plan, client_id, &bundle) {
        rollback_unpublished_process(state, plan, pid, client_id, bundle);
        return Err(log_phase_failure(plan, b"address_space", err));
    }
    if let Err(err) = phase::phase_fault_wire(state, plan, client_id, &mut bundle) {
        rollback_unpublished_process(state, plan, pid, client_id, bundle);
        return Err(log_phase_failure(plan, b"fault_wire", err));
    }
    if let Err(err) = phase::phase_request_watch(state, plan, pid, client_id, &bundle) {
        rollback_unpublished_process(state, plan, pid, client_id, bundle);
        return Err(log_phase_failure(plan, b"request_watch", err));
    }
    let staged = match phase::phase_stage(state, plan, pid, &bundle, exec_image) {
        Ok(v) => v,
        Err(err) => {
            rollback_unpublished_process(state, plan, pid, client_id, bundle);
            return Err(log_phase_failure(plan, b"stage", err));
        }
    };

    if matches!(plan.kind, SpawnKind::Service { .. }) {
        if let Err(err) = grant_publisher_if_needed(state, &plan.def, client_id) {
            rollback_unpublished_process(state, plan, pid, client_id, bundle);
            return Err(log_phase_failure(plan, b"grant_publisher", err));
        }
    }

    // Extract the vfs service endpoint address before `phase_install_proc_record`
    // consumes `bundle` by value. This slot addr is only used for the mint
    // below and is only valid until the bundle is dropped/moved anyway.
    let vfs_service_ep_send_addr =
        if matches!(plan.kind, SpawnKind::Service { .. }) && plan.def.name.as_bytes() == b"vfs" {
            bundle
                .service_ep_send
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr()
        } else {
            0
        };

    // The mmsrv-backed loader returns `child_sp` pointing at
    // `argc` inside the SysV-composed top stack page. `staged`
    // carries the IPC buffer VA + stack bounds the loader stamped
    // into the auxv / startup block; `phase_start` forwards them
    // to `TCB_SET_STACK_BOUNDS` + `TCB_CONFIGURE` so the kernel can
    // fastpath syscalls and enforce stack-overflow detection from
    // the very first instruction.
    //
    // `phase_start` borrows `bundle`; it must run before
    // `phase_install_proc_record` which moves `bundle` by value.
    let configured_start_tcb = match phase::phase_start(
        plan,
        &bundle,
        staged.entry_pc,
        staged.child_sp,
        staged.ipc_buffer_va,
        staged.stack_top,
        staged.stack_min,
        staged.guard_bottom,
    ) {
        Ok(tcb) => tcb,
        Err(err) => {
            rollback_unpublished_process(state, plan, pid, client_id, bundle);
            return Err(log_phase_failure(plan, b"start", err));
        }
    };

    // Moves `bundle` into ProcessRecord; no further borrow of bundle is valid.
    phase::phase_install_proc_record(state, plan, pid, bundle, &staged);

    let deferred_start_tcb = match plan.kind {
        SpawnKind::Service { .. } => {
            if configured_start_tcb != 0 {
                let err = invoke::tcb_start(CapRef::flat(configured_start_tcb));
                if err != 0 {
                    finalize_exit(state, pid, -1);
                    state.procs.release(pid);
                    return Err(log_phase_failure(plan, b"start", err));
                }
            }
            0
        }
        SpawnKind::Fork { .. } => configured_start_tcb,
        SpawnKind::Exec { .. } => 0,
    };

    // vfs is the one core server init never gets a client-exit signal for:
    // vfs's request MP stays open (it retains its own send side) and no
    // client sends an exit notice. Mint init's per-server VFS ROOT control
    // cap from vfs's freshly-created `service_ep_send`; it authorizes only
    // `VFS_ADMIN_REGISTER_CLIENT`, and every per-client admin verb (FD clone,
    // exec sweep, deregister) is driven on the control cap vfs mints and
    // returns at register.
    if vfs_service_ep_send_addr != 0 {
        match crate::supervisor::boot_core::mint_from_raw_send(
            vfs_service_ep_send_addr,
            trona_protocol::control::encode_root(),
            b"vfs root control cap",
        ) {
            Ok(cap) => state.caps.vfs_root_control_cap = Some(cap),
            Err(err) => {
                // Without the ROOT control cap init can drive no VFS admin
                // verb, so fork FD inheritance, the exec CLOEXEC sweep, and
                // client deregister would all silently no-op system-wide. Halt
                // loudly rather than boot into that degraded state.
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[INIT] FATAL: vfs root control cap mint failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" - init cannot drive VFS admin; halting.\n");
                });
                panic!("vfs root control cap mint failed");
            }
        }
    }
    phase::phase_publish_lifecycle(state, plan, pid);

    Ok(RealizeOutcome {
        child_pid: pid,
        deferred_start_tcb,
    })
}

// ---------------------------------------------------------------------------
// Public entry points called from `dispatch::handle_request_mp`.
// Every entry point builds a `BootstrapPlan` and hands it to
// `realize_process`.
// ---------------------------------------------------------------------------

/// `INIT_SPAWN(svc_idx, flags; argv/envp blob in IPC overflow)`.
pub fn handle_spawn(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let svc_idx = request.regs[0] as usize;
    let _flags = request.regs[1];

    if svc_idx >= state.manifest.count {
        reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
        return;
    }
    let def = state.manifest.services[svc_idx];
    let stack_spec = def.stack_layout_spec();

    // Resolve the service binary from the initrd and compute the *layout*
    // before `realize_process` runs. mmsrv's `MM_REGISTER_CLIENT` happens
    // before the loader stages bytes (the layout is what registers the
    // client); the loader's `plan_for_closure` reuses the same spans and
    // produces a bit-for-bit identical plan, so the registered layout is
    // guaranteed to match every staged run and every later mmap window.
    //
    // The pre-parse mirrors `loader::plan_for_closure` but stops at the
    // VmLayoutPlan — staging itself runs in `phase_stage` against the live
    // state, and re-parsing the bytes there would double the work.
    let client_layout = match compute_spawn_layout(state, &def, stack_spec) {
        Ok(l) => l,
        Err(err) => {
            reply.label = err as u64;
            return;
        }
    };

    let plan = BootstrapPlan {
        kind: SpawnKind::Service { svc_idx },
        parent_pid: Some(caller_pid),
        def,
        address_space: AddressSpacePlan::FreshImage,
        stack_spec,
        client_layout,
    };

    match realize_process(state, &plan, None) {
        Ok(outcome) => {
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = outcome.child_pid as u64;
        }
        Err(err) => {
            reply.label = err as u64;
        }
    }
}

/// Compute the per-process layout for a service spawn from its initrd
/// binary. Mirrors `loader::plan_for_closure` but stops at the
/// `VmLayoutPlan` — staging runs later in `phase_stage`.
///
/// Service spawn's ELF images carry the closure on disk, so the main
/// image's ELF is parsed to derive the span; the interpreter is loaded
/// from `/lib/<interp>` and its span folded in; DT_NEEDED closure is
/// resolved recursively. PE images carry a preloaded `kernel32.dll`
/// and an ELF rtld (`ldtrona-pe.so`) — same shape, different
/// resolver.
///
/// `def` provides the binary path (for service spawn) and the stack
/// policy. The binary path is read directly so callers that already
/// know the initrd path (boot_core deriving init's own layout from its
/// own `/bin/init`) can pass a synthesised `ServiceDef::empty_named`
/// carrying the right binary name.
pub fn compute_spawn_layout(
    state: &SupervisorState,
    def: &ServiceDef,
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
) -> Result<VmClientLayout, i32> {
    use trona_runtime::spawn::layout::compute_vm_layout;
    let binary_path = def.binary.as_bytes();
    let Some(image_bytes) = crate::supervisor::loader::cpio::find_file(state, binary_path) else {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    };
    if crate::supervisor::loader::pe::is_pe_header(image_bytes) {
        return compute_spawn_layout_pe(state, image_bytes, stack_spec);
    }
    let main_image = match crate::supervisor::loader::elf::parse(image_bytes) {
        Ok(i) => i,
        Err(_) => return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32),
    };
    let closure =
        match crate::supervisor::loader::dso::resolve(state, &main_image, binary_path, false) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
    let mut spans: [u64; 16] = [0; 16];
    let needed_count = closure.needed_len;
    for i in 0..needed_count {
        if let Some(dso) = closure.needed[i].as_ref() {
            spans[i] = dso.span;
        }
    }
    let interp_span = closure.interp.as_ref().map(|i| i.span).unwrap_or(0);
    let plan = compute_vm_layout(
        closure.main.span,
        interp_span,
        &spans[..needed_count],
        false,
        0,
        stack_spec,
    )
    .map_err(|e| e.wire_code() as i32)?;
    Ok(plan.client_layout())
}

fn compute_spawn_layout_pe(
    state: &SupervisorState,
    image_bytes: &[u8],
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
) -> Result<VmClientLayout, i32> {
    crate::supervisor::loader::pe::compute_pe_layout(state, image_bytes, stack_spec)
}

/// `INIT_FORK(saved_rsp, child_entry)` — duplicate the parent
/// process via COW. The two register values flow through from
/// `lib/trona/posix/arch/<arch>/fork.S`'s `_posix_fork_impl` IPC:
/// `saved_rsp` is the RSP the parent's trampoline captured after
/// pushing callee-saved registers; `child_entry` is the
/// `fork_child_entry` label address in the child image. Init
/// passes both through `TCB_CONFIGURE` so the child resumes inside
/// the trampoline with the correct initial register state.
pub fn handle_fork(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) -> PostReplyAction {
    let (caller_client_id, def) = match state.procs.get(caller_pid) {
        Some(p) => (p.client_id(), ServiceDef::empty_named(p.name)),
        None => {
            reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            return PostReplyAction::None;
        }
    };
    let saved_rsp = request.regs[0];
    let child_entry = request.regs[1];
    if request.length <= 9 || request.regs[9] == 0 {
        reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
        return PostReplyAction::None;
    }
    let tls_base = request.regs[9];
    // Fork inherits the parent's current layout. The parent's proc-record
    // `layout` is the layout mmsrv stamped at register time, which is
    // already layout-derived (service spawn pre-parses; exec swap sets
    // it; fork-parent saw its own layout at register). If the parent's
    // record is missing, the caller never registered — a programming
    // error, not a runtime fallback path.
    let Some(parent_layout) = state.procs.get(caller_pid).map(|p| p.layout) else {
        reply.label = uapi::KERNITE_ERR_INVALID_OPERATION as u64;
        return PostReplyAction::None;
    };
    let plan = BootstrapPlan {
        kind: SpawnKind::Fork {
            parent_pid: caller_pid,
            saved_rsp,
            child_entry,
            tls_base,
        },
        parent_pid: Some(caller_pid),
        def,
        address_space: AddressSpacePlan::ForkCow {
            parent_client_id: caller_client_id,
        },
        stack_spec: def.stack_layout_spec(),
        client_layout: parent_layout,
    };
    match realize_process(state, &plan, None) {
        Ok(outcome) => {
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = outcome.child_pid as u64;
            if outcome.deferred_start_tcb != 0 {
                return PostReplyAction::StartProcess {
                    pid: outcome.child_pid,
                    tcb: outcome.deferred_start_tcb,
                };
            }
        }
        Err(err) => reply.label = err as u64,
    }
    PostReplyAction::None
}

/// `INIT_EXEC(path, argv, envp, exec_size, exec_offset; caps=[exec_mo])` — replace the
/// caller's process image with the binary the caller resolved under its own
/// VFS authority and forwarded as a non-exec backing MemoryObject. The exact
/// byte size and file offset travel in the request so ldsrv hashes the same
/// image VFS opened, not the page-rounded MemoryObject extent. The caller keeps
/// its identity (client_id, endpoints) across exec; a synthetic empty-named def
/// carries the standard cap profile.
///
/// The exec MemoryObject is taken out of the receive window up front and
/// dropped on every exit; `handle_exec_inner` carries the body.
pub fn handle_exec(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let exec_mo_slot =
        match crate::supervisor::recv_window::move_user_cap_to_owned_slot(0, b"init exec mo") {
            Ok(s) => s,
            Err(err) => {
                reply.label = err as u64;
                return;
            }
        };

    match handle_exec_inner(state, request, caller_pid, exec_mo_slot) {
        Ok(child_pid) => {
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = child_pid as u64;
        }
        Err(err) => reply.label = err as u64,
    }

    // SAFETY: `exec_mo_slot` is the allocator-owned slot
    // `move_user_cap_to_owned_slot` handed us; this is its sole owner, and
    // the exec transaction dup'd the cap for mmsrv, so dropping it here
    // does not disturb the staged image.
    unsafe { crate::supervisor::recv_window::drop_owned_cap(exec_mo_slot) };
}

fn handle_exec_inner(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    exec_mo_slot: u64,
) -> Result<u32, i32> {
    let (caller_client_id, name) = state
        .procs
        .get(caller_pid)
        .map(|p| (p.client_id(), p.name))
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;

    // Parse the path-based request and copy argv/envp out of the IPC
    // buffer before reading the headers reuses it.
    let mut path_buf = [0u8; exec_load::MAX_EXEC_PATH + 1];
    let mut str_buf = [0u8; exec_load::EXEC_STR_BUF];
    let layout = exec_load::parse_exec_request(request, &mut path_buf, &mut str_buf)?;

    // The caller opened the image through the VFS under its own credential
    // (X_OK / MNT_NOEXEC) and passed the non-exec backing. ldsrv confers EXECUTE
    // — relaying a PE out to a memory image first — and returns the R-X code MO
    // the loader stages; it never re-opens by path, so the caller's access check
    // stands. Headers are read from the code MO via MO_READ (recoverable — a
    // pager failure never faults init).
    let backing = trona_runtime::core::slot_alloc::resolved_cap_ref(exec_mo_slot);
    let backing_xfer = trona_runtime::core::slot_alloc::dup_for_transfer(backing)
        .ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
    // `resolve_main` rides init's private exec-control MP, not the public
    // resolve endpoint — ldsrv refuses `RESOLVE_MAIN` anywhere else.
    let control_ep = state
        .ldsrv_exec_control_send
        .as_ref()
        .map(|c| c.as_raw())
        .unwrap_or(0);
    let resolved = unsafe {
        trona_runtime::client::ldsrv::resolve_main(
            control_ep,
            backing_xfer,
            layout.exec_size,
            layout.exec_offset,
        )
    }
    .map_err(|e| e as i32)?;
    let exec_mo = trona_runtime::core::slot_alloc::resolved_cap_ref(resolved.code_mo.as_raw());
    let mut header_buf = [0u8; exec_load::EXEC_HEADER_MAX];
    let header_len = exec_load::read_exec_headers(exec_mo, &mut header_buf)?;

    // Materialise the borrowed argv/envp slices from the copied blob.
    let mut argv: [&[u8]; exec_load::MAX_EXEC_ARGS] = [&[]; exec_load::MAX_EXEC_ARGS];
    let mut envp: [&[u8]; exec_load::MAX_EXEC_ARGS] = [&[]; exec_load::MAX_EXEC_ARGS];
    for i in 0..layout.argc {
        let (s, l) = layout.arg_off[i];
        argv[i] = &str_buf[s as usize..s as usize + l as usize];
    }
    for i in 0..layout.envc {
        let (s, l) = layout.env_off[i];
        envp[i] = &str_buf[s as usize..s as usize + l as usize];
    }
    let exec_image = ExecImage {
        exec_mo,
        header_bytes: &header_buf[..header_len],
        name: &path_buf[..layout.path_len],
        argv: &argv[..layout.argc],
        envp: &envp[..layout.envc],
    };

    let def = ServiceDef::empty_named(name);
    let stack_spec = def.stack_layout_spec();
    // Compute a layout for the new image BEFORE opening the exec transaction,
    // so `MM_BEGIN_EXEC_REPLACE` can carry the layout in regs.
    let new_client_layout = compute_exec_layout(state, exec_image.header_bytes, stack_spec)?;

    let plan = BootstrapPlan {
        kind: SpawnKind::Exec {
            existing_pid: caller_pid,
        },
        parent_pid: Some(caller_pid),
        def,
        address_space: AddressSpacePlan::ExecReplace {
            existing_client_id: caller_client_id,
        },
        stack_spec,
        client_layout: new_client_layout,
    };

    let outcome = realize_process(state, &plan, Some(exec_image));
    // Keep the R-X code MO alive until mmsrv has staged (and dup'd) the image.
    drop(resolved);
    Ok(outcome?.child_pid)
}

/// Compute the per-process layout for an exec target from its headers.
/// ELF path-exec has an initrd-resident interpreter and lets rtld resolve
/// DT_NEEDED at runtime. PE has the same shape as a service spawn: main
/// image + `ldtrona-pe.so` interpreter + preloaded `kernel32.dll`.
fn compute_exec_layout(
    state: &SupervisorState,
    header_bytes: &[u8],
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
) -> Result<VmClientLayout, i32> {
    if crate::supervisor::loader::pe::is_pe_header(header_bytes) {
        compute_exec_layout_pe(state, header_bytes, stack_spec).map_err(|e| e.wire_code() as i32)
    } else {
        compute_exec_layout_elf(state, header_bytes, stack_spec).map_err(|e| e.wire_code() as i32)
    }
}

fn compute_exec_layout_pe(
    state: &SupervisorState,
    header_bytes: &[u8],
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
) -> Result<VmClientLayout, LayoutError> {
    // PE exec shares the spawn layout contract — the loader stages the
    // same main image + `ldtrona-pe.so` + `kernel32.dll`, so the planner
    // must reserve the same windows. Both paths go through
    // `pe::compute_pe_layout` to keep them in lockstep.
    crate::supervisor::loader::pe::compute_pe_layout(state, header_bytes, stack_spec)
        .map_err(|_| LayoutError::HeapWindowEmpty)
}

fn compute_exec_layout_elf(
    state: &SupervisorState,
    header_bytes: &[u8],
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
) -> Result<VmClientLayout, LayoutError> {
    use trona_loader::common::elf::header::{get_interp, has_interp, load_span};
    use trona_runtime::spawn::layout::page_align_up;

    let image = match crate::supervisor::loader::elf::parse(header_bytes) {
        Ok(img) => img,
        Err(_) => return Err(LayoutError::HeapWindowEmpty),
    };
    let elf_span = match load_span(image.phdrs) {
        Some((lo, hi)) => page_align_up(hi.saturating_sub(lo)),
        None => 0,
    };
    let interp_span = if has_interp(image.phdrs) {
        let path = match unsafe { get_interp(image.bytes.as_ptr(), image.phdrs) } {
            Some(p) => p,
            None => return Err(LayoutError::HeapWindowEmpty),
        };
        let interp_bytes = match crate::supervisor::loader::cpio::find_file(state, path) {
            Some(b) => b,
            None => return Err(LayoutError::HeapWindowEmpty),
        };
        let interp_image = match crate::supervisor::loader::elf::parse(interp_bytes) {
            Ok(img) => img,
            Err(_) => return Err(LayoutError::HeapWindowEmpty),
        };
        match load_span(interp_image.phdrs) {
            Some((lo, hi)) => page_align_up(hi.saturating_sub(lo)),
            None => 0,
        }
    } else {
        0
    };
    let plan = compute_vm_layout(elf_span, interp_span, &[], false, 0, stack_spec)?;
    Ok(plan.client_layout())
}

/// `INIT_EXIT(status)`. No reply (Send only).
pub fn handle_exit(state: &mut SupervisorState, request: &TronaMsg, caller_pid: u32) {
    let status = request.regs[0] as i32;
    finalize_exit(state, caller_pid, status);
}
