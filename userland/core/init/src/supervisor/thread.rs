// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_THREAD` sub-op handler. pthread_create / pthread_exit /
//! pthread_join / pthread_detach / get_thread_caps. Threads live
//! inside their parent process; init only allocates new TCB / SC /
//! per-thread fault MP.

use trona_kernel::core_types::TronaMsg;
use trona_kernel::invoke;
use trona_protocol::common::TRONA_OK;
use trona_runtime::core::slot_alloc::{OwnedCap, resolved_cap_ref};

use crate::supervisor::SupervisorState;
use crate::supervisor::proc_table::{ThreadRecord, ThreadState};
use crate::supervisor::retype::RetypeClass;
use crate::supervisor::rsrc_ipc::{rsrc_alloc_mp_pair_recorded, rsrc_alloc_recorded, rsrc_free};
use crate::supervisor::spawn::fault_wire::{bind_fault_caps, register_fault_pipe};
use crate::supervisor::spawn::tcb::{
    SchedParams, sc_bind, sc_configure, tcb_configure, tcb_set_space, tcb_set_stack_bounds,
};
use crate::wire::{
    THREAD_SUB_CREATE, THREAD_SUB_DETACH, THREAD_SUB_EXIT, THREAD_SUB_GET_THREAD_CAPS,
    THREAD_SUB_JOIN, THREAD_SUB_REAP,
};

#[derive(Clone, Copy)]
pub enum PostReplyAction {
    None,
    StartThread { pid: u32, tid: u16, tcb: u64 },
    StartProcess { pid: u32, tcb: u64 },
}

pub fn handle(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply_endpoint_slot: u64,
    reply: &mut TronaMsg,
) -> PostReplyAction {
    let sub = request.regs[0];
    match sub {
        THREAD_SUB_CREATE => create_thread(state, request, caller_pid, reply),
        THREAD_SUB_EXIT => {
            exit_thread(state, request, caller_pid, reply);
            PostReplyAction::None
        }
        THREAD_SUB_JOIN => {
            join_thread(state, request, caller_pid, reply_endpoint_slot, reply);
            PostReplyAction::None
        }
        THREAD_SUB_DETACH => {
            detach_thread(state, request, caller_pid, reply);
            PostReplyAction::None
        }
        THREAD_SUB_REAP => {
            reap_joined_thread(state, request, caller_pid, reply);
            PostReplyAction::None
        }
        THREAD_SUB_GET_THREAD_CAPS => {
            get_thread_caps(state, request, caller_pid, reply);
            PostReplyAction::None
        }
        _ => {
            reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            PostReplyAction::None
        }
    }
}

fn create_thread(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) -> PostReplyAction {
    let entry_va = request.regs[1];
    let entry_rsp = request.regs[2];
    let tls_base = request.regs[3];
    let ipc_buf_vaddr = request.regs[4];
    let attr_flags = request.regs[5];
    let stack_base = request.regs[6];
    let stack_guard_bottom = request.regs[7];
    let reserve_top = request.regs[8];
    let budget_ns = if request.length >= 11 {
        request.regs[9]
    } else {
        0
    };
    let period_ns = if request.length >= 11 {
        request.regs[10]
    } else {
        0
    };

    if request.length < 9
        || entry_va == 0
        || entry_rsp == 0
        || ipc_buf_vaddr == 0
        || (ipc_buf_vaddr & 0xFFF) != 0
        || stack_base == 0
        || reserve_top == 0
        || stack_base >= reserve_top
        || (stack_base & 0xFFF) != 0
        || (reserve_top & 0xFFF) != 0
        || entry_rsp <= stack_base
        || entry_rsp > reserve_top
    {
        reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
        return PostReplyAction::None;
    }

    let (client_id, cspace, vspace) = match state.procs.get(caller_pid) {
        Some(p) => (
            p.client_id(),
            p.cspace.as_ref().map(OwnedCap::borrow).unwrap_or_default(),
            p.vspace.as_ref().map(OwnedCap::borrow).unwrap_or_default(),
        ),
        None => {
            reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            return PostReplyAction::None;
        }
    };
    if cspace.is_null() || vspace.is_null() {
        reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
        return PostReplyAction::None;
    }
    // SAFETY: slab backing bound at boot; single-threaded owner.
    let reserved = match unsafe {
        state
            .procs
            .reserve_thread_slot(caller_pid, &mut state.self_vm)
    } {
        Some(r) => r,
        None => {
            reply.label = uapi::KERNITE_ERR_OUT_OF_MEMORY as u64;
            return PostReplyAction::None;
        }
    };
    let tid = reserved.tid;

    // Allocate TCB / SC / fault MP pair through rsrcsrv. Caller
    // wrapper has already armed the receive window.
    const THREAD_CAP_WINDOW_LEN: u64 = 4;
    let recv_base = trona_runtime::core::slot_alloc::slot_alloc_consecutive_or_idle(
        THREAD_CAP_WINDOW_LEN,
        b"init thread receive window",
    );
    if recv_base == 0 {
        reply.label = uapi::KERNITE_ERR_OUT_OF_MEMORY as u64;
        return PostReplyAction::None;
    }

    let mp = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    let ipc_ctx = trona_runtime::current_ipc_ctx();

    let tcb_rec = match rsrc_alloc_recorded(mp, RetypeClass::Tcb, 0, recv_base, ipc_ctx) {
        Ok(r) => r,
        Err(e) => {
            cleanup_thread_alloc_range(recv_base, THREAD_CAP_WINDOW_LEN);
            reply.label = e as u64;
            return PostReplyAction::None;
        }
    };
    let tcb_slot = tcb_rec.cap_slot;
    let sc_rec = match rsrc_alloc_recorded(mp, RetypeClass::SchedContext, 0, recv_base + 1, ipc_ctx)
    {
        Ok(r) => r,
        Err(e) => {
            cleanup_thread_alloc_range(recv_base, THREAD_CAP_WINDOW_LEN);
            reply.label = e as u64;
            return PostReplyAction::None;
        }
    };
    let sc_slot = sc_rec.cap_slot;
    let flt = match rsrc_alloc_mp_pair_recorded(mp, recv_base + 2, ipc_ctx) {
        Ok(p) => p,
        Err(e) => {
            cleanup_thread_alloc_range(recv_base, THREAD_CAP_WINDOW_LEN);
            reply.label = e as u64;
            return PostReplyAction::None;
        }
    };
    let (flt_send_slot, flt_recv_slot) = (flt.send_slot, flt.recv_slot);
    // SAFETY: flt_recv_slot was just filled by rsrc_alloc_mp_pair_recorded and
    // is consumed by mmsrv registration below.
    let fault_recv = unsafe { OwnedCap::adopt_received(flt_recv_slot) };
    if let Err(e) = register_fault_pipe(state, client_id, tid as u32, fault_recv) {
        cleanup_thread_alloc_range_except(recv_base, THREAD_CAP_WINDOW_LEN, flt_recv_slot);
        reply.label = e as u64;
        return PostReplyAction::None;
    }
    if let Err(e) = bind_fault_caps(resolved_cap_ref(tcb_slot), resolved_cap_ref(flt_send_slot)) {
        cleanup_thread_alloc_range_except(recv_base, THREAD_CAP_WINDOW_LEN, flt_recv_slot);
        reply.label = e as u64;
        return PostReplyAction::None;
    }
    if let Err(e) = tcb_set_space(resolved_cap_ref(tcb_slot), cspace, vspace, 0) {
        cleanup_thread_alloc_range_except(recv_base, THREAD_CAP_WINDOW_LEN, flt_recv_slot);
        reply.label = e as u64;
        return PostReplyAction::None;
    }
    if let Err(e) = tcb_set_stack_bounds(
        resolved_cap_ref(tcb_slot),
        reserve_top,
        stack_base,
        stack_guard_bottom,
    ) {
        cleanup_thread_alloc_range_except(recv_base, THREAD_CAP_WINDOW_LEN, flt_recv_slot);
        reply.label = e as u64;
        return PostReplyAction::None;
    }
    if let Err(e) = tcb_configure(
        resolved_cap_ref(tcb_slot),
        entry_va,
        entry_rsp,
        ipc_buf_vaddr,
    ) {
        cleanup_thread_alloc_range_except(recv_base, THREAD_CAP_WINDOW_LEN, flt_recv_slot);
        reply.label = e as u64;
        return PostReplyAction::None;
    }
    let err = invoke::tcb_set_tls_base(resolved_cap_ref(tcb_slot), tls_base);
    if err != 0 {
        cleanup_thread_alloc_range_except(recv_base, THREAD_CAP_WINDOW_LEN, flt_recv_slot);
        reply.label = err as u64;
        return PostReplyAction::None;
    }
    let mut sched = SchedParams::fair_default();
    if budget_ns != 0 {
        sched.budget_ns = budget_ns;
    }
    if period_ns != 0 {
        sched.period_ns = period_ns;
    }
    if let Err(e) = sc_configure(resolved_cap_ref(sc_slot), sched)
        .and_then(|_| sc_bind(resolved_cap_ref(sc_slot), resolved_cap_ref(tcb_slot)))
    {
        cleanup_thread_alloc_range_except(recv_base, THREAD_CAP_WINDOW_LEN, flt_recv_slot);
        reply.label = e as u64;
        return PostReplyAction::None;
    }
    let detached = (attr_flags & 1) != 0;
    let rec = ThreadRecord {
        state: if detached {
            ThreadState::Detached
        } else {
            ThreadState::Running
        },
        // SAFETY: these slots were just filled through init's receive window.
        // The fault recv side was consumed by mmsrv registration above.
        tcb: Some(unsafe { OwnedCap::adopt_received(tcb_slot) }),
        sc: Some(unsafe { OwnedCap::adopt_received(sc_slot) }),
        fault_mp_recv: None,
        fault_mp_send: Some(unsafe { OwnedCap::adopt_received(flt_send_slot) }),
        join_token: None,
        tid,
        exit_status: 0,
        tcb_record_id: tcb_rec.record_id,
        sc_record_id: sc_rec.record_id,
        fault_mp_record_id: flt.core_record_id,
    };
    // SAFETY: `reserved` from reserve_thread_slot above; same pid, no
    // intervening structural change to the thread chain.
    if !unsafe { state.procs.install_reserved_thread(&reserved, rec) } {
        // Failed install drops the moved ThreadRecord without publishing it;
        // fault-recv was already transferred to mmsrv and locally reclaimed.
        reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
        return PostReplyAction::None;
    }

    reply.label = TRONA_OK;
    reply.length = 4;
    reply.regs[0] = tid as u64;
    reply.regs[1] = tcb_slot;
    reply.regs[2] = sc_slot;
    reply.regs[3] = flt_send_slot;
    PostReplyAction::StartThread {
        pid: caller_pid,
        tid,
        tcb: tcb_slot,
    }
}

pub fn finish_post_reply_action(
    state: &mut SupervisorState,
    action: PostReplyAction,
    reply_delivered: bool,
) {
    match action {
        PostReplyAction::None => {}
        PostReplyAction::StartThread { pid, tid, tcb } => {
            if !reply_delivered {
                abort_created_thread(state, pid, tid);
                return;
            }
            let err = invoke::tcb_start(resolved_cap_ref(tcb));
            if err != 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[INIT] deferred thread start failed tid=");
                    _lb.dec(tid as u64);
                    _lb.str(b" err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                abort_created_thread(state, pid, tid);
            }
        }
        PostReplyAction::StartProcess { pid, tcb } => {
            if !reply_delivered {
                crate::supervisor::lifecycle::finalize_exit(
                    state,
                    pid,
                    -(uapi::KERNITE_ERR_PEER_CLOSED as i32),
                );
                return;
            }
            let err = invoke::tcb_start(resolved_cap_ref(tcb));
            if err != 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[INIT] deferred process start failed pid=");
                    _lb.dec(pid as u64);
                    _lb.str(b" err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                crate::supervisor::lifecycle::finalize_exit(state, pid, -err);
            }
        }
    }
}

fn abort_created_thread(state: &mut SupervisorState, pid: u32, tid: u16) {
    let rsrcsrv_mp = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    if let Some(t) = state.procs.find_thread_mut(pid, tid) {
        reap_thread_caps(t, rsrcsrv_mp);
        *t = ThreadRecord::empty();
    }
}

fn cleanup_thread_alloc_range(base: u64, count: u64) {
    cleanup_thread_alloc_range_except(base, count, 0);
}

fn cleanup_thread_alloc_range_except(base: u64, count: u64, skip_slot: u64) {
    for off in 0..count {
        let slot = base + off;
        if slot == skip_slot {
            continue;
        }
        // SAFETY: [base, base+count) is this thread's own consecutive cap-alloc
        // range being torn down once. delete_and_free resolves each slot depth.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(slot) };
    }
}

fn reap_thread_caps(thread: &mut ThreadRecord, rsrcsrv_mp: u64) {
    if let Some(tcb) = thread.tcb.as_ref() {
        let _ = invoke::tcb_kill(tcb.borrow());
    }
    // Drop OwnedCap fields — Drop calls delete_and_free on each.
    let _ = thread.tcb.take();
    let _ = thread.sc.take();
    let _ = thread.fault_mp_recv.take();
    let _ = thread.fault_mp_send.take();
    // Release the rsrcsrv records backing this thread's kernel objects.
    // They were retyped under init's owner in `create_thread`, so
    // `owner_exited(process)` never reclaims them; without this the records
    // and the untyped chunks they were carved from leak for the life of the
    // system. Idempotent — a thread may be reaped twice (exit then join),
    // so the record ids are zeroed after freeing.
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    for record_id in [
        thread.tcb_record_id,
        thread.sc_record_id,
        thread.fault_mp_record_id,
    ] {
        if record_id != 0 {
            let _ = rsrc_free(rsrcsrv_mp, record_id, ipc_ctx);
        }
    }
    thread.tcb_record_id = 0;
    thread.sc_record_id = 0;
    thread.fault_mp_record_id = 0;
}

fn exit_thread(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let tid = request.regs[1] as u16;
    let status = request.regs[2];
    let rsrcsrv_mp = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    if let Some(t) = state.procs.find_thread_mut(caller_pid, tid) {
        let was_detached = t.state == ThreadState::Detached;
        // Drop join_token OwnedCap — its Drop handles delete_and_free.
        let _ = t.join_token.take();
        reap_thread_caps(t, rsrcsrv_mp);
        if was_detached {
            *t = ThreadRecord::empty();
        } else {
            t.exit_status = status;
            t.state = ThreadState::Joinable;
        }
    }
    reply.label = TRONA_OK;
    reply.length = 0;
}

fn join_thread(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    _reply_endpoint_slot: u64,
    reply: &mut TronaMsg,
) {
    let tid = request.regs[1] as u16;
    let rsrcsrv_mp = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    if let Some(t) = state.procs.find_thread_mut(caller_pid, tid) {
        if t.state == ThreadState::Joinable || t.state == ThreadState::Exited {
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = t.exit_status as u64;
            reap_thread_caps(t, rsrcsrv_mp);
            t.state = ThreadState::Exited;
            return;
        }
        if t.state == ThreadState::Detached {
            reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            return;
        }
        reply.label = uapi::KERNITE_ERR_WOULD_BLOCK as u64;
        return;
    }
    reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
}

fn reap_joined_thread(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let tid = request.regs[1] as u16;
    let rsrcsrv_mp = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    if let Some(t) = state.procs.find_thread_mut(caller_pid, tid) {
        match t.state {
            ThreadState::Joinable | ThreadState::Exited => {
                reap_thread_caps(t, rsrcsrv_mp);
                *t = ThreadRecord::empty();
            }
            ThreadState::Empty => {}
            ThreadState::Running | ThreadState::Detached => {
                reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
                return;
            }
        }
    }
    reply.label = TRONA_OK;
    reply.length = 0;
}

fn detach_thread(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let tid = request.regs[1] as u16;
    let rsrcsrv_mp = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    if let Some(t) = state.procs.find_thread_mut(caller_pid, tid) {
        if t.join_token.is_some() {
            reply.label = uapi::KERNITE_ERR_ALREADY_EXISTS as u64;
            return;
        }
        match t.state {
            ThreadState::Joinable | ThreadState::Exited => {
                reap_thread_caps(t, rsrcsrv_mp);
                *t = ThreadRecord::empty();
            }
            _ => t.state = ThreadState::Detached,
        }
        reply.label = TRONA_OK;
        reply.length = 0;
    } else {
        reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
    }
}

fn get_thread_caps(
    state: &mut SupervisorState,
    _request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let proc = match state.procs.get(caller_pid) {
        Some(p) => p,
        None => {
            reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            return;
        }
    };
    reply.label = TRONA_OK;
    reply.length = 3;
    reply.regs[0] = proc
        .main_tcb
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    reply.regs[1] = proc
        .sched_context
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    reply.regs[2] = proc
        .fault_mp_send
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
}
