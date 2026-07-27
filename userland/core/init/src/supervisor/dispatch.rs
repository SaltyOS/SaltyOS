// SPDX-License-Identifier: GPL-2.0-only
//
//! Label dispatch — routes per-client request MP and master-service
//! MP traffic to the matching subsystem handler. The owner reactor
//! calls into here every time `EQ_WAIT` returns a record whose Watch
//! cookie marks an MP recv side as readable.

use trona_kernel::core_types::TronaMsg;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::MpReplyTarget;

use crate::supervisor::SupervisorState;
use crate::supervisor::lifecycle::{
    WaitOutcome, handle_exec, handle_exit, handle_fork, handle_spawn, handle_wait,
};
use crate::supervisor::manifest::ReadinessSource;
use crate::supervisor::owner_loop::OwnerCtx;
use crate::wire::{
    LABEL_CORE_READY, LABEL_CRED, LABEL_DEBUG_DUMP_TABLE, LABEL_EXEC, LABEL_EXIT, LABEL_FORK,
    LABEL_GET_ABI_VERSION, LABEL_GET_BOOTINFO_FRAME, LABEL_GET_PID, LABEL_GET_PPID,
    LABEL_GET_PROC_INFO, LABEL_ITIMER, LABEL_KILL, LABEL_KILL_PGID, LABEL_LIFECYCLE_SUBSCRIBE,
    LABEL_LIFECYCLE_UNSUBSCRIBE, LABEL_NOTIFY_READY, LABEL_PGRP_SESSION, LABEL_REAP_BADGE,
    LABEL_REGISTER_FAULT_OBSERVER, LABEL_REGISTER_INTERFACE, LABEL_REPORT_FAULT,
    LABEL_RESOLVE_INTERFACE, LABEL_RLIMIT, LABEL_SERVICE_QUERY, LABEL_SIGACTION,
    LABEL_SIGPENDING_DUMP, LABEL_SPAWN, LABEL_THREAD, LABEL_UNREGISTER_FAULT_OBSERVER, LABEL_WAIT,
};

const KERNITE_ABI_PACKED: u64 = (0u64 << 32) | (0u64 << 16) | 1; // 0.0.1

/// A per-client request MP became readable. Read one record, dispatch
/// by label, and write one reply with `reply-marked MP_WRITE` on the same
/// MessagePipe recv endpoint.
pub fn handle_request_msg(
    state: &mut SupervisorState,
    ctx: &mut OwnerCtx,
    client_id: u32,
    request: &TronaMsg,
    badge: u64,
) {
    let received_cap_count = incoming_received_cap_count();
    let (proc_pid, reply_mp) = match state.find_proc_by_client_id_mut(client_id) {
        Some(p) => (
            p.pid,
            p.request_mp_recv
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr(),
        ),
        None => {
            let mut reply = TronaMsg::zeroed();
            reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
            send_mp_write_reply(&reply, MpReplyTarget::none(), received_cap_count);
            return;
        }
    };
    let reply_target = current_reply_target(reply_mp);

    let mut reply = TronaMsg::zeroed();
    let label = request.label;
    if label == LABEL_EXIT {
        drop_inbound_caps(received_cap_count);
        handle_exit(state, request, proc_pid);
        return;
    }
    let post_reply_action = dispatch_label(
        state,
        ctx,
        proc_pid,
        request,
        badge,
        &mut reply,
        label,
        reply_target,
    );
    let reply_delivered = send_mp_write_reply(&reply, reply_target, received_cap_count);
    crate::supervisor::thread::finish_post_reply_action(state, post_reply_action, reply_delivered);
}

/// Master service-EP MP became readable. Currently the only label
/// that arrives here is mmsrv's `INIT_REPORT_FAULT` (authenticated by
/// the `INIT_BADGE_FROM_MMSRV` badge on mmsrv's `ROLE_INIT_CONTROL`
/// cap); admin spawns from an external shell would arrive here too once
/// a privileged client exists.
pub fn handle_master_msg(
    state: &mut SupervisorState,
    _ctx: &mut OwnerCtx,
    request: &TronaMsg,
    badge: u64,
) {
    let received_cap_count = incoming_received_cap_count();
    let reply_mp = state
        .caps
        .master_service_mp_recv
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    let reply_target = current_reply_target(reply_mp);
    let mut reply = TronaMsg::zeroed();
    match request.label {
        LABEL_REPORT_FAULT => {
            crate::supervisor::fault::handle_report_fault(state, badge, &request.regs, &mut reply);
        }
        LABEL_GET_ABI_VERSION => {
            reply.label = trona_protocol::common::TRONA_OK;
            reply.length = 1;
            reply.regs[0] = KERNITE_ABI_PACKED;
        }
        LABEL_CORE_READY => {
            reply.label = u64::MAX;
        }
        _ => {
            reply.label = uapi::KERNITE_ERR_INVALID_OPERATION as u64;
        }
    }
    send_mp_write_reply(&reply, reply_target, received_cap_count);
}

pub fn handle_worker_completion(_state: &mut SupervisorState, _ctx: &mut OwnerCtx, worker_id: u32) {
    // Workers post their completion records as plain MP_WRITE into
    // the worker_completion EQ.
    let _ = worker_id;
}

pub fn handle_timer(state: &mut SupervisorState, _ctx: &mut OwnerCtx, timer_id: u32) {
    // Sweep itimers across the proc-table; deliver SIGALRM where the
    // deadline has passed.
    let _ = (state, timer_id);
}

/// One queued `NAMESRV_REGISTER_EVENT` arrived from namesrv's
/// subscribe MP. Read the prefix, feed it into
/// `unit_mgr::on_namesrv_register`, and try to spawn newly-unblocked
/// services. If namesrv pushed multiple events back-to-back, the
/// Watch on the recv side re-fires on the next `EQ_WAIT` so each
/// owner-loop iteration drains exactly one message.
pub fn handle_namesrv_register_event(
    state: &mut SupervisorState,
    _ctx: &mut OwnerCtx,
    msg: &TronaMsg,
) {
    use trona_protocol::namesrv::NAMESRV_REGISTER_EVENT;
    if msg.label != NAMESRV_REGISTER_EVENT {
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
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[INIT] namesrv ready ");
        _lb.bytes(&prefix[..written]);
        _lb.str(b"\n");
    });
    if let Err(err) = crate::supervisor::boot::drive_dispatch_ready(state) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] dispatch-ready failed err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
    }
}

fn dispatch_label(
    state: &mut SupervisorState,
    _ctx: &mut OwnerCtx,
    caller_pid: u32,
    request: &TronaMsg,
    badge: u64,
    reply: &mut TronaMsg,
    label: u64,
    reply_target: MpReplyTarget,
) -> crate::supervisor::thread::PostReplyAction {
    let _ = badge;
    let mut post_reply_action = crate::supervisor::thread::PostReplyAction::None;
    match label {
        LABEL_GET_ABI_VERSION => {
            reply.label = trona_protocol::common::TRONA_OK;
            reply.length = 1;
            reply.regs[0] = KERNITE_ABI_PACKED;
        }
        LABEL_GET_BOOTINFO_FRAME => {
            reply.label = trona_protocol::common::TRONA_OK;
            reply.length = 1;
            reply.regs[0] = state
                .caps
                .bootinfo_frame
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr();
        }
        LABEL_GET_PID => {
            reply.label = trona_protocol::common::TRONA_OK;
            reply.length = 1;
            reply.regs[0] = caller_pid as u64;
        }
        LABEL_GET_PPID => {
            reply.label = trona_protocol::common::TRONA_OK;
            reply.length = 1;
            reply.regs[0] = state
                .procs
                .get(caller_pid)
                .map(|p| p.parent_pid)
                .unwrap_or(0) as u64;
        }
        LABEL_SPAWN => handle_spawn(state, request, caller_pid, reply),
        LABEL_FORK => {
            post_reply_action = handle_fork(state, request, caller_pid, reply);
        }
        LABEL_EXEC => handle_exec(state, request, caller_pid, reply),
        LABEL_WAIT => match handle_wait(state, request, caller_pid, reply_target, reply) {
            WaitOutcome::Resolved => {}
            WaitOutcome::Parked => {
                // Skip emit — the reply endpoint is parked inside
                // the proc-table; the next matching child state
                // change emits the deferred reply.
                reply.label = u64::MAX;
            }
        },
        LABEL_KILL => {
            let target_pid = request.regs[0] as u32;
            let sig = request.regs[1] as u8;
            if !crate::supervisor::signal::is_known_signal(sig) {
                reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            } else {
                let delivered = crate::supervisor::signal::deliver_signal(
                    state, target_pid, sig, caller_pid, 0, 0, 0,
                );
                reply.label = match delivered {
                    crate::supervisor::signal::SignalDelivery::Invalid => {
                        uapi::KERNITE_ERR_NOT_FOUND as u64
                    }
                    _ => trona_protocol::common::TRONA_OK,
                };
            }
        }
        LABEL_KILL_PGID => {
            let pgid = request.regs[0] as u32;
            let sig = request.regs[1] as u8;
            if !crate::supervisor::signal::is_known_signal(sig) {
                reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            } else {
                const MAX_TARGETS: usize = 256;
                let mut targets = [0u32; MAX_TARGETS];
                let mut targets_len = 0usize;
                for p in state.procs.iter_active() {
                    if p.pgid == pgid && targets_len < targets.len() {
                        targets[targets_len] = p.pid;
                        targets_len += 1;
                    }
                }
                for pid in targets.iter().take(targets_len) {
                    let _ = crate::supervisor::signal::deliver_signal(
                        state, *pid, sig, caller_pid, 0, 0, 0,
                    );
                }
                reply.label = if targets_len == 0 {
                    uapi::KERNITE_ERR_NOT_FOUND as u64
                } else {
                    trona_protocol::common::TRONA_OK
                };
            }
        }
        LABEL_SIGACTION => {
            // Caller passes (signum, disposition_kind) → we update
            // the per-pid SignalState; handler entry point lives
            // inside the process.
            let signum = request.regs[0] as usize;
            let kind = request.regs[1] as u8;
            if let Some(proc) = state.procs.get_mut(caller_pid) {
                let idx = signum.min(crate::supervisor::signal::SIGNAL_COUNT - 1);
                let sig = &mut proc.signal_state;
                sig.dispositions[idx] = match kind {
                    1 => crate::supervisor::signal::SignalDisposition::Ignored,
                    2 => crate::supervisor::signal::SignalDisposition::Handled,
                    _ => crate::supervisor::signal::SignalDisposition::Default,
                };
                if sig.dispositions[idx].is_ignored_for(signum as u8) {
                    sig.pending_mask &= !(1u64 << (signum as u64).min(63));
                }
                reply.label = trona_protocol::common::TRONA_OK;
            } else {
                reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
            }
        }
        LABEL_SIGPENDING_DUMP => {
            if let Some(proc) = state.procs.get_mut(caller_pid) {
                let (pending, blocked) = crate::supervisor::signal::take_pending(proc);
                reply.label = trona_protocol::common::TRONA_OK;
                reply.length = 2;
                reply.regs[0] = pending;
                reply.regs[1] = blocked;
            } else {
                reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
            }
        }
        LABEL_CRED => crate::supervisor::cred::handle(state, request, caller_pid, reply),
        LABEL_PGRP_SESSION => {
            crate::supervisor::pgrp_session::handle(state, request, caller_pid, reply)
        }
        LABEL_RLIMIT => crate::supervisor::rlimit::handle(state, request, caller_pid, reply),
        LABEL_ITIMER => crate::supervisor::itimer::handle(state, request, caller_pid, reply),
        LABEL_THREAD => {
            post_reply_action = crate::supervisor::thread::handle(
                state,
                request,
                caller_pid,
                reply_target.mp_slot,
                reply,
            );
        }
        LABEL_GET_PROC_INFO => {
            crate::supervisor::proc_info::handle(state, request, caller_pid, reply)
        }
        LABEL_SERVICE_QUERY => crate::supervisor::service_query::handle(state, request, reply),
        LABEL_REGISTER_INTERFACE => handle_register_interface(state, request, caller_pid, reply),
        LABEL_RESOLVE_INTERFACE => handle_resolve_interface(state, request, reply),
        LABEL_REAP_BADGE => {
            // mmsrv / rsrcsrv tell us a foreign-process exit they
            // observed. Forward to finalize_exit.
            let pid = request.regs[0] as u32;
            let status = request.regs[1] as i32;
            crate::supervisor::lifecycle::finalize_exit(state, pid, status);
            reply.label = trona_protocol::common::TRONA_OK;
        }
        LABEL_LIFECYCLE_SUBSCRIBE => {
            let mask = request.regs[0] as u32;
            let hint_pid = request.regs[1] as u32;
            match crate::supervisor::recv_window::move_user_cap_to_owned_slot(
                0,
                b"init lifecycle observer",
            ) {
                Ok(raw_slot) => {
                    // SAFETY: move_user_cap_to_owned_slot moved the received cap
                    // into a fresh global slot we now solely own (depth resolved
                    // by adopt_received).
                    let mp_send = unsafe {
                        trona_runtime::core::slot_alloc::OwnedCap::adopt_received(raw_slot)
                    };
                    // SAFETY: slab backing bound at boot; single-threaded owner.
                    if unsafe {
                        state.lifecycle.subscribe(
                            mp_send,
                            mask,
                            hint_pid,
                            caller_pid,
                            &mut state.self_vm,
                        )
                    } {
                        reply.label = trona_protocol::common::TRONA_OK;
                    } else {
                        // subscribe took ownership on success; on failure it
                        // did not store it, so the OwnedCap drops here.
                        reply.label = uapi::KERNITE_ERR_OUT_OF_MEMORY as u64;
                    }
                }
                Err(err) => reply.label = err as u64,
            }
        }
        LABEL_LIFECYCLE_UNSUBSCRIBE => {
            let mp_send_addr = request.regs[0];
            state.lifecycle.unsubscribe(caller_pid, mp_send_addr);
            reply.label = trona_protocol::common::TRONA_OK;
        }
        LABEL_REGISTER_FAULT_OBSERVER => {
            match crate::supervisor::recv_window::move_user_cap_to_owned_slot(
                0,
                b"init fault observer",
            ) {
                Ok(raw_slot) => {
                    // SAFETY: move_user_cap_to_owned_slot moved the received cap
                    // into a fresh global slot we now solely own (depth resolved
                    // by adopt_received).
                    let mp_send = unsafe {
                        trona_runtime::core::slot_alloc::OwnedCap::adopt_received(raw_slot)
                    };
                    match crate::supervisor::fault::fault_observers().register(mp_send, caller_pid)
                    {
                        Ok(_) => reply.label = trona_protocol::common::TRONA_OK,
                        Err(_) => {
                            // register took ownership on success; on failure
                            // the OwnedCap drops here, releasing the slot.
                            reply.label = uapi::KERNITE_ERR_OUT_OF_MEMORY as u64;
                        }
                    }
                }
                Err(err) => reply.label = err as u64,
            }
        }
        LABEL_UNREGISTER_FAULT_OBSERVER => {
            let mp_send_addr = request.regs[0];
            crate::supervisor::fault::fault_observers().unregister(mp_send_addr);
            reply.label = trona_protocol::common::TRONA_OK;
        }
        LABEL_DEBUG_DUMP_TABLE => {
            reply.label = trona_protocol::common::TRONA_OK;
            reply.length = 1;
            reply.regs[0] = state.procs.count() as u64;
        }
        LABEL_NOTIFY_READY => {
            // Type=notify leaf service signaled readiness. Identity
            // comes from the per-client MP this call arrived on —
            // we resolve caller_pid → ProcessRecord.name →
            // manifest.find_index_by_name. The child sends no payload;
            // a compromised peer cannot misroute readiness because the
            // kernel cap system already pins each per-client MP to one
            // process, and we never trust caller-supplied indices.
            let resolved_idx = state
                .procs
                .get(caller_pid)
                .and_then(|p| state.manifest.find_index_by_name(p.name.as_bytes()));
            if let Some(idx) = resolved_idx {
                let name = state.manifest.services[idx].name;
                if state.manifest.services[idx].readiness_source()
                    != ReadinessSource::InitNotifyReady
                {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[INIT] ignored notify-ready from non-notify service ");
                        _lb.bytes(name.as_bytes());
                        _lb.str(b"\n");
                    });
                    reply.label = uapi::KERNITE_ERR_INVALID_OPERATION as u64;
                    return post_reply_action;
                }
                state.unit_graph.on_init_notify_ready(&state.manifest, idx);
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[INIT] notify ready ");
                    _lb.bytes(name.as_bytes());
                    _lb.str(b"\n");
                });
                if let Err(err) = crate::supervisor::boot::drive_dispatch_ready(state) {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[INIT] dispatch-ready failed err=");
                        _lb.hex(err as u64);
                        _lb.str(b"\n");
                    });
                }
                reply.label = trona_protocol::common::TRONA_OK;
            } else {
                reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64;
            }
        }
        _ => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[INIT] unknown label=");
                _lb.hex(label);
                _lb.str(b"\n");
            });
            reply.label = uapi::KERNITE_ERR_INVALID_OPERATION as u64;
        }
    }
    post_reply_action
}

fn handle_register_interface(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let key_len = request.regs[0] as usize;
    let mp_send_slot = request.regs[1];
    let mut buf = [0u8; 64];
    let words = (key_len + 7) / 8;
    for i in 0..words {
        let w = request.regs[2 + i].to_le_bytes();
        let n = (key_len - i * 8).min(8);
        buf[i * 8..i * 8 + n].copy_from_slice(&w[..n]);
    }
    let key = crate::supervisor::manifest::IfaceKey::from_bytes(&buf[..key_len]);
    match state.interfaces.register(key, mp_send_slot, caller_pid) {
        Ok(_) => {
            reply.label = trona_protocol::common::TRONA_OK;
        }
        Err(_) => reply.label = uapi::KERNITE_ERR_ALREADY_EXISTS as u64,
    }
}

fn handle_resolve_interface(state: &mut SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let key_len = request.regs[0] as usize;
    let mut buf = [0u8; 64];
    let words = (key_len + 7) / 8;
    for i in 0..words {
        let w = request.regs[1 + i].to_le_bytes();
        let n = (key_len - i * 8).min(8);
        buf[i * 8..i * 8 + n].copy_from_slice(&w[..n]);
    }
    let key = crate::supervisor::manifest::IfaceKey::from_bytes(&buf[..key_len]);
    match state.interfaces.lookup(&key) {
        Some(entry) => {
            reply.label = trona_protocol::common::TRONA_OK;
            reply.length = 1;
            reply.regs[0] = entry.provider_mp_send;
        }
        None => reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64,
    }
}

fn incoming_received_cap_count() -> u64 {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() {
        return 0;
    }
    let ipc_buf = unsafe { (*ctx).ipc_buffer };
    if ipc_buf.is_null() {
        return 0;
    }
    unsafe { crate::supervisor::recv_window::received_cap_count_for(ipc_buf as *const _) }
}

fn current_reply_target(reply_mp: u64) -> MpReplyTarget {
    let ctx = trona_runtime::current_ipc_ctx();
    let buf = if ctx.is_null() {
        core::ptr::null()
    } else {
        unsafe { (*ctx).ipc_buffer as *const _ }
    };
    unsafe { MpReplyTarget::from_ipc_buffer(buf, reply_mp) }
}

fn send_mp_write_reply(
    reply: &TronaMsg,
    reply_target: MpReplyTarget,
    received_cap_count: u64,
) -> bool {
    if reply.label == u64::MAX {
        crate::supervisor::recv_window::drop_received_caps_for_cap_count(received_cap_count);
        return false;
    }
    crate::supervisor::recv_window::drop_received_caps_for_cap_count(received_cap_count);
    if reply_target.is_none() {
        return true;
    }
    let ctx = trona_runtime::current_ipc_ctx();
    let ipc_buf = if ctx.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { (*ctx).ipc_buffer }
    };
    let len = core::cmp::min(reply.length as usize, reply.regs.len());
    let result = unsafe {
        trona_server::mp_write_reply_to(ipc_buf, reply_target, reply.label, &reply.regs[..len], 0)
    };
    if result == 0 {
        true
    } else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] mp_write_reply failed err=");
            _lb.hex(result as u64);
            _lb.str(b"\n");
        });
        false
    }
}

fn drop_inbound_caps(received_cap_count: u64) {
    crate::supervisor::recv_window::drop_received_caps_for_cap_count(received_cap_count);
}
