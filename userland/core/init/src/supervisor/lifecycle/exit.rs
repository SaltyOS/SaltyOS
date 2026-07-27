// SPDX-License-Identifier: GPL-2.0-only
//
//! Process-exit finalization. `finalize_exit` is the single seam
//! every exit path eventually drops into:
//!
//! * `INIT_EXIT(status)` from a process voluntarily terminating.
//! * fault dispatcher's `INIT_REPORT_FAULT` when mmsrv decides a
//!   fault is unrecoverable and asks init to kill the victim.
//! * the supervisor's own SIGKILL delivery for crashes / SIGSEGV
//!   etc. translated by `fault::handle_report_fault`.
//!
//! Marking the process Zombie + dropping per-client state in mmsrv,
//! rsrcsrv, and namesrv is unconditional — the only branching is in
//! the parent-side notification (SIGCHLD + waitpid wakeup), which is
//! gated on the existence of a `parent_pid > 0`.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_protocol::common::TRONA_OK;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::MpReplyTarget;
use trona_server::event_loop::decode_cookie;

use crate::supervisor::SupervisorState;
use crate::supervisor::lifecycle::wait::encode_wait_status;
use crate::supervisor::lifecycle_stream::EVT_EXIT;
use crate::supervisor::mm_ipc::mm_deregister_client;
use crate::supervisor::namesrv_ipc::namesrv_owner_exited;
use crate::supervisor::proc_table::{ProcessState, ThreadState};
use crate::supervisor::rsrc_ipc::{rsrc_free, rsrc_owner_exited};
use crate::supervisor::signal::queue_sigchld_pending;
use crate::supervisor::vfs_ipc::vfs_deregister_client;
use crate::wire::INIT_COOKIE_KIND_REQUEST_MP;

/// Mark a process as Zombie, deliver SIGCHLD to its parent, evict
/// its observer subscriptions, and tell mmsrv / rsrcsrv / namesrv
/// to drop their per-client state.
pub fn finalize_exit(state: &mut SupervisorState, pid: u32, status: i32) {
    let (parent_pid, exited_name) = {
        let Some(proc) = state.procs.get_mut(pid) else {
            return;
        };
        proc.exit_status = status;
        proc.state = ProcessState::Zombie;
        (proc.parent_pid, proc.name)
    };
    state.procs.for_each_thread_mut(pid, |t| {
        t.state = ThreadState::Exited;
    });

    // Type=oneshot readiness hook: a clean exit unblocks dependents.
    // Failure exits leave the unit not-ready so dependents stay
    // blocked (and the operator notices).
    let oneshot_became_ready = status == 0
        && state
            .unit_graph
            .on_oneshot_exit(&state.manifest, exited_name.as_bytes());

    // Teardown order is load-bearing for rsrcsrv's untyped reclaim. rsrcsrv
    // resets a drained chunk only when the kernel confirms it holds no live
    // children; any surviving reference to a reclaimed object — the child's
    // running TCB (object refs to its VSpace/CSpace/SchedContext), init's own
    // bundle cap copies, mmsrv's per-client caps — makes the kernel refuse the
    // reset with HasChildren. So drop every reference first, then run the
    // synchronous owner reclaim last:
    //   1. mmsrv deregister (async): mmsrv releases its per-client caps and
    //      cancels its request/fault watches. Kept async on purpose — mmsrv
    //      reports faults to init via a *synchronous* INIT_REPORT_FAULT
    //      MP_CALL, so a synchronous deregister here would deadlock the
    //      fault-kill path. rsrcsrv's back_ref revoke cascades any CDT-derived
    //      mmsrv cap regardless, so async suffices for reclaim correctness.
    //   2. drop init's own caps: kill the TCB and delete the bundle cap copies.
    //   3. rsrcsrv owner-exited (synchronous): revoke every back_ref and
    //      reclaim the now-drained chunks before the next fork reuses the pool.
    let client_id = state.procs.get(pid).map(|p| p.client_id());
    if let Some(client_id) = client_id {
        mm_deregister_client(state, client_id);
        vfs_deregister_client(state, client_id);
        namesrv_owner_exited(state, client_id);
    }
    drop_owned_caps(state, pid);
    if let Some(client_id) = client_id {
        let rsrcsrv_mp = state
            .caps
            .rsrcsrv_client_mp
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr();
        rsrc_owner_exited(rsrcsrv_mp, client_id, trona_runtime::current_ipc_ctx());
    }
    state.interfaces.evict_by_pid(pid);
    state.lifecycle.evict_by_pid(pid);
    crate::supervisor::fault::fault_observers().evict_by_pid(pid);

    let mut waitpid_reply = MpReplyTarget::none();
    if parent_pid != 0 {
        if let Some(parent) = state.procs.get_mut(parent_pid) {
            if !parent.waitpid_parked_reply.is_none()
                && (parent.waitpid_parked_target == -1
                    || parent.waitpid_parked_target == pid as i32)
            {
                waitpid_reply = parent.waitpid_parked_reply;
                parent.waitpid_parked_reply = MpReplyTarget::none();
                parent.waitpid_parked_target = 0;
            }
            let _ = queue_sigchld_pending(parent);
        }
    }
    if !waitpid_reply.is_none() {
        reply_waitpid_target(waitpid_reply, pid, status);
        state.procs.release(pid);
    }

    state.lifecycle.publish(
        trona_runtime::current_ipc_ctx(),
        EVT_EXIT,
        pid,
        parent_pid,
        status as u64,
        0,
    );

    if oneshot_became_ready {
        if let Err(err) = crate::supervisor::boot::drive_dispatch_ready(state) {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[INIT] dispatch-ready failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
        }
    }
}

fn reply_waitpid_target(reply_target: MpReplyTarget, pid: u32, status: i32) {
    let ctx = trona_runtime::current_ipc_ctx();
    let buf = if ctx.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { (*ctx).ipc_buffer }
    };
    let regs = [pid as u64, encode_wait_status(status)];
    let err = unsafe { trona_server::mp_write_reply_to(buf, reply_target, TRONA_OK, &regs, 0) };
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] waitpid mp_write_reply failed err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
    }
}

fn drop_owned_caps(state: &mut SupervisorState, pid: u32) {
    // Cancel the request-watch before anything else: the watch holds a
    // reference to the request MP recv slot and must be cancelled while
    // the MP cap is still valid.
    let (request_watch_addr, request_watch_cookie) = {
        let Some(proc) = state.procs.get(pid) else {
            return;
        };
        (
            proc.request_watch
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr(),
            proc.request_watch_cookie,
        )
    };
    if request_watch_addr != 0 {
        let (_kind, slot, _epoch) = decode_cookie(request_watch_cookie);
        let watch = state
            .cookie_table
            .cancel(INIT_COOKIE_KIND_REQUEST_MP, slot)
            .unwrap_or(request_watch_addr);
        let _ = invoke::watch_cancel(CapRef::flat(watch));
        // The watch cap itself is an OwnedCap in the process record; the
        // cancel above invalidates the kernel watch object. The cap slot
        // will be freed when the process record is dropped via release.
    }

    // Kill all TCBs while their caps are still valid, and collect rsrcsrv
    // record ids before the thread records are dropped. The main TCB cap lives
    // on ProcessRecord; auxiliary thread TCB caps live on ThreadRecord.
    if let Some(proc) = state.procs.get(pid) {
        if let Some(tcb) = proc.main_tcb.as_ref() {
            let _ = invoke::tcb_kill(tcb.borrow());
        }
    }
    let rsrcsrv_mp = state
        .caps
        .rsrcsrv_client_mp
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    state.procs.for_each_thread_mut(pid, |thread| {
        if let Some(tcb) = thread.tcb.as_ref() {
            let _ = invoke::tcb_kill(tcb.borrow());
        }
        for record_id in [
            thread.tcb_record_id,
            thread.sc_record_id,
            thread.fault_mp_record_id,
        ] {
            if record_id != 0 {
                let _ = rsrc_free(rsrcsrv_mp, record_id, ipc_ctx);
            }
        }
        // Same invariant as the ProcessRecord caps below: drop init's refs to
        // this aux thread's kernel objects before rsrc_owner_exited, not at the
        // later free_thread_chain in release(pid).
        let _ = thread.tcb.take();
        let _ = thread.sc.take();
        let _ = thread.fault_mp_send.take();
        let _ = thread.fault_mp_recv.take();
    });
    // Drop init's own references to the child's kernel objects before the
    // synchronous rsrc_owner_exited reclaim below: rsrcsrv can only reset a
    // drained untyped chunk, and any surviving reference (init's bundle cap
    // copies) makes the kernel refuse the reset with HasChildren. Each
    // OwnedCap drop deletes the cap and frees its slot; the zombie keeps only
    // status metadata until release(pid), which then drops Nones.
    if let Some(proc) = state.procs.get_mut(pid) {
        let _ = proc.main_tcb.take();
        let _ = proc.sched_context.take();
        let _ = proc.vspace.take();
        let _ = proc.cspace.take();
        let _ = proc.request_mp_send.take();
        let _ = proc.request_mp_recv.take();
        let _ = proc.request_watch.take();
        let _ = proc.signal_mp_send.take();
        let _ = proc.signal_mp_recv.take();
        // The per-client mmsrv / VFS control caps were already consumed by the
        // deregister calls above; drop init's refs now (the servers own the
        // teardown) instead of letting them linger in the zombie until reap.
        let _ = proc.mmsrv_control_cap.take();
        let _ = proc.vfs_control_cap.take();
        let _ = proc.mmsrv_request_mp_send.take();
        let _ = proc.mmsrv_request_mp_recv.take();
        let _ = proc.fault_mp_recv.take();
        let _ = proc.fault_mp_send.take();
        let _ = proc.service_ep_send.take();
        let _ = proc.service_ep_recv.take();
        let _ = proc.ldsrv_adopt_recv.take();
        let _ = proc.ldsrv_exec_control_recv.take();
        let _ = proc.ldsrv_plumbing_untyped.take();
    }
}
