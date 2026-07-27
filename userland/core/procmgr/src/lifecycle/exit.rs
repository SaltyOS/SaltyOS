//! Exit path — observer-visible Zombie transition plus async backend teardown.
//!
//! Split into two logical phases that proceed independently:
//!
//! 1. **Observer-visible transition.** `core_exit_sequence` →
//!    `mark_parent_visible_exit` populates the `ExitRecord`, flips
//!    `state` to `Zombie`, delivers SIGCHLD, and wakes any parked
//!    `waitpid` caller. Runs synchronously and is never gated on a
//!    backend service.
//!
//! 2. **Backend teardown.** `attempt_backend_teardown` runs the step
//!    sequence (personality pre, mmsrv deregister, rsrcsrv reclaim,
//!    aux-thread drop, CSpace deregister, personality post). Each
//!    step is idempotent and records completion in
//!    `teardown_steps_done`. On transient failure (only mmsrv retries
//!    in practice), the pump in `process_pending_teardowns` retries
//!    on a 100 ms interval until a 10 s hard deadline, after which
//!    the job is marked `teardown_abandoned` so the slot can recycle.
//!
//! Slot recycling (`Process::zeroed` via `cleanup_proc_resources`)
//! only happens once BOTH observer-visibility is consumed (via waitpid
//! or orphan sweep) AND backend teardown has completed or been
//! abandoned. `try_finalize_slot` gates this.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::*;

use crate::base::proc_table::{
    COMPLETION_EVENT_EXITED, MAX_NAME_LEN, ObserverEventRecord, ProcessState, SIG_DISP_CATCH,
    cleanup_proc_resources, find_by_badge, find_by_pid, monotonic_now_ns, proctab, proctab_cap,
};
use crate::base::teardown::{
    STEP_CSPACE, STEP_MMSRV, STEP_POST, STEP_PRE, STEP_RSRCSRV, STEP_THREADS,
    TEARDOWN_HARD_DEADLINE_NS, TEARDOWN_RETRY_INTERVAL_NS, is_complete,
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn signal_ntfn(ntfn: Cap, bits: u64) {
    trona_kernel::syscall::syscall(uapi::KERNITE_SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
}

fn current_time_ns() -> u64 {
    monotonic_now_ns()
}

unsafe fn schedule_teardown_retry(idx: usize) {
    unsafe {
        let now = current_time_ns();
        proctab(idx).teardown_retry_deadline_ns = now.saturating_add(TEARDOWN_RETRY_INTERVAL_NS);
    }
}

unsafe fn enqueue_teardown(idx: usize) {
    unsafe {
        let p = proctab(idx);
        // Set once; re-entry is a no-op.
        if p.teardown_hard_deadline_ns == 0 {
            let now = current_time_ns();
            p.teardown_hard_deadline_ns = now.saturating_add(TEARDOWN_HARD_DEADLINE_NS);
        }
    }
}

unsafe fn clear_pending_readiness(idx: usize, reply_label: u64) {
    unsafe {
        let p = proctab(idx);
        if p.pending_ready_reply != 0 {
            let reply_slot = p.pending_ready_reply;
            let mut ready_reply = TronaMsg::zeroed();
            ready_reply.label = reply_label;
            let _ = trona_kernel::ipc::mp_write_reply_ctx(
                crate::ipc_ctx(),
                reply_slot,
                &raw const ready_reply,
            );
            p.pending_ready_reply = 0;
        }
        p.pending_ready_deadline_ns = 0;
        p.wait_ready_on_resume = false;
        p.ready_timeout_ns = 0;
        if p.ready_badge_bit != crate::base::readiness::BIT_NONE {
            crate::base::readiness::free_readiness_bit(p.ready_badge_bit);
            p.ready_badge_bit = crate::base::readiness::BIT_NONE;
        }
    }
}

// ---------------------------------------------------------------------------
// Parent-visible transition
// ---------------------------------------------------------------------------

unsafe fn deliver_sigchld(idx: usize) {
    unsafe {
        let p = proctab(idx);
        if p.exit.sig_delivered {
            return;
        }
        let ppid = p.ppid;
        if let Some(pi) = find_by_pid(ppid) {
            let pp = proctab(pi);
            if pp.is_posix()
                && pp.state == ProcessState::Running
                && pp.signal_ntfn != 0
                && pp.posix().sig_disposition[crate::personality::posix::PM_SIGCHLD]
                    == SIG_DISP_CATCH
            {
                signal_ntfn(
                    pp.signal_ntfn,
                    1u64 << crate::personality::posix::PM_SIGCHLD,
                );
            }
        }
        p.exit.sig_delivered = true;
    }
}

/// Publish a child's current completion event into its observer's FIFO and, if
/// the observer is parked on a matching wait, wake it synchronously.
///
/// Flow:
/// 1. Orphan (`find_by_pid(observer_pid)` == `None`) — skip; the orphan arm of
///    `try_finalize_slot` handles auto-reap.
/// 2. Check whether the observer personality actually projects this event
///    kind. Unobserved non-terminal events are dropped at the caller.
/// 3. Enqueue the child onto the observer's completion FIFO tail if it does
///    not already have a queued event. A later terminal event may upgrade an
///    earlier queued non-terminal one in place.
/// 4. If the observer is parked and its filter matches this child's current
///    completion event, try the fast-path wake. The completion FIFO remains
///    authoritative; wake delivery is opportunistic. On send success the
///    waiter is consumed and the event is consumed immediately. On send
///    failure the event stays queued and a short deferred wake retry is armed.
pub(crate) unsafe fn publish_completion_event(idx: usize) -> bool {
    unsafe {
        let observer_pid = proctab(idx).completion_observer_pid;

        let Some(parent_idx) = find_by_pid(observer_pid) else {
            return false;
        };

        let event_kind = proctab(idx).completion_event_kind;
        if !proctab(parent_idx)
            .personality_kind()
            .observes_completion_event(event_kind)
        {
            return false;
        };

        let record = ObserverEventRecord {
            kind: event_kind,
            pid: proctab(idx).pid,
            status: proctab(idx).completion_event_status,
            cookie: proctab(idx).completion_event_cookie,
        };
        if !crate::lifecycle::wait::append_observer_event(parent_idx, record) {
            return false;
        }
        if !crate::lifecycle::wait::parked_wait_matches_child(parent_idx, idx) {
            return true;
        }

        if !crate::lifecycle::wait::try_wake_parent_waiter(parent_idx) {
            crate::lifecycle::wait::schedule_parent_wait_wake_retry(parent_idx);
        }
        true
    }
}

unsafe fn mark_parent_visible_exit(idx: usize) {
    unsafe {
        proctab(idx).state = ProcessState::Zombie;
        deliver_sigchld(idx);
        let _ = publish_completion_event(idx);
    }
}

// ---------------------------------------------------------------------------
// Backend teardown steps
// ---------------------------------------------------------------------------

unsafe fn run_step_pre(idx: usize) -> bool {
    unsafe {
        let kind = proctab(idx).personality_kind();
        let badge = proctab(idx).badge;
        kind.pre_teardown(badge);
        proctab(idx).teardown_steps_done |= STEP_PRE;
        true
    }
}

unsafe fn run_step_mmsrv(idx: usize) -> bool {
    unsafe {
        let p = proctab(idx);
        if !p.mmsrv_registered {
            p.teardown_steps_done |= STEP_MMSRV;
            return true;
        }
        if crate::base::mmsrv_ipc::quiesce_and_deregister_mmsrv_client(p.tcb_cap, p.pid, p.badge) {
            p.mmsrv_registered = false;
            p.teardown_steps_done |= STEP_MMSRV;
            return true;
        }
        false
    }
}

unsafe fn run_step_rsrcsrv(idx: usize) -> bool {
    unsafe {
        let badge = proctab(idx).badge;
        let _ = crate::base::alloc::reclaim_owner(trona_runtime::client::caps::rsrcsrv_ep(), badge);
        proctab(idx).teardown_steps_done |= STEP_RSRCSRV;
        true
    }
}

unsafe fn run_step_threads(idx: usize) -> bool {
    unsafe {
        crate::lifecycle::thread::drop_all_threads(idx);
        proctab(idx).teardown_steps_done |= STEP_THREADS;
        true
    }
}

unsafe fn run_step_cspace(idx: usize) -> bool {
    unsafe {
        let badge = proctab(idx).badge;
        // CSpace expand client deregistration is gone — substrate-side
        // self-expand owns lifecycle now.
        let _ = badge;
        proctab(idx).teardown_steps_done |= STEP_CSPACE;
        true
    }
}

unsafe fn run_step_post(idx: usize) -> bool {
    unsafe {
        let kind = proctab(idx).personality_kind();
        let badge = proctab(idx).badge;
        kind.post_teardown(badge);
        proctab(idx).teardown_steps_done |= STEP_POST;
        true
    }
}

/// Run each pending teardown step in order. Skips steps already done.
/// Stops on the first transient failure (only mmsrv fails
/// transiently in practice) and leaves `teardown_retry_deadline_ns`
/// set so the pump retries later.
///
/// When all steps complete, fires a one-shot respawn if requested.
/// Re-entry is guarded by the `is_complete` / `teardown_abandoned`
/// check at the top — respawn cannot fire twice.
unsafe fn attempt_backend_teardown(idx: usize) {
    unsafe {
        let p = proctab(idx);
        if p.teardown_abandoned || is_complete(p.teardown_steps_done) {
            return;
        }

        if p.teardown_steps_done & STEP_PRE == 0 && !run_step_pre(idx) {
            schedule_teardown_retry(idx);
            return;
        }
        if p.teardown_steps_done & STEP_MMSRV == 0 && !run_step_mmsrv(idx) {
            schedule_teardown_retry(idx);
            return;
        }
        if p.teardown_steps_done & STEP_RSRCSRV == 0 && !run_step_rsrcsrv(idx) {
            schedule_teardown_retry(idx);
            return;
        }
        if p.teardown_steps_done & STEP_THREADS == 0 && !run_step_threads(idx) {
            schedule_teardown_retry(idx);
            return;
        }
        if p.teardown_steps_done & STEP_CSPACE == 0 && !run_step_cspace(idx) {
            schedule_teardown_retry(idx);
            return;
        }
        if p.teardown_steps_done & STEP_POST == 0 && !run_step_post(idx) {
            schedule_teardown_retry(idx);
            return;
        }

        // All steps complete.
        p.teardown_retry_deadline_ns = 0;

        if p.respawn {
            // Gate respawn on the unit's `Restart=` policy (forwarded
            // from init) and apply exponential backoff with a degraded-
            // unit cutoff. `RESPAWN_ALWAYS` respawns on every exit;
            // `RESPAWN_ON_FAILURE` respawns only when the exit code is
            // non-zero (a clean shell-exit from `/bin/login` ends the
            // cycle).
            let exit_code = p.exit.exit_code;
            let should_respawn = match p.respawn_policy as u64 {
                x if x == trona_runtime::core::server_consts::server::RESPAWN_ALWAYS => true,
                x if x == trona_runtime::core::server_consts::server::RESPAWN_ON_FAILURE => {
                    exit_code != 0
                }
                _ => false,
            };
            if should_respawn {
                const RESPAWN_WINDOW_NS: u64 = 10_000_000_000;
                const RESPAWN_MAX_ATTEMPTS: u32 = 3;
                let now_ns = crate::base::proc_table::monotonic_now_ns();
                if p.respawn_first_attempt_tick == 0
                    || now_ns.saturating_sub(p.respawn_first_attempt_tick) > RESPAWN_WINDOW_NS
                {
                    p.respawn_first_attempt_tick = now_ns;
                    p.respawn_attempt_count = 0;
                }
                p.respawn_attempt_count = p.respawn_attempt_count.saturating_add(1);
                if p.respawn_attempt_count > RESPAWN_MAX_ATTEMPTS {
                    trona_runtime::uwarn!(|_lb| {
                        _lb.str(b"[PROCMGR] unit degraded (");
                        _lb.bytes(&p.respawn_binary[..]);
                        _lb.str(b"); stopped respawning after ");
                        _lb.dec(p.respawn_attempt_count as u64);
                        _lb.str(b" failures in window\n");
                    });
                    return;
                }
                let delay_ns: u64 = match p.respawn_attempt_count {
                    1 => 100_000_000,   // 100 ms
                    2 => 400_000_000,   // 400 ms
                    _ => 1_600_000_000, // capped at ~1.6 s (≤ 2 s ceiling)
                };
                // Defer the respawn by recording the next-ready tick —
                // the main recv loop's `recv_timed_ctx` aggregates this
                // into its timeout, and `process_ready_respawns()` fires
                // the actual respawn when the tick is reached. No
                // blocking sleep on procmgr's dispatch thread.
                p.respawn_next_ready_tick = now_ns + delay_ns;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Slot finalization
// ---------------------------------------------------------------------------

unsafe fn slot_cleanup(idx: usize) {
    unsafe {
        free_proc_alloc_slots(idx);
        cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
    }
}

/// If the backend teardown is complete (or abandoned) AND the
/// observer-visible side is consumed (or never observable), recycle
/// the slot. Called both inline from exit / waitpid paths and from
/// the periodic teardown pump.
unsafe fn try_finalize_slot(idx: usize) {
    unsafe {
        let observer_gone = find_by_pid(proctab(idx).completion_observer_pid).is_none();
        let p = proctab(idx);
        let can_recycle = is_complete(p.teardown_steps_done) || p.teardown_abandoned;
        if !can_recycle {
            return;
        }
        // Hold the slot for as long as a deferred respawn is still
        // waiting on it. `process_ready_respawns` snapshots the
        // respawn descriptor out of this proctab entry and clears the
        // tick; only then is recycling safe.
        if p.respawn_next_ready_tick != 0 {
            return;
        }

        match p.state {
            ProcessState::Reaped => {
                slot_cleanup(idx);
            }
            ProcessState::Exiting if p.launch_pending => {
                // Discard path: never became observer-visible.
                clear_pending_readiness(idx, trona_protocol::posix::TRONA_BUSY);
                slot_cleanup(idx);
            }
            ProcessState::Zombie => {
                // Orphan reap: the completion observer is already gone.
                if observer_gone {
                    p.exit.completion_consumed = true;
                    p.state = ProcessState::Reaped;
                    slot_cleanup(idx);
                }
                // else: waiting for the parent to call waitpid.
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Teardown pump — called from the server main loop on timer wakeups
// ---------------------------------------------------------------------------

pub(crate) fn has_pending_teardowns() -> bool {
    unsafe {
        let cap = proctab_cap();
        for i in 0..cap {
            let p = proctab(i);
            if p.state == ProcessState::Free {
                continue;
            }
            let in_teardown = matches!(p.state, ProcessState::Zombie | ProcessState::Reaped)
                || (p.state == ProcessState::Exiting && p.launch_pending);
            if !in_teardown {
                continue;
            }
            // Still needs attention: either steps pending, deadline
            // pending, or finalization pending.
            return true;
        }
        false
    }
}

pub(crate) fn nearest_teardown_deadline_ns() -> u64 {
    let mut deadline = u64::MAX;
    unsafe {
        let cap = proctab_cap();
        for i in 0..cap {
            let p = proctab(i);
            if p.state == ProcessState::Free {
                continue;
            }
            if is_complete(p.teardown_steps_done) || p.teardown_abandoned {
                continue;
            }
            let in_teardown = matches!(p.state, ProcessState::Zombie | ProcessState::Reaped)
                || (p.state == ProcessState::Exiting && p.launch_pending);
            if !in_teardown {
                continue;
            }
            if p.teardown_retry_deadline_ns != 0 && p.teardown_retry_deadline_ns < deadline {
                deadline = p.teardown_retry_deadline_ns;
            }
            if p.teardown_hard_deadline_ns != 0 && p.teardown_hard_deadline_ns < deadline {
                deadline = p.teardown_hard_deadline_ns;
            }
        }
    }
    deadline
}

/// True when any proctab entry has an outstanding deferred respawn
/// (`respawn_next_ready_tick != 0`). The main recv loop uses this to
/// decide whether to use `recv_timed_ctx` with a deadline that wakes
/// procmgr up in time for the respawn, vs. an unbounded receive.
pub(crate) fn has_pending_respawns() -> bool {
    unsafe {
        let cap = proctab_cap();
        for i in 0..cap {
            if proctab(i).respawn_next_ready_tick != 0 {
                return true;
            }
        }
    }
    false
}

/// Nearest `respawn_next_ready_tick` across all proctab entries, or
/// `u64::MAX` if none are scheduled. Feeds `recv_with_timer`'s
/// deadline aggregation so procmgr wakes just in time to fire the
/// respawn without spinning or sleeping.
pub(crate) fn nearest_respawn_deadline_ns() -> u64 {
    let mut deadline = u64::MAX;
    unsafe {
        let cap = proctab_cap();
        for i in 0..cap {
            let tick = proctab(i).respawn_next_ready_tick;
            if tick != 0 && tick < deadline {
                deadline = tick;
            }
        }
    }
    deadline
}

/// Fire all respawns whose `respawn_next_ready_tick` is at or before
/// `now_ns`. Called from the main recv loop when a timed receive wakes
/// on timeout. Clears the tick before dispatching so the proctab slot
/// becomes eligible for normal recycling after the respawn lands.
pub(crate) unsafe fn process_ready_respawns() {
    unsafe {
        let now_ns = crate::base::proc_table::monotonic_now_ns();
        let cap = proctab_cap();
        for i in 0..cap {
            let p = proctab(i);
            if p.respawn_next_ready_tick == 0 || p.respawn_next_ready_tick > now_ns {
                continue;
            }
            // Snapshot the respawn descriptor before clearing the
            // pending tick. `respawn_process` issues a synthetic
            // `INIT_SPAWN` that allocates a fresh proctab slot for the
            // new PID; the old entry will recycle through the normal
            // `try_finalize_slot` path.
            let binary = p.respawn_binary;
            let frame_slot_floor = p.cap_layout.frame_slot_start;
            let stdio_mode = p.stdio_mode;
            let respawn_policy = p.respawn_policy;
            let parent_badge = match find_by_pid(p.ppid) {
                Some(pi) => proctab(pi).badge,
                None => 0,
            };
            p.respawn_next_ready_tick = 0;

            respawn_process(
                &binary,
                frame_slot_floor,
                stdio_mode,
                respawn_policy,
                parent_badge,
            );
        }
    }
}

pub(crate) unsafe fn process_pending_teardowns() {
    unsafe {
        let now = current_time_ns();
        let cap = proctab_cap();
        for i in 0..cap {
            let p = proctab(i);
            if p.state == ProcessState::Free {
                continue;
            }

            // Already done — just finalize if appropriate.
            if is_complete(p.teardown_steps_done) || p.teardown_abandoned {
                try_finalize_slot(i);
                continue;
            }

            let in_teardown = matches!(p.state, ProcessState::Zombie | ProcessState::Reaped)
                || (p.state == ProcessState::Exiting && p.launch_pending);
            if !in_teardown {
                continue;
            }

            // Hard deadline — abandon and finalize.
            if p.teardown_hard_deadline_ns != 0 && now >= p.teardown_hard_deadline_ns {
                p.teardown_abandoned = true;
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] teardown abandoned pid=");
                    _lb.hex(p.pid as u64);
                    _lb.str(b" remaining_steps=0x");
                    _lb.hex((!p.teardown_steps_done & crate::base::teardown::STEP_ALL) as u64);
                    _lb.str(b" reason=hard_deadline\n");
                });
                try_finalize_slot(i);
                continue;
            }

            // Retry deadline — wait.
            if p.teardown_retry_deadline_ns != 0 && now < p.teardown_retry_deadline_ns {
                continue;
            }

            attempt_backend_teardown(i);
            try_finalize_slot(i);
        }
    }
}

// ---------------------------------------------------------------------------
// Respawn (synthetic INIT_SPAWN after backend teardown completes)
// ---------------------------------------------------------------------------

unsafe fn respawn_process(
    binary: &[u8; MAX_NAME_LEN],
    frame_slot_floor: u64,
    stdio_mode: u8,
    respawn_policy: u8,
    parent_badge: u64,
) {
    unsafe {
        let mut name_len = 0usize;
        while name_len < MAX_NAME_LEN && binary[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            return;
        }

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] Respawning: ");
            _lb.bytes(&binary[..name_len]);
            _lb.str(b"\n");
        });

        let mut spawn_flags = trona_runtime::core::server_consts::SPAWN_FLAG_RESPAWN;
        spawn_flags |= trona_runtime::core::server_consts::server::spawn_flags_with_stdio_mode(
            stdio_mode as u64,
        );
        spawn_flags |= trona_runtime::core::server_consts::server::spawn_flags_with_respawn_policy(
            respawn_policy as u64,
        );

        let mut msg = TronaMsg::zeroed();
        msg.label = crate::INIT_SPAWN;
        let packed_name_words = (name_len as u64 + 7) / 8;
        msg.regs[0] = name_len as u64;
        msg.regs[1] = trona_runtime::core::server_consts::SPAWN_READY_IMMEDIATE;
        msg.regs[2] = 0;
        msg.regs[3] = spawn_flags;
        msg.regs[4] = 0;
        msg.regs[5] = frame_slot_floor;
        msg.length = 6 + packed_name_words;

        let dst = &raw mut msg.regs[6] as *mut u8;
        for i in 0..name_len {
            *dst.add(i) = binary[i];
        }

        let mut reply = TronaMsg::zeroed();
        let alloc = &mut *(&raw mut crate::ALLOCATOR);
        let _ = crate::lifecycle::spawn::handle_spawn_tx(&msg, &mut reply, parent_badge, alloc);

        if reply.label == crate::TRONA_OK {
            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] Respawned PID=");
                _lb.hex(reply.regs[0]);
                _lb.str(b"\n");
            });
        } else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] Respawn failed, retrying...\n");
            });
            // 100 ms gap before the synchronous retry. The kernel's
            // `SYS_NANOSLEEP` takes (seconds, nanoseconds); the previous
            // call passed `100_000_000` into the *seconds* slot (≈ 3 years)
            // which silently stalled any unit that hit this path.
            trona_kernel::syscall::syscall(uapi::KERNITE_SYS_NANOSLEEP, 0, 100_000_000, 0, 0, 0, 0);
            let mut reply2 = TronaMsg::zeroed();
            let _ =
                crate::lifecycle::spawn::handle_spawn_tx(&msg, &mut reply2, parent_badge, alloc);
            if reply2.label != crate::TRONA_OK {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] Respawn retry failed\n");
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Slot bitmap cleanup — still shared with wait.rs
// ---------------------------------------------------------------------------

/// Free allocator-tracked bitmap slots for a process. Must be called
/// BEFORE cleanup_proc_resources so slot_base/slot_count are still
/// valid for cap revocation.
pub(crate) unsafe fn free_proc_alloc_slots(idx: usize) {
    unsafe {
        // Parked waitpid waiter first: it may clear process-local waiter
        // state. Acquire `ALLOCATOR` afterward for the remaining slot
        // cleanup below.
        crate::lifecycle::wait::clear_parent_waiter(idx);

        let alloc = &mut *(&raw mut crate::ALLOCATOR);

        if proctab(idx).pending_ready_reply != 0 {
            proctab(idx).pending_ready_reply = 0;
        }

        if proctab(idx).slot_count > 0 {
            alloc.free_slots(proctab(idx).slot_base, proctab(idx).slot_count as usize);
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Unified exit entry. Transitions the process through Exiting →
/// Zombie (observer-visible) → backend teardown → slot recycling.
///
/// Re-entry from a process already in
/// Exiting/Zombie/Reaped/Free is a no-op (idempotent).
pub(crate) unsafe fn core_exit_sequence(idx: usize, exit_code: i32) {
    unsafe {
        let p = proctab(idx);
        if matches!(
            p.state,
            ProcessState::Exiting
                | ProcessState::Zombie
                | ProcessState::Reaped
                | ProcessState::Free
        ) {
            return;
        }
        p.state = ProcessState::Exiting;

        // Capture CPU times and suspend the TCB before any teardown
        // step can revoke the cap.
        let _ = trona_kernel::invoke::tcb_suspend(p.tcb_cap);
        if let Some((ut, st)) =
            trona_kernel::invoke::tcb_get_cpu_times_ctx(trona_runtime::current_ipc_ctx(), p.tcb_cap)
        {
            p.exit.exit_user_time_ns = ut;
            p.exit.exit_system_time_ns = st;
        }
        p.exit.exit_code = exit_code;
        p.completion_event_kind = COMPLETION_EVENT_EXITED;
        p.completion_event_status = exit_code;

        clear_pending_readiness(idx, trona_protocol::posix::TRONA_BUSY);
        enqueue_teardown(idx);

        // launch_pending = discard path (spawn rollback). Parent never
        // observed the child; skip Zombie / SIGCHLD / waiters.
        if !p.launch_pending {
            mark_parent_visible_exit(idx);
        }

        attempt_backend_teardown(idx);
        try_finalize_slot(idx);
    }
}

/// Abort a provisional child that is still in the Spawning phase.
/// Bypasses Zombie (no parent ever saw this child) and routes
/// straight through backend teardown to slot recycling. Called by
/// spawn rollback paths.
pub(crate) unsafe fn abort_spawning_process(idx: usize) {
    unsafe {
        let p = proctab(idx);
        if p.state == ProcessState::Free {
            return;
        }
        if !p.launch_pending {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] abort_spawning_process on committed PID=");
                _lb.hex(p.pid as u64);
                _lb.str(b"\n");
            });
            core_exit_sequence(idx, 0);
            return;
        }

        clear_pending_readiness(idx, trona_protocol::posix::TRONA_BUSY);
        p.state = ProcessState::Exiting;
        enqueue_teardown(idx);
        attempt_backend_teardown(idx);
        try_finalize_slot(idx);
    }
}

pub(crate) unsafe fn handle_exit(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let raw_code = msg.regs[0] as i32;
        let exit_code = raw_code << 8;

        let Some(idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        core_exit_sequence(idx, exit_code);
    }
}

/// Called by a completion consumer after it consumes a terminal
/// completion record.
/// If backend teardown has already finished, cleanup the slot now;
/// otherwise leave it for the pump.
pub(crate) unsafe fn finalize_after_completion_consume(idx: usize) {
    unsafe {
        try_finalize_slot(idx);
    }
}
