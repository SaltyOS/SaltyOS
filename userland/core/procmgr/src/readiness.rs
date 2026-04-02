//! Async child readiness management for procmgr.
//!
//! Replaces the blocking `wait_for_child_ready` poll loop with a deferred-reply
//! state machine driven by the main server loop. Each pending readiness wait is
//! tracked via `pending_ready_reply` / `pending_ready_deadline_ns` fields on the
//! Process struct.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::ipc;
use trona::types::core::*;

use crate::proc_table::{proctab, proctab_cap};

/// Save the current caller's reply cap and register a pending readiness wait
/// for process `idx`. Returns `true` on success, `false` if the reply cap
/// could not be saved (OOM or save_caller failure).
///
/// The caller must have already set `proctab[idx].ready_ntfn` and
/// `proctab[idx].ready_timeout_ns` before calling this.
pub(crate) unsafe fn defer_readiness(idx: usize) -> bool {
    unsafe {
        let alloc = &mut *(&raw mut crate::ALLOCATOR);
        let reply_slot = match alloc.alloc_single_slot() {
            Some(s) => s,
            None => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] defer_readiness: no slot for reply cap\n");
                });
                return false;
            }
        };

        let err = trona::invoke::cnode_save_caller(crate::CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] defer_readiness: save_caller failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            alloc.free_single_slot(reply_slot);
            return false;
        }

        let p = proctab(idx);
        let timeout_ns = p.ready_timeout_ns;

        let now = trona::syscall::syscall(
            trona::SYS_CLOCK_GETTIME,
            trona::consts::CLOCK_REALTIME as u64,
            0, 0, 0, 0, 0,
        );
        let deadline = if now.error == 0 && timeout_ns > 0 {
            now.value.saturating_add(timeout_ns)
        } else {
            // Clock unavailable or zero timeout — use u64::MAX so we rely on
            // poll-checking each iteration without a hard deadline.
            u64::MAX
        };

        p.pending_ready_reply = reply_slot;
        p.pending_ready_deadline_ns = deadline;
        true
    }
}

/// Poll all pending readiness waits and complete any that are ready or timed out.
/// Called from the main server loop on every iteration.
pub(crate) unsafe fn check_pending_readiness() {
    unsafe {
        let now = trona::syscall::syscall(
            trona::SYS_CLOCK_GETTIME,
            trona::consts::CLOCK_REALTIME as u64,
            0, 0, 0, 0, 0,
        );
        let now_ns = if now.error == 0 { now.value } else { 0 };

        let cap = proctab_cap();
        for i in 0..cap {
            let p = proctab(i);
            if p.pending_ready_reply == 0 {
                continue;
            }

            // Poll the readiness notification (non-blocking)
            let poll = trona::syscall::syscall(
                trona::SYS_POLL, p.ready_ntfn, 0, 0, 0, 0, 0,
            );
            if poll.error == 0 && (poll.value & crate::READY_SIGNAL_BITS) != 0 {
                complete_readiness_ok(i);
                continue;
            }

            // Check timeout
            if now_ns > 0 && now_ns >= p.pending_ready_deadline_ns {
                complete_readiness_timeout(i);
                continue;
            }

            // Poll error other than WOULD_BLOCK — notification cap invalid
            if poll.error != 0 && poll.error != trona::TRONA_WOULD_BLOCK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] readiness poll failed err=");
                    _lb.hex(poll.error);
                    _lb.str(b" pid=");
                    _lb.hex(proctab(i).pid as u64);
                    _lb.str(b"\n");
                });
                complete_readiness_timeout(i);
            }
        }
    }
}

/// Child signaled readiness. Send TRONA_OK reply to the original caller.
unsafe fn complete_readiness_ok(idx: usize) {
    unsafe {
        let p = proctab(idx);
        let reply_slot = p.pending_ready_reply;
        if reply_slot == 0 {
            return;
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] child ready (async): PID=");
            _lb.hex(p.pid as u64);
            _lb.str(b"\n");
        });

        let mut reply = TronaMsg::zeroed();
        reply.label = trona::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = p.pid as u64;

        let _ = ipc::send_ctx(crate::ipc_ctx(), reply_slot, &raw const reply);
        trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, reply_slot);
        let alloc = &mut *(&raw mut crate::ALLOCATOR);
        alloc.free_single_slot(reply_slot);

        // Clear pending state
        p.pending_ready_reply = 0;
        p.pending_ready_deadline_ns = 0;
        p.ready_ntfn = 0;
        p.ready_timeout_ns = 0;
    }
}

/// Readiness timed out. Suspend child, clean up, send TRONA_BUSY to original caller.
unsafe fn complete_readiness_timeout(idx: usize) {
    unsafe {
        let p = proctab(idx);
        let reply_slot = p.pending_ready_reply;
        if reply_slot == 0 {
            return;
        }

        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] child ready timeout (async): PID=");
            _lb.hex(p.pid as u64);
            _lb.str(b"\n");
        });

        // Suspend the child
        let _ = trona::invoke::tcb_suspend_retry(p.tcb_cap, 4);

        // Reply TRONA_BUSY to the original spawn/resume caller
        let mut reply = TronaMsg::zeroed();
        reply.label = trona::TRONA_BUSY;
        let _ = ipc::send_ctx(crate::ipc_ctx(), reply_slot, &raw const reply);
        trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, reply_slot);
        let alloc = &mut *(&raw mut crate::ALLOCATOR);
        alloc.free_single_slot(reply_slot);

        // Clear pending state before teardown (teardown zeroes the entry)
        p.pending_ready_reply = 0;
        p.pending_ready_deadline_ns = 0;

        // Full process teardown
        let pid = p.pid;
        let tcb_cap = p.tcb_cap;
        crate::spawn_tx::clear_fault_handler(tcb_cap, pid);
        crate::spawn_tx::deregister_from_mmsrv(pid);
        crate::posix::exit_wait::free_proc_alloc_slots(idx);
        crate::proc_table::cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
    }
}

/// Returns `true` if any process has a pending readiness wait.
pub(crate) fn has_pending_readiness() -> bool {
    unsafe {
        let cap = proctab_cap();
        for i in 0..cap {
            if proctab(i).pending_ready_reply != 0 {
                return true;
            }
        }
    }
    false
}

/// Returns the nearest pending readiness deadline (absolute ns).
/// Returns `u64::MAX` if no pending readiness waits exist.
pub(crate) fn nearest_readiness_deadline_ns() -> u64 {
    let mut deadline = u64::MAX;
    unsafe {
        let cap = proctab_cap();
        for i in 0..cap {
            let p = proctab(i);
            if p.pending_ready_reply != 0
                && p.pending_ready_deadline_ns < deadline
            {
                deadline = p.pending_ready_deadline_ns;
            }
        }
    }
    deadline
}
