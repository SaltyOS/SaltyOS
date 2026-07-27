//! Async child readiness management for procmgr.
//!
//! Type=notify services signal readiness through procmgr's TCB-bound
//! notification. Each pending readiness wait is assigned a badge bit from
//! a small bitmap; the child's readiness cap is a badged mint of
//! `BOUND_NTFN`, so `SYS_SIGNAL` ORs the bit directly into procmgr's
//! notification word and wakes `mp_write_reply_read` without polling. The main
//! loop's notification dispatcher calls [`handle_ready_bits`] to fan out
//! the set bits to the corresponding proctab entries. Deadline timeouts
//! are still policed by [`check_pending_readiness`].
//!
//! Historically the upper 48 badge bits were shared with the procmgr
//! CSpace-expand bound-notification protocol; that path has been retired
//! (every userspace process now drives `slot_alloc::self_expand`
//! directly), so readiness now owns the entire badge word.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::*;

use crate::base::proc_table::{monotonic_now_ns, proctab, proctab_cap};

/// Number of concurrent pending readiness waits supported. Badge encoding
/// reserves the low 16 bits, so `MAX_BITS` must not exceed 16.
pub(crate) const MAX_BITS: u8 = 16;
/// Sentinel value for "no readiness bit assigned".
pub(crate) const BIT_NONE: u8 = 0xFF;
/// Badge bits reserved for readiness signalling (low 16 bits of the
/// notification word).
pub(crate) const BADGE_MASK: u64 = 0x0000_0000_0000_FFFF;

static mut READINESS_BITMAP: u16 = 0;

/// Allocate a free readiness badge bit. Returns `None` if all [`MAX_BITS`]
/// are currently in use.
pub(crate) fn alloc_readiness_bit() -> Option<u8> {
    unsafe {
        let bits = &raw mut READINESS_BITMAP;
        let current = *bits;
        if current == u16::MAX {
            return None;
        }
        let bit = (!current).trailing_zeros() as u8;
        *bits = current | (1u16 << bit);
        Some(bit)
    }
}

/// Release a previously-allocated readiness badge bit. Calling with
/// [`BIT_NONE`] (or any out-of-range value) is a safe no-op so rollback
/// paths can release unconditionally.
pub(crate) fn free_readiness_bit(bit: u8) {
    if bit >= MAX_BITS {
        return;
    }
    unsafe {
        let bits = &raw mut READINESS_BITMAP;
        *bits &= !(1u16 << bit);
    }
}

/// Current bitmap snapshot — exported for diagnostic dumps only.
pub(crate) fn readiness_bitmap_snapshot() -> u16 {
    unsafe { *(&raw const READINESS_BITMAP) }
}

/// Deliver `reply` through the saved MessagePipe endpoint. Deferred
/// procmgr waits store the server endpoint used by the original call;
/// regular RPC no longer receives or parks a per-call reply object.
#[inline]
unsafe fn send_pending_reply(reply_slot: Cap, pid: u32, reply: &TronaMsg) -> bool {
    unsafe {
        let err = trona_kernel::ipc::mp_write_reply_ctx(
            crate::ipc_ctx(),
            reply_slot,
            reply as *const TronaMsg,
        );
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] readiness mp_write_reply failed pid=");
                _lb.hex(pid as u64);
                _lb.str(b" ep=");
                _lb.hex(reply_slot);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return false;
        }
        true
    }
}

/// Find the proctab index whose assigned `ready_badge_bit` matches `bit`
/// and which is currently awaiting a reply. Returns `None` if the bit is
/// stale (already cleared by a prior signal or timeout — idempotent).
unsafe fn proc_idx_from_bit(bit: u8) -> Option<usize> {
    unsafe {
        let cap = proctab_cap();
        for i in 0..cap {
            let p = proctab(i);
            if p.ready_badge_bit == bit && p.pending_ready_reply != 0 {
                return Some(i);
            }
        }
        None
    }
}

/// Handle a notification word delivered to procmgr's bound notification.
/// `bits` is the raw badge value; only bits inside [`BADGE_MASK`] are acted
/// on, upper bits belong to cspace-expand and are ignored here.
pub(crate) unsafe fn handle_ready_bits(bits: u64) {
    unsafe {
        let mut m = bits & BADGE_MASK;
        while m != 0 {
            let b = m.trailing_zeros() as u8;
            m &= !(1u64 << b);
            if let Some(idx) = proc_idx_from_bit(b) {
                complete_readiness_ok(idx);
            }
            // Stale/duplicate signal → idempotent drop.
        }
    }
}

/// Save the current caller's reply endpoint and register a pending readiness
/// wait for process `idx`. Returns `true` on success, `false` if the endpoint
/// is not available.
///
/// The caller must have already assigned `proctab[idx].ready_badge_bit`
/// via [`alloc_readiness_bit`] and set `proctab[idx].ready_timeout_ns`
/// before calling this.
pub(crate) unsafe fn defer_readiness(idx: usize) -> bool {
    unsafe {
        let reply_slot = trona_runtime::client::caps::service_recv_ep();
        if reply_slot == 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] defer_readiness: no reply endpoint\n");
            });
            return false;
        }

        let p = proctab(idx);
        let timeout_ns = p.ready_timeout_ns;

        let now_ns = monotonic_now_ns();
        let deadline = if now_ns != 0 && timeout_ns > 0 {
            now_ns.saturating_add(timeout_ns)
        } else {
            // Clock unavailable or zero timeout — no hard deadline.
            u64::MAX
        };

        p.pending_ready_reply = reply_slot;
        p.pending_ready_deadline_ns = deadline;
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] readiness registered pid=");
            _lb.hex(p.pid as u64);
            _lb.str(b" bit=");
            _lb.hex(p.ready_badge_bit as u64);
            _lb.str(b" reply=");
            _lb.hex(reply_slot);
            _lb.str(b" deadline=");
            _lb.hex(deadline);
            _lb.str(b"\n");
        });
        true
    }
}

/// Cancel a deferred readiness reply before the child has actually completed
/// readiness (for example, if `tcb_resume` fails after the caller reply was
/// already parked with `save_caller`).
///
/// This only tears down the saved reply endpoint state. The readiness badge bit and
/// `wait_ready_on_resume` contract remain intact so a later PM_RESUME retry can
/// still wait for readiness.
pub(crate) unsafe fn cancel_deferred_readiness(idx: usize, reply_label: u64) -> bool {
    unsafe {
        let p = proctab(idx);
        let reply_slot = p.pending_ready_reply;
        if reply_slot == 0 {
            return false;
        }

        let pid = p.pid;
        let mut reply = TronaMsg::zeroed();
        reply.label = reply_label;

        let sent = send_pending_reply(reply_slot, pid, &reply);
        p.pending_ready_reply = 0;
        p.pending_ready_deadline_ns = 0;
        sent
    }
}

/// Check pending readiness waits for deadline expiry. Signal delivery itself
/// happens via [`handle_ready_bits`] from the main loop's notification
/// dispatcher; this function is only responsible for timing out waits whose
/// deadline has passed.
pub(crate) unsafe fn check_pending_readiness() {
    unsafe {
        let now_ns = monotonic_now_ns();
        if now_ns == 0 {
            return;
        }

        let cap = proctab_cap();
        for i in 0..cap {
            let p = proctab(i);
            if p.pending_ready_reply == 0 {
                continue;
            }
            if p.pending_ready_deadline_ns != u64::MAX && now_ns >= p.pending_ready_deadline_ns {
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
        let pid = p.pid;
        let ready_badge_bit = p.ready_badge_bit;

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] child ready (async): PID=");
            _lb.hex(pid as u64);
            _lb.str(b" bit=");
            _lb.hex(ready_badge_bit as u64);
            _lb.str(b"\n");
        });

        let mut reply = TronaMsg::zeroed();
        reply.label = trona_protocol::common::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;

        let _ = send_pending_reply(reply_slot, pid, &reply);

        // Clear pending state and release the badge bit
        p.pending_ready_reply = 0;
        p.pending_ready_deadline_ns = 0;
        p.wait_ready_on_resume = false;
        free_readiness_bit(ready_badge_bit);
        p.ready_badge_bit = BIT_NONE;
        p.ready_timeout_ns = 0;
    }
}

/// Readiness timed out. Suspend child, clean up, send TRONA_BUSY to original caller.
unsafe fn complete_readiness_timeout(idx: usize) {
    unsafe {
        let p = proctab(idx);
        if p.pending_ready_reply == 0 {
            return;
        }
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] child ready timeout (async): PID=");
            _lb.hex(p.pid as u64);
            _lb.str(b"\n");
        });
        let exit_code = 9i32; // SIGKILL-equivalent
        crate::lifecycle::exit::core_exit_sequence(idx, exit_code);
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
            if p.pending_ready_reply != 0 && p.pending_ready_deadline_ns < deadline {
                deadline = p.pending_ready_deadline_ns;
            }
        }
    }
    deadline
}
