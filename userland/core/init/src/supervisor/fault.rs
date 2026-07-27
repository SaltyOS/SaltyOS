// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_REPORT_FAULT` handler. mmsrv's fault dispatcher forwards every
//! crash it cannot recover (illegal instruction, breakpoint, user
//! exception, capability violation, OOM after backoff exhaustion) to
//! init via this label. init owns the action decision (resume / kill /
//! kill_group), updates the proc-table to Zombie, fans the event out
//! to lifecycle observers + fault observers, and instructs mmsrv
//! through the reply.
//!
//! Caller authentication: mmsrv's `ROLE_INIT_CONTROL` cap carries
//! `INIT_BADGE_FROM_MMSRV`, so a fault report is accepted only when the
//! record badge matches it; any other badge on this label gets
//! `KERNITE_ERR_INSUFFICIENT_RIGHTS`.

use trona_kernel::core_types::TronaMsg;
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::supervisor::SupervisorState;
use crate::supervisor::signal::fault_kind_to_signal;
use crate::wire::{
    FAULT_ACTION_KILL, FAULT_ACTION_KILL_GROUP, FAULT_ACTION_RESUME, INIT_BADGE_FROM_MMSRV,
};

pub const MAX_FAULT_OBSERVERS: usize = 8;

pub struct FaultObserver {
    /// Send side of the fault subscriber's MP — owned by init.
    /// `OwnedCap::null()` when the slot is vacant.
    pub mp_send: OwnedCap,
    pub owner_pid: u32,
}

impl FaultObserver {
    pub const fn empty() -> Self {
        Self {
            mp_send: OwnedCap::null(),
            owner_pid: 0,
        }
    }
}

pub struct FaultObservers {
    pub entries: [FaultObserver; MAX_FAULT_OBSERVERS],
}

impl FaultObservers {
    pub const fn new() -> Self {
        // SAFETY: OwnedCap::null() is a valid const initializer.
        Self {
            entries: [const { FaultObserver::empty() }; MAX_FAULT_OBSERVERS],
        }
    }

    pub fn register(&mut self, mp_send: OwnedCap, owner_pid: u32) -> Result<usize, ()> {
        for (i, e) in self.entries.iter_mut().enumerate() {
            if e.mp_send.as_raw() == 0 {
                *e = FaultObserver { mp_send, owner_pid };
                return Ok(i);
            }
        }
        Err(())
    }

    /// Remove the entry whose send address matches `mp_send_addr`.
    /// Returns `true` if found; the `OwnedCap` is dropped (cap deleted
    /// + slot freed) as part of the replacement.
    pub fn unregister(&mut self, mp_send_addr: u64) -> bool {
        for e in self.entries.iter_mut() {
            if e.mp_send.borrow().addr() == mp_send_addr {
                *e = FaultObserver::empty();
                return true;
            }
        }
        false
    }

    /// Evict every entry owned by `pid`. Each evicted `OwnedCap` is
    /// dropped automatically when the slot is overwritten with `empty()`.
    pub fn evict_by_pid(&mut self, pid: u32) -> usize {
        let mut n = 0;
        for e in self.entries.iter_mut() {
            if e.mp_send.as_raw() != 0 && e.owner_pid == pid {
                *e = FaultObserver::empty();
                n += 1;
            }
        }
        n
    }
}

static mut FAULT_OBSERVERS: FaultObservers = FaultObservers::new();

pub fn fault_observers() -> &'static mut FaultObservers {
    unsafe { &mut *core::ptr::addr_of_mut!(FAULT_OBSERVERS) }
}

/// Process one `INIT_REPORT_FAULT` request. Returns the action mmsrv
/// should take on the fault token (resume / kill / kill_group).
///
/// `request_regs` is the full `TronaMsg.regs` array; only `regs[0..=6]`
/// carry fault payload (packed `client_id|tcb_id`, padding, fault kind,
/// fault words). Receiving the entire array avoids a slicing copy on
/// the dispatcher hot path.
pub fn handle_report_fault(
    state: &mut SupervisorState,
    badge: u64,
    request_regs: &[u64; 32],
    reply: &mut TronaMsg,
) {
    if badge != INIT_BADGE_FROM_MMSRV {
        reply.label = trona_protocol::common::TRONA_PERMISSION_DENIED;
        return;
    }

    // mmsrv encodes `regs[0]` as packed `(client_id << 32) | tcb_id`
    // and `regs[1] = 0`. Resolve the victim by `client_id` (the
    // mmsrv-side identity) — `pid` is init-side bookkeeping that
    // mmsrv does not carry, so init looks it up via the proc table's
    // client-id index.
    let packed = request_regs[0];
    let victim_client_id = (packed >> 32) as u32;
    let victim_tcb_id = (packed & 0xFFFF_FFFF) as u32;
    let fault_kind = request_regs[2];
    let fault_word0 = request_regs[3];
    let fault_word1 = request_regs[4];
    let fault_word2 = request_regs[5];
    let fault_word3 = request_regs[6];
    let victim = state.procs.find_by_client_id(victim_client_id);
    let victim_pid = victim.map(|p| p.pid).unwrap_or(0);
    let victim_name = victim.map(|p| p.name);

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[INIT] fault pid=");
        _lb.dec(victim_pid as u64);
        if let Some(name) = victim_name {
            _lb.str(b" name=");
            _lb.bytes(name.as_bytes());
        }
        _lb.str(b" client=");
        _lb.dec(victim_client_id as u64);
        _lb.str(b" tcb=");
        _lb.dec(victim_tcb_id as u64);
        _lb.str(b" kind=");
        _lb.hex(fault_kind);
        _lb.str(b" w0=");
        _lb.hex(fault_word0);
        _lb.str(b" w1=");
        _lb.hex(fault_word1);
        _lb.str(b" w2=");
        _lb.hex(fault_word2);
        _lb.str(b" w3=");
        _lb.hex(fault_word3);
        _lb.str(b"\n");
    });

    // Resolve victim. If the pid is gone we still owe mmsrv a reply —
    // tell it to drop (the kernel will tear down the TCB anyway).
    if state.procs.get(victim_pid).is_none() {
        reply.label = uapi::KERNITE_OK as u64;
        reply.length = 1;
        reply.regs[0] = FAULT_ACTION_KILL;
        return;
    }

    // Map fault kind → signal → action. PAGE_FAULT recoverable was
    // already handled by mmsrv before reaching us. OOM here means
    // mmsrv exhausted its backoff queue.
    let sig = fault_kind_to_signal(fault_kind);
    let action = match fault_kind {
        // OOM is uncatchable — kill the whole pgid so a runaway
        // workload does not wedge the system.
        x if x == crate::wire::FAULT_KIND_OOM => FAULT_ACTION_KILL_GROUP,
        _ => FAULT_ACTION_KILL,
    };
    crate::supervisor::lifecycle::finalize_exit(state, victim_pid, -(sig as i32));

    reply.label = uapi::KERNITE_OK as u64;
    reply.length = 1;
    reply.regs[0] = match action {
        FAULT_ACTION_KILL_GROUP => FAULT_ACTION_KILL_GROUP,
        FAULT_ACTION_KILL => FAULT_ACTION_KILL,
        _ => FAULT_ACTION_RESUME,
    };
}
