//! Process table management
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use salty::layout::VmLayoutPlan;
use salty::types::Cap;

// ---- Process states ----
pub const PROC_FREE: u8 = 0;
pub const PROC_RUNNING: u8 = 1;
pub const PROC_ZOMBIE: u8 = 2;
pub const PROC_STOPPED: u8 = 3;

// ---- Signal constants ----
pub const NSIG: usize = 32;
pub const SIG_DISP_DFL: u8 = 0;
pub const SIG_DISP_IGN: u8 = 1;
pub const SIG_DISP_CATCH: u8 = 2;

// ---- Limits ----
pub const MAX_PROCESSES: usize = 16;
pub const MAX_NAME_LEN: usize = 32;

// ---- Per-process shared library mapping ----
pub const MAX_PROC_MAPPED_LIBS: usize = 4;

/// Compact record of which cached libraries were mapped into a process and
/// at what base VA. Used by fork to identify and re-share cached frames.
#[derive(Clone, Copy)]
pub struct ProcLibMap {
    pub count: u8,
    /// Index into SharedLibCache.libs[] for each mapped library.
    pub lib_idx: [u8; MAX_PROC_MAPPED_LIBS],
    /// Mapped base VA for each library.
    pub base: [u64; MAX_PROC_MAPPED_LIBS],
}

impl ProcLibMap {
    pub const fn zeroed() -> Self {
        ProcLibMap {
            count: 0,
            lib_idx: [0; MAX_PROC_MAPPED_LIBS],
            base: [0; MAX_PROC_MAPPED_LIBS],
        }
    }
}

// ===========================================================================
// Process struct
// ===========================================================================

pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub sid: u32,
    pub state: u8,
    pub exit_code: i32,
    pub badge: u64,
    pub tcb_cap: Cap,
    pub vspace_cap: Cap,
    pub cnode_cap: Cap,
    pub sc_cap: Cap,
    pub waiter_reply: Cap,
    pub waiter_pid: u32,
    pub any_waiter_reply: Cap,
    pub waiting_for_any: u8,
    pub signal_ntfn: Cap,
    pub sig_disposition: [u8; NSIG],
    pub stop_status: i32,
    pub pgid: u32,
    /// Base cap slot and count for this process's objects in procmgr CSpace.
    /// Set by the allocator during spawn; used for cleanup.
    pub slot_base: Cap,
    pub slot_count: u16,
    /// Secondary frame range from exec (freed on cleanup).
    pub frame_base: Cap,
    pub frame_count: u16,
    /// Base address of shared library RO pages (from spawn_tx cache).
    pub shared_lib_base: u64,
    /// Per-process library mapping (which cached libs, at what VAs).
    pub lib_map: ProcLibMap,
    /// VA layout used when this process was spawned/exec'd.
    pub layout: VmLayoutPlan,
    /// Async CSpace expansion: pending result flag.
    pub expand_pending: bool,
    /// Async CSpace expansion: result base address.
    pub expand_result_base: u64,
    /// Async CSpace expansion: result slot count.
    pub expand_result_count: u64,
    /// Procmgr-local cap to child's untyped (for init-registered services).
    pub child_ut_cap: Cap,
    /// Number of untyped expansions granted to this process (max 8).
    pub ut_expand_count: u8,
    /// Whether this process has a pre-created service EP at CHILD_CAP_SERVICE_EP.
    pub has_service_ep: bool,
    /// Restart on exit (set by SPAWN_FLAG_RESPAWN).
    pub respawn: bool,
    /// NUL-terminated binary name for respawn.
    pub respawn_binary: [u8; MAX_NAME_LEN],
}

impl Process {
    pub const fn zeroed() -> Self {
        Process {
            pid: 0,
            ppid: 0,
            sid: 0,
            state: PROC_FREE,
            exit_code: 0,
            badge: 0,
            tcb_cap: 0,
            vspace_cap: 0,
            cnode_cap: 0,
            sc_cap: 0,
            waiter_reply: 0,
            waiter_pid: 0,
            any_waiter_reply: 0,
            waiting_for_any: 0,
            signal_ntfn: 0,
            sig_disposition: [SIG_DISP_DFL; NSIG],
            stop_status: 0,
            pgid: 0,
            slot_base: 0,
            slot_count: 0,
            frame_base: 0,
            frame_count: 0,
            shared_lib_base: 0,
            lib_map: ProcLibMap::zeroed(),
            layout: VmLayoutPlan::zeroed(),
            expand_pending: false,
            expand_result_base: 0,
            expand_result_count: 0,
            child_ut_cap: 0,
            ut_expand_count: 0,
            has_service_ep: false,
            respawn: false,
            respawn_binary: [0; MAX_NAME_LEN],
        }
    }
}

// ===========================================================================
// Static state
// ===========================================================================

pub static mut PROCTAB: [Process; MAX_PROCESSES] = {
    const ZERO: Process = Process::zeroed();
    [ZERO; MAX_PROCESSES]
};
pub static mut NEXT_PID: u32 = 2;

// ===========================================================================
// Lookup helpers
// ===========================================================================

pub fn find_by_badge(badge: u64) -> Option<usize> {
    unsafe {
        for i in 0..MAX_PROCESSES {
            if PROCTAB[i].state != PROC_FREE && PROCTAB[i].badge == badge {
                return Some(i);
            }
        }
    }
    None
}

pub fn find_by_pid(pid: u32) -> Option<usize> {
    unsafe {
        for i in 0..MAX_PROCESSES {
            if PROCTAB[i].state != PROC_FREE && PROCTAB[i].pid == pid {
                return Some(i);
            }
        }
    }
    None
}

pub fn alloc_proc() -> Option<usize> {
    unsafe {
        for i in 0..MAX_PROCESSES {
            if PROCTAB[i].state == PROC_FREE {
                return Some(i);
            }
        }
    }
    None
}

/// Clean up all capability resources for a process and mark it free.
///
/// Uses the per-process slot_range if set (new allocator path),
/// otherwise falls back to stride-based cleanup for legacy compatibility.
pub unsafe fn cleanup_proc_resources(idx: usize, cap_self_cspace: Cap) {
    unsafe {
        let child_cn = PROCTAB[idx].cnode_cap;

        // Revoke all caps in child's CNode
        if child_cn != 0 {
            let child_cnode_slots = 1024u64;
            for i in 0..child_cnode_slots {
                let err = salty::invoke::cnode_revoke(child_cn, i);
                if err != 0 {
                    salty::invoke::cnode_delete(child_cn, i);
                }
            }
        }

        // Revoke procmgr-side caps for this process
        let base = PROCTAB[idx].slot_base;
        let count = PROCTAB[idx].slot_count as u64;

        if count > 0 {
            // New allocator path: clean up only the allocated range
            for i in 0..count {
                let slot = base + i;
                let err = salty::invoke::cnode_revoke(cap_self_cspace, slot);
                if err != 0 {
                    salty::invoke::cnode_delete(cap_self_cspace, slot);
                }
            }
        }

        // Reset process entry
        let p = &mut PROCTAB[idx];
        p.pid = 0;
        p.ppid = 0;
        p.sid = 0;
        p.exit_code = 0;
        p.badge = 0;
        p.tcb_cap = 0;
        p.vspace_cap = 0;
        p.cnode_cap = 0;
        p.sc_cap = 0;
        p.waiter_reply = 0;
        p.waiter_pid = 0;
        p.any_waiter_reply = 0;
        p.waiting_for_any = 0;
        p.signal_ntfn = 0;
        p.stop_status = 0;
        p.pgid = 0;
        p.slot_base = 0;
        p.slot_count = 0;
        p.frame_base = 0;
        p.frame_count = 0;
        p.shared_lib_base = 0;
        p.lib_map = ProcLibMap::zeroed();
        p.expand_pending = false;
        p.expand_result_base = 0;
        p.expand_result_count = 0;
        p.child_ut_cap = 0;
        p.ut_expand_count = 0;
        p.has_service_ep = false;
        p.respawn = false;
        for i in 0..MAX_NAME_LEN {
            p.respawn_binary[i] = 0;
        }
        for i in 0..NSIG {
            p.sig_disposition[i] = SIG_DISP_DFL;
        }
        p.state = PROC_FREE;
    }
}
