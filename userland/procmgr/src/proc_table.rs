//! Process table management
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

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

// ===========================================================================
// Process struct
// ===========================================================================

pub struct Process {
    pub pid: u32,
    pub ppid: u32,
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
}

impl Process {
    pub const fn zeroed() -> Self {
        Process {
            pid: 0,
            ppid: 0,
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
        for i in 0..NSIG {
            p.sig_disposition[i] = SIG_DISP_DFL;
        }
        p.state = PROC_FREE;
    }
}
