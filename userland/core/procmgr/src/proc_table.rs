//! Process table management
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::layout::VmLayoutPlan;
use trona::types::Cap;

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
pub const INITIAL_CAPACITY: usize = 16;
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
    /// Child readiness notification captured at spawn time for notify services.
    pub ready_ntfn: Cap,
    /// Whether PM_RESUME must wait for the child readiness notification once.
    pub wait_ready_on_resume: bool,
    /// Timeout used when waiting for the child's readiness signal after resume.
    pub ready_timeout_ns: u64,
    /// POSIX ITIMER_REAL reload interval in nanoseconds (0 = one-shot/disabled).
    pub itimer_real_interval_ns: u64,
    /// Absolute CLOCK_REALTIME deadline in nanoseconds for the next SIGALRM.
    /// Zero means no ITIMER_REAL is armed.
    pub itimer_real_deadline_ns: u64,
    pub sig_disposition: [u8; NSIG],
    pub stop_status: i32,
    pub pgid: u32,
    /// Base cap slot and count for this process's objects in procmgr CSpace.
    /// Set by the allocator during spawn; used for cleanup.
    pub slot_base: Cap,
    pub slot_count: u16,
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
    /// Number of CSpace expansions granted to this process (max 8).
    pub cspace_expand_count: u8,
    /// Whether this process is registered with mmsrv.
    pub mmsrv_registered: bool,
    /// Whether this process has a pre-created service EP at CHILD_CAP_SERVICE_EP.
    pub has_service_ep: bool,
    /// Restart on exit (set by SPAWN_FLAG_RESPAWN).
    pub respawn: bool,
    /// NUL-terminated binary name for respawn.
    pub respawn_binary: [u8; MAX_NAME_LEN],
    /// NUL-terminated process name (set at spawn/exec).
    pub name: [u8; 32],
    /// File creation mask (default 0o022).
    pub umask: u32,
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
            ready_ntfn: 0,
            wait_ready_on_resume: false,
            ready_timeout_ns: 0,
            itimer_real_interval_ns: 0,
            itimer_real_deadline_ns: 0,
            sig_disposition: [SIG_DISP_DFL; NSIG],
            stop_status: 0,
            pgid: 0,
            slot_base: 0,
            slot_count: 0,
            shared_lib_base: 0,
            lib_map: ProcLibMap::zeroed(),
            layout: VmLayoutPlan::zeroed(),
            expand_pending: false,
            expand_result_base: 0,
            expand_result_count: 0,
            cspace_expand_count: 0,
            mmsrv_registered: false,
            has_service_ep: false,
            respawn: false,
            respawn_binary: [0; MAX_NAME_LEN],
            name: [0; 32],
            umask: 0o022,
        }
    }
}

// ===========================================================================
// Growable process table
// ===========================================================================

/// Pointer to the process table (mmap'd memory).
static mut PROCTAB_PTR: *mut Process = core::ptr::null_mut();
/// Current capacity of the table.
static mut PROCTAB_CAP: usize = 0;

pub static mut NEXT_PID: u32 = 2;

/// Initialize the process table via posix_mmap.
///
/// Must be called once at procmgr startup, after mmsrv is available.
pub unsafe fn init_proctab() {
    unsafe {
        let cap = INITIAL_CAPACITY;
        let size = cap * core::mem::size_of::<Process>();
        let pages = (size + 4095) / 4096;
        let ptr = trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            (pages * 4096) as u64,
            0x3,  // PROT_READ | PROT_WRITE
            0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            -1,
            0,
        );
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FATAL: proctab mmap failed\n");
            });
            return;
        }
        PROCTAB_PTR = ptr as *mut Process;
        PROCTAB_CAP = cap;

        // Initialize all entries to zeroed
        for i in 0..cap {
            core::ptr::write(PROCTAB_PTR.add(i), Process::zeroed());
        }
    }
}

/// Get the current capacity of the process table.
#[inline]
pub fn proctab_cap() -> usize {
    unsafe { PROCTAB_CAP }
}

/// Access a process entry by index.
///
/// # Safety
/// Caller must ensure `idx < proctab_cap()`.
#[inline]
pub unsafe fn proctab(idx: usize) -> &'static mut Process {
    unsafe { &mut *PROCTAB_PTR.add(idx) }
}

/// Grow the process table by doubling capacity.
///
/// Returns true on success, false on failure.
unsafe fn grow_proctab() -> bool {
    unsafe {
        let old_cap = PROCTAB_CAP;
        let new_cap = old_cap * 2;
        let old_size = old_cap * core::mem::size_of::<Process>();
        let new_size = new_cap * core::mem::size_of::<Process>();
        let new_pages = (new_size + 4095) / 4096;

        let new_raw = trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            (new_pages * 4096) as u64,
            0x3,  // PROT_READ | PROT_WRITE
            0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            -1,
            0,
        );
        if new_raw.is_null() || new_raw == usize::MAX as *mut u8 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] proctab grow failed\n");
            });
            return false;
        }

        let new_ptr = new_raw as *mut Process;

        // Copy old entries
        let src = PROCTAB_PTR as *const u8;
        let dst = new_ptr as *mut u8;
        for i in 0..old_size {
            core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        }

        // Initialize new entries to zeroed
        for i in old_cap..new_cap {
            core::ptr::write(new_ptr.add(i), Process::zeroed());
        }

        // Unmap old region
        let old_pages = (old_size + 4095) / 4096;
        trona_posix::mm::posix_munmap(PROCTAB_PTR as *mut u8, (old_pages * 4096) as u64);

        PROCTAB_PTR = new_ptr;
        PROCTAB_CAP = new_cap;

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] proctab grown to ");
            _lb.hex(new_cap as u64);
            _lb.str(b" entries\n");
        });

        true
    }
}

// ===========================================================================
// Lookup helpers
// ===========================================================================

pub fn find_by_badge(badge: u64) -> Option<usize> {
    unsafe {
        let cap = PROCTAB_CAP;
        for i in 0..cap {
            let p = &*PROCTAB_PTR.add(i);
            if p.state != PROC_FREE && p.badge == badge {
                return Some(i);
            }
        }
    }
    None
}

pub fn find_by_pid(pid: u32) -> Option<usize> {
    unsafe {
        let cap = PROCTAB_CAP;
        for i in 0..cap {
            let p = &*PROCTAB_PTR.add(i);
            if p.state != PROC_FREE && p.pid == pid {
                return Some(i);
            }
        }
    }
    None
}

pub fn alloc_proc() -> Option<usize> {
    unsafe {
        let cap = PROCTAB_CAP;
        for i in 0..cap {
            let p = &*PROCTAB_PTR.add(i);
            if p.state == PROC_FREE {
                return Some(i);
            }
        }
        // All slots full — try to grow
        if grow_proctab() {
            // First slot in the new region
            return Some(cap);
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
        let p = &*PROCTAB_PTR.add(idx);
        let child_cn = p.cnode_cap;

        // Revoke all caps in child's CNode
        if child_cn != 0 {
            let child_cnode_slots = 1024u64;
            for i in 0..child_cnode_slots {
                let err = trona::invoke::cnode_revoke(child_cn, i);
                if err != 0 {
                    trona::invoke::cnode_delete(child_cn, i);
                }
            }
        }

        // Revoke procmgr-side caps for this process
        let base = p.slot_base;
        let count = p.slot_count as u64;

        if count > 0 {
            // New allocator path: clean up only the allocated range
            for i in 0..count {
                let slot = base + i;
                let err = trona::invoke::cnode_revoke(cap_self_cspace, slot);
                if err != 0 {
                    trona::invoke::cnode_delete(cap_self_cspace, slot);
                }
            }
        }

        // Reset process entry
        let p = &mut *PROCTAB_PTR.add(idx);
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
        p.ready_ntfn = 0;
        p.wait_ready_on_resume = false;
        p.ready_timeout_ns = 0;
        p.itimer_real_interval_ns = 0;
        p.itimer_real_deadline_ns = 0;
        p.stop_status = 0;
        p.pgid = 0;
        p.slot_base = 0;
        p.slot_count = 0;
        p.shared_lib_base = 0;
        p.lib_map = ProcLibMap::zeroed();
        p.expand_pending = false;
        p.expand_result_base = 0;
        p.expand_result_count = 0;
        p.cspace_expand_count = 0;
        p.mmsrv_registered = false;
        p.has_service_ep = false;
        p.respawn = false;
        for i in 0..MAX_NAME_LEN {
            p.respawn_binary[i] = 0;
        }
        for i in 0..NSIG {
            p.sig_disposition[i] = SIG_DISP_DFL;
        }
        p.umask = 0o022;
        p.state = PROC_FREE;
    }
}
