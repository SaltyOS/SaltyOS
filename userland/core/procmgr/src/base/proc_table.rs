//! Process table management
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::layout::VmLayoutPlan;
use trona::types::core::Cap;

use crate::base::child_layout::ChildCapLayout;
use crate::personality::PersonalityKind;

// ---- Process states ----
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Free     = 0,
    Spawning = 1,
    Running  = 2,
    Stopped  = 3,
    Exiting  = 4,
    Zombie   = 5,
}

impl ProcessState {
    pub fn is_ipc_eligible(self) -> bool {
        matches!(self, Self::Running | Self::Stopped)
    }

    pub fn is_transitional(self) -> bool {
        matches!(self, Self::Spawning | Self::Exiting)
    }
}

// ---- Subsystem IDs ----
pub const SUBSYS_POSIX: u8 = 0;
pub const SUBSYS_WIN32: u8 = 1;

// ---- Signal constants ----
pub const NSIG: usize = 32;
pub const SIG_DISP_DFL: u8 = 0;
pub const SIG_DISP_IGN: u8 = 1;
pub const SIG_DISP_CATCH: u8 = 2;

// ---- Limits ----
pub const INITIAL_CAPACITY: usize = 16;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_EXE_PATH_LEN: usize = 128;

// ---- Per-process shared library mapping ----
pub const MAX_PROC_MAPPED_LIBS: usize = 8;

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
// POSIX personality state (signal dispositions + credentials/limits)
// ===========================================================================

pub const NGROUPS_MAX: usize = 32;
pub const RLIM_NLIMITS: usize = 8;
pub const RLIM_INFINITY: u64 = u64::MAX;

pub struct PosixState {
    pub sig_disposition: [u8; NSIG],
    /// File creation mask (default 0o022).
    pub umask: u32,
    // Multi-user credentials
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub ngroups: u32,
    pub groups: [u32; NGROUPS_MAX],
    pub rlimits: [[u64; 2]; RLIM_NLIMITS],
}

impl PosixState {
    pub const fn zeroed() -> Self {
        PosixState {
            sig_disposition: [SIG_DISP_DFL; NSIG],
            umask: 0o022,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            ngroups: 0,
            groups: [0; NGROUPS_MAX],
            rlimits: [[RLIM_INFINITY; 2]; RLIM_NLIMITS],
        }
    }
}

// ===========================================================================
// Win32 personality state (minimal placeholder)
// ===========================================================================

pub struct Win32State {
    pub _reserved: u8,
}

impl Win32State {
    pub const fn zeroed() -> Self {
        Win32State { _reserved: 0 }
    }
}

// ===========================================================================
// Personality state enum
// ===========================================================================

pub enum PersonalityState {
    Posix(PosixState),
    Win32(Win32State),
    None,
}

impl PersonalityState {
    pub const fn none() -> Self {
        PersonalityState::None
    }

    pub const fn from_subsystem_id(subsystem_id: u8) -> Self {
        match subsystem_id {
            SUBSYS_WIN32 => PersonalityState::Win32(Win32State::zeroed()),
            _ => PersonalityState::Posix(PosixState::zeroed()),
        }
    }

    pub const fn is_posix(&self) -> bool {
        matches!(self, PersonalityState::Posix(_))
    }

    pub const fn is_win32(&self) -> bool {
        matches!(self, PersonalityState::Win32(_))
    }

    pub fn posix(&self) -> Option<&PosixState> {
        match self {
            PersonalityState::Posix(s) => Some(s),
            _ => None,
        }
    }

    pub fn posix_mut(&mut self) -> Option<&mut PosixState> {
        match self {
            PersonalityState::Posix(s) => Some(s),
            _ => None,
        }
    }
}

// ===========================================================================
// Thread table (per-process; main thread excluded)
// ===========================================================================

/// Maximum auxiliary threads (PM_THREAD_CREATE) per process.
/// Main thread (tid=0) is tracked via the Process struct itself, not here.
pub const MAX_THREADS_PER_PROC: usize = 63;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Unused   = 0,
    Creating = 1,
    Running  = 2,
    Exiting  = 3,
    Zombie   = 4,
}

/// Per-thread state record. Auxiliary threads only — the main thread's
/// kernel objects live in the Process struct (`tcb_cap`, `sc_cap`, ...).
#[derive(Clone, Copy)]
pub struct ThreadEntry {
    pub state: ThreadState,
    pub detached: bool,
    /// Per-process thread id (tid). 0 is reserved for main; auxiliary threads
    /// are assigned monotonically from `Process::next_tid`.
    pub tid: u32,
    /// procmgr-side cap slot for this thread's TCB. Caller (libpthread)
    /// receives a derived copy via cap_transfer in PM_THREAD_CREATE reply.
    pub tcb_cap: Cap,
    /// procmgr-side cap slot for this thread's SchedContext.
    pub sc_cap: Cap,
    /// procmgr-side cap slot for this thread's IPC buffer frame.
    pub frame_cap: Cap,
    /// rsrcsrv handles for the three objects above (TCB, SC, Frame).
    /// Used by per-thread reap (`RES_FREE_HANDLE`). Process-wide reap
    /// goes through `RES_RECLAIM_OWNER` and ignores these.
    pub rsrcsrv_handles: [u64; 3],
    /// Exit value passed by `pthread_exit` (or 0 if still running).
    pub retval: u64,
    /// Saved reply cap of a `PM_THREAD_JOIN` caller waiting for this thread
    /// to exit. 0 if no joiner is currently parked.
    pub joiner_reply_cap: Cap,
    /// Where the IPC buffer frame is mapped in the child's VSpace.
    /// Needed for cleanup (`vspace_unmap`) at reap time.
    pub ipc_buf_vaddr: u64,
}

impl ThreadEntry {
    pub const fn zeroed() -> Self {
        ThreadEntry {
            state: ThreadState::Unused,
            detached: false,
            tid: 0,
            tcb_cap: 0,
            sc_cap: 0,
            frame_cap: 0,
            rsrcsrv_handles: [0; 3],
            retval: 0,
            joiner_reply_cap: 0,
            ipc_buf_vaddr: 0,
        }
    }
}

pub struct ThreadTable {
    pub entries: [ThreadEntry; MAX_THREADS_PER_PROC],
    pub count: u16,
    pub next_tid: u32,
}

impl ThreadTable {
    pub const fn zeroed() -> Self {
        ThreadTable {
            entries: [ThreadEntry::zeroed(); MAX_THREADS_PER_PROC],
            count: 0,
            next_tid: 1,
        }
    }
}

// ===========================================================================
// Process struct
// ===========================================================================

pub struct Process {
    // ---- Generic core (subsystem-neutral) ----
    pub state: ProcessState,
    pub pid: u32,
    pub ppid: u32,
    pub exit_code: i32,
    /// Capability badge used for per-process IPC identity.
    ///
    /// mmsrv and VFS client state are keyed by this badge. It is currently
    /// pid-derived, but callers should treat it as the process IPC identity,
    /// not recompute the contract ad hoc at each call site.
    pub badge: u64,
    pub tcb_cap: Cap,
    pub vspace_cap: Cap,
    pub cnode_cap: Cap,
    pub sc_cap: Cap,
    /// Per-spawn layout of well-known caps inside this child's CSpace.
    /// Populated by spawn_tx/fork_exec from a `ChildSlotAlloc` cursor and
    /// communicated to the child via `AT_TRONA_*` auxv tags.
    pub cap_layout: ChildCapLayout,
    /// Base cap slot and count for this process's objects in procmgr CSpace.
    pub slot_base: Cap,
    pub slot_count: u16,
    /// Base address of shared library RO pages (from spawn_tx cache).
    pub shared_lib_base: u64,
    /// Per-process library mapping (which cached libs, at what VAs).
    pub lib_map: ProcLibMap,
    /// VA layout used when this process was spawned/exec'd.
    pub layout: VmLayoutPlan,
    /// Whether this process is registered with mmsrv.
    pub mmsrv_registered: bool,
    /// Whether this process has a pre-created service EP in its CSpace.
    /// The child-side slot index is recorded in `cap_layout.service_ep`.
    pub has_service_ep: bool,
    /// Restart on exit (set by SPAWN_FLAG_RESPAWN).
    pub respawn: bool,
    /// NUL-terminated binary name for respawn.
    pub respawn_binary: [u8; MAX_NAME_LEN],
    /// NUL-terminated process name (set at spawn/exec).
    pub name: [u8; 32],
    /// Per-process timer reload interval in nanoseconds (0 = one-shot/disabled).
    pub timer_interval_ns: u64,
    /// Absolute CLOCK_REALTIME deadline in nanoseconds for the next timer signal.
    pub timer_deadline_ns: u64,
    /// Readiness badge bit assigned to this process (Type=notify only).
    /// Index into the shared procmgr BOUND_NTFN badge word — when the child
    /// invokes `SYS_SIGNAL(readiness_ntfn)`, the kernel ORs `1 << bit` into
    /// procmgr's notification word, waking `reply_recv`. Value is
    /// `readiness::BIT_NONE` when unassigned (fork/exec, non-notify svc, or
    /// after completion/timeout).
    pub ready_badge_bit: u8,
    /// Monotonic process start time in nanoseconds since boot.
    pub start_time_ns: u64,
    /// POSIX-style process relationship state preserved across personality
    /// switches so wait/tty/process-group operations can still see the child.
    pub pgid: u32,
    pub sid: u32,
    pub ctty_dev: u64,
    pub ctty_pgrp: u32,
    /// Per-process signal notification object. POSIX signal delivery still
    /// consults personality-specific dispositions, but the cap itself survives
    /// cross-personality exec.
    pub signal_ntfn: Cap,
    /// Last wait/stop status observed for this process.
    pub stop_status: i32,
    /// Saved reply cap for a specific-child waiter parked on this process.
    pub waiter_reply: Cap,
    pub waiter_pid: u32,
    /// Saved reply cap for a parent waiting on any child.
    pub any_waiter_reply: Cap,
    pub waiting_for_any: u8,
    /// NUL-terminated executable path used for /proc/<pid>/exe.
    pub exe_path: [u8; MAX_EXE_PATH_LEN],
    /// Whether PM_RESUME must wait for the child readiness notification once.
    pub wait_ready_on_resume: bool,
    /// Timeout used when waiting for the child's readiness signal after resume.
    pub ready_timeout_ns: u64,
    /// CNode slot holding the saved reply cap for a deferred readiness wait.
    /// 0 = no pending readiness wait.
    pub pending_ready_reply: Cap,
    /// Absolute deadline (ns) for the pending readiness timeout.
    pub pending_ready_deadline_ns: u64,

    /// Auxiliary threads (libpthread / win32 thread shim spawned).
    /// Main thread (tid=0) is represented by Process itself, not by an entry.
    pub threads: ThreadTable,

    // ---- Personality (subsystem-specific state) ----
    pub personality: PersonalityState,
}

impl Process {
    pub const fn zeroed() -> Self {
        Process {
            state: ProcessState::Free,
            pid: 0,
            ppid: 0,
            exit_code: 0,
            badge: 0,
            tcb_cap: 0,
            vspace_cap: 0,
            cnode_cap: 0,
            sc_cap: 0,
            cap_layout: ChildCapLayout::zeroed(),
            slot_base: 0,
            slot_count: 0,
            shared_lib_base: 0,
            lib_map: ProcLibMap::zeroed(),
            layout: VmLayoutPlan::zeroed(),
            mmsrv_registered: false,
            has_service_ep: false,
            respawn: false,
            respawn_binary: [0; MAX_NAME_LEN],
            name: [0; 32],
            timer_interval_ns: 0,
            timer_deadline_ns: 0,
            ready_badge_bit: crate::base::readiness::BIT_NONE,
            start_time_ns: 0,
            pgid: 0,
            sid: 0,
            ctty_dev: 0,
            ctty_pgrp: 0,
            signal_ntfn: 0,
            stop_status: 0,
            waiter_reply: 0,
            waiter_pid: 0,
            any_waiter_reply: 0,
            waiting_for_any: 0,
            exe_path: [0; MAX_EXE_PATH_LEN],
            wait_ready_on_resume: false,
            ready_timeout_ns: 0,
            pending_ready_reply: 0,
            pending_ready_deadline_ns: 0,
            threads: ThreadTable::zeroed(),
            personality: PersonalityState::None,
        }
    }

    /// Access POSIX state (panics if not POSIX subsystem).
    /// Callers that iterate all processes must guard with `is_posix()`.
    pub fn posix(&self) -> &PosixState {
        match &self.personality {
            PersonalityState::Posix(s) => s,
            _ => unreachable!(),
        }
    }

    /// Mutable access to POSIX state.
    /// Panics if the personality is not POSIX. Callers that iterate all
    /// processes should guard with `is_posix()` or check `.posix()` first.
    pub fn posix_mut(&mut self) -> &mut PosixState {
        match &mut self.personality {
            PersonalityState::Posix(s) => s,
            _ => unreachable!(),
        }
    }

    pub fn is_posix(&self) -> bool {
        self.personality.is_posix()
    }

    pub fn set_personality_kind(&mut self, kind: PersonalityKind) {
        self.personality = match kind {
            PersonalityKind::Posix => PersonalityState::Posix(PosixState::zeroed()),
            PersonalityKind::Win32 => PersonalityState::Win32(Win32State::zeroed()),
        };
    }

    pub fn personality_kind(&self) -> PersonalityKind {
        match self.personality {
            PersonalityState::Posix(_) => PersonalityKind::Posix,
            PersonalityState::Win32(_) => PersonalityKind::Win32,
            PersonalityState::None => PersonalityKind::Posix,
        }
    }
}

#[inline]
pub fn monotonic_now_ns() -> u64 {
    trona::syscall::syscall(
        trona::consts::kernel::SYS_CLOCK_GETTIME,
        trona::consts::kernel::CLOCK_MONOTONIC as u64,
        0,
        0,
        0,
        0,
        0,
    )
    .value
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
            if p.state != ProcessState::Free && p.badge == badge {
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
            if p.state != ProcessState::Free && p.pid == pid {
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
            if p.state == ProcessState::Free {
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
        core::ptr::write(PROCTAB_PTR.add(idx), Process::zeroed());
    }
}
