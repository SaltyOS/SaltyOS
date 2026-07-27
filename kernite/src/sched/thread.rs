// SPDX-License-Identifier: GPL-2.0-only
//! Thread Control Block
//!

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::cap::CNode;
use crate::cap::{KernelObject, ObjectType};
use crate::mm::VSpace;
use crate::sched::class::fair::{
    FAIR_DEFAULT_SLICE_NS, FAIR_DEFAULT_WEIGHT, FAIR_DEFAULT_WEIGHT_HI, FAIR_DEFAULT_WEIGHT_LO,
    FAIR_KEY_BASE, FAIR_LAG_INVALID_NS, FAIR_VTIME_BASE,
};
use crate::sched::class::idle::IDLE_KEY_BASE;
use crate::sched::class::rt::{RT_FIFO_KEY_BASE, RT_FIFO_MAX_PRIORITY};
use crate::sched::class::{
    CLASS_KEY_MASK, SCHED_CLASS_DEADLINE, SCHED_CLASS_FAIR, SCHED_CLASS_IDLE, SCHED_CLASS_RT_FIFO,
    SCHED_CLASS_SHIFT,
};

pub const RUNTIME_MODE_KERNEL: u8 = 0;
pub const RUNTIME_MODE_USER: u8 = 1;

static NEXT_TCB_TRACE_ID: AtomicU64 = AtomicU64::new(1);

/// XSAVE state area for FPU/SSE context
///
/// FPU/SIMD save area.
///
/// x86_64: 64-byte aligned for XSAVE instruction requirements.
/// Size covers x87 (512) + XSAVE header (64) + AVX (256) = 832 bytes.
///
/// aarch64: 16-byte aligned for NEON register save/restore.
/// Size covers 32 x Q registers (512) + FPCR (4) + FPSR (4) = 528 bytes, rounded up.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(64))]
pub struct XSaveArea {
    pub data: [u8; 832],
}

#[cfg(target_arch = "aarch64")]
#[repr(C, align(16))]
pub struct XSaveArea {
    pub data: [u8; 528],
}

impl XSaveArea {
    pub const fn zeroed() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self { data: [0u8; 832] }
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self { data: [0u8; 528] }
        }
    }
}

// `ThreadState` is owned by the `task` plane — see
// `crate::task::state::ThreadState`. The `Tcb` field below imports
// it directly; every other module that matches on the state goes
// through the same path. There is no re-export here on purpose:
// each callsite names the owner module explicitly.
use crate::task::state::ThreadState;

/// Reason why a thread is blocked.
///
/// Pipe / queue waits are split into distinct variants so the
/// fastpath can verify the peer is in **exactly** the wait kind it
/// expects (e.g. "blocked reading on side B of this MessagePipeCore")
/// rather than the catch-all `PipeWait` that earlier revisions used.
#[derive(Clone, Copy)]
pub enum BlockedReason {
    /// Blocked on `EQ_WAIT` waiting for an `EventQueue` record.
    EventQueueWait,
    /// Blocked on `MP_READ` — waiting for a record from the peer side.
    PipeRead,
    /// Blocked on `MP_CALL` — waiting for the reply with this TCB's txid.
    PipeCall,
    /// Blocked on `MP_WRITE` — waiting for ring space.
    PipeWrite,
    /// Blocked on `DP_CONSUME` — waiting for inbound bytes.
    DataPipeRead,
    /// Blocked on `DP_PRODUCE` — waiting for outbound ring space.
    DataPipeWrite,
    /// Blocked on VSpace teardown — waiting for VSpace to become inactive.
    VSpaceWait,
    /// Blocked on `VSPACE_FUTEX_WAIT`.
    FutexBlocked,
    /// Blocked on `VSPACE_FUTEX_WAIT` with timeout.
    FutexTimedBlocked,
    /// Blocked on a file-backed page fault. The kernel parked the
    /// faulter on a `PendingPagerRequest` after emitting a
    /// `KERNITE_EVENT_TYPE_PAGER_REQUEST` to the attached pager's
    /// bound EventQueue. Wake is driven by `PAGER_SUPPLY_PAGE` (frame
    /// installed → faulting instruction retries) or `PAGER_FAIL`
    /// (surfaced to userspace via the existing fault delivery path
    /// as a SIGBUS-equivalent).
    PagerFaultBlocked,
}

impl BlockedReason {
    /// Whether this reason is a pipe-style wait — consumed by the
    /// fastpath wake helpers and the BlockedReason→Runnable check in
    /// the scheduler.
    #[inline]
    pub fn is_pipe_wait(self) -> bool {
        matches!(
            self,
            BlockedReason::PipeRead
                | BlockedReason::PipeCall
                | BlockedReason::PipeWrite
                | BlockedReason::DataPipeRead
                | BlockedReason::DataPipeWrite
                | BlockedReason::PagerFaultBlocked
        )
    }
}

/// Sentinel value meaning no CPU currently owns this thread's scheduler slot.
pub const RUN_OWNER_NONE: u8 = u8::MAX;

/// Scheduler-internal placement state for a Tcb.
///
/// Encapsulates ready-queue membership and the CPU that owns the thread's
/// live register state or a ready-queue dequeue claim. Touched only inside
/// `crate::sched`.
#[repr(C)]
pub(crate) struct SchedPlacement {
    pub(in crate::sched) last_cpu: u32,
    pub(in crate::sched) run_owner_cpu: AtomicU8,
    pub(crate) ready_queued: bool,
    pub(crate) queued_cpu: u32,
}

impl SchedPlacement {
    pub(in crate::sched) const fn new() -> Self {
        Self {
            last_cpu: 0xFFFF_FFFF,
            run_owner_cpu: AtomicU8::new(RUN_OWNER_NONE),
            ready_queued: false,
            queued_cpu: 0xFFFF_FFFF,
        }
    }
}

/// Thread Control Block
#[repr(C)]
pub struct Tcb {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Per-TCB spin lock state (0 = unlocked, 1 = locked)
    pub tcb_lock_state: core::sync::atomic::AtomicU8,
    /// Thread lifecycle state. Mutators live in
    /// `task::wait::mark_runnable_locked`,
    /// `task::wait::mark_blocked_locked`,
    /// `task::stop::mark_stopped_locked`,
    /// `task::quiesce::mark_dying_locked`,
    /// `task::state::mark_created_locked`,
    /// `task::state::mark_configured_locked`. Direct field assignment
    /// outside `task::*` and `sched::thread` init/cleanup is a
    /// convention violation — visibility stays `pub(crate)` because
    /// `task` is a sibling of `sched::thread`, so a tighter `pub(in
    /// path)` is not expressible without moving the field
    /// definition.
    pub(crate) state: ThreadState,
    /// Effective scheduler key. Lower values run first and may be boosted by PIP.
    pub priority: u64,
    /// Base scheduler key before any priority inheritance donation.
    pub base_priority: u64,
    /// TCB pointer this thread is donating priority to (PIP chain)
    pub pip_donating_to: *mut Tcb,
    /// Number of priority donations currently received (0 or 1)
    pub pip_donation_count: u16,
    /// Scheduler class for this thread.
    pub sched_class: u8,
    /// RT FIFO priority, or the low byte of Fair weight.
    pub rt_priority: u8,
    /// Scheduler-class flags, or the high byte of Fair weight.
    pub sched_flags: u8,
    /// Effective scheduler class used for the current ready-queue placement.
    pub queued_class: u8,
    /// Runtime-attribution mode for the thread's current continuation.
    pub runtime_mode: u8,
    /// Saved registers
    pub context: ThreadContext,
    /// Virtual address space root
    pub vspace_root: *mut VSpace,
    /// Capability space root
    pub cspace_root: *mut CNode,
    /// CSpace address depth (0 = flat single-level, non-zero = multi-level tree)
    pub cspace_depth: u8,
    /// IPC buffer address
    pub ipc_buffer: u64,
    /// Cached receive CNode slot for incoming cap transfers
    pub ipc_receive_cnode: u64,
    /// Cached receive index for incoming cap transfers
    pub ipc_receive_index: u64,
    /// Cached depth for resolving the receive CNode capability
    pub ipc_receive_depth: u64,
    /// Cached depth for resolving the destination slot path inside that CNode
    pub ipc_receive_slot_depth: u64,
    /// Stable scheduler-trace thread id. Immutable after allocation.
    pub trace_id: u64,
    /// Debug-only initial user entry point for service attribution in traces.
    /// Zero for kernel threads.
    pub debug_user_entry: u64,
    /// Pending invoke depth for argument 0 (set by SYS_SET_INVOKE_DEPTHS)
    pub invoke_depth0: u8,
    /// Pending invoke depth for argument 1 (set by SYS_SET_INVOKE_DEPTHS)
    pub invoke_depth1: u8,
    /// Scheduling context
    pub sched_context: *mut SchedContext,
    /// Fair-class virtual runtime used for EEVDF ordering.
    pub fair_vruntime: u64,
    /// Saved Fair lag in real runtime nanoseconds while off-rq.
    pub fair_saved_lag_ns: i64,
    /// CPU affinity (0xFFFF_FFFF = any CPU, otherwise specific CPU ID)
    pub cpu_affinity: u32,
    /// Scheduler-internal placement (last_cpu, run_owner_cpu, ready_queued, queued_cpu).
    pub(crate) placement: SchedPlacement,
    /// Fair ready-queue treap links — DEDICATED fields, not shared with any wait
    /// queue. `fair_left`/`fair_right`/`fair_parent` are the treap pointers;
    /// `fair_subtree_min` caches the min `fair_vruntime` in this subtree;
    /// `fair_subtree_stealable` caches whether this subtree holds any
    /// affinity-agnostic (stealable) entity. Decoupling these from the
    /// wait-queue link fields (`futex_next` / `vspace_wait_next` / `sleep_next`
    /// / `timer_wakeup_ns` / `blocked_vspace_tracking`) prevents scheduler
    /// topology from being corrupted by wait-queue manipulation.
    pub fair_left: *mut Tcb,
    pub fair_right: *mut Tcb,
    pub fair_parent: *mut Tcb,
    pub fair_subtree_min: u64,
    pub fair_subtree_stealable: bool,
    /// Next thread in queue
    pub next: *mut Tcb,
    /// Why this thread is blocked (valid when state == Blocked/Waiting)
    pub blocked_reason: Option<BlockedReason>,
    /// VSpace tracking pointer (for VSpaceWait)
    pub blocked_vspace_tracking: *mut crate::mm::VSpaceTracking,
    /// Next pointer for VSpace wait queue (intrusive)
    pub vspace_wait_next: *mut Tcb,
    /// Intrusive next pointer for `EventQueue::waiter_*` (used while
    /// blocked in `EQ_WAIT`) and for `MessagePipeCore` / `DataPipeCore`
    /// per-side waiter queues (used while blocked on `PipeRead`,
    /// `PipeWrite`, `DataPipeRead`, `DataPipeWrite`).
    pub eq_wait_next: *mut Tcb,
    /// Pointer to the kernel object that owns the waiter queue this
    /// TCB is currently parked on. Tagged by `blocked_reason`:
    /// `EventQueueWait` → `*mut EventQueue`; pipe waits →
    /// `*mut MessagePipeCore` / `*mut DataPipeCore`. The detach path
    /// uses this pointer + `wait_side` to remove the TCB from the
    /// correct queue when the thread is destroyed mid-wait.
    pub wait_object: *mut core::ffi::c_void,
    /// Side identity within `wait_object` for pipe waits — `SIDE_A`
    /// (0) or `SIDE_B` (1). Unused for `EventQueueWait`.
    pub wait_side: u8,
    /// Monotonic seq stamp the syscall layer increments on each
    /// pipe-wait entry. Used by the fastpath wake helpers to detect
    /// stale wake attempts after a cancel + re-wait race on the same
    /// TCB.
    pub wait_seq: u64,
    /// Per-thread `MP_CALL` reply slot (Zircon-style `MessageWaiter`): active
    /// txid + ready-flag + the delivered reply record/carriers. A matching
    /// reply-marked `MP_WRITE` delivers the reply here out-of-band and wakes
    /// this thread; the payload lives here, not in the recv ring.
    pub message_waiter: crate::ipc::message_pipe::MessageWaiter,
    /// Tagged fast-deposit mailbox for cross-thread MessagePipe
    /// delivery. Producer sites (`MessagePipe::try_write_fast`) publish
    /// records here; `MP_READ` claims deposits. The mailbox pins
    /// `source_obj` via refcount across the publish window so the raw
    /// pointer remains safe even if the source is destroyed between
    /// deposit and claim. See `ipc::message_pipe::MpFastMailbox` for
    /// the 5-state CAS protocol.
    pub mp_fast_mailbox: crate::ipc::message_pipe::MpFastMailbox,
    /// Embedded deadline-queue node. At most one armed deadline per
    /// thread (mutually exclusive across `Sleep` / `FutexTimed` /
    /// `IpcTimeout` because `blocked_reason` is a single-state field).
    /// Distinct from the fair treap's `sleep_next`/`futex_next`/
    /// `vspace_wait_next`/`timer_wakeup_ns` aliasing — those four
    /// fields are reused by the EEVDF tree and must NOT be
    /// re-purposed for deadline tracking.
    pub deadline_node: crate::sched::deadline_queue::DeadlineNode,
    /// Bound fault `MessagePipe` — receives faults via `TCB_SET_FAULT_PIPE`.
    pub fault_pipe: *mut crate::ipc::message_pipe::MessagePipe,
    /// Kernel stack top for syscall entry (per-thread kernel stack)
    pub kernel_stack_top: u64,
    /// One-page kernel trampoline stack used for first user dispatch on x86_64.
    pub trampoline_stack_top: u64,
    /// Per-thread stack canary (verified at syscall exit against %gs:32).
    /// Each thread gets its own unique canary so migration across CPUs
    /// does not cause false-positive corruption panics.
    pub stack_canary: u64,
    /// User stack upper bound — first VA above the usable reserve.
    /// Cache of the authoritative stack VmArea's end (see
    /// memory-model-audit I21); ground truth lives in the VSpace maple
    /// tree as the `region_kind = REGION_KIND_STACK` entry.
    pub user_stack_top: u64,
    /// Lowest VA inside the usable stack reserve (inclusive). Cache of
    /// the authoritative stack VmArea's start. Zero means "bounds not
    /// published yet"; the kernel treats zero as fail-closed for any
    /// stack range check.
    pub user_stack_min: u64,
    /// Lowest VA of the unmapped guard hole immediately below
    /// `user_stack_min` (inclusive). Zero means "no guard tracked". See
    /// memory-model-audit I22 — the range `[guard_bottom, stack_min)`
    /// must have neither VmArea nor present / demand PTE.
    pub user_stack_guard_bottom: u64,
    /// Aliased into the fair-class treap as the subtree min-vruntime
    /// cache (see `sched/scheduler.rs:42-43`). Reused across the
    /// EEVDF treap layout — not a wakeup deadline.
    pub timer_wakeup_ns: u64,
    /// Aliased into the fair-class treap as the left/right/parent
    /// link slot (see `sched/scheduler.rs:42-43`).
    pub sleep_next: *mut Tcb,
    /// FPU state save area (x86_64: XSAVE 832B, aarch64: NEON 528B).
    /// In eager FPU mode this buffer is the canonical state for any
    /// non-running thread; the currently running thread's live value is
    /// in the hardware registers and gets flushed on context switch.
    pub fpu_state: XSaveArea,
    /// Thread-local storage base address (FS_BASE MSR value)
    pub tls_base: u64,
    /// Architecture ABI thread pointer (x86_64 user GS base / aarch64 x18).
    pub abi_tp_base: u64,
    /// Next TCB in futex wait queue (intrusive linked list)
    pub futex_next: *mut Tcb,
    /// Virtual address this thread is waiting on (for futex)
    pub futex_addr: u64,
    /// VSpace pointer for futex address space identification
    pub futex_vspace: *mut VSpace,
    /// Futex timed wait result: 0 = woken by futex_wake, non-zero = timeout
    pub futex_wakeup_result: u64,
    /// Scheduler reference count — number of scheduler-owned raw pointer
    /// slots that currently reference this TCB.  Slots counted here:
    ///
    /// * `current[cpu]` on each CPU that is running the thread,
    /// * entry in a per-CPU ready queue (Fair tree / RT FIFO / Deadline),
    /// * per-CPU `pending_enqueue` deferred-wake slot.
    ///
    /// Transitions between slots preserve the count (incremented on the
    /// destination BEFORE the source is released) so the value is never
    /// transiently 0 while the scheduler still holds a raw pointer. While
    /// `> 0`, the capability system defers TCB destruction by setting
    /// `pending_destroy`; when the last scheduler slot is released and
    /// `pending_destroy` is set, the releasing path triggers the
    /// deferred destroy under `CAP_LOCK`.
    pub sched_ref: core::sync::atomic::AtomicU32,
    /// Set by `release_object` when capability refcount reaches 0 while
    /// `sched_ref > 0`.  Checked when `sched_ref` drops to 0 to trigger
    /// deferred destruction.
    pub pending_destroy: core::sync::atomic::AtomicBool,
    /// User-mode runtime attributed to this thread in nanoseconds.
    pub user_runtime_ns: AtomicU64,
    /// Kernel-mode runtime attributed to this thread in nanoseconds.
    pub system_runtime_ns: AtomicU64,
    /// Per-list intrusive links used by `DeferredReleaseList` to stitch this
    /// TCB into stack-local batches of pending `sched_ref` decrements.
    ///
    /// A scheduler operation is local to the CPU executing it, but different
    /// CPUs can legitimately stage releases for the same migrating TCB at the
    /// same time. Keeping one link/count per CPU lets each CPU own an
    /// independent stack-local list without corrupting another CPU's list.
    pub deferred_release_next: [*mut Tcb; crate::arch::MAX_CPUS],
    /// Per-CPU multiplicity for pending `sched_ref` decrements owed to that
    /// CPU's active `DeferredReleaseList`.
    pub deferred_release_count: [u32; crate::arch::MAX_CPUS],
}

#[inline]
pub(crate) fn ktrace_thread_state(g: &crate::kernel::printk::SerialGuard, state: ThreadState) {
    match state {
        ThreadState::Created => g.puts("Created"),
        ThreadState::Configured => g.puts("Configured"),
        ThreadState::Runnable => g.puts("Runnable"),
        ThreadState::Blocked => g.puts("Blocked"),
        ThreadState::Stopped => g.puts("Stopped"),
        ThreadState::Dying => g.puts("Dying"),
    }
}

#[inline]
pub(crate) fn ktrace_tcb_identity(g: &crate::kernel::printk::SerialGuard, tcb: &Tcb) {
    g.puts(" tid=");
    g.hex(tcb.trace_id);
    if !tcb.vspace_root.is_null() {
        g.puts(" vsid=");
        g.hex(unsafe { (*tcb.vspace_root).trace_id() });
    }

    #[cfg(target_arch = "x86_64")]
    {
        g.puts(" pc=");
        g.hex(tcb.context.rip);
    }

    #[cfg(target_arch = "aarch64")]
    {
        g.puts(" pc=");
        g.hex(tcb.context.return_elr);
    }
}

#[inline]
pub(crate) fn ktrace_blocked_reason(
    g: &crate::kernel::printk::SerialGuard,
    tcb: &Tcb,
    reason: Option<BlockedReason>,
) {
    match reason {
        None => g.puts("None"),
        Some(BlockedReason::EventQueueWait) => g.puts("EventQueueWait"),
        Some(BlockedReason::PipeRead) => g.puts("PipeRead"),
        Some(BlockedReason::PipeCall) => g.puts("PipeCall"),
        Some(BlockedReason::PipeWrite) => g.puts("PipeWrite"),
        Some(BlockedReason::DataPipeRead) => g.puts("DataPipeRead"),
        Some(BlockedReason::DataPipeWrite) => g.puts("DataPipeWrite"),
        Some(BlockedReason::PagerFaultBlocked) => g.puts("PagerFaultBlocked"),
        Some(BlockedReason::VSpaceWait) => {
            g.puts("VSpaceWait tracking=");
            g.hex(tcb.blocked_vspace_tracking as u64);
        }
        Some(BlockedReason::FutexBlocked) => {
            g.puts("FutexBlocked addr=");
            g.hex(tcb.futex_addr);
            g.puts(" vspace=");
            g.hex(tcb.futex_vspace as u64);
        }
        Some(BlockedReason::FutexTimedBlocked) => {
            g.puts("FutexTimedBlocked addr=");
            g.hex(tcb.futex_addr);
            g.puts(" vspace=");
            g.hex(tcb.futex_vspace as u64);
            if tcb.timer_wakeup_ns != 0 {
                g.puts(" deadline=");
                g.hex(tcb.timer_wakeup_ns);
            }
        }
    }
}

/// Saved thread context (x86_64)
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ThreadContext {
    // General purpose registers
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Instruction pointer
    pub rip: u64,
    // Flags
    pub rflags: u64,
    // Segments
    pub cs: u64,
    pub ss: u64,
}

/// Saved thread context (aarch64)
#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct ThreadContext {
    /// General purpose registers x0-x30
    pub x: [u64; 31],
    /// Saved userspace stack pointer restored into SP_EL0 on return.
    pub user_sp: u64,
    /// Saved EL1 stack pointer / context-switch anchor.
    ///
    /// For inactive/ready threads this points at the saved callee-saved
    /// register frame consumed by `aarch64_context_switch`. It is not the
    /// user-mode SP.
    pub sp: u64,
    /// Saved return PC restored into the active host ELR on `eret`.
    pub return_elr: u64,
    /// Saved return PSTATE restored into the active host SPSR on `eret`.
    pub return_spsr: u64,
}

#[cfg(target_arch = "x86_64")]
impl ThreadContext {
    pub const fn empty() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            cs: 0,
            ss: 0,
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl ThreadContext {
    pub const fn empty() -> Self {
        Self {
            x: [0u64; 31],
            user_sp: 0,
            sp: 0,
            return_elr: 0,
            return_spsr: 0,
        }
    }
}

/// Scheduling context (EDF parameters)
#[repr(C)]
pub struct SchedContext {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Per-SC spin lock state (0 = unlocked, 1 = locked)
    pub sc_lock_state: core::sync::atomic::AtomicU8,
    /// Budget per period in nanoseconds
    pub budget: u64,
    /// Remaining budget in nanoseconds
    pub remaining: u64,
    /// Period length in nanoseconds
    pub period: u64,
    /// Absolute deadline in nanoseconds
    pub deadline: u64,
    /// Bound TCB
    pub bound_tcb: *mut Tcb,
    /// Cumulative consumed runtime in nanoseconds.
    pub consumed: u64,
}

impl Tcb {
    #[inline]
    fn alloc_trace_id() -> u64 {
        NEXT_TCB_TRACE_ID.fetch_add(1, Ordering::Relaxed)
    }

    // `state()` accessor lives in `crate::task::state` because the
    // `state` field is narrow-visible to `crate::task` only.

    #[inline]
    pub fn trace_id(&self) -> u64 {
        self.trace_id
    }

    #[inline]
    pub fn ensure_trace_id(&mut self) {
        if self.trace_id == 0 {
            self.trace_id = Self::alloc_trace_id();
        }
    }

    #[inline]
    pub fn encode_deadline_priority(deadline: u64) -> u64 {
        deadline & CLASS_KEY_MASK
    }

    #[inline]
    pub fn encode_rt_fifo_priority(priority: u8) -> u64 {
        let clamped = if priority == 0 {
            1
        } else if priority > RT_FIFO_MAX_PRIORITY {
            RT_FIFO_MAX_PRIORITY
        } else {
            priority
        };
        RT_FIFO_KEY_BASE + (RT_FIFO_MAX_PRIORITY - clamped) as u64
    }

    #[inline]
    pub fn encode_fair_priority(vruntime: u64, slice_runtime: u64) -> u64 {
        FAIR_KEY_BASE + vruntime.saturating_add(slice_runtime).min(CLASS_KEY_MASK)
    }

    #[inline]
    pub fn encode_idle_priority() -> u64 {
        IDLE_KEY_BASE | CLASS_KEY_MASK
    }

    #[inline]
    pub fn priority_sched_class(priority: u64) -> u8 {
        match (priority >> SCHED_CLASS_SHIFT) as u8 {
            SCHED_CLASS_DEADLINE => SCHED_CLASS_DEADLINE,
            SCHED_CLASS_RT_FIFO => SCHED_CLASS_RT_FIFO,
            SCHED_CLASS_FAIR => SCHED_CLASS_FAIR,
            SCHED_CLASS_IDLE => SCHED_CLASS_IDLE,
            _ => SCHED_CLASS_FAIR,
        }
    }

    #[inline]
    pub fn fair_weight(&self) -> u16 {
        let weight = u16::from_le_bytes([self.rt_priority, self.sched_flags]);
        if weight == 0 {
            FAIR_DEFAULT_WEIGHT
        } else {
            weight
        }
    }

    #[inline]
    pub fn set_fair_weight(&mut self, weight: u16) {
        let clamped = if weight == 0 {
            FAIR_DEFAULT_WEIGHT
        } else {
            weight
        };
        let [lo, hi] = clamped.to_le_bytes();
        self.rt_priority = lo;
        self.sched_flags = hi;
    }

    #[inline]
    fn scale_fair_runtime(weight: u16, real_runtime_ns: u64) -> u64 {
        if real_runtime_ns == 0 {
            return 0;
        }
        let numer = (real_runtime_ns as u128).saturating_mul(FAIR_VTIME_BASE as u128);
        let denom = weight as u128;
        let scaled = ((numer + denom - 1) / denom) as u64;
        scaled.max(1)
    }

    #[inline]
    fn unscale_fair_runtime(weight: u16, virtual_runtime: u64) -> u64 {
        if virtual_runtime == 0 {
            return 0;
        }
        let numer = (virtual_runtime as u128).saturating_mul(weight as u128);
        let denom = FAIR_VTIME_BASE as u128;
        let scaled = ((numer + denom - 1) / denom) as u64;
        scaled.max(1)
    }

    #[inline]
    pub unsafe fn fair_vruntime(&self) -> u64 {
        self.fair_vruntime
    }

    #[inline]
    pub fn fair_saved_lag_valid(&self) -> bool {
        self.fair_saved_lag_ns != FAIR_LAG_INVALID_NS
    }

    #[inline]
    pub fn clear_fair_saved_lag(&mut self) {
        self.fair_saved_lag_ns = FAIR_LAG_INVALID_NS;
    }

    #[inline]
    pub unsafe fn snapshot_fair_lag(&mut self, avg_vruntime: u64) {
        let lag_virtual = avg_vruntime as i128 - self.fair_vruntime as i128;
        if lag_virtual == 0 {
            self.fair_saved_lag_ns = 0;
            return;
        }

        let abs_virtual = lag_virtual.unsigned_abs().min(u64::MAX as u128) as u64;
        let abs_runtime =
            Self::unscale_fair_runtime(self.fair_weight(), abs_virtual).min(i64::MAX as u64);
        let signed_runtime = if lag_virtual >= 0 {
            abs_runtime as i64
        } else {
            -(abs_runtime as i64)
        };
        self.fair_saved_lag_ns = signed_runtime;
    }

    #[inline]
    pub unsafe fn restore_fair_lag(&mut self, avg_vruntime: u64) -> bool {
        if !self.fair_saved_lag_valid() {
            return false;
        }

        let lag_runtime = self.fair_saved_lag_ns;
        self.clear_fair_saved_lag();

        if lag_runtime == 0 {
            self.fair_vruntime = avg_vruntime;
            return true;
        }

        let lag_virtual = Self::scale_fair_runtime(self.fair_weight(), lag_runtime.unsigned_abs());
        self.fair_vruntime = if lag_runtime >= 0 {
            avg_vruntime.saturating_sub(lag_virtual)
        } else {
            avg_vruntime.saturating_add(lag_virtual)
        };
        true
    }

    #[inline]
    pub unsafe fn fair_slice_runtime(&self) -> u64 {
        unsafe {
            if self.sched_context.is_null() {
                FAIR_DEFAULT_SLICE_NS
            } else if (*self.sched_context).budget != 0 {
                (*self.sched_context).budget
            } else {
                FAIR_DEFAULT_SLICE_NS
            }
        }
    }

    #[inline]
    pub unsafe fn fair_slice_remaining_runtime(&self) -> u64 {
        unsafe {
            if self.sched_context.is_null() {
                FAIR_DEFAULT_SLICE_NS
            } else {
                (*self.sched_context).remaining
            }
        }
    }

    #[inline]
    pub unsafe fn fair_entity_slice_expired(&self) -> bool {
        unsafe { !self.sched_context.is_null() && (*self.sched_context).remaining == 0 }
    }

    #[inline]
    pub unsafe fn deadline_entity_needs_replenish(&self) -> bool {
        unsafe {
            self.sched_class == SCHED_CLASS_DEADLINE
                && !self.sched_context.is_null()
                && (*self.sched_context).remaining == 0
        }
    }

    #[inline]
    pub unsafe fn fair_slice_virtual(&self) -> u64 {
        unsafe { Self::scale_fair_runtime(self.fair_weight(), self.fair_slice_runtime()) }
    }

    #[inline]
    pub unsafe fn fair_slice_remaining_virtual(&self) -> u64 {
        unsafe { Self::scale_fair_runtime(self.fair_weight(), self.fair_slice_remaining_runtime()) }
    }

    #[inline]
    pub unsafe fn fair_entity_needs_slice_refill(&self) -> bool {
        unsafe { self.fair_entity_slice_expired() && self.fair_entity_needs_initial_seed() }
    }

    #[inline]
    pub unsafe fn fair_entity_needs_initial_seed(&self) -> bool {
        !self.fair_saved_lag_valid() && self.fair_vruntime == 0
    }

    #[inline]
    pub unsafe fn fair_entity_needs_vruntime_translation(
        &self,
        cpu: usize,
        online_cpus: usize,
    ) -> bool {
        let last_cpu = self.placement.last_cpu as usize;
        !self.fair_saved_lag_valid()
            && unsafe { self.fair_vruntime() } != 0
            && last_cpu < online_cpus
            && last_cpu != cpu
    }

    #[inline]
    pub unsafe fn restore_fair_lag_or_seed(&mut self, avg_vruntime: u64) -> bool {
        unsafe {
            let restored = self.restore_fair_lag(avg_vruntime);
            if !restored && self.fair_entity_needs_initial_seed() {
                self.fair_vruntime = avg_vruntime;
            }
            restored
        }
    }

    #[inline]
    pub unsafe fn prepare_fair_entity_for_cpu(
        &mut self,
        src_min_vruntime: Option<u64>,
        dst_min_vruntime: u64,
        avg_vruntime: u64,
    ) {
        unsafe {
            if let Some(src_min_vruntime) = src_min_vruntime {
                self.translate_fair_vruntime(src_min_vruntime, dst_min_vruntime);
            }
            self.normalize_fair_entity(dst_min_vruntime, avg_vruntime);
            self.recompute_sched_key();
        }
    }

    #[inline]
    pub unsafe fn reweight_fair_entity_from_snapshot(
        &mut self,
        avg_vruntime: u64,
        new_weight: u16,
    ) {
        unsafe {
            self.set_fair_weight(new_weight);
            let _ = self.restore_fair_lag_or_seed(avg_vruntime);
            self.recompute_sched_key();
        }
    }

    #[inline]
    pub unsafe fn reweight_fair_entity_detached(&mut self, new_weight: u16) {
        unsafe {
            self.set_fair_weight(new_weight);
            self.recompute_sched_key();
        }
    }

    #[inline]
    pub unsafe fn fair_virtual_deadline(&self) -> u64 {
        unsafe {
            self.fair_vruntime()
                .saturating_add(self.fair_slice_remaining_virtual())
        }
    }

    #[inline]
    pub unsafe fn normalize_fair_entity(&mut self, _min_vruntime: u64, avg_vruntime: u64) {
        unsafe {
            self.prepare_fair_sched_context_for_enqueue();
            let _ = self.restore_fair_lag_or_seed(avg_vruntime);
        }
    }

    #[inline]
    pub unsafe fn prepare_fair_sched_context_for_enqueue(&mut self) {
        unsafe {
            if !self.sched_context.is_null() {
                let sc = &mut *self.sched_context;
                if sc.budget == 0 {
                    sc.budget = FAIR_DEFAULT_SLICE_NS;
                }
                if self.fair_entity_needs_slice_refill() {
                    sc.remaining = sc.budget;
                }
            }
        }
    }

    #[inline]
    pub unsafe fn translate_fair_vruntime(&mut self, src_min_vruntime: u64, dst_min_vruntime: u64) {
        let lag = self.fair_vruntime as i128 - src_min_vruntime as i128;
        self.fair_vruntime = if lag >= 0 {
            dst_min_vruntime.saturating_add(lag as u64)
        } else {
            dst_min_vruntime.saturating_sub((-lag) as u64)
        };
    }

    #[inline]
    pub unsafe fn reset_fair_slice(&mut self) {
        unsafe {
            if self.sched_context.is_null() {
                return;
            }
            let sc = &mut *self.sched_context;
            sc.remaining = if sc.budget != 0 {
                sc.budget
            } else {
                FAIR_DEFAULT_SLICE_NS
            };
        }
    }

    #[inline]
    pub unsafe fn advance_fair_vruntime(&mut self, delta: u64) -> u64 {
        unsafe {
            self.fair_vruntime = self
                .fair_vruntime
                .saturating_add(Self::scale_fair_runtime(self.fair_weight(), delta));
            if !self.sched_context.is_null() {
                let sc = &mut *self.sched_context;
                sc.consumed = sc.consumed.saturating_add(delta);
                sc.remaining = sc.remaining.saturating_sub(delta);
            }
            self.fair_vruntime
        }
    }

    #[inline]
    pub unsafe fn recompute_sched_key(&mut self) {
        unsafe {
            let key = match self.sched_class {
                SCHED_CLASS_DEADLINE => {
                    let deadline = if !self.sched_context.is_null() {
                        (*self.sched_context).deadline
                    } else {
                        self.base_priority
                    };
                    Self::encode_deadline_priority(deadline)
                }
                SCHED_CLASS_RT_FIFO => Self::encode_rt_fifo_priority(self.rt_priority),
                SCHED_CLASS_FAIR => Self::encode_fair_priority(
                    self.fair_vruntime(),
                    self.fair_slice_remaining_virtual(),
                ),
                SCHED_CLASS_IDLE => Self::encode_idle_priority(),
                _ => Self::encode_fair_priority(
                    self.fair_vruntime(),
                    self.fair_slice_remaining_virtual(),
                ),
            };
            self.base_priority = key;
            if self.pip_donation_count == 0 {
                self.priority = key;
            }
        }
    }

    #[inline]
    pub fn effective_sched_class(&self) -> u8 {
        if self.pip_donation_count == 0 {
            self.sched_class
        } else {
            Self::priority_sched_class(self.priority)
        }
    }

    #[inline]
    pub fn tcb_lock(&self) {
        use core::sync::atomic::Ordering;
        if self
            .tcb_lock_state
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        let mut backoff: u32 = 0;
        loop {
            let spins = 1u32 << backoff.min(6);
            for _ in 0..spins {
                core::hint::spin_loop();
            }
            if self.tcb_lock_state.load(Ordering::Relaxed) == 0
                && self
                    .tcb_lock_state
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return;
            }
            if backoff < 6 {
                backoff += 1;
            }
        }
    }

    #[inline]
    pub fn tcb_unlock(&self) {
        self.tcb_lock_state.store(0, Ordering::Release);
    }

    #[inline]
    pub fn run_owner(&self) -> Option<usize> {
        let owner = self.placement.run_owner_cpu.load(Ordering::Acquire);
        if owner == RUN_OWNER_NONE {
            None
        } else {
            Some(owner as usize)
        }
    }

    #[inline]
    pub fn ready_queued(&self) -> bool {
        self.placement.ready_queued
    }

    #[inline]
    pub fn queued_cpu(&self) -> u32 {
        self.placement.queued_cpu
    }

    #[inline]
    pub fn last_cpu(&self) -> u32 {
        self.placement.last_cpu
    }

    #[inline]
    pub fn set_run_owner_cpu(&self, cpu_id: usize) {
        self.placement
            .run_owner_cpu
            .store(cpu_id as u8, Ordering::Release);
    }

    #[inline]
    pub fn try_claim_run_owner_cpu(&self, cpu_id: usize) -> bool {
        self.placement
            .run_owner_cpu
            .compare_exchange(
                RUN_OWNER_NONE,
                cpu_id as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    pub fn clear_run_owner_cpu(&self) {
        self.placement
            .run_owner_cpu
            .store(RUN_OWNER_NONE, Ordering::Release);
    }

    /// Increment `sched_ref` for a scheduler-owned pointer slot taking
    /// ownership of this TCB (ready queue entry, pending_enqueue slot,
    /// or `current[]`).
    #[inline]
    pub(crate) fn sched_ref_inc(&self) {
        self.sched_ref.fetch_add(1, Ordering::AcqRel);
    }

    /// Execute a wake transition under the TCB lock and enqueue atomically
    /// with respect to concurrent suspend/resume on the same thread.
    ///
    /// On UP, local IRQ masking is sufficient to serialize against local
    /// timeout/IPC wake paths, so the extra spinlock round-trip is skipped.
    #[inline]
    pub(crate) unsafe fn with_lock_enqueue<F>(tcb: *mut Tcb, f: F) -> bool
    where
        F: FnOnce(&mut Tcb) -> bool,
    {
        let irq = unsafe { crate::mm::save_irq_disable() };
        let mut releases = crate::sched::scheduler::DeferredReleaseList::new();
        let smp_enabled = crate::sched::scheduler::scheduler().online_cpus > 1;

        if smp_enabled {
            let tcb_ref = unsafe { &*tcb };
            tcb_ref.tcb_lock();
            let should_enqueue = unsafe { f(&mut *tcb) };
            if should_enqueue {
                crate::sched::scheduler::scheduler()
                    .enqueue_with_releases_locked(tcb, &mut releases);
            }
            tcb_ref.tcb_unlock();
            unsafe {
                crate::sched::scheduler::scheduler().drain_release(&mut releases);
            }
            unsafe { crate::mm::restore_irq(irq) };
            return should_enqueue;
        }

        let should_enqueue = unsafe { f(&mut *tcb) };
        if should_enqueue {
            crate::sched::scheduler::scheduler().enqueue_with_releases_locked(tcb, &mut releases);
        }
        unsafe {
            crate::sched::scheduler::scheduler().drain_release(&mut releases);
        }
        unsafe { crate::mm::restore_irq(irq) };
        should_enqueue
    }

    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Tcb, 0),
            tcb_lock_state: AtomicU8::new(0),
            state: ThreadState::Created,
            priority: 0,
            base_priority: 0,
            pip_donating_to: core::ptr::null_mut(),
            pip_donation_count: 0,
            sched_class: SCHED_CLASS_FAIR,
            rt_priority: FAIR_DEFAULT_WEIGHT_LO,
            sched_flags: FAIR_DEFAULT_WEIGHT_HI,
            queued_class: SCHED_CLASS_IDLE,
            runtime_mode: RUNTIME_MODE_KERNEL,
            context: ThreadContext::empty(),
            vspace_root: core::ptr::null_mut(),
            cspace_root: core::ptr::null_mut(),
            cspace_depth: 0,
            ipc_buffer: 0,
            ipc_receive_cnode: 0,
            ipc_receive_index: 0,
            ipc_receive_depth: 0,
            ipc_receive_slot_depth: 0,
            trace_id: 0,
            debug_user_entry: 0,
            invoke_depth0: 0,
            invoke_depth1: 0,
            sched_context: core::ptr::null_mut(),
            fair_vruntime: 0,
            fair_saved_lag_ns: FAIR_LAG_INVALID_NS,
            cpu_affinity: 0xFFFF_FFFF,
            placement: SchedPlacement::new(),
            fair_left: core::ptr::null_mut(),
            fair_right: core::ptr::null_mut(),
            fair_parent: core::ptr::null_mut(),
            fair_subtree_min: 0,
            fair_subtree_stealable: false,
            next: core::ptr::null_mut(),
            blocked_reason: None,
            blocked_vspace_tracking: core::ptr::null_mut(),
            vspace_wait_next: core::ptr::null_mut(),
            eq_wait_next: core::ptr::null_mut(),
            wait_object: core::ptr::null_mut(),
            wait_side: 0,
            wait_seq: 0,
            message_waiter: crate::ipc::message_pipe::MessageWaiter::new(),
            mp_fast_mailbox: crate::ipc::message_pipe::MpFastMailbox::new(),
            deadline_node: crate::sched::deadline_queue::DeadlineNode::new(),
            fault_pipe: core::ptr::null_mut(),
            kernel_stack_top: 0,
            trampoline_stack_top: 0,
            stack_canary: 0,
            user_stack_top: 0,
            user_stack_min: 0,
            user_stack_guard_bottom: 0,
            timer_wakeup_ns: 0,
            sleep_next: core::ptr::null_mut(),
            fpu_state: XSaveArea::zeroed(),
            tls_base: 0,
            abi_tp_base: 0,
            futex_next: core::ptr::null_mut(),
            futex_addr: 0,
            futex_vspace: core::ptr::null_mut(),
            futex_wakeup_result: 0,
            sched_ref: core::sync::atomic::AtomicU32::new(0),
            pending_destroy: core::sync::atomic::AtomicBool::new(false),
            user_runtime_ns: AtomicU64::new(0),
            system_runtime_ns: AtomicU64::new(0),
            deferred_release_next: [core::ptr::null_mut(); crate::arch::MAX_CPUS],
            deferred_release_count: [0; crate::arch::MAX_CPUS],
        }
    }

    /// Initialize a TCB in-place without constructing a large by-value temporary.
    ///
    /// # Safety
    /// `ptr` must point to writable memory large enough for `Tcb`.
    pub unsafe fn init_at(ptr: *mut Tcb) -> bool {
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Tcb>());
            (*ptr).header = KernelObject::new(ObjectType::Tcb, 0);
            crate::task::state::mark_created_locked(ptr);
            (*ptr).sched_class = SCHED_CLASS_FAIR;
            (*ptr).set_fair_weight(FAIR_DEFAULT_WEIGHT);
            (*ptr).fair_saved_lag_ns = FAIR_LAG_INVALID_NS;
            (*ptr).queued_class = SCHED_CLASS_IDLE;
            (*ptr).runtime_mode = RUNTIME_MODE_KERNEL;
            (*ptr).trace_id = Self::alloc_trace_id();
            (*ptr).cpu_affinity = 0xFFFF_FFFF;
            (*ptr).placement = SchedPlacement::new();
            true
        }
    }

    // ------------------------------------------------------------------
    // Refcounted pip_donating_to helpers
    // ------------------------------------------------------------------

    /// Set `pip_donating_to` with refcount bookkeeping.
    ///
    /// # Safety
    /// `holder` must be a valid TCB pointer or null.
    #[inline]
    pub unsafe fn set_pip_target(&mut self, holder: *mut Tcb) {
        unsafe {
            let old = self.pip_donating_to;
            if holder == old {
                return;
            }
            tcb_ref_inc(holder);
            self.pip_donating_to = holder;
            tcb_ref_dec(old);
        }
    }

    /// Clear `pip_donating_to` and release the refcount.
    #[inline]
    pub unsafe fn clear_pip_target(&mut self) {
        unsafe {
            let old = self.pip_donating_to;
            self.pip_donating_to = core::ptr::null_mut();
            tcb_ref_dec(old);
        }
    }

    // ------------------------------------------------------------------

    /// Reset TCB state for destruction/reuse.
    ///
    /// Detaches from any wait queues the thread may be blocked on, then
    /// resets all state.
    pub fn cleanup(&mut self) {
        // Invariant: cap refcount hits 0 only while no scheduler slot
        // references this TCB. `release_object`'s `sched_ref > 0` guard
        // defers destruction until the scheduler releases the last slot
        // (current[], ready queue, or pending_enqueue). A non-zero value
        // here would indicate a scheduler lifetime bug — either a missing
        // dec on a slot exit, or a race that observed sched_ref as zero
        // between two slot transitions.
        crate::kernel::bug::kassert!(
            self.sched_ref.load(core::sync::atomic::Ordering::Acquire) == 0,
            "cleanup() entered with sched_ref > 0: scheduler still holds a pointer slot"
        );
        let old_kernel_stack_top = self.kernel_stack_top;
        let old_trampoline_stack_top = self.trampoline_stack_top;
        // Detach from all wait queues BEFORE clearing state.
        // This properly unlinks the TCB from MessagePipe / DataPipe
        // per-side waiter queues, EventQueue waiters, sleep queue,
        // futex hash, and VSpace waiter queues — preventing dangling
        // nodes when a TCB is destroyed while blocked.
        // SAFETY: self pointer is valid. The destroy_object path
        // calls us while holding CAP_LOCK, but
        // detach_thread_wait_queues now requires CAP_LOCK NOT
        // held (its inner cancel_pending acquires the lock locally
        // for carrier-delete; nested SpinLock would deadlock, and
        // sched_ref releases inside detach must be free to drive
        // drain_reaper which itself takes CAP_LOCK). Drop the lock
        // across detach and reacquire afterwards.
        unsafe {
            crate::mm::CAP_LOCK.unlock();
            detach_thread_wait_queues(self as *mut Tcb);
            crate::mm::CAP_LOCK.lock();
        }

        unsafe { crate::task::quiesce::mark_dying_locked(self as *mut Tcb) };
        self.sched_class = SCHED_CLASS_FAIR;
        self.set_fair_weight(FAIR_DEFAULT_WEIGHT);
        self.queued_class = SCHED_CLASS_IDLE;
        self.placement.ready_queued = false;
        self.placement.queued_cpu = 0xFFFF_FFFF;
        self.clear_run_owner_cpu();
        self.blocked_reason = None;
        self.blocked_vspace_tracking = core::ptr::null_mut();
        self.vspace_wait_next = core::ptr::null_mut();
        self.invoke_depth0 = 0;
        self.invoke_depth1 = 0;

        // Release refcount on bound fault MessagePipe.
        if !self.fault_pipe.is_null() {
            unsafe {
                crate::cap::release_object(
                    self.fault_pipe as *mut crate::cap::KernelObject,
                    crate::cap::ObjectType::MessagePipe,
                );
            }
            self.fault_pipe = core::ptr::null_mut();
        }
        self.user_stack_top = 0;
        self.user_stack_min = 0;
        self.user_stack_guard_bottom = 0;
        self.timer_wakeup_ns = 0;
        self.sleep_next = core::ptr::null_mut();
        self.abi_tp_base = 0;

        if self.kernel_stack_top != 0 {
            const KSTACK_PAGES: usize = 4;
            let base = self.kernel_stack_top - (KSTACK_PAGES as u64 * crate::mm::PAGE_SIZE as u64);
            let phys = crate::mm::virt_to_phys(base);
            let owner = crate::mm::frame::FrameOwner::KernelPrivate {
                subkind: crate::mm::frame::KernelMetaKind::KernelStack,
            };
            for i in 0..KSTACK_PAGES {
                crate::mm::pmm_free(phys + (i * crate::mm::PAGE_SIZE) as u64, &owner);
            }
            if !self.vspace_root.is_null() {
                let tracking = unsafe { (*self.vspace_root).tracking };
                if !tracking.is_null() {
                    unsafe {
                        (*tracking)
                            .vm_kstack_pages
                            .fetch_sub(KSTACK_PAGES as u64, core::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            self.kernel_stack_top = 0;
        }

        if self.trampoline_stack_top != 0 {
            let phys =
                crate::mm::virt_to_phys(self.trampoline_stack_top - crate::mm::PAGE_SIZE as u64);
            crate::mm::pmm_free(
                phys,
                &crate::mm::frame::FrameOwner::KernelPrivate {
                    subkind: crate::mm::frame::KernelMetaKind::KernelStack,
                },
            );
            if !self.vspace_root.is_null() {
                let tracking = unsafe { (*self.vspace_root).tracking };
                if !tracking.is_null() {
                    unsafe {
                        (*tracking)
                            .vm_kstack_pages
                            .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            self.trampoline_stack_top = 0;
        }

        if old_kernel_stack_top != 0 || old_trampoline_stack_top != 0 {
            crate::kernel::printk::kdebug!(sched, |_g| {
                _g.puts("[TCB_CLEANUP] freed stacks tcb=");
                _g.hex(self as *const Tcb as u64);
                _g.puts(" kstack_top=");
                _g.hex(old_kernel_stack_top);
                _g.puts(" tramp_top=");
                _g.hex(old_trampoline_stack_top);
                _g.puts(" free=");
                _g.dec(crate::mm::pmm_free_count() as u64);
                _g.puts("\n");
            });
        }

        // Clean up PIP state: revert donation to holder if active
        unsafe {
            crate::sched::pip::pip_cleanup(self as *mut Tcb);
        }

        // Release refcount on SchedContext held by this TCB
        if !self.sched_context.is_null() {
            unsafe {
                let sc = &mut *self.sched_context;
                sc.sc_lock();
                sc.bound_tcb = core::ptr::null_mut();
                sc.sc_unlock();
                let old_sc = self.sched_context;
                self.sched_context = core::ptr::null_mut();
                crate::cap::release_object(
                    old_sc as *mut crate::cap::KernelObject,
                    crate::cap::ObjectType::SchedContext,
                );
            }
        }

        // Release refcounts on VSpace/CSpace held by this TCB
        unsafe {
            if !self.vspace_root.is_null() {
                crate::cap::release_object(
                    self.vspace_root as *mut crate::cap::KernelObject,
                    crate::cap::ObjectType::VSpace,
                );
                self.vspace_root = core::ptr::null_mut();
            }
            if !self.cspace_root.is_null() {
                crate::cap::release_object(
                    self.cspace_root as *mut _ as *mut crate::cap::KernelObject,
                    crate::cap::ObjectType::CNode,
                );
                self.cspace_root = core::ptr::null_mut();
            }
        }

        // Reset FPU save area for clean reuse — the running thread's live
        // FPU state is irrelevant since the TCB is being destroyed.
        crate::arch::fpu::init_thread(self);

        // Clear TLS and futex state
        self.tls_base = 0;
        self.futex_next = core::ptr::null_mut();
        self.futex_addr = 0;
        self.futex_vspace = core::ptr::null_mut();
        self.futex_wakeup_result = 0;
    }
}

// -----------------------------------------------------------------------
// Module-internal refcount helpers for PIP TCB cross-references.
// These keep the holder alive while `pip_donating_to` points at it so
// pip_undonate never hits UAF.
// -----------------------------------------------------------------------

/// # Safety
/// `tcb` must be a valid TCB pointer or null.
#[inline]
unsafe fn tcb_ref_inc(tcb: *mut Tcb) {
    if !tcb.is_null() {
        unsafe {
            crate::cap::increment_refcount(tcb as *mut crate::cap::KernelObject);
        }
    }
}

/// # Safety
/// `tcb` must be a valid TCB pointer or null.
#[inline]
unsafe fn tcb_ref_dec(tcb: *mut Tcb) {
    if !tcb.is_null() {
        unsafe {
            crate::cap::release_object(
                tcb as *mut crate::cap::KernelObject,
                crate::cap::ObjectType::Tcb,
            );
        }
    }
}

// -----------------------------------------------------------------------
// Wait-queue detachment.
//
// Properly unlinks a blocked TCB from all auxiliary wait queues
// (event-queue waiter list, futex hash, sleep queue, VSpace waiter)
// before changing its run state. Called from both `TCB_STOP` (syscall)
// and `Tcb::cleanup` (destroy path).
//
// Lock ordering: the caller must NOT hold `CAP_LOCK`. The single
// CAP_LOCK-requiring subroutine here (`cancel_pending`) takes the
// lock locally for the duration of its carrier-delete walk and
// releases it before the surrounding detach finishes. Acquiring
// CAP_LOCK at the caller would block the inner sched_ref releases
// from triggering `drain_reaper`, which itself takes CAP_LOCK
// (non-reentrant `SpinLock`).
// -----------------------------------------------------------------------

/// Detach a blocked thread from auxiliary wait queues.
///
/// # Safety
/// `tcb` must be a valid, non-null TCB pointer. Caller must NOT
/// hold `CAP_LOCK` — see the lock-ordering note above.
pub(crate) unsafe fn detach_thread_wait_queues(tcb: *mut Tcb) {
    unsafe {
        let blocked_reason = (*tcb).blocked_reason;

        if (*tcb)
            .message_waiter
            .ready
            .swap(false, core::sync::atomic::Ordering::AcqRel)
        {
            let irq = crate::mm::save_irq_disable();
            crate::mm::CAP_LOCK.lock();
            (*tcb).message_waiter.reply_carriers.drop_via_cdt_locked();
            crate::mm::CAP_LOCK.unlock();
            crate::mm::restore_irq(irq);
            (*tcb)
                .message_waiter
                .txid
                .store(0, core::sync::atomic::Ordering::Release);
        }

        // 1. Deadline queue (futex-timed waits)
        if matches!(blocked_reason, Some(BlockedReason::FutexTimedBlocked)) {
            crate::sched::control::disarm_timed_wait(tcb);
        }

        // 4. Futex hash table
        if matches!(
            blocked_reason,
            Some(BlockedReason::FutexBlocked) | Some(BlockedReason::FutexTimedBlocked)
        ) {
            crate::ipc::futex::futex_remove_thread(tcb);
        }

        // 4a. Pipe waiter queues — `MessagePipeCore` and
        //     `DataPipeCore` per-side queues. The kernel-internal
        //     detach drops the waiter slot's `sched_ref_inc` taken
        //     at push time so the TCB is no longer reachable from
        //     any pipe wait list by the time we return.
        if matches!(
            blocked_reason,
            Some(BlockedReason::PipeRead)
                | Some(BlockedReason::PipeCall)
                | Some(BlockedReason::PipeWrite)
        ) {
            let obj = (*tcb).wait_object;
            let side = (*tcb).wait_side;
            if !obj.is_null() {
                let core = obj as *mut crate::ipc::message_pipe::MessagePipeCore;
                crate::ipc::message_pipe::MessagePipeCore::detach_waiter(
                    core,
                    tcb,
                    side,
                    blocked_reason.unwrap(),
                );
                (*tcb).wait_object = core::ptr::null_mut();
            }
        }
        if matches!(
            blocked_reason,
            Some(BlockedReason::DataPipeRead) | Some(BlockedReason::DataPipeWrite)
        ) {
            let obj = (*tcb).wait_object;
            let side = (*tcb).wait_side;
            if !obj.is_null() {
                let core = obj as *mut crate::ipc::data_pipe::DataPipeCore;
                crate::ipc::data_pipe::DataPipeCore::detach_waiter(
                    core,
                    tcb,
                    side,
                    blocked_reason.unwrap(),
                );
                (*tcb).wait_object = core::ptr::null_mut();
            }
        }

        // 4b. EventQueue waiter list — same shape as pipe waits but
        //     keyed off the EventQueue itself.
        if matches!(blocked_reason, Some(BlockedReason::EventQueueWait)) {
            let obj = (*tcb).wait_object;
            if !obj.is_null() {
                let eq = obj as *mut crate::event::event_queue::EventQueue;
                if (*eq).cancel_waiter(tcb) {
                    crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
                }
                (*tcb).wait_object = core::ptr::null_mut();
            }
        }

        // 4d. Pager request waiter list. The request lives in the
        // global pending pool and is protected by its owning Pager.lock.
        // If the request terminator already drained the waiter chain,
        // this removal returns false and the terminator owns the
        // waiter-slot sched_ref release.
        if matches!(blocked_reason, Some(BlockedReason::PagerFaultBlocked)) {
            let obj = (*tcb).wait_object;
            if !obj.is_null() {
                let req = obj as *mut crate::cap::pager::PendingPagerRequest;
                let pager = (*req).pager;
                let mut removed = false;
                if !pager.is_null() {
                    let irq = crate::mm::save_irq_disable();
                    (*pager).lock.lock();

                    let mut cursor: *mut *mut Tcb = &mut (*req).waiter_head;
                    while !(*cursor).is_null() {
                        if *cursor == tcb {
                            *cursor = (*tcb).eq_wait_next;
                            (*tcb).eq_wait_next = core::ptr::null_mut();
                            removed = true;
                            break;
                        }
                        cursor = &mut (**cursor).eq_wait_next;
                    }

                    (*pager).lock.unlock();
                    crate::mm::restore_irq(irq);
                }
                (*tcb).wait_object = core::ptr::null_mut();
                if removed {
                    crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
                }
            }
        }

        // 5. VSpace waiter queue (intrusive singly-linked list protected
        //    by VSpaceTracking::waiter_lock — NOT the scheduler lock).
        if matches!(blocked_reason, Some(BlockedReason::VSpaceWait)) {
            if !(*tcb).blocked_vspace_tracking.is_null() {
                let tracking = &*(*tcb).blocked_vspace_tracking;
                let irq = crate::mm::save_irq_disable();
                tracking.waiter_lock_acquire();

                let head = tracking.waiter_head_get_locked();
                if head == tcb {
                    tracking.waiter_head_set_locked((*tcb).vspace_wait_next);
                } else {
                    let mut prev = head;
                    while !prev.is_null() && (*prev).vspace_wait_next != tcb {
                        prev = (*prev).vspace_wait_next;
                    }
                    if !prev.is_null() {
                        (*prev).vspace_wait_next = (*tcb).vspace_wait_next;
                    }
                }

                (*tcb).vspace_wait_next = core::ptr::null_mut();
                (*tcb).blocked_vspace_tracking = core::ptr::null_mut();

                tracking.waiter_lock_release();
                crate::mm::restore_irq(irq);
            }
        }
    }
}

impl SchedContext {
    #[inline]
    pub fn sc_lock(&self) {
        use core::sync::atomic::Ordering;
        if self
            .sc_lock_state
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        let mut backoff: u32 = 0;
        loop {
            for _ in 0..(1u32 << backoff.min(6)) {
                core::hint::spin_loop();
            }
            if self.sc_lock_state.load(Ordering::Relaxed) == 0
                && self
                    .sc_lock_state
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return;
            }
            if backoff < 6 {
                backoff += 1;
            }
        }
    }

    #[inline]
    pub fn sc_unlock(&self) {
        self.sc_lock_state
            .store(0, core::sync::atomic::Ordering::Release);
    }

    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::SchedContext, 0),
            sc_lock_state: core::sync::atomic::AtomicU8::new(0),
            budget: 0,
            remaining: 0,
            period: 0,
            deadline: 0,
            bound_tcb: core::ptr::null_mut(),
            consumed: 0,
        }
    }

    /// Cleanup when scheduling context is destroyed.
    ///
    /// The TCB holds the strong ref on this SC. By the time SC::cleanup()
    /// runs (refcount == 0), the TCB must have already released its ref
    /// (via Tcb::cleanup() or syscall_sc_unbind). The bound_tcb null
    /// check is purely defensive.
    pub fn cleanup(&mut self) {
        if !self.bound_tcb.is_null() {
            unsafe {
                let tcb = &mut *self.bound_tcb;
                tcb.tcb_lock();
                if core::ptr::eq(tcb.sched_context, self as *mut SchedContext) {
                    tcb.sched_context = core::ptr::null_mut();
                }
                tcb.tcb_unlock();
            }
        }
        self.bound_tcb = core::ptr::null_mut();
    }
}
