//! Thread Control Block
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU8, Ordering};

use crate::cap::{KernelObject, ObjectType};
use crate::cap::CNode;
use crate::mm::VSpace;

pub const MAX_RECV_WAIT_ENDPOINTS: usize = 32;
pub const RECV_WAIT_SELECTED_NONE: u16 = u16::MAX;
pub const RECV_WAIT_SELECTED_NOTIFICATION: u16 = u16::MAX - 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecvWaitLink {
    pub tcb: *mut Tcb,
    pub endpoint: *mut u8,
    pub prev: *mut RecvWaitLink,
    pub next: *mut RecvWaitLink,
    pub wait_index: u16,
}

impl RecvWaitLink {
    pub const fn new() -> Self {
        Self {
            tcb: core::ptr::null_mut(),
            endpoint: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            wait_index: 0,
        }
    }
}

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
        { Self { data: [0u8; 832] } }
        #[cfg(target_arch = "aarch64")]
        { Self { data: [0u8; 528] } }
    }
}

/// Thread state
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Inactive,
    Ready,
    Running,
    Blocked,
    Waiting,
}

/// Reason why a thread is blocked
#[derive(Clone, Copy)]
pub enum BlockedReason {
    /// Blocked on send - waiting for receiver
    SendBlocked {
        /// Message to send
        msg: super::super::ipc::Message,
        /// Badge (sender identity)
        badge: u64,
    },
    /// Blocked on receive - waiting for sender
    RecvBlocked,
    /// Blocked on notification wait
    NotificationWait,
    /// Blocked on VSpace teardown - waiting for VSpace to become inactive
    VSpaceWait,
    /// Blocked waiting for reply from server (after call())
    ReplyWait {
        /// Message to send
        msg: super::super::ipc::Message,
        /// Badge (sender identity)
        badge: u64,
    },
    /// Blocked on fault delivery (waiting for fault handler to reply)
    FaultBlocked {
        /// Fault message (label = FaultType, regs = fault details)
        msg: super::super::ipc::Message,
        /// Badge
        badge: u64,
    },
    /// Blocked on call() send phase - waiting for receiver to pick up
    /// When recv() pops this, the sender stays blocked (transitions to ReplyWait)
    CallSendBlocked {
        /// Message to send
        msg: super::super::ipc::Message,
        /// Badge (sender identity)
        badge: u64,
    },
    /// Blocked on nanosleep timer
    TimerBlocked,
    /// Blocked on futex wait
    FutexBlocked,
    /// Blocked on futex wait with timeout (in both futex hash + sleep queue)
    FutexTimedBlocked,
    /// Blocked on send with timeout (in both endpoint send queue + sleep queue)
    SendTimedBlocked {
        /// Message to send
        msg: super::super::ipc::Message,
        /// Badge (sender identity)
        badge: u64,
    },
    /// Blocked on receive with timeout (in both endpoint recv queue + sleep queue)
    RecvTimedBlocked,
}

/// Sentinel value meaning no CPU currently owns the thread's live register state.
pub const RUN_OWNER_NONE: u8 = u8::MAX;

/// Thread Control Block
#[repr(C)]
pub struct Tcb {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Per-TCB spin lock state (0 = unlocked, 1 = locked)
    pub tcb_lock_state: core::sync::atomic::AtomicU8,
    /// Thread state
    pub state: ThreadState,
    /// Priority (for EDF: effective deadline, may be boosted by PIP)
    pub priority: u64,
    /// Base priority (original EDF deadline, unaffected by inheritance)
    pub base_priority: u64,
    /// TCB pointer this thread is donating priority to (PIP chain)
    pub pip_donating_to: *mut Tcb,
    /// Number of priority donations currently received (0 or 1)
    pub pip_donation_count: u16,
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
    /// Cached receive depth for incoming cap transfers
    pub ipc_receive_depth: u64,
    /// Pending invoke depth for argument 0 (set by SYS_SET_INVOKE_DEPTHS)
    pub invoke_depth0: u8,
    /// Pending invoke depth for argument 1 (set by SYS_SET_INVOKE_DEPTHS)
    pub invoke_depth1: u8,
    /// Scheduling context
    pub sched_context: *mut SchedContext,
    /// CPU affinity (0xFFFF_FFFF = any CPU, otherwise specific CPU ID)
    pub cpu_affinity: u32,
    /// Last CPU this thread ran on (cache affinity hint for load balancer)
    pub last_cpu: u32,
    /// CPU that still owns this thread's live register state.
    ///
    /// A thread may already be Blocked and present in an IPC wait queue while
    /// the old CPU is still unwinding toward `context_switch`. Fastpath cross-CPU
    /// handoff is only safe once this field becomes `RUN_OWNER_NONE`.
    pub run_owner_cpu: AtomicU8,
    /// Whether this thread is currently in the ready queue (O(1) membership test)
    pub ready_queued: bool,
    /// Which CPU's ready queue this thread is in (valid when ready_queued == true)
    pub queued_cpu: u32,
    /// Set by Notification::signal() when waking a bound TCB via endpoint.
    /// recv()/reply_recv()/recv_timeout() checks this on resume to consume
    /// notification bits under ntfn_lock instead of reading saved_caller_*.
    pub woken_by_notification: bool,
    /// Next thread in queue
    pub next: *mut Tcb,
    /// Why this thread is blocked (valid when state == Blocked/Waiting)
    pub blocked_reason: Option<BlockedReason>,
    /// Saved caller badge (for reply_recv)
    pub saved_caller_badge: u64,
    /// Saved caller message (for reply_recv)
    pub saved_caller_msg: super::super::ipc::Message,
    /// Number of endpoint recv queues this thread is currently armed on.
    pub recv_wait_link_count: u8,
    /// Selected recv source for multi-endpoint waits.
    pub recv_wait_selected: u16,
    /// Endpoint pointer if blocked on endpoint send/recv queue
    pub blocked_endpoint: *mut u8,
    /// Notification pointer if blocked on notification
    pub blocked_notification: *mut u8,
    /// VSpace tracking pointer (for VSpaceWait)
    pub blocked_vspace_tracking: *mut crate::mm::VSpaceTracking,
    /// Next pointer for VSpace wait queue (intrusive)
    pub vspace_wait_next: *mut Tcb,
    /// Reply capability: pointer to caller's TCB (for reply_recv)
    pub reply_tcb: *mut Tcb,
    /// Can the caller grant capabilities in the reply?
    pub reply_can_grant: bool,
    /// Fault handler endpoint (for delivering faults to userspace handler)
    pub fault_handler: *mut u8,
    /// Badge of the fault handler endpoint capability
    pub fault_handler_badge: u64,
    /// Bound notification for combined IPC wait
    pub bound_notification: *mut u8,
    /// User-mode signal dispatcher entry point (0 = not registered).
    /// When non-zero, the kernel injects a signal frame on the user stack
    /// and redirects control here instead of returning EINTR directly.
    pub signal_dispatcher: u64,
    /// Kernel stack top for syscall entry (per-thread kernel stack)
    pub kernel_stack_top: u64,
    /// Per-thread stack canary (verified at syscall exit against %gs:40).
    /// Each thread gets its own unique canary so migration across CPUs
    /// does not cause false-positive corruption panics.
    pub stack_canary: u64,
    /// User stack upper bound (initial user RSP from configure)
    pub user_stack_top: u64,
    /// Lowest virtual address eligible for automatic stack growth
    pub user_stack_min: u64,
    /// Wakeup time in nanoseconds (for nanosleep)
    pub timer_wakeup_ns: u64,
    /// Next pointer for sleep queue (intrusive singly-linked list)
    pub sleep_next: *mut Tcb,
    /// XSAVE FPU/SSE state (64-byte aligned, 832 bytes)
    pub fpu_state: XSaveArea,
    /// Whether this thread has used FPU instructions (lazy init on first #NM)
    pub fpu_initialized: bool,
    /// Thread-local storage base address (FS_BASE MSR value)
    pub tls_base: u64,
    /// Next TCB in futex wait queue (intrusive linked list)
    pub futex_next: *mut Tcb,
    /// Virtual address this thread is waiting on (for futex)
    pub futex_addr: u64,
    /// VSpace pointer for futex address space identification
    pub futex_vspace: *mut VSpace,
    /// Futex timed wait result: 0 = woken by futex_wake, non-zero = timeout
    pub futex_wakeup_result: u64,
    /// Intrusive links used when the thread is blocked on multiple recv endpoints.
    pub recv_wait_links: [RecvWaitLink; MAX_RECV_WAIT_ENDPOINTS],
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
    /// Budget per period (time units)
    pub budget: u64,
    /// Remaining budget
    pub remaining: u64,
    /// Period length
    pub period: u64,
    /// Absolute deadline
    pub deadline: u64,
    /// Bound TCB
    pub bound_tcb: *mut Tcb,
    /// Cumulative consumed time (ticks)
    pub consumed: u64,
}

impl Tcb {
    #[inline]
    pub fn tcb_lock(&self) {
        use core::sync::atomic::Ordering;
        if self.tcb_lock_state.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return;
        }
        let mut backoff: u32 = 0;
        loop {
            for _ in 0..(1u32 << backoff.min(6)) { core::hint::spin_loop(); }
            if self.tcb_lock_state.load(Ordering::Relaxed) == 0
                && self.tcb_lock_state.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
            { return; }
            if backoff < 6 { backoff += 1; }
        }
    }

    #[inline]
    pub fn tcb_unlock(&self) {
        self.tcb_lock_state.store(0, Ordering::Release);
    }

    #[inline]
    pub fn run_owner(&self) -> Option<usize> {
        let owner = self.run_owner_cpu.load(Ordering::Acquire);
        if owner == RUN_OWNER_NONE {
            None
        } else {
            Some(owner as usize)
        }
    }

    #[inline]
    pub fn set_run_owner_cpu(&self, cpu_id: usize) {
        self.run_owner_cpu.store(cpu_id as u8, Ordering::Release);
    }

    #[inline]
    pub fn clear_run_owner_cpu(&self) {
        self.run_owner_cpu.store(RUN_OWNER_NONE, Ordering::Release);
    }

    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Tcb, 0),
            tcb_lock_state: AtomicU8::new(0),
            state: ThreadState::Inactive,
            priority: 0,
            base_priority: 0,
            pip_donating_to: core::ptr::null_mut(),
            pip_donation_count: 0,
            context: ThreadContext::empty(),
            vspace_root: core::ptr::null_mut(),
            cspace_root: core::ptr::null_mut(),
            cspace_depth: 0,
            ipc_buffer: 0,
            ipc_receive_cnode: 0,
            ipc_receive_index: 0,
            ipc_receive_depth: 0,
            invoke_depth0: 0,
            invoke_depth1: 0,
            sched_context: core::ptr::null_mut(),
            cpu_affinity: 0xFFFF_FFFF,
            last_cpu: 0xFFFF_FFFF,
            run_owner_cpu: AtomicU8::new(RUN_OWNER_NONE),
            ready_queued: false,
            queued_cpu: 0xFFFF_FFFF,
            woken_by_notification: false,
            next: core::ptr::null_mut(),
            blocked_reason: None,
            saved_caller_badge: 0,
            saved_caller_msg: super::super::ipc::Message::empty(),
            recv_wait_link_count: 0,
            recv_wait_selected: RECV_WAIT_SELECTED_NONE,
            blocked_endpoint: core::ptr::null_mut(),
            blocked_notification: core::ptr::null_mut(),
            blocked_vspace_tracking: core::ptr::null_mut(),
            vspace_wait_next: core::ptr::null_mut(),
            reply_tcb: core::ptr::null_mut(),
            reply_can_grant: false,
            fault_handler: core::ptr::null_mut(),
            fault_handler_badge: 0,
            bound_notification: core::ptr::null_mut(),
            signal_dispatcher: 0,
            kernel_stack_top: 0,
            stack_canary: 0,
            user_stack_top: 0,
            user_stack_min: 0,
            timer_wakeup_ns: 0,
            sleep_next: core::ptr::null_mut(),
            fpu_state: XSaveArea::zeroed(),
            fpu_initialized: false,
            tls_base: 0,
            futex_next: core::ptr::null_mut(),
            futex_addr: 0,
            futex_vspace: core::ptr::null_mut(),
            futex_wakeup_result: 0,
            recv_wait_links: [RecvWaitLink::new(); MAX_RECV_WAIT_ENDPOINTS],
        }
    }

    /// Initialize a TCB in-place without constructing a large by-value temporary.
    ///
    /// # Safety
    /// `ptr` must point to writable memory large enough for `Tcb`.
    pub unsafe fn init_at(ptr: *mut Tcb) {
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Tcb>());
            (*ptr).header = KernelObject::new(ObjectType::Tcb, 0);
            (*ptr).state = ThreadState::Inactive;
            (*ptr).cpu_affinity = 0xFFFF_FFFF;
            (*ptr).last_cpu = 0xFFFF_FFFF;
            (*ptr).run_owner_cpu = AtomicU8::new(RUN_OWNER_NONE);
            (*ptr).queued_cpu = 0xFFFF_FFFF;
        }
    }

    /// Cleanup when TCB is destroyed
    ///
    /// Note: This does not wake the thread if blocked or remove it from scheduler queues.
    /// Those operations should be handled by the caller before calling cleanup.
    ///
    /// However, this DOES wake any caller waiting for a reply via reply_tcb.
    pub fn cleanup(&mut self) {
        self.state = ThreadState::Inactive;
        self.ready_queued = false;
        self.queued_cpu = 0xFFFF_FFFF;
        self.woken_by_notification = false;
        self.clear_run_owner_cpu();
        self.blocked_reason = None;
        self.recv_wait_link_count = 0;
        self.recv_wait_selected = RECV_WAIT_SELECTED_NONE;
        self.blocked_endpoint = core::ptr::null_mut();
        self.blocked_notification = core::ptr::null_mut();
        self.blocked_vspace_tracking = core::ptr::null_mut();
        self.vspace_wait_next = core::ptr::null_mut();
        self.invoke_depth0 = 0;
        self.invoke_depth1 = 0;
        self.signal_dispatcher = 0;

        // If we have a reply capability, wake the blocked caller
        // This handles the case where a server dies before replying
        if !self.reply_tcb.is_null() {
            unsafe {
                let caller = self.reply_tcb;
                // Wake the caller - it will receive an error or empty reply
                (*caller).state = ThreadState::Ready;
                (*caller).blocked_reason = None;
                crate::sched::scheduler::scheduler().enqueue(caller);
            }
        }
        self.reply_tcb = core::ptr::null_mut();
        self.reply_can_grant = false;
        self.fault_handler = core::ptr::null_mut();
        self.fault_handler_badge = 0;
        self.user_stack_top = 0;
        self.user_stack_min = 0;
        self.timer_wakeup_ns = 0;
        self.sleep_next = core::ptr::null_mut();

        // Clear bound notification's back-pointer to prevent use-after-free
        if !self.bound_notification.is_null() {
            unsafe {
                let ntfn = &mut *(self.bound_notification as *mut crate::ipc::Notification);
                ntfn.bound_tcb = core::ptr::null_mut();
            }
        }
        self.bound_notification = core::ptr::null_mut();

        // Clean up PIP state: revert donation to holder if active
        unsafe {
            crate::sched::pip::pip_cleanup(self as *mut Tcb);
        }

        // Clear FPU ownership if this TCB is the current CPU's FPU owner
        crate::arch::fpu::disown_if_current(self as *mut Tcb as *mut u8);
        self.fpu_initialized = false;

        // Clear TLS and futex state
        self.tls_base = 0;
        self.futex_next = core::ptr::null_mut();
        self.futex_addr = 0;
        self.futex_vspace = core::ptr::null_mut();
        self.futex_wakeup_result = 0;
    }
}

impl SchedContext {
    #[inline]
    pub fn sc_lock(&self) {
        use core::sync::atomic::Ordering;
        if self.sc_lock_state.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return;
        }
        let mut backoff: u32 = 0;
        loop {
            for _ in 0..(1u32 << backoff.min(6)) { core::hint::spin_loop(); }
            if self.sc_lock_state.load(Ordering::Relaxed) == 0
                && self.sc_lock_state.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
            { return; }
            if backoff < 6 { backoff += 1; }
        }
    }

    #[inline]
    pub fn sc_unlock(&self) {
        self.sc_lock_state.store(0, core::sync::atomic::Ordering::Release);
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

    /// Cleanup when scheduling context is destroyed
    pub fn cleanup(&mut self) {
        self.bound_tcb = core::ptr::null_mut();
    }
}
