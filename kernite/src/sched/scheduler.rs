// SPDX-License-Identifier: GPL-2.0-only
//! Class-based scheduler

use super::class::{SCHED_CLASS_DEADLINE, SCHED_CLASS_FAIR, SCHED_CLASS_IDLE, SCHED_CLASS_RT_FIFO};
use super::thread::{BlockedReason, RUNTIME_MODE_KERNEL, RUNTIME_MODE_USER, Tcb};
use crate::arch::MAX_CPUS;
use core::sync::atomic::{AtomicPtr, AtomicU64};

mod balance;
mod drive;
mod global;
mod rq;
mod runtime;
mod slots;
mod support;
mod switch;
mod wake;

pub(crate) use global::debug_reply_wake_once;
#[cfg(target_arch = "aarch64")]
pub use global::sched_runtime_exit_to_user;
pub use global::scheduler;
pub(crate) use support::DeferredReleaseList;

unsafe extern "C" {
    static _text_start: u8;
    static _text_end: u8;
}

/// Scheduler with explicit Deadline / RT FIFO / Fair / Idle classes.
pub struct Scheduler {
    /// Per-CPU Deadline-class ready queue heads.
    deadline_heads: [*mut Tcb; MAX_CPUS],
    /// Per-CPU RT FIFO ready queue heads.
    rt_fifo_heads: [*mut Tcb; MAX_CPUS],
    /// Per-CPU Fair ready queue roots.
    ///
    /// Fair entities live in an intrusive treap keyed by virtual deadline.
    /// While a thread is queued here, the scheduler temporarily reuses
    /// `sleep_next` / `futex_next` / `vspace_wait_next` as left / right /
    /// parent links, `timer_wakeup_ns` as the subtree min-vruntime cache, and
    /// `blocked_vspace_tracking` as the subtree any-affinity cache.
    fair_heads: [*mut Tcb; MAX_CPUS],
    /// Per-CPU runnable Fair weight sum for weighted average vruntime.
    fair_weight_sum: [u64; MAX_CPUS],
    /// Per-CPU sum of `fair_vruntime * fair_weight`.
    fair_weighted_vruntime_sum: [u128; MAX_CPUS],
    /// Per-CPU currently running thread
    current: [*mut Tcb; MAX_CPUS],
    /// Per-CPU timestamp at which the current thread last started running.
    current_started_ns: [u64; MAX_CPUS],
    /// Per-CPU timestamp at which the current user/kernel attribution window started.
    current_observed_started_ns: [u64; MAX_CPUS],
    /// Per-CPU runtime-attribution mode for the currently running thread.
    current_runtime_mode: [u8; MAX_CPUS],
    /// Per-CPU idle thread
    idle: [*mut Tcb; MAX_CPUS],
    /// Per-CPU deferred enqueue slot.
    ///
    /// Holds a thread that should be enqueued AFTER `context_switch` saves
    /// its registers. Prevents the double-schedule race where another CPU
    /// dequeues and switches to a thread before its context is saved.
    pending_enqueue: [AtomicPtr<Tcb>; MAX_CPUS],
    /// Per-CPU deferred current[] release slot.
    ///
    /// When `set_current(new)` replaces old, the old TCB pointer is stored
    /// here.  After the scheduler lock is released, `flush_deferred_current_release()`
    /// decrements `sched_ref` on the old TCB and triggers deferred destruction
    /// if its capability refcount already reached 0 (`pending_destroy`).
    deferred_current_release: [*mut Tcb; MAX_CPUS],
    /// Per-CPU lock states (each protects that CPU's ready queue and per-CPU state)
    lock_states: [core::sync::atomic::AtomicU8; MAX_CPUS],
    /// Per-CPU holder-site capture for `lock_cpu` (a `&'static panic::Location`
    /// address), so the hard-timeout dump names the wedged holder of a
    /// `lock_states` slot. `lock_cpu` is a raw atomic, not a `SpinLock`, so it
    /// carries no `acquired_loc` of its own.
    lock_cpu_acquired_loc: [core::sync::atomic::AtomicUsize; MAX_CPUS],
    /// Per-CPU context switch count. Written under `lock_cpu`,
    /// read across CPUs by procfs / debug paths — atomic for the
    /// cross-CPU read.
    pub context_switches: [AtomicU64; MAX_CPUS],
    /// Per-CPU timer tick count. Same discipline as `context_switches`.
    pub timer_ticks: [AtomicU64; MAX_CPUS],
    /// Per-CPU idle runtime in nanoseconds. Same discipline.
    pub idle_runtime_ns: [AtomicU64; MAX_CPUS],
    /// Per-CPU user-mode runtime in nanoseconds. Same discipline.
    pub per_cpu_user_runtime_ns: [AtomicU64; MAX_CPUS],
    /// Per-CPU kernel-mode runtime in nanoseconds. Same discipline.
    pub per_cpu_system_runtime_ns: [AtomicU64; MAX_CPUS],
    /// Per-CPU IPI reschedule count. Same discipline.
    pub ipi_reschedules: [AtomicU64; MAX_CPUS],
    /// Number of online CPUs (set during init/init_cpu)
    pub online_cpus: u32,
    /// Timer tick counter for periodic rebalancing
    rebalance_counter: u64,
    /// Monotonic floor for Fair-class virtual runtimes on each CPU.
    fair_min_vruntime: [u64; MAX_CPUS],
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            deadline_heads: [core::ptr::null_mut(); MAX_CPUS],
            rt_fifo_heads: [core::ptr::null_mut(); MAX_CPUS],
            fair_heads: [core::ptr::null_mut(); MAX_CPUS],
            fair_weight_sum: [0; MAX_CPUS],
            fair_weighted_vruntime_sum: [0; MAX_CPUS],
            current: [core::ptr::null_mut(); MAX_CPUS],
            current_started_ns: [0; MAX_CPUS],
            current_observed_started_ns: [0; MAX_CPUS],
            current_runtime_mode: [RUNTIME_MODE_KERNEL; MAX_CPUS],
            idle: [core::ptr::null_mut(); MAX_CPUS],
            pending_enqueue: [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS],
            deferred_current_release: [core::ptr::null_mut(); MAX_CPUS],
            lock_states: [const { core::sync::atomic::AtomicU8::new(0) }; MAX_CPUS],
            lock_cpu_acquired_loc: [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_CPUS],
            context_switches: [const { AtomicU64::new(0) }; MAX_CPUS],
            timer_ticks: [const { AtomicU64::new(0) }; MAX_CPUS],
            idle_runtime_ns: [const { AtomicU64::new(0) }; MAX_CPUS],
            per_cpu_user_runtime_ns: [const { AtomicU64::new(0) }; MAX_CPUS],
            per_cpu_system_runtime_ns: [const { AtomicU64::new(0) }; MAX_CPUS],
            ipi_reschedules: [const { AtomicU64::new(0) }; MAX_CPUS],
            online_cpus: 0,
            rebalance_counter: 0,
            fair_min_vruntime: [0; MAX_CPUS],
        }
    }
}
