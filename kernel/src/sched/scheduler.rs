//! EDF Scheduler
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::thread::{BlockedReason, Tcb, ThreadState};
use crate::arch::MAX_CPUS;
use crate::cap::ObjectType;
use core::sync::atomic::AtomicUsize;

unsafe extern "C" {
    static _text_start: u8;
    static _text_end: u8;
}

#[inline]
fn is_canonical_addr(addr: u64) -> bool {
    let sign = (addr >> 47) & 1;
    let upper = addr >> 48;
    if sign == 0 { upper == 0 } else { upper == 0xFFFF }
}

#[inline]
fn is_kernel_addr(addr: u64) -> bool {
    is_canonical_addr(addr) && addr >= crate::mm::PHYS_MAP_OFFSET
}

#[inline]
fn is_aligned_to<T>(addr: u64) -> bool {
    let align = core::mem::align_of::<T>() as u64;
    addr & (align - 1) == 0
}

#[inline]
fn checked_cpu_id(site: &'static str) -> usize {
    let cpu_id = crate::arch::current_cpu() as usize;
    if cpu_id >= MAX_CPUS {
        panic!("[SCHED] {}: invalid current_cpu={} (max={})", site, cpu_id, MAX_CPUS);
    }
    cpu_id
}

#[inline]
fn is_bootstrap_tcb(tcb: *mut Tcb) -> bool {
    if tcb.is_null() {
        return false;
    }
    core::ptr::eq(tcb, &raw mut super::BOOTSTRAP_TCB)
}

/// EDF Scheduler
pub struct Scheduler {
    /// Per-CPU ready queue heads (each sorted by deadline)
    ready_heads: [*mut Tcb; MAX_CPUS],
    /// Per-CPU currently running thread
    current: [*mut Tcb; MAX_CPUS],
    /// Per-CPU idle thread
    idle: [*mut Tcb; MAX_CPUS],
    /// Per-CPU deferred enqueue slot.
    ///
    /// Holds a thread that should be enqueued AFTER `context_switch` saves
    /// its registers. Prevents the double-schedule race where another CPU
    /// dequeues and switches to a thread before its context is saved.
    pending_enqueue: [*mut Tcb; MAX_CPUS],
    /// Lock state (simple test-and-set spinlock)
    lock_state: core::sync::atomic::AtomicU8,
    /// Per-CPU context switch count
    pub context_switches: [u64; MAX_CPUS],
    /// Per-CPU timer tick count
    pub timer_ticks: [u64; MAX_CPUS],
    /// Per-CPU idle tick count
    pub idle_ticks: [u64; MAX_CPUS],
    /// Per-CPU IPI reschedule count
    pub ipi_reschedules: [u64; MAX_CPUS],
    /// Number of online CPUs (set during init/init_cpu)
    pub online_cpus: u32,
    /// Timer tick counter for periodic rebalancing
    rebalance_counter: u64,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            ready_heads: [core::ptr::null_mut(); MAX_CPUS],
            current: [core::ptr::null_mut(); MAX_CPUS],
            idle: [core::ptr::null_mut(); MAX_CPUS],
            pending_enqueue: [core::ptr::null_mut(); MAX_CPUS],
            lock_state: core::sync::atomic::AtomicU8::new(0),
            context_switches: [0; MAX_CPUS],
            timer_ticks: [0; MAX_CPUS],
            idle_ticks: [0; MAX_CPUS],
            ipi_reschedules: [0; MAX_CPUS],
            online_cpus: 0,
            rebalance_counter: 0,
        }
    }

    /// Take scheduler lock
    pub(crate) fn lock(&self) {
        use core::sync::atomic::Ordering;

        // Fast path: uncontended acquire
        if self
            .lock_state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        // Slow path: bounded exponential backoff to reduce cache-line thrashing
        let mut backoff: u32 = 0;
        #[cfg(debug_assertions)]
        let mut _total_spins: u32 = 0;
        loop {
            let spins = 1u32 << backoff.min(6);
            for _ in 0..spins {
                core::hint::spin_loop();
            }
            #[cfg(debug_assertions)]
            {
                _total_spins += spins;
                if _total_spins > 10_000_000 {
                    crate::serial_puts("[SCHED SPINLOCK] possible deadlock detected\n");
                    _total_spins = 0;
                }
            }

            if self.lock_state.load(Ordering::Relaxed) == 0
                && self
                    .lock_state
                    .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return;
            }

            if backoff < 6 {
                backoff += 1;
            }
        }
    }

    /// Release scheduler lock
    pub(crate) fn unlock(&self) {
        self.lock_state
            .store(0, core::sync::atomic::Ordering::Release);
    }

    // ---------------------------------------------------------------
    // Per-CPU queue helpers (caller must hold lock + IRQs disabled)
    // ---------------------------------------------------------------

    /// Select which CPU's ready queue a thread should be enqueued on.
    ///
    /// - Specific affinity: always that CPU
    /// - Any-affinity: prefer last_cpu (cache affinity), fallback to current CPU
    ///
    /// Caller MUST hold the scheduler lock.
    fn select_target_cpu(&self, tcb: *mut Tcb) -> usize {
        unsafe {
            let affinity = (*tcb).cpu_affinity;
            if affinity != 0xFFFF_FFFF {
                return affinity as usize;
            }
            let last = (*tcb).last_cpu as usize;
            if last < self.online_cpus as usize {
                return last;
            }
            crate::arch::current_cpu() as usize
        }
    }

    /// Insert a thread into a specific CPU's ready queue, sorted by deadline.
    ///
    /// Sets `ready_queued` and `queued_cpu` on the TCB.
    /// Does NOT send IPIs — caller handles that.
    ///
    /// Caller MUST hold the scheduler lock.
    unsafe fn insert_sorted(&mut self, cpu: usize, tcb: *mut Tcb) {
        unsafe {
            (*tcb).ready_queued = true;
            (*tcb).queued_cpu = cpu as u32;

            if self.ready_heads[cpu].is_null()
                || (*tcb).priority < (*self.ready_heads[cpu]).priority
            {
                (*tcb).next = self.ready_heads[cpu];
                self.ready_heads[cpu] = tcb;
            } else {
                let mut current = self.ready_heads[cpu];
                while !(*current).next.is_null()
                    && (*(*current).next).priority <= (*tcb).priority
                {
                    current = (*current).next;
                }
                (*tcb).next = (*current).next;
                (*current).next = tcb;
            }
        }
    }

    // ---------------------------------------------------------------
    // Unlocked queue operations (caller must hold lock + IRQs disabled)
    // ---------------------------------------------------------------

    /// Add thread to ready queue (sorted by deadline) — unlocked variant.
    ///
    /// Routes the thread to the appropriate per-CPU queue based on affinity
    /// and cache affinity hints.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn enqueue_unlocked(&mut self, tcb: *mut Tcb) {
        unsafe {
            let cpu_id = checked_cpu_id("enqueue_unlocked");
            self.validate_tcb_ptr(tcb, "enqueue_unlocked", cpu_id);

            // Bootstrap TCB represents kmain's transient boot context. It has no
            // dedicated per-thread kernel stack and must never be scheduled
            // again after the first switch away from bootstrap.
            if is_bootstrap_tcb(tcb) {
                (*tcb).state = ThreadState::Inactive;
                return;
            }

            if self.find_running_cpu(tcb).is_some() {
                return;
            }

            // O(1) check via flag instead of O(N) queue walk
            if (*tcb).ready_queued {
                (*tcb).state = ThreadState::Ready;
                return;
            }

            // If the thread is still waiting for its outgoing context to be
            // saved on some CPU, defer actual queue insertion until that CPU
            // flushes its pending slot.
            if self.is_pending_on_any_cpu(tcb) {
                (*tcb).state = ThreadState::Ready;
                return;
            }

            (*tcb).state = ThreadState::Ready;

            // Route to the appropriate per-CPU queue
            let target = self.select_target_cpu(tcb);
            self.insert_sorted(target, tcb);

            // Wake the target CPU if it is idle and different from ours.
            // Skip IPI if the current CPU is idle — it will pick up the
            // thread in its own scheduling decision without cross-CPU overhead.
            let this_cpu = crate::arch::current_cpu() as usize;
            if target != this_cpu
                && target < self.online_cpus as usize
                && !self.idle[target].is_null()
                && self.current[target] == self.idle[target]
            {
                let this_cpu_idle = !self.idle[this_cpu].is_null()
                    && self.current[this_cpu] == self.idle[this_cpu];
                if !this_cpu_idle {
                    crate::arch::send_ipi(target, crate::arch::IpiKind::Reschedule);
                }
            }
        }
    }

    /// Remove highest priority (earliest deadline) thread — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn dequeue_unlocked(&mut self) -> Option<*mut Tcb> {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.dequeue_for_cpu_unlocked(cpu_id)
    }

    /// Remove highest priority thread for a CPU — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn dequeue_for_cpu_unlocked(&mut self, cpu_id: usize) -> Option<*mut Tcb> {
        // O(1): simply pop the head of this CPU's queue.
        // All threads in ready_heads[cpu] are compatible with cpu
        // (either any-affinity or pinned to this CPU).
        let head = self.ready_heads[cpu_id];
        if head.is_null() {
            return None;
        }
        unsafe {
            self.ready_heads[cpu_id] = (*head).next;
            (*head).next = core::ptr::null_mut();
            (*head).ready_queued = false;
            (*head).queued_cpu = 0xFFFF_FFFF;
            Some(head)
        }
    }

    /// Remove a specific thread from the ready queue — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn remove_from_ready_queue_unlocked(&mut self, tcb: *mut Tcb) -> bool {
        unsafe {
            if !(*tcb).ready_queued {
                return false;
            }
            let cpu = (*tcb).queued_cpu as usize;
            if cpu >= MAX_CPUS {
                return false;
            }

            let mut prev: *mut Tcb = core::ptr::null_mut();
            let mut current = self.ready_heads[cpu];
            while !current.is_null() {
                if current == tcb {
                    if prev.is_null() {
                        self.ready_heads[cpu] = (*current).next;
                    } else {
                        (*prev).next = (*current).next;
                    }
                    (*current).next = core::ptr::null_mut();
                    (*tcb).ready_queued = false;
                    (*tcb).queued_cpu = 0xFFFF_FFFF;
                    return true;
                }
                prev = current;
                current = (*current).next;
            }
            false
        }
    }

    /// Check whether a TCB is already present in the ready queue.
    ///
    /// O(1) via `ready_queued` flag instead of O(N) queue walk.
    /// Caller MUST hold the scheduler lock.
    fn is_ready_queued_unlocked(&self, tcb: *mut Tcb) -> bool {
        unsafe { (*tcb).ready_queued }
    }

    // ---------------------------------------------------------------
    // Locking wrapper methods (for external callers without lock held)
    // ---------------------------------------------------------------

    /// Add thread to ready queue with IRQ-safe locking.
    ///
    /// Acquires the scheduler spinlock with IRQs disabled.
    /// External callers (syscall, IPC, init) should use this.
    pub fn enqueue(&mut self, tcb: *mut Tcb) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();
        self.enqueue_unlocked(tcb);
        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
    }

    /// Remove highest priority thread with IRQ-safe locking.
    pub fn dequeue(&mut self) -> Option<*mut Tcb> {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();
        let result = self.dequeue_unlocked();
        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
        result
    }

    /// Remove highest priority thread for a CPU with IRQ-safe locking.
    pub fn dequeue_for_cpu(&mut self, cpu_id: usize) -> Option<*mut Tcb> {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();
        let result = self.dequeue_for_cpu_unlocked(cpu_id);
        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
        result
    }

    /// Remove a specific thread from the ready queue with IRQ-safe locking.
    pub fn remove_from_ready_queue(&mut self, tcb: *mut Tcb) -> bool {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();
        let result = self.remove_from_ready_queue_unlocked(tcb);
        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
        result
    }

    // ---------------------------------------------------------------
    // Schedule decision (unlocked — caller must hold lock)
    // ---------------------------------------------------------------

    /// Pick next thread to run on the current CPU — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    fn schedule_unlocked(&mut self) -> *mut Tcb {
        let cpu_id = crate::arch::current_cpu() as usize;

        // Try local queue first (O(1) pop — all threads are compatible)
        while let Some(tcb) = self.dequeue_for_cpu_unlocked(cpu_id) {
            unsafe {
                if (*tcb).state != ThreadState::Ready
                    || self.find_running_cpu(tcb).is_some()
                    || self.is_pending_on_any_cpu(tcb)
                {
                    continue;
                }
                (*tcb).state = ThreadState::Running;
                (*tcb).last_cpu = cpu_id as u32;
            }
            self.current[cpu_id] = tcb;
            CURRENT_ON_CPU[cpu_id].store(tcb as usize, core::sync::atomic::Ordering::Release);
            return tcb;
        }

        // Local queue empty — try work stealing from other CPUs.
        // Only steal any-affinity threads (specific-affinity threads
        // must remain on their pinned CPU's queue).
        let online = self.online_cpus as usize;
        for victim in 0..online {
            if victim == cpu_id {
                continue;
            }
            if let Some(tcb) = self.steal_from(victim) {
                unsafe {
                    (*tcb).state = ThreadState::Running;
                    (*tcb).last_cpu = cpu_id as u32;
                }
                self.current[cpu_id] = tcb;
                CURRENT_ON_CPU[cpu_id].store(tcb as usize, core::sync::atomic::Ordering::Release);
                return tcb;
            }
        }

        // No work anywhere — idle
        self.idle[cpu_id]
    }

    /// Steal one any-affinity thread from another CPU's ready queue.
    ///
    /// Scans the victim's queue for the first any-affinity thread that
    /// is valid to schedule. Returns None if no stealable thread found.
    ///
    /// Caller MUST hold the scheduler lock.
    fn steal_from(&mut self, victim: usize) -> Option<*mut Tcb> {
        unsafe {
            let mut prev: *mut Tcb = core::ptr::null_mut();
            let mut current = self.ready_heads[victim];

            while !current.is_null() {
                let affinity = (*current).cpu_affinity;
                // Only steal any-affinity threads
                if affinity == 0xFFFF_FFFF
                    && (*current).state == ThreadState::Ready
                    && self.find_running_cpu(current).is_none()
                    && !self.is_pending_on_any_cpu(current)
                {
                    // Remove from victim's queue
                    if prev.is_null() {
                        self.ready_heads[victim] = (*current).next;
                    } else {
                        (*prev).next = (*current).next;
                    }
                    (*current).next = core::ptr::null_mut();
                    (*current).ready_queued = false;
                    (*current).queued_cpu = 0xFFFF_FFFF;
                    return Some(current);
                }
                prev = current;
                current = (*current).next;
            }
            None
        }
    }

    /// Current running thread (on calling CPU)
    pub fn current(&self) -> *mut Tcb {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.current[cpu_id]
    }

    /// Set current running thread (on calling CPU)
    pub fn set_current(&mut self, tcb: *mut Tcb) {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.current[cpu_id] = tcb;
        CURRENT_ON_CPU[cpu_id].store(tcb as usize, core::sync::atomic::Ordering::Release);
    }

    /// Get idle thread for calling CPU
    pub fn get_idle(&self) -> *mut Tcb {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.idle[cpu_id]
    }

    /// Set idle thread for a specific CPU
    pub fn set_idle(&mut self, cpu_id: usize, tcb: *mut Tcb) {
        self.idle[cpu_id] = tcb;
    }

    /// Find which CPU a thread is running on by scanning current[].
    ///
    /// Checks `last_cpu` hint first for O(1) fast path, then falls back
    /// to scanning only online CPUs.
    /// Returns `None` if the thread is not the current thread on any CPU.
    /// Caller MUST hold the scheduler lock.
    pub fn find_running_cpu(&self, tcb: *mut Tcb) -> Option<usize> {
        // Fast path: check last_cpu hint first
        let last = unsafe { (*tcb).last_cpu } as usize;
        let online = self.online_cpus as usize;
        if last < online && self.current[last] == tcb {
            return Some(last);
        }
        for cpu in 0..online {
            if self.current[cpu] == tcb {
                return Some(cpu);
            }
        }
        None
    }

    /// Check if reschedule needed (preemption) on the calling CPU.
    ///
    /// O(1): the head of the local per-CPU queue is always the highest
    /// priority compatible thread — just compare its deadline with current.
    pub fn needs_reschedule(&self) -> bool {
        let cpu_id = crate::arch::current_cpu() as usize;
        let current = self.current[cpu_id];
        let head = self.ready_heads[cpu_id];
        if head.is_null() || current.is_null() {
            return false;
        }
        unsafe { (*head).priority < (*current).priority }
    }

    // ---------------------------------------------------------------
    // Deferred enqueue helpers
    // ---------------------------------------------------------------

    /// Validate a TCB pointer before dereferencing it in scheduler hot paths.
    ///
    /// These checks intentionally fail-fast on obviously corrupted pointers so
    /// we panic at the source instead of returning into random data later.
    unsafe fn validate_tcb_ptr(&self, tcb: *mut Tcb, site: &'static str, cpu_id: usize) {
        let addr = tcb as u64;
        if tcb.is_null() {
            panic!("[SCHED] {}: null TCB pointer (cpu={})", site, cpu_id);
        }
        if !is_kernel_addr(addr) {
            panic!(
                "[SCHED] {}: non-kernel/non-canonical TCB pointer 0x{:x} (cpu={})",
                site, addr, cpu_id
            );
        }
        if !is_aligned_to::<Tcb>(addr) {
            panic!(
                "[SCHED] {}: misaligned TCB pointer 0x{:x} (align={} cpu={})",
                site,
                addr,
                core::mem::align_of::<Tcb>(),
                cpu_id
            );
        }
        let obj_type_raw = unsafe {
            core::ptr::addr_of!((*tcb).header.obj_type)
                .cast::<u8>()
                .read_unaligned()
        };
        if obj_type_raw != ObjectType::Tcb as u8 {
            panic!(
                "[SCHED] {}: bad TCB obj_type={} at 0x{:x} (cpu={})",
                site,
                obj_type_raw,
                addr,
                cpu_id
            );
        }
    }

    /// Validate the incoming target context before low-level register restore.
    ///
    /// `context_switch` assumes `new_tcb->context.rsp/rip` are valid kernel
    /// values and will `ret` to `rip`. If either is corrupt, stack/control-flow
    /// corruption propagates far from the source.
    unsafe fn validate_switch_target_context(&self, new_tcb: *mut Tcb) {
        let cpu_id = checked_cpu_id("validate_switch_target_context");
        unsafe {
            self.validate_tcb_ptr(new_tcb, "switch target", cpu_id);

            let rip = (*new_tcb).context.rip;
            let rsp = (*new_tcb).context.rsp;
            let kstack = (*new_tcb).kernel_stack_top;
            let text_start = core::ptr::addr_of!(_text_start) as u64;
            let text_end = core::ptr::addr_of!(_text_end) as u64;

            if kstack == 0 || !is_kernel_addr(kstack) || !is_aligned_to::<u64>(kstack) {
                panic!(
                    "[SCHED] switch target: bad kernel_stack_top=0x{:x} tcb=0x{:x} cpu={}",
                    kstack, new_tcb as u64, cpu_id
                );
            }

            if rip < text_start || rip >= text_end {
                panic!(
                    "[SCHED] switch target: RIP out of kernel .text rip=0x{:x} text=[0x{:x},0x{:x}) tcb=0x{:x} cpu={}",
                    rip, text_start, text_end, new_tcb as u64, cpu_id
                );
            }
            if !is_kernel_addr(rsp) || (rsp & 0xF) != 0 {
                panic!(
                    "[SCHED] switch target: bad RSP=0x{:x} (kernel={} align16={}) tcb=0x{:x} cpu={}",
                    rsp,
                    is_kernel_addr(rsp),
                    (rsp & 0xF) == 0,
                    new_tcb as u64,
                    cpu_id
                );
            }
        }
    }

    /// Mark thread for deferred enqueue after context switch completes.
    ///
    /// Sets state to Ready but does NOT insert into the ready queue.
    /// The thread will be enqueued by `process_pending_enqueue()` after
    /// `context_switch` has saved its registers.
    ///
    /// If there is already a pending thread in the slot (e.g. from a
    /// previous switch to a fresh thread whose entry point never returned
    /// through `do_context_switch`), it is enqueued now before being
    /// overwritten.
    ///
    /// Caller MUST hold the scheduler lock.
    fn set_pending_enqueue(&mut self, cpu_id: usize, tcb: *mut Tcb) {
        if cpu_id >= MAX_CPUS {
            panic!(
                "[SCHED] set_pending_enqueue: invalid cpu_id={} (max={})",
                cpu_id, MAX_CPUS
            );
        }
        if is_bootstrap_tcb(tcb) {
            unsafe {
                self.validate_tcb_ptr(tcb, "set_pending_enqueue bootstrap", cpu_id);
                (*tcb).state = ThreadState::Inactive;
            }
            return;
        }
        // Flush any stale pending before overwriting (safety net for
        // switches to fresh threads that skip process_pending_enqueue).
        let old = self.pending_enqueue[cpu_id];
        if old == tcb {
            unsafe {
                self.validate_tcb_ptr(tcb, "set_pending_enqueue same slot", cpu_id);
                (*tcb).state = ThreadState::Ready;
            }
            return;
        }
        if !old.is_null() {
            // Clear first so enqueue_unlocked() doesn't see the stale slot and
            // suppress queue insertion.
            self.pending_enqueue[cpu_id] = core::ptr::null_mut();
            unsafe {
                self.validate_tcb_ptr(old, "set_pending_enqueue stale slot", cpu_id);
                if (*old).state == ThreadState::Ready {
                    self.enqueue_unlocked(old);
                }
            }
        }

        unsafe {
            self.validate_tcb_ptr(tcb, "set_pending_enqueue new slot", cpu_id);
            (*tcb).state = ThreadState::Ready;
        }
        self.pending_enqueue[cpu_id] = tcb;
    }

    /// Track an outgoing thread in a non-Ready state (typically Blocked).
    ///
    /// This protects against a cross-CPU wake racing with `context_switch`:
    /// the waker may mark the thread Ready, but enqueue_unlocked() will defer
    /// the queue insertion until the pending slot is flushed after registers are
    /// safely saved.
    ///
    /// Caller MUST hold the scheduler lock.
    fn track_pending_switch_out(&mut self, cpu_id: usize, tcb: *mut Tcb) {
        if cpu_id >= MAX_CPUS {
            panic!(
                "[SCHED] track_pending_switch_out: invalid cpu_id={} (max={})",
                cpu_id, MAX_CPUS
            );
        }
        if is_bootstrap_tcb(tcb) {
            unsafe {
                self.validate_tcb_ptr(tcb, "track_pending_switch_out bootstrap", cpu_id);
                (*tcb).state = ThreadState::Inactive;
            }
            return;
        }

        let old = self.pending_enqueue[cpu_id];
        if !old.is_null() && old != tcb {
            // Clear first so enqueue_unlocked() doesn't suppress stale flush.
            self.pending_enqueue[cpu_id] = core::ptr::null_mut();
            unsafe {
                self.validate_tcb_ptr(old, "track_pending_switch_out stale slot", cpu_id);
                if (*old).state == ThreadState::Ready {
                    self.enqueue_unlocked(old);
                }
            }
        }

        unsafe {
            self.validate_tcb_ptr(tcb, "track_pending_switch_out", cpu_id);
        }
        self.pending_enqueue[cpu_id] = tcb;
    }

    /// Returns true if a thread is present in any deferred-switch slot.
    ///
    /// Caller MUST hold the scheduler lock.
    fn is_pending_on_any_cpu(&self, tcb: *mut Tcb) -> bool {
        self.pending_cpu_for(tcb).is_some()
    }

    /// Return the CPU whose deferred-switch slot currently references `tcb`.
    ///
    /// Caller MUST hold the scheduler lock.
    pub(crate) fn pending_cpu_for(&self, tcb: *mut Tcb) -> Option<usize> {
        let online = self.online_cpus as usize;
        for cpu in 0..online {
            if self.pending_enqueue[cpu] == tcb {
                return Some(cpu);
            }
        }
        None
    }

    /// Process deferred enqueue after context switch.
    ///
    /// If there is a pending thread and its state is still Ready
    /// (guards against TCB_SUSPEND setting Inactive), enqueue it.
    /// Clears the pending slot.
    ///
    /// Caller MUST hold the scheduler lock.
    fn process_pending_enqueue(&mut self) {
        let cpu_id = checked_cpu_id("process_pending_enqueue");
        let tcb = self.pending_enqueue[cpu_id];
        if !tcb.is_null() {
            self.pending_enqueue[cpu_id] = core::ptr::null_mut();
            unsafe {
                self.validate_tcb_ptr(tcb, "process_pending_enqueue", cpu_id);
                if (*tcb).state == ThreadState::Ready {
                    self.enqueue_unlocked(tcb);
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Context switch helpers
    // ---------------------------------------------------------------

    /// Ensure the outgoing thread is represented in the deferred slot before
    /// releasing SCHED_IPC_LOCK and switching away.
    ///
    /// This closes the race where another CPU wakes a thread (Blocked->Ready)
    /// before `context_switch` has saved the outgoing kernel continuation.
    ///
    /// # Preconditions
    /// - SCHED_IPC_LOCK is held by the caller.
    /// - Scheduler lock is NOT held.
    unsafe fn track_outgoing_before_switch(&mut self, old_tcb: *mut Tcb) {
        if old_tcb.is_null() {
            return;
        }

        let cpu_id = checked_cpu_id("track_outgoing_before_switch");
        self.lock();
        unsafe {
            if old_tcb == self.idle[cpu_id] || self.is_pending_on_any_cpu(old_tcb) {
                self.unlock();
                return;
            }

            self.validate_tcb_ptr(old_tcb, "track_outgoing_before_switch", cpu_id);
            match (*old_tcb).state {
                ThreadState::Running | ThreadState::Ready => {
                    self.set_pending_enqueue(cpu_id, old_tcb);
                }
                ThreadState::Inactive | ThreadState::Blocked | ThreadState::Waiting => {
                    self.track_pending_switch_out(cpu_id, old_tcb);
                }
            }
        }
        self.unlock();
    }

    #[inline]
    fn bump_context_switch_count(&mut self) {
        let cs_cpu = checked_cpu_id("bump_context_switch_count");
        self.context_switches[cs_cpu] += 1;
    }

    /// Install the target thread's kernel stack into per-CPU entry state.
    ///
    /// This updates both the syscall-entry kernel stack cache (`GS:8`) and
    /// the TSS RSP0 used for privilege transitions.
    unsafe fn install_switch_kernel_stack(&self, new_tcb: *mut Tcb) {
        unsafe {
            if (*new_tcb).kernel_stack_top != 0 {
                crate::arch::set_kernel_stack((*new_tcb).kernel_stack_top);
                crate::arch::set_tss_rsp0((*new_tcb).kernel_stack_top);
            }
        }
    }

    /// Prepare a switch target for the normal scheduler path.
    ///
    /// Handles VSpace-switch failure by marking the target inactive and
    /// falling back to this CPU's idle thread, matching historical behavior.
    ///
    /// Returns the actual thread to switch to (possibly idle fallback).
    unsafe fn prepare_switch_target_full(&mut self, new_tcb: *mut Tcb) -> *mut Tcb {
        let mut new_tcb = new_tcb;

        unsafe {
            if !(*new_tcb).vspace_root.is_null() {
                let vspace = &*(*new_tcb).vspace_root;
                if !vspace.switch_to() {
                    // VSpace Dying/Dead — cannot switch to this thread.
                    // Mark it inactive and fall back to idle thread.
                    (*new_tcb).state = ThreadState::Inactive;

                    self.lock();
                    let cpu_id = checked_cpu_id("prepare_switch_target_full");
                    let idle = self.idle[cpu_id];
                    self.set_current(idle);
                    self.unlock();

                    // Idle has null vspace_root — VSpace switch will be
                    // skipped below, keeping the current CR3.
                    new_tcb = idle;
                }
            }

            self.install_switch_kernel_stack(new_tcb);
        }

        new_tcb
    }

    /// Prepare a switch target for IPC fastpath.
    ///
    /// Fastpath already validated the receiver's basic invariants, so this
    /// path skips scheduler fallback logic in the common case. If activation
    /// fails (e.g. VSpace turned Dying concurrently), returns `false` so the
    /// caller can fall back to the checked path.
    unsafe fn prepare_switch_target_fast(&self, new_tcb: *mut Tcb) -> bool {
        unsafe {
            if (*new_tcb).vspace_root.is_null() || (*new_tcb).kernel_stack_top == 0 {
                return false;
            }

            let vspace = &*(*new_tcb).vspace_root;
            if !vspace.switch_to() {
                return false;
            }

            self.install_switch_kernel_stack(new_tcb);
        }

        true
    }

    /// Shared low-level switch sequence after the target thread is prepared.
    ///
    /// This is the delicate portion that must remain consistent across normal
    /// scheduler switches and IPC fastpath direct switches.
    ///
    /// Callers must enter with local IRQs disabled and only restore them from
    /// the resumed continuation after this function returns.
    unsafe fn switch_common(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        unsafe {
            let cpu_id = checked_cpu_id("switch_common");
            self.validate_tcb_ptr(old_tcb, "switch old_tcb", cpu_id);
            self.validate_switch_target_context(new_tcb);

            // Save outgoing thread's TLS base (FS_BASE MSR)
            (*old_tcb).tls_base = crate::arch::read_fs_base();

            // Release SCHED_IPC_LOCK before context switch (IF=0, no interrupts possible)
            crate::mm::SCHED_IPC_LOCK.unlock();

            // Save outgoing thread's FPU state if it owns the hardware registers.
            // This ensures the TCB buffer is up-to-date before the thread can be
            // migrated to another CPU (where flush_if_owner would miss it).
            crate::arch::fpu::save_on_switch(old_tcb as *mut u8);

            // Set CR0.TS so the new thread's first FPU use triggers #NM for lazy switching
            crate::arch::fpu::set_ts();

            // Restore incoming thread's TLS base (FS_BASE MSR).
            // Always write — 0 clears the previous thread's FS_BASE.
            crate::arch::write_fs_base((*new_tcb).tls_base);

            // Update per-CPU canary cache to incoming thread's canary.
            crate::arch::set_per_cpu_canary((*new_tcb).stack_canary);

            // Pure register save/restore — no shared state accessed.
            let old_ctx = &mut (*old_tcb).context as *mut _;
            let new_ctx = &(*new_tcb).context as *const _;
            crate::arch::context_switch(old_ctx, new_ctx);

            // Reacquire SCHED_IPC_LOCK after resume
            crate::mm::SCHED_IPC_LOCK.lock();

            // Process deferred enqueue now that context is saved.
            self.lock();
            self.process_pending_enqueue();
            self.unlock();
        }
    }

    /// Fastpath-specific switch path that shares the common register/TLS/FPU
    /// sequence but uses a lighter target-preparation step in the hot path.
    unsafe fn switch_common_fast(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        unsafe {
            if self.prepare_switch_target_fast(new_tcb) {
                self.switch_common(old_tcb, new_tcb);
            } else {
                // Fall back to the fully-checked preparation path on races.
                let prepared = self.prepare_switch_target_full(new_tcb);
                self.switch_common(old_tcb, prepared);
            }
        }
    }

    /// Fastpath wrapper for the scheduler's full context-switch path.
    ///
    /// IPC fastpath uses this to avoid duplicating switch machinery while still
    /// preserving a lighter-weight target-preparation path.
    ///
    /// # Preconditions
    /// - `SCHED_IPC_LOCK` MUST be held.
    /// - Scheduler lock MUST NOT be held.
    /// - `set_current(new_tcb)` and thread state transitions were already done.
    /// - Local IRQs MUST remain disabled across the switch; restore them only
    ///   after the resumed continuation returns from this call.
    pub(crate) unsafe fn do_context_switch_fastpath(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        unsafe {
            self.track_outgoing_before_switch(old_tcb);
            self.bump_context_switch_count();
            self.switch_common_fast(old_tcb, new_tcb);
        }
    }

    /// Perform the actual context switch (VSpace, kernel stack, registers).
    ///
    /// # Preconditions
    /// - SCHED_IPC_LOCK MUST be held: this function releases it before switching
    ///   and reacquires it on resume. Callers without it cause a lock leak.
    /// - Scheduler lock (`lock_state`) MUST NOT be held.
    /// - Local IRQs MUST remain disabled across the switch; restore them only
    ///   after the resumed continuation returns from this call.
    unsafe fn do_context_switch(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        unsafe {
            self.track_outgoing_before_switch(old_tcb);
            self.bump_context_switch_count();
            let prepared = self.prepare_switch_target_full(new_tcb);
            self.switch_common(old_tcb, prepared);
        }
    }

    // ---------------------------------------------------------------
    // Timer tick (acquires lock internally)
    // ---------------------------------------------------------------

    /// Handle timer tick — called from interrupt context.
    ///
    /// Acquires the scheduler lock, performs budget accounting, and if a
    /// context switch is needed, releases the lock before switching.
    pub fn timer_tick(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        // Flush any deferred enqueue left over from a previous switch to a
        // fresh thread whose entry point never returned through do_context_switch.
        self.process_pending_enqueue();

        // Wake expired sleepers
        let now_ns = crate::arch::now_ns();
        unsafe { crate::sched::sleep_queue::check_wakeups(now_ns); }

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];

            // Count timer ticks on this CPU
            self.timer_ticks[cpu_id] += 1;

            if current.is_null() {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            let sched_ctx = (*current).sched_context;
            if sched_ctx.is_null() {
                // Idle thread — count idle tick and check if woken thread should preempt
                self.idle_ticks[cpu_id] += 1;
                let new_tcb = self.schedule_unlocked();
                if current != new_tcb {
                    self.set_current(new_tcb);
                    self.unlock();
                    self.do_context_switch(current, new_tcb);
                    crate::mm::restore_irq(irq_flag);
                    return;
                }
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Track consumed time
            (*sched_ctx).consumed += 1;

            // Decrement remaining budget
            (*sched_ctx).remaining = (*sched_ctx).remaining.saturating_sub(1);

            // Check if budget exhausted
            if (*sched_ctx).remaining == 0 {
                // If cross-CPU TCB_SUSPEND set us Inactive, just schedule away
                // without re-enqueuing (prevents resurrection)
                if (*current).state == ThreadState::Inactive {
                    let new_tcb = self.schedule_unlocked();
                    if current != new_tcb {
                        self.set_current(new_tcb);
                        self.unlock();
                        self.do_context_switch(current, new_tcb);
                        crate::mm::restore_irq(irq_flag);
                        return;
                    }
                } else {
                    self.replenish_budget_unlocked(current);
                    self.set_pending_enqueue(cpu_id, current);
                    let new_tcb = self.schedule_unlocked();
                    if new_tcb == self.idle[cpu_id] && !self.pending_enqueue[cpu_id].is_null() {
                        // No real thread available — cancel pending, keep current
                        self.pending_enqueue[cpu_id] = core::ptr::null_mut();
                        (*current).state = ThreadState::Running;
                    } else if current != new_tcb {
                        self.set_current(new_tcb);
                        self.unlock();
                        self.do_context_switch(current, new_tcb);
                        crate::mm::restore_irq(irq_flag);
                        return;
                    }
                }
            }
            // Check for preemption (earlier deadline ready)
            else if self.needs_reschedule() {
                // Deferred enqueue: mark Ready but don't insert into queue yet.
                // process_pending_enqueue() runs after context_switch saves registers.
                if (*current).state != ThreadState::Inactive {
                    self.set_pending_enqueue(cpu_id, current);
                }
                let new_tcb = self.schedule_unlocked();
                if new_tcb == self.idle[cpu_id] && !self.pending_enqueue[cpu_id].is_null() {
                    // No real thread available — cancel pending, keep current
                    self.pending_enqueue[cpu_id] = core::ptr::null_mut();
                    (*current).state = ThreadState::Running;
                } else if current != new_tcb {
                    self.set_current(new_tcb);
                    self.unlock();
                    self.do_context_switch(current, new_tcb);
                    crate::mm::restore_irq(irq_flag);
                    return;
                }
            }
        }

        // Periodic load balancing: BSP checks every 100 ticks (~100ms)
        let rebalance_ipi_mask = unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            if cpu_id == 0 {
                self.rebalance_counter += 1;
                if self.rebalance_counter >= 100 {
                    self.rebalance_counter = 0;
                    self.try_rebalance()
                } else {
                    0
                }
            } else {
                0
            }
        };

        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };

        // Send rebalance IPIs AFTER releasing lock to prevent deadlock
        if rebalance_ipi_mask != 0 {
            let online = self.online_cpus as usize;
            for cpu in 0..online {
                if rebalance_ipi_mask & (1 << cpu) != 0 {
                    unsafe {
                        crate::arch::send_ipi(cpu, crate::arch::IpiKind::Reschedule);
                    }
                }
            }
        }
    }

    /// Handle reschedule IPI — checks ready queue for work on this CPU.
    ///
    /// Unlike timer_tick(), this does not require a sched_context, so it
    /// works correctly when the current thread is the idle thread.
    pub fn handle_reschedule_ipi(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        // Flush any deferred enqueue left over from a previous switch to a
        // fresh thread whose entry point never returned through do_context_switch.
        self.process_pending_enqueue();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            self.ipi_reschedules[cpu_id] += 1;
            let current = self.current[cpu_id];
            if current.is_null() {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Deferred enqueue: mark Ready but don't insert into queue yet.
            // The Running check prevents re-enqueuing Inactive threads that were
            // suspended by a cross-CPU TCB_SUSPEND + IPI.
            if current != self.idle[cpu_id] && (*current).state == ThreadState::Running {
                self.set_pending_enqueue(cpu_id, current);
            }

            let new_tcb = self.schedule_unlocked();
            if new_tcb == self.idle[cpu_id] && !self.pending_enqueue[cpu_id].is_null() {
                // No real thread available — cancel pending, keep current
                self.pending_enqueue[cpu_id] = core::ptr::null_mut();
                (*current).state = ThreadState::Running;
            } else if current != new_tcb {
                self.set_current(new_tcb);
                self.unlock();
                self.do_context_switch(current, new_tcb);
                crate::mm::restore_irq(irq_flag);
                return;
            }
        }

        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
    }

    /// Replenish budget for a thread whose budget expired — unlocked variant.
    ///
    /// Advances deadline, updates priority, and replenishes budget.
    /// Does NOT enqueue the thread — caller must use `set_pending_enqueue()`.
    ///
    /// Caller MUST hold the scheduler lock.
    fn replenish_budget_unlocked(&mut self, tcb: *mut Tcb) {
        unsafe {
            let sched_ctx = (*tcb).sched_context;
            if sched_ctx.is_null() {
                return;
            }

            if (*sched_ctx).period > 0 {
                // Periodic: advance deadline by period
                (*sched_ctx).deadline += (*sched_ctx).period;
            } else {
                // Sporadic: move to lowest EDF priority
                (*sched_ctx).deadline = u64::MAX;
            }

            // Update base priority (unaffected by PIP)
            (*tcb).base_priority = (*sched_ctx).deadline;

            // Update effective priority only if no active PIP donation
            if (*tcb).pip_donation_count == 0 {
                (*tcb).priority = (*sched_ctx).deadline;
            }

            // Replenish budget
            (*sched_ctx).remaining = (*sched_ctx).budget;
        }
    }

    // ---------------------------------------------------------------
    // Load balancing
    // ---------------------------------------------------------------

    /// Periodic rebalancing: check if any CPU is running a lower-priority
    /// thread while the ready queue has a higher-priority compatible thread.
    ///
    /// Returns a bitmask of CPUs that should receive a reschedule IPI.
    /// IPIs are sent AFTER the scheduler lock is released to avoid
    /// deadlocks (target CPU spins on lock in IPI handler).
    ///
    /// Caller MUST hold the scheduler lock.
    fn try_rebalance(&mut self) -> u32 {
        let mut ipi_mask: u32 = 0;
        let this_cpu = crate::arch::current_cpu() as usize;
        let online = self.online_cpus as usize;

        // O(online_cpus): for each remote CPU, check if its queue head
        // can preempt the currently running thread on that CPU.
        for cpu in 0..online {
            if cpu == this_cpu {
                continue; // this CPU handles its own preemption
            }

            let head = self.ready_heads[cpu];
            let running = self.current[cpu];

            if running.is_null() || running == self.idle[cpu] {
                // Idle CPU — if it has work queued, wake it
                if !head.is_null() {
                    ipi_mask |= 1 << cpu;
                }
                continue;
            }

            if !head.is_null() {
                unsafe {
                    if (*head).priority < (*running).priority {
                        ipi_mask |= 1 << cpu;
                    }
                }
            }
        }

        ipi_mask
    }

    // ---------------------------------------------------------------
    // Reschedule (acquires lock, then drops before context switch)
    // ---------------------------------------------------------------

    /// Perform a context switch to the next thread.
    ///
    /// # Preconditions
    /// - SCHED_IPC_LOCK MUST be held by the caller. do_context_switch releases
    ///   it before switching and reacquires on resume.
    ///
    /// Acquires the scheduler lock internally for the scheduling decision.
    pub fn reschedule(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        // Flush any deferred enqueue left over from a previous switch to a
        // fresh thread whose entry point never returned through do_context_switch.
        self.process_pending_enqueue();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let old_tcb = self.current[cpu_id];
            if !old_tcb.is_null() && old_tcb != self.idle[cpu_id] {
                match (*old_tcb).state {
                    ThreadState::Running => self.set_pending_enqueue(cpu_id, old_tcb),
                    ThreadState::Inactive => {}
                    _ => self.track_pending_switch_out(cpu_id, old_tcb),
                }
            }
            let new_tcb = self.schedule_unlocked();

            if old_tcb == new_tcb {
                // No switch needed
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Update current pointer
            self.set_current(new_tcb);

            // Release lock before context switch
            self.unlock();
            self.do_context_switch(old_tcb, new_tcb);
            crate::mm::restore_irq(irq_flag);
        }
    }

    // ---------------------------------------------------------------
    // Yield (acquires lock, deferred enqueue before context switch)
    // ---------------------------------------------------------------

    /// Yield the current thread to the scheduler.
    ///
    /// Uses deferred enqueue to prevent double-schedule race on SMP:
    /// the current thread is NOT inserted into the ready queue until
    /// `context_switch` has saved its registers.
    ///
    /// # Preconditions
    /// - SCHED_IPC_LOCK MUST be held by the caller.
    pub fn yield_current(&mut self) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];
            if current.is_null() || current == self.idle[cpu_id] {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            if (*current).state != ThreadState::Inactive {
                self.set_pending_enqueue(cpu_id, current);
            }

            let new_tcb = self.schedule_unlocked();
            if new_tcb == self.idle[cpu_id] && !self.pending_enqueue[cpu_id].is_null() {
                // No real thread available — cancel pending, keep current
                self.pending_enqueue[cpu_id] = core::ptr::null_mut();
                (*current).state = ThreadState::Running;
            } else if current != new_tcb {
                self.set_current(new_tcb);
                self.unlock();
                self.do_context_switch(current, new_tcb);
                crate::mm::restore_irq(irq_flag);
                return;
            }
        }

        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
    }

    // ---------------------------------------------------------------
    // VSpace blocking / wakeup (manages lock internally)
    // ---------------------------------------------------------------

    /// Enqueue thread in VSpace's intrusive wait queue
    ///
    /// Must be called with scheduler lock held and IRQs disabled.
    unsafe fn enqueue_vspace_waiter_locked(
        &mut self,
        tracking: &crate::mm::VSpaceTracking,
        tcb: *mut Tcb,
    ) {
        unsafe {
            (*tcb).vspace_wait_next = core::ptr::null_mut();

            // Get and update waiter head (UnsafeCell, scheduler lock sync)
            let head = tracking.waiter_head_get_locked();
            (*tcb).vspace_wait_next = head;
            tracking.waiter_head_set_locked(tcb);
        }
    }

    /// Wake all threads waiting on a VSpace
    ///
    /// Called when last core exits the VSpace.
    /// CRITICAL: Must be called with scheduler lock held and IRQs disabled!
    fn wakeup_vspace_waiters_locked(&mut self, tracking: &crate::mm::VSpaceTracking) {
        unsafe {
            // Clear waiter head and get all waiters
            let mut current = tracking.waiter_head_get_locked();
            tracking.waiter_head_set_locked(core::ptr::null_mut());

            // Wake all waiters
            while !current.is_null() {
                let next = (*current).vspace_wait_next;

                (*current).state = ThreadState::Ready;
                (*current).blocked_reason = None;
                (*current).blocked_vspace_tracking = core::ptr::null_mut();
                (*current).vspace_wait_next = core::ptr::null_mut();

                self.enqueue_unlocked(current);
                current = next;
            }
        }
    }

    /// Finish deactivate operation - wake waiters if VSpace became inactive
    ///
    /// CRITICAL: Must be called with scheduler lock held and IRQs disabled!
    pub fn finish_deactivate(&mut self, tracking: &crate::mm::VSpaceTracking) {
        self.wakeup_vspace_waiters_locked(tracking);
    }

    /// Block current thread on VSpace teardown (MAY switch, manages IRQ state internally)
    ///
    /// CRITICAL: This function may call do_context_switch() which releases/reacquires
    /// SCHED_IPC_LOCK. The function manages both SCHED_IPC_LOCK and scheduler lock internally.
    /// Do NOT wrap with with_lock().
    pub fn block_current_on_vspace(&mut self, tracking: &crate::mm::VSpaceTracking) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        crate::mm::SCHED_IPC_LOCK.lock();
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];

            // Fast path: check if already inactive
            if !tracking.is_active() {
                self.unlock();
                crate::mm::SCHED_IPC_LOCK.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Mark as blocked
            (*current).state = ThreadState::Blocked;
            (*current).blocked_reason = Some(BlockedReason::VSpaceWait);
            (*current).blocked_vspace_tracking = tracking as *const _ as *mut _;

            // Add to VSpace's intrusive wait queue
            self.enqueue_vspace_waiter_locked(tracking, current);

            // Make schedule decision while still holding lock
            let new_tcb = self.schedule_unlocked();
            let old_tcb = current;
            if old_tcb != new_tcb {
                self.track_pending_switch_out(cpu_id, old_tcb);
            }

            // Release scheduler lock before context switch
            self.unlock();

            if old_tcb != new_tcb {
                self.set_current(new_tcb);
                // do_context_switch releases SCHED_IPC_LOCK before switch,
                // reacquires on resume
                self.do_context_switch(old_tcb, new_tcb);
            }

            // After resume: SCHED_IPC_LOCK is held (reacquired by do_context_switch)
            crate::mm::SCHED_IPC_LOCK.unlock();
            crate::mm::restore_irq(irq_flag);
        }
    }

    // ---------------------------------------------------------------
    // Sleep blocking (acquires lock internally)
    // ---------------------------------------------------------------

    /// Block current thread on nanosleep timer.
    ///
    /// Acquires the scheduler lock, sets up timer state, inserts into
    /// the sleep queue, and performs context switch if needed.
    /// This ensures sleep_queue::insert() is called with lock held.
    pub fn block_current_sleeping(&mut self, wakeup_ns: u64) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];
            if current.is_null() {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            (*current).timer_wakeup_ns = wakeup_ns;
            (*current).state = ThreadState::Blocked;
            (*current).blocked_reason = Some(BlockedReason::TimerBlocked);

            crate::sched::sleep_queue::insert(current);

            let new_tcb = self.schedule_unlocked();
            let old_tcb = current;
            if old_tcb != new_tcb {
                self.track_pending_switch_out(cpu_id, old_tcb);
                self.set_current(new_tcb);
                self.unlock();
                self.do_context_switch(old_tcb, new_tcb);
                crate::mm::restore_irq(irq_flag);
                return;
            }
        }

        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
    }

    // ---------------------------------------------------------------
    // Futex timed blocking (inserts into sleep queue, requires lock)
    // ---------------------------------------------------------------

    /// Block current thread for a futex timed wait.
    ///
    /// The caller has already set the thread's state to Blocked and
    /// blocked_reason to FutexTimedBlocked, and inserted it into the
    /// futex hash table. This method inserts the thread into the sleep
    /// queue and performs a context switch.
    ///
    /// # Preconditions
    /// - SCHED_IPC_LOCK MUST be held by the caller (released before switch,
    ///   reacquired on resume).
    /// - Thread state and futex fields already configured by caller.
    pub fn block_current_futex_timed(&mut self, wakeup_ns: u64) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];
            if current.is_null() {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Set timer wakeup and insert into sleep queue
            (*current).timer_wakeup_ns = wakeup_ns;
            crate::sched::sleep_queue::insert(current);

            let new_tcb = self.schedule_unlocked();
            let old_tcb = current;
            if old_tcb != new_tcb {
                self.track_pending_switch_out(cpu_id, old_tcb);
                self.set_current(new_tcb);
                self.unlock();
                // SAFETY: SCHED_IPC_LOCK is held; do_context_switch releases
                // before switch and reacquires on resume.
                self.do_context_switch(old_tcb, new_tcb);
                crate::mm::restore_irq(irq_flag);
                return;
            }
        }

        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
    }

    // ---------------------------------------------------------------
    // Kernel exit epilogue
    // ---------------------------------------------------------------

    /// Kernel exit epilogue - MUST be called from ALL kernel exit points
    ///
    /// # Safety
    /// Must be called with scheduler lock held and IRQs disabled.
    fn kernel_exit_epilogue(&mut self) {
        // Process pending VSpace deactivates
        self.process_pending_deactivates();
    }

    /// Process pending deactivates (internal, called by kernel_exit_epilogue)
    ///
    /// CRITICAL: Must be called with scheduler lock held and IRQs disabled!
    fn process_pending_deactivates(&mut self) {
        let cpu_id = crate::arch::current_cpu() as usize;

        unsafe {
            // Take pending if any (null check is implicit)
            let old_tracking = crate::mm::take_pending_deactivate(cpu_id);

            if !old_tracking.is_null() {
                // Perform deactivate_nosched and check result
                match (*old_tracking).deactivate_nosched(cpu_id) {
                    crate::mm::DeactivateResult::BecameInactive => {
                        // We hold scheduler lock, call finish_deactivate
                        self.finish_deactivate(&*old_tracking);
                    }
                    _ => {
                        // Not active or still active, no wakeup needed
                    }
                }
            }
        }

        // Always advance quiescent generation - we passed a safe point
        crate::mm::advance_quiescent_gen(cpu_id);
    }

    /// Execute closure with scheduler lock held and IRQs disabled
    ///
    /// **IMPORTANT**: Use this ONLY for operations that do NOT block/switch!
    /// For blocking operations like VSpace wait, use `block_current_on_vspace()` instead.
    ///
    /// Automatically calls `kernel_exit_epilogue()` to process pending deactivates.
    pub fn with_lock<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Scheduler) -> R,
    {
        // Save interrupt flag and disable IRQs
        let irq_flag = unsafe { crate::mm::save_irq_disable() };

        // Take scheduler lock
        self.lock();

        // Process pending deactivates (we hold lock + IRQs disabled)
        self.kernel_exit_epilogue();

        let result = f(self);

        // Release scheduler lock
        self.unlock();

        // Restore interrupt flag
        unsafe { crate::mm::restore_irq(irq_flag) };

        result
    }
}

static mut SCHEDULER: Scheduler = Scheduler::new();

/// Per-CPU atomic tracking of the currently running TCB pointer.
///
/// Updated via `set_current()` and `schedule_unlocked()` with Release ordering.
/// Read by `current_on_cpu()` with Acquire ordering. Used by cross-CPU
/// `TCB_SUSPEND` to spin-wait until the target CPU has context-switched away.
static CURRENT_ON_CPU: [AtomicUsize; MAX_CPUS] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; MAX_CPUS]
};

/// Read the current thread pointer for a given CPU (lock-free).
///
/// Returns the raw TCB pointer as `usize`. The caller can compare this
/// against a known TCB address to determine if that thread is still
/// executing on the target CPU.
pub fn current_on_cpu(cpu: usize) -> usize {
    CURRENT_ON_CPU[cpu].load(core::sync::atomic::Ordering::Acquire)
}

/// Global scheduler instance
pub fn scheduler() -> &'static mut Scheduler {
    // SAFETY: Single-threaded kernel access, interrupts disabled during scheduler operations
    unsafe { &mut *(&raw mut SCHEDULER) }
}
