//! EDF Scheduler
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::thread::{BlockedReason, Tcb, ThreadState};
use crate::arch::MAX_CPUS;
use core::sync::atomic::AtomicUsize;

/// EDF Scheduler
pub struct Scheduler {
    /// Ready queue head (sorted by deadline)
    ready_head: *mut Tcb,
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
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            ready_head: core::ptr::null_mut(),
            current: [core::ptr::null_mut(); MAX_CPUS],
            idle: [core::ptr::null_mut(); MAX_CPUS],
            pending_enqueue: [core::ptr::null_mut(); MAX_CPUS],
            lock_state: core::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Take scheduler lock
    pub(crate) fn lock(&self) {
        use core::sync::atomic::Ordering;
        let mut _spins: u32 = 0;
        while self
            .lock_state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.lock_state.load(Ordering::Relaxed) != 0 {
                core::hint::spin_loop();
                _spins += 1;
                #[cfg(debug_assertions)]
                if _spins > 10_000_000 {
                    crate::serial_puts("[SCHED SPINLOCK] possible deadlock detected\n");
                    _spins = 0;
                }
            }
        }
    }

    /// Release scheduler lock
    pub(crate) fn unlock(&self) {
        self.lock_state
            .store(0, core::sync::atomic::Ordering::Release);
    }

    // ---------------------------------------------------------------
    // Unlocked queue operations (caller must hold lock + IRQs disabled)
    // ---------------------------------------------------------------

    /// Add thread to ready queue (sorted by deadline) — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn enqueue_unlocked(&mut self, tcb: *mut Tcb) {
        unsafe {
            (*tcb).state = ThreadState::Ready;

            // Insert sorted by deadline (priority field stores deadline)
            if self.ready_head.is_null() || (*tcb).priority < (*self.ready_head).priority {
                (*tcb).next = self.ready_head;
                self.ready_head = tcb;
            } else {
                let mut current = self.ready_head;
                while !(*current).next.is_null() && (*(*current).next).priority <= (*tcb).priority {
                    current = (*current).next;
                }
                (*tcb).next = (*current).next;
                (*current).next = tcb;
            }

            // Wake an idle CPU so it can pick up this thread
            let affinity = (*tcb).cpu_affinity;
            let this_cpu = crate::arch::current_cpu() as usize;

            if affinity != 0xFFFF_FFFF {
                // Specific affinity: IPI target if idle
                let target = affinity as usize;
                if target != this_cpu
                    && target < MAX_CPUS
                    && !self.idle[target].is_null()
                    && self.current[target] == self.idle[target]
                {
                    crate::arch::send_ipi(
                        target,
                        crate::arch::IpiKind::Reschedule,
                    );
                }
            } else {
                // Any-CPU affinity: IPI one idle CPU so it picks up the thread
                for cpu in 0..MAX_CPUS {
                    if cpu != this_cpu
                        && !self.idle[cpu].is_null()
                        && self.current[cpu] == self.idle[cpu]
                    {
                        crate::arch::send_ipi(cpu, crate::arch::IpiKind::Reschedule);
                        break;
                    }
                }
            }
        }
    }

    /// Remove highest priority (earliest deadline) thread — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn dequeue_unlocked(&mut self) -> Option<*mut Tcb> {
        if self.ready_head.is_null() {
            None
        } else {
            unsafe {
                let tcb = self.ready_head;
                self.ready_head = (*tcb).next;
                (*tcb).next = core::ptr::null_mut();
                Some(tcb)
            }
        }
    }

    /// Remove highest priority thread for a CPU — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn dequeue_for_cpu_unlocked(&mut self, cpu_id: usize) -> Option<*mut Tcb> {
        unsafe {
            let mut prev: *mut Tcb = core::ptr::null_mut();
            let mut current = self.ready_head;

            while !current.is_null() {
                let affinity = (*current).cpu_affinity;
                if affinity == 0xFFFF_FFFF || affinity as usize == cpu_id {
                    if prev.is_null() {
                        self.ready_head = (*current).next;
                    } else {
                        (*prev).next = (*current).next;
                    }
                    (*current).next = core::ptr::null_mut();
                    return Some(current);
                }
                prev = current;
                current = (*current).next;
            }
            None
        }
    }

    /// Remove a specific thread from the ready queue — unlocked variant.
    ///
    /// Caller MUST hold the scheduler lock.
    pub fn remove_from_ready_queue_unlocked(&mut self, tcb: *mut Tcb) -> bool {
        unsafe {
            let mut prev: *mut Tcb = core::ptr::null_mut();
            let mut current = self.ready_head;
            while !current.is_null() {
                if current == tcb {
                    if prev.is_null() {
                        self.ready_head = (*current).next;
                    } else {
                        (*prev).next = (*current).next;
                    }
                    (*current).next = core::ptr::null_mut();
                    return true;
                }
                prev = current;
                current = (*current).next;
            }
            false
        }
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
        if let Some(tcb) = self.dequeue_for_cpu_unlocked(cpu_id) {
            unsafe {
                (*tcb).state = ThreadState::Running;
            }
            self.current[cpu_id] = tcb;
            CURRENT_ON_CPU[cpu_id].store(tcb as usize, core::sync::atomic::Ordering::Release);
            tcb
        } else {
            // Return idle thread for this CPU
            self.idle[cpu_id]
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
    /// Returns `None` if the thread is not the current thread on any CPU.
    /// Caller MUST hold the scheduler lock.
    pub fn find_running_cpu(&self, tcb: *mut Tcb) -> Option<usize> {
        for cpu in 0..MAX_CPUS {
            if self.current[cpu] == tcb {
                return Some(cpu);
            }
        }
        None
    }

    /// Check if reschedule needed (preemption) on the calling CPU
    pub fn needs_reschedule(&self) -> bool {
        let cpu_id = crate::arch::current_cpu() as usize;
        let current = self.current[cpu_id];
        if self.ready_head.is_null() || current.is_null() {
            return false;
        }
        unsafe {
            // Walk the ready queue to find the first thread compatible with this CPU
            let mut node = self.ready_head;
            while !node.is_null() {
                let affinity = (*node).cpu_affinity;
                if affinity == 0xFFFF_FFFF || affinity as usize == cpu_id {
                    return (*node).priority < (*current).priority;
                }
                node = (*node).next;
            }
            false
        }
    }

    // ---------------------------------------------------------------
    // Deferred enqueue helpers
    // ---------------------------------------------------------------

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
        // Flush any stale pending before overwriting (safety net for
        // switches to fresh threads that skip process_pending_enqueue).
        let old = self.pending_enqueue[cpu_id];
        if !old.is_null() {
            unsafe {
                if (*old).state == ThreadState::Ready {
                    self.enqueue_unlocked(old);
                }
            }
            self.pending_enqueue[cpu_id] = core::ptr::null_mut();
        }

        unsafe {
            (*tcb).state = ThreadState::Ready;
        }
        self.pending_enqueue[cpu_id] = tcb;
    }

    /// Process deferred enqueue after context switch.
    ///
    /// If there is a pending thread and its state is still Ready
    /// (guards against TCB_SUSPEND setting Inactive), enqueue it.
    /// Clears the pending slot.
    ///
    /// Caller MUST hold the scheduler lock.
    fn process_pending_enqueue(&mut self) {
        let cpu_id = crate::arch::current_cpu() as usize;
        let tcb = self.pending_enqueue[cpu_id];
        if !tcb.is_null() {
            self.pending_enqueue[cpu_id] = core::ptr::null_mut();
            unsafe {
                if (*tcb).state == ThreadState::Ready {
                    self.enqueue_unlocked(tcb);
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Context switch helpers
    // ---------------------------------------------------------------

    /// Perform the actual context switch (VSpace, kernel stack, registers).
    ///
    /// # Preconditions
    /// - SCHED_IPC_LOCK MUST be held: this function releases it before switching
    ///   and reacquires it on resume. Callers without it cause a lock leak.
    /// - Scheduler lock (`lock_state`) MUST NOT be held.
    unsafe fn do_context_switch(&mut self, old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
        // Shadow new_tcb so we can reassign on VSpace failure
        let mut new_tcb = new_tcb;

        unsafe {
            // Switch to the target thread's user VSpace
            if !(*new_tcb).vspace_root.is_null() {
                let vspace = &*(*new_tcb).vspace_root;
                if !vspace.switch_to() {
                    // VSpace Dying/Dead — cannot switch to this thread.
                    // Mark it inactive and fall back to idle thread.
                    (*new_tcb).state = ThreadState::Inactive;

                    self.lock();
                    let cpu_id = crate::arch::current_cpu() as usize;
                    let idle = self.idle[cpu_id];
                    self.set_current(idle);
                    self.unlock();

                    // Idle has null vspace_root — VSpace switch will be
                    // skipped below, keeping the current CR3.
                    new_tcb = idle;
                }
            }

            // Switch per-CPU kernel stack
            if (*new_tcb).kernel_stack_top != 0 {
                crate::arch::set_kernel_stack((*new_tcb).kernel_stack_top);
                crate::arch::set_tss_rsp0((*new_tcb).kernel_stack_top);
            }

            // Save outgoing thread's TLS base (FS_BASE MSR)
            (*old_tcb).tls_base = crate::arch::read_fs_base();

            // Release SCHED_IPC_LOCK before context switch (IF=0, no interrupts possible)
            crate::mm::SCHED_IPC_LOCK.unlock();

            // Set CR0.TS so the new thread's first FPU use triggers #NM for lazy switching
            crate::arch::fpu::set_ts();

            // Restore incoming thread's TLS base (FS_BASE MSR).
            // Always write — 0 clears the previous thread's FS_BASE.
            crate::arch::write_fs_base((*new_tcb).tls_base);

            // Pure register save/restore — no shared state accessed
            let old_ctx = &mut (*old_tcb).context as *mut _;
            let new_ctx = &(*new_tcb).context as *const _;
            crate::arch::context_switch(old_ctx, new_ctx);

            // Reacquire SCHED_IPC_LOCK after resume
            crate::mm::SCHED_IPC_LOCK.lock();

            // Process deferred enqueue now that context is saved.
            // The thread that was pending before the switch can now safely
            // appear in the ready queue (its registers are saved).
            self.lock();
            self.process_pending_enqueue();
            self.unlock();
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

        // Wake expired sleepers
        let now_ns = crate::arch::now_ns();
        unsafe { crate::sched::sleep_queue::check_wakeups(now_ns); }

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];

            if current.is_null() {
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                return;
            }

            let sched_ctx = (*current).sched_context;
            if sched_ctx.is_null() {
                // Idle thread — check if woken thread should preempt
                let new_tcb = self.schedule_unlocked();
                if current != new_tcb {
                    self.set_current(new_tcb);
                    self.unlock();
                    crate::mm::restore_irq(irq_flag);
                    self.do_context_switch(current, new_tcb);
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
                        crate::mm::restore_irq(irq_flag);
                        self.do_context_switch(current, new_tcb);
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
                        crate::mm::restore_irq(irq_flag);
                        self.do_context_switch(current, new_tcb);
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
                    crate::mm::restore_irq(irq_flag);
                    self.do_context_switch(current, new_tcb);
                    return;
                }
            }
        }

        self.unlock();
        unsafe { crate::mm::restore_irq(irq_flag) };
    }

    /// Handle reschedule IPI — checks ready queue for work on this CPU.
    ///
    /// Unlike timer_tick(), this does not require a sched_context, so it
    /// works correctly when the current thread is the idle thread.
    pub fn handle_reschedule_ipi(&mut self) {
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
                crate::mm::restore_irq(irq_flag);
                self.do_context_switch(current, new_tcb);
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

            // Update priority (deadline) in TCB
            (*tcb).priority = (*sched_ctx).deadline;

            // Replenish budget
            (*sched_ctx).remaining = (*sched_ctx).budget;
        }
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

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let old_tcb = self.current[cpu_id];
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
            crate::mm::restore_irq(irq_flag);

            self.do_context_switch(old_tcb, new_tcb);
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
                crate::mm::restore_irq(irq_flag);
                self.do_context_switch(current, new_tcb);
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
                self.set_current(new_tcb);
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                self.do_context_switch(old_tcb, new_tcb);
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
                self.set_current(new_tcb);
                self.unlock();
                crate::mm::restore_irq(irq_flag);
                // SAFETY: SCHED_IPC_LOCK is held; do_context_switch releases
                // before switch and reacquires on resume.
                self.do_context_switch(old_tcb, new_tcb);
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
