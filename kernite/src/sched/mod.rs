// SPDX-License-Identifier: GPL-2.0-only
//! Scheduler
//!
//! Class-based scheduler:
//! - general tasks use Fair/EEVDF-style virtual-runtime accounting
//! - future RT workloads use RT FIFO
//! - explicit scheduling-context workloads use Deadline
//! - idle threads stay in the Idle class

pub mod class;
pub mod control;
pub mod deadline_queue;
pub mod pip;
pub mod scheduler;
pub mod thread;

// Re-exports for public API
pub use thread::Tcb;

/// Scheduler tick frequency (Hz). Must stay in sync with
/// `lib/trona/uapi/consts/kernel.rs::TICKS_PER_SEC`.
///
/// One timer tick = 1 / `TICKS_PER_SEC` seconds. Used by sysctlfs /
/// procfs compatibility projections that still render Linux/FreeBSD-style
/// tick counters from the kernel's runtime-nanosecond accounting.
pub const TICKS_PER_SEC: u64 = 100;

use crate::arch;
use crate::arch::MAX_CPUS;
use crate::mm::{PAGE_SIZE, frame::FrameOwner, frame::KernelMetaKind, phys_to_virt, pmm_alloc};

/// Idle thread stack size
const IDLE_STACK_SIZE: usize = PAGE_SIZE;

/// Idle thread function
///
/// The idle thread runs when no other threads are ready.
///
/// **CRITICAL**: The idle loop MUST periodically call scheduler().with_lock()
/// to process pending VSpace deactivates. This structurally guarantees that
/// CPUs receiving IPI will eventually process pending, preventing the
/// delete syscall from hanging forever.
///
/// BSP also processes deferred free entries to clean up VSpaceTracking objects
/// that have reached quiescent state.
extern "C" fn idle_thread() -> ! {
    loop {
        // CRITICAL: Periodically process pending deactivates
        // with_lock acquires scheduler lock internally and calls kernel_exit_epilogue
        scheduler().with_lock(|_| {});

        // Flush any deferred TCB destruction from the current[] slot
        // transition (the only per-CPU persistent deferred slot). Other
        // sched_ref releases (ready queue, pending_enqueue, stale skips)
        // now travel through ephemeral `DeferredReleaseList` stack-local
        // batches that are drained by each scheduler API before it
        // returns, so no separate flush is needed here.
        unsafe {
            scheduler().flush_deferred_current_release();
        }

        // BSP also processes deferred free (only BSP to avoid concurrent manipulation)
        if arch::current_cpu() == 0 {
            crate::mm::process_deferred_free();
        }

        arch::sti();
        arch::halt();
    }
}

/// Bootstrap TCB - represents the thread running kmain
///
/// This TCB is used to capture the execution context of the bootstrap
/// thread (the thread that executes kmain) before the scheduler is
/// fully initialized. It allows the first context switch to properly
/// save the current state.
static mut BOOTSTRAP_TCB: Tcb = Tcb::new();

/// Initialize scheduler
///
/// Creates the idle thread and initializes scheduler structures.
pub fn init() {
    // Initialize bootstrap thread context first
    // This represents the thread currently running kmain
    unsafe {
        crate::task::wait::mark_runnable_locked(&raw mut BOOTSTRAP_TCB);
        BOOTSTRAP_TCB.sched_class = crate::sched::class::SCHED_CLASS_FAIR;
        BOOTSTRAP_TCB.priority = 0;
        BOOTSTRAP_TCB.sched_context = core::ptr::null_mut();
        BOOTSTRAP_TCB.vspace_root = core::ptr::null_mut();
        BOOTSTRAP_TCB.cspace_root = core::ptr::null_mut();
        BOOTSTRAP_TCB.ipc_buffer = 0;
        BOOTSTRAP_TCB.next = core::ptr::null_mut();
        BOOTSTRAP_TCB.cpu_affinity = 0; // Pin bootstrap thread to BSP

        // The bootstrap thread's context will be saved on first context switch
        // We don't need to initialize it here - the context_switch function
        // will save the current register state to BOOTSTRAP_TCB.context
    }

    // Allocate BSP idle TCB
    let idle_tcb = unsafe { allocate_idle_tcb(0) };

    // Initialize idle thread context
    unsafe {
        (*idle_tcb).ensure_trace_id();
        crate::task::wait::mark_runnable_locked(idle_tcb);
        (*idle_tcb).sched_class = crate::sched::class::SCHED_CLASS_IDLE;
        (*idle_tcb).priority = crate::sched::thread::Tcb::encode_idle_priority();
        (*idle_tcb).base_priority = (*idle_tcb).priority;
        (*idle_tcb).sched_context = core::ptr::null_mut();
        (*idle_tcb).vspace_root = core::ptr::null_mut();
        (*idle_tcb).cspace_root = core::ptr::null_mut();
        (*idle_tcb).ipc_buffer = 0;
        (*idle_tcb).next = core::ptr::null_mut();
        (*idle_tcb).cpu_affinity = 0;
        (*idle_tcb).stack_canary = crate::arch::generate_stack_canary();
    }

    // Allocate and set up stack
    let idle_stack = unsafe { allocate_idle_stack() };
    let stack_top = idle_stack + IDLE_STACK_SIZE as u64;

    // Initialize thread context
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            (*idle_tcb).context.rip = idle_thread as *const () as u64;
            (*idle_tcb).context.rsp = stack_top;
            (*idle_tcb).context.rflags = 0x202;
            (*idle_tcb).context.cs = 0x08;
            (*idle_tcb).context.ss = 0x10;
        }
        #[cfg(target_arch = "aarch64")]
        {
            crate::arch::aarch64::context::init_kernel_thread_context(
                &mut (*idle_tcb).context,
                stack_top,
                idle_thread as *const () as u64,
            );
        }
        (*idle_tcb).kernel_stack_top = stack_top;
    }

    // Set bootstrap as current thread (not idle!)
    // The first context switch will save the bootstrap context and switch to idle
    scheduler().set_idle(0, idle_tcb);
    scheduler().set_current(&raw mut BOOTSTRAP_TCB);
    scheduler().online_cpus = 1;
    crate::mm::set_online_cpu_count(1);
}

/// Initialize scheduler for an Application Processor
///
/// Creates a per-CPU idle thread for the given CPU.
/// Called during AP startup after the CPU is online.
pub fn init_cpu(cpu_id: usize) {
    let idle_tcb = unsafe { allocate_idle_tcb(cpu_id) };

    unsafe {
        (*idle_tcb).ensure_trace_id();
        crate::task::wait::mark_runnable_locked(idle_tcb);
        (*idle_tcb).sched_class = crate::sched::class::SCHED_CLASS_IDLE;
        (*idle_tcb).priority = crate::sched::thread::Tcb::encode_idle_priority();
        (*idle_tcb).base_priority = (*idle_tcb).priority;
        (*idle_tcb).sched_context = core::ptr::null_mut();
        (*idle_tcb).vspace_root = core::ptr::null_mut();
        (*idle_tcb).cspace_root = core::ptr::null_mut();
        (*idle_tcb).ipc_buffer = 0;
        (*idle_tcb).next = core::ptr::null_mut();
        (*idle_tcb).cpu_affinity = cpu_id as u32;
        (*idle_tcb).stack_canary = crate::arch::generate_stack_canary();
    }

    let idle_stack = unsafe { allocate_idle_stack() };
    let stack_top = idle_stack + IDLE_STACK_SIZE as u64;

    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            (*idle_tcb).context.rip = idle_thread as *const () as u64;
            (*idle_tcb).context.rsp = stack_top;
            (*idle_tcb).context.rflags = 0x202;
            (*idle_tcb).context.cs = 0x08;
            (*idle_tcb).context.ss = 0x10;
        }
        #[cfg(target_arch = "aarch64")]
        {
            crate::arch::aarch64::context::init_kernel_thread_context(
                &mut (*idle_tcb).context,
                stack_top,
                idle_thread as *const () as u64,
            );
        }
        (*idle_tcb).kernel_stack_top = stack_top;
    }

    scheduler().set_idle(cpu_id, idle_tcb);
    scheduler().set_current(idle_tcb);
    scheduler().online_cpus += 1;
    crate::mm::set_online_cpu_count(scheduler().online_cpus);
}

/// Per-CPU idle TCBs (static, never freed)
static mut IDLE_TCBS: [Tcb; MAX_CPUS] = [const { Tcb::new() }; MAX_CPUS];

/// Allocate TCB for idle thread on a specific CPU
///
/// The idle thread is a special thread that exists for the entire kernel lifetime
/// and is never destroyed, so we use static allocation rather than the slab allocator.
unsafe fn allocate_idle_tcb(cpu_id: usize) -> *mut Tcb {
    unsafe { &raw mut IDLE_TCBS[cpu_id] }
}

/// Allocate stack for idle thread
///
/// Allocates a physical frame and returns its virtual address.
unsafe fn allocate_idle_stack() -> u64 {
    let phys = match pmm_alloc(&FrameOwner::KernelPrivate {
        subkind: KernelMetaKind::KernelStack,
    }) {
        Some(p) => p,
        None => {
            // Halt on allocation failure - no memory available
            loop {
                arch::halt();
            }
        }
    };
    let virt = phys_to_virt(phys);

    // Zero the stack for cleanliness
    unsafe {
        let ptr = virt as *mut u8;
        core::ptr::write_bytes(ptr, 0, PAGE_SIZE);
    }

    virt
}

/// Yield current thread
///
/// Called by a thread to voluntarily give up the CPU.
/// Uses deferred enqueue — the thread is NOT placed in the ready queue
/// until context_switch has saved its registers (prevents SMP race).
/// No global lock needed — yield_current uses only per-CPU scheduler lock.
pub fn yield_now() {
    scheduler().yield_current();
}

/// Get current thread
///
/// Returns a reference to the currently running thread, or None if no thread is running.
pub fn current() -> Option<&'static mut Tcb> {
    unsafe {
        let tcb = scheduler().current();
        if tcb.is_null() { None } else { Some(&mut *tcb) }
    }
}

/// Timer tick handler
///
/// Called by the APIC timer interrupt handler (1ms intervals).
/// Notifies the scheduler of the tick for budget enforcement.
/// Entry/exit hooks account user/kernel runtime precisely at privilege
/// boundaries; the interrupt-mode hint is retained only for the arch-facing
/// timer API shape.
pub fn timer_tick(_interrupted_user_mode: bool) {
    scheduler().timer_tick(_interrupted_user_mode);
}

/// Handle reschedule IPI
///
/// Called by the IPI handler when a reschedule IPI is received.
/// Checks the ready queue for work on this CPU without requiring
/// a sched_context (works correctly for idle threads).
pub fn handle_reschedule_ipi() {
    scheduler().handle_reschedule_ipi();
}

/// Get global scheduler instance
fn scheduler() -> &'static mut scheduler::Scheduler {
    scheduler::scheduler()
}
