//! Scheduler
//!
//! EDF (Earliest Deadline First) with budget enforcement.
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub mod scheduler;
pub mod thread;

// Re-exports for public API
pub use thread::Tcb;

use crate::arch;
use crate::mm::{alloc_frame, phys_to_virt, PAGE_SIZE};

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
        // This structurally guarantees that CPUs receiving IPI will process pending
        scheduler().with_lock(|_| {
            // Empty closure - we just want the side effect of kernel_exit_epilogue()
        });

        // BSP also processes deferred free (only BSP to avoid concurrent manipulation)
        if arch::current_cpu() == 0 {
            crate::mm::process_deferred_free();
        }

        // Enable interrupts and halt
        // The CPU will wake up on the next interrupt (timer, etc.)
        arch::sti();
        arch::halt();
        // After interrupt, check for work and loop
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
        BOOTSTRAP_TCB.state = crate::sched::thread::ThreadState::Running;
        BOOTSTRAP_TCB.priority = 0; // Higher priority than idle
        BOOTSTRAP_TCB.sched_context = core::ptr::null_mut();
        BOOTSTRAP_TCB.vspace = core::ptr::null_mut();
        BOOTSTRAP_TCB.cspace = core::ptr::null_mut();
        BOOTSTRAP_TCB.ipc_buffer = 0;
        BOOTSTRAP_TCB.next = core::ptr::null_mut();

        // The bootstrap thread's context will be saved on first context switch
        // We don't need to initialize it here - the context_switch function
        // will save the current register state to BOOTSTRAP_TCB.context
    }

    // Allocate idle TCB
    let idle_tcb = unsafe { allocate_idle_tcb() };

    // Initialize idle thread context
    unsafe {
        (*idle_tcb).state = crate::sched::thread::ThreadState::Ready;
        (*idle_tcb).priority = u64::MAX; // Lowest priority (infinite deadline)
        (*idle_tcb).sched_context = core::ptr::null_mut(); // No scheduling context
        (*idle_tcb).vspace = core::ptr::null_mut();
        (*idle_tcb).cspace = core::ptr::null_mut();
        (*idle_tcb).ipc_buffer = 0;
        (*idle_tcb).next = core::ptr::null_mut();
    }

    // Allocate and set up stack
    let idle_stack = unsafe { allocate_idle_stack() };
    let stack_top = idle_stack + IDLE_STACK_SIZE as u64;

    // Initialize thread context
    unsafe {
        (*idle_tcb).context.rip = idle_thread as *const () as u64;
        (*idle_tcb).context.rsp = stack_top;
        (*idle_tcb).context.rflags = 0x202; // Interrupts enabled
        (*idle_tcb).context.cs = 0x08; // Kernel code segment
        (*idle_tcb).context.ss = 0x10; // Kernel data segment
    }

    // Set bootstrap as current thread (not idle!)
    // The first context switch will save the bootstrap context and switch to idle
    scheduler().set_idle(idle_tcb);
    scheduler().set_current(&raw mut BOOTSTRAP_TCB);
}

/// Allocate TCB for idle thread
///
/// The idle thread is a special thread that exists for the entire kernel lifetime
/// and is never destroyed, so we use static allocation rather than the slab allocator.
unsafe fn allocate_idle_tcb() -> *mut Tcb {
    static mut IDLE_TCB: Tcb = Tcb::new();
    &raw mut IDLE_TCB
}

/// Allocate stack for idle thread
///
/// Allocates a physical frame and returns its virtual address.
unsafe fn allocate_idle_stack() -> u64 {
    let phys = match alloc_frame() {
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
/// The thread is placed back in the ready queue and a reschedule is triggered.
pub fn yield_now() {
    let current = scheduler().current();
    if !current.is_null() && current != scheduler().get_idle() {
        // Put current back in ready queue
        scheduler().enqueue(current);
        // Trigger reschedule
        scheduler().reschedule();
    }
}

/// Get current thread
///
/// Returns a reference to the currently running thread, or None if no thread is running.
pub fn current() -> Option<&'static mut Tcb> {
    unsafe {
        let tcb = scheduler().current();
        if tcb.is_null() {
            None
        } else {
            Some(&mut *tcb)
        }
    }
}

/// Timer tick handler
///
/// Called by the APIC timer interrupt handler (1ms intervals).
/// Notifies the scheduler of the tick for budget enforcement.
pub fn timer_tick() {
    scheduler().timer_tick();
}

/// Get global scheduler instance
fn scheduler() -> &'static mut scheduler::Scheduler {
    scheduler::scheduler()
}
