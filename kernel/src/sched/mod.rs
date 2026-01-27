//! Scheduler
//!
//! EDF (Earliest Deadline First) with budget enforcement.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod scheduler;
pub mod thread;

// Re-exports for public API
pub use thread::{SchedContext, Tcb, ThreadContext};

use crate::arch;
use crate::mm::{alloc_frame, phys_to_virt, PAGE_SIZE};

/// Idle thread stack size
const IDLE_STACK_SIZE: usize = PAGE_SIZE;

/// Idle thread function
///
/// The idle thread runs when no other threads are ready.
/// It simply halts the CPU until an interrupt wakes it.
extern "C" fn idle_thread() -> ! {
    loop {
        // Enable interrupts and halt
        // The CPU will wake up on the next interrupt (timer, etc.)
        arch::sti();
        arch::halt();
        // After interrupt, check for work and loop
    }
}

/// Initialize scheduler
///
/// Creates the idle thread and initializes scheduler structures.
pub fn init() {
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
        (*idle_tcb).context.rip = idle_thread as u64;
        (*idle_tcb).context.rsp = stack_top;
        (*idle_tcb).context.rflags = 0x202; // Interrupts enabled
        (*idle_tcb).context.cs = 0x08; // Kernel code segment
        (*idle_tcb).context.ss = 0x10; // Kernel data segment
    }

    // Set as scheduler's idle thread and initial current thread
    scheduler().set_idle(idle_tcb);
    scheduler().set_current(idle_tcb);
}

/// Allocate TCB for idle thread
///
/// For now, we use a static allocation. In the future, this would use
/// the slab allocator or a dedicated TCB allocator.
unsafe fn allocate_idle_tcb() -> *mut Tcb {
    // Static allocation for idle thread TCB
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
                crate::arch::halt();
            }
        }
    };
    let virt = phys_to_virt(phys);

    // Zero the stack for cleanliness
    let ptr = virt as *mut u8;
    core::ptr::write_bytes(ptr, 0, PAGE_SIZE);

    virt
}

/// Yield current thread
///
/// Called by a thread to voluntarily give up the CPU.
/// The thread is placed back in the ready queue and a reschedule is triggered.
pub fn yield_now() {
    unsafe {
        let current = scheduler().current();
        if !current.is_null() && current != scheduler().get_idle() {
            // Put current back in ready queue
            scheduler().enqueue(current);
            // Trigger reschedule
            scheduler().reschedule();
        }
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
