//! AP (Application Processor) Kernel Entry
//!
//! Called from the AP trampoline after the MMU is enabled and the stack is set.
//! Initializes per-CPU structures and enters the scheduler idle loop.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Atomic flags: AP sets to `true` when its initialization is complete.
static AP_READY: [AtomicBool; super::MAX_CPUS] =
    [const { AtomicBool::new(false) }; super::MAX_CPUS];

/// Counter of APs that have successfully booted.
static AP_BOOT_COUNT: AtomicU32 = AtomicU32::new(0);

/// AP entry point called from trampoline assembly.
///
/// This function is called with:
///   - x0 = cpu_id (logical CPU index, passed as PSCI context_id)
///   - SP  = per-CPU kernel stack top
///   - MMU enabled, using BSP's page tables
///   - All exceptions masked (DAIF = 0xF)
///
/// # Safety
/// Called from the AP trampoline assembly with a specific ABI.
#[unsafe(no_mangle)]
pub extern "C" fn ap_entry(cpu_id: usize) -> ! {
    // Install exception vector table FIRST so any fault is caught and
    // reported (without this, the AP silently hangs on any exception).
    super::exceptions::init();

    // Guard: invalid cpu_id (poisoned or out of range).
    if cpu_id >= super::MAX_CPUS {
        loop {
            super::halt();
        }
    }

    // Guard: detect duplicate cpu_id. If another AP already claimed this
    // slot, two APs would share the same kernel stack -> corruption.
    if !super::cpu::try_claim_ap(cpu_id) {
        crate::kernel::printk::serial_puts("[AP] DUPLICATE cpu_id detected, halting\n");
        loop {
            super::halt();
        }
    }

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[AP] Entry cpu_id=");
        _g.dec(cpu_id as u64);
        _g.puts(" EL");
        _g.dec(super::current_el());
        _g.putc(b'\n');
    });

    // 1. Initialize per-CPU data (sets the active host TPIDR for this AP).
    super::cpu::init_ap(cpu_id as u32);

    // 2. Initialize GIC redistributor + CPU interface for this AP.
    super::gic::init_ap(cpu_id);

    // 3. Configure CPACR_EL1.FPEN=0b11 for eager FPU on this AP.
    super::fpu::init();

    // 4. Enable PAN (Privileged Access Never) if supported.
    super::uaccess::init();

    // 5. Allocate a kernel stack for syscall/exception entry and set it
    //    in the per-CPU data.
    {
        const STACK_PAGES: usize = 4;
        const STACK_SIZE: u64 = STACK_PAGES as u64 * 4096;

        let stack_owner = crate::mm::frame::FrameOwner::KernelPrivate {
            subkind: crate::mm::frame::KernelMetaKind::KernelStack,
        };
        let stack_phys = crate::mm::pmm_alloc_contiguous_owned(STACK_PAGES, &stack_owner)
            .expect("[AP] Failed to allocate syscall kernel stack");
        let stack_top = crate::mm::phys_to_virt(stack_phys) + STACK_SIZE;
        super::cpu::set_kernel_stack(stack_top);
    }

    // 6. Initialize per-CPU stack canary.
    super::cpu::init_ap_canary(cpu_id);

    // 7. Start timer on this CPU (enables CNTV + PPI 27).
    super::timer::start();

    // 8. Initialize scheduler for this CPU (creates per-CPU idle thread).
    crate::sched::init_cpu(cpu_id);

    // 10. Emit AP online log before signaling ready to reduce interleaving.
    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[AP] CPU ");
        _g.dec(cpu_id as u64);
        _g.puts(" online\n");
    });

    // 11. Signal BSP that this AP is ready.
    signal_ap_ready(cpu_id);

    // 12. Enable interrupts and enter idle loop.
    super::sti();

    loop {
        // Process pending VSpace deactivates under per-CPU scheduler lock.
        crate::sched::scheduler::scheduler().with_lock(|_| {});

        super::sti();
        super::halt();
    }
}

/// Signal that this AP has completed initialization.
fn signal_ap_ready(cpu_id: usize) {
    AP_READY[cpu_id].store(true, Ordering::Release);
    AP_BOOT_COUNT.fetch_add(1, Ordering::AcqRel);
}

/// Check if an AP has signaled ready (polled by BSP).
pub fn is_ap_ready(cpu_id: usize) -> bool {
    if cpu_id >= super::MAX_CPUS {
        return false;
    }
    AP_READY[cpu_id].load(Ordering::Acquire)
}

/// Clear AP ready flag (called by BSP before starting an AP).
pub fn clear_ap_ready(cpu_id: usize) {
    if cpu_id < super::MAX_CPUS {
        AP_READY[cpu_id].store(false, Ordering::Release);
    }
}

/// Return the number of APs that have successfully booted.
pub fn ap_boot_count() -> u32 {
    AP_BOOT_COUNT.load(Ordering::Acquire)
}
