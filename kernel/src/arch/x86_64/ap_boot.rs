//! AP (Application Processor) Kernel Entry
//!
//! Called from the AP trampoline after transitioning to 64-bit long mode.
//! Initializes per-CPU structures and enters the scheduler idle loop.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// AP entry point called from trampoline assembly
///
/// This function is called with:
///   - RDI = cpu_id (logical CPU index)
///   - RSP = per-CPU kernel stack top
///   - Long mode enabled, paging active (using BSP's PML4)
///   - Interrupts disabled
///
/// # Safety
/// Called from assembly trampoline with a specific ABI.
#[unsafe(no_mangle)]
pub extern "C" fn ap_entry(cpu_id: usize) -> ! {
    // Guard: poisoned CPU_ID (0xFFFF_FFFF) means this AP arrived after BSP
    // gave up waiting. Halt permanently to prevent using stale trampoline params.
    if cpu_id >= super::cpu::MAX_CPUS {
        loop {
            unsafe {
                core::arch::asm!("hlt", options(nomem, nostack));
            }
        }
    }

    // Guard: detect duplicate cpu_id. If another AP already claimed this slot,
    // two APs would share the same kernel stack → immediate corruption.
    if !super::apic::try_claim_ap(cpu_id) {
        crate::serial_puts("[AP] DUPLICATE cpu_id detected, halting\n");
        loop {
            unsafe {
                core::arch::asm!("hlt", options(nomem, nostack));
            }
        }
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[AP] Entry cpu_id=");
        s.dec(cpu_id as u64);
        s.putc(b'\n');
    }

    // 1. Seed per-CPU metadata for this AP
    unsafe {
        let per_cpu = super::cpu::per_cpu_mut(cpu_id as u32);
        per_cpu.cpu_id = cpu_id as u32;
    }

    // 2. Load per-CPU GDT and TSS
    unsafe {
        super::gdt::load_per_cpu(cpu_id);
    }
    crate::serial_puts("[AP] GDT/TSS loaded\n");

    // 3. Re-install GS base after segment reload in load_per_cpu()
    super::cpu::write_gs_base_for_cpu(cpu_id);

    // 4. Load IDT (shared with BSP - IDT is global)
    super::idt::load();
    crate::serial_puts("[AP] IDT loaded\n");

    // 4.5 Register this AP's CPUID features into the global intersection.
    // Must run before feature-dependent init (APIC/FPU).
    super::cpuid::register_ap(cpu_id);

    // 5. Initialize SYSCALL MSRs for this CPU
    init_ap_syscalls(cpu_id);
    crate::serial_puts("[AP] SYSCALL MSRs configured\n");

    // 6. Initialize Local APIC for this AP (timer + SVR)
    super::apic::init_ap();
    crate::serial_puts("[AP] Local APIC initialized\n");

    // 6.5. Initialize FPU/SSE hardware on this AP
    super::fpu::init_ap();

    // 6.6. Initialize per-CPU stack canary
    super::cpu::init_ap_canary(cpu_id);

    // 7. Allocate IST stack for double fault on this CPU
    init_ap_exception_stacks(cpu_id);
    crate::serial_puts("[AP] IST stacks allocated\n");

    // 8. Initialize scheduler for this CPU (creates idle thread)
    crate::sched::init_cpu(cpu_id);
    crate::serial_puts("[AP] Scheduler initialized\n");

    // 9. Emit AP online log before signaling ready to reduce serial interleaving
    {
        let s = crate::SerialGuard::acquire();
        s.puts("[AP] CPU ");
        s.dec(cpu_id as u64);
        s.puts(" online\n");
    }

    // 10. Signal that this AP is ready
    super::apic::signal_ap_ready(cpu_id);

    // 11. Enable interrupts and enter idle loop
    super::sti();

    loop {
        // Process pending deactivates under per-CPU scheduler lock
        crate::sched::scheduler::scheduler().with_lock(|_| {});

        super::sti();
        super::halt();
    }
}

/// Initialize SYSCALL/SYSRET MSRs for an AP
fn init_ap_syscalls(cpu_id: usize) {
    unsafe {
        // Allocate kernel stack for syscall (16KB = 4 pages)
        const STACK_PAGES: usize = 4;
        const STACK_SIZE: u64 = STACK_PAGES as u64 * 4096;

        let stack_phys = crate::mm::alloc_contiguous_frames(STACK_PAGES)
            .expect("[AP] Failed to allocate syscall kernel stack");
        let stack_top = crate::mm::phys_to_virt(stack_phys) + STACK_SIZE;

        // Set kernel stack slot directly for this CPU
        let per_cpu = super::cpu::per_cpu_mut(cpu_id as u32);
        per_cpu.kernel_stack = stack_top;

        // Set TSS rsp0 (for interrupt entry from user mode)
        super::gdt::set_tss_rsp0_cpu(cpu_id, stack_top);

        // STAR MSR: same layout as BSP
        let star = (0x10u64 << 48) | (0x08u64 << 32);
        let star_low = star as u32;
        let star_high = (star >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000081u32,
            in("rax") star_low,
            in("rdx") star_high,
            options(nostack)
        );

        // LSTAR: syscall entry point (same as BSP)
        unsafe extern "C" { fn syscall_entry(); }
        let lstar = syscall_entry as *const () as u64;
        let lstar_low = lstar as u32;
        let lstar_high = (lstar >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000082u32,
            in("rax") lstar_low,
            in("rdx") lstar_high,
            options(nostack)
        );

        // FMASK: clear IF on syscall
        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000084u32,
            in("rax") 0x200u32,
            in("rdx") 0u32,
            options(nostack)
        );

        // Enable SCE + NXE in EFER
        let mut efer: u64;
        core::arch::asm!(
            "rdmsr",
            in("rcx") 0xC0000080u32,
            lateout("rax") efer,
            out("rdx") _,
            options(nostack)
        );
        efer |= 1;        // SCE
        efer |= 1 << 11;  // NXE
        let efer_low = efer as u32;
        let efer_high = (efer >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000080u32,
            in("rax") efer_low,
            in("rdx") efer_high,
            options(nostack)
        );
    }
}

/// Allocate IST stacks for critical exceptions on this AP
fn init_ap_exception_stacks(cpu_id: usize) {
    let stack_phys = crate::mm::alloc_frame().expect("[AP] IST stack allocation failed");
    let stack_virt = crate::mm::phys_to_virt(stack_phys);
    let stack_top = stack_virt + 4096;

    unsafe {
        super::gdt::set_tss_ist_cpu(cpu_id, 1, stack_top);
    }
}
