//! x86_64 architecture support
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub mod acpi;
mod apic;
pub mod ap_boot;
mod boot;
mod context;
mod cpu;
mod gdt;
mod idt;
pub mod paging;
mod pit;

pub use apic::{send_ipi, set_tlb_shootdown_addr, IpiKind};
pub use cpu::{current_cpu, set_kernel_stack, MAX_CPUS};
pub use gdt::set_tss_rsp0;

use core::sync::atomic::{AtomicBool, Ordering};

/// True = APIC mode, False = PIC+PIT fallback
static APIC_MODE: AtomicBool = AtomicBool::new(false);

/// Check if APIC mode is active
pub fn has_apic() -> bool {
    APIC_MODE.load(Ordering::Relaxed)
}

/// Get tick count from the active timer backend
pub fn get_ticks() -> u64 {
    if has_apic() {
        apic::get_ticks()
    } else {
        pit::get_ticks()
    }
}

/// Get elapsed time in nanoseconds from the active timer backend
pub fn now_ns() -> u64 {
    if has_apic() {
        apic::now_ns()
    } else {
        pit::get_ticks() * 1_000_000
    }
}

// Re-export architecture-specific implementations for generic arch interface
pub use context::{context_switch, usermode_trampoline};

/// Initialize x86_64 architecture
///
/// Critical initialization order:
/// 1. CPU data (BSP)
/// 2. GDT (required for IDT)
/// 3. IDT (must be ready BEFORE any interrupts fire)
/// 4. Memory management (frame allocator, needed by paging)
/// 5. APIC (timer is masked, won't fire yet)
/// 6. PIT (used for APIC timer calibration)
/// 7. Paging (kernel page tables + direct mapping)
///
/// Timer is started later via start_timer() after scheduler is ready.
pub fn init(boot_info: Option<&crate::ParsedBootInfo>) {
    crate::serial_puts("\n[ARCH] init() called\n");

    // Initialize GDT (required before IDT)
    gdt::init();

    // Initialize per-CPU data for BSP
    // MUST be after gdt::init() because reload_segments() clobbers GS base
    cpu::init_bsp();

    crate::serial_puts("[ARCH] About to call idt::init()\n");

    // Initialize IDT BEFORE APIC timer starts
    // This prevents triple fault when timer fires
    idt::init();

    if apic::is_available() {
        APIC_MODE.store(true, Ordering::Release);
        // Disable legacy PIC immediately after IDT is ready
        // Prevents spurious IRQ0 (PIT timer) before APIC is initialized
        apic::disable_8259_pic();
    } else {
        APIC_MODE.store(false, Ordering::Release);
        // Initialize PIC with remapped vectors (IRQ0→vector 32)
        // All IRQs masked; start_timer() will unmask IRQ0
        pit::init_pic_mode();
        crate::serial_puts("[ARCH] No APIC, using PIC+PIT fallback\n");
    }

    crate::serial_puts("[ARCH] idt::init() returned successfully\n");

    // Initialize memory management (frame allocator needed by paging::init())
    if let Some(info) = boot_info {
        crate::mm::init(info);
    }

    // Allocate IST stacks now that frame allocator is ready
    init_exception_stacks();

    // Initialize syscalls (needs frame allocator for kernel stack)
    init_syscalls();

    // Initialize paging (kernel page tables already set up by bootloader)
    paging::init();

    // Switch frame bitmap pointer from identity map to direct physical map.
    // Must happen after paging::init() creates the direct map and before
    // the identity map (PML4[0]) is removed.
    crate::mm::remap_frame_bitmap();

    // Initialize PIT (for calibration and fallback)
    pit::init();

    // Initialize APIC only if available (timer is masked, won't fire yet)
    if has_apic() {
        apic::init();
    }
}

/// Start the timer (APIC or PIC+PIT depending on hardware)
///
/// Called after scheduler is initialized to begin timer ticks.
/// The timer is configured but masked during init() to prevent
/// interrupts before the scheduler is ready.
pub fn start_timer() {
    if has_apic() {
        apic::start_timer();
    } else {
        pit::start_timer();
    }
}

/// Initialize SMP (Symmetric Multi-Processing)
///
/// Parses ACPI MADT to discover APs, then sends INIT+SIPI to start them.
/// Must be called after scheduler is initialized and timer is running.
pub fn init_smp(boot_info: Option<&crate::ParsedBootInfo>) {
    if !has_apic() {
        crate::serial_puts("[SMP] No APIC available, running single-CPU\n");
        return;
    }

    // Try bootloader-provided RSDP first, then fall back to BIOS scan
    let rsdp_addr = match boot_info {
        Some(info) if info.rsdp_addr != 0 => info.rsdp_addr,
        _ => {
            // Fall back to scanning standard BIOS locations for RSDP
            let scanned = unsafe { acpi::scan_for_rsdp() };
            if scanned == 0 {
                crate::serial_puts("[SMP] No RSDP found, skipping SMP init\n");
                return;
            }
            scanned
        }
    };

    // Parse ACPI MADT
    let madt_info = match unsafe { acpi::parse_madt(rsdp_addr) } {
        Some(info) => info,
        None => {
            crate::serial_puts("[SMP] MADT parsing failed, running single-CPU\n");
            return;
        }
    };

    if madt_info.cpu_count <= 1 {
        crate::serial_puts("[SMP] Only 1 CPU found, no APs to start\n");
        return;
    }

    // Start APs
    unsafe {
        apic::start_aps(&madt_info.cpus, madt_info.cpu_count);
    }
}

/// Halt CPU until next interrupt
#[inline(always)]
pub fn halt() {
    // SAFETY: hlt is always safe, just waits for interrupt
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

/// Disable interrupts
#[inline(always)]
pub fn cli() {
    // SAFETY: Disabling interrupts is safe in kernel context
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

/// Enable interrupts
#[inline(always)]
pub fn sti() {
    // SAFETY: Enabling interrupts is safe when IDT is set up
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

/// Output byte to port
#[inline(always)]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller ensures port access is valid
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack)
        );
    }
}

/// Input byte from port
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Caller ensures port access is valid
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack)
        );
    }
    value
}

/// Allocate IST stacks for critical exceptions (called after mm::init)
///
/// The double fault handler (vector 8) gets its own stack via IST1 so it can
/// run even if the kernel stack is corrupted or overflowed.
fn init_exception_stacks() {
    let stack_phys = crate::mm::alloc_frame().expect("IST stack allocation failed");
    let stack_virt = crate::mm::phys_to_virt(stack_phys);
    let stack_top = stack_virt + 4096;

    unsafe {
        gdt::set_tss_ist(1, stack_top);
    }
    idt::set_double_fault_ist(1);

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ARCH] Double fault IST1 stack: ");
        s.hex(stack_top);
        s.putc(b'\n');
    }
}

// External assembly entry point
unsafe extern "C" {
    fn syscall_entry();
}

/// Initialize x86_64 SYSCALL/SYSRET MSRs
///
/// Sets up:
/// - IA32_STAR (0xC0000081): Ring 0/3 CS/SS selectors
/// - IA32_LSTAR (0xC0000082): Kernel entry point RIP
/// - IA32_FMASK (0xC0000084): RFLAGS mask to clear on syscall
/// - IA32_EFER.SCE: Enable syscall
///
/// Also allocates and sets up kernel stacks for syscall handling.
pub fn init_syscalls() {
    unsafe {
        crate::serial_puts("\n[SYSCALL] Initializing syscall MSRs\n");

        // Allocate kernel stack for syscall (16KB = 4 contiguous pages of 4KB each)
        const STACK_PAGES: usize = 4;
        const STACK_SIZE: u64 = STACK_PAGES as u64 * 4096;

        let stack_bottom_phys = match crate::mm::alloc_contiguous_frames(STACK_PAGES) {
            Some(addr) => addr,
            None => {
                crate::serial_puts("[SYSCALL] Failed to allocate contiguous kernel stack!\n");
                loop {
                    core::arch::asm!("hlt");
                }
            }
        };
        let stack_top = crate::mm::phys_to_virt(stack_bottom_phys) + STACK_SIZE;

        // Set kernel stack for current CPU (for syscall entry)
        cpu::set_kernel_stack(stack_top);

        // Set TSS rsp0 (for interrupt entry from user mode)
        gdt::set_tss_rsp0(stack_top);

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[SYSCALL] Kernel stack: ");
            s.hex(stack_top);
            s.putc(b'\n');
        }

        // STAR MSR format:
        // [63:48] = sysret base selector
        //   sysretq: CS = base+16 | RPL3, SS = base+8 | RPL3
        //   With base=0x10: CS = 0x20|3 = 0x23, SS = 0x18|3 = 0x1B
        // [47:32] = syscall selector
        //   syscall: CS = selector, SS = selector+8
        //   With selector=0x08: CS = 0x08, SS = 0x10
        let star = (0x10u64 << 48) | (0x08u64 << 32);
        let star_low = star as u32;
        let star_high = (star >> 32) as u32;

        // Write IA32_STAR
        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000081u32,  // IA32_STAR
            in("rax") star_low,
            in("rdx") star_high,
            options(nostack)
        );

        // Write IA32_LSTAR (syscall_entry address)
        let lstar = syscall_entry as *const () as u64;
        let lstar_low = lstar as u32;
        let lstar_high = (lstar >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000082u32,  // IA32_LSTAR
            in("rax") lstar_low,
            in("rdx") lstar_high,
            options(nostack)
        );

        // Write IA32_FMASK (clear IF on syscall, disable interrupts)
        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000084u32,  // IA32_FMASK
            in("rax") 0x200u32,       // Clear IF flag
            in("rdx") 0u32,
            options(nostack)
        );

        // Enable syscall in IA32_EFER
        let mut efer: u64;
        core::arch::asm!(
            "rdmsr",
            in("rcx") 0xC0000080u32,  // IA32_EFER
            lateout("rax") efer,
            out("rdx") _,
            options(nostack)
        );
        efer |= 1;        // Set SCE (SysCall Enable) bit
        efer |= 1 << 11;  // Set NXE (No-Execute Enable) bit
        
        let efer_low = efer as u32;
        let efer_high = (efer >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000080u32,
            in("rax") efer_low,
            in("rdx") efer_high,
            options(nostack)
        );

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[SYSCALL] MSRs configured successfully\n");
            s.puts("[SYSCALL]   STAR=");
            s.hex(star);
            s.puts("\n[SYSCALL]   LSTAR=");
            s.hex(lstar);
            s.putc(b'\n');
        }
    }
}
