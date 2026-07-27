//! x86_64 architecture support
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub mod acpi;
pub mod ap_boot;
mod apic;
mod boot;
mod context;
mod cpu;
pub mod cpuid;
pub mod fpu;
mod gdt;
mod idt;
pub mod paging;
mod pit;
pub mod random;
pub mod stacktrace;
pub mod uaccess;

pub use apic::{IpiKind, ioapic_mask, ioapic_unmask_level, send_ipi, set_tlb_shootdown_addr};
pub use cpu::{
    MAX_CPUS, current_cpu, current_invoke_seq, diagnostic_current_cpu, generate_stack_canary,
    get_kernel_stack, next_invoke_seq, per_cpu_ready, read_fs_base, set_kernel_stack,
    set_per_cpu_canary, write_abi_tp_base, write_fs_base,
};
pub use gdt::set_tss_rsp0;

use core::sync::atomic::{AtomicBool, Ordering};

unsafe extern "C" {
    fn x86_mod_read_cr0() -> u64;
    fn x86_mod_read_cr2() -> u64;
    fn x86_mod_read_cr4() -> u64;
    fn x86_mod_read_rflags() -> u64;
    fn x86_mod_hlt();
    fn x86_mod_cli();
    fn x86_mod_sti();
    fn x86_mod_outb(port: u16, value: u8);
    fn x86_mod_inb(port: u16) -> u8;
    fn x86_mod_outw(port: u16, value: u16);
    fn x86_mod_inw(port: u16) -> u16;
    fn x86_mod_outl(port: u16, value: u32);
    fn x86_mod_inl(port: u16) -> u32;
    fn x86_mod_rdmsr(msr: u32) -> u64;
    fn x86_mod_wrmsr(msr: u32, value: u64);
    fn x86_mod_ud2() -> !;
}

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

/// Print x86_64 detail for a generic panic without an exception frame.
pub fn dump_panic_detail() {
    use crate::kernel::printk::{serial_dec_raw, serial_hex_raw, serial_putc_hw, serial_puts_raw};

    let cr0 = unsafe { x86_mod_read_cr0() };
    let cr2 = unsafe { x86_mod_read_cr2() };
    let cr3 = paging::read_cr3();
    let cr4 = unsafe { x86_mod_read_cr4() };
    let rflags = unsafe { x86_mod_read_rflags() };

    serial_puts_raw("arch: x86_64 generic\n");
    serial_puts_raw("cpu: ");
    serial_dec_raw(cpu::diagnostic_current_cpu() as u64);
    serial_puts_raw(" per_cpu_ready=");
    serial_dec_raw(cpu::per_cpu_ready() as u64);
    serial_puts_raw(" apic_mode=");
    serial_dec_raw(has_apic() as u64);
    serial_puts_raw(" ticks=");
    serial_dec_raw(get_ticks());
    serial_putc_hw(b'\n');
    serial_puts_raw("CR0: ");
    serial_hex_raw(cr0);
    serial_puts_raw(" CR2: ");
    serial_hex_raw(cr2);
    serial_puts_raw(" CR3: ");
    serial_hex_raw(cr3);
    serial_puts_raw(" CR4: ");
    serial_hex_raw(cr4);
    serial_putc_hw(b'\n');
    serial_puts_raw("RFLAGS: ");
    serial_hex_raw(rflags);
    serial_putc_hw(b'\n');
}

// Re-export architecture-specific implementations for generic arch interface
pub use context::{context_switch, usermode_trampoline};

pub(crate) use stacktrace::capture_current_panic_context;

/// Save interrupt state and disable interrupts.
#[inline(always)]
pub fn save_irq_disable() -> u64 {
    // SAFETY: Reading RFLAGS is side-effect free in kernel context.
    let rflags = unsafe { x86_mod_read_rflags() };
    // SAFETY: Masking IRQs is valid in kernel context.
    unsafe {
        x86_mod_cli();
    }
    rflags
}

/// Restore interrupt state from a value returned by `save_irq_disable()`.
///
/// # Safety
/// `saved` must be a value previously returned by `save_irq_disable()`.
#[inline(always)]
pub unsafe fn restore_irq(saved: u64) {
    if saved & (1 << 9) != 0 {
        // SAFETY: Caller supplied an interrupt-state snapshot from save_irq_disable().
        unsafe {
            x86_mod_sti();
        }
    }
}

/// Return true when maskable IRQs are disabled.
#[inline(always)]
pub fn irqs_disabled() -> bool {
    // SAFETY: Reading RFLAGS is side-effect free in kernel context.
    unsafe { x86_mod_read_rflags() & (1 << 9) == 0 }
}

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
pub fn init(boot_info: Option<&crate::init::bootinfo::ParsedBootInfo>) {
    crate::kernel::printk::kdebug!(arch, |_g| {
        _g.puts("\n[ARCH] init() called\n");
    });

    // Initialize GDT (required before IDT)
    gdt::init();

    // Initialize per-CPU data for BSP
    // MUST be after gdt::init() because reload_segments() clobbers GS base
    cpu::init_bsp();

    crate::kernel::printk::kdebug!(arch, |_g| {
        _g.puts("[ARCH] About to call idt::init()\n");
    });

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
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[ARCH] No APIC, using PIC+PIT fallback\n");
        });
    }

    crate::kernel::printk::kdebug!(arch, |_g| {
        _g.puts("[ARCH] idt::init() returned successfully\n");
    });

    // Detect CPU features (SSE, XSAVE, etc.) — needed by FPU init
    cpuid::init();

    // Configure FPU/SSE hardware on BSP (CR0, CR4, XCR0)
    fpu::init_bsp();

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

    // Phase 2: allocate per-frame tracking arrays now that the direct map
    // covers all physical memory. These arrays can live anywhere in RAM.
    crate::mm::init_per_frame_arrays();

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
pub fn init_smp(boot_info: Option<&crate::init::bootinfo::ParsedBootInfo>) {
    if !has_apic() {
        crate::kernel::printk::serial_puts("[SMP] No APIC available, running single-CPU\n");
        return;
    }

    // Try bootloader-provided RSDP first, then fall back to BIOS scan
    let rsdp_addr = match boot_info {
        Some(info) if info.rsdp_addr != 0 => info.rsdp_addr,
        _ => {
            // Fall back to scanning standard BIOS locations for RSDP
            let scanned = unsafe { acpi::scan_for_rsdp() };
            if scanned == 0 {
                crate::kernel::printk::serial_puts("[SMP] No RSDP found, skipping SMP init\n");
                return;
            }
            scanned
        }
    };

    // Parse ACPI FADT for shutdown support (before MADT — reuses same RSDP)
    unsafe {
        acpi::parse_fadt(rsdp_addr);
    }

    // Parse ACPI MADT
    let madt_info = match unsafe { acpi::parse_madt(rsdp_addr) } {
        Some(info) => info,
        None => {
            crate::kernel::printk::serial_puts("[SMP] MADT parsing failed, running single-CPU\n");
            return;
        }
    };

    // Initialize IOAPIC BEFORE the cpu_count check — even single-CPU systems
    // need IOAPIC for routing external hardware IRQs (keyboard, COM1).
    if madt_info.io_apic_addr != 0 {
        // Find BSP APIC ID from the CPU descriptors
        let mut bsp_apic_id: u8 = 0;
        for i in 0..madt_info.cpu_count {
            if madt_info.cpus[i].is_bsp {
                bsp_apic_id = madt_info.cpus[i].apic_id;
                break;
            }
        }
        apic::init_ioapic(madt_info.io_apic_addr, bsp_apic_id);
    }

    if madt_info.cpu_count <= 1 {
        crate::kernel::printk::serial_puts("[SMP] Only 1 CPU found, no APs to start\n");
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
        x86_mod_hlt();
    }
}

/// Disable interrupts
#[inline(always)]
pub fn cli() {
    // SAFETY: Disabling interrupts is safe in kernel context
    unsafe {
        x86_mod_cli();
    }
}

/// Enable interrupts
#[inline(always)]
pub fn sti() {
    // SAFETY: Enabling interrupts is safe when IDT is set up
    unsafe {
        x86_mod_sti();
    }
}

/// Output byte to port
#[inline(always)]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller ensures port access is valid
    unsafe {
        x86_mod_outb(port, value);
    }
}

/// Input byte from port
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures port access is valid
    unsafe { x86_mod_inb(port) }
}

/// Output 16-bit word to port
#[inline(always)]
pub unsafe fn outw(port: u16, value: u16) {
    // SAFETY: Caller ensures port access is valid
    unsafe {
        x86_mod_outw(port, value);
    }
}

/// Input 16-bit word from port
#[inline(always)]
pub unsafe fn inw(port: u16) -> u16 {
    // SAFETY: Caller ensures port access is valid
    unsafe { x86_mod_inw(port) }
}

/// Output 32-bit dword to port
#[inline(always)]
pub unsafe fn outl(port: u16, value: u32) {
    // SAFETY: Caller ensures port access is valid
    unsafe {
        x86_mod_outl(port, value);
    }
}

/// Input 32-bit dword from port
#[inline(always)]
pub unsafe fn inl(port: u16) -> u32 {
    // SAFETY: Caller ensures port access is valid
    unsafe { x86_mod_inl(port) }
}

/// Perform ACPI S5 shutdown (power off).
///
/// Writes SLP_EN | SLP_TYP to PM1a_CNT_BLK. Falls back to QEMU default
/// port 0x604 if FADT was not parsed.
pub fn shutdown() -> ! {
    let power = acpi::get_power_info();
    let port = if power.valid {
        power.pm1a_cnt_blk
    } else {
        0x604
    };
    // SLP_EN (bit 13) | SLP_TYPa (bits 12:10)
    let val: u16 = (power.slp_typ_s5 << 10) | (1 << 13);

    crate::kernel::printk::serial_puts("[SHUTDOWN] Powering off via ACPI S5\n");
    cli();
    // SAFETY: Writing to PM1a_CNT_BLK with SLP_EN triggers hardware power off.
    unsafe {
        outw(port, val);
    }

    // If PM1b is also present, write to it as well
    if power.pm1b_cnt_blk != 0 {
        unsafe {
            outw(power.pm1b_cnt_blk, val);
        }
    }

    // Should not reach here; loop halt as fallback
    loop {
        halt();
    }
}

/// Trigger a warm reboot via the PCI reset register (port 0xCF9). The
/// 0x0E bit pattern (SYS_RST | RST_CPU) drives a full hardware reset
/// on every chipset that implements the legacy reset I/O — including
/// QEMU's i440fx and q35 fakes. Falls back to `ud2` to force a triple
/// fault if the reset port is somehow unhandled.
pub fn reboot() -> ! {
    crate::kernel::printk::serial_puts("[REBOOT] Triggering reset via PCI reset register\n");
    cli();
    unsafe {
        outb(0xCF9, 0x0E);
    }
    unsafe {
        x86_mod_ud2();
    }
}

/// Allocate IST stacks for critical exceptions (called after mm::init)
///
/// The double fault handler (vector 8) gets its own stack via IST1 so it can
/// run even if the kernel stack is corrupted or overflowed.
fn init_exception_stacks() {
    let stack_phys = crate::mm::pmm_alloc(&crate::mm::frame::FrameOwner::KernelPrivate {
        subkind: crate::mm::frame::KernelMetaKind::KernelStack,
    })
    .expect("IST stack allocation failed");
    let stack_virt = crate::mm::phys_to_virt(stack_phys);
    let stack_top = stack_virt + 4096;

    unsafe {
        gdt::set_tss_ist(1, stack_top);
    }
    idt::set_double_fault_ist(1);

    crate::kernel::printk::kdebug!(arch, |_g| {
        _g.puts("[ARCH] Double fault IST1 stack: ");
        _g.hex(stack_top);
        _g.putc(b'\n');
    });
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
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("\n[SYSCALL] Initializing syscall MSRs\n");
        });

        // Allocate kernel stack for syscall (16KB = 4 contiguous pages of 4KB each)
        const STACK_PAGES: usize = 4;
        const STACK_SIZE: u64 = STACK_PAGES as u64 * 4096;

        let stack_owner = crate::mm::frame::FrameOwner::KernelPrivate {
            subkind: crate::mm::frame::KernelMetaKind::KernelStack,
        };
        let stack_bottom_phys =
            match crate::mm::pmm_alloc_contiguous_owned(STACK_PAGES, &stack_owner) {
                Some(addr) => addr,
                None => {
                    crate::kernel::printk::serial_puts(
                        "[SYSCALL] Failed to allocate contiguous kernel stack!\n",
                    );
                    loop {
                        halt();
                    }
                }
            };
        let stack_top = crate::mm::phys_to_virt(stack_bottom_phys) + STACK_SIZE;

        // Set kernel stack for current CPU (for syscall entry)
        cpu::set_kernel_stack(stack_top);

        // Set TSS rsp0 (for interrupt entry from user mode)
        gdt::set_tss_rsp0(stack_top);

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[SYSCALL] Kernel stack: ");
            _g.hex(stack_top);
            _g.putc(b'\n');
        });

        // STAR MSR format:
        // [63:48] = sysret base selector
        //   sysretq: CS = base+16 | RPL3, SS = base+8 | RPL3
        //   With base=0x10: CS = 0x20|3 = 0x23, SS = 0x18|3 = 0x1B
        // [47:32] = syscall selector
        //   syscall: CS = selector, SS = selector+8
        //   With selector=0x08: CS = 0x08, SS = 0x10
        let star = (0x10u64 << 48) | (0x08u64 << 32);

        // Write IA32_STAR
        x86_mod_wrmsr(0xC0000081u32, star);

        // Write IA32_LSTAR (syscall_entry address)
        let lstar = syscall_entry as *const () as u64;

        x86_mod_wrmsr(0xC0000082u32, lstar);

        // Write IA32_FMASK: clear IF (bit 9) and AC (bit 18) on syscall.
        // IF=0 disables interrupts; AC=0 re-enables SMAP protection so
        // user-set AC cannot bypass SMAP in the kernel syscall path.
        x86_mod_wrmsr(0xC0000084u32, 0x200u64 | 0x40000u64);

        // Enable syscall in IA32_EFER
        let mut efer = x86_mod_rdmsr(0xC0000080u32);
        efer |= 1; // Set SCE (SysCall Enable) bit
        efer |= 1 << 11; // Set NXE (No-Execute Enable) bit

        x86_mod_wrmsr(0xC0000080u32, efer);

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[SYSCALL] MSRs configured successfully\n");
            _g.puts("[SYSCALL]   STAR=");
            _g.hex(star);
            _g.puts("\n[SYSCALL]   LSTAR=");
            _g.hex(lstar);
            _g.putc(b'\n');
        });
    }
}
