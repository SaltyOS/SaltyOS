//! x86_64 architecture support
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod apic;
mod boot;
mod context;
mod cpu;
mod gdt;
mod idt;
pub mod paging;
mod pit;

pub use apic::{get_ticks, send_ipi, IpiKind};
pub use cpu::{current_cpu, MAX_CPUS};

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
    // Debug: Print init entry
    unsafe {
        for byte in b"\n[ARCH] init() called\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
    }

    // Initialize GDT (required before IDT)
    gdt::init();

    // Initialize per-CPU data for BSP
    // MUST be after gdt::init() because reload_segments() clobbers GS base
    cpu::init_bsp();

    // Debug: Before IDT init
    unsafe {
        for byte in b"[ARCH] About to call idt::init()\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
    }

    // Initialize IDT BEFORE APIC timer starts
    // This prevents triple fault when timer fires
    idt::init();

    // Disable legacy PIC immediately after IDT is ready
    // Prevents spurious IRQ0 (PIT timer) before APIC is initialized
    apic::disable_8259_pic();

    // Debug: After IDT init
    unsafe {
        for byte in b"[ARCH] idt::init() returned successfully\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
    }

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

    // Initialize PIT (for calibration and fallback)
    pit::init();

    // Initialize APIC (timer is masked, won't fire yet)
    apic::init();
}

/// Start the APIC timer
///
/// Called after scheduler is initialized to begin timer ticks.
/// The timer is configured but masked during init() to prevent
/// interrupts before the scheduler is ready.
pub fn start_timer() {
    apic::start_timer();
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

/// Print a hexadecimal number to serial port
unsafe fn print_hex(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    unsafe {
        for byte in b"0x" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
    }
    if val == 0 {
        unsafe {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, b'0');
        }
        return;
    }
    let mut buf = [0u8; 16];
    let mut pos = 15;
    while val > 0 {
        buf[pos] = HEX_CHARS[(val & 0xF) as usize];
        val >>= 4;
        pos -= 1;
    }
    unsafe {
        for &c in &buf[(pos + 1)..] {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, c);
        }
    }
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

    unsafe {
        for byte in b"[ARCH] Double fault IST1 stack: " {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
        print_hex(stack_top);
        for byte in b"\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
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
        // Debug output
        for byte in b"\n[SYSCALL] Initializing syscall MSRs\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }

        // Allocate kernel stack for syscall (16KB = 4 contiguous pages of 4KB each)
        const STACK_PAGES: usize = 4;
        const STACK_SIZE: u64 = STACK_PAGES as u64 * 4096;

        let stack_bottom_phys = match crate::mm::alloc_contiguous_frames(STACK_PAGES) {
            Some(addr) => addr,
            None => {
                for byte in b"[SYSCALL] Failed to allocate contiguous kernel stack!\n" {
                    while (inb(0x3F8 + 5) & 0x20) == 0 {}
                    outb(0x3F8, *byte);
                }
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

        // Print stack info
        for byte in b"[SYSCALL] Kernel stack: " {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
        print_hex(stack_top);
        for byte in b"\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
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
        efer |= 1;  // Set SCE (SysCall Enable) bit
        
        let efer_low = efer as u32;
        let efer_high = (efer >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("rcx") 0xC0000080u32,
            in("rax") efer_low,
            in("rdx") efer_high,
            options(nostack)
        );

        for byte in b"[SYSCALL] MSRs configured successfully\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
        for byte in b"[SYSCALL]   STAR=" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
        print_hex(star);
        for byte in b"\n[SYSCALL]   LSTAR=" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
        print_hex(lstar);
        for byte in b"\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
    }
}
