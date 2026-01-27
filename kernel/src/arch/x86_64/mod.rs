//! x86_64 architecture support

#![no_std]

pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod syscall;
pub mod tss;

use gdt::Gdt;
use idt::Idt;
use tss::Tss;
use saltyos_ska::{KERNEL_VIRT_BASE, KERNEL_PHYS_BASE, USER_CODE_BASE,
                    USER_STACK_BASE, USER_STACK_SIZE};

/// Initialize x86_64 architecture
pub fn init() {
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
    // Load GDT
    static mut GDT: Gdt = Gdt::new();
    static mut TSS: Tss = Tss::new();
    unsafe {
        crate::print_string("gdt/tss init start\r\n");
        let tss_ptr = &raw mut TSS;
        tss::init_tss(&mut *tss_ptr);
        crate::print_string("tss init done\r\n");
        let gdt_ptr = &raw mut GDT;
        (*gdt_ptr).set_tss(&*tss_ptr);
        crate::print_string("gdt set_tss done\r\n");
        (*gdt_ptr).load_and_set_segments();
        crate::print_string("gdt load+segments done\r\n");
        Gdt::load_tss();
        crate::print_string("tss load done\r\n");
        crate::print_string("gdt/tss init done\r\n");
    }

    // Load IDT
    static mut IDT: Idt = Idt::new();
    unsafe {
        crate::print_string("idt init start\r\n");
        let idt_ptr = &raw mut IDT;
        interrupts::init_idt(&mut *idt_ptr);
        (*idt_ptr).load();
        crate::print_string("idt init done\r\n");
    }

    interrupts::init_pic();
    interrupts::enable_irq(0);
    interrupts::init_pit(100);

    // Initialize syscall support
    crate::print_string("syscall init start\r\n");
    syscall::init();
    crate::print_string("syscall init done\r\n");

    // Allow SSE instructions (memset/memcpy may use XMM regs).
    unsafe {
        enable_sse();
    }

    // TODO: Initialize APIC for IRQ handling

    // Interrupts are enabled later after MM init.
}

pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

/// Enable SSE/SSE2 instruction usage in kernel code.
unsafe fn enable_sse() {
    let mut cr0: u64;
    let mut cr4: u64;
    core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
    // Clear EM/TS, set MP.
    cr0 &= !(1 << 2);
    cr0 &= !(1 << 3);
    cr0 |= 1 << 1;
    core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));

    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
    // OSFXSR | OSXMMEXCPT
    cr4 |= 1 << 9;
    cr4 |= 1 << 10;
    core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
}

/// Enter user mode at the given entry point with the given user stack
#[allow(dead_code)]
pub unsafe fn enter_user_mode(entry: u64, user_stack: u64) -> ! {
    core::arch::asm!(
        "cli",
        "mov ax, 0x1b",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "push 0x1b",
        "push {user_stack}",
        "pushfq",
        "pop rax",
        "or rax, 0x200",
        "push rax",
        "push 0x23",
        "push {entry}",
        "iretq",
        entry = in(reg) entry,
        user_stack = in(reg) user_stack,
        options(noreturn),
    );
}

pub unsafe fn user_stack_top() -> u64 {
    USER_STACK_BASE + USER_STACK_SIZE
}

pub fn user_test_entry_low() -> u64 {
    USER_CODE_BASE
}

pub fn kernel_virt_base() -> u64 {
    KERNEL_VIRT_BASE
}

pub fn kernel_phys_base() -> u64 {
    KERNEL_PHYS_BASE
}

pub fn user_test_entry_raw() -> u64 {
    syscall::user_test_entry_addr()
}
