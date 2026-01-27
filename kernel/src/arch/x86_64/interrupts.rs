//! x86_64 interrupt handlers

#![no_std]

use crate::arch::x86_64::idt::{InterruptFrame, Idt};
use core::sync::atomic::{AtomicU64, Ordering};

// Interrupt type attributes
const TYPE_INTERRUPT_GATE: u8 = 0x8E;  // Present, DPL=0, Interrupt gate
const TYPE_TRAP_GATE: u8 = 0x8F;       // Present, DPL=0, Trap gate

// External assembly interrupt handlers
unsafe extern "C" {
    fn interrupt_handler_0();
    fn interrupt_handler_1();
    fn interrupt_handler_2();
    fn interrupt_handler_3();
    fn interrupt_handler_4();
    fn interrupt_handler_5();
    fn interrupt_handler_6();
    fn interrupt_handler_7();
    fn interrupt_handler_8();
    fn interrupt_handler_9();
    fn interrupt_handler_10();
    fn interrupt_handler_11();
    fn interrupt_handler_12();
    fn interrupt_handler_13();
    fn interrupt_handler_14();
    fn interrupt_handler_15();
    fn interrupt_handler_16();
    fn interrupt_handler_17();
    fn interrupt_handler_18();
    fn interrupt_handler_19();
    fn interrupt_handler_20();
    fn interrupt_handler_21();
    fn interrupt_handler_22();
    fn interrupt_handler_23();
    fn interrupt_handler_24();
    fn interrupt_handler_25();
    fn interrupt_handler_26();
    fn interrupt_handler_27();
    fn interrupt_handler_28();
    fn interrupt_handler_29();
    fn interrupt_handler_30();
    fn interrupt_handler_31();
    fn interrupt_handler_32();
    fn interrupt_handler_33();
    fn interrupt_handler_34();
    fn interrupt_handler_35();
    fn interrupt_handler_36();
    fn interrupt_handler_37();
    fn interrupt_handler_38();
    fn interrupt_handler_39();
    fn interrupt_handler_40();
    fn interrupt_handler_41();
    fn interrupt_handler_42();
    fn interrupt_handler_43();
    fn interrupt_handler_44();
    fn interrupt_handler_45();
    fn interrupt_handler_46();
    fn interrupt_handler_47();
}

/// Initialize the IDT with interrupt handlers
pub fn init_idt(idt: &mut Idt) {
    unsafe {
        // Exception handlers (0-31)
        set_handler(idt, 0, interrupt_handler_0 as u64);
        set_handler(idt, 1, interrupt_handler_1 as u64);
        set_handler(idt, 2, interrupt_handler_2 as u64);
        set_handler(idt, 3, interrupt_handler_3 as u64);
        set_handler(idt, 4, interrupt_handler_4 as u64);
        set_handler(idt, 5, interrupt_handler_5 as u64);
        set_handler(idt, 6, interrupt_handler_6 as u64);
        set_handler(idt, 7, interrupt_handler_7 as u64);
        set_handler_with_ist(idt, 8, interrupt_handler_8 as u64, 1);
        set_handler(idt, 9, interrupt_handler_9 as u64);
        set_handler(idt, 10, interrupt_handler_10 as u64);
        set_handler(idt, 11, interrupt_handler_11 as u64);
        set_handler(idt, 12, interrupt_handler_12 as u64);
        set_handler(idt, 13, interrupt_handler_13 as u64);
        set_handler(idt, 14, interrupt_handler_14 as u64);
        set_handler(idt, 15, interrupt_handler_15 as u64);
        set_handler(idt, 16, interrupt_handler_16 as u64);
        set_handler(idt, 17, interrupt_handler_17 as u64);
        set_handler(idt, 18, interrupt_handler_18 as u64);
        set_handler(idt, 19, interrupt_handler_19 as u64);
        set_handler(idt, 20, interrupt_handler_20 as u64);
        set_handler(idt, 21, interrupt_handler_21 as u64);
        set_handler(idt, 22, interrupt_handler_22 as u64);
        set_handler(idt, 23, interrupt_handler_23 as u64);
        set_handler(idt, 24, interrupt_handler_24 as u64);
        set_handler(idt, 25, interrupt_handler_25 as u64);
        set_handler(idt, 26, interrupt_handler_26 as u64);
        set_handler(idt, 27, interrupt_handler_27 as u64);
        set_handler(idt, 28, interrupt_handler_28 as u64);
        set_handler(idt, 29, interrupt_handler_29 as u64);
        set_handler(idt, 30, interrupt_handler_30 as u64);
        set_handler(idt, 31, interrupt_handler_31 as u64);

        // PIC IRQs (32-47) use IST1 to avoid clobbering kernel/user stacks
        set_handler_with_ist(idt, 32, interrupt_handler_32 as u64, 1);
        set_handler_with_ist(idt, 33, interrupt_handler_33 as u64, 1);
        set_handler_with_ist(idt, 34, interrupt_handler_34 as u64, 1);
        set_handler_with_ist(idt, 35, interrupt_handler_35 as u64, 1);
        set_handler_with_ist(idt, 36, interrupt_handler_36 as u64, 1);
        set_handler_with_ist(idt, 37, interrupt_handler_37 as u64, 1);
        set_handler_with_ist(idt, 38, interrupt_handler_38 as u64, 1);
        set_handler_with_ist(idt, 39, interrupt_handler_39 as u64, 1);
        set_handler_with_ist(idt, 40, interrupt_handler_40 as u64, 1);
        set_handler_with_ist(idt, 41, interrupt_handler_41 as u64, 1);
        set_handler_with_ist(idt, 42, interrupt_handler_42 as u64, 1);
        set_handler_with_ist(idt, 43, interrupt_handler_43 as u64, 1);
        set_handler_with_ist(idt, 44, interrupt_handler_44 as u64, 1);
        set_handler_with_ist(idt, 45, interrupt_handler_45 as u64, 1);
        set_handler_with_ist(idt, 46, interrupt_handler_46 as u64, 1);
        set_handler_with_ist(idt, 47, interrupt_handler_47 as u64, 1);
    }
}

unsafe fn set_handler(idt: &mut Idt, index: usize, handler: u64) {
    idt.entries[index].set_handler(handler, 0x08, TYPE_INTERRUPT_GATE);
}

unsafe fn set_handler_with_ist(idt: &mut Idt, index: usize, handler: u64, ist: u8) {
    idt.entries[index].set_handler_with_ist(handler, 0x08, TYPE_INTERRUPT_GATE, ist);
}

// Rust handler functions called from assembly

#[unsafe(no_mangle)]
pub extern "C" fn handle_divide_error(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** DIVIDE ERROR ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_debug(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** DEBUG EXCEPTION ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_nmi(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** NMI ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_breakpoint(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** BREAKPOINT ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_overflow(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** OVERFLOW ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_bound_range_exceeded(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** BOUND RANGE EXCEEDED ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_invalid_opcode(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** INVALID OPCODE ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_device_not_available(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** DEVICE NOT AVAILABLE ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_double_fault(frame: &InterruptFrame) {
    serial_print_str("\r\n*** DOUBLE FAULT ***\r\n");
    serial_print_str("Error code: ");
    serial_print_number(frame.error_code);
    serial_print_str("\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_invalid_tss(frame: &InterruptFrame) {
    serial_print_str("\r\n*** INVALID TSS ***\r\n");
    serial_print_str("Error code: ");
    serial_print_number(frame.error_code);
    serial_print_str("\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_segment_not_present(frame: &InterruptFrame) {
    serial_print_str("\r\n*** SEGMENT NOT PRESENT ***\r\n");
    serial_print_str("Error code: ");
    serial_print_number(frame.error_code);
    serial_print_str("\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_stack_segment_fault(frame: &InterruptFrame) {
    serial_print_str("\r\n*** STACK SEGMENT FAULT ***\r\n");
    serial_print_str("Error code: ");
    serial_print_number(frame.error_code);
    serial_print_str("\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_general_protection_fault(frame: &InterruptFrame) {
    serial_print_str("\r\n*** GENERAL PROTECTION FAULT ***\r\n");
    serial_print_str("Error code: ");
    serial_print_number(frame.error_code);
    serial_print_str("\r\n");
    serial_print_str("RIP: ");
    serial_print_hex(frame.instruction_pointer);
    serial_print_str("\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_page_fault(frame: &InterruptFrame) {
    let cr2 = read_cr2();
    let fault_addr = crate::mm::VirtAddr::new(cr2);

    unsafe {
        match crate::mm::handle_page_fault(fault_addr, frame.error_code) {
            Ok(_) => {
                // Page fault resolved successfully
                return;
            }
            Err(_) => {
                // Page fault failed - halt
                serial_print_str("\r\n*** PAGE FAULT (FAILED) ***\r\n");
                serial_print_str("Error code: ");
                serial_print_number(frame.error_code);
                serial_print_str("\r\n");
                serial_print_str("CR2: ");
                serial_print_hex(cr2);
                serial_print_str("\r\n");
                loop { core::arch::asm!("hlt"); }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_x87_fpu_error(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** X87 FPU ERROR ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_alignment_check(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** ALIGNMENT CHECK ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_machine_check(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** MACHINE CHECK ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_simd_floating_point(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** SIMD FLOATING POINT ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_virtualization(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** VIRTUALIZATION EXCEPTION ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_security(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** SECURITY EXCEPTION ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_unknown(_frame: &InterruptFrame) {
    serial_print_str("\r\n*** UNKNOWN EXCEPTION ***\r\n");
    loop { unsafe { core::arch::asm!("hlt"); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_irq(frame: &InterruptFrame) {
    let vector = frame.vector;
    if vector >= 32 && vector < 48 {
        let irq = (vector - 32) as u8;
        if irq == 0 {
            IRQ0_TICKS.fetch_add(1, Ordering::Relaxed);
        }
        pic_send_eoi(irq);
    }
}

pub fn init_pic() {
    unsafe {
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        outb(PIC1_CMD, 0x11);
        outb(PIC2_CMD, 0x11);

        outb(PIC1_DATA, 0x20);
        outb(PIC2_DATA, 0x28);

        outb(PIC1_DATA, 0x04);
        outb(PIC2_DATA, 0x02);

        outb(PIC1_DATA, 0x01);
        outb(PIC2_DATA, 0x01);

        outb(PIC1_DATA, mask1);
        outb(PIC2_DATA, mask2);
    }
}

pub fn init_pit(hz: u32) {
    let freq = if hz == 0 { 100 } else { hz };
    let divisor = (PIT_BASE_FREQUENCY / freq).max(1).min(0xffff);
    unsafe {
        outb(PIT_CMD, 0x36);
        outb(PIT_CH0, (divisor & 0xff) as u8);
        outb(PIT_CH0, (divisor >> 8) as u8);
    }
}

pub fn enable_irq(irq: u8) {
    unsafe {
        if irq < 8 {
            let mask = inb(PIC1_DATA) & !(1 << irq);
            outb(PIC1_DATA, mask);
        } else {
            let mask = inb(PIC2_DATA) & !(1 << (irq - 8));
            outb(PIC2_DATA, mask);
        }
    }
}

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;
const PIT_CMD: u16 = 0x43;
const PIT_CH0: u16 = 0x40;
const PIT_BASE_FREQUENCY: u32 = 1_193_182;
static IRQ0_TICKS: AtomicU64 = AtomicU64::new(0);

fn pic_send_eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, 0x20);
        }
        outb(PIC1_CMD, 0x20);
    }
}

fn read_cr2() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) val, options(nostack, preserves_flags));
    }
    val
}

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack));
    val
}

const COM1_PORT: u16 = 0x3f8;

fn serial_print_str(s: &str) {
    for byte in s.bytes() {
        serial_write(byte);
    }
}

fn serial_print_number(mut n: u64) {
    if n == 0 {
        serial_write(b'0');
        return;
    }

    let mut buffer = [0u8; 20];
    let mut i = 0;

    while n > 0 {
        buffer[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    while i > 0 {
        serial_write(buffer[i - 1]);
        i -= 1;
    }
}

fn serial_print_hex(mut n: u64) {
    serial_print_str("0x");

    let mut buffer = [0u8; 16];
    let mut i = 0;

    if n == 0 {
        serial_write(b'0');
        return;
    }

    while n > 0 {
        let digit = (n & 0xf) as u8;
        buffer[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        n >>= 4;
        i += 1;
    }

    while i > 0 {
        serial_write(buffer[i - 1]);
        i -= 1;
    }
}

fn serial_write(byte: u8) {
    unsafe {
        while (inb(COM1_PORT + 5) & 0x20) == 0 {}
        outb(COM1_PORT, byte);
    }
}
