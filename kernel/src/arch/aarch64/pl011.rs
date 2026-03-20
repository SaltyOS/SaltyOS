//! PL011 UART driver for QEMU virt machine
//!
//! The QEMU virt machine maps PL011 at 0x0900_0000. Since we run in
//! EL1 with identity mapping (or direct physical map) during early boot,
//! we can access it at that physical address. After paging is set up,
//! we use the direct physical map offset.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::ptr;

/// PL011 base address on QEMU virt machine
const PL011_BASE: usize = 0x0900_0000;

/// PL011 register offsets
const UARTDR: usize = 0x000;   // Data Register
const UARTFR: usize = 0x018;   // Flag Register
const UARTCR: usize = 0x030;   // Control Register
const UARTIMSC: usize = 0x038; // Interrupt Mask Set/Clear

/// Flag Register bits
const FR_TXFF: u32 = 1 << 5;   // Transmit FIFO full
const FR_RXFE: u32 = 1 << 4;   // Receive FIFO empty

/// Base address (may be updated after paging init to use direct map)
static mut UART_BASE: usize = PL011_BASE;

/// Read a PL011 register
#[inline(always)]
fn read_reg(offset: usize) -> u32 {
    // SAFETY: PL011 registers are memory-mapped at UART_BASE, which is
    // either the physical address (identity-mapped during early boot) or
    // the direct physical map address (after paging init).
    unsafe {
        let base = core::ptr::addr_of!(UART_BASE).read_volatile();
        ptr::read_volatile((base + offset) as *const u32)
    }
}

/// Write a PL011 register
#[inline(always)]
fn write_reg(offset: usize, value: u32) {
    // SAFETY: PL011 registers are memory-mapped at UART_BASE, which is
    // either the physical address (identity-mapped during early boot) or
    // the direct physical map address (after paging init).
    unsafe {
        let base = core::ptr::addr_of!(UART_BASE).read_volatile();
        ptr::write_volatile((base + offset) as *mut u32, value)
    }
}

/// Initialize the PL011 UART
pub fn init() {
    // Enable UART: set UARTEN bit in CR
    write_reg(UARTCR, 0x0301); // TXE | RXE | UARTEN
    // Mask all interrupts for now
    write_reg(UARTIMSC, 0);
}

/// Update UART base address for direct physical map
pub fn set_base(new_base: usize) {
    // SAFETY: Called once during paging init, single-threaded at that point
    unsafe { core::ptr::addr_of_mut!(UART_BASE).write_volatile(new_base); }
}

/// Write a single byte to the UART
pub fn putc(c: u8) {
    // Wait for transmit FIFO to have space
    while (read_reg(UARTFR) & FR_TXFF) != 0 {
        core::hint::spin_loop();
    }
    write_reg(UARTDR, c as u32);
}

/// Read a single byte from the UART (non-blocking)
pub fn getc() -> Option<u8> {
    if (read_reg(UARTFR) & FR_RXFE) != 0 {
        return None;
    }
    Some((read_reg(UARTDR) & 0xFF) as u8)
}
