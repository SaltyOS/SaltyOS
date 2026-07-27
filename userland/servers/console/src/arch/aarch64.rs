// SPDX-License-Identifier: GPL-2.0-only
//! aarch64 console hardware — PL011 UART I/O via device untyped + MMIO.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_kernel::uapi::*;

// Virtual address where PL011 registers are mapped.
// Keep this well above the low-ASLR ELF/rtld/shared-lib window.
const UART_MMIO_VADDR: u64 = 0x0000_0000_3000_0000;

// PL011 register offsets
const UARTDR: usize = 0x000;
const UARTFR: usize = 0x018;
const UARTIMSC: usize = 0x038;
const UARTICR: usize = 0x044;

// UARTFR bits
const UARTFR_RXFE: u32 = 1 << 4; // RX FIFO empty

static mut UART_BASE: *mut u8 = core::ptr::null_mut();
static mut UART_READY: bool = false;

/// Read a 32-bit register at the given offset from the UART MMIO base.
///
/// # Safety
///
/// `UART_BASE` must have been initialized to a valid mapped address by
/// `serial_init()` before calling this function.
unsafe fn mmio_read32(offset: usize) -> u32 {
    // SAFETY: UART_BASE is set by serial_init() to a valid device-mapped address,
    // and offset is within the PL011 register space. Volatile read is required
    // for MMIO.
    unsafe {
        let base = *&raw const UART_BASE;
        core::ptr::read_volatile(base.add(offset) as *const u32)
    }
}

/// Write a 32-bit value to a register at the given offset from the UART MMIO base.
///
/// # Safety
///
/// `UART_BASE` must have been initialized to a valid mapped address by
/// `serial_init()` before calling this function.
unsafe fn mmio_write32(offset: usize, val: u32) {
    // SAFETY: UART_BASE is set by serial_init() to a valid device-mapped address,
    // and offset is within the PL011 register space. Volatile write is required
    // for MMIO.
    unsafe {
        let base = *&raw const UART_BASE;
        core::ptr::write_volatile(base.add(offset) as *mut u32, val);
    }
}

/// Map the PL011 UART device untyped into our VSpace and store the base address.
pub fn serial_init() {
    let flags = KERNITE_PAGE_FLAG_WRITABLE | KERNITE_PAGE_FLAG_USER | KERNITE_PAGE_FLAG_NOCACHE;
    let err = invoke::vspace_map_device(
        CapRef::flat(KERNITE_CAP_SELF_VSPACE as u64),
        trona_runtime::client::caps::com1_ioport().cap_ref(),
        0,
        UART_MMIO_VADDR,
        flags,
    );
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[CONSOLE] FAIL: PL011 device map failed err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        unsafe {
            *&raw mut UART_READY = false;
            *&raw mut UART_BASE = core::ptr::null_mut();
        }
        return;
    }

    // SAFETY: We are storing a valid mapped virtual address. This is the only
    // write to UART_BASE and occurs before any MMIO access.
    unsafe {
        *&raw mut UART_BASE = UART_MMIO_VADDR as *mut u8;
        *&raw mut UART_READY = true;
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[CONSOLE] PL011 UART mapped\n");
    });
}

/// Set up UART hardware. IRQ delivery is pending the console
/// EventQueue/Watch conversion; input is drained opportunistically.
pub fn irq_setup() {
    // If MMIO mapping is unavailable, keep the service alive in output-only mode.
    unsafe {
        if !*(&raw const UART_READY) {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[CONSOLE] UART input disabled\n");
            });
            return;
        }
    }

    // Enable RX interrupt (RXIM = bit 4) and receive timeout (RTIM = bit 6).
    // RTIM fires when the RX FIFO has data below the trigger level after a
    // timeout (~32 bit periods), ensuring single-character input is delivered
    // promptly even when the FIFO trigger threshold is > 1.
    // SAFETY: UART_BASE is initialized by serial_init() which must be called first.
    unsafe {
        let imsc = mmio_read32(UARTIMSC);
        mmio_write32(UARTIMSC, imsc | (1 << 4) | (1 << 6));
    }

    // Prime IRQ delivery: the first ack enables INTID 33 in the GIC
    // distributor. Without this, the GIC blocks the PL011 interrupt
    // and the console never receives input notifications.
    invoke::irq_ack(trona_runtime::client::caps::com1_irq().cap_ref());
}

/// Bind the PL011 (COM1) IRQ handler to the reactor's `EventQueue` so fired
/// interrupts arrive as `EVENT_TYPE_IRQ` records (carrying `cookie`) on the
/// priority interrupt lane. No-op when UART input is unavailable.
pub fn bind_input_irqs(eq_cap: u64, cookie: u64) {
    unsafe {
        if !*(&raw const UART_READY) {
            return;
        }
    }
    let eq = trona_kernel::core_types::CapRef::flat(eq_cap);
    let _ = invoke::irq_bind_eq(
        trona_runtime::client::caps::com1_irq().cap_ref(),
        eq,
        cookie,
    );
}

/// Drain PL011 RX FIFO into `buf`. Returns the number of bytes read.
pub fn drain_input(buf: &mut [u8]) -> usize {
    let mut count = 0usize;

    unsafe {
        if !*(&raw const UART_READY) {
            return 0;
        }
    }

    // SAFETY: UART_BASE is initialized by serial_init() which is called before
    // the main loop. All accesses are volatile MMIO reads within the mapped region.
    unsafe {
        loop {
            let fr = mmio_read32(UARTFR);
            if (fr & UARTFR_RXFE) != 0 {
                break;
            }
            let dr = mmio_read32(UARTDR) as u8;
            if count < buf.len() {
                buf[count] = dr;
                count += 1;
            }
        }
    }

    count
}

/// Clear PL011 interrupts and acknowledge the IRQ handler.
pub fn ack_irqs() {
    unsafe {
        if !*(&raw const UART_READY) {
            return;
        }
    }

    // SAFETY: UART_BASE is initialized by serial_init(). Writing 0x7FF to UARTICR
    // clears all interrupt flags in the PL011.
    unsafe {
        mmio_write32(UARTICR, 0x7FF);
    }
    invoke::irq_ack(trona_runtime::client::caps::com1_irq().cap_ref());
}
