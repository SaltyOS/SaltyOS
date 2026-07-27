// SPDX-License-Identifier: GPL-2.0-only
//! x86_64 console hardware — COM1 serial and PS/2 keyboard I/O via IoPort caps.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;

use crate::kbd::KbdState;

// Every hardware cap (COM1 IoPort / IRQ, PS/2 keyboard
// IoPort / IRQ) is resolved at runtime through the matching `ROLE_*`
// getter in `trona_runtime::client::caps` — init's `init_slot_to_role` emits the
// corresponding cap_table entries when the referenced `.cap` units are
// processed, so no slot number is hard-coded here.

// PS/2 controller register ports (absolute I/O port numbers).
const PS2_DATA: u64 = 0x60;
const PS2_STATUS: u64 = 0x64;
const PS2_STATUS_OUTPUT_FULL: u8 = 1;

// COM1 register ports (absolute I/O port numbers).
const COM1_BASE: u64 = 0x3F8;
const COM1_RBR: u64 = COM1_BASE + 0;
const COM1_IER: u64 = COM1_BASE + 1;
const COM1_FCR: u64 = COM1_BASE + 2;
const COM1_LCR: u64 = COM1_BASE + 3;
const COM1_MCR: u64 = COM1_BASE + 4;
const COM1_LSR: u64 = COM1_BASE + 5;
const COM1_DLL: u64 = COM1_BASE + 0;
const COM1_DLH: u64 = COM1_BASE + 1;

// LSR bits
const LSR_DR: u8 = 1 << 0;

static mut KBD: KbdState = KbdState::new();

#[cold]
fn log_ioport_err(op: &[u8], port: u64, err: i32) {
    trona_runtime::uerror!(|_lb| {
        _lb.str(b"[CONSOLE] ioport ");
        _lb.bytes(op);
        _lb.str(b" port=");
        _lb.hex(port);
        _lb.str(b" err=");
        _lb.dec(err as u64);
        _lb.putc(b'\n');
    });
}

#[inline]
fn ioport_read_byte(cap: CapRef, port: u64) -> u8 {
    invoke::ioport_in8(cap, port).unwrap_or_else(|err| {
        log_ioport_err(b"read", port, err);
        0
    })
}

#[inline]
fn ioport_write_byte(cap: CapRef, port: u64, value: u8) {
    if let Err(err) = invoke::ioport_out8(cap, port, value) {
        log_ioport_err(b"write", port, err);
    }
}

/// Initialize COM1 hardware registers via IoPort cap.
pub fn serial_init() {
    let ioport = trona_runtime::client::caps::com1_ioport().cap_ref();
    ioport_write_byte(ioport, COM1_IER, 0x00);
    ioport_write_byte(ioport, COM1_LCR, 0x80);
    ioport_write_byte(ioport, COM1_DLL, 0x01);
    ioport_write_byte(ioport, COM1_DLH, 0x00);
    ioport_write_byte(ioport, COM1_LCR, 0x03);
    ioport_write_byte(ioport, COM1_FCR, 0xC7);
    ioport_write_byte(ioport, COM1_MCR, 0x0B);
    // Enable Received Data Available interrupt
    ioport_write_byte(ioport, COM1_IER, 0x01);
}

/// Set up COM1 + PS/2 hardware. IRQ delivery is pending the console
/// EventQueue/Watch conversion; input is drained opportunistically.
pub fn irq_setup() {
    kbd_init();
    // Clear any unacknowledged IRQ1 from kbd_init responses
    invoke::irq_ack(trona_runtime::client::caps::kbd_irq().cap_ref());
}

/// Bind the COM1 + PS/2 IRQ handlers to the reactor's `EventQueue` so fired
/// interrupts arrive as `EVENT_TYPE_IRQ` records (carrying `cookie`) on the
/// priority interrupt lane, dispatched by the console reactor's `handle_other`.
pub fn bind_input_irqs(eq_cap: u64, cookie: u64) {
    let eq = trona_kernel::core_types::CapRef::flat(eq_cap);
    let _ = invoke::irq_bind_eq(
        trona_runtime::client::caps::com1_irq().cap_ref(),
        eq,
        cookie,
    );
    let _ = invoke::irq_bind_eq(trona_runtime::client::caps::kbd_irq().cap_ref(), eq, cookie);
}

/// Poll COM1 and PS/2, translate scancodes, write bytes into `buf`.
/// Returns the number of bytes written.
pub fn drain_input(buf: &mut [u8]) -> usize {
    let mut count = 0usize;
    let com1 = trona_runtime::client::caps::com1_ioport().cap_ref();
    let kbd = trona_runtime::client::caps::kbd_ioport().cap_ref();

    // COM1 input
    loop {
        let lsr = ioport_read_byte(com1, COM1_LSR);
        if (lsr & LSR_DR) == 0 {
            break;
        }
        let c = ioport_read_byte(com1, COM1_RBR);
        if count < buf.len() {
            buf[count] = c;
            count += 1;
        }
    }

    // PS/2 keyboard input
    loop {
        let status = ioport_read_byte(kbd, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) == 0 {
            break;
        }
        let scancode = ioport_read_byte(kbd, PS2_DATA);
        // SAFETY: We are the sole consumer of KBD state; the console server is
        // single-threaded so there is no data race.
        let key = unsafe { (*&raw mut KBD).translate(scancode) };
        for i in 0..key.len as usize {
            if count < buf.len() {
                buf[count] = key.bytes[i];
                count += 1;
            }
        }
    }

    count
}

/// Acknowledge both COM1 and PS/2 IRQs.
pub fn ack_irqs() {
    invoke::irq_ack(trona_runtime::client::caps::com1_irq().cap_ref());
    invoke::irq_ack(trona_runtime::client::caps::kbd_irq().cap_ref());
}

/// Initialize PS/2 keyboard controller via IoPort capability.
fn kbd_init() {
    let kbd = trona_runtime::client::caps::kbd_ioport().cap_ref();

    // Disable both ports
    ioport_write_byte(kbd, PS2_STATUS, 0xAD);
    ioport_write_byte(kbd, PS2_STATUS, 0xA7);

    // Flush output buffer
    for _ in 0..16 {
        let status = ioport_read_byte(kbd, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) == 0 {
            break;
        }
        let _ = ioport_read_byte(kbd, PS2_DATA);
    }

    // Read controller configuration byte (command 0x20)
    ioport_write_byte(kbd, PS2_STATUS, 0x20);
    for _ in 0..1000 {
        let status = ioport_read_byte(kbd, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) != 0 {
            break;
        }
    }
    let mut config = ioport_read_byte(kbd, PS2_DATA);

    // Enable IRQ1 (bit 0) and scancode translation (bit 6)
    config |= 1;
    config |= 1 << 6;

    // Write configuration back (command 0x60)
    ioport_write_byte(kbd, PS2_STATUS, 0x60);
    ioport_write_byte(kbd, PS2_DATA, config);

    // Enable port 1
    ioport_write_byte(kbd, PS2_STATUS, 0xAE);

    // Reset keyboard (send 0xFF)
    ioport_write_byte(kbd, PS2_DATA, 0xFF);
    for _ in 0..10000 {
        let status = ioport_read_byte(kbd, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) != 0 {
            let byte = ioport_read_byte(kbd, PS2_DATA);
            if byte == 0xAA {
                break;
            }
        }
    }

    // Enable scanning (send 0xF4)
    ioport_write_byte(kbd, PS2_DATA, 0xF4);
    for _ in 0..1000 {
        let status = ioport_read_byte(kbd, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) != 0 {
            let _ = ioport_read_byte(kbd, PS2_DATA);
            break;
        }
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[CONSOLE] PS/2 keyboard initialized\n");
    });
}
