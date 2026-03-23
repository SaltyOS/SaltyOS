// SPDX-License-Identifier: GPL-2.0-only
//! x86_64 console hardware — COM1 serial and PS/2 keyboard I/O via IoPort caps.

use besalt::invoke;
use besalt::serial;

use crate::kbd::KbdState;

// Cap layout (set up by init for the console server)
const CAP_SELF_TCB: u64 = 0;
const CAP_IOPORT: u64 = 64;     // COM1 IoPort (CopyCap 8:64)
const CAP_IRQ: u64 = 65;        // COM1 IRQ handler (CopyCap 9:65)
const CAP_NTFN: u64 = 66;       // COM1+PS/2 IRQ notification (CopyCap 10:66)
const CAP_KBD_IOPORT: u64 = 69; // PS/2 Keyboard IoPort (CopyCap 6:69)
const CAP_KBD_IRQ: u64 = 70;    // PS/2 Keyboard IRQ handler (CopyCap 7:70)

// PS/2 controller register offsets (relative to base port 0x60)
const PS2_DATA: u64 = 0;    // offset 0 = port 0x60
const PS2_STATUS: u64 = 4;  // offset 4 = port 0x64
const PS2_STATUS_OUTPUT_FULL: u8 = 1;

// COM1 register offsets
const COM1_RBR: u64 = 0;
const COM1_IER: u64 = 1;
const COM1_FCR: u64 = 2;
const COM1_LCR: u64 = 3;
const COM1_MCR: u64 = 4;
const COM1_LSR: u64 = 5;
const COM1_DLL: u64 = 0;
const COM1_DLH: u64 = 1;

// LSR bits
const LSR_DR: u8 = 1 << 0;

static mut KBD: KbdState = KbdState::new();

/// Initialize COM1 hardware registers via IoPort cap.
pub fn serial_init() {
    invoke::ioport_out8(CAP_IOPORT, COM1_IER, 0x00);
    invoke::ioport_out8(CAP_IOPORT, COM1_LCR, 0x80);
    invoke::ioport_out8(CAP_IOPORT, COM1_DLL, 0x01);
    invoke::ioport_out8(CAP_IOPORT, COM1_DLH, 0x00);
    invoke::ioport_out8(CAP_IOPORT, COM1_LCR, 0x03);
    invoke::ioport_out8(CAP_IOPORT, COM1_FCR, 0xC7);
    invoke::ioport_out8(CAP_IOPORT, COM1_MCR, 0x0B);
    // Enable Received Data Available interrupt
    invoke::ioport_out8(CAP_IOPORT, COM1_IER, 0x01);
}

/// Set up COM1 + PS/2 IRQ notifications and initialize keyboard.
pub fn irq_setup() {
    // Set up COM1 IRQ notification
    invoke::irq_handler_set_notification(CAP_IRQ, CAP_NTFN);

    // Set up PS/2 keyboard notification BEFORE init — kbd_init() generates
    // IRQ1 from keyboard ACK/self-test responses
    invoke::irq_handler_set_notification(CAP_KBD_IRQ, CAP_NTFN);
    kbd_init();
    // Clear any unacknowledged IRQ1 from kbd_init responses
    invoke::irq_handler_ack(CAP_KBD_IRQ);

    // Bind notification to TCB for combined wait
    invoke::tcb_bind_notification(CAP_SELF_TCB, CAP_NTFN);
}

/// Poll COM1 and PS/2, translate scancodes, write bytes into `buf`.
/// Returns the number of bytes written.
pub fn drain_input(buf: &mut [u8]) -> usize {
    let mut count = 0usize;

    // COM1 input
    loop {
        let lsr = invoke::ioport_in8(CAP_IOPORT, COM1_LSR);
        if (lsr & LSR_DR) == 0 { break; }
        let c = invoke::ioport_in8(CAP_IOPORT, COM1_RBR);
        if count < buf.len() {
            buf[count] = c;
            count += 1;
        }
    }

    // PS/2 keyboard input
    loop {
        let status = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) == 0 { break; }
        let scancode = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_DATA);
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
    invoke::irq_handler_ack(CAP_IRQ);
    invoke::irq_handler_ack(CAP_KBD_IRQ);
}

/// Initialize PS/2 keyboard controller via IoPort capability.
fn kbd_init() {
    // Disable both ports
    invoke::ioport_out8(CAP_KBD_IOPORT, PS2_STATUS, 0xAD);
    invoke::ioport_out8(CAP_KBD_IOPORT, PS2_STATUS, 0xA7);

    // Flush output buffer
    for _ in 0..16 {
        let status = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) == 0 { break; }
        let _ = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_DATA);
    }

    // Read controller configuration byte (command 0x20)
    invoke::ioport_out8(CAP_KBD_IOPORT, PS2_STATUS, 0x20);
    for _ in 0..1000 {
        let status = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) != 0 { break; }
    }
    let mut config = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_DATA);

    // Enable IRQ1 (bit 0) and scancode translation (bit 6)
    config |= 1;
    config |= 1 << 6;

    // Write configuration back (command 0x60)
    invoke::ioport_out8(CAP_KBD_IOPORT, PS2_STATUS, 0x60);
    invoke::ioport_out8(CAP_KBD_IOPORT, PS2_DATA, config);

    // Enable port 1
    invoke::ioport_out8(CAP_KBD_IOPORT, PS2_STATUS, 0xAE);

    // Reset keyboard (send 0xFF)
    invoke::ioport_out8(CAP_KBD_IOPORT, PS2_DATA, 0xFF);
    for _ in 0..10000 {
        let status = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) != 0 {
            let byte = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_DATA);
            if byte == 0xAA { break; }
        }
    }

    // Enable scanning (send 0xF4)
    invoke::ioport_out8(CAP_KBD_IOPORT, PS2_DATA, 0xF4);
    for _ in 0..1000 {
        let status = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_STATUS);
        if (status & PS2_STATUS_OUTPUT_FULL) != 0 {
            let _ = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_DATA);
            break;
        }
    }

    serial::serial_puts(b"[CONSOLE] PS/2 keyboard initialized\n");
}
