//! SaltyOS Console Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides serial console access over IPC.
//! Receives CONSOLE_WRITE / CONSOLE_READ requests on its endpoint.
//! Output goes through the DebugPutStr syscall so all COM1 writes are
//! serialized under the kernel's SERIAL_LOCK.
//!
//! Input is IRQ-driven: COM1 IRQ4 fires a notification, the server reads
//! incoming bytes into a ring buffer, echoes them back to the terminal,
//! and satisfies any pending CONSOLE_READ request.

#![no_std]
#![no_main]

extern crate salty;

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::types::*;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// Cap layout (set up by init for the console server)
const CAP_SERVER_EP: u64 = 3;
const CAP_IOPORT: u64 = 4;
const CAP_IRQ: u64 = 5;
const CAP_NTFN: u64 = 6;

// Slot used for saving reply cap when blocking a CONSOLE_READ caller
const CAP_REPLY_SLOT: u64 = 32;

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

const RING_SIZE: usize = 256;

struct RingBuf {
    buf: [u8; RING_SIZE],
    head: usize,
    tail: usize,
}

impl RingBuf {
    const fn new() -> Self {
        RingBuf {
            buf: [0; RING_SIZE],
            head: 0,
            tail: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    fn is_full(&self) -> bool {
        ((self.head + 1) % RING_SIZE) == self.tail
    }

    fn push(&mut self, c: u8) -> bool {
        if self.is_full() {
            return false;
        }
        self.buf[self.head] = c;
        self.head = (self.head + 1) % RING_SIZE;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let c = self.buf[self.tail];
        self.tail = (self.tail + 1) % RING_SIZE;
        Some(c)
    }
}

fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

/// Initialize COM1 hardware registers via IoPort cap
fn com1_init() {
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

/// Write a byte slice with CR/LF translation via DebugPutStr syscall.
///
/// All output goes through the kernel's SERIAL_LOCK, preventing
/// interleaving with other CPUs/threads.
fn console_puts(s: &[u8]) {
    let mut buf = [0u8; 80];
    let mut buf_len = 0;
    for &c in s {
        if c == b'\n' {
            buf[buf_len] = b'\r';
            buf_len += 1;
            if buf_len >= buf.len() {
                serial::serial_puts(&buf[..buf_len]);
                buf_len = 0;
            }
        }
        buf[buf_len] = c;
        buf_len += 1;
        if buf_len >= buf.len() {
            serial::serial_puts(&buf[..buf_len]);
            buf_len = 0;
        }
    }
    if buf_len > 0 {
        serial::serial_puts(&buf[..buf_len]);
    }
}

/// Echo a character back to the terminal with line discipline handling.
fn echo_char(c: u8) {
    match c {
        // Backspace (0x7F = DEL, 0x08 = BS) — erase last character on terminal
        0x7F | 0x08 => {
            serial::serial_puts(b"\x08 \x08");
        }
        // Carriage return — echo CR+LF
        0x0D => {
            serial::serial_puts(b"\r\n");
        }
        // Normal printable characters (and some control chars)
        _ => {
            serial::serial_puts(&[c]);
        }
    }
}

unsafe fn handle_write(msg: *const SaltyMsg) {
    unsafe {
        let mut len = (*msg).regs[0];
        if len > 24 {
            len = 24;
        }
        let data = core::slice::from_raw_parts(
            &(*msg).regs[1] as *const u64 as *const u8,
            len as usize,
        );
        console_puts(data);
    }
}

/// Drain all available characters from COM1 into the ring buffer, echoing each.
/// If a reader is pending, deliver the first buffered char and clear the pending state.
fn handle_irq(ring: &mut RingBuf, pending_reader: &mut bool) {
    // Read all available characters from COM1
    loop {
        let lsr = invoke::ioport_in8(CAP_IOPORT, COM1_LSR);
        if (lsr & LSR_DR) == 0 {
            break;
        }
        let c = invoke::ioport_in8(CAP_IOPORT, COM1_RBR);

        // Echo the character back to terminal
        echo_char(c);

        // Push into ring buffer (drop if full)
        ring.push(c);
    }

    // If there's a pending reader and we have data, reply to them
    if *pending_reader && !ring.is_empty() {
        if let Some(c) = ring.pop() {
            let mut reply = SaltyMsg::zeroed();
            reply.label = SALTY_OK;
            reply.length = 1;
            reply.regs[0] = c as u64;

            // Send reply on the saved reply cap
            unsafe {
                ipc::send_ctx(ipc_ctx(), CAP_REPLY_SLOT, &raw const reply);
            }
            *pending_reader = false;
        }
    }

    // Acknowledge the IRQ so it can fire again
    invoke::irq_handler_ack(CAP_IRQ);
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    com1_init();
    serial::serial_puts(b"[CONSOLE] SaltyOS console server ready\n");

    unsafe {
        invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);

        // Set up IRQ notification
        invoke::irq_handler_set_notification(CAP_IRQ, CAP_NTFN);

        // Bind notification to TCB for combined wait (recv delivers both
        // IPC messages and notification signals)
        invoke::tcb_bind_notification(CAP_SELF_TCB, CAP_NTFN);
    }

    let mut ring = RingBuf::new();
    let mut pending_reader = false;

    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    // Initial recv — wait for first message or notification
    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        serial::serial_puts(b"[CONSOLE] initial recv failed\n");
        idle();
    }

    loop {
        // Check if this is a notification (badge != 0) or an IPC message (badge == 0)
        if badge != 0 {
            // Notification received — handle IRQ input
            handle_irq(&mut ring, &mut pending_reader);

            // After handling notification, do a plain recv to wait for next event
            let err =
                unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
            if err != 0 {
                serial::serial_puts(b"[CONSOLE] recv failed after IRQ\n");
                break;
            }
            continue;
        }

        // IPC message — handle CONSOLE_WRITE or CONSOLE_READ
        let mut reply = SaltyMsg::zeroed();
        let mut do_reply = true;

        match msg.label {
            CONSOLE_WRITE => {
                unsafe { handle_write(&raw const msg) };
                reply.label = SALTY_OK;
            }
            CONSOLE_READ => {
                if let Some(c) = ring.pop() {
                    // Data available — return immediately
                    reply.regs[0] = c as u64;
                    reply.label = SALTY_OK;
                    reply.length = 1;
                } else {
                    // No data — save the caller's reply cap and block
                    invoke::cnode_save_caller(CAP_SELF_CSPACE, CAP_REPLY_SLOT);
                    pending_reader = true;
                    do_reply = false;
                }
            }
            _ => {
                reply.label = SALTY_INVALID_OPERATION;
            }
        }

        if do_reply {
            // Normal path: reply to caller and wait for next message
            let err = unsafe {
                ipc::reply_recv_ctx(
                    ipc_ctx(),
                    CAP_SERVER_EP,
                    &raw const reply,
                    &raw mut msg,
                    &raw mut badge,
                )
            };
            if err != 0 {
                serial::serial_puts(b"[CONSOLE] reply_recv failed\n");
                break;
            }
        } else {
            // Blocking read path: don't reply, just recv next event
            let err =
                unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
            if err != 0 {
                serial::serial_puts(b"[CONSOLE] recv failed (blocking read)\n");
                break;
            }
        }
    }

    idle();
}

fn idle() -> ! {
    loop {
        salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
