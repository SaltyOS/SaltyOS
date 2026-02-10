//! SaltyOS Console Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides serial console access over IPC.
//! Receives CONSOLE_WRITE / CONSOLE_READ requests on its endpoint.
//! Output goes through the DebugPutStr syscall so all COM1 writes are
//! serialized under the kernel's SERIAL_LOCK.

#![no_std]
#![no_main]

extern crate salty;

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::types::*;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// Cap layout
const CAP_SERVER_EP: u64 = 3;
const CAP_IOPORT: u64 = 4;
const CAP_IRQ: u64 = 5;
const CAP_NTFN: u64 = 6;

// COM1 register offsets (still needed for init and input)
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
    invoke::ioport_out8(CAP_IOPORT, COM1_IER, 0x01);
}

/// Write a byte slice with CR/LF translation via DebugPutStr syscall.
///
/// All output goes through the kernel's SERIAL_LOCK, preventing
/// interleaving with other CPUs/threads.
fn console_puts(s: &[u8]) {
    // Pre-process CR/LF: expand \n → \r\n into a stack buffer
    // Max expansion: each byte could become 2 bytes
    // Process in chunks to avoid large stack allocations
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

/// Read a character from COM1 via IoPort cap (input path, no lock needed)
fn com1_getc() -> i32 {
    if (invoke::ioport_in8(CAP_IOPORT, COM1_LSR) & LSR_DR) != 0 {
        invoke::ioport_in8(CAP_IOPORT, COM1_RBR) as i32
    } else {
        -1
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

fn handle_read() -> u64 {
    let c = com1_getc();
    if c >= 0 {
        c as u64
    } else {
        u64::MAX
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    com1_init();
    serial::serial_puts(b"[CONSOLE] SaltyOS console server ready\n");

    unsafe {
        invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
        invoke::irq_handler_set_notification(CAP_IRQ, CAP_NTFN);
    }

    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        serial::serial_puts(b"[CONSOLE] initial recv failed\n");
        idle();
    }

    loop {
        let mut reply = SaltyMsg::zeroed();

        match msg.label {
            CONSOLE_WRITE => {
                unsafe { handle_write(&raw const msg) };
                reply.label = SALTY_OK;
            }
            CONSOLE_READ => {
                reply.regs[0] = handle_read();
                reply.label = SALTY_OK;
                reply.length = 1;
            }
            _ => {
                reply.label = SALTY_INVALID_OPERATION;
            }
        }

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
    }

    idle();
}

fn idle() -> ! {
    loop {
        salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
