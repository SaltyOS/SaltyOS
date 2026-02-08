//! SaltyOS Console Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides serial console access over IPC.
//! Receives CONSOLE_WRITE / CONSOLE_READ requests on its endpoint
//! and translates them to COM1 I/O via IoPort capability invocations.

#![no_std]
#![no_main]

extern crate salty;

use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::types::*;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// Cap layout
const CAP_SERVER_EP: u64 = 3;
const CAP_IOPORT: u64 = 4;
const CAP_IRQ: u64 = 5;
const CAP_NTFN: u64 = 6;

// COM1 register offsets
const COM1_THR: u64 = 0;
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
const LSR_THRE: u8 = 1 << 5;

fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

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

fn com1_putc(c: u8) {
    while (invoke::ioport_in8(CAP_IOPORT, COM1_LSR) & LSR_THRE) == 0 {}
    invoke::ioport_out8(CAP_IOPORT, COM1_THR, c);
}

fn com1_puts(s: &[u8]) {
    for &c in s {
        if c == b'\n' {
            com1_putc(b'\r');
        }
        com1_putc(c);
    }
}

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
        let data = &(*msg).regs[1] as *const u64 as *const u8;
        for i in 0..len as usize {
            let c = *data.add(i);
            if c == b'\n' {
                com1_putc(b'\r');
            }
            com1_putc(c);
        }
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
    com1_puts(b"[CONSOLE] SaltyOS console server ready\n");

    unsafe {
        invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
        invoke::irq_handler_set_notification(CAP_IRQ, CAP_NTFN);
    }

    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        com1_puts(b"[CONSOLE] initial recv failed\n");
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
            com1_puts(b"[CONSOLE] reply_recv failed\n");
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
