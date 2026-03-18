//! SaltyOS TTY daemon — PTY driver with line discipline
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides PTY (pseudo-terminal) instances with per-PTY line discipline,
//! termios state, and session/job control metadata.
//!
//! Data flow:
//!   Console IRQ → console server → TTYD_INPUT_EVENT → line discipline →
//!   slave ring buffer → sys_signal(VFS notification) → VFS collects →
//!   client (bash)
//!
//! Output flow:
//!   bash write → VFS → TTYD_PTY_WRITE → OPOST processing →
//!   serial (DebugPutStr) + display (queued IPC with blocking fallback)

#![no_std]
#![no_main]

extern crate besalt;

mod types;
mod input;
mod handlers;

use besalt::consts::*;
use besalt::ipc;
use besalt::serial;
use besalt::serial::LineBuf as SerialLB;
use besalt::types::*;

use types::*;

// ======================================================================
// Global state
// ======================================================================

pub(crate) static mut PTYS: [PtyInstance; MAX_PTYS] = {
    const INIT: PtyInstance = PtyInstance::new();
    [INIT; MAX_PTYS]
};

// Display TX queue. Fast path is non-blocking; under sustained backpressure
// we fall back to blocking flushes rather than dropping bytes and corrupting
// the terminal escape stream.
static mut DISPLAY_TX_BUF: [u8; DISPLAY_TX_BUF_SIZE] = [0; DISPLAY_TX_BUF_SIZE];
static mut DISPLAY_TX_HEAD: usize = 0;
static mut DISPLAY_TX_TAIL: usize = 0;

// Serial TX queue. Decouples UART busy-wait from the event loop — data is
// enqueued here and drained in small chunks (SERIAL_TX_DRAIN_MAX bytes per
// loop iteration) so TTYD remains responsive during large writes.
const SERIAL_TX_BUF_SIZE: usize = 4096;
const SERIAL_TX_DRAIN_MAX: usize = 64;
static mut SERIAL_TX_BUF: [u8; SERIAL_TX_BUF_SIZE] = [0; SERIAL_TX_BUF_SIZE];
static mut SERIAL_TX_HEAD: usize = 0;
static mut SERIAL_TX_TAIL: usize = 0;

// ======================================================================
// Helper functions
// ======================================================================

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    &raw mut besalt::__besalt_ipc_ctx
}

fn signal_ready() {
    let _ = besalt::syscall::syscall(besalt::SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Forward output bytes to the display server.
/// Uses a queued nbsend fast path and blocking flush fallback to preserve
/// terminal stream ordering under display backpressure.
pub(crate) fn display_write(data: &[u8]) {
    if data.is_empty() { return; }
    unsafe {
        display_tx_enqueue(data);
        display_try_flush();
    }
}

#[inline(always)]
unsafe fn display_tx_is_empty() -> bool {
    unsafe { DISPLAY_TX_HEAD == DISPLAY_TX_TAIL }
}

#[inline(always)]
unsafe fn display_tx_is_full() -> bool {
    unsafe { ((DISPLAY_TX_HEAD + 1) % DISPLAY_TX_BUF_SIZE) == DISPLAY_TX_TAIL }
}

#[inline(always)]
unsafe fn display_tx_len() -> usize {
    unsafe { (DISPLAY_TX_HEAD + DISPLAY_TX_BUF_SIZE - DISPLAY_TX_TAIL) % DISPLAY_TX_BUF_SIZE }
}

#[inline(always)]
unsafe fn display_tx_free() -> usize {
    unsafe { DISPLAY_TX_BUF_SIZE - 1 - display_tx_len() }
}

unsafe fn display_tx_enqueue(data: &[u8]) {
    unsafe {
        let mut offset = 0usize;
        while offset < data.len() {
            if display_tx_is_full() {
                display_try_flush();
                if display_tx_is_full() && !display_flush_blocking_one() {
                    break;
                }
            }

            let free = display_tx_free();
            if free == 0 {
                break;
            }

            let count = core::cmp::min(free, data.len() - offset);
            for i in 0..count {
                DISPLAY_TX_BUF[DISPLAY_TX_HEAD] = data[offset + i];
                DISPLAY_TX_HEAD = (DISPLAY_TX_HEAD + 1) % DISPLAY_TX_BUF_SIZE;
            }
            offset += count;
        }
    }
}

unsafe fn display_tx_peek_chunk(dst: &mut [u8; DISPLAY_TX_CHUNK_MAX]) -> usize {
    unsafe {
        let mut idx = DISPLAY_TX_TAIL;
        let head = DISPLAY_TX_HEAD;
        let mut n = 0usize;
        while idx != head && n < dst.len() {
            dst[n] = DISPLAY_TX_BUF[idx];
            idx = (idx + 1) % DISPLAY_TX_BUF_SIZE;
            n += 1;
        }
        n
    }
}

unsafe fn display_tx_consume(n: usize) {
    unsafe {
        DISPLAY_TX_TAIL = (DISPLAY_TX_TAIL + n) % DISPLAY_TX_BUF_SIZE;
    }
}

unsafe fn display_flush_blocking_one() -> bool {
    unsafe {
        let mut chunk = [0u8; DISPLAY_TX_CHUNK_MAX];
        let len = display_tx_peek_chunk(&mut chunk);
        if len == 0 {
            return true;
        }

        let mut msg = BesaltMsg::zeroed();
        msg.label = DISPLAY_TERMINAL_WRITE;
        msg.regs[0] = len as u64;
        msg.length = 1 + ((len as u64 + 7) / 8);
        let dst = &raw mut msg.regs[1] as *mut u8;
        for (i, b) in chunk[..len].iter().enumerate() {
            *dst.add(i) = *b;
        }

        let err = ipc::nbsend_ctx(ipc_ctx(), CAP_DISPLAY_EP, &raw const msg);
        if err == 0 {
            display_tx_consume(len);
            true
        } else {
            false
        }
    }
}

unsafe fn display_try_flush() {
    unsafe {
        let mut chunk = [0u8; DISPLAY_TX_CHUNK_MAX];
        loop {
            if display_tx_is_empty() {
                break;
            }

            let len = display_tx_peek_chunk(&mut chunk);
            if len == 0 {
                break;
            }

            let mut msg = BesaltMsg::zeroed();
            msg.label = DISPLAY_TERMINAL_WRITE;
            msg.regs[0] = len as u64;
            msg.length = 1 + ((len as u64 + 7) / 8);
            let dst = &raw mut msg.regs[1] as *mut u8;
            for i in 0..len {
                *dst.add(i) = chunk[i];
            }

            let err = ipc::nbsend_ctx(ipc_ctx(), CAP_DISPLAY_EP, &raw const msg);
            if err == 0 {
                display_tx_consume(len);
                continue;
            }
            // Backpressure — keep queued, try again next event loop turn.
            break;
        }
    }
}

// ======================================================================
// Serial TX ring buffer helpers
// ======================================================================

/// Queue bytes for deferred serial output.
pub(crate) fn serial_write_queued(data: &[u8]) {
    unsafe {
        for &b in data {
            let next = (SERIAL_TX_HEAD + 1) % SERIAL_TX_BUF_SIZE;
            if next == SERIAL_TX_TAIL {
                // Buffer full — drain synchronously to avoid dropping bytes
                serial_try_flush();
                let next2 = (SERIAL_TX_HEAD + 1) % SERIAL_TX_BUF_SIZE;
                if next2 == SERIAL_TX_TAIL {
                    // Still full after flush — write directly as fallback
                    serial::serial_puts(&data[..]);
                    return;
                }
            }
            SERIAL_TX_BUF[SERIAL_TX_HEAD] = b;
            SERIAL_TX_HEAD = (SERIAL_TX_HEAD + 1) % SERIAL_TX_BUF_SIZE;
        }
    }
}

/// Drain up to SERIAL_TX_DRAIN_MAX bytes from the serial TX queue.
/// Called once per event loop iteration to keep TTYD responsive.
unsafe fn serial_try_flush() {
    unsafe {
        if SERIAL_TX_HEAD == SERIAL_TX_TAIL {
            return;
        }

        let mut buf = [0u8; SERIAL_TX_DRAIN_MAX];
        let mut n = 0usize;
        let mut idx = SERIAL_TX_TAIL;
        while idx != SERIAL_TX_HEAD && n < SERIAL_TX_DRAIN_MAX {
            buf[n] = SERIAL_TX_BUF[idx];
            idx = (idx + 1) % SERIAL_TX_BUF_SIZE;
            n += 1;
        }
        if n > 0 {
            serial::serial_puts(&buf[..n]);
            SERIAL_TX_TAIL = (SERIAL_TX_TAIL + n) % SERIAL_TX_BUF_SIZE;
        }
    }
}

// ======================================================================
// Name service registration
// ======================================================================

fn register_with_nameserv() -> bool {
    let mut reg_msg = BesaltMsg::zeroed();
    let mut reg_reply = BesaltMsg::zeroed();
    let svc_name = b"ttyd";

    reg_msg.label = POSIX_NS_REGISTER;
    reg_msg.regs[0] = svc_name.len() as u64;
    reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;

    let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
    unsafe {
        for i in 0..svc_name.len() {
            *ns_dst.add(i) = svc_name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let err = ipc::call_ctx(
            ipc_ctx(),
            CAP_NAMESERV_EP,
            &raw const reg_msg,
            &raw mut reg_reply,
        );
        if err == 0 && reg_reply.label == BESALT_OK {
            puts(b"[TTYD] registered with nameserv\n");
            return true;
        }
        let mut lb = SerialLB::new();
        lb.str(b"[TTYD] nameserv register failed: err=");
        lb.hex(err as u64);
        lb.str(b" label=");
        lb.hex(reg_reply.label);
        lb.str(b"\n");
        lb.flush();
    }
    false
}

// ======================================================================
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[TTYD] SaltyOS PTY driver starting\n");

    unsafe {
        let err = besalt::invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        if err != 0 {
            puts(b"[TTYD] FAIL: tcb_set_ipc_buffer\n");
            idle();
        }
        besalt::ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }

    // Query display server for actual framebuffer dimensions.
    unsafe {
        let mut qmsg = BesaltMsg::zeroed();
        let mut qreply = BesaltMsg::zeroed();
        qmsg.label = DISPLAY_GET_INFO;
        qmsg.length = 0;
        let err = besalt::ipc::call_ctx(
            ipc_ctx(),
            CAP_DISPLAY_EP,
            &raw const qmsg,
            &raw mut qreply,
        );
        if err == 0 && qreply.label == BESALT_OK {
            let fb_width = qreply.regs[0] as u32;
            let fb_height = qreply.regs[1] as u32;
            // GLYPH_WIDTH=8, GLYPH_HEIGHT=16
            let cols = fb_width / 8;
            let rows = fb_height / 16;
            if cols > 0 && rows > 0 {
                *(&raw mut types::WINSIZE_COLS) = cols;
                *(&raw mut types::WINSIZE_ROWS) = rows;
                let mut lb = SerialLB::new();
                lb.str(b"[TTYD] Display dimensions: ");
                lb.dec(cols as u64);
                lb.str(b"x");
                lb.dec(rows as u64);
                lb.str(b"\n");
                lb.flush();
            }
        } else {
            puts(b"[TTYD] WARN: display query failed, using 80x24\n");
        }
    }

    // Activate PTY 0 (the console PTY)
    unsafe {
        PTYS[0].active = true;
    }
    puts(b"[TTYD] PTY 0 (console) active\n");

    register_with_nameserv();
    input::signal_vfs(0);

    signal_ready();
    puts(b"[TTYD] Ready\n");

    // Main server loop
    let mut msg = BesaltMsg::zeroed();
    let mut badge = 0u64;

    let err = unsafe {
        besalt::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
    };
    if err != 0 {
        puts(b"[TTYD] initial recv failed\n");
        idle();
    }

    loop {
        unsafe { display_try_flush(); }
        unsafe { serial_try_flush(); }

        let mut reply = BesaltMsg::zeroed();
        let mut skip_reply = false;

        match msg.label {
            // New PTY protocol
            TTYD_INPUT_EVENT => {
                unsafe { input::handle_input_event(&msg) };
                // Console used send (not call), no reply expected
                skip_reply = true;
            }
            TTYD_PTY_READ => {
                unsafe { handlers::handle_pty_read(&msg, &mut reply) };
            }
            TTYD_PTY_COLLECT => {
                unsafe { handlers::handle_pty_collect(&msg, &mut reply) };
            }
            TTYD_PTY_WRITE => {
                unsafe { handlers::handle_pty_write(&msg, &mut reply) };
                unsafe { display_try_flush(); }
            }
            TTYD_PTY_TCGETATTR => {
                unsafe { handlers::handle_pty_tcgetattr(&msg, &mut reply) };
            }
            TTYD_PTY_TCSETATTR => {
                unsafe { handlers::handle_pty_tcsetattr(&msg, &mut reply) };
            }
            TTYD_PTY_IOCTL => {
                unsafe { handlers::handle_pty_ioctl(&msg, &mut reply) };
            }
            TTYD_PTY_POLL => {
                unsafe { handlers::handle_pty_poll(&msg, &mut reply) };
            }
            TTYD_CLIENT_EXIT => {
                let dead_badge = msg.regs[0];
                unsafe {
                    for i in 0..MAX_PTYS {
                        let pty = &mut *(&raw mut PTYS[i]);
                        if pty.has_ctty && pty.ctty_owner_badge == dead_badge {
                            pty.has_ctty = false;
                            pty.ctty_owner_badge = 0;
                            pty.fg_pgid = 0;
                        } else if pty.fg_pgid == dead_badge as u32 {
                            pty.fg_pgid = 0;
                        }
                    }
                }
                reply.label = BESALT_OK;
                reply.length = 0;
            }
            // Legacy labels (backward compat, redirect to PTY 0)
            TTYD_GET_FG_PGRP | TTYD_SET_FG_PGRP | TTYD_SET_CTTY | TTYD_DROP_CTTY => {
                unsafe { handlers::handle_legacy(msg.label, &msg, &mut reply) };
            }
            _ => {
                reply.label = BESALT_INVALID_OPERATION;
                reply.length = 0;
            }
        }

        if skip_reply {
            // No reply expected (sender used send, not call) — just recv next
            let err = unsafe {
                besalt::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
            };
            if err != 0 {
                puts(b"[TTYD] recv failed\n");
                break;
            }
        } else {
            let err = unsafe {
                besalt::ipc::reply_recv_ctx(
                    ipc_ctx(),
                    CAP_SERVER_EP,
                    &raw const reply,
                    &raw mut msg,
                    &raw mut badge,
                )
            };
            if err != 0 {
                puts(b"[TTYD] reply_recv failed\n");
                break;
            }
        }
    }

    idle();
}

fn idle() -> ! {
    loop {
        besalt::syscall::syscall(besalt::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
