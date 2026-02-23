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
//!   serial (DebugPutStr) + display (nbsend)

#![no_std]
#![no_main]

extern crate salty;

mod types;
mod input;
mod handlers;

use salty::consts::*;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf as SerialLB;
use salty::types::*;

use types::*;

// ======================================================================
// Global state
// ======================================================================

pub(crate) static mut PTYS: [PtyInstance; MAX_PTYS] = {
    const INIT: PtyInstance = PtyInstance::new();
    [INIT; MAX_PTYS]
};

// Non-blocking display TX queue. Keeps ttyd responsive even if display EP
// is temporarily back-pressured.
static mut DISPLAY_TX_BUF: [u8; DISPLAY_TX_BUF_SIZE] = [0; DISPLAY_TX_BUF_SIZE];
static mut DISPLAY_TX_HEAD: usize = 0;
static mut DISPLAY_TX_TAIL: usize = 0;

// ======================================================================
// Helper functions
// ======================================================================

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

fn signal_ready() {
    let _ = salty::syscall::syscall(salty::SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Forward output bytes to the display server via nbsend (fire-and-forget).
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

unsafe fn display_tx_enqueue(data: &[u8]) {
    unsafe {
        for &b in data {
            if display_tx_is_full() {
                // Drop oldest byte to keep forward progress without blocking.
                DISPLAY_TX_TAIL = (DISPLAY_TX_TAIL + 1) % DISPLAY_TX_BUF_SIZE;
            }
            DISPLAY_TX_BUF[DISPLAY_TX_HEAD] = b;
            DISPLAY_TX_HEAD = (DISPLAY_TX_HEAD + 1) % DISPLAY_TX_BUF_SIZE;
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

unsafe fn display_try_flush() {
    unsafe {
        let mut chunk = [0u8; DISPLAY_TX_CHUNK_MAX];
        let mut would_block_retries = 0usize;
        loop {
            if display_tx_is_empty() {
                break;
            }

            let len = display_tx_peek_chunk(&mut chunk);
            if len == 0 {
                break;
            }

            let mut msg = SaltyMsg::zeroed();
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
                would_block_retries = 0;
                continue;
            }
            if err == SALTY_WOULD_BLOCK as i32 && would_block_retries < 2 {
                let _ = salty::syscall::syscall(salty::SYS_YIELD, 0, 0, 0, 0, 0, 0);
                would_block_retries += 1;
                continue;
            }
            // Back-pressured or temporarily unavailable: keep queued and retry
            // on next event loop turn.
            break;
        }
    }
}

// ======================================================================
// Name service registration
// ======================================================================

fn register_with_nameserv() -> bool {
    let mut reg_msg = SaltyMsg::zeroed();
    let mut reg_reply = SaltyMsg::zeroed();
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
        if err == 0 && reg_reply.label == SALTY_OK {
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
        let err = salty::invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        if err != 0 {
            puts(b"[TTYD] FAIL: tcb_set_ipc_buffer\n");
            idle();
        }
        salty::ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
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
    let mut msg = SaltyMsg::zeroed();
    let mut badge = 0u64;

    let err = unsafe {
        salty::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
    };
    if err != 0 {
        puts(b"[TTYD] initial recv failed\n");
        idle();
    }

    loop {
        unsafe { display_try_flush(); }

        let mut reply = SaltyMsg::zeroed();
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
                reply.label = SALTY_OK;
                reply.length = 0;
            }
            // Legacy labels (backward compat, redirect to PTY 0)
            TTYD_GET_FG_PGRP | TTYD_SET_FG_PGRP | TTYD_SET_CTTY | TTYD_DROP_CTTY => {
                unsafe { handlers::handle_legacy(msg.label, &msg, &mut reply) };
            }
            _ => {
                reply.label = SALTY_INVALID_OPERATION;
                reply.length = 0;
            }
        }

        if skip_reply {
            // No reply expected (sender used send, not call) — just recv next
            let err = unsafe {
                salty::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
            };
            if err != 0 {
                puts(b"[TTYD] recv failed\n");
                break;
            }
        } else {
            let err = unsafe {
                salty::ipc::reply_recv_ctx(
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
        salty::syscall::syscall(salty::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
