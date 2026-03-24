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

// SHM ring buffer for terminal output to the display server.
// Replaces the old IPC-based TX queue: ttyd writes bytes to shared memory
// and signals the display via notification — no blocking IPC needed.
const TERM_SHM_ID: u64 = 0x54524D00; // "TRM\0"
const TERM_RING_VADDR: u64 = 0x0000_0000_0060_0000;
const TERM_RING_PAGES: u64 = 4;
const TERM_RING_HDR_SIZE: usize = 16;
static mut TERM_RING_BASE: *mut u8 = core::ptr::null_mut();
static mut TERM_RING_ACTIVE: bool = false;

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

// ======================================================================
// SHM ring buffer helpers (producer side)
// ======================================================================

fn term_ring_data_size() -> usize {
    TERM_RING_PAGES as usize * 4096 - TERM_RING_HDR_SIZE
}

/// Write bytes to the SHM ring. Returns number of bytes written.
///
/// # Safety
/// `base` must point to a valid, mapped SHM ring header page.
unsafe fn term_ring_push(base: *mut u8, ring_size: usize, data: &[u8]) -> usize {
    unsafe {
        let head = core::ptr::read_volatile(base as *const u32) as usize;
        let tail = core::ptr::read_volatile(base.add(4) as *const u32) as usize;
        // Acquire: observe consumer's tail update before computing free space.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let used = (head + ring_size - tail) % ring_size;
        let free = ring_size - 1 - used;
        let count = core::cmp::min(free, data.len());
        if count == 0 { return 0; }

        let dp = base.add(TERM_RING_HDR_SIZE);
        let mut i = 0usize;
        while i < count {
            core::ptr::write_volatile(dp.add((head + i) % ring_size), data[i]);
            i += 1;
        }
        // Release: all data writes above are visible before the head update
        // that publishes them to the consumer. Required on ARM (weak ordering);
        // x86 TSO provides this implicitly.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(base as *mut u32, ((head + count) % ring_size) as u32);
        count
    }
}

/// Forward output bytes to the display server via SHM ring + notification.
/// Never blocks on display state — writes to shared memory and signals.
pub(crate) fn display_write(data: &[u8]) {
    unsafe {
        if !TERM_RING_ACTIVE || data.is_empty() { return; }
        let base = TERM_RING_BASE;
        let ring_size = term_ring_data_size();
        let mut offset = 0usize;
        while offset < data.len() {
            let written = term_ring_push(base, ring_size, &data[offset..]);
            offset += written;
            if written > 0 {
                // SAFETY: Signal display notification — always succeeds, coalesces.
                besalt::syscall::syscall(
                    besalt::SYS_SIGNAL, CAP_DISPLAY_RING_NTFN, 1, 0, 0, 0, 0,
                );
            }
            if offset < data.len() {
                // Ring full — signal display to drain, yield CPU, retry.
                besalt::syscall::syscall(
                    besalt::SYS_SIGNAL, CAP_DISPLAY_RING_NTFN, 1, 0, 0, 0, 0,
                );
                besalt::syscall::syscall(besalt::SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
        }
    }
}

/// Set up the SHM ring buffer between ttyd and the display server.
/// Allocates shared memory + notification, performs handshake with display.
fn setup_display_ring() -> bool {
    let ctx = ipc_ctx();

    // 1. Allocate notification via mmsrv
    // SAFETY: IPC context is valid; set up receive slot for cap transfer.
    unsafe {
        ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, CAP_DISPLAY_RING_NTFN, 0);
    }
    let mut msg = BesaltMsg::zeroed();
    msg.label = MM_ALLOC_OBJECT;
    msg.regs[0] = OBJ_NOTIFICATION;
    msg.regs[1] = 0;
    msg.length = 2;
    let mut reply = BesaltMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != BESALT_OK {
        puts(b"[TTYD] Failed to allocate ring notification\n");
        return false;
    }

    // 2. Create SHM
    let mut msg = BesaltMsg::zeroed();
    msg.label = MM_SHM_CREATE;
    msg.regs[0] = TERM_SHM_ID;
    msg.regs[1] = TERM_RING_PAGES;
    msg.length = 2;
    let mut reply = BesaltMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || (reply.label != BESALT_OK && reply.label != BESALT_ALREADY_EXISTS) {
        puts(b"[TTYD] SHM create failed\n");
        return false;
    }

    // 3. Map SHM into our address space
    let mut msg = BesaltMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.regs[0] = TERM_SHM_ID;
    msg.regs[1] = 0; // map into self
    msg.regs[2] = TERM_RING_VADDR;
    msg.regs[3] = 0x3; // RW
    msg.length = 4;
    let mut reply = BesaltMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to mmsrv.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != BESALT_OK {
        puts(b"[TTYD] SHM map failed\n");
        return false;
    }

    // 4. Initialize ring header
    // SAFETY: SHM is mapped at TERM_RING_VADDR; single-threaded init.
    unsafe {
        let hdr = TERM_RING_VADDR as *mut u32;
        core::ptr::write_volatile(hdr, 0);         // head
        core::ptr::write_volatile(hdr.add(1), 0);  // tail
        core::ptr::write_volatile(hdr.add(2), term_ring_data_size() as u32); // size
        core::ptr::write_volatile(hdr.add(3), 0);  // reserved
        *(&raw mut TERM_RING_BASE) = TERM_RING_VADDR as *mut u8;
    }

    // 5. Send DISPLAY_SETUP_RING to display with notification cap
    // SAFETY: IPC context is valid; staging notification cap for transfer.
    unsafe {
        ipc::set_send_cap_ctx(ctx, 0, CAP_DISPLAY_RING_NTFN);
    }
    let mut msg = BesaltMsg::zeroed();
    msg.label = DISPLAY_SETUP_RING;
    msg.regs[0] = TERM_SHM_ID;
    msg.length = 1;
    let mut reply = BesaltMsg::zeroed();
    // SAFETY: IPC context is valid; making RPC to display.
    let err = unsafe { ipc::call_ctx(ctx, CAP_DISPLAY_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != BESALT_OK {
        puts(b"[TTYD] DISPLAY_SETUP_RING failed\n");
        return false;
    }

    // SAFETY: Single-threaded init; written once.
    unsafe { *(&raw mut TERM_RING_ACTIVE) = true; }
    puts(b"[TTYD] Display ring buffer active\n");
    true
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
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    puts(b"[TTYD] SaltyOS PTY driver starting\n");

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

    // Set up SHM ring buffer for display output (before signal_ready so
    // the ring is active before any client writes arrive).
    if !setup_display_ring() {
        puts(b"[TTYD] WARN: display ring setup failed, no display output\n");
    }

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

        // Flush queued serial echo BEFORE blocking on IPC, otherwise
        // characters echoed during input processing stay buffered until
        // the next event arrives — causing a visible one-character delay.
        unsafe { serial_try_flush(); }

        if skip_reply {
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
