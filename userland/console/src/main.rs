//! SaltyOS Console Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides serial console access over IPC.
//! Receives CONSOLE_WRITE / CONSOLE_READ / CONSOLE_TCGETATTR / CONSOLE_TCSETATTR
//! requests on its endpoint.
//! Output goes through the DebugPutStr syscall so all COM1 writes are
//! serialized under the kernel's SERIAL_LOCK.
//!
//! Input is IRQ-driven: COM1 IRQ4 fires a notification, the server reads
//! incoming bytes, applies line discipline (ICANON, ECHO, ISIG), and
//! satisfies any pending CONSOLE_READ request.

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
const CAP_PROCMGR: u64 = 9; // Injected late by init after procmgr starts

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

// Termios local flags
const ISIG: u32 = 0o000001;
const ICANON: u32 = 0o000002;
const ECHO: u32 = 0o000010;
const ECHOE: u32 = 0o000020;
const ECHOK: u32 = 0o000040;
const ECHONL: u32 = 0o000100;
const IEXTEN: u32 = 0o100000;
const ECHOCTL: u32 = 0o001000;
const ECHOKE: u32 = 0o004000;

// Termios input flags
const ICRNL: u32 = 0o000400;
const IXON: u32 = 0o002000;

// Termios output flags
const OPOST: u32 = 0o000001;
const ONLCR: u32 = 0o000004;

// Termios control flags
const CS8: u32 = 0o000060;
const CREAD: u32 = 0o000200;
const CLOCAL: u32 = 0o004000;

// cc indices
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VMIN: usize = 6;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VSUSP: usize = 10;

// Baud rate default
const B38400: u32 = 38400;

const RING_SIZE: usize = 256;
const LINE_BUF_SIZE: usize = 256;

// ======================================================================
// Data structures
// ======================================================================

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

    fn len(&self) -> usize {
        (self.head + RING_SIZE - self.tail) % RING_SIZE
    }
}

struct LineBuf {
    buf: [u8; LINE_BUF_SIZE],
    len: usize,
}

impl LineBuf {
    const fn new() -> Self {
        LineBuf {
            buf: [0; LINE_BUF_SIZE],
            len: 0,
        }
    }

    fn push(&mut self, c: u8) -> bool {
        if self.len >= LINE_BUF_SIZE {
            return false;
        }
        self.buf[self.len] = c;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }
        self.len -= 1;
        true
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

struct ConsoleTermios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

impl ConsoleTermios {
    const fn default() -> Self {
        let mut c_cc = [0u8; 32];
        c_cc[VINTR] = 3;     // Ctrl-C
        c_cc[VQUIT] = 28;    // Ctrl-backslash
        c_cc[VERASE] = 127;  // DEL
        c_cc[VKILL] = 21;    // Ctrl-U
        c_cc[VEOF] = 4;      // Ctrl-D
        c_cc[VMIN] = 1;
        c_cc[VSTART] = 17;   // Ctrl-Q
        c_cc[VSTOP] = 19;    // Ctrl-S
        c_cc[VSUSP] = 26;    // Ctrl-Z
        ConsoleTermios {
            c_iflag: ICRNL | IXON,
            c_oflag: OPOST | ONLCR,
            c_cflag: CS8 | CREAD | CLOCAL,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN | ECHOCTL | ECHOKE,
            c_cc,
            c_ispeed: B38400,
            c_ospeed: B38400,
        }
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

/// Echo a control character as ^X if ECHOCTL is set.
fn echo_ctrl(c: u8) {
    serial::serial_puts(&[b'^', c + 0x40]);
}

/// Deliver line buffer contents to a pending reader via saved reply cap.
fn deliver_line(line: &mut LineBuf, pending_reader: &mut bool) {
    if !*pending_reader || line.len == 0 {
        return;
    }

    let mut reply = SaltyMsg::zeroed();
    reply.label = SALTY_OK;
    let deliver_len = if line.len > 152 { 152 } else { line.len };
    reply.regs[0] = deliver_len as u64;
    reply.length = 1 + ((deliver_len as u64 + 7) / 8);

    let dst = &mut reply.regs[1] as *mut u64 as *mut u8;
    for i in 0..deliver_len {
        unsafe { *dst.add(i) = line.buf[i]; }
    }

    unsafe {
        ipc::send_ctx(ipc_ctx(), CAP_REPLY_SLOT, &raw const reply);
    }
    *pending_reader = false;
    line.clear();
}

/// Deliver the line buffer contents to the ring buffer (for deferred reads).
fn flush_line_to_ring(line: &mut LineBuf, ring: &mut RingBuf) {
    for i in 0..line.len {
        ring.push(line.buf[i]);
    }
    line.clear();
}

/// Send ISIG signal to foreground process group via procmgr.
fn send_signal(sig: i32) {
    let mut msg = SaltyMsg::zeroed();
    let mut reply = SaltyMsg::zeroed();
    msg.label = POSIX_PM_KILL;
    msg.length = 2;
    msg.regs[0] = 0; // pid=0 means foreground group
    msg.regs[1] = sig as u64;

    unsafe {
        ipc::call_ctx(ipc_ctx(), CAP_PROCMGR, &raw const msg, &raw mut reply);
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

/// Handle TCGETATTR: pack termios state into reply regs.
fn handle_tcgetattr(termios: &ConsoleTermios, reply: &mut SaltyMsg) {
    reply.label = SALTY_OK;
    reply.length = 10;
    reply.regs[0] = termios.c_iflag as u64;
    reply.regs[1] = termios.c_oflag as u64;
    reply.regs[2] = termios.c_cflag as u64;
    reply.regs[3] = termios.c_lflag as u64;
    reply.regs[4] = termios.c_ispeed as u64;
    reply.regs[5] = termios.c_ospeed as u64;
    // Pack c_cc[32] into regs[6..9] (4 u64s = 32 bytes)
    let dst = &mut reply.regs[6] as *mut u64 as *mut u8;
    for i in 0..32 {
        unsafe { *dst.add(i) = termios.c_cc[i]; }
    }
}

/// Handle TCSETATTR: unpack termios from msg regs.
fn handle_tcsetattr(msg: &SaltyMsg, termios: &mut ConsoleTermios, reply: &mut SaltyMsg) {
    // msg layout: regs[0]=fd, regs[1]=action,
    // regs[2]=c_iflag, regs[3]=c_oflag, regs[4]=c_cflag, regs[5]=c_lflag,
    // regs[6]=c_ispeed, regs[7]=c_ospeed, regs[8..11]=c_cc
    termios.c_iflag = msg.regs[2] as u32;
    termios.c_oflag = msg.regs[3] as u32;
    termios.c_cflag = msg.regs[4] as u32;
    termios.c_lflag = msg.regs[5] as u32;
    termios.c_ispeed = msg.regs[6] as u32;
    termios.c_ospeed = msg.regs[7] as u32;
    let src = &msg.regs[8] as *const u64 as *const u8;
    for i in 0..32 {
        termios.c_cc[i] = unsafe { *src.add(i) };
    }
    reply.label = SALTY_OK;
    reply.length = 0;
}

/// Drain all available characters from COM1, apply line discipline.
fn handle_irq(
    ring: &mut RingBuf,
    line: &mut LineBuf,
    pending_reader: &mut bool,
    termios: &ConsoleTermios,
) {
    let canonical = (termios.c_lflag & ICANON) != 0;
    let do_echo = (termios.c_lflag & ECHO) != 0;
    let do_isig = (termios.c_lflag & ISIG) != 0;

    loop {
        let lsr = invoke::ioport_in8(CAP_IOPORT, COM1_LSR);
        if (lsr & LSR_DR) == 0 {
            break;
        }
        let mut c = invoke::ioport_in8(CAP_IOPORT, COM1_RBR);

        // ISIG: check for signal-generating characters
        if do_isig {
            if c == termios.c_cc[VINTR] {
                if (termios.c_lflag & ECHOCTL) != 0 {
                    echo_ctrl(c);
                    serial::serial_puts(b"\r\n");
                }
                send_signal(SIGINT);
                if canonical { line.clear(); }
                continue;
            }
            if c == termios.c_cc[VQUIT] {
                if (termios.c_lflag & ECHOCTL) != 0 {
                    echo_ctrl(c);
                    serial::serial_puts(b"\r\n");
                }
                send_signal(SIGQUIT);
                if canonical { line.clear(); }
                continue;
            }
            if c == termios.c_cc[VSUSP] {
                if (termios.c_lflag & ECHOCTL) != 0 {
                    echo_ctrl(c);
                    serial::serial_puts(b"\r\n");
                }
                send_signal(SIGTSTP);
                if canonical { line.clear(); }
                continue;
            }
        }

        // Input flag: ICRNL — translate CR to NL
        if (termios.c_iflag & ICRNL) != 0 && c == b'\r' {
            c = b'\n';
        }

        if canonical {
            // === CANONICAL MODE ===

            // Backspace (DEL or BS)
            if c == termios.c_cc[VERASE] || c == 0x08 {
                if line.pop() {
                    if (termios.c_lflag & ECHOE) != 0 {
                        serial::serial_puts(b"\x08 \x08");
                    }
                }
                continue;
            }

            // Kill line (Ctrl-U)
            if c == termios.c_cc[VKILL] {
                if (termios.c_lflag & ECHOK) != 0 || (termios.c_lflag & ECHOKE) != 0 {
                    // Erase each character on terminal
                    for _ in 0..line.len {
                        serial::serial_puts(b"\x08 \x08");
                    }
                }
                line.clear();
                continue;
            }

            // EOF (Ctrl-D)
            if c == termios.c_cc[VEOF] {
                // Deliver current line (empty = EOF)
                if *pending_reader {
                    deliver_line(line, pending_reader);
                    // If line was empty, send 0-length reply
                    if !*pending_reader {
                        // Already delivered
                    } else {
                        // pending_reader is still true — deliver empty
                        let mut reply = SaltyMsg::zeroed();
                        reply.label = SALTY_OK;
                        reply.length = 1;
                        reply.regs[0] = 0;
                        unsafe {
                            ipc::send_ctx(ipc_ctx(), CAP_REPLY_SLOT, &raw const reply);
                        }
                        *pending_reader = false;
                    }
                } else {
                    flush_line_to_ring(line, ring);
                }
                continue;
            }

            // Newline (Enter)
            if c == b'\n' {
                line.push(b'\n');
                if do_echo || (termios.c_lflag & ECHONL) != 0 {
                    serial::serial_puts(b"\r\n");
                }
                // Deliver line
                if *pending_reader {
                    deliver_line(line, pending_reader);
                } else {
                    flush_line_to_ring(line, ring);
                }
                continue;
            }

            // Printable character
            if line.push(c) {
                if do_echo {
                    if c < 0x20 && (termios.c_lflag & ECHOCTL) != 0 {
                        echo_ctrl(c);
                    } else {
                        serial::serial_puts(&[c]);
                    }
                }
            }
            // If line buffer full, deliver
            if line.len >= LINE_BUF_SIZE {
                if *pending_reader {
                    deliver_line(line, pending_reader);
                } else {
                    flush_line_to_ring(line, ring);
                }
            }
        } else {
            // === RAW MODE ===
            if do_echo {
                serial::serial_puts(&[c]);
            }

            // Push to ring buffer and deliver immediately if pending reader
            if *pending_reader {
                let mut reply = SaltyMsg::zeroed();
                reply.label = SALTY_OK;
                reply.length = 2;
                reply.regs[0] = 1;
                let dst = &mut reply.regs[1] as *mut u64 as *mut u8;
                unsafe { *dst = c; }

                unsafe {
                    ipc::send_ctx(ipc_ctx(), CAP_REPLY_SLOT, &raw const reply);
                }
                *pending_reader = false;
            } else {
                ring.push(c);
            }
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
    let mut line = LineBuf::new();
    let mut pending_reader = false;
    let mut termios = ConsoleTermios::default();

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
            handle_irq(&mut ring, &mut line, &mut pending_reader, &termios);

            // After handling notification, do a plain recv to wait for next event
            let err =
                unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
            if err != 0 {
                serial::serial_puts(b"[CONSOLE] recv failed after IRQ\n");
                break;
            }
            continue;
        }

        // IPC message
        let mut reply = SaltyMsg::zeroed();
        let mut do_reply = true;

        match msg.label {
            CONSOLE_WRITE => {
                unsafe { handle_write(&raw const msg) };
                reply.label = SALTY_OK;
            }
            CONSOLE_READ => {
                // In canonical mode, only deliver complete lines
                if (termios.c_lflag & ICANON) != 0 {
                    // Check ring buffer for a complete line or data
                    if ring.len() > 0 {
                        // Deliver from ring (already cooked in handle_irq)
                        let mut count = ring.len();
                        if count > 152 { count = 152; }
                        reply.regs[0] = count as u64;
                        reply.length = 1 + ((count as u64 + 7) / 8);
                        let dst = &mut reply.regs[1] as *mut u64 as *mut u8;
                        for i in 0..count {
                            if let Some(c) = ring.pop() {
                                unsafe { *dst.add(i) = c; }
                            }
                        }
                        reply.label = SALTY_OK;
                    } else {
                        // No data — block reader
                        invoke::cnode_save_caller(CAP_SELF_CSPACE, CAP_REPLY_SLOT);
                        pending_reader = true;
                        do_reply = false;
                    }
                } else {
                    // Raw mode: return any available byte
                    if let Some(c) = ring.pop() {
                        reply.regs[0] = 1;
                        reply.length = 2;
                        let dst = &mut reply.regs[1] as *mut u64 as *mut u8;
                        unsafe { *dst = c; }
                        reply.label = SALTY_OK;
                    } else {
                        // No data — save the caller's reply cap and block
                        invoke::cnode_save_caller(CAP_SELF_CSPACE, CAP_REPLY_SLOT);
                        pending_reader = true;
                        do_reply = false;
                    }
                }
            }
            CONSOLE_TCGETATTR => {
                handle_tcgetattr(&termios, &mut reply);
            }
            CONSOLE_TCSETATTR => {
                handle_tcsetattr(&msg, &mut termios, &mut reply);
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
