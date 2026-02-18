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

use salty::consts::*;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf as SerialLB;
use salty::types::*;

// ======================================================================
// Capability layout
// ======================================================================

const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_PROCMGR_EP: u64 = 3;
const CAP_NAMESERV_EP: u64 = 5;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_DISPLAY_EP: u64 = 65;
const CAP_VFS_NTFN: u64 = 66;
const CAP_SERVER_EP: u64 = 68;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// ======================================================================
// Buffer sizes and limits
// ======================================================================

const RING_SIZE: usize = 4096;
const LINE_BUF_SIZE: usize = 256;
const MAX_PTYS: usize = 4;
const DISPLAY_TX_BUF_SIZE: usize = 4096;
const DISPLAY_TX_CHUNK_MAX: usize = 152;

// ======================================================================
// Termios flag constants
// ======================================================================

// Local flags (c_lflag)
const ISIG: u32 = 0o000001;
const ICANON: u32 = 0o000002;
const ECHO: u32 = 0o000010;
const ECHOE: u32 = 0o000020;
const ECHOK: u32 = 0o000040;
const ECHONL: u32 = 0o000100;
const ECHOCTL: u32 = 0o001000;
const ECHOKE: u32 = 0o004000;
const IEXTEN: u32 = 0o100000;

// Input flags (c_iflag)
const ICRNL: u32 = 0o000400;
const IXON: u32 = 0o002000;

// Output flags (c_oflag)
const OPOST: u32 = 0o000001;
const ONLCR: u32 = 0o000004;

// Control flags (c_cflag)
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

const B38400: u32 = 38400;

// POLLIN/POLLOUT for PTY_POLL
const POLLIN: u32 = 0x0001;
const POLLOUT: u32 = 0x0004;
const POLLHUP: u32 = 0x0010;

// ioctl commands
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCSCTTY: u64 = 0x540E;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGWINSZ: u64 = 0x5413;

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
        RingBuf { buf: [0; RING_SIZE], head: 0, tail: 0 }
    }

    fn is_empty(&self) -> bool { self.head == self.tail }
    fn is_full(&self) -> bool { ((self.head + 1) % RING_SIZE) == self.tail }

    fn push(&mut self, c: u8) -> bool {
        if self.is_full() { return false; }
        self.buf[self.head] = c;
        self.head = (self.head + 1) % RING_SIZE;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.is_empty() { return None; }
        let c = self.buf[self.tail];
        self.tail = (self.tail + 1) % RING_SIZE;
        Some(c)
    }

    fn len(&self) -> usize {
        (self.head + RING_SIZE - self.tail) % RING_SIZE
    }

    fn clear(&mut self) { self.head = 0; self.tail = 0; }
}

struct InputLineBuf {
    buf: [u8; LINE_BUF_SIZE],
    len: usize,
}

impl InputLineBuf {
    const fn new() -> Self {
        InputLineBuf { buf: [0; LINE_BUF_SIZE], len: 0 }
    }

    fn push(&mut self, c: u8) -> bool {
        if self.len >= LINE_BUF_SIZE { return false; }
        self.buf[self.len] = c;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> bool {
        if self.len == 0 { return false; }
        self.len -= 1;
        true
    }

    fn clear(&mut self) { self.len = 0; }
}

struct PtyTermios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

impl PtyTermios {
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
        PtyTermios {
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

struct PtyInstance {
    active: bool,
    // Slave-side input ring (data from keyboard → line disc → here → bash reads)
    slave_ring: RingBuf,
    // Canonical mode line accumulator
    line: InputLineBuf,
    // Per-PTY termios
    termios: PtyTermios,
    // Controlling terminal ownership + foreground process group
    has_ctty: bool,
    ctty_owner_badge: u64,
    fg_pgid: u32,
    // Whether VFS has a pending read for this PTY (needs notification on data)
    vfs_pending: bool,
    // State tracking
    master_closed: bool,
    slave_closed: bool,
}

impl PtyInstance {
    const fn new() -> Self {
        PtyInstance {
            active: false,
            slave_ring: RingBuf::new(),
            line: InputLineBuf::new(),
            termios: PtyTermios::default(),
            has_ctty: false,
            ctty_owner_badge: 0,
            fg_pgid: 0,
            vfs_pending: false,
            master_closed: false,
            slave_closed: false,
        }
    }
}

// ======================================================================
// Global state
// ======================================================================

static mut PTYS: [PtyInstance; MAX_PTYS] = {
    const INIT: PtyInstance = PtyInstance::new();
    [INIT; MAX_PTYS]
};

// Non-blocking display TX queue. Keeps ttyd responsive even if display EP
// is temporarily back-pressured.
static mut DISPLAY_TX_BUF: [u8; DISPLAY_TX_BUF_SIZE] = [0; DISPLAY_TX_BUF_SIZE];
static mut DISPLAY_TX_HEAD: usize = 0;
static mut DISPLAY_TX_TAIL: usize = 0;
static mut DISPLAY_TX_DROP_COUNT: u64 = 0;

// ======================================================================
// Helper functions
// ======================================================================

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

fn signal_ready() {
    let _ = salty::syscall::syscall(salty::SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Echo a control character as ^X to serial.
fn echo_ctrl_serial(c: u8) {
    serial::serial_puts(&[b'^', c + 0x40]);
}

/// Forward output bytes to the display server via nbsend (fire-and-forget).
fn display_write(data: &[u8]) {
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
                DISPLAY_TX_DROP_COUNT = DISPLAY_TX_DROP_COUNT.wrapping_add(1);
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

/// Push a byte to the display echo buffer, flushing if full.
fn echo_push(buf: &mut [u8; 64], len: &mut usize, c: u8) {
    if *len >= 64 {
        display_write(&buf[..*len]);
        *len = 0;
    }
    buf[*len] = c;
    *len += 1;
}

/// Write a byte slice with CR/LF translation via DebugPutStr syscall (serial output).
fn serial_puts_opost(s: &[u8]) {
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

/// Send signal to foreground process group via nbsend to procmgr (fire-and-forget).
/// Uses POSIX_PM_KILL_PGID to target an explicit pgid.
fn send_signal_pgid(pgid: u32, sig: i32) {
    let mut msg = SaltyMsg::zeroed();
    msg.label = POSIX_PM_KILL_PGID;
    msg.length = 2;
    msg.regs[0] = pgid as u64;
    msg.regs[1] = sig as u64;
    unsafe {
        ipc::nbsend_ctx(ipc_ctx(), CAP_PROCMGR_EP, &raw const msg);
    }
}

/// Signal VFS's bound notification to wake it for PTY data.
/// Badge bits encode the PTY id.
fn signal_vfs(pty_id: usize) {
    let _r = salty::syscall::syscall(
        salty::SYS_SIGNAL,
        CAP_VFS_NTFN,
        1u64 << pty_id as u64,
        0, 0, 0, 0,
    );
}

/// Flush line buffer contents into the slave ring.
fn flush_line_to_ring(line: &mut InputLineBuf, ring: &mut RingBuf) {
    for i in 0..line.len {
        ring.push(line.buf[i]);
    }
    line.clear();
}

// ======================================================================
// Line discipline
// ======================================================================

/// Process a single input character through the line discipline for a PTY.
/// After processing, if slave_ring transitions from empty to non-empty and
/// VFS has a pending reader, signals VFS via notification.
unsafe fn process_input_char(pty_id: usize, c: u8, echo_buf: &mut [u8; 64], echo_len: &mut usize) {
    unsafe {
        let pty = &mut *(&raw mut PTYS[pty_id]);
        let mut ch = c;
        let canonical = (pty.termios.c_lflag & ICANON) != 0;
        let do_echo = (pty.termios.c_lflag & ECHO) != 0;
        let do_isig = (pty.termios.c_lflag & ISIG) != 0;

        // ISIG: check for signal-generating characters
        if do_isig {
            if ch == pty.termios.c_cc[VINTR] {
                if (pty.termios.c_lflag & ECHOCTL) != 0 {
                    echo_ctrl_serial(ch);
                    serial::serial_puts(b"\r\n");
                    echo_push(echo_buf, echo_len, b'^');
                    echo_push(echo_buf, echo_len, ch + 0x40);
                    echo_push(echo_buf, echo_len, b'\n');
                }
                if pty.fg_pgid != 0 {
                    send_signal_pgid(pty.fg_pgid, SIGINT);
                }
                if canonical { pty.line.clear(); }
                return;
            }
            if ch == pty.termios.c_cc[VQUIT] {
                if (pty.termios.c_lflag & ECHOCTL) != 0 {
                    echo_ctrl_serial(ch);
                    serial::serial_puts(b"\r\n");
                    echo_push(echo_buf, echo_len, b'^');
                    echo_push(echo_buf, echo_len, ch + 0x40);
                    echo_push(echo_buf, echo_len, b'\n');
                }
                if pty.fg_pgid != 0 {
                    send_signal_pgid(pty.fg_pgid, SIGQUIT);
                }
                if canonical { pty.line.clear(); }
                return;
            }
            if ch == pty.termios.c_cc[VSUSP] {
                if (pty.termios.c_lflag & ECHOCTL) != 0 {
                    echo_ctrl_serial(ch);
                    serial::serial_puts(b"\r\n");
                    echo_push(echo_buf, echo_len, b'^');
                    echo_push(echo_buf, echo_len, ch + 0x40);
                    echo_push(echo_buf, echo_len, b'\n');
                }
                if pty.fg_pgid != 0 {
                    send_signal_pgid(pty.fg_pgid, SIGTSTP);
                }
                if canonical { pty.line.clear(); }
                return;
            }
        }

        // ICRNL: translate CR to NL
        if (pty.termios.c_iflag & ICRNL) != 0 && ch == b'\r' {
            ch = b'\n';
        }

        if canonical {
            // === CANONICAL MODE ===

            // Backspace (DEL or BS)
            if ch == pty.termios.c_cc[VERASE] || ch == 0x08 {
                if pty.line.pop() {
                    if (pty.termios.c_lflag & ECHOE) != 0 {
                        serial::serial_puts(b"\x08 \x08");
                        echo_push(echo_buf, echo_len, 0x08);
                    }
                }
                return;
            }

            // Kill line (Ctrl-U)
            if ch == pty.termios.c_cc[VKILL] {
                if (pty.termios.c_lflag & ECHOK) != 0 || (pty.termios.c_lflag & ECHOKE) != 0 {
                    for _ in 0..pty.line.len {
                        serial::serial_puts(b"\x08 \x08");
                        echo_push(echo_buf, echo_len, 0x08);
                    }
                }
                pty.line.clear();
                return;
            }

            // EOF (Ctrl-D)
            if ch == pty.termios.c_cc[VEOF] {
                let was_empty = pty.slave_ring.is_empty();
                flush_line_to_ring(&mut pty.line, &mut pty.slave_ring);
                if was_empty && !pty.slave_ring.is_empty() && pty.vfs_pending {
                    signal_vfs(pty_id);
                } else if was_empty && pty.slave_ring.is_empty() && pty.vfs_pending {
                    // EOF with empty line: signal VFS so it returns 0 bytes (EOF)
                    signal_vfs(pty_id);
                }
                return;
            }

            // Newline (Enter)
            if ch == b'\n' {
                pty.line.push(b'\n');
                if do_echo || (pty.termios.c_lflag & ECHONL) != 0 {
                    serial::serial_puts(b"\r\n");
                    echo_push(echo_buf, echo_len, b'\n');
                }
                let was_empty = pty.slave_ring.is_empty();
                flush_line_to_ring(&mut pty.line, &mut pty.slave_ring);
                if was_empty && !pty.slave_ring.is_empty() && pty.vfs_pending {
                    signal_vfs(pty_id);
                }
                return;
            }

            // Regular character
            if pty.line.push(ch) {
                if do_echo {
                    if ch < 0x20 && (pty.termios.c_lflag & ECHOCTL) != 0 {
                        echo_ctrl_serial(ch);
                        echo_push(echo_buf, echo_len, b'^');
                        echo_push(echo_buf, echo_len, ch + 0x40);
                    } else {
                        serial::serial_puts(&[ch]);
                        echo_push(echo_buf, echo_len, ch);
                    }
                }
            }
            // Flush if line buffer is full
            if pty.line.len >= LINE_BUF_SIZE {
                let was_empty = pty.slave_ring.is_empty();
                flush_line_to_ring(&mut pty.line, &mut pty.slave_ring);
                if was_empty && !pty.slave_ring.is_empty() && pty.vfs_pending {
                    signal_vfs(pty_id);
                }
            }
        } else {
            // === RAW MODE ===
            if do_echo {
                serial::serial_puts(&[ch]);
                echo_push(echo_buf, echo_len, ch);
            }
            let was_empty = pty.slave_ring.is_empty();
            pty.slave_ring.push(ch);
            if was_empty && pty.vfs_pending {
                signal_vfs(pty_id);
            }
        }
    }
}

// ======================================================================
// IPC handlers
// ======================================================================

/// TTYD_INPUT_EVENT: raw bytes from console server.
/// msg.regs[0] = byte_count, msg.regs[1..] = packed bytes.
unsafe fn handle_input_event(msg: &SaltyMsg) {
    unsafe {
        let count = msg.regs[0] as usize;
        if count == 0 || count > 128 { return; }

        let src = &msg.regs[1] as *const u64 as *const u8;
        let mut echo_buf = [0u8; 64];
        let mut echo_len: usize = 0;

        // Route all console input to PTY 0 (the console PTY)
        for i in 0..count {
            let c = *src.add(i);
            process_input_char(0, c, &mut echo_buf, &mut echo_len);
        }

        if echo_len > 0 {
            display_write(&echo_buf[..echo_len]);
        }
    }
}

/// TTYD_PTY_READ: try-read from slave side (called by VFS).
/// msg.regs[0] = pty_id, msg.regs[1] = max_count
/// Reply: regs[0] = actual_count (0 = WOULD_BLOCK), regs[1..] = data
unsafe fn handle_pty_read(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let max_count = msg.regs[1] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        let available = pty.slave_ring.len();

        if available > 0 {
            let count = if available < max_count { available } else { max_count };
            let count = if count > 152 { 152 } else { count };
            reply.label = SALTY_OK;
            reply.regs[0] = count as u64;
            reply.length = 1 + ((count as u64 + 7) / 8);
            let dst = &raw mut reply.regs[1] as *mut u8;
            for i in 0..count {
                if let Some(c) = pty.slave_ring.pop() {
                    *dst.add(i) = c;
                }
            }
            pty.vfs_pending = false;
        } else {
            // No data — return WOULD_BLOCK, mark VFS as pending
            reply.label = SALTY_OK;
            reply.regs[0] = 0; // 0 = WOULD_BLOCK
            reply.length = 1;
            pty.vfs_pending = true;
        }
    }
}

/// TTYD_PTY_COLLECT: VFS collects data after notification wake.
/// Same as PTY_READ but called when data is guaranteed available.
unsafe fn handle_pty_collect(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let max_count = msg.regs[1] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        let available = pty.slave_ring.len();
        let count = if available < max_count { available } else { max_count };
        let count = if count > 152 { 152 } else { count };

        reply.label = SALTY_OK;
        reply.regs[0] = count as u64;
        reply.length = 1 + ((count as u64 + 7) / 8);

        let dst = &raw mut reply.regs[1] as *mut u8;
        for i in 0..count {
            if let Some(c) = pty.slave_ring.pop() {
                *dst.add(i) = c;
            }
        }
        pty.vfs_pending = false;
    }
}

/// TTYD_PTY_WRITE: write from slave side (output from bash via VFS).
/// msg.regs[0] = pty_id, msg.regs[1] = byte_count, msg.regs[2..] = data
/// Applies OPOST processing and outputs to serial + display.
unsafe fn handle_pty_write(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let count = msg.regs[1] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        if count == 0 || count > 152 {
            reply.label = SALTY_OK;
            reply.regs[0] = 0;
            reply.length = 1;
            return;
        }

        let pty = &*(&raw const PTYS[pty_id]);
        let src = &msg.regs[2] as *const u64 as *const u8;

        // Apply OPOST processing
        if (pty.termios.c_oflag & OPOST) != 0 {
            let mut buf = [0u8; 256];
            let mut buf_len = 0;
            for i in 0..count {
                let c = *src.add(i);
                // ONLCR: translate NL to CR+NL
                if (pty.termios.c_oflag & ONLCR) != 0 && c == b'\n' {
                    if buf_len < 255 {
                        buf[buf_len] = b'\r';
                        buf_len += 1;
                    }
                }
                if buf_len < 256 {
                    buf[buf_len] = c;
                    buf_len += 1;
                }
            }
            serial::serial_puts(&buf[..buf_len]);
            display_write(&buf[..buf_len]);
        } else {
            // No OPOST: raw output
            let mut buf = [0u8; 152];
            for i in 0..count {
                buf[i] = *src.add(i);
            }
            serial::serial_puts(&buf[..count]);
            display_write(&buf[..count]);
        }

        reply.label = SALTY_OK;
        reply.regs[0] = count as u64;
        reply.length = 1;
    }
}

/// TTYD_PTY_TCGETATTR: get per-PTY termios.
/// msg.regs[0] = pty_id
unsafe fn handle_pty_tcgetattr(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let t = &PTYS[pty_id].termios;
        reply.label = SALTY_OK;
        reply.length = 10;
        reply.regs[0] = t.c_iflag as u64;
        reply.regs[1] = t.c_oflag as u64;
        reply.regs[2] = t.c_cflag as u64;
        reply.regs[3] = t.c_lflag as u64;
        reply.regs[4] = t.c_ispeed as u64;
        reply.regs[5] = t.c_ospeed as u64;
        let dst = &raw mut reply.regs[6] as *mut u8;
        for i in 0..32 {
            *dst.add(i) = t.c_cc[i];
        }
    }
}

/// TTYD_PTY_TCSETATTR: set per-PTY termios.
/// msg.regs[0] = pty_id, msg.regs[1] = action,
/// msg.regs[2..7] = iflag/oflag/cflag/lflag/ispeed/ospeed, msg.regs[8..11] = c_cc
unsafe fn handle_pty_tcsetattr(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let t = &mut (*(&raw mut PTYS[pty_id])).termios;
        t.c_iflag = msg.regs[2] as u32;
        t.c_oflag = msg.regs[3] as u32;
        t.c_cflag = msg.regs[4] as u32;
        t.c_lflag = msg.regs[5] as u32;
        t.c_ispeed = msg.regs[6] as u32;
        t.c_ospeed = msg.regs[7] as u32;
        let src = &msg.regs[8] as *const u64 as *const u8;
        for i in 0..32 {
            t.c_cc[i] = *src.add(i);
        }
        reply.label = SALTY_OK;
        reply.length = 0;
    }
}

/// TTYD_PTY_IOCTL: per-PTY ioctl handling.
/// msg.regs[0] = pty_id, msg.regs[1] = ioctl_cmd, msg.regs[2] = arg, msg.regs[3] = caller_badge
unsafe fn handle_pty_ioctl(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let cmd = msg.regs[1];
        let arg = msg.regs[2];
        let caller_badge = msg.regs[3];

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);

        match cmd {
            TIOCGPGRP => {
                reply.label = SALTY_OK;
                reply.length = 1;
                reply.regs[0] = pty.fg_pgid as u64;
            }
            TIOCSPGRP => {
                // Validate against controlling-tty owner badge.
                if pty.has_ctty && pty.ctty_owner_badge == caller_badge {
                    pty.fg_pgid = arg as u32;
                    reply.label = SALTY_OK;
                    reply.length = 0;
                } else {
                    reply.label = SALTY_INVALID_OPERATION;
                }
            }
            TIOCSCTTY => {
                if pty.has_ctty && pty.ctty_owner_badge != caller_badge {
                    reply.label = SALTY_BUSY;
                    return;
                }
                pty.has_ctty = true;
                pty.ctty_owner_badge = caller_badge;
                reply.label = SALTY_OK;
                reply.length = 0;
            }
            TIOCNOTTY => {
                if pty.has_ctty && pty.ctty_owner_badge == caller_badge {
                    pty.has_ctty = false;
                    pty.ctty_owner_badge = 0;
                    pty.fg_pgid = 0;
                    reply.label = SALTY_OK;
                    reply.length = 0;
                } else {
                    reply.label = SALTY_INVALID_OPERATION;
                }
            }
            TIOCGWINSZ => {
                // Return 80x24 (standard terminal size)
                reply.label = SALTY_OK;
                reply.length = 2;
                reply.regs[0] = 24; // rows
                reply.regs[1] = 80; // cols
            }
            _ => {
                reply.label = SALTY_INVALID_OPERATION;
            }
        }
    }
}

/// TTYD_PTY_POLL: check PTY readiness.
/// msg.regs[0] = pty_id, msg.regs[1] = requested events
/// Reply: regs[0] = ready events
unsafe fn handle_pty_poll(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let events = msg.regs[1] as u32;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let pty = &*(&raw const PTYS[pty_id]);
        let mut rev: u32 = 0;

        if (events & POLLIN) != 0 && !pty.slave_ring.is_empty() {
            rev |= POLLIN;
        }
        if (events & POLLOUT) != 0 {
            rev |= POLLOUT; // always writable
        }
        if pty.master_closed {
            rev |= POLLHUP;
        }

        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = rev as u64;
    }
}

/// Handle legacy TTYD labels (1-4) by redirecting to PTY 0.
unsafe fn handle_legacy(label: u64, msg: &SaltyMsg, reply: &mut SaltyMsg) {
    match label {
        TTYD_GET_FG_PGRP => {
            let caller_badge = msg.regs[0];
            unsafe {
                let pty = &*(&raw const PTYS[0]);
                if !pty.has_ctty || pty.ctty_owner_badge != caller_badge {
                    reply.label = SALTY_INVALID_OPERATION;
                    return;
                }
                reply.label = SALTY_OK;
                reply.length = 1;
                reply.regs[0] = pty.fg_pgid as u64;
            }
        }
        TTYD_SET_FG_PGRP => {
            let caller_badge = msg.regs[0];
            let requested = msg.regs[1] as u32;
            unsafe {
                let pty = &mut *(&raw mut PTYS[0]);
                if !pty.has_ctty || pty.ctty_owner_badge != caller_badge {
                    reply.label = SALTY_INVALID_OPERATION;
                    return;
                }
                pty.fg_pgid = requested;
                reply.label = SALTY_OK;
                reply.length = 0;
            }
        }
        TTYD_SET_CTTY => {
            let caller_badge = msg.regs[0];
            unsafe {
                let pty = &mut *(&raw mut PTYS[0]);
                if pty.has_ctty && pty.ctty_owner_badge != caller_badge {
                    reply.label = SALTY_BUSY;
                    return;
                }
                pty.has_ctty = true;
                pty.ctty_owner_badge = caller_badge;
                reply.label = SALTY_OK;
                reply.length = 0;
            }
        }
        TTYD_DROP_CTTY => {
            let caller_badge = msg.regs[0];
            unsafe {
                let pty = &mut *(&raw mut PTYS[0]);
                if !pty.has_ctty || pty.ctty_owner_badge != caller_badge {
                    reply.label = SALTY_INVALID_OPERATION;
                    return;
                }
                pty.has_ctty = false;
                pty.ctty_owner_badge = 0;
                pty.fg_pgid = 0;
                reply.label = SALTY_OK;
                reply.length = 0;
            }
        }
        _ => {
            reply.label = SALTY_INVALID_OPERATION;
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
    signal_vfs(0);

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
                unsafe { handle_input_event(&msg) };
                // Console used send (not call), no reply expected
                skip_reply = true;
            }
            TTYD_PTY_READ => {
                unsafe { handle_pty_read(&msg, &mut reply) };
            }
            TTYD_PTY_COLLECT => {
                unsafe { handle_pty_collect(&msg, &mut reply) };
            }
            TTYD_PTY_WRITE => {
                unsafe { handle_pty_write(&msg, &mut reply) };
            }
            TTYD_PTY_TCGETATTR => {
                unsafe { handle_pty_tcgetattr(&msg, &mut reply) };
            }
            TTYD_PTY_TCSETATTR => {
                unsafe { handle_pty_tcsetattr(&msg, &mut reply) };
            }
            TTYD_PTY_IOCTL => {
                unsafe { handle_pty_ioctl(&msg, &mut reply) };
            }
            TTYD_PTY_POLL => {
                unsafe { handle_pty_poll(&msg, &mut reply) };
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
                        }
                    }
                }
                reply.label = SALTY_OK;
                reply.length = 0;
            }
            // Legacy labels (backward compat, redirect to PTY 0)
            TTYD_GET_FG_PGRP | TTYD_SET_FG_PGRP | TTYD_SET_CTTY | TTYD_DROP_CTTY => {
                unsafe { handle_legacy(msg.label, &msg, &mut reply) };
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
