//! SaltyOS Console Server — Input Source + Output Sink
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Handles hardware I/O for COM1 serial and PS/2 keyboard.
//! Forwards raw input bytes to ttyd via TTYD_INPUT_EVENT.
//! Handles CONSOLE_WRITE for direct serial + display output.
//!
//! Line discipline, termios, and signal delivery are handled by ttyd.

#![no_std]
#![no_main]

extern crate besalt;

mod kbd;

use besalt::consts::*;
use besalt::invoke;
use besalt::ipc;
use besalt::serial;
use besalt::types::*;

use kbd::KbdState;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// Cap layout (set up by init for the console server)
const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 3;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_IOPORT: u64 = 64;     // COM1 IoPort (CopyCap 8:64)
const CAP_IRQ: u64 = 65;        // COM1 IRQ handler (CopyCap 9:65)
const CAP_NTFN: u64 = 66;       // COM1+PS/2 IRQ notification (CopyCap 10:66)
const CAP_TTYD_EP: u64 = 67;    // TTYD endpoint (NeedEP ttyd:67)
const CAP_DISPLAY_EP: u64 = 68; // Display EP (NeedEP display:68)
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

// termios flag defaults (match ttyd canonical defaults)
const ISIG: u32 = 0o000001;
const ICANON: u32 = 0o000002;
const ECHO: u32 = 0o000010;
const ECHOE: u32 = 0o000020;
const ECHOK: u32 = 0o000040;
const ECHOCTL: u32 = 0o001000;
const ECHOKE: u32 = 0o004000;
const IEXTEN: u32 = 0o100000;
const ICRNL: u32 = 0o000400;
const IXON: u32 = 0o002000;
const OPOST: u32 = 0o000001;
const ONLCR: u32 = 0o000004;
const CS8: u32 = 0o000060;
const CREAD: u32 = 0o000200;
const CLOCAL: u32 = 0o004000;
const B38400: u32 = 38400;

const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VMIN: usize = 6;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VSUSP: usize = 10;

static mut CONSOLE_TERMIOS: Termios = Termios::zeroed();
const DISPLAY_TX_BUF_SIZE: usize = 16384;
const DISPLAY_TX_CHUNK_MAX: usize = 152;

static mut DISPLAY_TX_BUF: [u8; DISPLAY_TX_BUF_SIZE] = [0; DISPLAY_TX_BUF_SIZE];
static mut DISPLAY_TX_HEAD: usize = 0;
static mut DISPLAY_TX_TAIL: usize = 0;

// ======================================================================
// Helpers
// ======================================================================

fn ipc_ctx() -> *mut IpcContext {
    &raw mut besalt::__besalt_ipc_ctx
}

unsafe fn init_console_termios() {
    unsafe {
        let t = &raw mut CONSOLE_TERMIOS;
        (*t).c_iflag = ICRNL | IXON;
        (*t).c_oflag = OPOST | ONLCR;
        (*t).c_cflag = CS8 | CREAD | CLOCAL;
        (*t).c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN | ECHOCTL | ECHOKE;
        (*t).c_line = 0;
        (*t).c_ispeed = B38400;
        (*t).c_ospeed = B38400;
        (*t).c_cc = [0; 32];
        (*t).c_cc[VINTR] = 3;
        (*t).c_cc[VQUIT] = 28;
        (*t).c_cc[VERASE] = 127;
        (*t).c_cc[VKILL] = 21;
        (*t).c_cc[VEOF] = 4;
        (*t).c_cc[VMIN] = 1;
        (*t).c_cc[VSTART] = 17;
        (*t).c_cc[VSTOP] = 19;
        (*t).c_cc[VSUSP] = 26;
    }
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

fn signal_ready() {
    let _ = besalt::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
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

/// Forward output to the display server.
/// Uses a queued nbsend fast path and a true blocking send fallback to
/// preserve terminal stream ordering under display backpressure.
fn display_write(data: &[u8]) {
    if data.is_empty() { return; }
    unsafe {
        display_tx_enqueue(data);
        display_try_flush();
        if !display_tx_is_empty() {
            let _ = display_flush_blocking_one();
        }
    }
}

unsafe fn display_flush_blocking_all() {
    unsafe {
        while !display_tx_is_empty() {
            if !display_flush_blocking_one() {
                break;
            }
        }
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
                    return;
                }
            }

            let free = display_tx_free();
            if free == 0 {
                continue;
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

        let err = ipc::send_ctx(ipc_ctx(), CAP_DISPLAY_EP, &raw const msg);
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
            // Backpressure — keep queued, try again next iteration.
            break;
        }
    }
}

/// Forward raw input bytes to ttyd in bounded chunks.
/// Uses nbsend first, then applies blocking backpressure if ttyd is saturated.
fn forward_to_ttyd(raw: &[u8], raw_len: usize) {
    if raw_len == 0 { return; }
    let mut offset = 0usize;
    while offset < raw_len {
        let chunk_len = core::cmp::min(raw_len - offset, 128);
        let mut fwd = BesaltMsg::zeroed();
        fwd.label = TTYD_INPUT_EVENT;
        fwd.regs[0] = chunk_len as u64;
        fwd.length = 1 + ((chunk_len as u64 + 7) / 8);
        let dst = &raw mut fwd.regs[1] as *mut u8;
        unsafe {
            for i in 0..chunk_len {
                *dst.add(i) = raw[offset + i];
            }
            let mut err = ipc::nbsend_ctx(ipc_ctx(), CAP_TTYD_EP, &raw const fwd);
            if err != 0 {
                err = ipc::send_ctx(ipc_ctx(), CAP_TTYD_EP, &raw const fwd);
            }
            if err != 0 {
                serial::serial_puts(b"[CONSOLE] FAIL: ttyd input send failed\n");
                return;
            }
        }
        offset += chunk_len;
    }
}

unsafe fn handle_write(msg: *const BesaltMsg) {
    unsafe {
        let mut len = (*msg).regs[0];
        if len > 24 { len = 24; }
        let data = core::slice::from_raw_parts(
            &(*msg).regs[1] as *const u64 as *const u8,
            len as usize,
        );
        console_puts(data);
        display_write(data);
        display_flush_blocking_all();
    }
}

unsafe fn handle_tcgetattr(reply: *mut BesaltMsg) {
    unsafe {
        let t = &raw const CONSOLE_TERMIOS;
        (*reply).label = BESALT_OK;
        (*reply).length = 10;
        (*reply).regs[0] = (*t).c_iflag as u64;
        (*reply).regs[1] = (*t).c_oflag as u64;
        (*reply).regs[2] = (*t).c_cflag as u64;
        (*reply).regs[3] = (*t).c_lflag as u64;
        (*reply).regs[4] = (*t).c_ispeed as u64;
        (*reply).regs[5] = (*t).c_ospeed as u64;
        let dst = &raw mut (*reply).regs[6] as *mut u8;
        for i in 0..32 {
            *dst.add(i) = (*t).c_cc[i];
        }
    }
}

unsafe fn handle_tcsetattr(msg: *const BesaltMsg, reply: *mut BesaltMsg) {
    unsafe {
        // Expected layout from VFS:
        // regs[0]=fd regs[1]=action regs[2..7]=flags/speeds regs[8..11]=c_cc[32]
        if (*msg).length < 11 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let t = &raw mut CONSOLE_TERMIOS;
        (*t).c_iflag = (*msg).regs[2] as u32;
        (*t).c_oflag = (*msg).regs[3] as u32;
        (*t).c_cflag = (*msg).regs[4] as u32;
        (*t).c_lflag = (*msg).regs[5] as u32;
        (*t).c_ispeed = (*msg).regs[6] as u32;
        (*t).c_ospeed = (*msg).regs[7] as u32;
        let src = &(*msg).regs[8] as *const u64 as *const u8;
        for i in 0..32 {
            (*t).c_cc[i] = *src.add(i);
        }

        (*reply).label = BESALT_OK;
        (*reply).length = 0;
    }
}

// ======================================================================
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    com1_init();
    serial::serial_puts(b"[CONSOLE] SaltyOS console server ready\n");

    unsafe {
        invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
        init_console_termios();

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
    signal_ready();

    let mut kbd = KbdState::new();
    let mut msg = BesaltMsg::zeroed();
    let mut badge: u64 = 0;

    // Initial recv
    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        serial::serial_puts(b"[CONSOLE] initial recv failed\n");
        idle();
    }

    loop {
        unsafe { display_try_flush(); }

        // Bound notifications have label=0 and length=0.
        // Regular IPC may carry a non-zero badge (sender badge).
        if badge != 0 && msg.label == 0 && msg.length == 0 {
            // Notification: drain COM1 and PS/2 input, forward to ttyd.
            let mut raw_buf = [0u8; 256];
            let mut raw_len = 0;

            // COM1 input
            loop {
                let lsr = invoke::ioport_in8(CAP_IOPORT, COM1_LSR);
                if (lsr & LSR_DR) == 0 { break; }
                let c = invoke::ioport_in8(CAP_IOPORT, COM1_RBR);
                if raw_len < 256 {
                    raw_buf[raw_len] = c;
                    raw_len += 1;
                }
            }
            invoke::irq_handler_ack(CAP_IRQ);

            // PS/2 keyboard input
            loop {
                let status = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_STATUS);
                if (status & PS2_STATUS_OUTPUT_FULL) == 0 { break; }
                let scancode = invoke::ioport_in8(CAP_KBD_IOPORT, PS2_DATA);
                let key = kbd.translate(scancode);
                for i in 0..key.len as usize {
                    if raw_len < 256 {
                        raw_buf[raw_len] = key.bytes[i];
                        raw_len += 1;
                    }
                }
            }
            invoke::irq_handler_ack(CAP_KBD_IRQ);

            // Forward raw bytes to ttyd
            forward_to_ttyd(&raw_buf, raw_len);
            unsafe { display_try_flush(); }

            // Wait for next event
            let err = unsafe {
                ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
            };
            if err != 0 {
                serial::serial_puts(b"[CONSOLE] recv failed after IRQ\n");
                break;
            }
            continue;
        }

        // IPC message
        let mut reply = BesaltMsg::zeroed();

        match msg.label {
            CONSOLE_WRITE => {
                unsafe { handle_write(&raw const msg) };
                reply.label = BESALT_OK;
            }
            CONSOLE_TCGETATTR => {
                unsafe { handle_tcgetattr(&raw mut reply) };
            }
            CONSOLE_TCSETATTR => {
                unsafe { handle_tcsetattr(&raw const msg, &raw mut reply) };
            }
            _ => {
                reply.label = BESALT_INVALID_OPERATION;
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
        besalt::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
