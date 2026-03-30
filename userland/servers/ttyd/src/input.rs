// SPDX-License-Identifier: GPL-2.0-only
//! Line discipline and input processing for PTY.

use trona::consts::*;
use trona::ipc;
use trona::types::*;

use crate::types::*;
use crate::{ipc_ctx, display_write, serial_write_queued, PTYS};

/// Echo a control character as ^X to serial.
pub fn echo_ctrl_serial(c: u8) {
    serial_write_queued(&[b'^', c + 0x40]);
}

/// Push a byte to the display echo buffer, flushing if full.
pub fn echo_push(buf: &mut [u8; 64], len: &mut usize, c: u8) {
    if *len >= 64 {
        display_write(&buf[..*len]);
        *len = 0;
    }
    buf[*len] = c;
    *len += 1;
}

/// Emit a destructive backspace for display output (`\b \b`).
fn echo_backspace_erase(buf: &mut [u8; 64], len: &mut usize) {
    echo_push(buf, len, 0x08);
    echo_push(buf, len, b' ');
    echo_push(buf, len, 0x08);
}

/// Write a byte slice with CR/LF translation to serial (queued).
pub fn serial_puts_opost(s: &[u8]) {
    let mut buf = [0u8; 80];
    let mut buf_len = 0;
    for &c in s {
        if c == b'\n' {
            buf[buf_len] = b'\r';
            buf_len += 1;
            if buf_len >= buf.len() {
                serial_write_queued(&buf[..buf_len]);
                buf_len = 0;
            }
        }
        buf[buf_len] = c;
        buf_len += 1;
        if buf_len >= buf.len() {
            serial_write_queued(&buf[..buf_len]);
            buf_len = 0;
        }
    }
    if buf_len > 0 {
        serial_write_queued(&buf[..buf_len]);
    }
}

/// Send signal to foreground process group via nbsend to procmgr (fire-and-forget).
/// Uses POSIX_PM_KILL_PGID to target an explicit pgid.
pub fn send_signal_pgid(pgid: u32, sig: i32) {
    let mut msg = TronaMsg::zeroed();
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
pub fn signal_vfs(pty_id: usize) {
    let _r = trona::syscall::syscall(
        trona::SYS_SIGNAL,
        CAP_VFS_NTFN,
        1u64 << pty_id as u64,
        0, 0, 0, 0,
    );
}

pub(crate) fn pty_has_readable_data(pty: &PtyInstance) -> bool {
    !pty.slave_ring.is_empty() || !pty.spill_ring.is_empty()
}

pub(crate) fn signal_vfs_if_readable(pty_id: usize, pty: &PtyInstance) {
    if pty_has_readable_data(pty) {
        signal_vfs(pty_id);
    }
}

pub(crate) fn refill_slave_ring(pty: &mut PtyInstance) {
    while !pty.slave_ring.is_full() {
        let Some(byte) = pty.spill_ring.pop() else { break };
        if !pty.slave_ring.push(byte) {
            break;
        }
    }
}

fn push_slave_byte(pty_id: usize, pty: &mut PtyInstance, byte: u8) {
    if pty.slave_ring.push(byte) {
        return;
    }
    if pty.spill_ring.push(byte) {
        signal_vfs(pty_id);
        return;
    }
    serial_write_queued(b"[TTYD] WARN: input queues full, input dropped\n");
}

/// Flush line buffer contents into the slave ring.
pub fn flush_line_to_ring(pty_id: usize, pty: &mut PtyInstance) {
    let line_len = pty.line.len;
    let mut buf = [0u8; LINE_BUF_SIZE];
    let mut i = 0usize;
    while i < line_len {
        buf[i] = pty.line.buf[i];
        i += 1;
    }
    for byte in &buf[..line_len] {
        push_slave_byte(pty_id, pty, *byte);
    }
    pty.line.clear();
}

/// Process a single input character through the line discipline for a PTY.
/// Readability notifications are emitted at line-delivery boundaries and once
/// again after each input batch so VFS sees buffered data as level-triggered.
pub unsafe fn process_input_char(pty_id: usize, c: u8, echo_buf: &mut [u8; 64], echo_len: &mut usize) {
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
                    serial_write_queued(b"\r\n");
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
                    serial_write_queued(b"\r\n");
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
                    serial_write_queued(b"\r\n");
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
                        serial_write_queued(b"\x08 \x08");
                        echo_backspace_erase(echo_buf, echo_len);
                    }
                }
                return;
            }

            // Kill line (Ctrl-U)
            if ch == pty.termios.c_cc[VKILL] {
                if (pty.termios.c_lflag & ECHOK) != 0 || (pty.termios.c_lflag & ECHOKE) != 0 {
                    for _ in 0..pty.line.len {
                        serial_write_queued(b"\x08 \x08");
                        echo_backspace_erase(echo_buf, echo_len);
                    }
                }
                pty.line.clear();
                return;
            }

            // EOF (Ctrl-D)
            if ch == pty.termios.c_cc[VEOF] {
                flush_line_to_ring(pty_id, pty);
                signal_vfs_if_readable(pty_id, pty);
                return;
            }

            // Newline (Enter)
            if ch == b'\n' {
                pty.line.push(b'\n');
                if do_echo || (pty.termios.c_lflag & ECHONL) != 0 {
                    serial_write_queued(b"\r\n");
                    echo_push(echo_buf, echo_len, b'\n');
                }
                flush_line_to_ring(pty_id, pty);
                signal_vfs_if_readable(pty_id, pty);
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
                        serial_write_queued(&[ch]);
                        echo_push(echo_buf, echo_len, ch);
                    }
                }
            }
            // Flush if line buffer is full
            if pty.line.len >= LINE_BUF_SIZE {
                flush_line_to_ring(pty_id, pty);
                signal_vfs_if_readable(pty_id, pty);
            }
        } else {
            // === RAW MODE ===
            if do_echo {
                serial_write_queued(&[ch]);
                echo_push(echo_buf, echo_len, ch);
            }
            push_slave_byte(pty_id, pty, ch);
        }
    }
}

/// TTYD_INPUT_EVENT: raw bytes from console server.
/// msg.regs[0] = byte_count, msg.regs[1..] = packed bytes.
pub unsafe fn handle_input_event(msg: &TronaMsg) {
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

        let pty = &*(&raw const PTYS[0]);
        signal_vfs_if_readable(0, pty);

        if echo_len > 0 {
            display_write(&echo_buf[..echo_len]);
        }
    }
}
