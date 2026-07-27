// SPDX-License-Identifier: GPL-2.0-only
//! Line discipline and input processing for PTY.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::*;

use crate::types::*;
use crate::{PTYS, display_write, ipc_ctx, serial_write_queued};

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

/// Send signal to foreground process group via blocking send to procmgr.
/// Uses INIT_KILL_PGID to target an explicit pgid.
///
/// This used to be a fire-and-forget `nbsend` call; `SYS_NBSEND` was
/// retired alongside the per-Endpoint ring. Signal delivery is
/// infrequent (tty control keys) and procmgr handles INIT_KILL_PGID
/// promptly, so a blocking `send` is acceptable here.
pub fn send_signal_pgid(pgid: u32, sig: i32) {
    let mut msg = TronaMsg::zeroed();
    msg.label = INIT_KILL_PGID;
    msg.length = 2;
    msg.regs[0] = pgid as u64;
    msg.regs[1] = sig as u64;
    unsafe {
        ipc::mp_write_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
        );
    }
}

pub fn signal_vfs(pty_id: usize) {
    let vfs = trona_runtime::client::caps::vfs_ep().addr();
    if vfs == 0 {
        return;
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = VFS_POSIX_PTY_READY;
    msg.regs[0] = pty_id as u64;
    msg.length = 1;
    // One-way readiness kick (the reply was always discarded). Non-blocking so
    // the ttysrv reactor never parks on VFS — that blocking call was one side of
    // the VFS↔ttysrv reactor deadlock. A dropped wakeup on a full ring is safe:
    // VFS's `handle_pty_ready` is level-triggered (re-scans every parked PTY
    // reader), so the next input byte / poll re-delivers it; no retain queue.
    unsafe {
        let _ = ipc::mp_write_ctx(ipc_ctx(), vfs, &raw const msg);
    }
}

pub(crate) fn pty_has_readable_data(pty: &PtyInstance) -> bool {
    !pty.slave_ring.is_empty() || !pty.spill_ring.is_empty()
}

pub(crate) fn signal_vfs_if_readable(pty_id: usize, pty: &PtyInstance) {
    if pty.vfs_pending_slave && pty_has_readable_data(pty) {
        signal_vfs(pty_id);
    }
}

pub(crate) fn refill_slave_ring(pty: &mut PtyInstance) {
    while !pty.slave_ring.is_full() {
        let Some(byte) = pty.spill_ring.pop() else {
            break;
        };
        if !pty.slave_ring.push(byte) {
            break;
        }
    }
}

pub(crate) fn push_slave_byte(pty_id: usize, pty: &mut PtyInstance, byte: u8) {
    if pty.slave_ring.push(byte) {
        return;
    }
    if pty.spill_ring.push(byte) {
        if pty.vfs_pending_slave {
            signal_vfs(pty_id);
        }
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
/// Readability kicks are emitted at line-delivery boundaries and once again
/// after each input batch so VFS sees buffered data as level-triggered.
pub unsafe fn process_input_char(
    pty_id: usize,
    c: u8,
    echo_buf: &mut [u8; 64],
    echo_len: &mut usize,
) {
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
                // POSIX: INTR flushes the canonical input queue (termios(3)).
                // Flushing slave_ring/spill_ring too prevents stale bytes from
                // the killed fg_pgrp being consumed by its exec-chain successor
                // (e.g. respawned login reading a stale "root\n").
                if canonical {
                    pty.line.clear();
                    pty.slave_ring.clear();
                    pty.spill_ring.clear();
                }
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
                // POSIX: QUIT flushes the canonical input queue (termios(3)).
                if canonical {
                    pty.line.clear();
                    pty.slave_ring.clear();
                    pty.spill_ring.clear();
                }
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
                // POSIX: SUSP flushes the canonical input queue (termios(3)).
                if canonical {
                    pty.line.clear();
                    pty.slave_ring.clear();
                    pty.spill_ring.clear();
                }
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

/// Drain all available bytes from the console input SHM ring into PTY 0.
/// Called when posix_ttysrv receives `POSIX_TTYSRV_INPUT_KICK` from console.
///
/// # Safety
/// `CONSOLE_INPUT_RING_BASE` must point to a valid mapped SHM ring header.
/// `CONSOLE_INPUT_RING_ACTIVE` must be true before calling.
pub unsafe fn drain_console_input_ring(ring_base: *mut u8, ring_size: usize, ring_hdr_size: usize) {
    unsafe {
        let mut echo_buf = [0u8; 64];
        let mut echo_len: usize = 0;

        loop {
            // tail is written only by us (single consumer); read it without fence.
            let tail = core::ptr::read_volatile(ring_base.add(4) as *const u32) as usize;
            let head = core::ptr::read_volatile(ring_base as *const u32) as usize;
            // Acquire: ensure we observe all data the producer wrote before it
            // advanced head. Fence must be after the head read so data written
            // before head was published is visible before we read ring[tail].
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

            if head == tail {
                break;
            } // ring empty

            let c = core::ptr::read_volatile(ring_base.add(ring_hdr_size).add(tail % ring_size));

            // Release: data read above must complete before we publish the new
            // tail to the producer (so it doesn't reclaim space we haven't read).
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(
                ring_base.add(4) as *mut u32,
                ((tail + 1) % ring_size) as u32,
            );

            process_input_char(0, c, &mut echo_buf, &mut echo_len);
        }

        let pty = &*(&raw const PTYS[0]);
        signal_vfs_if_readable(0, pty);

        if echo_len > 0 {
            display_write(&echo_buf[..echo_len]);
        }
    }
}
