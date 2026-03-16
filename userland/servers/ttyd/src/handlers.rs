// SPDX-License-Identifier: GPL-2.0-only
//! IPC request handlers for PTY operations.

use besalt::consts::*;
use besalt::ipc;
use besalt::serial;
use besalt::types::*;

use crate::types::*;
use crate::{ipc_ctx, PTYS};

fn procmgr_get_pgid_by_badge(badge: u64) -> Option<u32> {
    unsafe {
        let mut msg = BesaltMsg::zeroed();
        let mut reply = BesaltMsg::zeroed();
        msg.label = POSIX_PM_GETPGID_BADGE;
        msg.length = 1;
        msg.regs[0] = badge;

        let err = ipc::call_ctx(ipc_ctx(), CAP_PROCMGR_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != BESALT_OK || reply.length < 1 {
            return None;
        }

        Some(reply.regs[0] as u32)
    }
}

/// TTYD_PTY_READ: try-read from slave side (called by VFS).
/// msg.regs[0] = pty_id, msg.regs[1] = max_count
/// Reply: regs[0] = actual_count (0 = WOULD_BLOCK), regs[1..] = data
pub unsafe fn handle_pty_read(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let max_count = msg.regs[1] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        let available = pty.slave_ring.len();

        if available > 0 {
            let count = if available < max_count { available } else { max_count };
            let count = if count > 152 { 152 } else { count };
            reply.label = BESALT_OK;
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
            // No data -- return WOULD_BLOCK, mark VFS as pending
            reply.label = BESALT_OK;
            reply.regs[0] = 0; // 0 = WOULD_BLOCK
            reply.length = 1;
            pty.vfs_pending = true;
        }
    }
}

/// TTYD_PTY_COLLECT: VFS collects data after notification wake.
/// Same as PTY_READ but called when data is guaranteed available.
pub unsafe fn handle_pty_collect(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let max_count = msg.regs[1] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        let available = pty.slave_ring.len();
        let count = if available < max_count { available } else { max_count };
        let count = if count > 152 { 152 } else { count };

        reply.label = BESALT_OK;
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
pub unsafe fn handle_pty_write(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let count = msg.regs[1] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = BESALT_INVALID_ARGUMENT;
            return;
        }
        if count == 0 || count > 152 {
            reply.label = BESALT_OK;
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
            crate::display_write(&buf[..buf_len]);
        } else {
            // No OPOST: raw output
            let mut buf = [0u8; 152];
            for i in 0..count {
                buf[i] = *src.add(i);
            }
            serial::serial_puts(&buf[..count]);
            crate::display_write(&buf[..count]);
        }

        reply.label = BESALT_OK;
        reply.regs[0] = count as u64;
        reply.length = 1;
    }
}

/// TTYD_PTY_TCGETATTR: get per-PTY termios.
/// msg.regs[0] = pty_id
pub unsafe fn handle_pty_tcgetattr(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = BESALT_INVALID_ARGUMENT;
            return;
        }
        let t = &PTYS[pty_id].termios;
        reply.label = BESALT_OK;
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
pub unsafe fn handle_pty_tcsetattr(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = BESALT_INVALID_ARGUMENT;
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
        reply.label = BESALT_OK;
        reply.length = 0;
    }
}

/// TTYD_PTY_IOCTL: per-PTY ioctl handling.
/// msg.regs[0] = pty_id, msg.regs[1] = ioctl_cmd, msg.regs[2] = arg, msg.regs[3] = caller_badge
pub unsafe fn handle_pty_ioctl(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let cmd = msg.regs[1];
        let arg = msg.regs[2];
        let caller_badge = msg.regs[3];

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);

        match cmd {
            TIOCGPGRP => {
                // Return cached fg_pgid directly. Do NOT call procmgr here —
                // VFS→ttyd→procmgr creates a deadlock cycle when procmgr is
                // blocked on VFS (e.g., during exec binary loading).
                //
                // Stale pgid cleanup is handled by:
                // - TIOCSCTTY: resets dead owner on session takeover
                // - TIOCSPGRP: caller sets fg_pgid authoritatively
                reply.label = BESALT_OK;
                reply.length = 1;
                reply.regs[0] = pty.fg_pgid as u64;
            }
            TIOCSPGRP => {
                if pty.has_ctty && pty.ctty_owner_badge == caller_badge {
                    pty.fg_pgid = arg as u32;
                    reply.label = BESALT_OK;
                    reply.length = 0;
                } else {
                    reply.label = BESALT_INVALID_OPERATION;
                }
            }
            TIOCSCTTY => {
                if pty.has_ctty && pty.ctty_owner_badge != caller_badge {
                    let old_alive =
                        procmgr_get_pgid_by_badge(pty.ctty_owner_badge).is_some();
                    if old_alive {
                        reply.label = BESALT_BUSY;
                        return;
                    }
                    // Old owner is dead -- reset and allow takeover
                    pty.fg_pgid = 0;
                }
                let newly_acquired = !pty.has_ctty || pty.fg_pgid == 0;
                pty.has_ctty = true;
                pty.ctty_owner_badge = caller_badge;
                if newly_acquired {
                    if let Some(pgid) = procmgr_get_pgid_by_badge(caller_badge) {
                        pty.fg_pgid = pgid;
                    } else if caller_badge != 0 && caller_badge <= u32::MAX as u64 {
                        pty.fg_pgid = caller_badge as u32;
                    }
                }
                reply.label = BESALT_OK;
                reply.length = 0;
            }
            TIOCNOTTY => {
                if pty.has_ctty && pty.ctty_owner_badge == caller_badge {
                    pty.has_ctty = false;
                    pty.ctty_owner_badge = 0;
                    pty.fg_pgid = 0;
                    reply.label = BESALT_OK;
                    reply.length = 0;
                } else {
                    reply.label = BESALT_INVALID_OPERATION;
                }
            }
            TIOCGWINSZ => {
                // Return actual display dimensions (queried from display server at startup)
                reply.label = BESALT_OK;
                reply.length = 2;
                reply.regs[0] = *(&raw const crate::types::WINSIZE_ROWS) as u64;
                reply.regs[1] = *(&raw const crate::types::WINSIZE_COLS) as u64;
            }
            _ => {
                reply.label = BESALT_INVALID_OPERATION;
            }
        }
    }
}

/// TTYD_PTY_POLL: check PTY readiness.
/// msg.regs[0] = pty_id, msg.regs[1] = requested events
/// Reply: regs[0] = ready events
pub unsafe fn handle_pty_poll(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let events = msg.regs[1] as u32;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let pty = &*(&raw const PTYS[pty_id]);
        let mut rev: u32 = 0;

        if (events & POLLIN as u32) != 0 && !pty.slave_ring.is_empty() {
            rev |= POLLIN as u32;
        }
        if (events & POLLOUT as u32) != 0 {
            rev |= POLLOUT as u32; // always writable
        }
        if pty.master_closed {
            rev |= POLLHUP as u32;
        }

        reply.label = BESALT_OK;
        reply.length = 1;
        reply.regs[0] = rev as u64;
    }
}

/// Handle legacy TTYD labels (1-4) by redirecting to PTY 0.
pub unsafe fn handle_legacy(label: u64, msg: &BesaltMsg, reply: &mut BesaltMsg) {
    match label {
        TTYD_GET_FG_PGRP => {
            let caller_badge = msg.regs[0];
            unsafe {
                let pty = &*(&raw const PTYS[0]);
                if !pty.has_ctty || pty.ctty_owner_badge != caller_badge {
                    reply.label = BESALT_INVALID_OPERATION;
                    return;
                }
                reply.label = BESALT_OK;
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
                    reply.label = BESALT_INVALID_OPERATION;
                    return;
                }
                pty.fg_pgid = requested;
                reply.label = BESALT_OK;
                reply.length = 0;
            }
        }
        TTYD_SET_CTTY => {
            let caller_badge = msg.regs[0];
            unsafe {
                let pty = &mut *(&raw mut PTYS[0]);
                if pty.has_ctty && pty.ctty_owner_badge != caller_badge {
                    let old_alive =
                        procmgr_get_pgid_by_badge(pty.ctty_owner_badge).is_some();
                    if old_alive {
                        reply.label = BESALT_BUSY;
                        return;
                    }
                    pty.fg_pgid = 0;
                }
                pty.has_ctty = true;
                pty.ctty_owner_badge = caller_badge;
                reply.label = BESALT_OK;
                reply.length = 0;
            }
        }
        TTYD_DROP_CTTY => {
            let caller_badge = msg.regs[0];
            unsafe {
                let pty = &mut *(&raw mut PTYS[0]);
                if !pty.has_ctty || pty.ctty_owner_badge != caller_badge {
                    reply.label = BESALT_INVALID_OPERATION;
                    return;
                }
                pty.has_ctty = false;
                pty.ctty_owner_badge = 0;
                pty.fg_pgid = 0;
                reply.label = BESALT_OK;
                reply.length = 0;
            }
        }
        _ => {
            reply.label = BESALT_INVALID_OPERATION;
        }
    }
}
