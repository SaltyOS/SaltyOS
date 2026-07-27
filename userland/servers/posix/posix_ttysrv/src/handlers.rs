// SPDX-License-Identifier: GPL-2.0-only
//! IPC request handlers for PTY operations.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_protocol::common::{
    TRONA_BUSY, TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_NOT_FOUND, TRONA_OK,
};
use trona_protocol::posix::*;

use crate::PTYS;
use crate::input::{
    pty_has_readable_data, push_slave_byte, refill_slave_ring, signal_vfs_if_readable,
};
use crate::types::*;

const PTY_SIDE_SLAVE: u64 = 0;
const PTY_SIDE_MASTER: u64 = 1;

fn pty_has_master_readable_data(pty: &PtyInstance) -> bool {
    !pty.master_ring.is_empty()
}

fn signal_vfs_if_master_readable(pty_id: usize, pty: &PtyInstance) {
    if pty.vfs_pending_master && pty_has_master_readable_data(pty) {
        crate::input::signal_vfs(pty_id);
    }
}

fn reset_allocated_pty(pty: &mut PtyInstance, active: bool) {
    pty.active = active;
    pty.slave_ring.clear();
    pty.spill_ring.clear();
    pty.master_ring.clear();
    pty.line.clear();
    pty.termios = PtyTermios::default();
    pty.has_ctty = false;
    pty.ctty_session_id = 0;
    pty.fg_pgid = 0;
    pty.vfs_pending_slave = false;
    pty.vfs_pending_master = false;
    // Bump generation on every (re)allocation so stale devfs vdata
    // holding the old generation is rejected by handle_pty_open_slave.
    pty.generation = pty.generation.wrapping_add(1);
    // An active PTY starts with master already open via PTY_ALLOC
    // (ptmx fd held by the allocator). Slave opens are counted
    // independently via PTY_OPEN_SLAVE emitted from devfs whenever
    // `/dev/pts/N` is opened. Both counts decrement on PTY_CLOSE
    // and the slot is reset when both reach zero. Inactive teardown
    // zeros both so the next allocation starts clean.
    if active {
        pty.master_open_count = 1;
        pty.slave_open_count = 0;
    } else {
        pty.master_open_count = 0;
        pty.slave_open_count = 0;
    }
}

fn push_master_byte(pty_id: usize, pty: &mut PtyInstance, byte: u8) {
    if !pty.master_ring.push(byte) {
        return;
    }
    signal_vfs_if_master_readable(pty_id, pty);
}

fn read_ring_into_reply(ring: &mut RingBuf, max_count: usize, reply: &mut TronaMsg) {
    let available = ring.len();
    let count = if available < max_count {
        available
    } else {
        max_count
    };
    let count = if count > 152 { 152 } else { count };

    reply.label = TRONA_OK;
    reply.regs[0] = count as u64;
    reply.length = 1 + ((count as u64 + 7) / 8);

    let dst = &raw mut reply.regs[1] as *mut u8;
    for i in 0..count {
        if let Some(c) = ring.pop() {
            unsafe {
                *dst.add(i) = c;
            }
        }
    }
}

pub unsafe fn handle_pty_alloc(reply: &mut TronaMsg) {
    unsafe {
        for pty_id in 1..MAX_PTYS {
            let pty = &mut *(&raw mut PTYS[pty_id]);
            // Skip still-in-use slots — either count above zero means
            // at least one side still holds an OFD and the slot is
            // not reclaimable.
            if pty.active && (pty.master_open_count > 0 || pty.slave_open_count > 0) {
                continue;
            }

            reset_allocated_pty(pty, true);
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = pty_id as u64;
            return;
        }

        reply.label = TRONA_BUSY;
    }
}

/// POSIX_TTYSRV_PTY_READ: try-read from slave side (called by VFS).
/// msg.regs[0] = pty_id, msg.regs[1] = max_count
/// Reply: regs[0] = actual_count (0 = WOULD_BLOCK), regs[1..] = data
pub unsafe fn handle_pty_read(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let max_count = msg.regs[1] as usize;
        let side = msg.regs[2];

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        match side {
            PTY_SIDE_MASTER => {
                if pty.master_ring.is_empty() {
                    reply.label = TRONA_OK;
                    reply.regs[0] = 0;
                    reply.length = 1;
                    pty.vfs_pending_master = true;
                    return;
                }
                read_ring_into_reply(&mut pty.master_ring, max_count, reply);
                pty.vfs_pending_master = false;
                signal_vfs_if_master_readable(pty_id, pty);
            }
            _ => {
                refill_slave_ring(pty);
                let available = pty.slave_ring.len();

                if available > 0 {
                    read_ring_into_reply(&mut pty.slave_ring, max_count, reply);
                    refill_slave_ring(pty);
                    pty.vfs_pending_slave = false;
                    signal_vfs_if_readable(pty_id, pty);
                } else {
                    // No data -- return WOULD_BLOCK, mark VFS as pending
                    reply.label = TRONA_OK;
                    reply.regs[0] = 0; // 0 = WOULD_BLOCK
                    reply.length = 1;
                    pty.vfs_pending_slave = true;
                }
            }
        }
    }
}

/// POSIX_TTYSRV_PTY_COLLECT: VFS collects data after VFS_PTY_READY wake.
/// Same as PTY_READ but called when data is guaranteed available.
pub unsafe fn handle_pty_collect(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let max_count = msg.regs[1] as usize;
        let side = if msg.length >= 3 {
            msg.regs[2]
        } else {
            PTY_SIDE_SLAVE
        };

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        if side == PTY_SIDE_MASTER {
            read_ring_into_reply(&mut pty.master_ring, max_count, reply);
            pty.vfs_pending_master = false;
            signal_vfs_if_master_readable(pty_id, pty);
            return;
        }
        refill_slave_ring(pty);
        let available = pty.slave_ring.len();
        let count = if available < max_count {
            available
        } else {
            max_count
        };
        let count = if count > 152 { 152 } else { count };

        reply.label = TRONA_OK;
        reply.regs[0] = count as u64;
        reply.length = 1 + ((count as u64 + 7) / 8);

        let dst = &raw mut reply.regs[1] as *mut u8;
        for i in 0..count {
            if let Some(c) = pty.slave_ring.pop() {
                *dst.add(i) = c;
            }
        }
        refill_slave_ring(pty);
        pty.vfs_pending_slave = false;
        signal_vfs_if_readable(pty_id, pty);
    }
}

/// POSIX_TTYSRV_PTY_WRITE: write from slave side (output from bash via VFS).
/// msg.regs[0] = pty_id, msg.regs[1] = byte_count, msg.regs[2..] = data
/// Applies OPOST processing and outputs to serial + display.
pub unsafe fn handle_pty_write(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let count = msg.regs[1] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }
        if count == 0 || count > 152 {
            reply.label = TRONA_OK;
            reply.regs[0] = 0;
            reply.length = 1;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        let src = &msg.regs[2] as *const u64 as *const u8;

        // Console PTY keeps driving the visible terminal.
        if pty_id == 0 {
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
                crate::display_write(&buf[..buf_len]);
                crate::serial_write_queued(&buf[..buf_len]);
            } else {
                // No OPOST: raw output
                let mut buf = [0u8; 152];
                for i in 0..count {
                    buf[i] = *src.add(i);
                }
                crate::display_write(&buf[..count]);
                crate::serial_write_queued(&buf[..count]);
            }
        } else {
            for i in 0..count {
                let c = *src.add(i);
                if (pty.termios.c_oflag & OPOST) != 0
                    && (pty.termios.c_oflag & ONLCR) != 0
                    && c == b'\n'
                {
                    push_master_byte(pty_id, pty, b'\r');
                }
                push_master_byte(pty_id, pty, c);
            }
        }
        reply.label = TRONA_OK;
        reply.regs[0] = count as u64;
        reply.length = 1;
    }
}

pub unsafe fn handle_pty_master_write(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let count = msg.regs[1] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }
        if count == 0 || count > 152 {
            reply.label = TRONA_OK;
            reply.regs[0] = 0;
            reply.length = 1;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        let src = &msg.regs[2] as *const u64 as *const u8;
        for i in 0..count {
            push_slave_byte(pty_id, pty, *src.add(i));
        }
        signal_vfs_if_readable(pty_id, pty);

        reply.label = TRONA_OK;
        reply.regs[0] = count as u64;
        reply.length = 1;
    }
}

/// POSIX_TTYSRV_PTY_LOOKUP: query whether a PTY slot is active.
/// Request: regs[0] = pty_id.
/// Reply on success: regs[0] = generation (u32 promoted to u64).
/// Reply on missing slot: `TRONA_NOT_FOUND`.
pub unsafe fn handle_pty_lookup(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_NOT_FOUND;
            return;
        }

        let pty = &*(&raw const PTYS[pty_id]);
        reply.label = TRONA_OK;
        reply.length = 1;
        reply.regs[0] = pty.generation as u64;
    }
}

/// POSIX_TTYSRV_PTY_OPEN_SLAVE: emitted by devfs when `/dev/pts/N` is
/// opened. Increments the slave-side open count so PTY teardown waits
/// for every slave OFD to drop. The caller passes the generation it
/// captured at lookup time — mismatch means the slot was recycled
/// while the vdata was stale, and we reject the open cleanly.
pub unsafe fn handle_pty_open_slave(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let expected_generation = msg.regs[1] as u32;

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_NOT_FOUND;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        if pty.generation != expected_generation {
            reply.label = TRONA_NOT_FOUND;
            return;
        }
        pty.slave_open_count = pty.slave_open_count.saturating_add(1);

        reply.label = TRONA_OK;
        reply.length = 0;
    }
}

pub unsafe fn handle_pty_close(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let side = msg.regs[1];

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        if side == PTY_SIDE_MASTER {
            pty.master_open_count = pty.master_open_count.saturating_sub(1);
        } else {
            pty.slave_open_count = pty.slave_open_count.saturating_sub(1);
        }

        // PTY 0 is the console — never tear it down; only clean up
        // user-allocated PTY slots once both sides have closed their
        // last OFD reference.
        if pty.master_open_count == 0 && pty.slave_open_count == 0 && pty_id != 0 {
            reset_allocated_pty(pty, false);
        }

        reply.label = TRONA_OK;
        reply.length = 0;
    }
}

/// POSIX_TTYSRV_PTY_TCGETATTR: get per-PTY termios.
/// msg.regs[0] = pty_id
pub unsafe fn handle_pty_tcgetattr(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let t = &PTYS[pty_id].termios;
        reply.label = TRONA_OK;
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

/// POSIX_TTYSRV_PTY_TCSETATTR: set per-PTY termios.
/// msg.regs[0] = pty_id, msg.regs[1] = action,
/// msg.regs[2..7] = iflag/oflag/cflag/lflag/ispeed/ospeed, msg.regs[8..11] = c_cc
pub unsafe fn handle_pty_tcsetattr(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
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
        reply.label = TRONA_OK;
        reply.length = 0;
    }
}

/// POSIX_TTYSRV_PTY_IOCTL: per-PTY ioctl handling.
/// msg.regs[0] = pty_id, msg.regs[1] = ioctl_cmd, msg.regs[2] = arg,
/// msg.regs[3] = caller_sid, msg.regs[4] = caller_pgid
pub unsafe fn handle_pty_ioctl(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let cmd = msg.regs[1];
        let arg = msg.regs[2];
        let caller_sid = msg.regs[3];
        let caller_pgid = msg.regs[4];

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);

        match cmd {
            TIOCGPGRP => {
                // Return cached fg_pgid directly. Do NOT call procmgr here —
                // VFS→posix_ttysrv→procmgr creates a deadlock cycle when procmgr is
                // blocked on VFS (e.g., during exec binary loading).
                //
                // Stale pgid cleanup is handled by:
                // - TIOCSCTTY: resets dead owner on session takeover
                // - TIOCSPGRP: caller sets fg_pgid authoritatively
                reply.label = TRONA_OK;
                reply.length = 1;
                reply.regs[0] = pty.fg_pgid as u64;
            }
            TIOCSPGRP => {
                if pty.has_ctty && pty.ctty_session_id == caller_sid {
                    pty.fg_pgid = arg as u32;
                    reply.label = TRONA_OK;
                    reply.length = 0;
                } else {
                    reply.label = TRONA_INVALID_OPERATION;
                }
            }
            TIOCGSID => {
                reply.label = TRONA_OK;
                reply.length = 1;
                reply.regs[0] = pty.ctty_session_id;
            }
            TIOCSCTTY => {
                if pty.has_ctty && pty.ctty_session_id != caller_sid {
                    pty.fg_pgid = 0;
                }
                let newly_acquired = !pty.has_ctty || pty.fg_pgid == 0;
                pty.has_ctty = true;
                pty.ctty_session_id = caller_sid;
                if newly_acquired {
                    if caller_pgid != 0 && caller_pgid <= u32::MAX as u64 {
                        pty.fg_pgid = caller_pgid as u32;
                    }
                }
                reply.label = TRONA_OK;
                reply.length = 0;
            }
            TIOCNOTTY => {
                if pty.has_ctty && pty.ctty_session_id == caller_sid {
                    pty.has_ctty = false;
                    pty.ctty_session_id = 0;
                    pty.fg_pgid = 0;
                    reply.label = TRONA_OK;
                    reply.length = 0;
                } else {
                    reply.label = TRONA_INVALID_OPERATION;
                }
            }
            TIOCGWINSZ => {
                // Return actual display dimensions (queried from display server at startup)
                reply.label = TRONA_OK;
                reply.length = 2;
                reply.regs[0] = *(&raw const crate::types::WINSIZE_ROWS) as u64;
                reply.regs[1] = *(&raw const crate::types::WINSIZE_COLS) as u64;
            }
            TIOCSWINSZ => {
                *(&raw mut crate::types::WINSIZE_ROWS) = arg as u32;
                *(&raw mut crate::types::WINSIZE_COLS) = caller_sid as u32;
                reply.label = TRONA_OK;
                reply.length = 0;
            }
            _ => {
                reply.label = TRONA_INVALID_OPERATION;
            }
        }
    }
}

/// POSIX_TTYSRV_PTY_POLL: check PTY readiness.
/// msg.regs[0] = pty_id, msg.regs[1] = requested events
/// Reply: regs[0] = ready events
pub unsafe fn handle_pty_poll(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pty_id = msg.regs[0] as usize;
        let events = msg.regs[1] as u32;
        let side = msg.regs[2];

        if pty_id >= MAX_PTYS || !PTYS[pty_id].active {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let pty = &mut *(&raw mut PTYS[pty_id]);
        let mut rev: u32 = 0;

        if side == PTY_SIDE_MASTER {
            if (events & POLLIN as u32) != 0 && pty_has_master_readable_data(pty) {
                rev |= POLLIN as u32;
            }
            if (events & POLLOUT as u32) != 0 {
                rev |= POLLOUT as u32;
            }
            if pty.slave_open_count == 0 {
                rev |= POLLHUP as u32;
            }
        } else {
            refill_slave_ring(pty);
            if (events & POLLIN as u32) != 0 && pty_has_readable_data(pty) {
                rev |= POLLIN as u32;
            }
            if (events & POLLOUT as u32) != 0 {
                rev |= POLLOUT as u32; // always writable
            }
            if pty.master_open_count == 0 {
                rev |= POLLHUP as u32;
            }
        }

        reply.label = TRONA_OK;
        reply.length = 1;
        reply.regs[0] = rev as u64;
    }
}

/// Reverse lookup: return the `pty_id` whose controlling-terminal session
/// equals `sid`. VFS resolves the caller's POSIX session id and uses this
/// to answer "what is my ctty tty_dev" and to route `/dev/tty`.
pub unsafe fn handle_ctty_pty_for_sid(msg: &TronaMsg, reply: &mut TronaMsg) {
    let sid = msg.regs[0];
    unsafe {
        for i in 0..MAX_PTYS {
            let pty = &*(&raw const PTYS[i]);
            if pty.active && pty.has_ctty && pty.ctty_session_id == sid {
                reply.label = TRONA_OK;
                reply.length = 1;
                reply.regs[0] = i as u64;
                return;
            }
        }
        reply.label = TRONA_NOT_FOUND;
    }
}

/// `POSIX_TTYSRV_CTTY_DUMP` — return every active session→pty
/// controlling-terminal binding so a caller (vfs) can join `tty_dev`
/// onto a batch of process records in one round-trip (the bulk
/// `kern.proc.*` path). Reply: `regs[0]` = count, then `regs[1 + i]` =
/// `(ctty_session_id in low 32) | (pty_id in high 32)` for each binding.
pub unsafe fn handle_ctty_dump(reply: &mut TronaMsg) {
    unsafe {
        let mut count: u64 = 0;
        for i in 0..MAX_PTYS {
            let pty = &*(&raw const PTYS[i]);
            if pty.active && pty.has_ctty {
                reply.regs[1 + count as usize] =
                    (pty.ctty_session_id & 0xFFFF_FFFF) | ((i as u64) << 32);
                count += 1;
            }
        }
        reply.regs[0] = count;
        reply.label = TRONA_OK;
        reply.length = 1 + count;
    }
}

/// Handle legacy TTYD labels (1-4) by redirecting to PTY 0.
pub unsafe fn handle_legacy(label: u64, msg: &TronaMsg, reply: &mut TronaMsg) {
    match label {
        POSIX_TTYSRV_GET_FG_PGRP => unsafe {
            let pty = &*(&raw const PTYS[0]);
            if !pty.has_ctty {
                reply.label = TRONA_INVALID_OPERATION;
                return;
            }
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = pty.fg_pgid as u64;
        },
        POSIX_TTYSRV_SET_FG_PGRP => {
            let requested = msg.regs[1] as u32;
            unsafe {
                let pty = &mut *(&raw mut PTYS[0]);
                if !pty.has_ctty {
                    reply.label = TRONA_INVALID_OPERATION;
                    return;
                }
                pty.fg_pgid = requested;
                reply.label = TRONA_OK;
                reply.length = 0;
            }
        }
        POSIX_TTYSRV_SET_CTTY => {
            let caller_sid = msg.regs[0];
            let caller_pgid = msg.regs[1];
            unsafe {
                let pty = &mut *(&raw mut PTYS[0]);
                if pty.has_ctty && pty.ctty_session_id != caller_sid {
                    pty.fg_pgid = 0;
                }
                pty.has_ctty = true;
                pty.ctty_session_id = caller_sid;
                if caller_pgid != 0 && caller_pgid <= u32::MAX as u64 {
                    pty.fg_pgid = caller_pgid as u32;
                }
                reply.label = TRONA_OK;
                reply.length = 0;
            }
        }
        POSIX_TTYSRV_DROP_CTTY => {
            let caller_sid = msg.regs[0];
            unsafe {
                let pty = &mut *(&raw mut PTYS[0]);
                if !pty.has_ctty || pty.ctty_session_id != caller_sid {
                    reply.label = TRONA_INVALID_OPERATION;
                    return;
                }
                pty.has_ctty = false;
                pty.ctty_session_id = 0;
                pty.fg_pgid = 0;
                reply.label = TRONA_OK;
                reply.length = 0;
            }
        }
        _ => {
            reply.label = TRONA_INVALID_OPERATION;
        }
    }
}
