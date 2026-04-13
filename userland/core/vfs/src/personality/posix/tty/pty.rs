// SPDX-License-Identifier: GPL-2.0-only
//! PTY deferred-read and notification handlers.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::ipc::timer_wheel::{self, TimerKind};
use crate::ipc_ctx;
use crate::owner::loop_::OWNER_STATE_PTR;
use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::personality::posix::types::*;
use crate::server::client::send_client_exit_error;
use crate::server::consts::*;
use crate::server::types::*;

const VTIME: usize = 5;
const VMIN: usize = 6;
static PTY_TIMER_COOKIE: AtomicU32 = AtomicU32::new(1);
static PTY_TIMER_DEADLINE: AtomicU64 = AtomicU64::new(0);

fn next_pty_timer_cookie() -> u32 {
    PTY_TIMER_COOKIE.fetch_add(1, Ordering::AcqRel).wrapping_add(1)
}

fn arm_pty_deadline(deadline_ns: u64) {
    if deadline_ns == 0 {
        return;
    }
    loop {
        let armed = PTY_TIMER_DEADLINE.load(Ordering::Acquire);
        if armed != 0 && armed <= deadline_ns {
            return;
        }
        if PTY_TIMER_DEADLINE
            .compare_exchange(armed, deadline_ns, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            timer_wheel::register_timer(
                deadline_ns,
                TimerKind::PtyReadTimeout,
                next_pty_timer_cookie(),
            );
            return;
        }
    }
}

pub(super) unsafe fn fetch_pty_termios(pty_id: u64, termios: *mut Termios) -> bool {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = POSIX_TTYSRV_PTY_TCGETATTR;
        req.regs[0] = pty_id;
        req.length = 1;

        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const req, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }

        (*termios).c_iflag = reply.regs[0] as u32;
        (*termios).c_oflag = reply.regs[1] as u32;
        (*termios).c_cflag = reply.regs[2] as u32;
        (*termios).c_lflag = reply.regs[3] as u32;
        (*termios).c_ispeed = reply.regs[4] as u32;
        (*termios).c_ospeed = reply.regs[5] as u32;
        (*termios).c_line = 0;
        let src = &reply.regs[6] as *const u64 as *const u8;
        for i in 0..32 {
            (*termios).c_cc[i] = *src.add(i);
        }

        true
    }
}

unsafe fn send_pty_timeout_reply(reply_slot: u64) {
    unsafe {
        let mut wake = TronaMsg::zeroed();
        wake.label = TRONA_OK;
        wake.length = 1;
        wake.regs[0] = 0;
        ipc::send_ctx(ipc_ctx(), reply_slot, &raw const wake);
    }
}

unsafe fn owner_state() -> Option<&'static mut VfsState> {
    unsafe {
        let ptr = OWNER_STATE_PTR;
        if ptr.is_null() {
            None
        } else {
            Some(&mut *ptr)
        }
    }
}

fn next_pty_deadline_ns(state: &VfsState) -> u64 {
    let mut earliest = u64::MAX;
    for pty_id in 0..MAX_PTYS {
        for index in 0..state.pty_pending_count[pty_id] {
            let reader = state.pty_pending[pty_id][index];
            if reader.active == 0 || reader.deadline_ns == 0 {
                continue;
            }
            if reader.deadline_ns < earliest {
                earliest = reader.deadline_ns;
            }
        }
    }
    if earliest == u64::MAX { 0 } else { earliest }
}

pub(crate) unsafe fn expire_pty_read_timeouts(now_ns: u64) -> bool {
    let Some(state) = (unsafe { owner_state() }) else {
        return false;
    };

    let mut expired = false;
    for pty_id in 0..MAX_PTYS {
        let mut index = 0usize;
        while index < state.pty_pending_count[pty_id] {
            let reader = state.pty_pending[pty_id][index];
            if reader.active == 0 || reader.deadline_ns == 0 || reader.deadline_ns > now_ns {
                index += 1;
                continue;
            }

            unsafe { send_pty_timeout_reply(reader.reply_slot); }
            let count = state.pty_pending_count[pty_id];
            for j in (index + 1)..count {
                state.pty_pending[pty_id][j - 1] = state.pty_pending[pty_id][j];
            }
            state.pty_pending_count[pty_id] -= 1;
            state.pty_pending[pty_id][state.pty_pending_count[pty_id]] = PtyPendingReader::zeroed();
            expired = true;
        }
    }
    expired
}

pub(crate) unsafe fn next_pty_read_timeout_ns(now_ns: u64) -> u64 {
    let Some(state) = (unsafe { owner_state() }) else {
        return 0;
    };
    let earliest = next_pty_deadline_ns(state);
    if earliest == 0 {
        0
    } else if earliest <= now_ns {
        1
    } else {
        earliest.saturating_sub(now_ns)
    }
}

pub(crate) unsafe fn handle_pty_timer(cookie: u32, now_ns: u64) {
    unsafe {
        if cookie != PTY_TIMER_COOKIE.load(Ordering::Acquire) {
            return;
        }
        PTY_TIMER_DEADLINE.store(0, Ordering::Release);
        let _ = expire_pty_read_timeouts(now_ns);
        if let Some(state) = owner_state() {
            let deadline = next_pty_deadline_ns(state);
            if deadline != 0 {
                arm_pty_deadline(deadline);
            }
        }
    }
}

pub(crate) unsafe fn clear_pty_pending_badge(state: &mut VfsState, badge: u64) -> bool {
    unsafe {
        let mut cleared = false;
        for pty_id in 0..MAX_PTYS {
            let count = state.pty_pending_count[pty_id];
            let mut keep = 0usize;
            for idx in 0..count {
                let reader = state.pty_pending[pty_id][idx];
                if reader.active != 0 && reader.badge == badge {
                    send_client_exit_error(reader.reply_slot);
                    cleared = true;
                    continue;
                }
                if keep != idx {
                    state.pty_pending[pty_id][keep] = reader;
                }
                keep += 1;
            }
            let new_count = keep;
            while keep < count {
                state.pty_pending[pty_id][keep] = PtyPendingReader::zeroed();
                keep += 1;
            }
            state.pty_pending_count[pty_id] = new_count;
        }
        cleared
    }
}

pub(crate) unsafe fn handle_pty_dev_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let count = (*msg).regs[1];
        let max = if count > 152 { 152 } else { count };

        let (pty_id, nonblocking) = {
            let cli = match state.clients.get(cli_handle) {
                Some(c) => c,
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
            };
            let slot = &cli.objects[fd as usize];
            (slot.device_info().map(|d| d.pty_id).unwrap_or(0), slot.nonblocking != 0)
        };

        let mut treq = TronaMsg::zeroed();
        let mut treply = TronaMsg::zeroed();
        treq.label = POSIX_TTYSRV_PTY_READ;
        treq.regs[0] = pty_id as u64;
        treq.regs[1] = max;
        treq.length = 2;

        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
        if err != 0 || treply.label != TRONA_OK {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let actual = treply.regs[0];
        if actual > 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1 + (actual + 7) / 8;
            (*reply).regs[0] = actual;
            let src = &treply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for i in 0..actual as usize {
                *dst.add(i) = *src.add(i);
            }
            return false;
        }

        if nonblocking {
            (*reply).label = TRONA_WOULD_BLOCK;
            return false;
        }

        let mut deadline_ns = 0u64;
        let mut termios = Termios::zeroed();
        if fetch_pty_termios(pty_id as u64, &raw mut termios) {
            let vmin = termios.c_cc[VMIN] as u64;
            let vtime = termios.c_cc[VTIME] as u64;
            if vmin == 0 {
                if vtime == 0 {
                    (*reply).label = TRONA_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return false;
                }
                deadline_ns = super::super::poll::monotonic_now_ns()
                    .saturating_add(vtime.saturating_mul(100_000_000));
            }
        }

        let pid = pty_id as usize;
        if pid >= MAX_PTYS || state.pty_pending_count[pid] >= MAX_PTY_WAITERS {
            (*reply).label = TRONA_BUSY;
            return false;
        }

        let slot = state.alloc_reply_slot();
        let save_err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if save_err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let badge = match state.clients.get(cli_handle) {
            Some(c) => c.badge,
            None => 0,
        };

        let idx = state.pty_pending_count[pid];
        state.pty_pending[pid][idx] = PtyPendingReader {
            active: 1,
            badge,
            reply_slot: slot,
            max_count: max,
            deadline_ns,
        };
        state.pty_pending_count[pid] += 1;

        if deadline_ns != 0 {
            arm_pty_deadline(deadline_ns);
        }

        true
    }
}

pub(crate) unsafe fn handle_pty_notification(ntfn_badge: u64) {
    let Some(state) = (unsafe { owner_state() }) else {
        return;
    };

    unsafe {
        for pty_id in 0..MAX_PTYS {
            if ntfn_badge & (1u64 << pty_id) == 0 {
                continue;
            }

            while state.pty_pending_count[pty_id] > 0 {
                let reader = state.pty_pending[pty_id][0];
                if reader.active == 0 {
                    break;
                }

                let mut creq = TronaMsg::zeroed();
                let mut creply = TronaMsg::zeroed();
                creq.label = POSIX_TTYSRV_PTY_COLLECT;
                creq.regs[0] = pty_id as u64;
                creq.regs[1] = reader.max_count;
                creq.length = 2;
                let cerr = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const creq, &raw mut creply);

                if cerr != 0 || creply.label != TRONA_OK {
                    break;
                }

                let actual = creply.regs[0];
                if actual == 0 {
                    break;
                }

                let mut wake = TronaMsg::zeroed();
                wake.label = TRONA_OK;
                wake.length = 1 + (actual + 7) / 8;
                wake.regs[0] = actual;
                let src = &creply.regs[1] as *const u64 as *const u8;
                let dst = &raw mut wake.regs[1] as *mut u8;
                for i in 0..actual as usize {
                    *dst.add(i) = *src.add(i);
                }
                ipc::send_ctx(ipc_ctx(), reader.reply_slot, &raw const wake);

                let count = state.pty_pending_count[pty_id];
                for j in 1..count {
                    state.pty_pending[pty_id][j - 1] = state.pty_pending[pty_id][j];
                }
                state.pty_pending_count[pty_id] -= 1;
                state.pty_pending[pty_id][state.pty_pending_count[pty_id]] = PtyPendingReader::zeroed();
            }

            // Blocking readers in `pty_pending` were just serviced; now wake any
            // `poll()`/`epoll` waiters registered on an fd backed by this PTY.
            // They live on a separate waiter list and are not drained by the
            // COLLECT loop above, so without this callers like `openpam_ttyconv`
            // (poll + read) would never see readiness.
            super::super::poll::wake_pty_poll_waiters(pty_id as u32);
        }
    }
}
