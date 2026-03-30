//! POSIX interval timers owned by procmgr.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::TronaMsg;

use crate::proc_table::{find_by_badge, proctab, proctab_cap, PROC_RUNNING, PROC_STOPPED};

const ITIMER_REAL: u64 = 0;
const USEC_PER_SEC: u64 = 1_000_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;

fn clock_realtime_ns() -> u64 {
    let now = trona::syscall::syscall(
        trona::SYS_CLOCK_GETTIME,
        trona::consts::CLOCK_REALTIME as u64,
        0,
        0,
        0,
        0,
        0,
    );
    if now.error == 0 { now.value } else { 0 }
}

fn timeval_to_ns(sec: u64, usec: u64) -> Option<u64> {
    if usec >= USEC_PER_SEC {
        return None;
    }
    sec.checked_mul(NSEC_PER_SEC)?
        .checked_add(usec.checked_mul(1_000)?)
}

fn ns_to_timeval(ns: u64) -> (u64, u64) {
    (ns / NSEC_PER_SEC, (ns % NSEC_PER_SEC) / 1_000)
}

fn current_timer_value(idx: usize, now_ns: u64) -> (u64, u64, u64, u64) {
    unsafe {
        let p = proctab(idx);
        let remaining_ns = if p.itimer_real_deadline_ns == 0 {
            0
        } else {
            p.itimer_real_deadline_ns.saturating_sub(now_ns)
        };
        let interval_ns = p.itimer_real_interval_ns;
        let (value_sec, value_usec) = ns_to_timeval(remaining_ns);
        let (interval_sec, interval_usec) = ns_to_timeval(interval_ns);
        (value_sec, value_usec, interval_sec, interval_usec)
    }
}

pub(crate) fn has_pending_timers() -> bool {
    unsafe {
        for i in 0..proctab_cap() {
            let p = proctab(i);
            if (p.state == PROC_RUNNING || p.state == PROC_STOPPED) && p.itimer_real_deadline_ns != 0
            {
                return true;
            }
        }
    }
    false
}

pub(crate) fn nearest_deadline_ns() -> u64 {
    let mut deadline = u64::MAX;
    unsafe {
        for i in 0..proctab_cap() {
            let p = proctab(i);
            if (p.state == PROC_RUNNING || p.state == PROC_STOPPED)
                && p.itimer_real_deadline_ns != 0
                && p.itimer_real_deadline_ns < deadline
            {
                deadline = p.itimer_real_deadline_ns;
            }
        }
    }
    deadline
}

pub(crate) fn process_expired_timers() {
    let now_ns = clock_realtime_ns();

    unsafe {
        for i in 0..proctab_cap() {
            let (state, deadline_ns, interval_ns) = {
                let p = proctab(i);
                (p.state, p.itimer_real_deadline_ns, p.itimer_real_interval_ns)
            };

            if state != PROC_RUNNING && state != PROC_STOPPED {
                continue;
            }
            if deadline_ns == 0 || deadline_ns > now_ns {
                continue;
            }

            let next_deadline_ns = if interval_ns == 0 {
                0
            } else {
                let mut next_deadline = deadline_ns;
                while next_deadline <= now_ns {
                    let Some(advanced) = next_deadline.checked_add(interval_ns) else {
                        next_deadline = 0;
                        break;
                    };
                    next_deadline = advanced;
                }
                next_deadline
            };

            {
                let p = proctab(i);
                if p.state != PROC_RUNNING && p.state != PROC_STOPPED {
                    continue;
                }
                p.itimer_real_deadline_ns = next_deadline_ns;
            }

            let _ = crate::signal::deliver_signal_to(i, crate::PM_SIGALRM);
        }
    }
}

pub(crate) unsafe fn handle_setitimer(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        if msg.regs[0] != ITIMER_REAL {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        let value_sec = msg.regs[1];
        let value_usec = msg.regs[2];
        let interval_sec = msg.regs[3];
        let interval_usec = msg.regs[4];

        let Some(value_ns) = timeval_to_ns(value_sec, value_usec) else {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        };
        let Some(interval_ns) = timeval_to_ns(interval_sec, interval_usec) else {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        };

        let now_ns = clock_realtime_ns();
        let (old_value_sec, old_value_usec, old_interval_sec, old_interval_usec) = if now_ns == 0 {
            (0, 0, 0, 0)
        } else {
            current_timer_value(idx, now_ns)
        };

        if value_ns != 0 && now_ns == 0 {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        proctab(idx).itimer_real_interval_ns = interval_ns;
        proctab(idx).itimer_real_deadline_ns = if value_ns == 0 {
            0
        } else {
            now_ns.saturating_add(value_ns)
        };

        reply.label = crate::TRONA_OK;
        reply.length = 4;
        reply.regs[0] = old_value_sec;
        reply.regs[1] = old_value_usec;
        reply.regs[2] = old_interval_sec;
        reply.regs[3] = old_interval_usec;
    }
}

pub(crate) unsafe fn handle_getitimer(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        if msg.regs[0] != ITIMER_REAL {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        let now_ns = clock_realtime_ns();
        let (value_sec, value_usec, interval_sec, interval_usec) = if now_ns == 0 {
            (0, 0, 0, 0)
        } else {
            current_timer_value(idx, now_ns)
        };

        reply.label = crate::TRONA_OK;
        reply.length = 4;
        reply.regs[0] = value_sec;
        reply.regs[1] = value_usec;
        reply.regs[2] = interval_sec;
        reply.regs[3] = interval_usec;
    }
}
