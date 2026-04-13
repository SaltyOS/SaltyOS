//! Process manager reply/receive transition path.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::ipc;
use trona::types::TronaMsg;

use crate::{
    ipc_ctx, server, CAP_RECV_SCRATCH, CAP_REPLY_TEMP, CAP_SELF_CSPACE, POST_REPLY_RESUME_COUNT,
};
use crate::base::readiness;
use crate::personality::posix;

unsafe fn prepare_receive_slot() {
    unsafe {
        trona::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_RECV_SCRATCH);
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECV_SCRATCH, 0);
    }
}

unsafe fn recv_with_timer(msg: *mut TronaMsg, badge: *mut u64) -> i32 {
    unsafe {
        let has_timers = posix::timer::has_pending_timers();
        let has_readiness = readiness::has_pending_readiness();
        if has_timers || has_readiness {
            let now = trona::syscall::syscall(
                trona::SYS_CLOCK_GETTIME,
                trona::consts::CLOCK_REALTIME as u64,
                0,
                0,
                0,
                0,
                0,
            );
            if now.error == 0 {
                let timer_deadline = if has_timers {
                    posix::timer::nearest_deadline_ns()
                } else {
                    u64::MAX
                };
                let ready_deadline = if has_readiness {
                    readiness::nearest_readiness_deadline_ns()
                } else {
                    u64::MAX
                };
                let deadline = timer_deadline.min(ready_deadline);

                if deadline <= now.value {
                    if !msg.is_null() {
                        *msg = TronaMsg::zeroed();
                    }
                    if !badge.is_null() {
                        *badge = 1;
                    }
                    return 0;
                }

                let timeout = deadline.saturating_sub(now.value).max(100_000);
                let err = trona::ipc::recv_timed_ctx(
                    ipc_ctx(),
                    trona::caps::service_ep(),
                    timeout,
                    msg,
                    badge,
                );
                if err as u64 == crate::TRONA_CANCELLED {
                    if !msg.is_null() {
                        *msg = TronaMsg::zeroed();
                    }
                    if !badge.is_null() {
                        *badge = 0;
                    }
                    return 0;
                }
                return err;
            }

            let err = trona::ipc::recv_timed_ctx(
                ipc_ctx(),
                trona::caps::service_ep(),
                100_000,
                msg,
                badge,
            );
            if err as u64 == crate::TRONA_CANCELLED {
                if !msg.is_null() {
                    *msg = TronaMsg::zeroed();
                }
                if !badge.is_null() {
                    *badge = 0;
                }
                return 0;
            }
            return err;
        }

        trona::ipc::recv_ctx(ipc_ctx(), trona::caps::service_ep(), msg, badge)
    }
}

pub(crate) unsafe fn prime_receive(msg: *mut TronaMsg, badge: *mut u64) -> i32 {
    unsafe {
        prepare_receive_slot();
        recv_with_timer(msg, badge)
    }
}

pub(crate) unsafe fn advance_after_dispatch(
    skip_reply: bool,
    reply: &TronaMsg,
    msg: *mut TronaMsg,
    badge: *mut u64,
) -> i32 {
    unsafe {
        prepare_receive_slot();

        if skip_reply {
            return recv_with_timer(msg, badge);
        }

        if POST_REPLY_RESUME_COUNT != 0
            || posix::timer::has_pending_timers()
            || readiness::has_pending_readiness()
        {
            let save_err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, CAP_REPLY_TEMP);
            if save_err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] save_caller failed for timed recv err=");
                    _lb.hex(save_err as u64);
                    _lb.str(b"\n");
                });
                return save_err;
            }

            let send_err = trona::ipc::send_ctx(ipc_ctx(), CAP_REPLY_TEMP, &raw const *reply);
            trona::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_REPLY_TEMP);
            if send_err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] reply send failed before timed recv err=");
                    _lb.hex(send_err as u64);
                    _lb.str(b"\n");
                });
                return send_err;
            }

            server::run_post_reply_work();
            return recv_with_timer(msg, badge);
        }

        trona::ipc::reply_recv_ctx(
            ipc_ctx(),
            trona::caps::service_ep(),
            &raw const *reply,
            msg,
            badge,
        )
    }
}
