//! Process manager server runtime.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::Cap;
use trona::types::TronaMsg;

use crate::{
    dispatch, reply_path, POST_REPLY_RESUME_COUNT, POST_REPLY_RESUME_QUEUE,
    POST_REPLY_RESUME_QUEUE_CAP,
};
use crate::base::readiness;
use crate::personality::posix;

pub(crate) unsafe fn run_post_reply_work() {
    unsafe {
        let count = POST_REPLY_RESUME_COUNT;
        if count == 0 {
            return;
        }

        for q in 0..count {
            let tcb = POST_REPLY_RESUME_QUEUE[q];
            POST_REPLY_RESUME_QUEUE[q] = 0;
            if tcb == 0 {
                continue;
            }

            let err = trona::invoke::tcb_resume(tcb);
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] deferred resume failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" tcb=");
                    _lb.hex(tcb);
                    _lb.str(b"\n");
                });
            }
        }

        POST_REPLY_RESUME_COUNT = 0;
    }
}

pub(crate) unsafe fn enqueue_post_reply_resume(tcb: Cap) -> bool {
    unsafe {
        if tcb == 0 {
            return true;
        }
        let count = POST_REPLY_RESUME_COUNT;
        if count >= POST_REPLY_RESUME_QUEUE_CAP {
            return false;
        }
        POST_REPLY_RESUME_QUEUE[count] = tcb;
        POST_REPLY_RESUME_COUNT = count + 1;
        true
    }
}

pub(crate) unsafe fn run() -> ! {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut badge: u64 = 0;

        let err = reply_path::prime_receive(&raw mut msg, &raw mut badge);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] initial recv failed\n");
            });
            crate::idle();
        }

        loop {
            // Timer and readiness expiry are checked only when the timed
            // receive wakes on timeout (msg zeroed, badge 0 or 1) or on a
            // notification (label 0). Normal IPC messages skip this.
            if msg.label == 0 {
                posix::timer::process_expired_timers();
                readiness::check_pending_readiness();
            }

            let mut reply = TronaMsg::zeroed();
            let skip_reply = dispatch::handle_message(&msg, badge, &mut reply);

            let err = reply_path::advance_after_dispatch(
                skip_reply,
                &reply,
                &raw mut msg,
                &raw mut badge,
            );
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] reply_recv failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                break;
            }
        }
    }

    crate::idle()
}
