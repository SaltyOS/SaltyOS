//! Process manager bootstrap path.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::ipc;
use trona::protocol::NS_REGISTER;
use trona::types::TronaMsg;

use crate::{
    ipc_ctx, signal_ready, ALLOCATOR, BOUND_NTFN, CAP_SELF_CSPACE, CAP_SELF_TCB,
};
use crate::service::registry as service_registry;

pub(crate) unsafe fn initialize() {
    unsafe {
        crate::base::proc_table::init_proctab();
        trona::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] process table ready\n");
        });

        (*(&raw mut ALLOCATOR)).init(CAP_SELF_CSPACE);
        trona::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] allocator ready\n");
        });

        match crate::base::alloc::alloc_single(trona::caps::rsrcsrv_ep(), 0, trona::OBJ_NOTIFICATION, 0) {
            Ok((slot, _handle)) => {
                let bind_err = trona::invoke::tcb_bind_notification(CAP_SELF_TCB, slot);
                if bind_err != 0 {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] bind cspace ntfn failed err=");
                        _lb.hex(bind_err as u64);
                        _lb.str(b"\n");
                    });
                } else {
                    BOUND_NTFN = slot;
                    trona::uinfo!(|_lb| {
                        _lb.str(b"[PROCMGR] cspace expansion notification bound\n");
                    });
                }
            }
            Err(e) => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] alloc cspace ntfn failed err=");
                    _lb.hex(e as u64);
                    _lb.str(b"\n");
                });
            }
        }

        crate::loader::shared_lib_cache::init_shared_lib_cache(&mut *(&raw mut ALLOCATOR));
        service_registry::install_bootstrap_providers();
        signal_ready();

        if trona::caps::namesrv_ep() != 0 {
            let mut reg_msg = TronaMsg::zeroed();
            let mut reg_reply = TronaMsg::zeroed();
            let svc_name = b"procmgr";
            reg_msg.label = NS_REGISTER;
            reg_msg.regs[0] = svc_name.len() as u64;
            reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;
            let dst = &raw mut reg_msg.regs[1] as *mut u8;
            for i in 0..svc_name.len() {
                *dst.add(i) = svc_name[i];
            }
            reg_msg.regs[2] = 0;
            reg_msg.regs[3] = 0;
            ipc::set_send_cap_ctx(ipc_ctx(), 0, trona::caps::service_ep());
            let err = ipc::call_ctx(
                ipc_ctx(),
                trona::caps::namesrv_ep(),
                &raw const reg_msg,
                &raw mut reg_reply,
            );
            if err == 0 && reg_reply.label == trona::TRONA_OK {
                trona::uinfo!(|_lb| {
                    _lb.str(b"[PROCMGR] registered with namesrv\n");
                });
            } else {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[PROCMGR] WARN: namesrv registration failed\n");
                });
            }
        }
    }
}
