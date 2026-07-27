//! Process manager bootstrap path.
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc;
use trona_protocol::posix::NS_REGISTER;

use crate::service::registry as service_registry;
use crate::{
    ALLOCATOR, BOUND_NTFN, CAP_RECV_SCRATCH, CAP_SELF_CSPACE, CAP_SELF_TCB, ipc_ctx, signal_ready,
};

pub(crate) unsafe fn initialize() {
    unsafe {
        crate::base::proc_table::init_proctab();
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] process table ready\n");
        });

        (*(&raw mut ALLOCATOR)).init(CAP_SELF_CSPACE);
        let _ = (*(&raw mut ALLOCATOR)).mark_slot_used(CAP_RECV_SCRATCH);
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] allocator ready\n");
        });

        crate::base::vfs_notify::initialize();
        crate::reply_path::initialize_recv_timer();

        match crate::base::alloc::alloc_single(
            trona_runtime::client::caps::rsrcsrv_ep(),
            0,
            uapi::KERNITE_OBJ_NOTIFICATION,
            0,
        ) {
            Ok((slot, _handle)) => {
                let bind_err = trona_kernel::invoke::tcb_bind_notification(CAP_SELF_TCB, slot);
                if bind_err != 0 {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] bind cspace ntfn failed err=");
                        _lb.hex(bind_err as u64);
                        _lb.str(b"\n");
                    });
                } else {
                    BOUND_NTFN = slot;
                    trona_runtime::uinfo!(|_lb| {
                        _lb.str(b"[PROCMGR] cspace expansion notification bound\n");
                    });
                }
            }
            Err(e) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] alloc cspace ntfn failed err=");
                    _lb.hex(e as u64);
                    _lb.str(b"\n");
                });
            }
        }

        // Shared library mapping is owned by RTLD inside each child process;
        // procmgr no longer maintains a path-keyed MO cache here.
        service_registry::install_bootstrap_providers();
        let _ = crate::base::cap_helpers::refresh_vfs_caps(trona_runtime::client::caps::vfs_ep());

        // stdio handoff is now per-spawn via `stdio_mode`: tty-bound
        // children get a console-backed fd 0/1/2 triple installed by
        // `pty_handoff::handoff_tty_stdio_to_child`. procmgr no longer
        // maintains a shared stdio fd triple in its own VFS client
        // state.

        // Readiness: "spawn / fork / exec dispatch usable — stdio
        // handoff is per-spawn via `stdio_mode`".
        signal_ready();

        if trona_runtime::client::caps::namesrv_ep() != 0 {
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
            let publish_ep = trona_runtime::client::caps::service_client_ep_for_transfer();
            ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_ep);
            let err = ipc::call_ctx(
                ipc_ctx(),
                trona_runtime::client::caps::namesrv_ep(),
                &raw const reg_msg,
                &raw mut reg_reply,
            );
            trona_runtime::client::caps::finish_service_client_ep_transfer(publish_ep, err);
            if err == 0 && reg_reply.label == trona_protocol::common::TRONA_OK {
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[PROCMGR] registered with namesrv\n");
                });
            } else {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[PROCMGR] WARN: namesrv registration failed\n");
                });
            }
        }
    }
}
