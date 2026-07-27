//! SaltyOS userland log broker
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Receives non-privileged diagnostic records from ordinary services,
//! and forwards them to the privileged kernel debug console. Ordinary
//! services never receive `KernelDebug`; only logsrv bridges their
//! records into that sink.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_kernel::syscall::invoke;
use trona_protocol::log::{LOG_INLINE_BYTES, LOG_WRITE};
use trona_protocol::namesrv::NAMESRV_REGISTER;

fn ipc_ctx() -> *mut IpcContext {
    trona_runtime::current_ipc_ctx()
}

fn register_namesrv() -> bool {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let name = b"logsrv";
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_REGISTER;
    msg.regs[0] = name.len() as u64;
    let Some(publish_ep) = trona_runtime::client::caps::service_client_ep_for_transfer() else {
        return false;
    };
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_ep.slot());
    }
    msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    msg.length = (REGISTER_FLAGS_REG + 1) as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    // `publish_ep` (TransferCap) reclaims its slot on drop whether the send
    // moved the cap out to namesrv (success) or left it in place (failure).
    drop(publish_ep);
    err == 0 && reply.label == trona_protocol::common::TRONA_OK
}

fn valid_payload_len(msg: &TronaMsg) -> Option<usize> {
    if msg.length == 0 {
        return None;
    }
    let requested = msg.regs[0] as usize;
    let words = (msg.length as usize)
        .saturating_sub(1)
        .min(msg.regs.len().saturating_sub(1));
    let inline_bytes = (words * 8).min(LOG_INLINE_BYTES);
    if requested > inline_bytes {
        return None;
    }
    Some(requested)
}

fn handle_log(msg: &TronaMsg) {
    let Some(len) = valid_payload_len(msg) else {
        return;
    };
    let kdebug = trona_runtime::client::caps::kernel_debug_cap();
    if kdebug.is_null() {
        return;
    }
    let data = &msg.regs[1] as *const u64 as *const u8;
    let _ = invoke(
        kdebug.addr(),
        uapi::KERNITE_INV_KDEBUG_PUTBUF as u64,
        data as u64,
        len as u64,
        0,
        0,
    );
}

fn server_loop() -> ! {
    let mut msg = TronaMsg::zeroed();
    let mut badge = 0u64;
    loop {
        let err = unsafe {
            ipc::mp_read_ctx(
                ipc_ctx(),
                trona_runtime::client::caps::service_recv_ep().addr(),
                &raw mut msg,
                &raw mut badge,
            )
        };
        if err != 0 {
            let _ = trona_kernel::syscall::yield_now();
            continue;
        }

        if msg.label == LOG_WRITE {
            handle_log(&msg);
        }

        msg = TronaMsg::zeroed();
        badge = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if !register_namesrv() {
        loop {
            let _ = trona_kernel::syscall::yield_now();
        }
    }
    server_loop()
}
