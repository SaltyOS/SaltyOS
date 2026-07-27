// SPDX-License-Identifier: GPL-2.0-only
//
//! Generic control-cap admin IPC plumbing shared by the per-server admin
//! drivers (`mm_ipc`, `vfs_ipc`). Each per-server module owns the resolver
//! that maps a `client_id` to its control-cap address; this module owns the
//! endpoint-addressed call primitives and the two-step transactional invoke
//! that two-operand verbs (fork, cross-client stage / clone) drive.

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc;
use uapi::KERNITE_OK;

/// Monotonic nonce binding a two-step transaction's step 1 to its step 2.
/// init is the single serial lifecycle driver, so a plain counter suffices;
/// one shared counter is enough across every server's single pending slot.
static NEXT_NONCE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

pub fn next_nonce() -> u64 {
    NEXT_NONCE.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Invoke a control cap (by raw addr) with a reply-bearing `MP_CALL`. A zero
/// `endpoint` (an unresolved control cap) fails closed.
pub fn admin_call(endpoint: u64, msg: &TronaMsg, reply: &mut TronaMsg) -> Result<(), i32> {
    if endpoint == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx,
            endpoint,
            msg as *const _,
            reply as *mut _,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(err);
    }
    if reply.label != KERNITE_OK as u64 {
        return Err(reply.label as i32);
    }
    Ok(())
}

/// As [`admin_call`] but carries outgoing transferred caps (e.g. a register
/// verb's vspace + request-MP caps).
pub fn admin_call_with_caps(
    endpoint: u64,
    msg: &TronaMsg,
    caps: &[u64],
    reply: &mut TronaMsg,
) -> Result<(), i32> {
    if endpoint == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let err = unsafe {
        ipc::mp_call_with_caps_ctx(
            ipc_ctx,
            endpoint,
            msg as *const _,
            caps.as_ptr(),
            caps.len() as u64,
            reply as *mut _,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(err);
    }
    if reply.label != KERNITE_OK as u64 {
        return Err(reply.label as i32);
    }
    Ok(())
}

/// Drive a two-operand admin verb as a two-step transactional invoke: invoke
/// the secondary operand's control cap (`partner_label` + a fresh nonce) so
/// the server records the pending partner, then invoke the primary's control
/// cap with `operate_msg` carrying the same nonce in `regs[0]`. `operate_msg`'s
/// `regs[0]` is overwritten with the nonce here.
pub fn two_step_admin(
    secondary_addr: u64,
    primary_addr: u64,
    partner_label: u64,
    operate_msg: &mut TronaMsg,
    operate_reply: &mut TronaMsg,
) -> Result<(), i32> {
    if secondary_addr == 0 || primary_addr == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }
    let nonce = next_nonce();
    let mut partner_msg = TronaMsg::zeroed();
    partner_msg.label = partner_label;
    partner_msg.length = 1;
    partner_msg.regs[0] = nonce;
    let mut partner_reply = TronaMsg::zeroed();
    admin_call(secondary_addr, &partner_msg, &mut partner_reply)?;
    operate_msg.regs[0] = nonce;
    admin_call(primary_addr, operate_msg, operate_reply)
}
