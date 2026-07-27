// SPDX-License-Identifier: GPL-2.0-only
//
//! namesrv IPC wire helpers — capability broker calls init issues on
//! `state.caps.namesrv_client_mp` (init's send side of namesrv's
//! master MP).
//!
//! init drives namesrv on three operational moments:
//!
//! * **Service spawn** — init calls `NAMESRV_GRANT_PUBLISHER` to authorize
//!   the service's own name under its policy_id. namesrv maps that service
//!   name to the policy_id; subsequent `NAMESRV_REGISTER` calls from the
//!   publisher process are accepted only for that name.
//! * **Per-process exit** — `finalize_exit` calls
//!   `NAMESRV_OWNER_EXITED(client_id)` so namesrv evicts the
//!   client's `OwnerTable` entry and drops every registered name
//!   keyed off it.
//! * **Bootstrap publishing** — namesrv itself does not need init to
//!   register on its behalf; namesrv's own `boot::register` call uses
//!   the in-process protocol. The wrapper here is for *clients of*
//!   namesrv — not namesrv internals.

use trona_kernel::core_types::{CapRef, IpcContext, TronaMsg};
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::common::TRONA_OK;
use trona_protocol::namesrv::{
    NAMESRV_GRANT_PUBLISHER, NAMESRV_LOOKUP_NONBLOCK, NAMESRV_OWNER_EXITED,
};
use trona_runtime::core::slot_alloc::{OwnedCap, alloc_slot};
use uapi::KERNITE_CAP_SELF_CSPACE;

use crate::supervisor::SupervisorState;
use crate::supervisor::manifest::ServiceDef;

/// First-time publisher grant. namesrv's `PublisherPolicy` table is
/// indexed by `policy_id`, which init owns per-service. The
/// systemd-style invariant from Plan 6 P1: a service publishes its own
/// service name (the master service-EP — every service always exposes this).
/// `[Capabilities] ProvidesInterface=` is provider-local manifest metadata,
/// not a global namesrv prefix; otherwise two filesystem providers declaring
/// `fs` would collide on the same namespace entry.
///
/// Fail-loud except for idempotent duplicates: namesrv treats repeat
/// grants as `KERNITE_ERR_ALREADY_EXISTS`, which we absorb because
/// init's spawn path may retry on respawn after a service crash.
/// Every other error aborts spawn before the child can run and lose
/// its first `NAMESRV_REGISTER` to a missing publisher policy.
pub fn grant_publisher_if_needed(
    state: &SupervisorState,
    def: &ServiceDef,
    _client_id: u32,
) -> Result<(), i32> {
    grant_one_prefix(state, def.name.as_bytes(), def.policy_id)?;
    Ok(())
}

fn grant_one_prefix(state: &SupervisorState, prefix: &[u8], policy_id: u16) -> Result<(), i32> {
    if prefix.is_empty() {
        return Ok(());
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_GRANT_PUBLISHER;
    msg.length = 2 + ((prefix.len() + 7) / 8) as u64;
    msg.regs[0] = prefix.len() as u64;
    msg.regs[1] = policy_id as u64;
    let mut buf = [0u8; 8];
    for (chunk_i, chunk) in prefix.chunks(8).enumerate() {
        buf[..chunk.len()].copy_from_slice(chunk);
        msg.regs[2 + chunk_i] = u64::from_le_bytes(buf);
        buf = [0u8; 8];
    }
    let mut reply = TronaMsg::zeroed();
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx,
            state
                .caps
                .namesrv_client_mp
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(err);
    }
    match reply.label {
        TRONA_OK => Ok(()),
        x if x == uapi::KERNITE_ERR_ALREADY_EXISTS as u64 => Ok(()),
        other => Err(other as i32),
    }
}

/// `NAMESRV_OWNER_EXITED(client_id)` — best-effort owner eviction
/// notice. Exit finalization must not wait for namesrv cleanup;
/// namesrv only replies when the request arrived as an `MP_CALL`.
pub fn namesrv_owner_exited(state: &SupervisorState, client_id: u32) {
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_OWNER_EXITED;
    msg.length = 1;
    msg.regs[0] = client_id as u64;
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let _ = unsafe {
        ipc::mp_write_ctx(
            ipc_ctx,
            state
                .caps
                .namesrv_client_mp
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr(),
            &raw const msg,
        )
    };
}

/// Resolve a namesrv entry while presenting `client_id` as the lookup
/// caller. Entries registered with `ENTRY_FLAG_BADGE_AS_CALLER` use the
/// caller id from the namesrv request badge when minting the returned
/// service cap, so init must perform this lookup through a temporary
/// namesrv cap badged as the target child instead of through init's
/// admin namesrv cap.
pub fn lookup_as_client(
    state: &SupervisorState,
    client_id: u32,
    name: &[u8],
    receive_slot: u64,
    ipc_ctx: *mut IpcContext,
) -> Result<u64, i32> {
    let raw = state
        .caps
        .namesrv_master_mp_send_raw
        .as_ref()
        .map(OwnedCap::borrow)
        .ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
    lookup_as_client_at(
        raw,
        client_id,
        name,
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        receive_slot,
        ipc_ctx,
    )
}

/// Same as [`lookup_as_client`], but installs the returned cap into an explicit
/// CNode/slot. This is needed when init is installing a service cap directly
/// into a child CSpace: namesrv lookup returns a consumer copy, not a
/// GRANT-bearing redistribution source that init may copy again.
///
/// IPC receive installs transferred caps into the receiving thread's own CSpace.
/// It is not a grant for the receiver to make the sender write directly into an
/// arbitrary child CNode. When init is seeding a child, receive the namesrv result
/// into an init-owned temporary slot first, then move that exact CapRef into the
/// requested child destination using init's CNode authority.
pub fn lookup_as_client_at(
    namesrv_raw_send: CapRef,
    client_id: u32,
    name: &[u8],
    receive_cnode: CapRef,
    receive_slot: u64,
    ipc_ctx: *mut IpcContext,
) -> Result<u64, i32> {
    if name.is_empty() || name.len() > 64 {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    if ipc_ctx.is_null() {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }

    let lookup_ep =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"init namesrv child lookup");
    if lookup_ep == 0 {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }

    let result = (|| -> Result<u64, i32> {
        let mint_err = invoke::cnode_mint_ref(
            CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
            namesrv_raw_send,
            CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
            CapRef::at_depth(
                lookup_ep,
                trona_runtime::core::slot_alloc::slot_invoke_depth(lookup_ep),
            ),
            client_id as u64,
        );
        if mint_err != 0 {
            return Err(mint_err);
        }

        let recv = alloc_slot().ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
        let saved = unsafe { ipc::get_receive_slot_path_ctx(ipc_ctx) };
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                ipc_ctx,
                KERNITE_CAP_SELF_CSPACE as u64,
                recv.addr(),
                0,
            );
            ipc::clear_send_caps_ctx(ipc_ctx);
        }

        let mut msg = TronaMsg::zeroed();
        msg.label = NAMESRV_LOOKUP_NONBLOCK;
        msg.regs[0] = name.len() as u64;
        for (chunk_i, chunk) in name.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            msg.regs[1 + chunk_i] = u64::from_le_bytes(word);
        }
        msg.length = 1 + ((name.len() + 7) / 8) as u64;

        let mut reply = TronaMsg::zeroed();
        let err = unsafe {
            ipc::mp_call_ctx(
                ipc_ctx,
                lookup_ep,
                &raw const msg,
                &raw mut reply,
                trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
            )
        };
        unsafe {
            ipc::clear_send_caps_ctx(ipc_ctx);
            ipc::set_receive_slot_path_ctx(ipc_ctx, saved.0, saved.1, saved.2, saved.3);
        }
        let received = recv.assume_filled();
        if err != 0 {
            return Err(err);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label as i32);
        }
        let move_err = invoke::cnode_move_ref(
            receive_cnode,
            CapRef::flat(receive_slot),
            CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
            received.borrow(),
        );
        if move_err != 0 {
            return Err(move_err);
        }
        Ok(receive_slot)
    })();

    // SAFETY: lookup_ep is the transient lookup endpoint cap minted for this
    // call, solely owned here; freed once after the lookup completes.
    unsafe { trona_runtime::core::slot_alloc::delete_and_free(lookup_ep) };
    result
}
