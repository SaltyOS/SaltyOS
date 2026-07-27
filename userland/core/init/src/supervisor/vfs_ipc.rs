// SPDX-License-Identifier: GPL-2.0-only
//
//! init → VFS admin-tier driver. Every VFS client is a per-process client, so
//! init registers each spawned process with VFS at spawn time, holds the
//! returned per-client control cap in that process's `ProcessRecord`, and
//! drives the admin verbs (fork FD-clone, exec `FD_CLOEXEC` sweep, deregister)
//! on it. `VFS_ADMIN_REGISTER_CLIENT` is authorized by the per-server VFS ROOT
//! control cap (`vfs_root_control_cap`); the generic call / two-step plumbing
//! lives in [`control_ipc`](super::control_ipc).

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc;
use trona_runtime::core::slot_alloc::OwnedCap;
use uapi::KERNITE_CAP_SELF_CSPACE;

use crate::supervisor::SupervisorState;
use crate::supervisor::control_ipc::{admin_call, two_step_admin};
use trona_protocol::vfs::public::{
    VFS_ADMIN_CLONE_FDS, VFS_ADMIN_CLONE_SET_PARTNER, VFS_ADMIN_EXEC_SWEEP,
    VFS_ADMIN_REGISTER_CLIENT, VFS_DEREGISTER_CLIENT,
};

/// Resolve a `client_id` to the raw addr of its VFS control cap. VFS clients
/// are per-process only (core services do not use VFS), so this consults the
/// process table exclusively. Returns 0 when unknown.
fn vfs_control_addr(state: &SupervisorState, client_id: u32) -> u64 {
    state
        .procs
        .find_by_client_id_any(client_id)
        .and_then(|p| p.vfs_control_cap.as_ref())
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr()
}

/// `VFS_ADMIN_REGISTER_CLIENT(client_id, pid)` on the VFS ROOT control cap. VFS
/// pre-creates the client's control slot, mints its per-client control cap,
/// and returns it in `caps[0]`; init adopts it into the receive window and
/// hands the `OwnedCap` back to the caller to store in the `ProcessRecord`.
pub fn vfs_register_client(
    state: &SupervisorState,
    client_id: u32,
    pid: u32,
) -> Result<OwnedCap, i32> {
    let root = state
        .caps
        .vfs_root_control_cap
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    if root == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = VFS_ADMIN_REGISTER_CLIENT;
    msg.length = 2;
    msg.regs[0] = client_id as u64;
    msg.regs[1] = pid as u64;

    let Some(recv) = trona_runtime::core::slot_alloc::alloc_slot() else {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    };
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    // SAFETY: arm the receive window so VFS's reply moves the minted control
    // cap into `recv`.
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx,
            KERNITE_CAP_SELF_CSPACE as u64,
            recv.addr(),
            0,
        );
    }
    let mut reply = TronaMsg::zeroed();
    match admin_call(root, &msg, &mut reply) {
        Ok(()) => {
            // The reply moved the control cap into `recv`; adopt it (preserving
            // invoke depth). `into_raw` forgets the OwnedSlot so the OwnedCap is
            // the sole owner.
            let raw = recv.into_raw();
            Ok(unsafe { OwnedCap::adopt_received(raw) })
        }
        // No cap received; `recv` (OwnedSlot) drops here, freeing the slot.
        Err(e) => Err(e),
    }
}

/// Clone the parent's FD table into the child as a two-step transactional
/// invoke: pin the child via `VFS_ADMIN_CLONE_SET_PARTNER` (secondary), then
/// operate with `VFS_ADMIN_CLONE_FDS` on the parent (primary). VFS fails the
/// verb on any clone error so a fork never commits a truncated FD table.
pub fn vfs_clone_fds(
    state: &SupervisorState,
    parent_client_id: u32,
    child_client_id: u32,
) -> Result<(), i32> {
    let child_addr = vfs_control_addr(state, child_client_id);
    let parent_addr = vfs_control_addr(state, parent_client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = VFS_ADMIN_CLONE_FDS;
    msg.length = 1;
    let mut reply = TronaMsg::zeroed();
    two_step_admin(
        child_addr,
        parent_addr,
        VFS_ADMIN_CLONE_SET_PARTNER,
        &mut msg,
        &mut reply,
    )
}

/// `VFS_ADMIN_EXEC_SWEEP` on the client's control cap — drop its `FD_CLOEXEC`
/// descriptors after the exec point of no return. Best-effort: the caller does
/// not fail the already-committed exec on error.
pub fn vfs_exec_sweep(state: &SupervisorState, client_id: u32) -> Result<(), i32> {
    let endpoint = vfs_control_addr(state, client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = VFS_ADMIN_EXEC_SWEEP;
    msg.length = 0;
    let mut reply = TronaMsg::zeroed();
    admin_call(endpoint, &msg, &mut reply)
}

/// `VFS_DEREGISTER_CLIENT` on the client's control cap — best-effort teardown
/// notice. Sent as a non-reply `MP_WRITE` so exit/rollback finalization never
/// blocks on VFS cleanup (VFS may itself be blocked on init).
pub fn vfs_deregister_client(state: &SupervisorState, client_id: u32) {
    let endpoint = vfs_control_addr(state, client_id);
    if endpoint == 0 {
        return;
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = VFS_DEREGISTER_CLIENT;
    msg.length = 0;
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let _ = unsafe { ipc::mp_write_ctx(ipc_ctx, endpoint, &raw const msg) };
}
