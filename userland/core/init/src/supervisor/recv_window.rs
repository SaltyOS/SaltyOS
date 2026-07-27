// SPDX-License-Identifier: GPL-2.0-only
//
//! Init owner-thread receive window helpers.
//!
//! Every inbound `MP_CALL` installs sender caps into a fixed scratch
//! window. Init replies on the MessagePipe endpoint that produced the
//! request, so there is no per-call reply object in this regular RPC
//! receive window.

use trona_kernel::core_types::{CapRef, IpcContext};
use trona_kernel::invoke;
use uapi::{KERNITE_CAP_SELF_CSPACE, KERNITE_ERR_INVALID_OPERATION, kernite_ipc_buffer};

use crate::internal_slots::{SLOT_RECV_SCRATCH_BASE, SLOT_RECV_SCRATCH_LEN};

const SELF_CSPACE: u64 = KERNITE_CAP_SELF_CSPACE as u64;

pub fn arm(ctx: *mut IpcContext) {
    let window = trona_server::recv_slot::FixedRecvWindow::new(
        SLOT_RECV_SCRATCH_BASE,
        SLOT_RECV_SCRATCH_LEN,
        trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
    );
    unsafe {
        window.arm(ctx, SELF_CSPACE);
    }
}

pub fn clear() {
    let window = trona_server::recv_slot::FixedRecvWindow::new(
        SLOT_RECV_SCRATCH_BASE,
        SLOT_RECV_SCRATCH_LEN,
        trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
    );
    unsafe {
        window.clear(SELF_CSPACE);
    }
}

pub const fn user_slot(idx: u64) -> u64 {
    SLOT_RECV_SCRATCH_BASE + idx
}

/// Snapshot the received-cap count from the current inbound IPC record.
///
/// # Safety
/// `buf` must point at the current thread's IPC buffer after a
/// successful `MP_READ`.
pub unsafe fn received_cap_count_for(buf: *const kernite_ipc_buffer) -> u64 {
    unsafe { trona_kernel::ipc_buffer::read_received_cap_count(buf) }
}

fn current_ipc_buf() -> Result<*mut kernite_ipc_buffer, i32> {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() {
        return Err(KERNITE_ERR_INVALID_OPERATION as i32);
    }
    let buf = unsafe { (*ctx).ipc_buffer };
    if buf.is_null() {
        return Err(KERNITE_ERR_INVALID_OPERATION as i32);
    }
    Ok(buf as *mut kernite_ipc_buffer)
}

fn received_user_cap_count(buf: *const kernite_ipc_buffer) -> u64 {
    unsafe { trona_kernel::ipc_buffer::read_received_cap_count(buf) }
}

fn delete_received_user_caps(user_cap_count: u64, skip_idx: Option<u64>) {
    let limit = core::cmp::min(user_cap_count, SLOT_RECV_SCRATCH_LEN);
    for idx in 0..limit {
        if skip_idx == Some(idx) {
            continue;
        }
        let _ = invoke::cnode_delete(CapRef::flat(SELF_CSPACE), user_slot(idx));
    }
}

pub fn drop_received_caps_for_cap_count(cap_count: u64) {
    delete_received_user_caps(cap_count, None);
}

pub fn move_cap_to_owned_slot(src_slot: u64, label: &[u8]) -> Result<u64, i32> {
    if src_slot == 0 {
        return Err(KERNITE_ERR_INVALID_OPERATION as i32);
    }
    let stable = trona_runtime::core::slot_alloc::alloc_slot_or_idle(label);
    let r = invoke::cnode_move(
        CapRef::flat(SELF_CSPACE),
        stable.addr(),
        CapRef::flat(SELF_CSPACE),
        src_slot,
    );
    if r != 0 {
        // move failed: `stable` (OwnedSlot) Drop frees the still-empty slot.
        return Err(r);
    }
    Ok(stable.into_raw())
}

/// Move the `idx`-th user cap from the current inbound MP_CALL out of
/// init's fixed receive scratch window into an allocator-owned slot.
pub fn move_user_cap_to_owned_slot(idx: u64, label: &[u8]) -> Result<u64, i32> {
    let buf = current_ipc_buf()?;
    let user_cap_count = received_user_cap_count(buf as *const _);
    if idx >= user_cap_count {
        delete_received_user_caps(user_cap_count, None);
        return Err(KERNITE_ERR_INVALID_OPERATION as i32);
    }

    let stable = trona_runtime::core::slot_alloc::alloc_slot_or_idle(label);
    let r = invoke::cnode_move(
        CapRef::flat(SELF_CSPACE),
        stable.addr(),
        CapRef::flat(SELF_CSPACE),
        user_slot(idx),
    );
    if r != 0 {
        // move failed: `stable` (OwnedSlot) Drop frees the still-empty slot.
        delete_received_user_caps(user_cap_count, None);
        return Err(r);
    }

    delete_received_user_caps(user_cap_count, Some(idx));
    Ok(stable.into_raw())
}

/// # Safety
/// `slot` is a cap slot the caller solely owns; torn down and its index freed
/// once here.
pub unsafe fn drop_owned_cap(slot: u64) {
    // SAFETY: exclusive ownership of `slot` is the caller's obligation per the
    // `# Safety` contract above.
    unsafe { trona_runtime::core::slot_alloc::delete_and_free(slot) };
}
