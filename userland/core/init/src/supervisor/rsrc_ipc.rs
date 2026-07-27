// SPDX-License-Identifier: GPL-2.0-only
//
//! rsrcsrv IPC wire helpers — kernel-object retype factory.
//!
//! Every helper here arms the IPC buffer's receive window via
//! [`set_receive_slot_ctx`] **before** calling rsrcsrv. rsrcsrv stages
//! result caps in its reply payload; the kernel installs those caps
//! into the caller's armed receive window when the server answers with
//! `reply-marked MP_WRITE`.
//!
//! Callers pass whichever rsrcsrv send cap matches the operation's
//! owner: init's admin cap for administrative labels, or a temporary
//! child-badged cap resolved through namesrv when allocating objects
//! that must be reclaimed by that child's owner id.

use trona_kernel::core_types::{IpcContext, TronaMsg};
use trona_kernel::ipc;
use trona_protocol::common::TRONA_OK;
use uapi::KERNITE_CAP_SELF_CSPACE;

use crate::supervisor::retype::RetypeClass;

// ---------------------------------------------------------------------------
// RSRC_* labels.
// ---------------------------------------------------------------------------

/// Charge per-class quota and retype one fixed-size object into the
/// caller's receive slot. Reply.regs[0] = rsrcsrv object record id.
pub const RSRC_ALLOC: u64 = trona_protocol::rsrcsrv::RSRC_ALLOC;
/// Release a previously allocated rsrcsrv object record. For grouped
/// objects such as MP pairs, rsrcsrv releases the entire group.
pub const RSRC_FREE: u64 = 0x301;
/// Owner's per-class allocation reclaim. Used at exit teardown.
pub const RSRC_OWNER_EXITED: u64 = 0x305;
/// Retype an MP_CORE + two MessagePipe sides + bind into a pair. Two
/// caps arrive in `receive_index..receive_index+2`: send (idx 0) and
/// recv (idx 1).
pub const RSRC_ALLOC_MP_PAIR: u64 = 0x30A;

// ---------------------------------------------------------------------------
// Wrapper internals.
// ---------------------------------------------------------------------------

/// Arm the IPC buffer's receive window so rsrcsrv's reply cap-transfer
/// installs new caps at `dest_slot..` in init's CSpace.
unsafe fn arm_recv_window(ipc_ctx: *mut IpcContext, dest_slot: u64) {
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx,
            KERNITE_CAP_SELF_CSPACE as u64,
            dest_slot,
            0,
        );
    }
}

fn call(
    rsrcsrv_mp: u64,
    msg: &TronaMsg,
    reply: &mut TronaMsg,
    ipc_ctx: *mut IpcContext,
) -> Result<(), i32> {
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx,
            rsrcsrv_mp,
            msg as *const _,
            reply as *mut _,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(err);
    }
    if reply.label != TRONA_OK {
        return Err(reply.label as i32);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public helpers.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct RsrcAlloc {
    pub cap_slot: u64,
    pub record_id: u64,
}

#[derive(Clone, Copy)]
pub struct RsrcMpPair {
    pub send_slot: u64,
    pub recv_slot: u64,
    pub core_record_id: u64,
}

/// `RSRC_ALLOC(obj_type, size_bits, flags=0)` — retype one fixed-size
/// kernel object and receive the result cap at `dest_slot`. The
/// destination slot is not part of the rsrcsrv payload; this wrapper
/// arms the caller's IPC receive window before the call, and the
/// kernel installs the returned cap there when rsrcsrv sends its
/// `reply-marked MP_WRITE`.
///
/// Wire layout (see `userland/core/rsrcsrv/src/dispatch.rs`):
///
/// ```text
///   regs[0] = obj_type (KERNITE_OBJ_*)
///   regs[1] = size_bits (or 0 for fixed-size objects)
///   regs[2] = flags (currently 0)
///   reply.regs[0] = rsrcsrv object record id
///   reply.cap[0] = newly minted object cap
/// ```
pub fn rsrc_alloc(
    rsrcsrv_mp: u64,
    class: RetypeClass,
    size_bits: u64,
    receive_slot: u64,
    ipc_ctx: *mut IpcContext,
) -> Result<u64, i32> {
    Ok(rsrc_alloc_recorded(rsrcsrv_mp, class, size_bits, receive_slot, ipc_ctx)?.cap_slot)
}

/// Same wire operation as [`rsrc_alloc`], but preserves rsrcsrv's
/// returned record id so callers can roll back a partially-realised
/// spawn with `RSRC_FREE`.
pub fn rsrc_alloc_recorded(
    rsrcsrv_mp: u64,
    class: RetypeClass,
    size_bits: u64,
    receive_slot: u64,
    ipc_ctx: *mut IpcContext,
) -> Result<RsrcAlloc, i32> {
    unsafe { arm_recv_window(ipc_ctx, receive_slot) };

    let mut msg = TronaMsg::zeroed();
    msg.label = RSRC_ALLOC;
    msg.length = 3;
    msg.regs[0] = class.obj_type();
    msg.regs[1] = size_bits;
    msg.regs[2] = 0;

    let mut reply = TronaMsg::zeroed();
    call(rsrcsrv_mp, &msg, &mut reply, ipc_ctx)?;
    Ok(RsrcAlloc {
        cap_slot: receive_slot,
        record_id: reply.regs[0],
    })
}

/// `RSRC_ALLOC_MP_PAIR()` — retype a fresh MP_CORE + two MessagePipe
/// sides, bind them into a pair, and mint two caps into `recv_base`
/// (send) and `recv_base+1` (recv) in caller's CSpace. `recv_base`
/// is carried only in the caller's IPC receive window, not in the
/// rsrcsrv payload.
pub fn rsrc_alloc_mp_pair(
    rsrcsrv_mp: u64,
    recv_base: u64,
    ipc_ctx: *mut IpcContext,
) -> Result<(u64, u64), i32> {
    let pair = rsrc_alloc_mp_pair_recorded(rsrcsrv_mp, recv_base, ipc_ctx)?;
    Ok((pair.send_slot, pair.recv_slot))
}

/// Same wire operation as [`rsrc_alloc_mp_pair`], preserving the
/// rsrcsrv record id for rollback. `core_record_id` is sufficient for
/// `RSRC_FREE` because rsrcsrv frees MP/DP pair groups atomically.
pub fn rsrc_alloc_mp_pair_recorded(
    rsrcsrv_mp: u64,
    recv_base: u64,
    ipc_ctx: *mut IpcContext,
) -> Result<RsrcMpPair, i32> {
    // RSRC_ALLOC_MP_PAIR returns 2 consecutive caps; the kernel's
    // `cap-transfer` loop walks the receive window starting at
    // `receive_index` and increments per cap. Arming with the base
    // index is sufficient.
    unsafe { arm_recv_window(ipc_ctx, recv_base) };

    let mut msg = TronaMsg::zeroed();
    msg.label = RSRC_ALLOC_MP_PAIR;
    msg.length = 0;

    let mut reply = TronaMsg::zeroed();
    call(rsrcsrv_mp, &msg, &mut reply, ipc_ctx)?;
    Ok(RsrcMpPair {
        send_slot: recv_base,
        recv_slot: recv_base + 1,
        core_record_id: reply.regs[0],
    })
}

/// `RSRC_FREE(record_id)` — best-effort release for a record owned
/// by the caller's badge. Used by init during spawn rollback before
/// the child is visible to normal process-exit teardown.
pub fn rsrc_free(rsrcsrv_mp: u64, record_id: u64, ipc_ctx: *mut IpcContext) -> Result<(), i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = RSRC_FREE;
    msg.length = 1;
    msg.regs[0] = record_id;

    let mut reply = TronaMsg::zeroed();
    call(rsrcsrv_mp, &msg, &mut reply, ipc_ctx)
}

/// `RSRC_OWNER_EXITED(client_id)` — synchronous owner reclaim.
///
/// Blocks until rsrcsrv has revoked every object the owner held and
/// reclaimed the drained untyped chunks, so the pool is ready before the
/// next fork retypes a fresh bundle. Reclaim correctness depends on this
/// running *after* the caller has already dropped every other reference
/// to those objects (init's bundle cap copies and the child's TCB): a
/// surviving reference forces the kernel to refuse the per-chunk
/// `UNTYPED_RESET` with `HasChildren`. rsrcsrv never calls back into init,
/// so this `MP_CALL` cannot deadlock the supervisor.
pub fn rsrc_owner_exited(rsrcsrv_mp: u64, client_id: u32, ipc_ctx: *mut IpcContext) {
    let mut msg = TronaMsg::zeroed();
    msg.label = RSRC_OWNER_EXITED;
    msg.length = 1;
    msg.regs[0] = client_id as u64;
    let mut reply = TronaMsg::zeroed();
    let _ = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx,
            rsrcsrv_mp,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
}
