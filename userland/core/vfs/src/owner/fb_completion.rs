// SPDX-License-Identifier: GPL-2.0-only
//
//! Dispdrv backend completion router.
//!
//! Wired onto every dispdrv `BackendSessionSlot::completion_fn`
//! during `begin_fb_mount`. The owner reactor's
//! `dispatch_pending_reply` resolves the originating `PendingOp` via
//! the 5-tuple `(fs_instance_id, mount_handle, session_id, live_gen,
//! tx_id)`, then hands control here together with the snapshot of
//! `OpCore` and the parsed `Resume::Fb` payload.
//!
//! The router decides the reply shape based on
//! [`FbResume::op_type`]:
//! - `FBRESUME_OP_GET_INFO` — width / height / pitch / format
//!   regs flow through to the client unchanged. No cap transfer.
//! - `FBRESUME_OP_GET_BACKING_MO` — dispdrv reply carried the
//!   framebuffer backing cap; the router forwards it to the client via
//!   the saved reply slot's `caps[0]` slot.
//! - `FBRESUME_OP_PRESENT` — ack only; reply label echoes through.
//!
//! Cap forwarding for `GET_BACKING_MO`: the dispdrv reply install
//! lands in the per-session callback recv's scratch slot. The
//! router stages that cap into `IpcContext`'s outbound `caps[0]`
//! slot before calling `reply_send`, which packs it into the
//! reply IPC. The receive scratch is cleared/re-armed by the
//! reactor's fixed receive-window helper on the next iteration;
//! the caller is responsible for not racing two
//! cap-bearing replies through the scratch in the same tick.

use trona_kernel::core_types::TronaMsg;

use crate::core::identity::FsInstanceId;
use crate::owner::VfsState;
use crate::owner::pending::{PendingKindPayload, TxId};
use crate::owner::resume::{FbResume, Resume};
use trona_server::ReplyLease;

// ---------------------------------------------------------------------------
// FbResume `op_type` discriminator values
// ---------------------------------------------------------------------------

/// Reply carries (width, height, pitch, format) inline regs.
pub(crate) const FBRESUME_OP_GET_INFO: u8 = 1;
/// Reply carries the framebuffer backing cap in `caps[0]`.
pub(crate) const FBRESUME_OP_GET_BACKING_MO: u8 = 2;
/// Reply is an ack — frame submission complete.
pub(crate) const FBRESUME_OP_PRESENT: u8 = 3;

// ---------------------------------------------------------------------------
// Reply register layout (`FB_*` reply shape, dispdrv-side contract)
// ---------------------------------------------------------------------------

/// Public reply label dispdrv echoes on success.
const FB_REPLY_OK: u64 = 0;

/// `FB_GET_INFO` reply carries inline scalars in regs[0..=5].
const FB_GET_INFO_REG_WIDTH: usize = 0;
const FB_GET_INFO_REG_HEIGHT: usize = 1;
const FB_GET_INFO_REG_PITCH: usize = 2;
const FB_GET_INFO_REG_FORMAT: usize = 3;
const FB_GET_INFO_REG_RED_GREEN: usize = 4;
const FB_GET_INFO_REG_BLUE: usize = 5;

/// Registered into `BackendSessionSlot::completion_fn` at
/// dispdrv-mount time. Receives the parked op's identity tuple
/// plus the freshly-decoded reply message; emits the matching
/// VFS_PUBLIC reply through the saved reply slot.
///
/// # Safety
///
/// Runs on the owner thread holding `&mut VfsState`. The dispatcher
/// has already validated the 5-tuple; this routine only checks the
/// resume-variant invariant before dispatching.
pub(crate) unsafe fn fb_completion(
    state: &mut VfsState,
    _fs_id: FsInstanceId,
    _tx_id: TxId,
    kind_payload: &PendingKindPayload,
    resume_ctx: Resume,
    backend_session_idx: u32,
    reply_lease: Option<ReplyLease>,
    reply_msg: &TronaMsg,
    _personality: crate::personality::Personality,
) {
    let fb_resume = match resume_ctx {
        Resume::Fb(r) => r,
        _ => {
            // Other domains landing on the dispdrv completion fn is
            // a caller-side stamping bug — drop the lease (kernel
            // finaliser cancels the saved token) and release the
            // backend credit. Same shape as the saltyfs / netsrv /
            // pty routers' wrong-resume handling.
            release_and_drop(state, reply_lease, backend_session_idx, kind_payload);
            return;
        }
    };
    if reply_lease
        .as_ref()
        .map(|l| l.epoch() != fb_resume.client_badge)
        .unwrap_or(false)
    {
        release_and_drop(state, reply_lease, backend_session_idx, kind_payload);
        return;
    }

    // The kind-payload slot/epoch fields capture the FB vnode the
    // request was issued against. Refuse a completion whose resume
    // payload no longer agrees with the captured vnode slot.
    if kind_payload.words[0] as u32 != fb_resume.vnode_slot {
        release_and_drop(state, reply_lease, backend_session_idx, kind_payload);
        return;
    }
    let _ = kind_payload.words[1];

    if reply_msg.label != FB_REPLY_OK {
        // dispdrv-side error — translate to the public-protocol
        // generic IO error. Future work narrows this map once
        // dispdrv defines distinct failure labels.
        send_error(reply_lease, reply_msg.label);
        state.backend_credit_release_for_session_idx(backend_session_idx);
        return;
    }

    match fb_resume.op_type {
        FBRESUME_OP_GET_INFO => emit_get_info_reply(reply_lease, reply_msg, fb_resume),
        FBRESUME_OP_GET_BACKING_MO => emit_get_backing_mo_reply(state, reply_lease, reply_msg),
        FBRESUME_OP_PRESENT => emit_ack_reply(reply_lease),
        _ => send_error(reply_lease, fb_resume.op_type as u64),
    }

    state.backend_credit_release_for_session_idx(backend_session_idx);
}

// ---------------------------------------------------------------------------
// Reply emission helpers
// ---------------------------------------------------------------------------

fn emit_get_info_reply(lease: Option<ReplyLease>, reply: &TronaMsg, fb_resume: FbResume) {
    let Some(l) = lease else { return };
    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    if fb_resume.request as u64 == trona_protocol::posix_abi::tty::FBIOGET_FSCREENINFO {
        out.regs[0] = reply.regs[FB_GET_INFO_REG_PITCH];
        out.regs[1] = reply.regs[FB_GET_INFO_REG_HEIGHT] * reply.regs[FB_GET_INFO_REG_PITCH];
        out.regs[2] = 0;
        out.length = 3;
    } else if fb_resume.request as u64 == trona_protocol::posix_abi::tty::FBIOGET_VSCREENINFO {
        out.regs[0] = reply.regs[FB_GET_INFO_REG_WIDTH];
        out.regs[1] = reply.regs[FB_GET_INFO_REG_HEIGHT];
        out.regs[2] = reply.regs[FB_GET_INFO_REG_FORMAT];
        out.regs[3] = reply.regs[FB_GET_INFO_REG_RED_GREEN];
        out.regs[4] = reply.regs[FB_GET_INFO_REG_BLUE];
        out.length = 5;
    } else {
        let len = (reply.length as usize).min(out.regs.len());
        for i in 0..len {
            out.regs[i] = reply.regs[i];
        }
        out.length = len as u64;
    }
    // SAFETY: The completion dispatcher owns the parked reply endpoint lease.
    crate::owner::op::reply_send(l, &out);
}

fn emit_get_backing_mo_reply(state: &mut VfsState, lease: Option<ReplyLease>, reply: &TronaMsg) {
    let Some(l) = lease else { return };
    // dispdrv's reply landed at the per-iteration receive scratch
    // slot — the kernel installs every inbound cap there because
    // the IPC buffer's `receive_index` is sticky-staged at reactor
    // boot. On success the dispdrv emits exactly one cap (the
    // framebuffer backing cap); `reply_send_with_cap` stages that
    // source slot into `caps[0]` and reply-marked MP_WRITE moves ownership out of
    // vfs's CSpace into the caller's. The recv scratch slot is
    // rearmed by the reactor's next iteration.
    // SAFETY: The owner reactor is processing the current backend reply; the
    // TLS IPC buffer belongs to this thread and is valid for this tick.
    let received = unsafe {
        trona_kernel::ipc_buffer::read_received_cap_count(
            (*trona_posix::tls::current_ipc_ctx()).ipc_buffer as *const _,
        )
    };
    if received == 0 {
        let mut out = TronaMsg::default();
        out.label = crate::ipc::protocol::public::vfs_error_to_public_reply(
            crate::core::error::VfsError::Io,
        );
        // SAFETY: The completion dispatcher owns the parked reply lease.
        crate::owner::op::reply_send(l, &out);
        return;
    }
    let mo_cap = state.recv_scratch_slot;
    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    out.regs[trona_protocol::vfs::public::VFS_BACKING_MO_REPLY_REG_SIZE] = reply.regs[0];
    out.regs[trona_protocol::vfs::public::VFS_BACKING_MO_REPLY_REG_OFFSET] = 0;
    out.regs[trona_protocol::vfs::public::VFS_BACKING_MO_REPLY_REG_MMAP_KIND] =
        trona_protocol::mm::MMAP_KIND_DEVICE;
    out.regs[trona_protocol::vfs::public::VFS_BACKING_MO_REPLY_REG_BACKING_ID] = 0;
    out.regs[trona_protocol::vfs::public::VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH] = reply.regs[0];
    out.length = trona_protocol::vfs::public::VFS_BACKING_MO_REPLY_REG_COUNT;
    // `mo_cap` is the single cap the backend delivered into the reactor's
    // sticky receive-scratch slot. `forward_external` moves it out to the
    // caller without touching the slot — the reactor rearms it next tick.
    // SAFETY: the parked reply lease is consumed exactly once here.
    crate::owner::op::reply_send_with_cap(
        l,
        &out,
        // SAFETY: mo_cap is the backend's cap in the reactor's sticky
        // receive-scratch slot (per the comment above) — an external-rearmer
        // slot, not any OwnedCap's; the send moves it out and leaves the slot.
        unsafe {
            trona_runtime::core::slot_alloc::forward_external(
                trona_runtime::core::slot_alloc::resolved_cap_ref(mo_cap),
            )
        },
    );
}

fn emit_ack_reply(lease: Option<ReplyLease>) {
    let Some(l) = lease else { return };
    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    out.length = 0;
    // SAFETY: The completion dispatcher owns the parked reply lease.
    crate::owner::op::reply_send(l, &out);
}

fn send_error(lease: Option<ReplyLease>, _backend_label: u64) {
    let Some(l) = lease else { return };
    let mut out = TronaMsg::default();
    out.label =
        crate::ipc::protocol::public::vfs_error_to_public_reply(crate::core::error::VfsError::Io);
    // SAFETY: The completion dispatcher owns the parked reply lease.
    crate::owner::op::reply_send(l, &out);
}

fn release_and_drop(
    state: &mut VfsState,
    lease: Option<ReplyLease>,
    backend_session_idx: u32,
    _kind_payload: &PendingKindPayload,
) {
    if let Some(l) = lease {
        // SAFETY: The completion dispatcher owns the parked reply lease.
        crate::owner::op::reply_drop(l);
    }
    state.backend_credit_release_for_session_idx(backend_session_idx);
}
