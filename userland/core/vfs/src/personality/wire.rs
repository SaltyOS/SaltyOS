// SPDX-License-Identifier: GPL-2.0-only
//
//! Raw wire-reply helpers — POSIX `errno` / NT `IoStatusBlock`
//! emission used directly by sync entries that have not yet
//! migrated to the typed `ReplyIntent` dispatcher in
//! [`super::reply`].
//!
//! Two categories:
//!
//! - **Personality-tagged** (`send_*_for_client`, `send_reply_err_for_op`,
//!   `send_*_typed`): pick the wire shape from a `Personality` /
//!   `ClientHandle` / `OpCore::personality` so the same helper
//!   serves both POSIX and Win32 callers.
//!
//! - **Single-personality** (`send_error_reply`, `send_ok_reply`,
//!   `send_ntstatus_reply`, `send_ntstatus_ok_reply`): emit one
//!   personality's wire shape directly. Use these only when the
//!   caller already knows which personality it is.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

/// Emit a typed-error reply through the supplied reply endpoint
/// lease. Encodes `err` via the POSIX `errno` surface; Win32
/// callers use [`send_ntstatus_reply`] instead.
pub(crate) fn send_error_reply(reply_lease: ReplyLease, err: VfsError) {
    let mut out = TronaMsg::default();
    out.label = crate::ipc::protocol::public::vfs_error_to_public_reply(err);
    out.length = 0;
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Emit a sync OK reply with optional regs (POSIX wire).
pub(crate) fn send_ok_reply(reply_lease: ReplyLease, regs: &[u64]) {
    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    out.length = (regs.len().min(32)) as u64;
    for (i, &v) in regs.iter().enumerate().take(32) {
        out.regs[i] = v;
    }
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Win32 reply helper — encode `err` as an NTSTATUS value
/// (`STATUS_*`) carried in `regs[0]` of the reply.
pub(crate) fn send_ntstatus_reply(reply_lease: ReplyLease, err: VfsError) {
    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    out.regs[0] = crate::personality::win32::consts::vfs_error_to_ntstatus(err) as u64;
    out.length = 1;
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Win32 success reply — emits `STATUS_SUCCESS` in `regs[0]`,
/// with up to 31 additional NT-level information words packed
/// into `regs[1..]`.
pub(crate) fn send_ntstatus_ok_reply(reply_lease: ReplyLease, extras: &[u64]) {
    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    out.regs[0] = 0;
    let count = extras.len().min(31);
    for (i, &v) in extras.iter().enumerate().take(31) {
        out.regs[1 + i] = v;
    }
    out.length = (1 + count) as u64;
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Personality-aware success reply core. Branches on
/// `personality` and dispatches to either [`send_ok_reply`]
/// (POSIX wire — `regs` echoed verbatim) or
/// [`send_ntstatus_ok_reply`] (Win32 wire — `STATUS_SUCCESS` in
/// `regs[0]`, caller's `regs` packed into `regs[1..]`).
pub(crate) fn send_reply_ok_typed(
    personality: crate::personality::Personality,
    reply_lease: ReplyLease,
    regs: &[u64],
) {
    match personality {
        crate::personality::Personality::Win32 => send_ntstatus_ok_reply(reply_lease, regs),
        _ => send_ok_reply(reply_lease, regs),
    }
}

/// Personality-aware error reply core. Counterpart of
/// [`send_reply_ok_typed`].
pub(crate) fn send_reply_err_typed(
    personality: crate::personality::Personality,
    reply_lease: ReplyLease,
    err: VfsError,
) {
    match personality {
        crate::personality::Personality::Win32 => send_ntstatus_reply(reply_lease, err),
        _ => send_error_reply(reply_lease, err),
    }
}

/// Personality-aware success reply driven by a `ClientHandle` —
/// looks up `client.personality` and dispatches to
/// [`send_reply_ok_typed`].
pub(crate) fn send_reply_ok_for_client(
    state: &VfsState,
    client: ClientHandle,
    reply_lease: ReplyLease,
    regs: &[u64],
) {
    let personality = state
        .clients
        .get(client)
        .map(|c| c.personality)
        .unwrap_or(crate::personality::Personality::Posix);
    send_reply_ok_typed(personality, reply_lease, regs)
}

/// Personality-aware error reply driven by a `ClientHandle`.
pub(crate) fn send_reply_err_for_client(
    state: &VfsState,
    client: ClientHandle,
    reply_lease: ReplyLease,
    err: VfsError,
) {
    let personality = state
        .clients
        .get(client)
        .map(|c| c.personality)
        .unwrap_or(crate::personality::Personality::Posix);
    send_reply_err_typed(personality, reply_lease, err)
}

/// Personality-aware error reply driven by an `OpCore`.
pub(crate) fn send_reply_err_for_op(
    op_core: &crate::owner::op::OpCore,
    reply_lease: ReplyLease,
    err: VfsError,
) {
    send_reply_err_typed(op_core.personality, reply_lease, err)
}
