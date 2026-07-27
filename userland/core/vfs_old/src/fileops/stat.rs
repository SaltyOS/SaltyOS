// SPDX-License-Identifier: GPL-2.0-only
//! Stat and access operations — VopMetaOps dispatch.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_posix::types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{resolve_fd, root_vnode_for};
use crate::owner::pending::{WALK_PATH_MAX, WalkCursor, WalkPolicy};
use crate::owner::resume::{
    Resume,
    fs::{FsResume, NameiTerminal},
};
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::namei_async::{NameiWalkOutcome, namei_walk_async};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::VnodeHandle;

use crate::server::types::ClientHandle;

/// Fill stat reply from a VnodeHandle via MetaOps::getattr.
///
/// Returns `true` when the caller should skip emitting a reply in
/// the current dispatch turn — i.e. the backend parked the RPC and
/// the matching correlated backend completion will resume via
/// `resume_fill_stat_reply`. Returns `false` for the synchronous
/// path (success or hard error) where `reply` has already been
/// populated and should be sent back immediately.
pub(crate) unsafe fn fill_stat_reply_handle(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
    vh: VnodeHandle,
) -> bool {
    unsafe {
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        let vnode_snap = &*ctx.vnode;
        let ops = vnode_snap.ops;
        if ops.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let vkey = vnode_snap.vnode_key();
        let vnode_id = vnode_snap.id;
        let vnode_vtype = vnode_snap.vtype as u64;
        let mut attr = VAttr::zeroed();
        let call_result = ((*ops).meta.getattr)(&mut ctx, &raw mut attr);

        match call_result {
            Ok(Ready(())) => {
                (*reply).label = TRONA_OK;
                (*reply).length = 8;
                (*reply).regs[0] = vnode_id;
                (*reply).regs[1] = attr.mode as u64;
                (*reply).regs[2] = attr.nlink as u64;
                (*reply).regs[3] = attr.size;
                (*reply).regs[4] = attr.uid as u64;
                (*reply).regs[5] = attr.gid as u64;
                (*reply).regs[6] = attr.mtime / 1_000_000_000;
                (*reply).regs[7] = vnode_vtype;
                false
            }
            Ok(Parked(handle)) => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::FillStatReply {
                        client: cli_handle,
                        vkey,
                    }),
                ) {
                    (*reply).label = err.to_trona();
                    return false;
                }
                true
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// Fill an `access(2)`-style reply from a resolved vnode.
///
/// Returns `true` when the terminal `meta.access` parked and the
/// reply will be emitted later via `resume_fill_access_reply`.
pub(crate) unsafe fn fill_access_reply_handle(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
    vh: VnodeHandle,
    mode: u32,
) -> bool {
    unsafe {
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
            (*reply).label = TRONA_OK;
            return false;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            (*reply).label = TRONA_OK;
            return false;
        }
        let vkey = (*ctx.vnode).vnode_key();
        match ((*ops).meta.access)(&mut ctx, mode, &raw const cred) {
            Ok(Ready(())) => {
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::FillAccessReply {
                        client: cli_handle,
                        vkey,
                    }),
                ) {
                    (*reply).label = err.to_trona();
                    return false;
                }
                true
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// Resume entry point invoked by the owning backend's
/// `BackendSessionSlot::completion_fn` after it has parsed the wire
/// reply into a backend-agnostic [`VAttr`]. Re-resolves `vkey` →
/// `VnodeHandle`, merges the cached vnode id + vtype with the parsed
/// attrs, and emits the client stat reply via the saved reply cap.
///
/// `attr` is `None` when the backend reported an error — the reply
/// is delivered as `TRONA_IO_ERROR` so the client unblocks with a
/// stable label.
pub(crate) unsafe fn resume_fill_stat_reply(
    state: &mut VfsState,
    _client: ClientHandle,
    vkey: crate::vfs_core::identity::VnodeKey,
    reply_slot: u64,
    attr: Option<VAttr>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        // Re-resolve the vnode so we can harvest its `id` + `vtype`
        // for the reply shape. The mount is guaranteed live (stale
        // check already passed), but the specific vnode slot may
        // have been reclaimed if refcount dropped during the RPC.
        let vh = state.lookup_resolve_cache(vkey);
        let (vnode_id, vnode_vtype) = if let Some(vh) = vh {
            match state.vnodes.get(vh) {
                Some(v) => (v.id, v.vtype as u64),
                None => {
                    out.label = TRONA_INVALID_OPERATION;
                    state.send_saved_reply(reply_slot, &raw const out);
                    return;
                }
            }
        } else {
            out.label = TRONA_INVALID_OPERATION;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        let Some(attr) = attr else {
            out.label = TRONA_IO_ERROR;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        out.label = TRONA_OK;
        out.length = 8;
        out.regs[0] = vnode_id;
        out.regs[1] = attr.mode as u64;
        out.regs[2] = attr.nlink as u64;
        out.regs[3] = attr.size;
        out.regs[4] = attr.uid as u64;
        out.regs[5] = attr.gid as u64;
        out.regs[6] = attr.mtime / 1_000_000_000;
        out.regs[7] = vnode_vtype;
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Resume entry for parked `access(2)` syscalls.
pub(crate) unsafe fn resume_fill_access_reply(
    state: &mut VfsState,
    _client: ClientHandle,
    vkey: crate::vfs_core::identity::VnodeKey,
    reply_slot: u64,
    ack: Result<(), crate::vfs_core::error::VfsError>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        if state.lookup_resolve_cache(vkey).is_none() {
            out.label = TRONA_INVALID_OPERATION;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        out.label = match ack {
            Ok(()) => TRONA_OK,
            Err(e) => e.to_trona(),
        };
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Emit a saved reply for a terminal `access` check on `vh`.
///
/// This is the deferred twin of `fill_access_reply_handle`: the async
/// walker has already resolved the path and already owns the saved
/// caller cap, so this helper only drives the terminal `meta.access`
/// VOP and either sends the reply immediately or stamps
/// `FillAccessReply` for the backend completion router.
pub(crate) unsafe fn send_access_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vh: VnodeHandle,
    mode: u32,
    reply_slot: u64,
) {
    unsafe {
        if reply_slot == 0 {
            return;
        }

        let mut out = TronaMsg::zeroed();
        let vkey = match state.vnodes.get(vh) {
            Some(v) => v.vnode_key(),
            None => {
                out.label = TRONA_INVALID_OPERATION;
                state.send_saved_reply(reply_slot, &raw const out);
                return;
            }
        };
        let cred = crate::owner::dispatch::client_cred(state, client);
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
            out.label = TRONA_OK;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            out.label = TRONA_OK;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        match ((*ops).meta.access)(&mut ctx, mode, &raw const cred) {
            Ok(Ready(())) => {
                out.label = TRONA_OK;
                state.send_saved_reply(reply_slot, &raw const out);
            }
            Ok(Parked(handle)) => {
                let badge = state.clients.get(client).map(|c| c.badge).unwrap_or(0);
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    Resume::Fs(FsResume::FillAccessReply { client, vkey }),
                ) {
                    out.label = TRONA_BUSY;
                    state.send_saved_reply(reply_slot, &raw const out);
                }
            }
            Err(e) => {
                out.label = e.to_trona();
                state.send_saved_reply(reply_slot, &raw const out);
            }
        }
    }
}

/// Second stage of `stat_for_exec`: harvest `getattr` after the
/// executable access check has already succeeded.
unsafe fn send_stat_for_exec_attr_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vh: VnodeHandle,
    vkey: crate::vfs_core::identity::VnodeKey,
    reply_slot: u64,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
            out.label = TRONA_NOT_FOUND;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            out.label = TRONA_NOT_FOUND;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        let mut attr = VAttr::zeroed();
        match ((*ops).meta.getattr)(&mut ctx, &raw mut attr) {
            Ok(Ready(())) => {
                out.label = TRONA_OK;
                out.length = 4;
                out.regs[0] = attr.mode as u64;
                out.regs[1] = attr.uid as u64;
                out.regs[2] = attr.gid as u64;
                out.regs[3] = attr.size;
                state.send_saved_reply(reply_slot, &raw const out);
            }
            Ok(Parked(handle)) => {
                let badge = state.clients.get(client).map(|c| c.badge).unwrap_or(0);
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    Resume::Fs(FsResume::FillStatForExecAttrReply { client, vkey }),
                ) {
                    out.label = TRONA_BUSY;
                    state.send_saved_reply(reply_slot, &raw const out);
                }
            }
            Err(e) => {
                out.label = e.to_trona();
                state.send_saved_reply(reply_slot, &raw const out);
            }
        }
    }
}

/// Emit the deferred `stat_for_exec` reply for an already-resolved
/// vnode.
///
/// Unlike plain `stat`, exec preflight is intentionally two-stage:
/// first verify `X_OK` with the caller's credentials, then return the
/// compact `(mode, uid, gid, size)` tuple that exec uses. Parking can
/// happen at either terminal VOP, so both stages have dedicated
/// `FsResume` variants.
pub(crate) unsafe fn send_stat_for_exec_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vh: VnodeHandle,
    reply_slot: u64,
) {
    unsafe {
        if reply_slot == 0 {
            return;
        }

        let mut out = TronaMsg::zeroed();
        let vkey = match state.vnodes.get(vh) {
            Some(v) => v.vnode_key(),
            None => {
                out.label = TRONA_NOT_FOUND;
                state.send_saved_reply(reply_slot, &raw const out);
                return;
            }
        };
        let cred = crate::owner::dispatch::client_cred(state, client);
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
            out.label = TRONA_NOT_FOUND;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            out.label = TRONA_NOT_FOUND;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        match ((*ops).meta.access)(&mut ctx, X_OK as u32, &raw const cred) {
            Ok(Ready(())) => {
                send_stat_for_exec_attr_reply_for_vnode(state, client, vh, vkey, reply_slot);
            }
            Ok(Parked(handle)) => {
                let badge = state.clients.get(client).map(|c| c.badge).unwrap_or(0);
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    Resume::Fs(FsResume::FillStatForExecAccessReply { client, vkey }),
                ) {
                    out.label = TRONA_BUSY;
                    state.send_saved_reply(reply_slot, &raw const out);
                }
            }
            Err(_) => {
                out.label = TRONA_INSUFFICIENT_RIGHTS;
                state.send_saved_reply(reply_slot, &raw const out);
            }
        }
    }
}

/// Resume the parked `access(X_OK)` half of `stat_for_exec`, then run
/// the second-stage `getattr` on the same resolved vnode.
pub(crate) unsafe fn resume_fill_stat_for_exec_access_reply(
    state: &mut VfsState,
    client: ClientHandle,
    vkey: crate::vfs_core::identity::VnodeKey,
    reply_slot: u64,
    ack: Result<(), crate::vfs_core::error::VfsError>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();
        let Some(vh) = state.lookup_resolve_cache(vkey) else {
            out.label = TRONA_INVALID_OPERATION;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };
        if ack.is_err() {
            out.label = TRONA_INSUFFICIENT_RIGHTS;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        send_stat_for_exec_attr_reply_for_vnode(state, client, vh, vkey, reply_slot);
    }
}

/// Resume the parked `getattr` half of `stat_for_exec`.
pub(crate) unsafe fn resume_fill_stat_for_exec_attr_reply(
    state: &mut VfsState,
    _client: ClientHandle,
    vkey: crate::vfs_core::identity::VnodeKey,
    reply_slot: u64,
    attr: Option<VAttr>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        if state.lookup_resolve_cache(vkey).is_none() {
            out.label = TRONA_INVALID_OPERATION;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        let Some(attr) = attr else {
            out.label = TRONA_IO_ERROR;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        out.label = TRONA_OK;
        out.length = 4;
        out.regs[0] = attr.mode as u64;
        out.regs[1] = attr.uid as u64;
        out.regs[2] = attr.gid as u64;
        out.regs[3] = attr.size;
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// fstat — owner-loop version. Returns `true` when the reply is
/// deferred (the backend parked the RPC); `false` means `reply` was
/// populated synchronously and the dispatcher should send it.
pub(crate) unsafe fn handle_fstat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let vh = match resolve_fd(state, cli_handle, fd) {
            Some(s) if s.vnode_handle().is_valid() => s.vnode_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        fill_stat_reply_handle(state, cli_handle, reply, vh)
    }
}

/// stat — owner-loop version. Path-based stat via async namei walk.
/// Same skip_reply contract as `handle_fstat_owned`.
///
/// All paths go through the async walker (`namei_walk_async`).
/// Cross-mount transparency (e.g. `/dev`), backend-resolved lookups,
/// and multi-component paths all follow the same code path. When
/// the walk or terminal getattr parks on a backend RPC, the reply
/// is deferred and resumes via `FsResume::NameiStep` or
/// `FsResume::FillStatAfterWalk`.
pub(crate) unsafe fn handle_stat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let Some((path_ptr, path_len)) = crate::fileops::open::normalize_path_owned(
            state,
            cli_handle,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };

        let root_vh = root_vnode_for(state, cli_handle);
        stat_path_from_start_owned(
            state,
            cli_handle,
            root_vh,
            root_vh,
            path_ptr,
            path_len,
            crate::vfs_core::namei_common::NAMEI_FOLLOW,
            reply,
        )
    }
}

/// Shared async stat walker used by absolute `stat(2)` and
/// relative-handle callers such as `fstatat` / `lstat`.
///
/// Builds a `WalkCursor` from the supplied start/root pair,
/// drives `namei_walk_async`, and either:
/// - formats a synchronous reply via `fill_stat_reply_handle` on
///   `Ok(result)`,
/// - allocates a reply slot + stamps `Resume::Fs(FsResume::NameiStep { .. })`
///   on `NameiWalkOutcome::Parked`, or
/// - emits a synchronous error label on `Err(other)`.
///
/// Returns `true` when the reply is deferred; `false` when
/// `reply` was populated synchronously.
pub(crate) unsafe fn stat_path_from_start_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    start_vh: VnodeHandle,
    root_vh: VnodeHandle,
    path_ptr: *const u8,
    path_len: u8,
    namei_flags: u32,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        // Path must fit in the cursor's inline buffer.
        if (path_len as usize) > WALK_PATH_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let Some(root_vkey) = state.vnodes.get(root_vh).map(|v| v.vnode_key()) else {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        };
        state.install_resolve_cache(root_vkey, root_vh);
        let initial_vh = if !path_ptr.is_null() && *path_ptr == b'/' {
            root_vh
        } else {
            start_vh
        };
        let Some(start_vkey) = state.vnodes.get(initial_vh).map(|v| v.vnode_key()) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        state.install_resolve_cache(start_vkey, initial_vh);

        let mut remaining_path = [0u8; WALK_PATH_MAX];
        for i in 0..(path_len as usize) {
            remaining_path[i] = *path_ptr.add(i);
        }
        let mut effective_flags = namei_flags;
        if (path_len as usize) > 1 {
            if *path_ptr.add((path_len as usize) - 1) == b'/' {
                effective_flags |= crate::vfs_core::namei_common::NAMEI_DIRECTORY;
            }
        }

        let mut cursor = WalkCursor {
            cwd_vkey: start_vkey,
            root_vkey,
            remaining_path,
            remaining_len: path_len as u16,
            follow_depth: 0,
            cred: crate::owner::dispatch::client_cred(state, cli_handle),
            flags: effective_flags,
            policy: WalkPolicy::Continue,
        };

        match namei_walk_async(state, &mut cursor) {
            NameiWalkOutcome::Done(result) => {
                if result.vp.is_valid() {
                    fill_stat_reply_handle(state, cli_handle, reply, result.vp)
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                    false
                }
            }
            NameiWalkOutcome::Parked { handle, phase } => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::NameiStep {
                        client: cli_handle,
                        cursor,
                        phase,
                        terminal: NameiTerminal::Stat,
                    }),
                ) {
                    (*reply).label = err.to_trona();
                    return false;
                }
                true
            }
            NameiWalkOutcome::Error(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// Shared async access walker used by absolute `access(2)` and
/// dirfd-relative `faccessat(2)`.
///
/// The terminal access check itself can still park, so this helper
/// may defer twice: once during lookup (`NameiStep`) and once during
/// the final `meta.access` (`FillAccessReply`).
pub(crate) unsafe fn access_path_from_start_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    start_vh: VnodeHandle,
    root_vh: VnodeHandle,
    path_ptr: *const u8,
    path_len: u8,
    mode: u32,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if (path_len as usize) > WALK_PATH_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let Some(root_vkey) = state.vnodes.get(root_vh).map(|v| v.vnode_key()) else {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        };
        state.install_resolve_cache(root_vkey, root_vh);
        let initial_vh = if !path_ptr.is_null() && *path_ptr == b'/' {
            root_vh
        } else {
            start_vh
        };
        let Some(start_vkey) = state.vnodes.get(initial_vh).map(|v| v.vnode_key()) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        state.install_resolve_cache(start_vkey, initial_vh);

        let mut remaining_path = [0u8; WALK_PATH_MAX];
        for i in 0..(path_len as usize) {
            remaining_path[i] = *path_ptr.add(i);
        }

        let mut namei_flags = crate::vfs_core::namei_common::NAMEI_FOLLOW;
        if (path_len as usize) > 1 && *path_ptr.add((path_len as usize) - 1) == b'/' {
            namei_flags |= crate::vfs_core::namei_common::NAMEI_DIRECTORY;
        }

        let mut cursor = WalkCursor {
            cwd_vkey: start_vkey,
            root_vkey,
            remaining_path,
            remaining_len: path_len as u16,
            follow_depth: 0,
            cred: crate::owner::dispatch::client_cred(state, cli_handle),
            flags: namei_flags,
            policy: WalkPolicy::Continue,
        };

        match namei_walk_async(state, &mut cursor) {
            NameiWalkOutcome::Done(result) => {
                if result.vp.is_valid() {
                    fill_access_reply_handle(state, cli_handle, reply, result.vp, mode)
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                    false
                }
            }
            NameiWalkOutcome::Parked { handle, phase } => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::NameiStep {
                        client: cli_handle,
                        cursor,
                        phase,
                        terminal: NameiTerminal::Access { mode },
                    }),
                ) {
                    (*reply).label = err.to_trona();
                    return false;
                }
                true
            }
            NameiWalkOutcome::Error(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// Shared async walker for exec preflight on a path.
///
/// This is intentionally not just "stat with a different reply shape".
/// Exec resolution must prove `X_OK` first, then fetch attrs, and each
/// terminal VOP may independently park. That is why the helper always
/// transitions onto a saved-reply path before running the terminal
/// stage, even when namei itself completed synchronously.
pub(crate) unsafe fn stat_for_exec_path_from_start_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    start_vh: VnodeHandle,
    root_vh: VnodeHandle,
    path_ptr: *const u8,
    path_len: u8,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if (path_len as usize) > WALK_PATH_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let Some(root_vkey) = state.vnodes.get(root_vh).map(|v| v.vnode_key()) else {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        };
        state.install_resolve_cache(root_vkey, root_vh);
        let initial_vh = if !path_ptr.is_null() && *path_ptr == b'/' {
            root_vh
        } else {
            start_vh
        };
        let Some(start_vkey) = state.vnodes.get(initial_vh).map(|v| v.vnode_key()) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        state.install_resolve_cache(start_vkey, initial_vh);

        let mut remaining_path = [0u8; WALK_PATH_MAX];
        for i in 0..(path_len as usize) {
            remaining_path[i] = *path_ptr.add(i);
        }

        let mut cursor = WalkCursor {
            cwd_vkey: start_vkey,
            root_vkey,
            remaining_path,
            remaining_len: path_len as u16,
            follow_depth: 0,
            cred: crate::owner::dispatch::client_cred(state, cli_handle),
            flags: crate::vfs_core::namei_common::NAMEI_FOLLOW,
            policy: WalkPolicy::Continue,
        };

        match namei_walk_async(state, &mut cursor) {
            NameiWalkOutcome::Done(result) => {
                if result.vp.is_valid() {
                    // `stat_for_exec` always replies through the
                    // deferred path because its terminal stage is a
                    // two-step state machine (`access` then `getattr`)
                    // and either half may park.
                    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                    let reply_slot = match state.alloc_reply_slot_for(badge) {
                        Some(slot) => slot,
                        None => {
                            (*reply).label = TRONA_OUT_OF_MEMORY;
                            return false;
                        }
                    };
                    let save_err =
                        trona_kernel::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
                    if save_err != 0 {
                        state.release_reply_slot(reply_slot);
                        (*reply).label = TRONA_INVALID_OPERATION;
                        return false;
                    }
                    send_stat_for_exec_reply_for_vnode(state, cli_handle, result.vp, reply_slot);
                    true
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                    false
                }
            }
            NameiWalkOutcome::Parked { handle, phase } => {
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::NameiStep {
                        client: cli_handle,
                        cursor,
                        phase,
                        terminal: NameiTerminal::StatForExec,
                    }),
                ) {
                    (*reply).label = err.to_trona();
                    return false;
                }
                true
            }
            NameiWalkOutcome::Error(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// stat_for_exec — owner-loop version.
pub(crate) unsafe fn handle_stat_for_exec_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let Some((path_ptr, path_len)) = crate::fileops::open::normalize_path_owned(
            state,
            cli_handle,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        stat_for_exec_path_from_start_owned(
            state, cli_handle, root, root, path_ptr, path_len, reply,
        )
    }
}

/// canon_path — owner-loop version. Pure path canonicalization, no VOP calls.
pub(crate) unsafe fn handle_canon_path_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = crate::fileops::open::normalize_path_owned(
            state,
            cli_handle,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        (*reply).label = TRONA_OK;
        (*reply).regs[0] = path_len as u64;
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path_ptr.add(i);
        }
        (*reply).length = 1 + ((path_len as u64 + 7) / 8);
    }
}

/// access — owner-loop version.
pub(crate) unsafe fn handle_access_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let Some((path_ptr, path_len)) = crate::fileops::open::normalize_path_owned(
            state,
            cli_handle,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let amode = (*msg).regs[0] as u32;
        access_path_from_start_owned(
            state, cli_handle, root, root, path_ptr, path_len, amode, reply,
        )
    }
}
