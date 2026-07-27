// SPDX-License-Identifier: GPL-2.0-only
//! Generic resume helpers for readlink / getxattr / listxattr.
//!
//! The backend's [`BackendSessionSlot::completion_fn`] is responsible
//! for parsing the wire reply and pre-extracting any SHM payload.
//! These helpers receive fully-parsed generic data (a byte slice or an
//! error indicator) and emit the POSIX-shaped client reply via the
//! saved caller cap.
//!
//! The earlier versions of these functions reached directly into
//! backend-private mount/vnode data and called backend-specific
//! parse helpers — that coupling now lives entirely in each
//! backend's completion router, keeping fileops backend-neutral.

use trona_kernel::core_types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::dispatch::client_cred;
use crate::owner::pending::{WALK_PATH_MAX, WalkCursor, WalkPolicy};
use crate::owner::resume::{
    Resume,
    fs::{FsResume, NameiTerminal},
};
use crate::server::consts::MAX_PATH_LEN;
use crate::server::types::ClientHandle;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::identity::VnodeKey;
use crate::vfs_core::namei_async::{NameiWalkOutcome, namei_walk_async};
use crate::vfs_core::namei_common::{NAMEI_DIRECTORY, NAMEI_NOFOLLOW_FINAL};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::VnodeHandle;

/// Issue a terminal `readlink` on an already-resolved vnode.
///
/// Returns `true` when the backend parked the metadata RPC and the
/// reply will be emitted later via `FsResume::FillReadlinkReply`.
pub(crate) unsafe fn fill_readlink_reply_handle(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
    vh: VnodeHandle,
) -> bool {
    unsafe {
        let cred = client_cred(state, cli_handle);
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
            (*reply).label = TRONA_IO_ERROR;
            return false;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            (*reply).label = TRONA_IO_ERROR;
            return false;
        }
        let vkey = (*ctx.vnode).vnode_key();
        let mut buf = [0u8; MAX_PATH_LEN];
        match ((*ops).meta.readlink)(&mut ctx, buf.as_mut_ptr(), MAX_PATH_LEN, &raw const cred) {
            Ok(Ready(n)) => {
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = n as u64;
                let dst = &raw mut (*reply).regs[1] as *mut u8;
                for i in 0..n {
                    *dst.add(i) = buf[i];
                }
                (*reply).length = 1 + ((n as u64 + 7) / 8);
                false
            }
            Ok(Parked(handle)) => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::FillReadlinkReply {
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

/// Shared async walker entry for path-based `readlinkat`.
///
/// The walker owns path semantics and park/resume state; the terminal
/// `readlink` stays a separate fileop on the resolved vnode.
pub(crate) unsafe fn readlink_path_from_start_owned(
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

        let mut namei_flags = NAMEI_NOFOLLOW_FINAL;
        if (path_len as usize) > 1 && *path_ptr.add((path_len as usize) - 1) == b'/' {
            namei_flags |= NAMEI_DIRECTORY;
        }

        let mut cursor = WalkCursor {
            cwd_vkey: start_vkey,
            root_vkey,
            remaining_path,
            remaining_len: path_len as u16,
            follow_depth: 0,
            cred: client_cred(state, cli_handle),
            flags: namei_flags,
            policy: WalkPolicy::Continue,
        };

        match namei_walk_async(state, &mut cursor) {
            NameiWalkOutcome::Done(result) => {
                if result.vp.is_valid() {
                    fill_readlink_reply_handle(state, cli_handle, reply, result.vp)
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
                        terminal: NameiTerminal::Readlink,
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

/// Emit a saved reply for a terminal `readlink` on `vh`.
pub(crate) unsafe fn send_readlink_reply_for_vnode(
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
                out.label = TRONA_IO_ERROR;
                state.send_saved_reply(reply_slot, &raw const out);
                return;
            }
        };
        let cred = client_cred(state, client);
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
            out.label = TRONA_IO_ERROR;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            out.label = TRONA_IO_ERROR;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        let mut buf = [0u8; MAX_PATH_LEN];
        match ((*ops).meta.readlink)(&mut ctx, buf.as_mut_ptr(), MAX_PATH_LEN, &raw const cred) {
            Ok(Ready(n)) => {
                out.label = TRONA_OK;
                out.regs[0] = n as u64;
                let dst = &raw mut out.regs[1] as *mut u8;
                for i in 0..n {
                    *dst.add(i) = buf[i];
                }
                out.length = 1 + ((n as u64 + 7) / 8);
                state.send_saved_reply(reply_slot, &raw const out);
            }
            Ok(Parked(handle)) => {
                let badge = state.clients.get(client).map(|c| c.badge).unwrap_or(0);
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    Resume::Fs(FsResume::FillReadlinkReply { client, vkey }),
                ) {
                    out.label = TRONA_IO_ERROR;
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

/// Resume entry for parked `readlink` syscalls. `target` is `None`
/// on error; `Some(bytes)` otherwise where `bytes.len()` is the
/// symlink-target byte count (capped at [`MAX_PATH_LEN`] by the
/// caller).
pub(crate) unsafe fn resume_fill_readlink_reply(
    state: &mut VfsState,
    _client: ClientHandle,
    vkey: VnodeKey,
    reply_slot: u64,
    target: Option<&[u8]>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        // Confirm vnode still live (mount already validated by dispatcher).
        if state.lookup_resolve_cache(vkey).is_none() {
            out.label = TRONA_INVALID_OPERATION;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let Some(bytes) = target else {
            out.label = TRONA_IO_ERROR;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        // Cap to MAX_PATH_LEN — matches the sync path's buf size.
        let n = core::cmp::min(bytes.len(), MAX_PATH_LEN as usize);

        out.label = TRONA_OK;
        out.regs[0] = n as u64;
        let dst = &raw mut out.regs[1] as *mut u8;
        for i in 0..n {
            *dst.add(i) = bytes[i];
        }
        out.length = 1 + ((n as u64 + 7) / 8);
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Resume entry for parked `listxattr` syscalls.
///
/// `result` carries `(bytes_needed, name_list_slice)` on success,
/// where `name_list_slice` is the NUL-separated name list already
/// copied out of the backend's SHM region. `None` indicates a
/// backend error.
pub(crate) unsafe fn resume_fill_listxattr_reply(
    state: &mut VfsState,
    _client: ClientHandle,
    vkey: VnodeKey,
    reply_slot: u64,
    result: Option<(usize, &[u8])>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        if state.lookup_resolve_cache(vkey).is_none() {
            out.label = TRONA_INVALID_OPERATION;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let Some((bytes_needed, names)) = result else {
            out.label = TRONA_IO_ERROR;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        const LIST_INLINE_MAX: usize = 31 * 8;
        let copy_len = core::cmp::min(names.len(), LIST_INLINE_MAX);

        out.label = TRONA_OK;
        out.regs[0] = bytes_needed as u64;
        if copy_len > 0 {
            let dst = &raw mut out.regs[1] as *mut u8;
            for i in 0..copy_len {
                *dst.add(i) = names[i];
            }
        }
        out.length = 1 + ((copy_len as u64 + 7) / 8);
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Resume entry for parked simple-mutation syscalls (`setattr`,
/// `setxattr`, `removexattr`). Backend-neutral at this seam: the
/// backend's `completion_fn` has already parsed the reply, mapped
/// backend-level failures to [`VfsError`], and refreshed any
/// backend-private attribute cache before invoking this helper.
/// The fileops layer only needs to re-confirm the vnode identity
/// and emit the POSIX-shaped ack reply.
pub(crate) unsafe fn resume_fill_ack_mutation_reply(
    state: &mut VfsState,
    _client: ClientHandle,
    vkey: VnodeKey,
    reply_slot: u64,
    ack: Result<(), crate::vfs_core::error::VfsError>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        if state.lookup_resolve_cache(vkey).is_none() {
            out.label = TRONA_INVALID_OPERATION;
            out.length = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        match ack {
            Ok(()) => {
                out.label = TRONA_OK;
                out.length = 0;
            }
            Err(e) => {
                out.label = e.to_trona();
                out.length = 0;
            }
        }
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Resume entry for parked `getxattr` syscalls.
///
/// `result` carries `(total_value_len, value_slice)` on success,
/// where `value_slice` holds the already-extracted value bytes (capped
/// to the inline reply capacity). `None` indicates a backend error.
pub(crate) unsafe fn resume_fill_xattr_get_reply(
    state: &mut VfsState,
    _client: ClientHandle,
    vkey: VnodeKey,
    reply_slot: u64,
    result: Option<(usize, &[u8])>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        if state.lookup_resolve_cache(vkey).is_none() {
            out.label = TRONA_INVALID_OPERATION;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let Some((val_len, value)) = result else {
            out.label = TRONA_IO_ERROR;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        const VAL_INLINE_MAX: usize = 31 * 8;
        let copy_len = core::cmp::min(value.len(), VAL_INLINE_MAX);

        out.label = TRONA_OK;
        out.regs[0] = val_len as u64;
        if copy_len > 0 {
            let dst = &raw mut out.regs[1] as *mut u8;
            for i in 0..copy_len {
                *dst.add(i) = value[i];
            }
        }
        out.length = 1 + ((copy_len as u64 + 7) / 8);
        state.send_saved_reply(reply_slot, &raw const out);
    }
}
