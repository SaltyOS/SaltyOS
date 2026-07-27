// SPDX-License-Identifier: GPL-2.0-only
//! Directory open and readdir — VopMetaOps/VopDataOps dispatch.

use trona_kernel::core_types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{build_data_ctx, resolve_fd, resolve_fd_mut, root_vnode_for};
use crate::owner::op::OpKind;
use crate::owner::pending::{WALK_PATH_MAX, WalkCursor, WalkPolicy};
use crate::owner::resume::{
    Resume,
    fs::{FsResume, NameiTerminal},
};
use crate::server::consts::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::namei_async::{NameiWalkOutcome, namei_walk_async};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::{VT_DIR, VnodeHandle};

use crate::server::types::{ClientHandle, ObjectKind};

/// Install the directory open object and emit the final client reply.
///
/// By the time this runs the path walk is finished and, if a backend
/// `meta.open` exists, that terminal open has already succeeded.
/// What remains is purely local state shaping: validate that the vnode
/// is still a directory, install open arbitration, allocate an fd, and
/// populate the directory-flavoured `OpenObject`.
unsafe fn finish_opendir_reply_for_vnode(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    dir_vh: VnodeHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let vtype = match state.vnodes.get(dir_vh) {
            Some(v) => v.vtype,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if vtype != VT_DIR {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        if let Some(vnode) = state.vnodes.get_mut(dir_vh) {
            crate::vfs_core::arbitration::install_open(vnode, 0, 0);
        }

        let fd = match crate::fileops::open::reserve_fd_owned(state, cli_handle) {
            Some(fd) => fd,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let vnode_id = state.vnodes.get(dir_vh).map(|v| v.id).unwrap_or(0);
        if let Some(obj) = state.open_object_at_mut(cli_handle, fd as usize) {
            obj.rights = OBJ_RIGHT_READ;
            obj.offset = 0;
            obj.flags = 0;
            obj.set_directory(dir_vh, vnode_id as u32);
            obj.dir_cursor = 0;
            obj.held_access = 0;
            obj.held_deny = 0;
        } else {
            if let Some(vnode) = state.vnodes.get_mut(dir_vh) {
                crate::vfs_core::arbitration::release_open(vnode, 0, 0);
            }
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

/// Run the terminal directory-open VOP on an already-resolved vnode.
///
/// This is the synchronous-front-half for `opendir(3)`: if the
/// backend returns `Ready(())` we can install the directory object
/// and fd immediately; if it parks, this helper allocates the saved
/// reply slot and stamps `FillOpenDirReply` so completion resumes at
/// the same terminal boundary without re-driving path walk.
unsafe fn fill_opendir_reply_handle(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
    dir_vh: VnodeHandle,
) -> bool {
    unsafe {
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, dir_vh)
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            finish_opendir_reply_for_vnode(state, cli_handle, dir_vh, reply);
            return false;
        }
        let vkey = (*ctx.vnode).vnode_key();
        match ((*ops).meta.open)(&mut ctx, 0) {
            Ok(Ready(())) => {
                finish_opendir_reply_for_vnode(state, cli_handle, dir_vh, reply);
                false
            }
            Ok(Parked(handle)) => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::FillOpenDirReply {
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

/// Resume a parked directory-open terminal op after the backend has
/// translated the wire completion into a generic success/failure ack.
pub(crate) unsafe fn resume_fill_opendir_reply(
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

        if let Err(e) = ack {
            out.label = e.to_trona();
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        finish_opendir_reply_for_vnode(state, client, vh, &raw mut out);
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Emit the deferred `opendir` reply once async path walk has already
/// completed and the only remaining boundary is the terminal
/// `meta.open` on the resolved directory vnode.
pub(crate) unsafe fn send_opendir_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    dir_vh: VnodeHandle,
    reply_slot: u64,
) {
    unsafe {
        if reply_slot == 0 {
            return;
        }

        let mut out = TronaMsg::zeroed();
        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, dir_vh)
        else {
            out.label = TRONA_INVALID_ARGUMENT;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            finish_opendir_reply_for_vnode(state, client, dir_vh, &raw mut out);
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        let vkey = (*ctx.vnode).vnode_key();
        match ((*ops).meta.open)(&mut ctx, 0) {
            Ok(Ready(())) => {
                finish_opendir_reply_for_vnode(state, client, dir_vh, &raw mut out);
                state.send_saved_reply(reply_slot, &raw const out);
            }
            Ok(Parked(handle)) => {
                let badge = state.clients.get(client).map(|c| c.badge).unwrap_or(0);
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    Resume::Fs(FsResume::FillOpenDirReply { client, vkey }),
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

/// Shared async path walker for directory opens.
///
/// Callers decide the namespace anchors (`start_vh`, `root_vh`) and
/// this helper owns the rest: resolve-cache seeding, `WalkCursor`
/// construction, reply-slot lifetime on parked lookups, and the final
/// handoff into the `OpenDir` terminal stage.
pub(crate) unsafe fn opendir_path_from_start_owned(
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
            flags: crate::vfs_core::namei_common::NAMEI_FOLLOW
                | crate::vfs_core::namei_common::NAMEI_DIRECTORY,
            policy: WalkPolicy::Continue,
        };

        match namei_walk_async(state, &mut cursor) {
            NameiWalkOutcome::Done(result) => {
                if result.vp.is_valid() {
                    fill_opendir_reply_handle(state, cli_handle, reply, result.vp)
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
                        terminal: NameiTerminal::OpenDir,
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

/// opendir — owner-loop version.
///
/// Resolves path via handle-based namei, allocates fd for directory.
pub(crate) unsafe fn handle_opendir_owned(
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

        let root = root_vnode_for(state, cli_handle);
        opendir_path_from_start_owned(state, cli_handle, root, root, path_ptr, path_len, reply)
    }
}

/// readdir — owner-loop version.
///
/// Reads one directory entry via VopDataOps::readdir. Updates dir_cursor
/// in the OpenObject. Returns `true` when the reply was deferred (the
/// backend parked the RPC; the resume handler will emit the client
/// reply on completion). Returns `false` for synchronous replies.
pub(crate) unsafe fn handle_readdir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;

        let (vnode_h, cookie, open_h) = {
            let slot_handle = state
                .clients
                .get(cli_handle)
                .and_then(|c| {
                    if (fd as usize) < crate::server::types::MAX_CLIENT_OBJECTS {
                        Some(c.slots[fd as usize].open_object)
                    } else {
                        None
                    }
                })
                .unwrap_or(crate::server::open_object::OpenObjectHandle::INVALID);
            match resolve_fd(state, cli_handle, fd) {
                Some(s) if s.kind() == ObjectKind::Directory && s.vnode_handle().is_valid() => {
                    (s.vnode_handle(), s.dir_cursor as u64, slot_handle)
                }
                _ => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
            }
        };

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let (vkey, fs_id, ops) = match state.vnodes.get(vnode_h) {
            Some(v) => (v.vnode_key(), v.fs_instance_id, v.ops),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        if ops.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        // Credit-exhausted park — bypass VOP entirely for the async
        // backend path. Only enters when: (1) cookie >= 2 (so we
        // cannot satisfy the call synchronously via "." / ".."),
        // (2) the OpenObject's batch cache is empty (no pending
        // entry to drain), and (3) the backend session exists and
        // is at its inflight cap.
        let batch_has_pending = state
            .open_objects
            .get(open_h)
            .map(|o| o.readdir_batch.has_pending())
            .unwrap_or(false);
        if cookie >= 2
            && !batch_has_pending
            && fs_id.is_valid()
            && state.backend_session_slot_index(fs_id).is_some()
            && !state.backend_credit_available(fs_id)
        {
            let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
            let op = match state.begin_op_for_client(cli_handle, OpKind::DeferredBackend) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return false;
                }
            };
            let parked = state.session_defer_push(
                fs_id,
                crate::owner::DeferArgs::Readdir {
                    vnode_data: data_ctx.data,
                    mount_data: data_ctx.mount_data,
                    fd,
                    client: cli_handle,
                    open_handle: open_h,
                    start_cursor: cookie,
                    vkey,
                },
                badge,
                op,
            );
            if parked {
                return true;
            }
            state.cancel_op(op);
            (*reply).label = TRONA_WOULD_BLOCK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return false;
        }

        let data_ctx = if crate::owner::worker::worker_running()
            && matches!(
                (*ops).data.readdir_mode,
                crate::vfs_core::vop::DataExecMode::WorkerSafe
            ) {
            let op = match state.begin_worker_op_for_client(cli_handle, OpKind::Readdir) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return false;
                }
            };
            let item = crate::owner::worker::WorkItem::Readdir {
                op,
                client: cli_handle,
                fd,
                data_ctx: data_ctx.into_worker_ctx(),
                cookie,
            };
            if let Some(rejected) = crate::owner::worker::try_submit(item) {
                match rejected {
                    crate::owner::worker::WorkItem::Readdir { op, data_ctx, .. } => {
                        state.cancel_worker_op(op);
                        data_ctx
                    }
                    _ => {
                        (*reply).label = TRONA_INVALID_OPERATION;
                        (*reply).length = 1;
                        (*reply).regs[0] = 0;
                        return false;
                    }
                }
            } else {
                return true;
            }
        } else {
            data_ctx
        };

        let mut cookie_mut = cookie;
        let mut got_entry = false;

        let emit_fn =
            &mut |ino: u64, name: *const u8, name_len: u8, d_type: u8, _attr: &VAttr| -> bool {
                (*reply).label = TRONA_OK;
                (*reply).length = 5 + ((name_len as u64 + 7) / 8);
                (*reply).regs[0] = name_len as u64;
                (*reply).regs[1] = 0;
                (*reply).regs[2] = ino;
                (*reply).regs[3] = d_type as u64;
                for j in 4..20 {
                    (*reply).regs[j] = 0;
                }
                let dst = &raw mut (*reply).regs[4] as *mut u8;
                for j in 0..name_len as usize {
                    *dst.add(j) = *name.add(j);
                }
                got_entry = true;
                false
            };

        // Thread the current OpenObject through WorkerIoCtx and arm the
        // state trampoline so the data VOP can reach VfsState for async
        // issue. Cleared on every exit below.
        let data_ctx = data_ctx.with_open_object(open_h);
        let readdir_result = ((*ops).data.readdir)(&data_ctx, &raw mut cookie_mut, emit_fn);

        match readdir_result {
            Ok(Ready(())) => {
                if let Some(slot) = resolve_fd_mut(state, cli_handle, fd) {
                    slot.dir_cursor = cookie_mut as u32;
                }
                if !got_entry {
                    (*reply).label = TRONA_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                }
                false
            }
            Ok(Parked(handle)) => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    crate::owner::resume::Resume::Fs(
                        crate::owner::resume::fs::FsResume::BulkReaddirStage {
                            client: cli_handle,
                            dir_vkey: vkey,
                            fs_id,
                            fd,
                            open_handle: open_h,
                            start_cursor: cookie,
                        },
                    ),
                ) {
                    (*reply).label = err.to_trona();
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return false;
                }
                true
            }
            Err(crate::vfs_core::error::VfsError::WouldBlock) => {
                // Backend signalled a resource-contended retry (e.g.
                // a per-mount SHM region held by another live readdir
                // owner). Park on the session's waiter ring via
                // `DeferArgs::Readdir` — the drain path promotes us
                // once the prior owner finishes draining its batch.
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                let reply_slot = match state.alloc_reply_slot_for(badge) {
                    Some(s) => s,
                    None => {
                        (*reply).label = TRONA_OUT_OF_MEMORY;
                        (*reply).length = 1;
                        (*reply).regs[0] = 0;
                        return false;
                    }
                };
                let op = match state.begin_op_for_client(cli_handle, OpKind::DeferredBackend) {
                    Ok(op) => op,
                    Err(err) => {
                        (*reply).label = err.to_trona();
                        (*reply).length = 1;
                        (*reply).regs[0] = 0;
                        return false;
                    }
                };
                let parked = state.session_defer_push(
                    fs_id,
                    crate::owner::DeferArgs::Readdir {
                        vnode_data: data_ctx.data,
                        mount_data: data_ctx.mount_data,
                        fd,
                        client: cli_handle,
                        open_handle: open_h,
                        start_cursor: cookie,
                        vkey,
                    },
                    badge,
                    op,
                );
                if parked {
                    return true;
                }
                state.cancel_op(op);
                (*reply).label = TRONA_WOULD_BLOCK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
                false
            }
            Err(e) => {
                if !got_entry {
                    (*reply).label = e.to_trona();
                }
                false
            }
        }
    }
}

/// Maximum inline name length carried on the first-entry fast path
/// in [`ReaddirReplyData`]. Backends that deliver readdir entries
/// through this struct must cap their per-entry name payload at
/// this bound (they may surface longer names through subsequent
/// batch-cached drains, but this struct only carries one entry's
/// first-name prefix).
///
/// Kept backend-neutral on purpose: the fileops layer is the reply-
/// format authority here, not the filesystem backend. Each backend's
/// internal per-entry name cap must not exceed this constant;
/// backends carry their own compile-time assertion to enforce the
/// bound where they define their readdir wire layout.
pub(crate) const READDIR_FIRST_ENTRY_NAME_MAX: usize = 44;

/// Pre-parsed readdir completion data handed to
/// [`resume_fill_bulk_readdir_reply`] by the backend's completion
/// router. Layout is intentionally plain (no slices) so this crosses
/// the backend → fileops boundary without lifetime constraints.
///
/// `entries_written == 0` indicates EOF; all entry fields are then
/// ignored and the reply shape is a zero-entry drain.
pub(crate) struct ReaddirReplyData {
    pub(crate) next_cursor: u64,
    pub(crate) entries_written: u64,
    pub(crate) bytes_written: u64,
    pub(crate) first_entry_ino: u64,
    pub(crate) first_entry_dtype: u8,
    pub(crate) first_entry_name_len: usize,
    pub(crate) first_entry_name: [u8; READDIR_FIRST_ENTRY_NAME_MAX],
}

/// Resume entry for `FsResume::BulkReaddirStage`.
///
/// The backend's `completion_fn` has pre-parsed the reply into a
/// [`ReaddirReplyData`] (or `None` on error) and released one
/// inflight credit back to the owning session. This helper is
/// responsible for:
/// 1. Seeding `OpenObject.readdir_batch` with the full batch so
///    subsequent POSIX `readdir` calls drain entries without a new
///    backend RPC.
/// 2. Emitting entry 0 inline into the client reply via the saved
///    caller cap.
/// 3. Advancing the client's `dir_cursor` by one.
/// 4. Releasing the per-mount SHM ownership on EOF so concurrent
///    readdir on another OpenObject can proceed.
///
/// A stale `open_handle` (client closed the fd mid-flight) surfaces
/// `TRONA_INVALID_OPERATION` so the caller unblocks with a stable
/// error.
pub(crate) unsafe fn resume_fill_bulk_readdir_reply(
    state: &mut VfsState,
    client: ClientHandle,
    _dir_vkey: crate::vfs_core::identity::VnodeKey,
    fs_id: crate::vfs_core::identity::FsInstanceId,
    fd: i32,
    open_handle: crate::server::open_object::OpenObjectHandle,
    start_cursor: u64,
    reply_slot: u64,
    data: Option<ReaddirReplyData>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();

        let Some(data) = data else {
            out.label = TRONA_IO_ERROR;
            out.length = 1;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        if data.entries_written == 0 {
            // EOF: zero-entry reply matches the sync drain exit shape.
            // The backend-registered `readdir_eof_fn` hook handles
            // any session-scoped cleanup it needs (e.g. releasing
            // per-mount readdir SHM ownership; backends that don't
            // hold SHM ownership install a no-op).
            if let Some(obj) = state.open_objects.get_mut(open_handle) {
                obj.readdir_batch = crate::server::open_object::ReaddirBatch::zeroed();
            }
            state.session_readdir_eof(fs_id, open_handle);
            out.label = TRONA_OK;
            out.length = 1;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let total_u16 = if data.entries_written > u16::MAX as u64 {
            u16::MAX
        } else {
            data.entries_written as u16
        };

        if let Some(obj) = state.open_objects.get_mut(open_handle) {
            obj.readdir_batch = crate::server::open_object::ReaddirBatch {
                cookie: data.next_cursor,
                shm_offset: 0,
                entries_total: total_u16,
                entries_consumed: 1,
            };
        }

        out.label = TRONA_OK;
        out.length = 5 + ((data.first_entry_name_len as u64 + 7) / 8);
        out.regs[0] = data.first_entry_name_len as u64;
        out.regs[1] = 0;
        out.regs[2] = data.first_entry_ino;
        out.regs[3] = data.first_entry_dtype as u64;
        let dst = &raw mut out.regs[4] as *mut u8;
        for j in 0..data.first_entry_name_len {
            *dst.add(j) = data.first_entry_name[j];
        }

        if let Some(slot) = state.open_objects.get_mut(open_handle) {
            slot.dir_cursor = (start_cursor + 1) as u32;
        }
        let _ = fd;
        let _ = client;

        state.send_saved_reply(reply_slot, &raw const out);
    }
}
