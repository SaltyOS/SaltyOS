// SPDX-License-Identifier: GPL-2.0-only
//! Bulk transfer operations — SHM-based read and write.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::MM_SHM_MAP;
use uapi::*;

use crate::backend::notify_mmsrv_mmap_write;
use crate::owner::VfsState;
use crate::owner::dispatch::{build_data_ctx, resolve_fd, resolve_fd_mut};
use crate::owner::op::OpKind;
use crate::server::consts::*;
use crate::server::types::ClientHandle;
use crate::server::types::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::outcome::{Parked, Ready};

/// bulk_setup — owner-loop version. Maps client SHM into VFS address space.
pub(crate) unsafe fn handle_bulk_setup_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_pages = (*msg).regs[1];

        if client_pages < CLIENT_BULK_SHM_PAGES {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mut req = TronaMsg::zeroed();
        let mut mm_reply = TronaMsg::zeroed();
        req.label = MM_SHM_MAP;
        req.regs[0] = shm_id;
        req.regs[1] = 0;
        req.regs[2] = 0;
        req.regs[3] = 0x3;
        req.length = 4;
        ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const req,
            &raw mut mm_reply,
        );

        if mm_reply.label != TRONA_OK {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mapped_vaddr = mm_reply.regs[0];
        if let Some(cli) = state.clients.get_mut(cli_handle) {
            cli.bulk_shm_vaddr = mapped_vaddr;
            cli.bulk_shm_id = shm_id;
        }

        (*reply).label = TRONA_OK;
    }
}

/// bulk_read — owner-loop version. Reads file data into client SHM.
///
/// Returns `true` when the reply has been deferred (the backend parked
/// the RPC; the resume handler will send the client reply on
/// completion). Returns `false` for synchronous replies, which the
/// dispatcher delivers via the normal reply path.
pub(crate) unsafe fn handle_bulk_read_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let count = (*msg).regs[1];
        let shm_offset = (*msg).regs[2];

        let client_shm = state
            .clients
            .get(cli_handle)
            .map(|c| c.bulk_shm_vaddr)
            .unwrap_or(0);
        if client_shm == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).regs[0] = 0;
            (*reply).length = 1;
            return false;
        }

        let (vnode_h, offset) = match resolve_fd(state, cli_handle, fd) {
            Some(s) if s.vnode_handle().is_valid() => (s.vnode_handle(), s.offset),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return false;
            }
        };

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
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

        let shm_limit = CLIENT_BULK_SHM_PAGES * 4096;
        let capped = count.min(shm_limit.saturating_sub(shm_offset));
        let dst = (client_shm + shm_offset) as *mut u8;

        // Credit-exhausted park: if the backend has a registered
        // credit session for `fs_id` and it's at its inflight cap,
        // bypass the VOP call entirely. Alloc the reply slot, save
        // the caller, and hand the backend an opaque `DeferArgs` so
        // it can push a waiter onto the session's ring without this
        // generic path knowing which backend type owns the mount.
        if fs_id.is_valid()
            && state.backend_session_slot_index(fs_id).is_some()
            && !state.backend_credit_available(fs_id)
        {
            let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
            let op = match state.begin_op_for_client(cli_handle, OpKind::DeferredBackend) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    (*reply).regs[0] = 0;
                    (*reply).length = 1;
                    return false;
                }
            };
            let parked = state.session_defer_push(
                fs_id,
                crate::owner::DeferArgs::Read {
                    vnode_data: data_ctx.data,
                    mount_data: data_ctx.mount_data,
                    file_offset: offset,
                    len: capped,
                    fd,
                    shm_offset,
                    client: cli_handle,
                    vkey,
                },
                badge,
                op,
            );
            if parked {
                return true;
            }
            // Waiter ring was full — release the slot so the client
            // unblocks with BUSY rather than hanging.
            state.cancel_op(op);
            (*reply).label = TRONA_WOULD_BLOCK;
            (*reply).regs[0] = 0;
            (*reply).length = 1;
            return false;
        }

        // Arm the VfsState trampoline so the data VOP can reserve
        // pending slots and credit. `build_data_ctx` did not set
        // trampolines (it's pure lookup), so the backend's async read
        // VOP needs the arming done here. Mirror the pattern used by
        // the meta-op path in handle_stat_owned_async.
        if crate::owner::worker::worker_running()
            && matches!(
                (*ops).data.read_mode,
                crate::vfs_core::vop::DataExecMode::WorkerSafe
            )
        {
            let op = match state.begin_worker_op_for_client(cli_handle, OpKind::BulkRead) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    (*reply).regs[0] = 0;
                    (*reply).length = 1;
                    return false;
                }
            };
            let item = crate::owner::worker::WorkItem::BulkRead {
                op,
                client: cli_handle,
                fd,
                data_ctx: data_ctx.into_worker_ctx(),
                offset,
                shm_dst: dst,
                len: capped,
            };
            if let Some(rejected) = crate::owner::worker::try_submit(item) {
                let ctx = match rejected {
                    crate::owner::worker::WorkItem::BulkRead { op, data_ctx, .. } => {
                        state.cancel_worker_op(op);
                        data_ctx
                    }
                    _ => {
                        (*reply).label = TRONA_INVALID_OPERATION;
                        (*reply).regs[0] = 0;
                        (*reply).length = 1;
                        return false;
                    }
                };
                match ((*ops).data.read)(&ctx, offset, dst, capped) {
                    Ok(Ready(actual)) => {
                        if let Some(slot) = resolve_fd_mut(state, cli_handle, fd) {
                            slot.offset += actual;
                        }
                        (*reply).label = TRONA_OK;
                        (*reply).regs[0] = actual;
                        (*reply).length = 1;
                    }
                    Ok(Parked(_)) => {
                        (*reply).label = TRONA_BUSY;
                        (*reply).regs[0] = 0;
                        (*reply).length = 1;
                    }
                    Err(err) => {
                        (*reply).label = err.to_trona();
                        (*reply).regs[0] = 0;
                        (*reply).length = 1;
                    }
                }
                return false;
            }
            return true;
        }

        let read_result = ((*ops).data.read)(&data_ctx, offset, dst, capped);

        match read_result {
            Ok(Ready(actual)) => {
                if let Some(slot) = resolve_fd_mut(state, cli_handle, fd) {
                    slot.offset += actual;
                }
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = actual;
                (*reply).length = 1;
                false
            }
            Ok(Parked(handle)) => {
                // The VOP has already issued the backend RPC and the
                // parked op-kind payload records the transfer shape.
                // fileops only needs to supply client-scope info
                // (client, fd, shm_offset, vkey); the completion
                // router consults the backend-opaque kind to
                // reconstruct the inline / SHM branch.
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                let reply_slot = match state.alloc_reply_slot_for(badge) {
                    Some(s) => s,
                    None => {
                        // The backend RPC is already in flight; cancel
                        // the pending slot so the eventual completion
                        // drops the reply and returns credit. Do NOT
                        // pre-release credit here — the inflight
                        // request still counts against the cap.
                        state.cancel_pending_op(handle);
                        (*reply).label = TRONA_OUT_OF_MEMORY;
                        (*reply).regs[0] = 0;
                        (*reply).length = 1;
                        return false;
                    }
                };
                let save_err =
                    trona_kernel::invoke::cnode_save_caller(uapi::CAP_SELF_CSPACE, reply_slot);
                if save_err != 0 {
                    state.release_reply_slot(reply_slot);
                    state.cancel_pending_op(handle);
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).regs[0] = 0;
                    (*reply).length = 1;
                    return false;
                }
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    crate::owner::resume::Resume::Fs(
                        crate::owner::resume::fs::FsResume::BulkReadStage {
                            client: cli_handle,
                            vkey,
                            fs_id,
                            fd,
                            shm_offset,
                        },
                    ),
                ) {
                    state.release_reply_slot(reply_slot);
                    state.cancel_pending_op(handle);
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).regs[0] = 0;
                    (*reply).length = 1;
                    return false;
                }
                true
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                false
            }
        }
    }
}

/// bulk_pwrite — owner-loop version. Writes from client SHM to file.
pub(crate) unsafe fn handle_bulk_pwrite_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let count = (*msg).regs[1];
        let file_offset = (*msg).regs[2];
        let shm_offset = (*msg).regs[3];

        let client_shm = state
            .clients
            .get(cli_handle)
            .map(|c| c.bulk_shm_vaddr)
            .unwrap_or(0);
        if client_shm == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).regs[0] = 0;
            (*reply).length = 1;
            return false;
        }

        let vnode_h = match resolve_fd(state, cli_handle, fd) {
            Some(s) if s.vnode_handle().is_valid() => s.vnode_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return false;
            }
        };

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return false;
            }
        };
        let vnode = match state.vnodes.get(vnode_h) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let ops = vnode.ops;
        if ops.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let shm_limit = CLIENT_BULK_SHM_PAGES * 4096;
        let capped = count.min(shm_limit.saturating_sub(shm_offset));
        let src = (client_shm + shm_offset) as *const u8;
        let mut old_size = 0;
        if let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        {
            let mut attr = VAttr::zeroed();
            match ((*(*ctx.vnode).ops).meta.getattr)(&mut ctx, &raw mut attr) {
                Ok(Ready(())) | Ok(Parked(_)) | Err(_) => {}
            }
            old_size = attr.size;
        }

        if crate::owner::worker::worker_running()
            && matches!(
                (*ops).data.write_mode,
                crate::vfs_core::vop::DataExecMode::WorkerSafe
            )
        {
            let op = match state.begin_worker_op_for_client(cli_handle, OpKind::BulkWrite) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    (*reply).regs[0] = 0;
                    (*reply).length = 1;
                    return false;
                }
            };
            let item = crate::owner::worker::WorkItem::BulkWrite {
                op,
                client: cli_handle,
                fd,
                old_size,
                data_ctx: data_ctx.into_worker_ctx(),
                offset: file_offset,
                shm_src: src,
                len: capped,
            };
            if let Some(rejected) = crate::owner::worker::try_submit(item) {
                let ctx = match rejected {
                    crate::owner::worker::WorkItem::BulkWrite { op, data_ctx, .. } => {
                        state.cancel_worker_op(op);
                        data_ctx
                    }
                    _ => {
                        (*reply).label = TRONA_INVALID_OPERATION;
                        (*reply).regs[0] = 0;
                        (*reply).length = 1;
                        return false;
                    }
                };
                match ((*ops).data.write)(&ctx, file_offset, src, capped) {
                    Ok(Ready(written)) => {
                        (*reply).label = TRONA_OK;
                        (*reply).regs[0] = written;
                        (*reply).length = 1;
                        let new_size =
                            core::cmp::max(old_size, file_offset.saturating_add(written));
                        if let Some(slot) = resolve_fd(state, cli_handle, fd) {
                            notify_mmsrv_mmap_write(
                                state,
                                slot,
                                file_offset,
                                written,
                                old_size,
                                new_size,
                            );
                        }
                    }
                    Ok(Parked(_)) => {
                        (*reply).label = TRONA_BUSY;
                        (*reply).regs[0] = 0;
                        (*reply).length = 1;
                    }
                    Err(err) => {
                        (*reply).label = err.to_trona();
                        (*reply).regs[0] = 0;
                        (*reply).length = 1;
                    }
                }
                return false;
            }
            return true;
        }

        match ((*ops).data.write)(&data_ctx, file_offset, src, capped) {
            Ok(Ready(written)) => {
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = written;
                (*reply).length = 1;
                let new_size = core::cmp::max(old_size, file_offset.saturating_add(written));
                if let Some(slot) = resolve_fd(state, cli_handle, fd) {
                    notify_mmsrv_mmap_write(state, slot, file_offset, written, old_size, new_size);
                }
            }
            Ok(Parked(_)) => {
                (*reply).label = TRONA_BUSY;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                (*reply).regs[0] = 0;
                (*reply).length = 1;
            }
        }
        false
    }
}

/// Resume entry for the inline branch of a `BulkReadStage`
/// completion, or for a zero-byte / error completion.
///
/// The backend's `completion_fn` has already parsed the reply and
/// released one inflight credit back to the owning session before
/// calling here. `payload` is `None` on error (an error label is
/// emitted); `Some(&[])` for a zero-byte read; or `Some(bytes)` with
/// the inline reply payload already materialised into a stack
/// buffer.
///
/// SHM-relay reads take the dedicated [`resume_fill_bulk_read_reply_shm`]
/// entry point so we do not copy the backend payload twice.
pub(crate) unsafe fn resume_fill_bulk_read_reply(
    state: &mut VfsState,
    client: ClientHandle,
    _vkey: crate::vfs_core::identity::VnodeKey,
    _fs_id: crate::vfs_core::identity::FsInstanceId,
    fd: i32,
    shm_offset: u64,
    reply_slot: u64,
    bytes_read: u64,
    payload: Option<&[u8]>,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();
        out.length = 1;

        let Some(bytes) = payload else {
            out.label = TRONA_IO_ERROR;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };

        if bytes_read == 0 {
            out.label = TRONA_OK;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let client_shm = state
            .clients
            .get(client)
            .map(|c| c.bulk_shm_vaddr)
            .unwrap_or(0);
        if client_shm == 0 {
            out.label = TRONA_INVALID_OPERATION;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let shm_limit = CLIENT_BULK_SHM_PAGES * 4096;
        if shm_offset.saturating_add(bytes_read) > shm_limit {
            out.label = TRONA_INVALID_OPERATION;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        let dst = (client_shm + shm_offset) as *mut u8;
        let n = core::cmp::min(bytes.len(), bytes_read as usize);
        for i in 0..n {
            *dst.add(i) = bytes[i];
        }

        if let Some(slot) = resolve_fd_mut(state, client, fd) {
            slot.offset = slot.offset.saturating_add(bytes_read);
        }

        out.label = TRONA_OK;
        out.regs[0] = bytes_read;
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Resume entry for the SHM-relay branch of a `BulkReadStage`
/// completion. `src_shm` points at the backend's SHM region where
/// the payload already lives; the fileops helper copies
/// `bytes_read` bytes into the client's bulk-SHM at `shm_offset`.
///
/// The caller (backend completion router) is responsible for
/// bounds-checking `src_shm + bytes_read` against the backend's SHM
/// size before invocation. The fileops layer trusts the pointer +
/// length pair it receives.
pub(crate) unsafe fn resume_fill_bulk_read_reply_shm(
    state: &mut VfsState,
    client: ClientHandle,
    _vkey: crate::vfs_core::identity::VnodeKey,
    _fs_id: crate::vfs_core::identity::FsInstanceId,
    fd: i32,
    shm_offset: u64,
    reply_slot: u64,
    bytes_read: u64,
    src_shm: *const u8,
) {
    unsafe {
        let mut out = TronaMsg::zeroed();
        out.length = 1;

        if bytes_read == 0 {
            out.label = TRONA_OK;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let client_shm = state
            .clients
            .get(client)
            .map(|c| c.bulk_shm_vaddr)
            .unwrap_or(0);
        if client_shm == 0 {
            out.label = TRONA_INVALID_OPERATION;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let shm_limit = CLIENT_BULK_SHM_PAGES * 4096;
        if shm_offset.saturating_add(bytes_read) > shm_limit {
            out.label = TRONA_INVALID_OPERATION;
            out.regs[0] = 0;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        let dst = (client_shm + shm_offset) as *mut u8;
        core::ptr::copy_nonoverlapping(src_shm, dst, bytes_read as usize);

        if let Some(slot) = resolve_fd_mut(state, client, fd) {
            slot.offset = slot.offset.saturating_add(bytes_read);
        }

        out.label = TRONA_OK;
        out.regs[0] = bytes_read;
        state.send_saved_reply(reply_slot, &raw const out);
    }
}
