// SPDX-License-Identifier: GPL-2.0-only
//! Positional read and write — VopDataOps dispatch.

use trona_kernel::core_types::*;
use uapi::*;

use crate::backend::notify_mmsrv_mmap_write;
use crate::owner::VfsState;
use crate::owner::dispatch::{build_data_ctx, resolve_fd};
use crate::owner::op::OpKind;
use crate::server::client::flags_allow_read;
use crate::server::consts::*;
use crate::server::types::ClientHandle;
use crate::server::types::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::outcome::{Parked, Ready};

/// pread — owner-loop version. Reads at explicit offset, no cursor update.
pub(crate) unsafe fn handle_pread_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];
        let offset = (*msg).regs[2];
        if count > VFS_INLINE_READ_MAX as u64 {
            count = VFS_INLINE_READ_MAX as u64;
        }

        let (kind, vnode_h) = {
            match resolve_fd(state, cli_handle, fd) {
                Some(s) => (s.kind(), s.vnode_handle()),
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
            }
        };

        if kind != ObjectKind::File || !vnode_h.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
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

        if crate::owner::worker::worker_running()
            && matches!(
                (*ops).data.read_mode,
                crate::vfs_core::vop::DataExecMode::WorkerSafe
            )
        {
            let op = match state.begin_worker_op_for_client(cli_handle, OpKind::PRead) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    return false;
                }
            };

            let item = crate::owner::worker::WorkItem::Read {
                op,
                client: cli_handle,
                fd,
                update_fd_offset: false,
                data_ctx: data_ctx.into_worker_ctx(),
                offset,
                len: count,
            };
            if let Some(rejected) = crate::owner::worker::try_submit(item) {
                let ctx = match rejected {
                    crate::owner::worker::WorkItem::Read { op, data_ctx, .. } => {
                        state.cancel_worker_op(op);
                        data_ctx
                    }
                    _ => {
                        (*reply).label = TRONA_INVALID_OPERATION;
                        return false;
                    }
                };
                let dst = &raw mut (*reply).regs[1] as *mut u8;
                match ((*ops).data.read)(&ctx, offset, dst, count) {
                    Ok(Ready(actual)) => {
                        (*reply).label = TRONA_OK;
                        (*reply).length = 1 + (actual + 7) / 8;
                        (*reply).regs[0] = actual;
                    }
                    Ok(Parked(_)) => {
                        (*reply).label = TRONA_BUSY;
                    }
                    Err(e) => {
                        (*reply).label = e.to_trona();
                    }
                }
                return false;
            }
            return true;
        }

        let dst = &raw mut (*reply).regs[1] as *mut u8;
        match ((*ops).data.read)(&data_ctx, offset, dst, count) {
            Ok(Ready(actual)) => {
                (*reply).label = TRONA_OK;
                (*reply).length = if actual == 0 { 1 } else { 1 + (actual + 7) / 8 };
                (*reply).regs[0] = actual;
            }
            Ok(Parked(_)) => {
                (*reply).label = TRONA_BUSY;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
        false
    }
}

/// pwrite — owner-loop version. Writes at explicit offset, no cursor update.
pub(crate) unsafe fn handle_pwrite_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];
        let offset = (*msg).regs[2];
        if count > VFS_INLINE_PWRITE_MAX as u64 {
            count = VFS_INLINE_PWRITE_MAX as u64;
        }

        let (kind, vnode_h) = {
            match resolve_fd(state, cli_handle, fd) {
                Some(s) => (s.kind(), s.vnode_handle()),
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
            }
        };

        if kind != ObjectKind::File || !vnode_h.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
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

        let src = &(*msg).regs[3] as *const u64 as *const u8;
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
            let mut inline_data = [0u8; VFS_INLINE_WRITE_MAX];
            core::ptr::copy_nonoverlapping(src, inline_data.as_mut_ptr(), count as usize);
            let op = match state.begin_worker_op_for_client(cli_handle, OpKind::PWrite) {
                Ok(op) => op,
                Err(err) => {
                    (*reply).label = err.to_trona();
                    return false;
                }
            };

            let item = crate::owner::worker::WorkItem::Write {
                op,
                client: cli_handle,
                fd,
                old_size,
                update_fd_offset: false,
                data_ctx: data_ctx.into_worker_ctx(),
                offset,
                len: count,
                data: inline_data,
            };
            if let Some(rejected) = crate::owner::worker::try_submit(item) {
                let ctx = match rejected {
                    crate::owner::worker::WorkItem::Write { op, data_ctx, .. } => {
                        state.cancel_worker_op(op);
                        data_ctx
                    }
                    _ => {
                        (*reply).label = TRONA_INVALID_OPERATION;
                        return false;
                    }
                };
                match ((*ops).data.write)(&ctx, offset, src, count) {
                    Ok(Ready(written)) => {
                        (*reply).label = TRONA_OK;
                        (*reply).length = 1;
                        (*reply).regs[0] = written;
                        let new_size = core::cmp::max(old_size, offset.saturating_add(written));
                        if let Some(slot) = resolve_fd(state, cli_handle, fd) {
                            notify_mmsrv_mmap_write(
                                state, slot, offset, written, old_size, new_size,
                            );
                        }
                    }
                    Ok(Parked(_)) => {
                        (*reply).label = TRONA_BUSY;
                    }
                    Err(e) => {
                        (*reply).label = e.to_trona();
                    }
                }
                return false;
            }
            return true;
        }

        match ((*ops).data.write)(&data_ctx, offset, src, count) {
            Ok(Ready(written)) => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = written;
                let new_size = core::cmp::max(old_size, offset.saturating_add(written));
                if let Some(slot) = resolve_fd(state, cli_handle, fd) {
                    notify_mmsrv_mmap_write(state, slot, offset, written, old_size, new_size);
                }
            }
            Ok(Parked(_)) => {
                (*reply).label = TRONA_BUSY;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
        false
    }
}
