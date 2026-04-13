// SPDX-License-Identifier: GPL-2.0-only
//! Bulk transfer operations — SHM-based read and write.

use trona::consts::kernel::*;
use trona::ipc;
use trona::protocol::MM_SHM_MAP;
use trona::types::core::*;

use crate::backend::notify_mmsrv_mmap_write;
use crate::owner::VfsState;
use crate::owner::dispatch::{resolve_fd, resolve_fd_mut, build_data_ctx};
use crate::server::consts::*;
use crate::server::types::ClientHandle;
use crate::server::types::*;
use crate::vfs_core::file::VAttr;

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
            trona::caps::mmsrv_ep(),
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
pub(crate) unsafe fn handle_bulk_read_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let count = (*msg).regs[1];
        let shm_offset = (*msg).regs[2];

        let client_shm = state.clients.get(cli_handle)
            .map(|c| c.bulk_shm_vaddr).unwrap_or(0);
        if client_shm == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).regs[0] = 0;
            (*reply).length = 1;
            return;
        }

        let (vnode_h, offset) = match resolve_fd(state, cli_handle, fd) {
            Some(s) if s.vnode_handle().is_valid() => (s.vnode_handle(), s.offset),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return;
            }
        };

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return;
            }
        };
        let vnode = match state.vnodes.get(vnode_h) {
            Some(v) => v, None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let ops = vnode.ops;
        if ops.is_null() { (*reply).label = TRONA_INVALID_ARGUMENT; return; }

        let shm_limit = CLIENT_BULK_SHM_PAGES * 4096;
        let capped = count.min(shm_limit.saturating_sub(shm_offset));
        let dst = (client_shm + shm_offset) as *mut u8;

        match ((*ops).data.read)(&data_ctx, offset, dst, capped) {
            Ok(actual) => {
                if let Some(slot) = resolve_fd_mut(state, cli_handle, fd) {
                    slot.offset += actual;
                }
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = actual;
                (*reply).length = 1;
            }
            Err(_) => {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
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
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let count = (*msg).regs[1];
        let file_offset = (*msg).regs[2];
        let shm_offset = (*msg).regs[3];

        let client_shm = state.clients.get(cli_handle)
            .map(|c| c.bulk_shm_vaddr).unwrap_or(0);
        if client_shm == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).regs[0] = 0;
            (*reply).length = 1;
            return;
        }

        let vnode_h = match resolve_fd(state, cli_handle, fd) {
            Some(s) if s.vnode_handle().is_valid() => s.vnode_handle(),
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return;
            }
        };

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return;
            }
        };
        let vnode = match state.vnodes.get(vnode_h) {
            Some(v) => v, None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let ops = vnode.ops;
        if ops.is_null() { (*reply).label = TRONA_INVALID_ARGUMENT; return; }

        let shm_limit = CLIENT_BULK_SHM_PAGES * 4096;
        let capped = count.min(shm_limit.saturating_sub(shm_offset));
        let src = (client_shm + shm_offset) as *const u8;
        let mut old_size = 0;
        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vnode_h) {
            let mut attr = VAttr::zeroed();
            let _ = ((*(*ctx.vnode).ops).meta.getattr)(&ctx, &raw mut attr);
            crate::vfs_core::mount_ctl::clear_trampolines();
            old_size = attr.size;
        }

        match ((*ops).data.write)(&data_ctx, file_offset, src, capped) {
            Ok(written) => {
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = written;
                (*reply).length = 1;
                let new_size = core::cmp::max(old_size, file_offset.saturating_add(written));
                if let Some(slot) = resolve_fd(state, cli_handle, fd) {
                    notify_mmsrv_mmap_write(state, slot, file_offset, written, old_size, new_size);
                }
            }
            Err(_) => {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
            }
        }
    }
}
