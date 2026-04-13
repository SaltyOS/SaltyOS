// SPDX-License-Identifier: GPL-2.0-only
//! Positional read and write — VopDataOps dispatch.

use trona::consts::kernel::*;
use trona::types::core::*;

use crate::backend::notify_mmsrv_mmap_write;
use crate::owner::VfsState;
use crate::owner::dispatch::{resolve_fd, build_data_ctx};
use crate::server::client::flags_allow_read;
use crate::server::consts::*;
use crate::server::types::ClientHandle;
use crate::server::types::*;
use crate::vfs_core::file::VAttr;

/// pread — owner-loop version. Reads at explicit offset, no cursor update.
pub(crate) unsafe fn handle_pread_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];
        let offset = (*msg).regs[2];
        if count > 152 { count = 152; }

        let (kind, vnode_h) = {
            match resolve_fd(state, cli_handle, fd) {
                Some(s) => (s.kind(), s.vnode_handle()),
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            }
        };

        if kind != ObjectKind::File || !vnode_h.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let vnode = match state.vnodes.get(vnode_h) {
            Some(v) => v,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let ops = vnode.ops;
        if ops.is_null() { (*reply).label = TRONA_INVALID_ARGUMENT; return; }

        let dst = &raw mut (*reply).regs[1] as *mut u8;
        match ((*ops).data.read)(&data_ctx, offset, dst, count) {
            Ok(actual) => {
                (*reply).label = TRONA_OK;
                (*reply).length = if actual == 0 { 1 } else { 1 + (actual + 7) / 8 };
                (*reply).regs[0] = actual;
            }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
    }
}

/// pwrite — owner-loop version. Writes at explicit offset, no cursor update.
pub(crate) unsafe fn handle_pwrite_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];
        let offset = (*msg).regs[2];
        if count > 136 { count = 136; }

        let (kind, vnode_h) = {
            match resolve_fd(state, cli_handle, fd) {
                Some(s) => (s.kind(), s.vnode_handle()),
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            }
        };

        if kind != ObjectKind::File || !vnode_h.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let data_ctx = match build_data_ctx(state, vnode_h) {
            Some(dc) => dc,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let vnode = match state.vnodes.get(vnode_h) {
            Some(v) => v,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let ops = vnode.ops;
        if ops.is_null() { (*reply).label = TRONA_INVALID_ARGUMENT; return; }

        let src = &(*msg).regs[3] as *const u64 as *const u8;
        let mut old_size = 0;
        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vnode_h) {
            let mut attr = VAttr::zeroed();
            let _ = ((*(*ctx.vnode).ops).meta.getattr)(&ctx, &raw mut attr);
            crate::vfs_core::mount_ctl::clear_trampolines();
            old_size = attr.size;
        }
        match ((*ops).data.write)(&data_ctx, offset, src, count) {
            Ok(written) => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = written;
                let new_size = core::cmp::max(old_size, offset.saturating_add(written));
                if let Some(slot) = resolve_fd(state, cli_handle, fd) {
                    notify_mmsrv_mmap_write(state, slot, offset, written, old_size, new_size);
                }
            }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
    }
}
