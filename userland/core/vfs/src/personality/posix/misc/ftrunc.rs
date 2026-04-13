// SPDX-License-Identifier: GPL-2.0-only
//! ftruncate handler — VopMetaOps-based dispatch for regular files.
//!
//! SHM truncation reads the arena-backed SHM descriptor from the TmpfsVnodeData
//! attached to the SHM vnode, then calls mmsrv to allocate backing pages.

use trona::consts::kernel::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::types::*;
use crate::fs::tmpfs::TmpfsVnodeData;
use crate::personality::posix::misc::ensure_shm_backing_pages;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::mount_ctl;

use crate::backend::notify_mmsrv_mmap_truncate;

pub(crate) unsafe fn handle_ftruncate(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let length = (*msg).regs[1];

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let cli = match state.clients.get(cli_handle) {
            Some(c) => c,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
        };
        let slot = &cli.objects[fd as usize];
        if !slot.is_live() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let kind = slot.kind();
        let vh = slot.vnode_handle();

        // SHM truncation
        if kind == ObjectKind::Shm {
            if !vh.is_valid() {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
            let vnode = match state.vnodes.get(vh) {
                Some(v) => v,
                None => { (*reply).label = TRONA_INVALID_OPERATION; return false; }
            };
            let vd = vnode.data as *mut TmpfsVnodeData;
            if vd.is_null() || !(*vd).shm_handle.is_valid() {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            let num_pages = ((length + 4095) / 4096) as u16;

            if let Err(label) = ensure_shm_backing_pages(state, (*vd).shm_handle, num_pages) {
                (*reply).label = label;
                return false;
            }

            (*vd).size = length;
            (*reply).label = TRONA_OK;
            return false;
        }

        // VopMetaOps truncation for regular files
        if !vh.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let ctx = match mount_ctl::build_vop_context(state, vh) {
            Some(c) => c,
            None => { (*reply).label = TRONA_INVALID_OPERATION; return false; }
        };
        let ops = &*(*ctx.vnode).ops;

        // Get current size for mmsrv notification
        let mut attr = VAttr::zeroed();
        let old_size = if (ops.meta.getattr)(&ctx, &raw mut attr).is_ok() {
            attr.size
        } else {
            0
        };

        match (ops.meta.truncate)(&ctx, length) {
            Ok(()) => {
                mount_ctl::clear_trampolines();
                let cli = state.clients.get(cli_handle);
                if let Some(c) = cli {
                    let s = &c.objects[fd as usize];
                    notify_mmsrv_mmap_truncate(state, s, old_size, length);
                }
                (*reply).label = TRONA_OK;
            }
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
            }
        }
        false
    }
}
