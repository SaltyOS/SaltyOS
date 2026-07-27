// SPDX-License-Identifier: GPL-2.0-only
//! ftruncate handler — VopMetaOps-based dispatch for regular files.
//!
//! SHM truncation reads the arena-backed SHM descriptor from the TmpfsVnodeData
//! attached to the SHM vnode, then calls mmsrv to allocate backing pages.

use trona_kernel::core_types::*;
use uapi::*;

use crate::fs::tmpfs::TmpfsVnodeData;
use crate::owner::VfsState;
use crate::owner::resume::{Resume, fs::FsResume};
use crate::personality::posix::misc::ensure_shm_backing_pages;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::outcome::{Parked, Ready};

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

        let (kind, vh) = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) => (obj.kind(), obj.vnode_handle()),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        // SHM truncation
        if kind == ObjectKind::Shm {
            if !vh.is_valid() {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
            let vnode = match state.vnodes.get(vh) {
                Some(v) => v,
                None => {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return false;
                }
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

        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
        };
        let ops = &*(*ctx.vnode).ops;

        // Get current size for mmsrv notification
        let mut attr = VAttr::zeroed();
        let old_size = match (ops.meta.getattr)(&mut ctx, &raw mut attr) {
            Ok(Ready(())) => attr.size,
            Ok(Parked(_)) | Err(_) => 0,
        };

        let parent_vkey = (*ctx.vnode).vnode_key();
        let trunc_result = (ops.meta.truncate)(&mut ctx, length);
        match trunc_result {
            Ok(Ready(())) => {
                if let Some(obj) = state.open_object_at(cli_handle, fd as usize) {
                    notify_mmsrv_mmap_truncate(state, obj, old_size, length);
                }
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::FinalOpAckTruncate {
                        client: cli_handle,
                        file_vkey: parent_vkey,
                        fd,
                        old_size,
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
