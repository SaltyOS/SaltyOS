// SPDX-License-Identifier: GPL-2.0-only
//! `statvfs` / `fstatvfs` IPC handlers.
//!
//! Both variants resolve a vnode (path or fd), walk to its mount, and
//! invoke the backend `vfsops::statfs` callback. The 11-field
//! [`TronaStatvfs`] reply fits in `regs[0..11]` so no IPC-buffer
//! overflow handling is required.

use trona_kernel::core_types::*;
use trona_posix::types::TronaStatvfs;
use uapi::*;

use crate::owner::VfsState;
use crate::server::client::extract_path;
use crate::server::types::ClientHandle;
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::vfsops::{self, StatfsSnapshot};
use crate::vfs_core::vnode::VnodeHandle;

const MAX_STATFS_PATH: usize = 248;

unsafe fn statfs_continuation_adopt(
    state: &mut VfsState,
    badge: u64,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    reply: *mut TronaMsg,
) {
    let cli_handle = state.lookup_client(badge).unwrap_or(ClientHandle::INVALID);
    let body = crate::owner::namei::StatvfsContBody { _reserved: [0; 96] };
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_STATVFS_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_STATVFS,
            crate::owner::namei::namei_aux_statvfs(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_vfs_statfs(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let path_len = (*msg).regs[0] as usize;
        if path_len == 0 || path_len > MAX_STATFS_PATH {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let mut path = [0u8; 256];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr()) as usize;
        if raw_len != path_len {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let path = &path[..path_len];
        if path.first().copied() != Some(b'/') {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let vh = match state.lookup_path_dynamic_absolute(path, false) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(vh))) => vh,
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                statfs_continuation_adopt(state, badge, op_id, path, reply);
                return;
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        emit_statfs_for_vnode(state, vh, reply);
    }
}

pub(crate) unsafe fn handle_vfs_fstatfs(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let target_badge = if (*msg).length >= 2 && (*msg).regs[1] != 0 {
            (*msg).regs[1]
        } else {
            badge
        };
        let Some(cli_handle) = state.lookup_client(target_badge) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let Some(of) = state.client_open_file(cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let vh = of.vnode;
        emit_statfs_for_vnode(state, vh, reply);
    }
}

pub(crate) unsafe fn emit_statfs_for_vnode(
    state: &mut VfsState,
    vh: VnodeHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mount = match state.vnodes.get(vh) {
            Some(vn) => vn.mount.handle,
            None => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
        };
        if !mount.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        let mut snapshot = StatfsSnapshot::zeroed();
        let label = run_backend_statfs(state, mount, &mut snapshot);
        if label != TRONA_OK {
            (*reply).label = label;
            (*reply).length = 0;
            return;
        }
        write_statfs_reply(reply, &snapshot);
    }
}

fn run_backend_statfs(state: &VfsState, mount: MountHandle, out: &mut StatfsSnapshot) -> u64 {
    let ops_ptr = state
        .mounts
        .get(mount)
        .map(|m| m.vfsops)
        .unwrap_or(core::ptr::null());
    let Some(ops) = vfsops::table_from_ptr(ops_ptr) else {
        return TRONA_NOT_SUPPORTED;
    };
    let Some(callback) = ops.statfs else {
        return TRONA_NOT_SUPPORTED;
    };
    callback(state, mount, out)
}

unsafe fn write_statfs_reply(reply: *mut TronaMsg, snapshot: &StatfsSnapshot) {
    let stat = TronaStatvfs {
        f_bsize: snapshot.f_bsize,
        f_frsize: snapshot.f_frsize,
        f_blocks: snapshot.f_blocks,
        f_bfree: snapshot.f_bfree,
        f_bavail: snapshot.f_bavail,
        f_files: snapshot.f_files,
        f_ffree: snapshot.f_ffree,
        f_favail: snapshot.f_favail,
        f_fsid: snapshot.f_fsid,
        f_flag: snapshot.f_flag,
        f_namemax: snapshot.f_namemax,
    };
    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).length = 11;
        (*reply).regs[0] = stat.f_bsize;
        (*reply).regs[1] = stat.f_frsize;
        (*reply).regs[2] = stat.f_blocks;
        (*reply).regs[3] = stat.f_bfree;
        (*reply).regs[4] = stat.f_bavail;
        (*reply).regs[5] = stat.f_files;
        (*reply).regs[6] = stat.f_ffree;
        (*reply).regs[7] = stat.f_favail;
        (*reply).regs[8] = stat.f_fsid;
        (*reply).regs[9] = stat.f_flag;
        (*reply).regs[10] = stat.f_namemax;
    }
}
