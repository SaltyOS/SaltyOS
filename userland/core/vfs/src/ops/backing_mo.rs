// SPDX-License-Identifier: GPL-2.0-only
//
//! File-backed memory-object lookup shared by POSIX mmap setup
//! and Win32 section creation.

use crate::core::error::VfsError;
use crate::core::vnode::{VnodeHandle, VnodeKind};
use crate::owner::VfsState;
use crate::owner::mm_ipc::BackingMoInfo;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn do_get_backing_mo_from_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<BackingMoInfo, VfsError> {
    unsafe {
        let vnode = resolve_fd_vnode_for_mmap(state, client, fd)?;
        crate::owner::mm_ipc::ensure_backing_mo_for_vnode(state, vnode)
    }
}

fn resolve_fd_vnode_for_mmap(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<VnodeHandle, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get(client).ok_or(VfsError::Io)?;
    let fd_idx = u32::try_from(fd).map_err(|_| VfsError::BadF)?;
    let oh = cli.slot_table.lookup(fd_idx).ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(oh).ok_or(VfsError::BadF)?;
    if !obj.vnode.is_valid() {
        return Err(VfsError::BadF);
    }
    let kind = state
        .vnodes
        .get(obj.vnode)
        .map(|v| v.kind)
        .unwrap_or(VnodeKind::Empty);
    match kind {
        VnodeKind::Regular | VnodeKind::CharDev => Ok(obj.vnode),
        VnodeKind::Directory => Err(VfsError::IsDir),
        _ => Err(VfsError::Inval),
    }
}
