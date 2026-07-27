// SPDX-License-Identifier: GPL-2.0-only
//
//! Filesystem statistics helper shared by personality frontends.

use crate::core::error::VfsError;
use crate::core::file::VStatfs;
use crate::core::vop_context::OwnerMountCtx;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn do_statfs_from_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<VStatfs, VfsError> {
    unsafe {
        let target_vh = resolve_fd_vnode(state, client, fd)?;
        let mount_h = match state.vnodes.get(target_vh).map(|v| v.mount) {
            Some(m) if m.is_valid() => m,
            _ => return Err(VfsError::Io),
        };
        let vfsops_ptr = match state.mounts.get(mount_h) {
            Some(m) => m.vfsops,
            None => return Err(VfsError::Io),
        };
        if vfsops_ptr.is_null() {
            return Err(VfsError::Io);
        }

        let mut stat = VStatfs::zeroed();
        let mut mctx = OwnerMountCtx::from_state(state, mount_h).ok_or(VfsError::Io)?;
        ((*vfsops_ptr).statfs)(&mut mctx, &raw mut stat)?;
        Ok(stat)
    }
}

fn resolve_fd_vnode(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<crate::core::vnode::VnodeHandle, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get(client).ok_or(VfsError::Io)?;
    let oh = cli.slot_table.lookup(fd as u32).ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(oh).ok_or(VfsError::BadF)?;
    if !obj.vnode.is_valid() {
        return Err(VfsError::BadF);
    }
    Ok(obj.vnode)
}
