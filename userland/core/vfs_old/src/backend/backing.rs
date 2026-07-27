// SPDX-License-Identifier: GPL-2.0-only
//! Backend mmap backing resolution helpers.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::owner::dispatch::build_data_ctx;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::VnodeHandle;

fn find_mount_by_id(state: &VfsState, mount_id: u64) -> MountHandle {
    if mount_id > u16::MAX as u64 {
        return MountHandle::INVALID;
    }
    let mut result = MountHandle::INVALID;
    state.mounts.for_each_active(|mh, mp| {
        if mp.id as u64 == mount_id {
            result = mh;
            false
        } else {
            true
        }
    });
    result
}

fn resolve_backing_vnode(
    state: &mut VfsState,
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
) -> VnodeHandle {
    unsafe {
        let (mh, vnode_id) = match backing_kind {
            MMAP_BACKING_FILE => (state.root_mount, backing_id0),
            MMAP_BACKING_MOUNT => (find_mount_by_id(state, backing_id0), backing_id1),
            _ => return VnodeHandle::INVALID,
        };
        if !mh.is_valid() {
            return VnodeHandle::INVALID;
        }
        let mp = match state.mounts.get(mh) {
            Some(m) => m,
            None => return VnodeHandle::INVALID,
        };
        let vfsops = mp.vfsops;
        if vfsops.is_null() {
            return VnodeHandle::INVALID;
        }
        let result = {
            let mut mctx = match crate::vfs_core::vop_context::OwnerMountCtx::from_state(state, mh)
            {
                Some(c) => c,
                None => {
                    return VnodeHandle::INVALID;
                }
            };
            ((*vfsops).vget)(&mut mctx, vnode_id)
        };
        match result {
            Ok(vh) => vh,
            Err(_) => VnodeHandle::INVALID,
        }
    }
}

pub(crate) fn read_backing_bytes(
    state: &mut VfsState,
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
    offset: u64,
    dst: *mut u8,
    count: u64,
) -> Option<u64> {
    unsafe {
        match backing_kind {
            MMAP_BACKING_FILE | MMAP_BACKING_MOUNT => {
                let vh = resolve_backing_vnode(state, backing_kind, backing_id0, backing_id1);
                if !vh.is_valid() {
                    return None;
                }
                let data_ctx = build_data_ctx(state, vh)?;
                let vnode = state.vnodes.get(vh)?;
                let ops = vnode.ops;
                if ops.is_null() {
                    return None;
                }
                match ((*ops).data.read)(&data_ctx, offset, dst, count) {
                    Ok(Ready(n)) => Some(n),
                    Ok(Parked(_)) => None,
                    Err(_) => None,
                }
            }
            _ => None,
        }
    }
}

pub(crate) fn write_backing_bytes(
    state: &mut VfsState,
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
    offset: u64,
    src: *const u8,
    count: u64,
) -> Option<u64> {
    unsafe {
        match backing_kind {
            MMAP_BACKING_FILE | MMAP_BACKING_MOUNT => {
                let vh = resolve_backing_vnode(state, backing_kind, backing_id0, backing_id1);
                if !vh.is_valid() {
                    return None;
                }
                let data_ctx = build_data_ctx(state, vh)?;
                let vnode = state.vnodes.get(vh)?;
                let ops = vnode.ops;
                if ops.is_null() {
                    return None;
                }
                match ((*ops).data.write)(&data_ctx, offset, src, count) {
                    Ok(Ready(n)) => Some(n),
                    Ok(Parked(_)) => None,
                    Err(_) => None,
                }
            }
            _ => None,
        }
    }
}

pub(crate) unsafe fn handle_resolve_backing(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    let fd = unsafe { (*msg).regs[0] as i32 };

    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        unsafe {
            (*reply).label = TRONA_INVALID_ARGUMENT;
        }
        return;
    }

    let slot = match state.open_object_at(cli_handle, fd as usize) {
        Some(obj) => *obj,
        None => {
            unsafe {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
            return;
        }
    };

    let mut resolve_flags: u64 = 0;
    if (slot.rights & OBJ_RIGHT_WRITE) != 0 {
        resolve_flags |= 1;
    }

    if slot.kind() == ObjectKind::Shm {
        let vh = slot.vnode_handle();
        if !vh.is_valid() {
            unsafe {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
            return;
        }

        let mut ctx =
            match unsafe { crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) } {
                Some(c) => c,
                None => {
                    unsafe {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                    }
                    return;
                }
            };
        let vnode = unsafe { &*ctx.vnode };
        let ops = vnode.ops;
        let mut attr = VAttr::zeroed();
        let file_size = if !ops.is_null() {
            match unsafe { ((*ops).meta.getattr)(&mut ctx, &raw mut attr) } {
                Ok(Ready(())) => attr.size,
                Ok(Parked(_)) | Err(_) => 0,
            }
        } else {
            0
        };

        unsafe {
            (*reply).label = TRONA_OK;
            (*reply).length = 5;
            (*reply).regs[0] = MMAP_BACKING_SHM;
            (*reply).regs[1] = slot.inode() as u64;
            (*reply).regs[2] = 0;
            (*reply).regs[3] = file_size;
            (*reply).regs[4] = resolve_flags;
        }
        return;
    }

    let vh = slot.vnode_handle();
    if vh.is_valid() {
        let mut ctx =
            match unsafe { crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) } {
                Some(c) => c,
                None => {
                    unsafe {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                    }
                    return;
                }
            };
        let vnode = unsafe { &*ctx.vnode };
        let ops = vnode.ops;
        if !ops.is_null() {
            let mut attr = VAttr::zeroed();
            let file_size = match unsafe { ((*ops).meta.getattr)(&mut ctx, &raw mut attr) } {
                Ok(Ready(())) => attr.size,
                Ok(Parked(_)) | Err(_) => 0,
            };

            let (backing_kind, backing_id0, backing_id1) = match state.resolve_vnode_mount(vh) {
                Some(mh) => match state.mounts.get(mh) {
                    Some(mp) => (MMAP_BACKING_MOUNT, mp.id as u64, vnode.id),
                    None => (MMAP_BACKING_FILE, vnode.id, 0),
                },
                None => (MMAP_BACKING_FILE, vnode.id, 0),
            };

            unsafe {
                (*reply).label = TRONA_OK;
                (*reply).length = 5;
                (*reply).regs[0] = backing_kind;
                (*reply).regs[1] = backing_id0;
                (*reply).regs[2] = backing_id1;
                (*reply).regs[3] = file_size;
                (*reply).regs[4] = resolve_flags;
            }
            return;
        }
    }

    if slot.kind() == ObjectKind::Device && slot.device_info().map(|d| d.dev_type) == Some(DEV_FB0)
    {
        let smem_len = unsafe { crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64 };
        unsafe { ipc::set_send_cap_ctx(ipc_ctx(), 0, trona_runtime::client::caps::fb_untyped()) };
        unsafe {
            (*reply).label = TRONA_OK;
            (*reply).length = 5;
            (*reply).regs[0] = MMAP_BACKING_DEVICE;
            (*reply).regs[1] = DEV_FB0 as u64;
            (*reply).regs[2] = 0;
            (*reply).regs[3] = smem_len;
            (*reply).regs[4] = resolve_flags;
        }
        return;
    }

    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).length = 5;
        (*reply).regs[0] = MMAP_BACKING_NONE;
        (*reply).regs[1] = 0;
        (*reply).regs[2] = 0;
        (*reply).regs[3] = 0;
        (*reply).regs[4] = 0;
    }
}

/// Path-keyed counterpart of [`handle_resolve_backing`]. Takes a UTF-8 path in
/// the IPC message (regs[0] = length, regs[1..] = packed bytes) and resolves
/// it through `namei` using the calling client's mount namespace + cred. On
/// success, fills in the same `(backing_kind, id0, id1, file_size, flags)`
/// tuple as the fd-keyed variant. The `flags` field always advertises
/// `inode_readonly = 1` (bit 1) — file-MO sharing is only meaningful for
/// read-only mappings, and the caller (mmsrv) requires that invariant.
pub(crate) unsafe fn handle_resolve_path_backing(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let path_len = (*msg).regs[0] as usize;
        if path_len == 0 || path_len > MAX_PATH_LEN {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mut path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 1, path.as_mut_ptr()) as usize;
        if raw_len == 0 || raw_len != path_len {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);
        let args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path.as_ptr(),
            path_len: raw_len as u16,
            flags: crate::vfs_core::namei_common::NAMEI_FOLLOW,
            cred,
            root,
        };

        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(r) if r.vp.is_valid() => r,
            Ok(_) => {
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, result.vp)
        {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let vnode = &*ctx.vnode;
        let ops = vnode.ops;
        let file_size = if !ops.is_null() {
            let mut attr = VAttr::zeroed();
            match ((*ops).meta.getattr)(&mut ctx, &raw mut attr) {
                Ok(Ready(())) => attr.size,
                Ok(Parked(_)) | Err(_) => 0,
            }
        } else {
            0
        };

        let (backing_kind, backing_id0, backing_id1) = match state.resolve_vnode_mount(result.vp) {
            Some(mh) => match state.mounts.get(mh) {
                Some(mp) => (MMAP_BACKING_MOUNT, mp.id as u64, vnode.id),
                None => (MMAP_BACKING_FILE, vnode.id, 0),
            },
            None => (MMAP_BACKING_FILE, vnode.id, 0),
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 5;
        (*reply).regs[0] = backing_kind;
        (*reply).regs[1] = backing_id0;
        (*reply).regs[2] = backing_id1;
        (*reply).regs[3] = file_size;
        (*reply).regs[4] = 2;
    }
}
