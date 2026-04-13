// SPDX-License-Identifier: GPL-2.0-only
//! Backend mmap backing resolution helpers.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::types::core::*;

use crate::ipc_ctx;
use crate::owner::dispatch::build_data_ctx;
use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::mount_ctl;
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
        let mp_ptr = match state.mounts.raw_ptr(mh) {
            Some(p) => p,
            None => return VnodeHandle::INVALID,
        };
        mount_ctl::set_trampolines(state);
        let result = ((*vfsops).vget)(mp_ptr, vnode_id);
        mount_ctl::clear_trampolines();
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
                    Ok(n) => Some(n),
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
                    Ok(n) => Some(n),
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
        unsafe { (*reply).label = TRONA_INVALID_ARGUMENT; }
        return;
    }

    let slot = match state.clients.get(cli_handle) {
        Some(c) => c.objects[fd as usize],
        None => {
            unsafe { (*reply).label = TRONA_INVALID_ARGUMENT; }
            return;
        }
    };
    if !slot.is_live() {
        unsafe { (*reply).label = TRONA_INVALID_ARGUMENT; }
        return;
    }

    let mut resolve_flags: u64 = 0;
    if (slot.rights & OBJ_RIGHT_WRITE) != 0 {
        resolve_flags |= 1;
    }

    if slot.kind() == ObjectKind::Shm {
        let vh = slot.vnode_handle();
        if !vh.is_valid() {
            unsafe { (*reply).label = TRONA_INVALID_ARGUMENT; }
            return;
        }

        let ctx = match unsafe { mount_ctl::build_vop_context(state, vh) } {
            Some(c) => c,
            None => {
                unsafe { (*reply).label = TRONA_INVALID_ARGUMENT; }
                return;
            }
        };
        let vnode = unsafe { &*ctx.vnode };
        let ops = vnode.ops;
        let mut attr = VAttr::zeroed();
        let file_size = if !ops.is_null() && unsafe { ((*ops).meta.getattr)(&ctx, &raw mut attr).is_ok() } {
            attr.size
        } else {
            0
        };
        mount_ctl::clear_trampolines();

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
        let ctx = match unsafe { mount_ctl::build_vop_context(state, vh) } {
            Some(c) => c,
            None => {
                unsafe { (*reply).label = TRONA_INVALID_ARGUMENT; }
                return;
            }
        };
        let vnode = unsafe { &*ctx.vnode };
        let ops = vnode.ops;
        if !ops.is_null() {
            let mut attr = VAttr::zeroed();
            let file_size = if unsafe { ((*ops).meta.getattr)(&ctx, &raw mut attr).is_ok() } {
                attr.size
            } else {
                0
            };
            mount_ctl::clear_trampolines();

            let mount_handle = vnode.mount;
            let (backing_kind, backing_id0, backing_id1) = if mount_handle.is_valid() {
                if let Some(mp) = state.mounts.get(mount_handle) {
                    (MMAP_BACKING_MOUNT, mp.id as u64, vnode.id)
                } else {
                    (MMAP_BACKING_FILE, vnode.id, 0)
                }
            } else {
                (MMAP_BACKING_FILE, vnode.id, 0)
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
        mount_ctl::clear_trampolines();
    }

    if slot.kind() == ObjectKind::Device && slot.device_info().map(|d| d.dev_type) == Some(DEV_FB0) {
        let smem_len = unsafe { crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64 };
        unsafe { ipc::set_send_cap_ctx(ipc_ctx(), 0, trona::caps::fb_untyped()) };
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
