// SPDX-License-Identifier: GPL-2.0-only
//! Mutating file operations — VopMetaOps dispatch: close, lseek, unlink,
//! rename, mkdir, mkfifo, rmdir.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::personality::posix::consts::{S_IFDIR_L, S_IFREG_L};
use crate::server::consts::*;
use crate::personality::posix::misc::{maybe_reclaim_unlinked_shm, slot_shm_handle};
use crate::server::types::*;
use crate::ipc_ctx;
use crate::vfs_core::vnode::VnodeHandle;
use crate::vfs_core::arbitration::release_open;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::namei_common::{NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_WANTPARENT};
use crate::vfs_core::vnode::{VT_DIR, VT_FIFO};

use crate::server::types::{ClientHandle, MAX_CLIENT_OBJECTS};

/// Close an fd — owner-loop version.
///
/// No vref/vrele, no vnode lock, no take_fd_slot. ObjectSlot is zeroed
/// directly. Vnode reclaim is handle-based.
pub(crate) unsafe fn handle_close_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let slot_copy = {
            let cli = match state.clients.get(cli_handle) {
                Some(c) => c,
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            };
            let slot = &cli.objects[fd as usize];
            if !slot.is_live() {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            *slot
        };

        // SHM close: tell mmsrv to unmap
        if slot_copy.kind() == ObjectKind::Shm && slot_copy.offset != 0 {
            if slot_copy.vnode_handle().is_valid() {
                let mut mm_msg = TronaMsg::zeroed();
                let mut mm_reply_msg = TronaMsg::zeroed();
                mm_msg.label = MM_SHM_UNMAP;
                mm_msg.length = 3;
                mm_msg.regs[0] = slot_copy.inode() as u64;
                mm_msg.regs[1] = badge;
                mm_msg.regs[2] = slot_copy.offset;
                let _ = ipc::call_ctx(
                    ipc_ctx(),
                    trona::caps::mmsrv_ep(),
                    &raw const mm_msg,
                    &raw mut mm_reply_msg,
                );
            }
        }

        let shm_handle = unsafe { slot_shm_handle(state, &slot_copy) };

        // VOP close + arbitration release on vnode-backed fds
        let vh = slot_copy.vnode_handle();
        if vh.is_valid()
            && slot_copy.kind() != ObjectKind::Pipe
            && slot_copy.kind() != ObjectKind::UnixSocket
            && slot_copy.kind() != ObjectKind::InetSocket
        {
            if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vh) {
                let ops = (*ctx.vnode).ops;
                if !ops.is_null() {
                    let _ = ((*ops).meta.close)(&ctx, slot_copy.flags);
                }
                crate::vfs_core::mount_ctl::clear_trampolines();
            }

            if let Some(vnode) = state.vnodes.get_mut(vh) {
                release_open(vnode, slot_copy.held_access, slot_copy.held_deny);

                if vnode.should_reclaim() {
                    if vnode.flight_count == 0 {
                        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vh) {
                            let ops = (*ctx.vnode).ops;
                            if !ops.is_null() {
                                ((*ops).meta.inactive)(&ctx);
                            }
                            crate::vfs_core::mount_ctl::clear_trampolines();
                        }
                        state.vnodes.release(vh);
                    } else {
                        state.vnodes.retire(vh);
                    }
                }
            }
        }

        if shm_handle.is_valid() {
            let _ = unsafe {
                maybe_reclaim_unlinked_shm(
                    state,
                    shm_handle,
                    vh,
                    Some((cli_handle, fd as usize)),
                )
            };
        }

        // Zero the fd slot
        if let Some(cli) = state.clients.get_mut(cli_handle) {
            cli.objects[fd as usize].clear();
            cli.obj_count = cli.obj_count.saturating_sub(1);
        }

        (*reply).label = TRONA_OK;
    }
}

/// unlink — owner-loop version.
///
/// No retry loop, no locks, no vrele — single-owner model.
pub(crate) unsafe fn handle_unlink_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
            )
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);
        let args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        if !result.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Target must not be a directory.
        let target_vtype = state.vnodes.get(result.vp).map(|v| v.vtype).unwrap_or(0);
        if target_vtype == VT_DIR {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        // Call MetaOps::unlink on the parent directory.
        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, result.dvp) {
            let ops = (*ctx.vnode).ops;
            if ops.is_null() {
                crate::vfs_core::mount_ctl::clear_trampolines();
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
            match ((*ops).meta.unlink)(&ctx, result.last_name, result.last_name_len) {
                Ok(()) => { (*reply).label = TRONA_OK; }
                Err(e) => { (*reply).label = e.to_trona(); }
            }
            crate::vfs_core::mount_ctl::clear_trampolines();
        } else {
            (*reply).label = TRONA_NOT_SUPPORTED;
        }
    }
}

/// rename — owner-loop version.
pub(crate) unsafe fn handle_rename_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut old_len = (*msg).regs[0] as u8;
        let mut new_len = (*msg).regs[1] as u8;
        if (old_len as usize) > MAX_PATH_LEN { old_len = MAX_PATH_LEN as u8; }
        if (new_len as usize) > MAX_PATH_LEN { new_len = MAX_PATH_LEN as u8; }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let mut old_abs = [0u8; MAX_PATH_LEN];
        let mut new_abs = [0u8; MAX_PATH_LEN];
        let raw = &(*msg).regs[2] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }
        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some((old_ptr, old_norm_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, old_path.as_ptr(), old_len, old_abs.as_mut_ptr(),
            )
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };
        let Some((new_ptr, new_norm_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, new_path.as_ptr(), new_len, new_abs.as_mut_ptr(),
            )
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);

        // Resolve old path parent.
        let old_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: old_ptr,
            path_len: old_norm_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let old_result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &old_args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !old_result.dvp.is_valid() || !old_result.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Resolve new path parent.
        let new_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: new_ptr,
            path_len: new_norm_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let new_result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &new_args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !new_result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Build VopContext for old parent dir and call MetaOps::rename.
        let old_ctx = match crate::vfs_core::mount_ctl::build_vop_context(state, old_result.dvp) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
        };
        let ops = (*old_ctx.vnode).ops;
        if ops.is_null() {
            crate::vfs_core::mount_ctl::clear_trampolines();
            (*reply).label = TRONA_NOT_SUPPORTED;
            return;
        }

        // For rename, we also need a VopContext for the new parent.
        // Since set_trampolines is already active, build_vop_context
        // would re-set them (idempotent). But we need raw ptrs for both
        // directories simultaneously.
        let new_ctx_vnode_ptr = state.vnodes.raw_ptr(new_result.dvp);
        let new_mount_h = new_ctx_vnode_ptr
            .and_then(|vp| Some((*vp).mount))
            .unwrap_or(crate::vfs_core::mount::MountHandle::INVALID);
        let new_mount_ptr = state.mounts.raw_ptr(new_mount_h);

        if new_ctx_vnode_ptr.is_none() || new_mount_ptr.is_none() {
            crate::vfs_core::mount_ctl::clear_trampolines();
            (*reply).label = TRONA_NOT_SUPPORTED;
            return;
        }

        let new_vnode_ptr = new_ctx_vnode_ptr.unwrap();
        let new_mp = new_mount_ptr.unwrap();
        let new_ctx = crate::vfs_core::vop_context::VopContext {
            handle: new_result.dvp,
            vnode: new_vnode_ptr,
            mount_handle: new_mount_h,
            mount: new_mp as *const crate::vfs_core::mount::Mount,
            data: (*new_vnode_ptr).data,
            mount_data: (*new_mp).data,
            alloc: old_ctx.alloc,
            resolve_vnode: old_ctx.resolve_vnode,
            resolve_mount: old_ctx.resolve_mount,
        };

        match ((*ops).meta.rename)(
            &old_ctx,
            old_result.last_name,
            old_result.last_name_len,
            &new_ctx,
            new_result.last_name,
            new_result.last_name_len,
        ) {
            Ok(()) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
        crate::vfs_core::mount_ctl::clear_trampolines();
    }
}

/// mkdir — owner-loop version.
pub(crate) unsafe fn handle_mkdir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
            )
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);

        // Check if target already exists.
        let check_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };
        if let Ok(result) = crate::owner::dispatch::resolve_namei(state, cli_handle, &check_args) {
            if result.vp.is_valid() {
                (*reply).label = TRONA_ALREADY_EXISTS;
                return;
            }
        }

        // Resolve parent.
        let parent_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &parent_args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        if result.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        let mode = (*msg).regs[0] as u32 & 0o777;
        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, result.dvp) {
            let ops = (*ctx.vnode).ops;
            if ops.is_null() {
                crate::vfs_core::mount_ctl::clear_trampolines();
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
            let create_mode = S_IFDIR_L | mode;
            match ((*ops).meta.mkdir)(
                &ctx,
                result.last_name,
                result.last_name_len,
                create_mode,
                &raw const cred,
            ) {
                Ok(_new_vh) => { (*reply).label = TRONA_OK; }
                Err(e) => { (*reply).label = e.to_trona(); }
            }
            crate::vfs_core::mount_ctl::clear_trampolines();
        } else {
            (*reply).label = TRONA_NOT_SUPPORTED;
        }
    }
}

/// mkfifo — owner-loop version.
pub(crate) unsafe fn handle_mkfifo_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
            )
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);

        // Check if target already exists.
        let check_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW,
            cred,
            root,
        };
        if let Ok(result) = crate::owner::dispatch::resolve_namei(state, cli_handle, &check_args) {
            if result.vp.is_valid() {
                (*reply).label = TRONA_ALREADY_EXISTS;
                return;
            }
        }

        // Allocate a pipe via VfsState arena.
        let pipe_handle = match crate::fileops::pipe::alloc_pipe(state) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        // Resolve parent directory.
        let parent_args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };
        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &parent_args) {
            Ok(r) => r,
            Err(e) => {
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !result.dvp.is_valid() {
            crate::fileops::pipe::release_pipe(state, pipe_handle);
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        if result.vp.is_valid() {
            crate::fileops::pipe::release_pipe(state, pipe_handle);
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        let mode = (*msg).regs[0] as u32 & 0o777;
        let ctx = match crate::vfs_core::mount_ctl::build_vop_context(state, result.dvp) {
            Some(c) => c,
            None => {
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            crate::vfs_core::mount_ctl::clear_trampolines();
            crate::fileops::pipe::release_pipe(state, pipe_handle);
            (*reply).label = TRONA_NOT_SUPPORTED;
            return;
        }

        let create_mode = S_IFREG_L | mode;
        let new_vh = match ((*ops).meta.create)(
            &ctx,
            result.last_name,
            result.last_name_len,
            create_mode,
            &raw const cred,
        ) {
            Ok(vh) => vh,
            Err(_) => {
                crate::vfs_core::mount_ctl::clear_trampolines();
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };
        crate::vfs_core::mount_ctl::clear_trampolines();

        // Set FIFO metadata on the new vnode.
        if let Some(vnode) = state.vnodes.get_mut(new_vh) {
            vnode.vtype = VT_FIFO;
            if vnode.ops == &raw const crate::fs::ramfs::RAMFS_VOPS {
                let vd = vnode.data as *mut crate::fs::ramfs::RamfsVnodeData;
                (*vd).ftype = VT_FIFO;
                (*vd).fifo_pipe = pipe_handle;
            } else if vnode.ops == &raw const crate::fs::tmpfs::TMPFS_VOPS {
                let vd = vnode.data as *mut crate::fs::tmpfs::TmpfsVnodeData;
                (*vd).ftype = VT_FIFO;
                (*vd).fifo_pipe = pipe_handle;
            } else {
                crate::fileops::pipe::release_pipe(state, pipe_handle);
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
        }

        (*reply).label = TRONA_OK;
    }
}

/// rmdir — owner-loop version.
pub(crate) unsafe fn handle_rmdir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = crate::server::client::extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            crate::fileops::open::normalize_path_owned(
                state, cli_handle, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
            )
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let root = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);
        let args = crate::vfs_core::namei_common::NameiArgs {
            start: root,
            path: path_ptr,
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
            Ok(r) => r,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        if !result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        if !result.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Target must be a directory.
        let target_vtype = state.vnodes.get(result.vp).map(|v| v.vtype).unwrap_or(0);
        if target_vtype != VT_DIR {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Must not be a mount point.
        let is_covered = state.vnodes.get(result.vp)
            .map(|v| v.covered_by.is_valid())
            .unwrap_or(false);
        if is_covered {
            (*reply).label = TRONA_BUSY;
            return;
        }

        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, result.dvp) {
            let ops = (*ctx.vnode).ops;
            if ops.is_null() {
                crate::vfs_core::mount_ctl::clear_trampolines();
                (*reply).label = TRONA_NOT_SUPPORTED;
                return;
            }
            match ((*ops).meta.rmdir)(&ctx, result.last_name, result.last_name_len) {
                Ok(()) => { (*reply).label = TRONA_OK; }
                Err(e) => { (*reply).label = e.to_trona(); }
            }
            crate::vfs_core::mount_ctl::clear_trampolines();
        } else {
            (*reply).label = TRONA_NOT_SUPPORTED;
        }
    }
}

/// Lseek — owner-loop version.
pub(crate) unsafe fn handle_lseek_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let offset = (*msg).regs[1] as i64;
        let whence = (*msg).regs[2] as i32;

        let (kind, vnode_handle, current_offset) = {
            match crate::owner::dispatch::resolve_fd(state, cli_handle, fd) {
                Some(s) => (s.kind(), s.vnode_handle(), s.offset),
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            }
        };

        if kind != ObjectKind::File {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let file_size: u64 = if vnode_handle.is_valid() {
            if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vnode_handle) {
                let ops = (*ctx.vnode).ops;
                let sz = if !ops.is_null() {
                    let mut attr = VAttr::zeroed();
                    let _ = ((*ops).meta.getattr)(&ctx, &raw mut attr);
                    attr.size
                } else { 0 };
                crate::vfs_core::mount_ctl::clear_trampolines();
                sz
            } else { 0 }
        } else { 0 };

        let new_offset: i64 = match whence {
            0 => offset,
            1 => current_offset as i64 + offset,
            2 => file_size as i64 + offset,
            _ => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };

        if new_offset < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if let Some(slot_mut) = crate::owner::dispatch::resolve_fd_mut(state, cli_handle, fd) {
            slot_mut.offset = new_offset as u64;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_offset as u64;
    }
}
