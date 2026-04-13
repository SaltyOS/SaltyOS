// SPDX-License-Identifier: GPL-2.0-only
//! fchmodat, fchownat, fchmod, fchown, utimensat, symlinkat, readlinkat

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, client_cred, root_vnode_for, cwd_vnode_for, resolve_fd};
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::vfs_core::file::VAttr;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{
    NameiArgs, NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_NOFOLLOW_FINAL, NAMEI_WANTPARENT,
};
use crate::vfs_core::vnode::VnodeHandle;

use super::at_open::resolve_dirfd_vnode;

/// Common pattern: resolve path via namei from dirfd, then call a VopMetaOps callback.
unsafe fn resolve_and_setattr(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    dirfd: i32,
    path: &[u8],
    path_len: u8,
    namei_flags: u32,
    attr: &VAttr,
    reply: *mut TronaMsg,
) {
    unsafe {
        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let start = resolve_dirfd_vnode(state, cli_handle, dirfd);
        if !start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: path.as_ptr(),
            path_len: path_len as u16,
            flags: namei_flags,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if !ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let ctx = match mount_ctl::build_vop_context(state, ni.vp) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let ops = &*(*ctx.vnode).ops;
        match (ops.meta.setattr)(&ctx, &raw const *attr) {
            Ok(()) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
        mount_ctl::clear_trampolines();
    }
}

/// fchmodat(dirfd, path, mode, flags)
pub(crate) unsafe fn handle_fchmodat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        let mut attr = VAttr::zeroed();
        attr.mode = mode;
        resolve_and_setattr(state, cli_handle, dirfd, &path, path_len, NAMEI_FOLLOW, &attr, reply);
    }
}

/// fchownat(dirfd, path, uid, gid, flags)
pub(crate) unsafe fn handle_fchownat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let uid = (*msg).regs[1] as u32;
        let gid = (*msg).regs[2] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 4, path.as_mut_ptr());

        let at_flags = (*msg).regs[3] as i32;
        let namei_flags = if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
            NAMEI_NOFOLLOW_FINAL
        } else {
            NAMEI_FOLLOW
        };

        let mut attr = VAttr::zeroed();
        attr.uid = uid;
        attr.gid = gid;
        resolve_and_setattr(state, cli_handle, dirfd, &path, path_len, namei_flags, &attr, reply);
    }
}

/// fchmod(fd, mode)
pub(crate) unsafe fn handle_fchmod(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let vh = match state.clients.get(cli_handle) {
            Some(cli) => {
                let slot = &cli.objects[fd as usize];
                if !slot.is_live() || !slot.vnode_handle().is_valid() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                slot.vnode_handle()
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };

        let ctx = match mount_ctl::build_vop_context(state, vh) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let ops = &*(*ctx.vnode).ops;
        let mut attr = VAttr::zeroed();
        attr.mode = mode;
        match (ops.meta.setattr)(&ctx, &raw const attr) {
            Ok(()) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
        mount_ctl::clear_trampolines();
    }
}

/// fchown(fd, uid, gid)
pub(crate) unsafe fn handle_fchown(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let uid = (*msg).regs[1] as u32;
        let gid = (*msg).regs[2] as u32;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let vh = match state.clients.get(cli_handle) {
            Some(cli) => {
                let slot = &cli.objects[fd as usize];
                if !slot.is_live() || !slot.vnode_handle().is_valid() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                slot.vnode_handle()
            }
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };

        let ctx = match mount_ctl::build_vop_context(state, vh) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let ops = &*(*ctx.vnode).ops;
        let mut attr = VAttr::zeroed();
        attr.uid = uid;
        attr.gid = gid;
        match (ops.meta.setattr)(&ctx, &raw const attr) {
            Ok(()) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
        mount_ctl::clear_trampolines();
    }
}

/// utimensat(dirfd, path, times, flags)
pub(crate) unsafe fn handle_utimensat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let atime_ns = (*msg).regs[4];
        let mtime_ns = (*msg).regs[5];
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        // fd-based utimensat (AT_EMPTY_PATH with fd)
        if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 && dirfd >= 0 {
            if dirfd as usize >= MAX_CLIENT_OBJECTS {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            let vh = match state.clients.get(cli_handle) {
                Some(cli) => {
                    let slot = &cli.objects[dirfd as usize];
                    if !slot.is_live() || !slot.vnode_handle().is_valid() {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                    slot.vnode_handle()
                }
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            };
            let ctx = match mount_ctl::build_vop_context(state, vh) {
                Some(c) => c,
                None => { (*reply).label = TRONA_IO_ERROR; return; }
            };
            let ops = &*(*ctx.vnode).ops;
            let mut attr = VAttr::zeroed();
            attr.atime = atime_ns;
            attr.mtime = mtime_ns;
            match (ops.meta.setattr)(&ctx, &raw const attr) {
                Ok(()) => { (*reply).label = TRONA_OK; }
                Err(e) => { (*reply).label = e.to_trona(); }
            }
            mount_ctl::clear_trampolines();
            return;
        }

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let namei_flags = if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
            NAMEI_NOFOLLOW_FINAL
        } else {
            NAMEI_FOLLOW
        };

        let mut attr = VAttr::zeroed();
        attr.atime = atime_ns;
        attr.mtime = mtime_ns;
        resolve_and_setattr(state, cli_handle, dirfd, &path, path_len, namei_flags, &attr, reply);
    }
}

/// symlinkat(target, dirfd, linkpath)
pub(crate) unsafe fn handle_symlinkat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let target_len = (*msg).regs[0] as u8;
        let dirfd = (*msg).regs[1] as i32;
        let mut link_path = [0u8; MAX_PATH_LEN];
        let link_len = extract_path(msg, 2, link_path.as_mut_ptr());

        if target_len == 0 || link_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Extract target string from msg after link path.
        let mut target = [0u8; MAX_PATH_LEN];
        let target_src = &(*msg).regs[3 + ((link_len as usize + 7) / 8)] as *const u64 as *const u8;
        for i in 0..target_len as usize {
            target[i] = *target_src.add(i);
        }

        let start = resolve_dirfd_vnode(state, cli_handle, dirfd);
        if !start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: link_path.as_ptr(),
            path_len: link_len as u16,
            flags: NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if ni.vp.is_valid() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }
        if !ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let ctx = match mount_ctl::build_vop_context(state, ni.dvp) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let ops = &*(*ctx.vnode).ops;
        match (ops.meta.symlink)(
            &ctx,
            ni.last_name,
            ni.last_name_len,
            target.as_ptr(),
            target_len,
            &raw const cred,
        ) {
            Ok(_) => { (*reply).label = TRONA_OK; }
            Err(e) => { (*reply).label = e.to_trona(); }
        }
        mount_ctl::clear_trampolines();
    }
}

/// readlinkat(dirfd, path, buf, bufsiz)
pub(crate) unsafe fn handle_readlinkat(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 1, path.as_mut_ptr());

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let start = resolve_dirfd_vnode(state, cli_handle, dirfd);
        if !start.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let root = root_vnode_for(state, cli_handle);

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: path.as_ptr(),
            path_len: path_len as u16,
            flags: NAMEI_NOFOLLOW_FINAL,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if !ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let ctx = match mount_ctl::build_vop_context(state, ni.vp) {
            Some(c) => c,
            None => { (*reply).label = TRONA_IO_ERROR; return; }
        };
        let ops = &*(*ctx.vnode).ops;
        let mut buf = [0u8; MAX_PATH_LEN];
        match (ops.meta.readlink)(&ctx, buf.as_mut_ptr(), MAX_PATH_LEN, &raw const cred) {
            Ok(n) => {
                mount_ctl::clear_trampolines();
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = n as u64;
                let dst = &raw mut (*reply).regs[1] as *mut u8;
                for i in 0..n {
                    *dst.add(i) = buf[i];
                }
                (*reply).length = 1 + ((n as u64 + 7) / 8);
            }
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
            }
        }
    }
}
