// SPDX-License-Identifier: GPL-2.0-only
//! VFS IPC dispatch — owner-loop entry point.
//!
//! Replaces `ipc/dispatch.rs`. Every handler receives `&mut VfsState`
//! instead of reaching into global statics. Client lookup uses
//! `BadgeMap` instead of O(n) pool scan.

use trona::consts::kernel::*;
use trona::protocol::mmsrv::*;
use trona::protocol::vfs::*;
use trona::types::core::*;

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::PERS_WIN32;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NameiArgs, NameiResult};
use crate::vfs_core::vnode::{Vnode, VnodeHandle};
use crate::vfs_core::vop_context::{VopContext, VopDataContext};
use crate::{ipc_ctx, personality};

// =========================================================================
// Client resolution
// =========================================================================

/// Resolve badge to ClientHandle, auto-registering new clients.
fn resolve_client(state: &mut VfsState, badge: u64) -> Option<ClientHandle> {
    if let Some((slot, epoch)) = state.badge_map.lookup(badge) {
        let h = ClientHandle::new(slot, epoch);
        if state.clients.is_alive(h) {
            return Some(h);
        }
    }
    // Auto-register new client.
    let h = state.clients.alloc()?;
    let cli = state.clients.get_mut(h)?;
    *cli = ClientState::zeroed();
    cli.badge = badge;
    cli.personality = 0; // PERS_POSIX default
    cli.cwd_vnode = VnodeHandle::INVALID;
    cli.mount_ns = state.global_ns;
    cli.cwd[0] = b'/';
    state.badge_map.insert(badge, h.slot(), h.epoch());
    Some(h)
}

fn lookup_client(state: &VfsState, badge: u64) -> Option<ClientHandle> {
    let (slot, epoch) = state.badge_map.lookup(badge)?;
    let h = ClientHandle::new(slot, epoch);
    if state.clients.is_alive(h) {
        Some(h)
    } else {
        None
    }
}

/// Get client personality without allocating.
fn client_personality(state: &VfsState, badge: u64) -> u8 {
    if let Some((slot, epoch)) = state.badge_map.lookup(badge) {
        let h = ClientHandle::new(slot, epoch);
        if let Some(cli) = state.clients.get(h) {
            return cli.personality;
        }
    }
    0 // PERS_POSIX default
}

// =========================================================================
// FD resolution helpers
// =========================================================================

/// Resolve an fd from a client's object table. Returns a reference to the
/// ObjectSlot if live, None otherwise.
pub(crate) fn resolve_fd<'a>(
    state: &'a VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) -> Option<&'a ObjectSlot> {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return None;
    }
    let cli = state.clients.get(cli_handle)?;
    let slot = &cli.objects[fd as usize];
    if !slot.is_live() {
        return None;
    }
    Some(slot)
}

/// Resolve fd to a mutable ObjectSlot reference.
pub(crate) fn resolve_fd_mut<'a>(
    state: &'a mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) -> Option<&'a mut ObjectSlot> {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return None;
    }
    let cli = state.clients.get_mut(cli_handle)?;
    let slot = &mut cli.objects[fd as usize];
    if !slot.is_live() {
        return None;
    }
    Some(slot)
}

/// Resolve fd to its VnodeHandle. Returns INVALID if the fd is not
/// vnode-backed (pipes, sockets, epoll).
pub(crate) fn fd_vnode_handle(state: &VfsState, cli_handle: ClientHandle, fd: i32) -> VnodeHandle {
    match resolve_fd(state, cli_handle, fd) {
        Some(slot) => slot.vnode_handle(),
        None => VnodeHandle::INVALID,
    }
}

/// Build a VopContext for a vnode handle. Sets up arena trampolines.
/// Caller must call `mount_ctl::clear_trampolines()` after the VOP call.
pub(crate) unsafe fn build_ctx(state: &mut VfsState, vh: VnodeHandle) -> Option<VopContext> {
    unsafe { mount_ctl::build_vop_context(state, vh) }
}

/// Build a NameiCtx from VfsState for path resolution.
///
/// Sets up trampolines and borrows arenas. Caller must call
/// `mount_ctl::clear_trampolines()` after namei completes.
///
/// # Safety
///
/// The returned NameiCtx borrows `state.vnodes` and `state.mounts` as
/// shared references while the alloc trampoline holds a raw mutable
/// pointer to `state.vnodes`. This is sound because alloc is only
/// invoked from inside VOP callbacks (backend code), never while NameiCtx
/// methods are reading the arena. Single-threaded guarantee.
pub(crate) unsafe fn build_namei_ctx<'a>(
    state: &'a mut VfsState,
) -> crate::vfs_core::namei_common::NameiCtx<'a> {
    unsafe {
        mount_ctl::set_trampolines(state);
        crate::vfs_core::namei_common::NameiCtx {
            vnodes: &state.vnodes,
            mounts: &state.mounts,
            alloc: mount_ctl::trampoline_alloc_vnode as crate::vfs_core::vop_context::VnodeAllocFn,
            resolve_vnode: mount_ctl::vnode_resolve_trampoline
                as crate::vfs_core::vop_context::VnodeResolveFn,
            resolve_mount: mount_ctl::mount_resolve_trampoline
                as crate::vfs_core::vop_context::MountResolveFn,
        }
    }
}

/// Resolve a path according to the caller personality while keeping
/// common fileops free from direct POSIX/Win32 resolver calls.
pub(crate) unsafe fn resolve_namei(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    args: &NameiArgs,
) -> Result<NameiResult, VfsError> {
    unsafe {
        let personality = state
            .clients
            .get(cli_handle)
            .map(|cli| cli.personality)
            .unwrap_or(0);
        let namei_ctx = build_namei_ctx(state);
        let result = if personality == PERS_WIN32 {
            personality::win32::namei::namei_win32(&namei_ctx, args)
        } else {
            personality::posix::namei::namei_posix(&namei_ctx, args)
        };
        mount_ctl::clear_trampolines();
        result
    }
}

/// Build a VopDataContext from a vnode handle. No trampolines needed.
pub(crate) fn build_data_ctx(state: &VfsState, vh: VnodeHandle) -> Option<VopDataContext> {
    let vnode = state.vnodes.get(vh)?;
    let mount_handle = vnode.mount;
    let mount = state.mounts.get(mount_handle)?;
    Some(VopDataContext::new(
        vh,
        mount_handle,
        vnode.data,
        mount.data,
        vnode.vtype,
        vnode.id,
    ))
}

// =========================================================================
// Credential helpers
// =========================================================================

/// Build a VfsCred from a client's cached credentials.
pub(crate) fn client_cred(
    state: &VfsState,
    cli_handle: ClientHandle,
) -> crate::vfs_core::cred::VfsCred {
    let mut cred = crate::vfs_core::cred::VfsCred::zeroed();
    if let Some(cli) = state.clients.get(cli_handle) {
        cred.pid = (cli.badge & 0xFFFF) as u32;
        cred.uid = cli.cred_uid;
        cred.euid = cli.cred_uid;
        cred.gid = cli.cred_gid;
        cred.egid = cli.cred_gid;
        cred.ngroups = cli.cred_ngroups;
        let n = cred.ngroups as usize;
        for i in 0..n {
            cred.groups[i] = cli.cred_groups[i];
        }
    }
    cred
}

/// Get the root vnode handle for a client (namespace root or global root).
pub(crate) fn root_vnode_for(state: &VfsState, cli_handle: ClientHandle) -> VnodeHandle {
    if let Some(cli) = state.clients.get(cli_handle) {
        if cli.mount_ns.is_valid() {
            if let Some(ns) = state.mount_ns.get(cli.mount_ns) {
                if ns.root_mount.is_valid() {
                    if let Some(mp) = state.mounts.get(ns.root_mount) {
                        return mp.root_vnode;
                    }
                }
            }
        }
    }
    // Fall back to global root.
    if let Some(mp) = state.mounts.get(state.root_mount) {
        mp.root_vnode
    } else {
        VnodeHandle::INVALID
    }
}

/// Get the cwd vnode handle for a client. Falls back to root if unset.
pub(crate) fn cwd_vnode_for(state: &VfsState, cli_handle: ClientHandle) -> VnodeHandle {
    if let Some(cli) = state.clients.get(cli_handle) {
        if cli.cwd_vnode.is_valid() {
            return cli.cwd_vnode;
        }
    }
    root_vnode_for(state, cli_handle)
}

// =========================================================================
// Main dispatch
// =========================================================================

/// Dispatch a single VFS IPC message.
///
/// Returns `true` if the reply should be skipped (deferred reply via saved
/// caller cap), `false` if the caller should send `reply` back.
pub(crate) unsafe fn vfs_dispatch_owned(
    state: &mut VfsState,
    msg: *const TronaMsg,
    badge: u64,
    recv_source: u64,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        state.dispatch_count += 1;

        // Bound notification (PTY data-ready).
        if recv_source == IPC_RECV_SOURCE_NOTIFICATION {
            personality::posix::tty::handle_pty_notification(badge);
            return true;
        }

        // Backend callback endpoint.
        if recv_source == 1 {
            if badge == NETSRV_CALLBACK_BADGE {
                personality::posix::inet::handle_netsrv_callback(msg, reply);
            } else if (*msg).label == MM_PAGER_REQUEST {
                crate::backend::handle_pager_read(state, msg, reply);
            } else if (*msg).label == MM_PAGER_WRITE_REQUEST {
                crate::backend::handle_pager_write(state, msg, reply);
            } else {
                (*reply).label = TRONA_INVALID_OPERATION;
            }
            return false;
        }

        // Backend service requests sent through the regular VFS service EP.
        if (*msg).label == VFS_BACKEND_PAGER_READ {
            crate::backend::handle_pager_read(state, msg, reply);
            return false;
        }
        if (*msg).label == VFS_BACKEND_PAGER_WRITE {
            crate::backend::handle_pager_write(state, msg, reply);
            return false;
        }
        if (*msg).label == VFS_BACKEND_RESOLVE_BACKING {
            let target_badge = (*msg).regs[1];
            let Some(target_client) = lookup_client(state, target_badge) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            };
            let _ = crate::backend::ensure_mmsrv_pager_callback_registered();
            crate::backend::handle_resolve_backing(state, target_client, msg, reply);
            return false;
        }

        if (*msg).label == VFS_CLIENT_REGISTER {
            dispatch_client_register(state, msg, reply, badge);
            return false;
        }
        if (*msg).label == VFS_CLIENT_EXIT {
            dispatch_client_exit(state, msg, reply, badge);
            return true;
        }
        if (*msg).label == VFS_CLIENT_EXEC {
            dispatch_client_exec(state, msg, reply, badge);
            return true;
        }

        // Resolve client.
        let cli_handle = match resolve_client(state, badge) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        };

        let mut skip_reply = false;

        match (*msg).label {
            VFS_READ => {
                let fd = (*msg).regs[0] as i32;
                let pers = client_personality(state, badge);
                skip_reply = if pers == PERS_WIN32 {
                    personality::win32::dispatch::dispatch_read(state, cli_handle, fd, msg, reply)
                } else {
                    personality::posix::dispatch::dispatch_read(state, cli_handle, fd, msg, reply)
                };
            }
            VFS_WRITE => {
                let fd = (*msg).regs[0] as i32;
                let pers = client_personality(state, badge);
                skip_reply = if pers == PERS_WIN32 {
                    personality::win32::dispatch::dispatch_write(state, cli_handle, fd, msg, reply)
                } else {
                    personality::posix::dispatch::dispatch_write(state, cli_handle, fd, msg, reply)
                };
            }
            VFS_CLOSE => {
                let fd = (*msg).regs[0] as i32;
                let pers = client_personality(state, badge);
                if pers == PERS_WIN32 {
                    personality::win32::dispatch::pre_close(state, cli_handle, fd);
                } else {
                    personality::posix::dispatch::pre_close(state, cli_handle, fd);
                }
                crate::fileops::mutate::handle_close_owned(state, cli_handle, msg, reply, badge);
            }
            VFS_LSEEK => {
                crate::fileops::mutate::handle_lseek_owned(state, cli_handle, msg, reply);
            }
            VFS_PREAD => {
                crate::fileops::pio::handle_pread_owned(state, cli_handle, msg, reply);
            }
            VFS_PWRITE => {
                crate::fileops::pio::handle_pwrite_owned(state, cli_handle, msg, reply);
            }
            VFS_BULK_SETUP => {
                crate::fileops::bulk::handle_bulk_setup_owned(state, cli_handle, msg, reply);
            }
            VFS_BULK_READ => {
                crate::fileops::bulk::handle_bulk_read_owned(state, cli_handle, msg, reply);
            }
            VFS_BULK_PWRITE => {
                crate::fileops::bulk::handle_bulk_pwrite_owned(state, cli_handle, msg, reply);
            }
            VFS_FSYNC => {
                dispatch_fsync(state, msg, reply, cli_handle);
            }
            VFS_GETXATTR => {
                dispatch_getxattr(state, msg, reply, cli_handle);
            }
            VFS_SETXATTR => {
                dispatch_setxattr(state, msg, reply, cli_handle);
            }
            VFS_REMOVEXATTR => {
                dispatch_removexattr(state, msg, reply, cli_handle);
            }
            VFS_LISTXATTR => {
                dispatch_listxattr(state, msg, reply, cli_handle);
            }
            VFS_SYSCTL => {
                dispatch_sysctl(msg, reply);
            }
            VFS_MOUNT => {
                crate::ipc::mount_ipc::handle_vfs_mount(state, msg, reply, badge);
            }
            VFS_UMOUNT => {
                crate::ipc::mount_ipc::handle_vfs_umount(state, msg, reply, badge);
            }
            VFS_PIVOT_ROOT => {
                crate::ipc::mount_ipc::handle_vfs_pivot_root(state, msg, reply, badge);
            }
            VFS_DUMP_PENDING => {
                (*reply).label = TRONA_OK;
            }
            _ => {
                let pers = client_personality(state, badge);
                let handled = if pers == PERS_WIN32 {
                    personality::win32::dispatch::dispatch(state, cli_handle, msg, reply)
                } else {
                    personality::posix::dispatch::dispatch(state, cli_handle, msg, reply)
                };
                if let Some(sr) = handled {
                    skip_reply = sr;
                } else {
                    (*reply).label = TRONA_INVALID_OPERATION;
                }
            }
        }

        skip_reply
    }
}

// =========================================================================
// Client registration (VfsState-based)
// =========================================================================

unsafe fn dispatch_client_register(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let pers = (*msg).regs[1] as u8;
        if pers > 1 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let existing = lookup_client(state, target_badge).is_some();

        let cli_handle = match resolve_client(state, target_badge) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        if let Some(cli) = state.clients.get_mut(cli_handle) {
            if existing {
                // Exec-time re-registration must preserve inherited fd/cwd/ns
                // state; only the client personality changes.
                cli.personality = pers;
                cli.win32_drive_cwd = [0u32; 26];
                cli.win32_current_drive = if pers == PERS_WIN32 { 2 } else { 0 };
            } else {
                let badge = cli.badge;
                *cli = ClientState::zeroed();
                cli.badge = badge;
                cli.personality = pers;
                if pers == PERS_WIN32 {
                    cli.win32_current_drive = 2; // C:
                    cli.win32_drive_cwd = [0u32; 26];
                }
                cli.mount_ns = state.global_ns;
                cli.cwd[0] = b'/';
            }
        }
        (*reply).label = TRONA_OK;
    }
}

// =========================================================================
// Client exit (VfsState-based)
// =========================================================================

unsafe fn dispatch_client_exit(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let dead_badge = (*msg).regs[0];
        if let Some((slot, epoch)) = state.badge_map.lookup(dead_badge) {
            let h = ClientHandle::new(slot, epoch);
            crate::personality::posix::tty::pty::clear_pty_pending_badge(state, dead_badge);
            let pers = state.clients.get(h).map(|cli| cli.personality).unwrap_or(0);

            if pers == PERS_WIN32 {
                personality::win32::dispatch::cleanup_client_objects(state, h);
            } else {
                personality::posix::dispatch::cleanup_client_objects(state, h);
            }

            // Release all vnode references held by this client's fds.
            let mut live_objects = [ObjectSlot::zeroed(); MAX_CLIENT_OBJECTS];
            let mut live_count = 0usize;
            if let Some(cli) = state.clients.get(h) {
                for i in 0..MAX_CLIENT_OBJECTS {
                    if cli.objects[i].is_live() {
                        live_objects[live_count] = cli.objects[i];
                        live_count += 1;
                    }
                }
            }

            for obj_copy in live_objects[..live_count].iter().copied() {
                let vh = obj_copy.vnode_handle();
                if vh.is_valid() {
                    if let Some(vnode) = state.vnodes.get_mut(vh) {
                        crate::vfs_core::arbitration::release_open(
                            vnode,
                            obj_copy.held_access,
                            obj_copy.held_deny,
                        );
                    }
                }
                let shm_handle = crate::personality::posix::misc::slot_shm_handle(state, &obj_copy);
                if shm_handle.is_valid() {
                    let _ = crate::personality::posix::misc::maybe_reclaim_unlinked_shm(
                        state, shm_handle, vh, None,
                    );
                }
            }

            if let Some(cli) = state.clients.get_mut(h) {
                for i in 0..MAX_CLIENT_OBJECTS {
                    if cli.objects[i].is_live() {
                        cli.objects[i].clear();
                    }
                }
                cli.obj_count = 0;
            }
            state.badge_map.remove(dead_badge);
            state.clients.release(h);
        }
    }
}

unsafe fn dispatch_client_exec(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let exec_badge = (*msg).regs[0];
        crate::personality::posix::tty::pty::clear_pty_pending_badge(state, exec_badge);
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

// =========================================================================
// Xattr dispatch (fd-based, using VfsState)
// =========================================================================

const XATTR_INLINE_MAX: usize = 30 * 8;

unsafe fn extract_inline(msg: *const TronaMsg, reg_start: usize, dst: *mut u8, len: usize) -> bool {
    let avail = (32 - reg_start) * 8;
    if len > avail {
        return false;
    }
    unsafe {
        let src = &(*msg).regs[reg_start] as *const u64 as *const u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
    true
}

unsafe fn pack_inline(reply: *mut TronaMsg, reg_start: usize, src: *const u8, len: usize) {
    unsafe {
        let dst = &raw mut (*reply).regs[reg_start] as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
}

/// Resolve fd to VnodeHandle and build a VopDataContext.
fn fd_to_data_ctx(state: &VfsState, cli_handle: ClientHandle, fd: i32) -> Option<VopDataContext> {
    let slot = resolve_fd(state, cli_handle, fd)?;
    if !slot.vnode_handle().is_valid() {
        return None;
    }
    build_data_ctx(state, slot.vnode_handle())
}

unsafe fn dispatch_fsync(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        match fd_to_data_ctx(state, cli_handle, fd) {
            Some(data_ctx) => {
                let vnode = state.vnodes.get(data_ctx.vnode_handle);
                if let Some(vn) = vnode {
                    let ops = vn.ops;
                    if !ops.is_null() {
                        match ((*ops).data.fsync)(&data_ctx) {
                            Ok(()) => (*reply).label = TRONA_OK,
                            Err(e) => (*reply).label = e.to_trona(),
                        }
                        return;
                    }
                }
                (*reply).label = TRONA_OK;
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}

unsafe fn dispatch_getxattr(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_ctx = match fd_to_data_ctx(state, cli_handle, fd) {
            Some(ctx) => ctx,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let name_len = (*msg).regs[1] as usize;
        if name_len == 0 || name_len > XATTR_INLINE_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let mut name_buf = [0u8; XATTR_INLINE_MAX];
        if !extract_inline(msg, 2, name_buf.as_mut_ptr(), name_len) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let vnode = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let ops = vnode.ops;
        if ops.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let val_cap = 31 * 8;
        let mut val_buf = [0u8; 31 * 8];
        match ((*ops).data.getxattr)(
            &data_ctx,
            name_buf.as_ptr(),
            name_len as u8,
            val_buf.as_mut_ptr(),
            val_cap,
        ) {
            Ok(val_len) => {
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = val_len as u64;
                if val_len > 0 {
                    pack_inline(reply, 1, val_buf.as_ptr(), val_len);
                }
                (*reply).length = 1 + ((val_len as u64) + 7) / 8;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

unsafe fn dispatch_setxattr(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_ctx = match fd_to_data_ctx(state, cli_handle, fd) {
            Some(ctx) => ctx,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let name_len = (*msg).regs[1] as usize;
        let value_len = (*msg).regs[2] as usize;
        let flags = (*msg).regs[3] as u32;
        let total = name_len + value_len;
        if name_len == 0 || total > (28 * 8) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let mut buf = [0u8; 28 * 8];
        if !extract_inline(msg, 4, buf.as_mut_ptr(), total) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let vnode = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let ops = vnode.ops;
        if ops.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        match ((*ops).data.setxattr)(
            &data_ctx,
            buf.as_ptr(),
            name_len as u8,
            buf.as_ptr().add(name_len),
            value_len,
            flags,
        ) {
            Ok(()) => {
                (*reply).label = TRONA_OK;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

unsafe fn dispatch_listxattr(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_ctx = match fd_to_data_ctx(state, cli_handle, fd) {
            Some(ctx) => ctx,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let vnode = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let ops = vnode.ops;
        if ops.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let requested = (*msg).regs[1] as usize;
        let buf_cap = 31 * 8;
        let effective = if requested == 0 {
            0
        } else {
            buf_cap.min(requested)
        };
        let mut buf = [0u8; 31 * 8];

        match ((*ops).data.listxattr)(
            &data_ctx,
            if effective == 0 {
                core::ptr::null_mut()
            } else {
                buf.as_mut_ptr()
            },
            effective,
        ) {
            Ok(actual_len) => {
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = actual_len as u64;
                if actual_len > 0 && effective > 0 {
                    let copy_len = actual_len.min(effective);
                    pack_inline(reply, 1, buf.as_ptr(), copy_len);
                }
                (*reply).length = 1 + ((actual_len.min(effective) as u64) + 7) / 8;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

unsafe fn dispatch_removexattr(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_ctx = match fd_to_data_ctx(state, cli_handle, fd) {
            Some(ctx) => ctx,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let name_len = (*msg).regs[1] as usize;
        if name_len == 0 || name_len > XATTR_INLINE_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let mut name_buf = [0u8; XATTR_INLINE_MAX];
        if !extract_inline(msg, 2, name_buf.as_mut_ptr(), name_len) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let vnode = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let ops = vnode.ops;
        if ops.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        match ((*ops).data.removexattr)(&data_ctx, name_buf.as_ptr(), name_len as u8) {
            Ok(()) => {
                (*reply).label = TRONA_OK;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

// =========================================================================
// Sysctl dispatch — unchanged logic, no VfsState dependency
// =========================================================================

const SYSCTL_OP_GET: u64 = 0;
const SYSCTL_OP_SET: u64 = 1;

unsafe fn dispatch_sysctl(msg: *const TronaMsg, reply: *mut TronaMsg) {
    // Sysctl logic is self-contained (MIB tree walk, no VFS state).
    // Kept identical to the old implementation.
    unsafe {
        use crate::fs::sysctlfs::tree;
        let op = (*msg).regs[0];
        match op {
            SYSCTL_OP_GET => {
                let path_len = (*msg).regs[1] as usize;
                if path_len == 0 || path_len > 30 * 8 {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                let path_ptr = &(*msg).regs[2] as *const u64 as *const u8;
                let root = &raw const tree::MIB_ROOT;
                let mut current = &*root;
                let mut pos = 0usize;
                let mut leaf: Option<&tree::SysctlLeaf> = None;
                while pos < path_len {
                    let comp_start = pos;
                    while pos < path_len && *path_ptr.add(pos) != b'.' {
                        pos += 1;
                    }
                    let comp =
                        core::slice::from_raw_parts(path_ptr.add(comp_start), pos - comp_start);
                    if pos < path_len {
                        pos += 1;
                    }
                    let is_last = pos >= path_len;
                    if is_last {
                        if let Some(l) = current.find_leaf(comp) {
                            leaf = Some(l);
                            break;
                        }
                    }
                    match current.find_child_node(comp) {
                        Some(child) => current = child,
                        None => {
                            (*reply).label = TRONA_NOT_FOUND;
                            return;
                        }
                    }
                }
                match leaf {
                    Some(l) => {
                        if let Some(read_fn) = l.read_fn {
                            let mut buf = [0u8; 31 * 8];
                            let val_len = read_fn(buf.as_mut_ptr(), 31 * 8);
                            (*reply).label = TRONA_OK;
                            (*reply).regs[0] = val_len as u64;
                            if val_len > 0 {
                                let dst = &raw mut (*reply).regs[1] as *mut u8;
                                core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, val_len);
                            }
                            (*reply).length = 1 + ((val_len as u64) + 7) / 8;
                        } else {
                            (*reply).label = TRONA_NOT_SUPPORTED;
                        }
                    }
                    None => {
                        (*reply).label = TRONA_NOT_FOUND;
                    }
                }
            }
            SYSCTL_OP_SET => {
                let packed = (*msg).regs[1];
                let path_len = (packed >> 32) as usize;
                let value_len = (packed & 0xFFFF_FFFF) as usize;
                let total = path_len + value_len;
                if path_len == 0 || total > 30 * 8 {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                let data_ptr = &(*msg).regs[2] as *const u64 as *const u8;
                let root = &raw const tree::MIB_ROOT;
                let mut current = &*root;
                let mut pos = 0usize;
                let mut leaf: Option<&tree::SysctlLeaf> = None;
                while pos < path_len {
                    let comp_start = pos;
                    while pos < path_len && *data_ptr.add(pos) != b'.' {
                        pos += 1;
                    }
                    let comp =
                        core::slice::from_raw_parts(data_ptr.add(comp_start), pos - comp_start);
                    if pos < path_len {
                        pos += 1;
                    }
                    let is_last = pos >= path_len;
                    if is_last {
                        if let Some(l) = current.find_leaf(comp) {
                            leaf = Some(l);
                            break;
                        }
                    }
                    match current.find_child_node(comp) {
                        Some(child) => current = child,
                        None => {
                            (*reply).label = TRONA_NOT_FOUND;
                            return;
                        }
                    }
                }
                match leaf {
                    Some(l) => {
                        if (l.flags & tree::CTLFLAG_WR) == 0 {
                            (*reply).label = TRONA_INSUFFICIENT_RIGHTS;
                            return;
                        }
                        if let Some(write_fn) = l.write_fn {
                            let value_ptr = data_ptr.add(path_len);
                            let rc = write_fn(value_ptr, value_len);
                            (*reply).label = if rc == 0 {
                                TRONA_OK
                            } else {
                                TRONA_INVALID_ARGUMENT
                            };
                        } else {
                            (*reply).label = TRONA_NOT_SUPPORTED;
                        }
                    }
                    None => {
                        (*reply).label = TRONA_NOT_FOUND;
                    }
                }
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}
