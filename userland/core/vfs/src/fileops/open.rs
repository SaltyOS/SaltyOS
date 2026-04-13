// SPDX-License-Identifier: GPL-2.0-only
//! Open path resolution and fd allocation — VopMetaOps dispatch.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::owner::VfsState;
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::ipc_ctx;
use crate::fs::devfs::{DevKind, DevfsVnodeData};
use crate::vfs_core::arbitration::{
    check_open, install_open, release_open, ACCESS_READ, ACCESS_WRITE,
};
use crate::vfs_core::vnode::{VnodeHandle, VT_CHR, VT_DIR, VT_FIFO, VT_REG};

use crate::server::types::{ClientHandle, ObjectSlot, MAX_CLIENT_OBJECTS};
use trona::consts::posix::{
    DEV_CONSOLE, DEV_FB0, DEV_NULL, DEV_PTMX, DEV_PTY_SLAVE, DEV_ZERO,
    TTY_DEV_CONSOLE, TTY_DEV_PTS_BASE,
};
use crate::personality::posix::consts::DEV_URANDOM;

fn object_rights_from_access(access: u8) -> u8 {
    let mut rights = 0u8;
    if (access & ACCESS_READ) != 0 {
        rights |= OBJ_RIGHT_READ;
    }
    if (access & ACCESS_WRITE) != 0 {
        rights |= OBJ_RIGHT_WRITE;
    }
    rights
}

unsafe fn procmgr_call1(label: u64, arg0: u64, out0: *mut u64) -> bool {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = label;
        msg.length = 1;
        msg.regs[0] = arg0;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }
        if !out0.is_null() {
            *out0 = reply.regs[0];
        }
        true
    }
}

unsafe fn controlling_tty_device(state: &VfsState, cli_handle: ClientHandle) -> Option<DeviceInfo> {
    unsafe {
        let badge = state.clients.get(cli_handle)?.badge;
        let mut tty_dev = 0u64;
        if !procmgr_call1(PM_GET_SESSION_TTY_BADGE, badge, &raw mut tty_dev) {
            return None;
        }
        if tty_dev == TTY_DEV_CONSOLE {
            return Some(DeviceInfo {
                dev_type: DEV_CONSOLE,
                pty_id: 0,
            });
        }
        if tty_dev >= TTY_DEV_PTS_BASE {
            let pty_id = tty_dev - TTY_DEV_PTS_BASE;
            if pty_id <= u32::MAX as u64 {
                return Some(DeviceInfo {
                    dev_type: DEV_PTY_SLAVE,
                    pty_id: pty_id as u32,
                });
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OpenRequest {
    pub(crate) backend_open_flags: u32,
    pub(crate) object_flags: u32,
    pub(crate) create_mode: u32,
    pub(crate) win32_desired_access: u32,
    pub(crate) access: u8,
    pub(crate) deny: u8,
    pub(crate) append_on_write: bool,
    pub(crate) nonblocking: bool,
    pub(crate) create_if_missing: bool,
    pub(crate) fail_if_exists: bool,
    pub(crate) truncate_existing: bool,
    pub(crate) mutating_data: bool,
    pub(crate) cloexec: bool,
    pub(crate) delete_on_close: bool,
}

/// Normalize a user path using VfsState client cwd (owner-loop version).
///
/// Equivalent to `normalize_path_for_client` but reads cwd from
/// `Arena<ClientState>` instead of the old raw-pointer pool.
pub(crate) unsafe fn normalize_path_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    in_path: *const u8,
    in_len: u8,
    tmp_abs: *mut u8,
) -> Option<(*const u8, u8)> {
    unsafe {
        if in_len == 0 {
            return None;
        }
        let mut raw_abs = [0u8; MAX_PATH_LEN];
        let raw_len: usize;

        if *in_path == b'/' {
            raw_len = in_len as usize;
            if raw_len == 0 || raw_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..raw_len {
                raw_abs[i] = *in_path.add(i);
            }
        } else {
            let cli = state.clients.get(cli_handle)?;

            let mut cwd_len: usize = 0;
            while cwd_len < 128 && cli.cwd[cwd_len] != 0 {
                cwd_len += 1;
            }
            if cwd_len == 0 {
                cwd_len = 1;
            }

            let cwd_is_root = cwd_len == 1 && cli.cwd[0] == b'/';
            let rel_len = in_len as usize;
            raw_len = if cwd_is_root {
                1 + rel_len
            } else {
                cwd_len + 1 + rel_len
            };
            if raw_len > MAX_PATH_LEN {
                return None;
            }

            if cwd_is_root {
                raw_abs[0] = b'/';
                for i in 0..rel_len {
                    raw_abs[1 + i] = *in_path.add(i);
                }
            } else {
                for i in 0..cwd_len {
                    raw_abs[i] = cli.cwd[i];
                }
                raw_abs[cwd_len] = b'/';
                for i in 0..rel_len {
                    raw_abs[cwd_len + 1 + i] = *in_path.add(i);
                }
            }
        }

        // Canonicalize — identical logic to normalize_path_for_client.
        let mut out_len: usize = 1;
        *tmp_abs = b'/';
        let mut comp_starts = [0usize; MAX_PATH_LEN / 2];
        let mut depth: usize = 0;

        let mut pos: usize = 0;
        if raw_len > 0 && raw_abs[0] == b'/' {
            pos = 1;
        }

        while pos < raw_len {
            while pos < raw_len && raw_abs[pos] == b'/' {
                pos += 1;
            }
            if pos >= raw_len {
                break;
            }

            let start = pos;
            while pos < raw_len && raw_abs[pos] != b'/' {
                pos += 1;
            }
            let seg_len = pos - start;
            if seg_len == 0 {
                continue;
            }

            if seg_len == 1 && raw_abs[start] == b'.' {
                continue;
            }
            if seg_len == 2 && raw_abs[start] == b'.' && raw_abs[start + 1] == b'.' {
                if depth > 0 {
                    depth -= 1;
                    out_len = comp_starts[depth];
                    if out_len == 0 {
                        out_len = 1;
                        *tmp_abs = b'/';
                    }
                }
                continue;
            }

            if depth >= comp_starts.len() {
                return None;
            }
            if out_len > 1 {
                if out_len >= MAX_PATH_LEN {
                    return None;
                }
                *tmp_abs.add(out_len) = b'/';
                out_len += 1;
            }
            comp_starts[depth] = out_len;
            depth += 1;

            if out_len + seg_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..seg_len {
                *tmp_abs.add(out_len + i) = raw_abs[start + i];
            }
            out_len += seg_len;
        }

        if out_len == 0 || out_len > u8::MAX as usize {
            return None;
        }
        Some((tmp_abs as *const u8, out_len as u8))
    }
}

/// Find a free fd slot in the client's object table.
pub(crate) fn reserve_fd_owned(state: &mut VfsState, cli_handle: ClientHandle) -> Option<i32> {
    let cli = state.clients.get_mut(cli_handle)?;
    for i in 0..MAX_CLIENT_OBJECTS {
        if cli.objects[i].is_free() {
            cli.objects[i].reserve();
            cli.obj_count += 1;
            return Some(i as i32);
        }
    }
    None
}

/// Open a resolved vnode — owner-loop version.
///
/// Performs arbitration check, calls MetaOps::open, installs open counters,
/// allocates fd, fills ObjectSlot. No vnode lock (single-owner).
pub(crate) unsafe fn open_vnode_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    vh: VnodeHandle,
    request: &OpenRequest,
    reply: *mut TronaMsg,
) {
    unsafe {
        let (vtype, vnode_data) = {
            let vnode = match state.vnodes.get(vh) {
                Some(v) => v,
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            };
            (vnode.vtype, vnode.data)
        };

        // Directories cannot be opened for write.
        if vtype == VT_DIR {
            if request.mutating_data {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
        }

        let access = request.access;
        let deny = request.deny;

        // Arbitration check — no lock needed (single-owner).
        {
            let vnode = match state.vnodes.get(vh) {
                Some(v) => v,
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            };
            if let Err(_) = check_open(vnode, access, deny) {
                (*reply).label = TRONA_BUSY;
                return;
            }
        }

        // MetaOps::open — backend-specific resource acquisition.
        if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vh) {
            if request.win32_desired_access != 0 {
                let cli_ptr = state.clients.raw_ptr(cli_handle).unwrap_or(core::ptr::null_mut());
                if cli_ptr.is_null() {
                    crate::vfs_core::mount_ctl::clear_trampolines();
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                if let Err(e) = crate::personality::win32::security::check_nt_acl(
                    &ctx,
                    request.win32_desired_access,
                    cli_ptr as *const ClientState,
                ) {
                    crate::vfs_core::mount_ctl::clear_trampolines();
                    (*reply).label = e.to_trona();
                    return;
                }
            }
            let ops = (*ctx.vnode).ops;
            if !ops.is_null() {
                if let Err(e) = ((*ops).meta.open)(&ctx, request.backend_open_flags) {
                    crate::vfs_core::mount_ctl::clear_trampolines();
                    (*reply).label = e.to_trona();
                    return;
                }
            }

            if vtype == VT_REG && request.truncate_existing && request.mutating_data {
                if !ops.is_null() {
                    let _ = ((*ops).meta.truncate)(&ctx, 0);
                }
            }

            crate::vfs_core::mount_ctl::clear_trampolines();
        }

        // Commit arbitration counters.
        {
            let vnode = match state.vnodes.get_mut(vh) {
                Some(v) => v,
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
            };
            install_open(vnode, access, deny);
        }

        // Allocate fd.
        let fd = match reserve_fd_owned(state, cli_handle) {
            Some(fd) => fd,
            None => {
                // Rollback: release arbitration.
                if let Some(vnode) = state.vnodes.get_mut(vh) {
                    release_open(vnode, access, deny);
                }
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let vnode_id = state.vnodes.get(vh).map(|v| v.id).unwrap_or(0);
        let mut slot_value = ObjectSlot::zeroed();
        slot_value.rights = object_rights_from_access(access);
        slot_value.offset = 0;
        slot_value.dir_cursor = 0;
        slot_value.flags = request.object_flags;
        slot_value.held_access = access;
        slot_value.held_deny = deny;
        slot_value.cloexec = if request.cloexec { 1 } else { 0 };
        slot_value.append_on_write = if request.append_on_write { 1 } else { 0 };
        slot_value.nonblocking = if request.nonblocking { 1 } else { 0 };
        slot_value.delete_on_close = if request.delete_on_close { 1 } else { 0 };

        match vtype {
            VT_DIR => {
                slot_value.set_directory(vh, vnode_id as u32);
            }
            VT_CHR => {
                let vd = vnode_data as *const DevfsVnodeData;
                if !vd.is_null() {
                    let kind = (*vd).kind;
                    let device = match kind {
                        DevKind::Console => Some(DeviceInfo {
                            dev_type: DEV_CONSOLE,
                            pty_id: 0,
                        }),
                        DevKind::Null => Some(DeviceInfo {
                            dev_type: DEV_NULL,
                            pty_id: 0,
                        }),
                        DevKind::Zero => Some(DeviceInfo {
                            dev_type: DEV_ZERO,
                            pty_id: 0,
                        }),
                        DevKind::Fb0 => Some(DeviceInfo {
                            dev_type: DEV_FB0,
                            pty_id: 0,
                        }),
                        DevKind::Urandom => Some(DeviceInfo {
                            dev_type: DEV_URANDOM,
                            pty_id: 0,
                        }),
                        DevKind::PtySlave => Some(DeviceInfo {
                            dev_type: DEV_PTY_SLAVE,
                            pty_id: (*vd).sub_id,
                        }),
                        DevKind::Ptmx => {
                            let mut treq = TronaMsg::zeroed();
                            let mut treply = TronaMsg::zeroed();
                            treq.label = POSIX_TTYSRV_PTY_ALLOC;
                            let err = ipc::call_ctx(
                                ipc_ctx(),
                                VFS_CAP_POSIX_TTYSRV_EP,
                                &raw const treq,
                                &raw mut treply,
                            );
                            if err != 0 || treply.label != TRONA_OK {
                                if let Some(cli) = state.clients.get_mut(cli_handle) {
                                    cli.objects[fd as usize].clear();
                                    cli.obj_count = cli.obj_count.saturating_sub(1);
                                }
                                if let Some(vn) = state.vnodes.get_mut(vh) {
                                    release_open(vn, access, deny);
                                }
                                (*reply).label = TRONA_BUSY;
                                return;
                            }
                            Some(DeviceInfo {
                                dev_type: DEV_PTMX,
                                pty_id: treply.regs[0] as u32,
                            })
                        }
                        DevKind::Tty => controlling_tty_device(state, cli_handle),
                        DevKind::PtsDir => None,
                    };
                    let Some(device) = device else {
                        if let Some(cli) = state.clients.get_mut(cli_handle) {
                            cli.objects[fd as usize].clear();
                            cli.obj_count = cli.obj_count.saturating_sub(1);
                        }
                        if let Some(vn) = state.vnodes.get_mut(vh) {
                            release_open(vn, access, deny);
                        }
                        (*reply).label = TRONA_INVALID_OPERATION;
                        return;
                    };
                    slot_value.set_device(vh, vnode_id as u32, device.dev_type, device.pty_id);
                }
            }
            VT_FIFO => {
                let pipe_handle = crate::fileops::pipe::fifo_pipe_from_vnode(state, vh);
                if !pipe_handle.is_valid() {
                    if let Some(cli) = state.clients.get_mut(cli_handle) {
                        cli.objects[fd as usize].clear();
                        cli.obj_count = cli.obj_count.saturating_sub(1);
                    }
                    if let Some(vn) = state.vnodes.get_mut(vh) {
                        release_open(vn, access, deny);
                    }
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                slot_value.set_fifo_pipe(pipe_handle, vh, vnode_id as u32);
            }
            _ => {
                slot_value.set_file(vh, vnode_id as u32);
            }
        }

        if let Some(cli) = state.clients.get_mut(cli_handle) {
            cli.objects[fd as usize] = slot_value;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

pub(crate) unsafe fn open_path_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    path: *const u8,
    raw_len: u8,
    request: &OpenRequest,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut abs_path = [0u8; MAX_PATH_LEN];

        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some((path_ptr, path_len)) =
            normalize_path_owned(state, cli_handle, path, raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let root_vh = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        let cwd_vh = crate::owner::dispatch::cwd_vnode_for(state, cli_handle);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);

        use crate::vfs_core::namei_common::*;

        if request.create_if_missing {
            let args = NameiArgs {
                start: cwd_vh,
                root: root_vh,
                path: path_ptr,
                path_len: path_len as u16,
                flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
                cred,
            };

            let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
                Ok(r) => r,
                Err(e) => {
                    (*reply).label = e.to_trona();
                    return;
                }
            };

            if result.vp.is_valid() {
                if request.fail_if_exists {
                    (*reply).label = TRONA_ALREADY_EXISTS;
                    return;
                }
                open_vnode_owned(state, cli_handle, result.vp, request, reply);
            } else {
                if !result.dvp.is_valid() {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
                if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, result.dvp) {
                    let ops = (*ctx.vnode).ops;
                    if ops.is_null() {
                        crate::vfs_core::mount_ctl::clear_trampolines();
                        (*reply).label = TRONA_NOT_SUPPORTED;
                        return;
                    }
                    match ((*ops).meta.create)(
                        &ctx,
                        result.last_name,
                        result.last_name_len,
                        request.create_mode,
                        &raw const cred,
                    ) {
                        Ok(new_vh) => {
                            crate::vfs_core::mount_ctl::clear_trampolines();
                            open_vnode_owned(state, cli_handle, new_vh, request, reply);
                        }
                        Err(e) => {
                            crate::vfs_core::mount_ctl::clear_trampolines();
                            (*reply).label = e.to_trona();
                        }
                    }
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                }
            }
        } else {
            let args = NameiArgs {
                start: cwd_vh,
                root: root_vh,
                path: path_ptr,
                path_len: path_len as u16,
                flags: NAMEI_FOLLOW,
                cred,
            };

            let result = match crate::owner::dispatch::resolve_namei(state, cli_handle, &args) {
                Ok(r) => r,
                Err(e) => {
                    (*reply).label = e.to_trona();
                    return;
                }
            };

            if !result.vp.is_valid() {
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }

            open_vnode_owned(state, cli_handle, result.vp, request, reply);
        }
    }
}

/// POSIX open IPC wrapper.
pub(crate) unsafe fn handle_open_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mode = (*msg).regs[0] as u32;
        let flags = (*msg).regs[1] as u32;
        let raw_len = extract_path(msg, 2, path.as_mut_ptr());
        let request = crate::personality::posix::policy::posix_open_request(flags, mode);
        open_path_owned(state, cli_handle, path.as_ptr(), raw_len, &request, reply);
    }
}
