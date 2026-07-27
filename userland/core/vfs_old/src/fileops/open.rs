// SPDX-License-Identifier: GPL-2.0-only
//! Open path resolution and fd allocation — VopMetaOps dispatch.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::types::*;
use trona_protocol::posix::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::fs::devfs::{DevKind, DevfsVnodeData};
use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::owner::pending::{WALK_PATH_MAX, WalkCursor, WalkPolicy};
use crate::owner::resume::{
    Resume,
    fs::{FsResume, NameiTerminal},
};
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::arbitration::{
    ACCESS_READ, ACCESS_WRITE, check_open, install_open, release_open,
};
use crate::vfs_core::namei_async::{NameiWalkOutcome, namei_walk_async};
use crate::vfs_core::vnode::{VT_CHR, VT_DIR, VT_FIFO, VT_REG, VnodeHandle};

use crate::personality::posix::consts::DEV_URANDOM;
use crate::server::open_object::OpenObject;
use crate::server::types::{ClientHandle, MAX_CLIENT_OBJECTS};
use crate::vfs_core::outcome::{Parked, Ready};
use trona_posix::consts::{
    DEV_CONSOLE, DEV_FB0, DEV_NULL, DEV_PTMX, DEV_PTY_SLAVE, DEV_ZERO, TTY_DEV_CONSOLE,
    TTY_DEV_PTS_BASE,
};

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
            trona_runtime::client::caps::init_ep(),
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
        if !procmgr_call1(INIT_GET_SESSION_TTY_BADGE, badge, &raw mut tty_dev) {
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

/// Thin wrapper over [`VfsState::reserve_fd_owned`] kept as a free
/// function for backwards source-level compatibility with existing
/// `crate::fileops::open::reserve_fd_owned(state, cli)` call sites.
#[inline]
pub(crate) fn reserve_fd_owned(state: &mut VfsState, cli_handle: ClientHandle) -> Option<i32> {
    state.reserve_fd_owned(cli_handle)
}

/// Open a resolved vnode — owner-loop version.
///
/// Performs arbitration check, calls MetaOps::open, installs open counters,
/// allocates fd, installs `OpenObject`. No vnode lock (single-owner).
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
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
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
        let skip_vnode_arbitration = vtype == VT_CHR && !vnode_data.is_null() && {
            matches!(
                (*(vnode_data as *const DevfsVnodeData)).kind,
                DevKind::Console | DevKind::Tty | DevKind::PtySlave | DevKind::Ptmx
            )
        };

        // Terminal device nodes are stream endpoints, not regular shared
        // backing objects. `/dev/ptmx` allocates a fresh PTY pair per open,
        // and `/dev/console`, `/dev/tty`, `/dev/pts/N` are session/terminal
        // views whose exclusivity is governed by tty/session state rather than
        // vnode share counters. Applying vnode-level open arbitration here can
        // therefore surface spurious BUSY on perfectly valid console/tty opens.
        if !skip_vnode_arbitration {
            // Arbitration check — no lock needed (single-owner).
            let vnode = match state.vnodes.get(vh) {
                Some(v) => v,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            };
            if let Err(_) = check_open(vnode, access, deny) {
                (*reply).label = TRONA_BUSY;
                return;
            }
        }

        // Snapshot the client pointer before constructing the ctx so we do
        // not hold a conflicting immutable borrow of `state` alongside
        // the mutable borrow held by ctx.
        let cli_ptr = state
            .clients
            .raw_ptr(cli_handle)
            .unwrap_or(core::ptr::null_mut());

        // MetaOps::open — backend-specific resource acquisition.
        if let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) {
            if request.win32_desired_access != 0 {
                if cli_ptr.is_null() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                if let Err(e) = crate::personality::win32::security::check_nt_acl(
                    &mut ctx,
                    request.win32_desired_access,
                    cli_ptr as *const ClientState,
                ) {
                    (*reply).label = e.to_trona();
                    return;
                }
            }
            let ops = (*ctx.vnode).ops;
            if !ops.is_null() {
                match ((*ops).meta.open)(&mut ctx, request.backend_open_flags) {
                    Ok(Ready(())) => {}
                    Ok(Parked(_)) => {
                        (*reply).label = TRONA_BUSY;
                        return;
                    }
                    Err(e) => {
                        (*reply).label = e.to_trona();
                        return;
                    }
                }
            }

            if vtype == VT_REG && request.truncate_existing && request.mutating_data {
                if !ops.is_null() {
                    let _ = ((*ops).meta.truncate)(&mut ctx, 0);
                }
            }
        }

        // Commit arbitration counters.
        if !skip_vnode_arbitration {
            let vnode = match state.vnodes.get_mut(vh) {
                Some(v) => v,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            };
            install_open(vnode, access, deny);
        }

        // Allocate fd.
        let fd = match reserve_fd_owned(state, cli_handle) {
            Some(fd) => fd,
            None => {
                // Rollback: release arbitration.
                if !skip_vnode_arbitration {
                    if let Some(vnode) = state.vnodes.get_mut(vh) {
                        release_open(vnode, access, deny);
                    }
                }
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let vnode_id = state.vnodes.get(vh).map(|v| v.id).unwrap_or(0);
        let cloexec: u8 = if request.cloexec { 1 } else { 0 };
        let mut value = OpenObject::zeroed();
        value.rights = object_rights_from_access(access);
        value.offset = 0;
        value.dir_cursor = 0;
        value.flags = request.object_flags;
        value.held_access = access;
        value.held_deny = deny;
        value.append_on_write = if request.append_on_write { 1 } else { 0 };
        value.nonblocking = if request.nonblocking { 1 } else { 0 };
        value.delete_on_close = if request.delete_on_close { 1 } else { 0 };

        match vtype {
            VT_DIR => {
                value.set_directory(vh, vnode_id as u32);
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
                                posix_ttysrv_ep(),
                                &raw const treq,
                                &raw mut treply,
                            );
                            if err != 0 || treply.label != TRONA_OK {
                                trona_runtime::uwarn!(|_lb| {
                                    _lb.str(b"[VFS] ptmx alloc failed ipc_err=");
                                    _lb.hex(err as u64);
                                    _lb.str(b" label=");
                                    _lb.hex(treply.label);
                                    _lb.str(b" ep=");
                                    _lb.dec(posix_ttysrv_ep());
                                    _lb.str(b"\n");
                                });
                                state.slot_release(cli_handle, fd as usize);
                                if !skip_vnode_arbitration {
                                    if let Some(vn) = state.vnodes.get_mut(vh) {
                                        release_open(vn, access, deny);
                                    }
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
                        state.slot_release(cli_handle, fd as usize);
                        if !skip_vnode_arbitration {
                            if let Some(vn) = state.vnodes.get_mut(vh) {
                                release_open(vn, access, deny);
                            }
                        }
                        (*reply).label = TRONA_INVALID_OPERATION;
                        return;
                    };
                    value.set_device(vh, vnode_id as u32, device.dev_type, device.pty_id);
                }
            }
            VT_FIFO => {
                let pipe_handle = crate::fileops::pipe::fifo_pipe_from_vnode(state, vh);
                if !pipe_handle.is_valid() {
                    state.slot_release(cli_handle, fd as usize);
                    if let Some(vn) = state.vnodes.get_mut(vh) {
                        release_open(vn, access, deny);
                    }
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                value.set_fifo_pipe(pipe_handle, vh, vnode_id as u32);
            }
            _ => {
                value.set_file(vh, vnode_id as u32);
            }
        }

        if state
            .slot_install(cli_handle, fd as usize, value, cloexec)
            .is_none()
        {
            state.slot_release(cli_handle, fd as usize);
            if !skip_vnode_arbitration {
                if let Some(vn) = state.vnodes.get_mut(vh) {
                    release_open(vn, access, deny);
                }
            }
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
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
) -> bool {
    unsafe {
        let mut abs_path = [0u8; MAX_PATH_LEN];

        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let Some((path_ptr, path_len)) =
            normalize_path_owned(state, cli_handle, path, raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        let root_vh = crate::owner::dispatch::root_vnode_for(state, cli_handle);
        open_path_from_start_owned(
            state, cli_handle, root_vh, root_vh, path_ptr, path_len, request, reply,
        )
    }
}

pub(crate) unsafe fn open_path_from_start_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    start_vh: VnodeHandle,
    root_vh: VnodeHandle,
    path: *const u8,
    path_len: u8,
    request: &OpenRequest,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        // Shared async open trunk for plain `open` and POSIX `openat`.
        // Callers choose only the namespace anchors and open policy;
        // the walker and terminal open/create replay remain centralized.
        handle_open_owned_async(
            state, cli_handle, start_vh, root_vh, path, path_len, *request, reply,
        )
    }
}

fn build_open_walk_policy(
    path_ptr: *const u8,
    path_len: u8,
    request: OpenRequest,
) -> Option<WalkPolicy> {
    if !request.create_if_missing {
        return Some(WalkPolicy::Continue);
    }

    let mut len = path_len as usize;
    while len > 1 {
        unsafe {
            if *path_ptr.add(len - 1) != b'/' {
                break;
            }
        }
        len -= 1;
    }
    if len == 1 {
        // `open("/", O_CREAT)` still resolves the existing root vnode.
        unsafe {
            if !path_ptr.is_null() && *path_ptr == b'/' {
                return Some(WalkPolicy::Continue);
            }
        }
    }

    let mut last_sep = None;
    for i in 0..len {
        unsafe {
            if *path_ptr.add(i) == b'/' {
                last_sep = Some(i);
            }
        }
    }
    let start = last_sep.map_or(0usize, |idx| idx.saturating_add(1));
    if start >= len {
        return None;
    }
    let final_len = len - start;
    if final_len == 0 || final_len > crate::owner::pending::WALK_NAME_MAX {
        return None;
    }

    let mut final_name = [0u8; crate::owner::pending::WALK_NAME_MAX];
    for i in 0..final_len {
        unsafe {
            final_name[i] = *path_ptr.add(start + i);
        }
    }

    Some(WalkPolicy::CreateOrOpen {
        final_name,
        final_name_len: final_len as u8,
        final_missing: false,
    })
}

unsafe fn complete_open_walk_result(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    result: &crate::vfs_core::namei_async::NameiAsyncResult,
    request: OpenRequest,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if result.vp.is_valid() {
            if request.create_if_missing && request.fail_if_exists {
                (*reply).label = TRONA_ALREADY_EXISTS;
                return false;
            }
            open_vnode_owned(state, cli_handle, result.vp, &request, reply);
            return false;
        }

        if !request.create_if_missing || !result.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        let parent_vkey = state
            .vnodes
            .get(result.dvp)
            .map(|v| v.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);
        let Some(mut ctx) =
            crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, result.dvp)
        else {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            (*reply).label = TRONA_NOT_SUPPORTED;
            return false;
        }
        match ((*ops).meta.create)(
            &mut ctx,
            result.last_name.as_ptr(),
            result.last_name_len,
            request.create_mode,
            &raw const cred,
        ) {
            Ok(Ready(new_vh)) => {
                open_vnode_owned(state, cli_handle, new_vh, &request, reply);
                false
            }
            Ok(Parked(handle)) => {
                crate::personality::posix::at_ops::at_mutate::finalise_with_resume(
                    state,
                    cli_handle,
                    handle,
                    reply,
                    Resume::Fs(FsResume::FinalOpChild {
                        client: cli_handle,
                        parent_vkey,
                        kind_hint: crate::owner::resume::fs::FinalOpKind::Create,
                        open_request: Some(request),
                        creds_uid: cred.euid,
                        creds_gid: cred.egid,
                    }),
                )
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

pub(crate) unsafe fn resume_open_walk_result(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    result: &crate::vfs_core::namei_async::NameiAsyncResult,
    request: OpenRequest,
    reply_slot: u64,
) {
    unsafe {
        if reply_slot == 0 {
            return;
        }

        let mut out = TronaMsg::zeroed();
        if result.vp.is_valid() {
            if request.create_if_missing && request.fail_if_exists {
                out.label = TRONA_ALREADY_EXISTS;
                state.send_saved_reply(reply_slot, &raw const out);
                return;
            }
            open_vnode_owned(state, cli_handle, result.vp, &request, &raw mut out);
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        if !request.create_if_missing || !result.dvp.is_valid() {
            out.label = TRONA_NOT_FOUND;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }

        let parent_vkey = state
            .vnodes
            .get(result.dvp)
            .map(|v| v.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        let cred = crate::owner::dispatch::client_cred(state, cli_handle);
        let Some(mut ctx) =
            crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, result.dvp)
        else {
            out.label = TRONA_NOT_FOUND;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            out.label = TRONA_NOT_SUPPORTED;
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        match ((*ops).meta.create)(
            &mut ctx,
            result.last_name.as_ptr(),
            result.last_name_len,
            request.create_mode,
            &raw const cred,
        ) {
            Ok(Ready(new_vh)) => {
                open_vnode_owned(state, cli_handle, new_vh, &request, &raw mut out);
                state.send_saved_reply(reply_slot, &raw const out);
            }
            Ok(Parked(handle)) => {
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    Resume::Fs(FsResume::FinalOpChild {
                        client: cli_handle,
                        parent_vkey,
                        kind_hint: crate::owner::resume::fs::FinalOpKind::Create,
                        open_request: Some(request),
                        creds_uid: cred.euid,
                        creds_gid: cred.egid,
                    }),
                ) {
                    out.label = TRONA_BUSY;
                    state.send_saved_reply(reply_slot, &raw const out);
                }
            }
            Err(e) => {
                out.label = e.to_trona();
                state.send_saved_reply(reply_slot, &raw const out);
            }
        }
    }
}

unsafe fn handle_open_owned_async(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    start_vh: VnodeHandle,
    root_vh: VnodeHandle,
    path_ptr: *const u8,
    path_len: u8,
    request: OpenRequest,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if (path_len as usize) > WALK_PATH_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let Some(root_vkey) = state.vnodes.get(root_vh).map(|v| v.vnode_key()) else {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        };
        state.install_resolve_cache(root_vkey, root_vh);
        let initial_vh = if !path_ptr.is_null() && *path_ptr == b'/' {
            root_vh
        } else {
            start_vh
        };
        let Some(start_vkey) = state.vnodes.get(initial_vh).map(|v| v.vnode_key()) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        state.install_resolve_cache(start_vkey, initial_vh);

        let mut remaining_path = [0u8; WALK_PATH_MAX];
        for i in 0..(path_len as usize) {
            remaining_path[i] = *path_ptr.add(i);
        }

        let policy = match build_open_walk_policy(path_ptr, path_len, request) {
            Some(policy) => policy,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let mut namei_flags = crate::vfs_core::namei_common::NAMEI_FOLLOW;
        if (path_len as usize) > 1 {
            unsafe {
                if *path_ptr.add((path_len as usize) - 1) == b'/' {
                    namei_flags |= crate::vfs_core::namei_common::NAMEI_DIRECTORY;
                }
            }
        }

        let mut cursor = WalkCursor {
            cwd_vkey: start_vkey,
            root_vkey,
            remaining_path,
            remaining_len: path_len as u16,
            follow_depth: 0,
            cred: crate::owner::dispatch::client_cred(state, cli_handle),
            flags: namei_flags,
            policy,
        };

        match namei_walk_async(state, &mut cursor) {
            NameiWalkOutcome::Done(result) => {
                complete_open_walk_result(state, cli_handle, &result, request, reply)
            }
            NameiWalkOutcome::Parked { handle, phase } => {
                // The walker stays backend-neutral. This layer owns
                // the client reply slot and records which terminal
                // action must run once the walk completes.
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    Resume::Fs(FsResume::NameiStep {
                        client: cli_handle,
                        cursor,
                        phase,
                        terminal: NameiTerminal::Open { request },
                    }),
                ) {
                    (*reply).label = err.to_trona();
                    return false;
                }
                true
            }
            NameiWalkOutcome::Error(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// POSIX open IPC wrapper.
pub(crate) unsafe fn handle_open_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mode = (*msg).regs[0] as u32;
        let flags = (*msg).regs[1] as u32;
        let raw_len = extract_path(msg, 2, path.as_mut_ptr());
        let request = crate::personality::posix::policy::posix_open_request(flags, mode);
        open_path_owned(state, cli_handle, path.as_ptr(), raw_len, &request, reply)
    }
}
