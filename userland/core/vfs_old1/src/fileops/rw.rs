// SPDX-License-Identifier: GPL-2.0-only
//! Synchronous bootstrap file I/O.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_protocol::posix::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::types::{ClientHandle, OBJ_DIRECTORY, OBJ_FILE, OBJ_SHM};

const INLINE_READ_MAX: usize = 152;
const INLINE_WRITE_MAX: usize = 144;
const INLINE_PWRITE_MAX: usize = 136;

unsafe fn fill_read_reply(
    state: &VfsState,
    cli_handle: ClientHandle,
    vnode: crate::vfs_core::vnode::VnodeHandle,
    offset: u64,
    want_count: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let actual = match crate::fileops::regular::read_into(
            state,
            Some(cli_handle),
            vnode,
            offset,
            &raw mut (*reply).regs[1] as *mut u8,
            core::cmp::min(want_count as usize, INLINE_READ_MAX),
        ) {
            Ok(actual) => actual as u64,
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = actual;
        (*reply).length = 1 + ((actual + 7) / 8);
    }
}

pub(crate) unsafe fn handle_read_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        if crate::fileops::pipe::handle_pipe_read_owned(state, cli_handle, msg, reply) {
            return;
        }
        if crate::fileops::socket::handle_socket_read_owned(state, cli_handle, msg, reply) {
            return;
        }
        if crate::fileops::device::handle_device_read_owned(state, cli_handle, msg, reply) {
            return;
        }
        let fd = (*msg).regs[0] as i32;
        let want_count = (*msg).regs[1];
        if fd < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (vnode, offset, kind, flags) = match state.client_open_file(cli_handle, fd as usize) {
            Some(of) => (of.vnode, of.offset, of.kind, of.status_flags),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        if kind == OBJ_DIRECTORY {
            (*reply).label = TRONA_IS_DIRECTORY;
            (*reply).length = 0;
            return;
        }
        if kind == OBJ_SHM {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if kind != OBJ_FILE {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if (flags & O_ACCMODE) == O_WRONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        // Procfs entries that need a backend RPC are deferred to a
        // worker. Sync path stays in place for pure-state procfs
        // entries (RootMeminfo etc.) and every other backend.
        let backend_kind = state
            .vnodes
            .get(vnode)
            .map(|vn| vn.backend_kind)
            .unwrap_or(0);
        if backend_kind == crate::vfs_core::vnode::VNODE_BACKEND_PROCFS {
            if let Some((kind, pid)) = crate::fs::procfs::proc_read_kind(state, vnode) {
                if crate::fs::procfs::proc_read_needs_deferred(kind) {
                    if crate::fs::procfs::defer_procfs_read(
                        state, cli_handle, fd, vnode, offset, want_count, kind, pid, false, reply,
                    ) {
                        return;
                    }
                }
            }
        }

        fill_read_reply(state, cli_handle, vnode, offset, want_count, reply);
        if (*reply).label != TRONA_OK {
            return;
        }
        if let Some(of) = state.client_open_file_mut(cli_handle, fd as usize) {
            of.offset = of.offset.saturating_add((*reply).regs[0]);
        }
    }
}

pub(crate) unsafe fn handle_pread_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let want_count = (*msg).regs[1];
        let offset = (*msg).regs[2] as i64;
        if fd < 0 || offset < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (vnode, kind, flags) = match state.client_open_file(cli_handle, fd as usize) {
            Some(of) => (of.vnode, of.kind, of.status_flags),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        if kind == OBJ_DIRECTORY {
            (*reply).label = TRONA_IS_DIRECTORY;
            (*reply).length = 0;
            return;
        }
        if kind == OBJ_SHM {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if kind != OBJ_FILE {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if (flags & O_ACCMODE) == O_WRONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        // pread procfs deferred branch (no fd-offset bump on completion).
        let backend_kind = state
            .vnodes
            .get(vnode)
            .map(|vn| vn.backend_kind)
            .unwrap_or(0);
        if backend_kind == crate::vfs_core::vnode::VNODE_BACKEND_PROCFS {
            if let Some((kind, pid)) = crate::fs::procfs::proc_read_kind(state, vnode) {
                if crate::fs::procfs::proc_read_needs_deferred(kind) {
                    if crate::fs::procfs::defer_procfs_read(
                        state,
                        cli_handle,
                        fd,
                        vnode,
                        offset as u64,
                        want_count,
                        kind,
                        pid,
                        true,
                        reply,
                    ) {
                        return;
                    }
                }
            }
        }

        fill_read_reply(state, cli_handle, vnode, offset as u64, want_count, reply);
    }
}

pub(crate) unsafe fn handle_write_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        if crate::fileops::pipe::handle_pipe_write_owned(state, cli_handle, msg, reply) {
            return;
        }
        if crate::fileops::socket::handle_socket_write_owned(state, cli_handle, msg, reply) {
            return;
        }
        if crate::fileops::device::handle_device_write_owned(state, cli_handle, msg, reply) {
            return;
        }
        let fd = (*msg).regs[0] as i32;
        let want_count = core::cmp::min((*msg).regs[1] as usize, INLINE_WRITE_MAX);
        if fd < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (vnode, kind, flags, offset) = match state.client_open_file(cli_handle, fd as usize) {
            Some(of) => (of.vnode, of.kind, of.status_flags, of.offset),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        if kind == OBJ_DIRECTORY {
            (*reply).label = TRONA_IS_DIRECTORY;
            (*reply).length = 0;
            return;
        }
        if kind == OBJ_SHM {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if kind != OBJ_FILE {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if (flags & O_ACCMODE) == O_RDONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        let write_offset = if (flags & O_APPEND) != 0 {
            match state.vnodes.get(vnode) {
                Some(vn) => vn.size,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                }
            }
        } else {
            offset
        };
        let src = &raw const (*msg).regs[2] as *const u8;
        let actual = match crate::fileops::regular::write_from(
            state,
            vnode,
            write_offset,
            src,
            want_count,
        ) {
            Ok(actual) => actual,
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        if let Some(of) = state.client_open_file_mut(cli_handle, fd as usize) {
            of.offset = write_offset.saturating_add(actual);
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual;
    }
}

pub(crate) unsafe fn handle_pwrite_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let want_count = core::cmp::min((*msg).regs[1] as usize, INLINE_PWRITE_MAX);
        let offset = (*msg).regs[2] as i64;
        if fd < 0 || offset < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (vnode, kind, flags) = match state.client_open_file(cli_handle, fd as usize) {
            Some(of) => (of.vnode, of.kind, of.status_flags),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        if kind == OBJ_DIRECTORY {
            (*reply).label = TRONA_IS_DIRECTORY;
            (*reply).length = 0;
            return;
        }
        if kind == OBJ_SHM {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if kind != OBJ_FILE {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if (flags & O_ACCMODE) == O_RDONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        let src = &raw const (*msg).regs[3] as *const u8;
        let actual =
            match crate::fileops::regular::write_from(state, vnode, offset as u64, src, want_count)
            {
                Ok(actual) => actual,
                Err(err) => {
                    (*reply).label = err;
                    (*reply).length = 0;
                    return;
                }
            };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual;
    }
}

pub(crate) unsafe fn handle_lseek_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let offset = (*msg).regs[1] as i64;
        let whence = (*msg).regs[2];
        if fd < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (kind, vnode, current_offset) = match state.client_open_file(cli_handle, fd as usize) {
            Some(of) => (of.kind, of.vnode, of.offset),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        if kind == OBJ_SHM {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        if kind != OBJ_FILE {
            (*reply).label = if kind == OBJ_DIRECTORY {
                TRONA_IS_DIRECTORY
            } else {
                TRONA_NOT_SUPPORTED
            };
            (*reply).length = 0;
            return;
        }
        let Some(vn) = state.vnodes.get(vnode) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        let base = match whence {
            SEEK_SET => 0i64,
            SEEK_CUR => current_offset as i64,
            SEEK_END => vn.size as i64,
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        let Some(new_offset) = base.checked_add(offset) else {
            (*reply).label = TRONA_OUT_OF_RANGE;
            (*reply).length = 0;
            return;
        };
        if new_offset < 0 {
            (*reply).label = TRONA_OUT_OF_RANGE;
            (*reply).length = 0;
            return;
        }

        if let Some(of) = state.client_open_file_mut(cli_handle, fd as usize) {
            of.offset = new_offset as u64;
        } else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_offset as u64;
    }
}

pub(crate) unsafe fn handle_ftruncate_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let new_size = (*msg).regs[1];
        if fd < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (vnode, kind, flags) = match state.client_open_file(cli_handle, fd as usize) {
            Some(of) => (of.vnode, of.kind, of.status_flags),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        if kind == OBJ_DIRECTORY {
            (*reply).label = TRONA_IS_DIRECTORY;
            (*reply).length = 0;
            return;
        }
        if kind == OBJ_SHM {
            let new_pages = if new_size == 0 {
                0
            } else {
                ((new_size + 4095) / 4096) as u32
            };
            let shm_handle = match state.client_open_file(cli_handle, fd as usize) {
                Some(of) => of.shm,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                }
            };
            let shm_id = match state.shm_state(shm_handle) {
                Some(shm) => shm.id,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                }
            };
            let current_pages = state
                .shm_state(shm_handle)
                .map(|shm| shm.num_pages)
                .unwrap_or(0);
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = if new_pages == 0 {
                MM_SHM_DESTROY
            } else if current_pages == 0 {
                MM_SHM_CREATE
            } else {
                MM_SHM_RESIZE
            };
            mm_msg.length = if new_pages == 0 { 1 } else { 2 };
            mm_msg.regs[0] = shm_id;
            mm_msg.regs[1] = new_pages as u64;
            let err = trona_kernel::ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0
                || (mm_reply.label != TRONA_OK
                    && !(new_pages == 0 && mm_reply.label == TRONA_NOT_FOUND))
            {
                (*reply).label = if err != 0 {
                    TRONA_INVALID_OPERATION
                } else {
                    mm_reply.label
                };
                (*reply).length = 0;
                return;
            }
            if let Some(shm) = state.shm_state_mut(shm_handle) {
                shm.num_pages = new_pages;
            }
            if let Some(vn) = state.vnodes.get_mut(vnode) {
                vn.size = new_size;
                vn.mtime_ns = vn.mtime_ns.saturating_add(1);
            } else {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
            return;
        }
        if kind != OBJ_FILE {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if (flags & O_ACCMODE) == O_RDONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        match crate::vfs_core::vops::truncate(state, vnode, new_size) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => (*reply).label = TRONA_OK,
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                if !crate::owner::continuation::populate_alloced_op_for_caller(
                    state, op_id, cli_handle, reply,
                ) {
                    crate::owner::pending_ops::free(op_id);
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                }
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}
