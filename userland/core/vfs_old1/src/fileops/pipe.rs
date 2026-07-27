// SPDX-License-Identifier: GPL-2.0-only
//! Anonymous pipe lifecycle and synchronous inline I/O.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_runtime::core::server_consts::TRONA_NOT_CONNECTED;
use uapi::*;

use crate::owner::VfsState;
use crate::server::types::{ClientHandle, OBJ_PIPE};

const PIPE_INLINE_READ_MAX: usize = 152;
pub(crate) const PIPE_INLINE_WRITE_MAX: usize = 144;

pub(crate) unsafe fn handle_pipe_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let flags = (*msg).regs[0] as u32;
        if (flags & !(O_CLOEXEC | O_NONBLOCK)) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let Some(pipe) = state.alloc_pipe() else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        let Some(read_fd) = state.alloc_pipe_client_slot(
            cli_handle,
            crate::vfs_core::vnode::VnodeHandle::INVALID,
            pipe,
            O_RDONLY | (flags & (O_CLOEXEC | O_NONBLOCK)),
        ) else {
            let _ = state.pipes.release(pipe);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        let Some(write_fd) = state.alloc_pipe_client_slot(
            cli_handle,
            crate::vfs_core::vnode::VnodeHandle::INVALID,
            pipe,
            O_WRONLY | (flags & (O_CLOEXEC | O_NONBLOCK)),
        ) else {
            let _ = state.release_client_slot(cli_handle, read_fd);
            let _ = state.pipes.release(pipe);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 2;
        (*reply).regs[0] = read_fd as u64;
        (*reply).regs[1] = write_fd as u64;
    }
}

pub(crate) unsafe fn handle_pipe_read_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let want_count = core::cmp::min((*msg).regs[1] as usize, PIPE_INLINE_READ_MAX);
        let (kind, pipe_valid, status_flags) = match state.client_open_file(cli_handle, fd) {
            Some(of) => (of.kind, of.pipe.is_valid(), of.status_flags),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return true;
            }
        };
        if kind != OBJ_PIPE || !pipe_valid {
            return false;
        }
        let nonblocking = (status_flags & O_NONBLOCK) != 0;
        match try_pipe_read_to_reply(state, cli_handle, fd, want_count, reply) {
            Ok(true) => true,
            Ok(false) if nonblocking => {
                (*reply).label = TRONA_WOULD_BLOCK;
                (*reply).length = 0;
                true
            }
            Ok(false) => {
                crate::fileops::tty_wait::defer_pipe_read(state, cli_handle, fd, want_count, reply);
                true
            }
            Err(label) => {
                (*reply).label = label;
                (*reply).length = 0;
                true
            }
        }
    }
}

pub(crate) unsafe fn handle_pipe_write_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let want_count = core::cmp::min((*msg).regs[1] as usize, PIPE_INLINE_WRITE_MAX);
        let (kind, pipe_valid, status_flags) = match state.client_open_file(cli_handle, fd) {
            Some(of) => (of.kind, of.pipe.is_valid(), of.status_flags),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return true;
            }
        };
        if kind != OBJ_PIPE || !pipe_valid {
            return false;
        }
        let nonblocking = (status_flags & O_NONBLOCK) != 0;
        let src = &raw const (*msg).regs[2] as *const u8;
        match try_pipe_write_to_reply(state, cli_handle, fd, src, want_count, reply) {
            Ok(true) => true,
            Ok(false) if nonblocking => {
                (*reply).label = TRONA_WOULD_BLOCK;
                (*reply).length = 0;
                true
            }
            Ok(false) => {
                crate::fileops::tty_wait::defer_pipe_write(
                    state, cli_handle, fd, src, want_count, reply,
                );
                true
            }
            Err(label) => {
                (*reply).label = label;
                (*reply).length = 0;
                true
            }
        }
    }
}

pub(crate) unsafe fn try_pipe_read_to_reply(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: usize,
    want_count: usize,
    reply: *mut TronaMsg,
) -> Result<bool, u64> {
    unsafe {
        let Some(of) = state.client_open_file(cli_handle, fd) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        if of.kind != OBJ_PIPE || !of.pipe.is_valid() {
            return Err(TRONA_INVALID_ARGUMENT);
        }
        if (of.status_flags & O_ACCMODE) == O_WRONLY {
            return Err(TRONA_INVALID_OPERATION);
        }
        if want_count == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return Ok(true);
        }

        let available = state.pipe_buffer_len(of.pipe).unwrap_or(0) as usize;
        if available == 0 {
            let (_, write_refs) = state.pipe_refcounts(of.pipe).unwrap_or((0, 0));
            if write_refs == 0 {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
                return Ok(true);
            }
            return Ok(false);
        }

        let actual = core::cmp::min(want_count, available);
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = actual as u64;
        (*reply).length = 1 + ((actual as u64 + 7) / 8);
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        let _ = state.pipe_read(of.pipe, dst, actual);
        Ok(true)
    }
}

pub(crate) unsafe fn try_pipe_write_to_reply(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: usize,
    src: *const u8,
    want_count: usize,
    reply: *mut TronaMsg,
) -> Result<bool, u64> {
    unsafe {
        let Some(of) = state.client_open_file(cli_handle, fd) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        if of.kind != OBJ_PIPE || !of.pipe.is_valid() {
            return Err(TRONA_INVALID_ARGUMENT);
        }
        if (of.status_flags & O_ACCMODE) == O_RDONLY {
            return Err(TRONA_INVALID_OPERATION);
        }
        if want_count == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return Ok(true);
        }

        let (read_refs, _) = state.pipe_refcounts(of.pipe).unwrap_or((0, 0));
        if read_refs == 0 {
            return Err(TRONA_NOT_CONNECTED);
        }

        let free = state.pipe_buffer_free(of.pipe).unwrap_or(0) as usize;
        if free == 0 {
            return Ok(false);
        }

        let actual = core::cmp::min(want_count, free);
        let _ = state.pipe_write(of.pipe, src, actual);
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual as u64;
        Ok(true)
    }
}
