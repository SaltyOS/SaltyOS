// SPDX-License-Identifier: GPL-2.0-only
//! POSIX descriptor-control operations on top of shared open-file descriptions.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::types::{ClientHandle, MAX_CLIENT_OBJECTS, PERS_POSIX, PERS_WIN32};

fn next_free_fd(state: &VfsState, cli_handle: ClientHandle, min_fd: usize) -> Option<usize> {
    let client = state.clients.get(cli_handle)?;
    for fd in min_fd..MAX_CLIENT_OBJECTS {
        if client.slots[fd].active == 0 {
            return Some(fd);
        }
    }
    None
}

fn slot_fd_flags(state: &VfsState, cli_handle: ClientHandle, fd: usize) -> Option<u32> {
    state.client_slot(cli_handle, fd).map(|slot| slot.fd_flags)
}

pub(crate) unsafe fn handle_dup_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let oldfd = (*msg).regs[0] as usize;
        let Some(open_file) = state.client_open_file_handle(cli_handle, oldfd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let Some(newfd) = next_free_fd(state, cli_handle, 0) else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        if !state.install_client_slot_shared(cli_handle, newfd, open_file, 0) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

pub(crate) unsafe fn handle_dup2_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let oldfd = (*msg).regs[0] as usize;
        let newfd = (*msg).regs[1] as usize;
        if newfd >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let Some(open_file) = state.client_open_file_handle(cli_handle, oldfd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        if oldfd == newfd {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = newfd as u64;
            return;
        }
        if !state.install_client_slot_shared(cli_handle, newfd, open_file, 0) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

pub(crate) unsafe fn handle_dup3_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let oldfd = (*msg).regs[0] as usize;
        let newfd = (*msg).regs[1] as usize;
        let flags = (*msg).regs[2] as u32;
        if newfd >= MAX_CLIENT_OBJECTS || (flags & !O_CLOEXEC) != 0 || oldfd == newfd {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let Some(open_file) = state.client_open_file_handle(cli_handle, oldfd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let fd_flags = if (flags & O_CLOEXEC) != 0 {
            FD_CLOEXEC as u32
        } else {
            0
        };
        if !state.install_client_slot_shared(cli_handle, newfd, open_file, fd_flags) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

pub(crate) unsafe fn handle_clone_fds_owned(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let parent_badge = (*msg).regs[0];
        let child_badge = (*msg).regs[1];
        if parent_badge == child_badge {
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
            return;
        }
        let Some(parent_handle) = state.lookup_client(parent_badge) else {
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
            return;
        };

        let (personality, mount_ns, cwd_anchor, bulk_shm_vaddr, bulk_shm_id, bulk_shm_pages, slots) = {
            let parent = match state.clients.get(parent_handle) {
                Some(parent) => parent,
                None => {
                    (*reply).label = TRONA_OK;
                    (*reply).length = 0;
                    return;
                }
            };
            let mut slots =
                [(crate::server::open_file::OpenFileHandle::INVALID, 0u32); MAX_CLIENT_OBJECTS];
            for fd in 0..MAX_CLIENT_OBJECTS {
                let slot = parent.slots[fd];
                if slot.active != 0 {
                    slots[fd] = (slot.open_file, slot.fd_flags);
                }
            }
            (
                parent.personality,
                parent.mount_ns,
                parent.cwd_anchor,
                parent.bulk_shm_vaddr,
                parent.bulk_shm_id,
                parent.bulk_shm_pages,
                slots,
            )
        };

        let Some(child_handle) = state.ensure_client(child_badge, personality) else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        for fd in 0..MAX_CLIENT_OBJECTS {
            let _ = state.release_client_slot(child_handle, fd);
        }
        if let Some(child) = state.clients.get_mut(child_handle) {
            child.personality = if personality == PERS_WIN32 {
                PERS_WIN32
            } else {
                PERS_POSIX
            };
            child.mount_ns = mount_ns;
            child.cwd_anchor = cwd_anchor;
            child.bulk_shm_vaddr = bulk_shm_vaddr;
            child.bulk_shm_id = bulk_shm_id;
            child.bulk_shm_pages = bulk_shm_pages;
        }
        for (fd, (open_file, fd_flags)) in slots.iter().copied().enumerate() {
            if !open_file.is_valid() {
                continue;
            }
            if !state.install_client_slot_shared(child_handle, fd, open_file, fd_flags) {
                for rollback_fd in 0..MAX_CLIENT_OBJECTS {
                    let _ = state.release_client_slot(child_handle, rollback_fd);
                }
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return;
            }
        }
        if personality == PERS_WIN32 {
            state.clone_win32_client_state(parent_handle, child_handle);
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_client_exec_owned(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let exec_badge = (*msg).regs[0];
        crate::owner::cancel::vfs_cancel_for_badge(
            state,
            exec_badge,
            crate::owner::pending_ops::CANCEL_DROP,
        );
        if let Some(cli_handle) = state.lookup_client(exec_badge) {
            let mut cloexec = [false; MAX_CLIENT_OBJECTS];
            if let Some(client) = state.clients.get(cli_handle) {
                for (fd, slot) in client.slots.iter().enumerate() {
                    cloexec[fd] = slot.active != 0 && (slot.fd_flags & FD_CLOEXEC as u32) != 0;
                }
            }
            for (fd, should_close) in cloexec.iter().copied().enumerate() {
                if should_close {
                    let _ = state.release_client_slot(cli_handle, fd);
                }
            }
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_fcntl_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let cmd = (*msg).regs[1] as i32;
        let arg = (*msg).regs[2] as i64;
        if fd >= MAX_CLIENT_OBJECTS || state.client_open_file_handle(cli_handle, fd).is_none() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        match cmd {
            F_DUPFD | F_DUPFD_CLOEXEC => {
                let min_fd = if arg < 0 { 0 } else { arg as usize };
                let Some(open_file) = state.client_open_file_handle(cli_handle, fd) else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                let Some(newfd) = next_free_fd(state, cli_handle, min_fd) else {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                    return;
                };
                let fd_flags = if cmd == F_DUPFD_CLOEXEC {
                    FD_CLOEXEC as u32
                } else {
                    0
                };
                if !state.install_client_slot_shared(cli_handle, newfd, open_file, fd_flags) {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = newfd as u64;
            }
            F_GETFD => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = slot_fd_flags(state, cli_handle, fd).unwrap_or(0) as u64;
            }
            F_SETFD => {
                let Some(slot) = state.client_slot_mut(cli_handle, fd) else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                slot.fd_flags = if (arg & FD_CLOEXEC as i64) != 0 {
                    FD_CLOEXEC as u32
                } else {
                    0
                };
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            F_GETFL => {
                let Some(of) = state.client_open_file(cli_handle, fd) else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = of.status_flags as u64;
            }
            F_SETFL => {
                let Some(of) = state.client_open_file_mut(cli_handle, fd) else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                let changeable = O_APPEND | O_NONBLOCK;
                of.status_flags = (of.status_flags & !changeable) | ((arg as u32) & changeable);
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
            }
        }
    }
}

pub(crate) unsafe fn handle_isatty_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let is_tty = if fd < MAX_CLIENT_OBJECTS
            && crate::fileops::device::is_tty_fd(state, cli_handle, fd)
        {
            1u64
        } else {
            0u64
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = is_tty;
    }
}

pub(crate) unsafe fn handle_fsync_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if fd >= MAX_CLIENT_OBJECTS || state.client_open_file_handle(cli_handle, fd).is_none() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_ioctl_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if fd >= MAX_CLIENT_OBJECTS || state.client_open_file_handle(cli_handle, fd).is_none() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
        } else if !crate::fileops::device::handle_device_ioctl_owned(state, cli_handle, msg, reply)
        {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_tcgetattr_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if fd >= MAX_CLIENT_OBJECTS || state.client_open_file_handle(cli_handle, fd).is_none() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
        } else if !crate::fileops::device::handle_device_tcgetattr_owned(
            state, cli_handle, msg, reply,
        ) {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
        }
    }
}

pub(crate) unsafe fn handle_tcsetattr_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        if fd >= MAX_CLIENT_OBJECTS || state.client_open_file_handle(cli_handle, fd).is_none() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
        } else if !crate::fileops::device::handle_device_tcsetattr_owned(
            state, cli_handle, msg, reply,
        ) {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
        }
    }
}
