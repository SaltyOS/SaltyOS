// SPDX-License-Identifier: GPL-2.0-only
//! Immediate polling and epoll control.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::epoll_object::{EPOLL_MAX_INTERESTS, EpollHandle};
use crate::server::types::{
    ClientHandle, OBJ_DEVICE, OBJ_DIRECTORY, OBJ_EPOLL, OBJ_FILE, OBJ_PIPE, OBJ_SOCKET,
};

pub(crate) const POLL_INLINE_MAX_FDS: usize = 8;
const EPOLL_INLINE_MAX_EVENTS: usize = 15;

pub(crate) fn monotonic_now_ns() -> u64 {
    trona_kernel::syscall::syscall(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC as u64, 0, 0, 0, 0, 0).value
}

pub(crate) fn poll_bits_for_fd(
    state: &VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    events: i16,
) -> i16 {
    if fd < 0 {
        return 0;
    }
    let Some(of) = state.client_open_file(cli_handle, fd as usize) else {
        return POLLNVAL;
    };
    let mut revents = 0i16;
    match of.kind {
        OBJ_FILE | OBJ_DIRECTORY => {
            if (events & POLLIN) != 0 {
                revents |= POLLIN;
            }
            if (events & POLLOUT) != 0 && of.kind == OBJ_FILE {
                revents |= POLLOUT;
            }
        }
        OBJ_PIPE => {
            let available = state.pipe_buffer_len(of.pipe).unwrap_or(0);
            let free = state.pipe_buffer_free(of.pipe).unwrap_or(0);
            let (read_refs, write_refs) = state.pipe_refcounts(of.pipe).unwrap_or((0, 0));
            let access = of.status_flags & O_ACCMODE;
            if access != O_WRONLY {
                if (events & POLLIN) != 0 && available != 0 {
                    revents |= POLLIN;
                }
                if write_refs == 0 {
                    revents |= POLLHUP;
                }
            }
            if access != O_RDONLY {
                if (events & POLLOUT) != 0 && free != 0 {
                    revents |= POLLOUT;
                }
                if read_refs == 0 {
                    revents |= POLLERR;
                }
            }
        }
        OBJ_EPOLL => {
            if (events & POLLIN) != 0 && epoll_ready_count(state, cli_handle, of.epoll) != 0 {
                revents |= POLLIN;
            }
        }
        OBJ_SOCKET => {
            revents |= crate::fileops::socket::poll_bits_for_socket(of, state, events);
        }
        OBJ_DEVICE => {
            revents |= crate::fileops::device::poll_bits_for_device(
                of.device_dev_type,
                of.device_pty_id,
                events,
            );
        }
        _ => {
            revents |= POLLNVAL;
        }
    }
    revents
}

pub(crate) unsafe fn fill_poll_reply(
    state: &VfsState,
    cli_handle: ClientHandle,
    nfds: usize,
    fds: &[i32; POLL_INLINE_MAX_FDS],
    events: &[i16; POLL_INLINE_MAX_FDS],
    reply: *mut TronaMsg,
) -> u64 {
    unsafe {
        let mut ready = 0u64;
        (*reply).label = TRONA_OK;
        (*reply).length = 1 + nfds as u64;
        for idx in 0..nfds {
            let revents = poll_bits_for_fd(state, cli_handle, fds[idx], events[idx]);
            (*reply).regs[1 + idx] = revents as u64;
            if revents != 0 {
                ready += 1;
            }
        }
        (*reply).regs[0] = ready;
        ready
    }
}

fn epoll_event_mask(state: &VfsState, cli_handle: ClientHandle, fd: i32, events: u32) -> u32 {
    let polled = poll_bits_for_fd(
        state,
        cli_handle,
        fd,
        ((events & (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP)) as i16) | POLLERR | POLLHUP,
    );
    let mut ready = 0u32;
    if (polled & POLLIN) != 0 {
        ready |= EPOLLIN;
    }
    if (polled & POLLOUT) != 0 {
        ready |= EPOLLOUT;
    }
    if (polled & POLLERR) != 0 {
        ready |= EPOLLERR;
    }
    if (polled & POLLHUP) != 0 {
        ready |= EPOLLHUP;
    }
    ready & (events | EPOLLERR | EPOLLHUP)
}

fn epoll_ready_count(state: &VfsState, cli_handle: ClientHandle, epoll: EpollHandle) -> usize {
    let Some(ep) = state.epolls.get(epoll) else {
        return 0;
    };
    let mut count = 0usize;
    for entry in ep.entries.iter() {
        if entry.active == 0 {
            continue;
        }
        if epoll_event_mask(state, cli_handle, entry.fd, entry.events) != 0 {
            count += 1;
        }
    }
    count
}

fn find_epoll_entry_index(state: &VfsState, epoll: EpollHandle, fd: i32) -> Option<usize> {
    let ep = state.epolls.get(epoll)?;
    for (idx, entry) in ep.entries.iter().enumerate() {
        if entry.active != 0 && entry.fd == fd {
            return Some(idx);
        }
    }
    None
}

pub(crate) unsafe fn handle_poll_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let nfds = core::cmp::min((*msg).regs[0] as usize, POLL_INLINE_MAX_FDS);
        let timeout_ms = (*msg).regs[1] as i32;
        let mut fds = [-1i32; POLL_INLINE_MAX_FDS];
        let mut events = [0i16; POLL_INLINE_MAX_FDS];
        for idx in 0..nfds {
            fds[idx] = (*msg).regs[2 + idx * 2] as i32;
            events[idx] = (*msg).regs[2 + idx * 2 + 1] as i16;
        }

        let ready = fill_poll_reply(state, cli_handle, nfds, &fds, &events, reply);
        if ready != 0 || timeout_ms == 0 {
            return;
        }
        crate::fileops::tty_wait::defer_poll(state, cli_handle, msg, nfds, timeout_ms, reply);
    }
}

pub(crate) unsafe fn handle_epoll_create_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let Some(fd) = state.alloc_epoll_client_slot(cli_handle) else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

pub(crate) unsafe fn handle_epoll_ctl_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let epfd = (*msg).regs[0] as i32;
        let op = (*msg).regs[1] as i32;
        let fd = (*msg).regs[2] as i32;
        let events = (*msg).regs[3] as u32;
        let data = (*msg).regs[4];
        if epfd < 0 || fd < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let Some(ep_of) = state.client_open_file(cli_handle, epfd as usize) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        if ep_of.kind != OBJ_EPOLL || !ep_of.epoll.is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let epoll = ep_of.epoll;
        let Some(target_of) = state.client_open_file(cli_handle, fd as usize) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        if target_of.kind == OBJ_EPOLL {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        match op {
            EPOLL_CTL_ADD => {
                if find_epoll_entry_index(state, epoll, fd).is_some() {
                    (*reply).label = TRONA_ALREADY_EXISTS;
                    (*reply).length = 0;
                    return;
                }
                let Some(ep) = state.epolls.get_mut(epoll) else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                let mut free_idx = None;
                for idx in 0..EPOLL_MAX_INTERESTS {
                    if ep.entries[idx].active == 0 {
                        free_idx = Some(idx);
                        break;
                    }
                }
                let Some(idx) = free_idx else {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                    return;
                };
                ep.entries[idx].active = 1;
                ep.entries[idx].fd = fd;
                ep.entries[idx].events = events;
                ep.entries[idx].data = data;
            }
            EPOLL_CTL_DEL => {
                let Some(idx) = find_epoll_entry_index(state, epoll, fd) else {
                    (*reply).label = TRONA_NOT_FOUND;
                    (*reply).length = 0;
                    return;
                };
                let Some(ep) = state.epolls.get_mut(epoll) else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                ep.entries[idx] = crate::server::epoll_object::EpollInterest::zeroed();
            }
            EPOLL_CTL_MOD => {
                let Some(idx) = find_epoll_entry_index(state, epoll, fd) else {
                    (*reply).label = TRONA_NOT_FOUND;
                    (*reply).length = 0;
                    return;
                };
                let Some(ep) = state.epolls.get_mut(epoll) else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                    return;
                };
                ep.entries[idx].events = events;
                ep.entries[idx].data = data;
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn fill_epoll_wait_reply(
    state: &VfsState,
    cli_handle: ClientHandle,
    epfd: i32,
    maxevents: usize,
    reply: *mut TronaMsg,
) -> Result<u64, u64> {
    unsafe {
        if epfd < 0 || maxevents == 0 {
            return Err(TRONA_INVALID_ARGUMENT);
        }
        let Some(ep_of) = state.client_open_file(cli_handle, epfd as usize) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        if ep_of.kind != OBJ_EPOLL || !ep_of.epoll.is_valid() {
            return Err(TRONA_INVALID_ARGUMENT);
        }
        let Some(ep) = state.epolls.get(ep_of.epoll) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };

        let mut count = 0usize;
        (*reply).label = TRONA_OK;
        for entry in ep.entries.iter() {
            if entry.active == 0 {
                continue;
            }
            let ready = epoll_event_mask(state, cli_handle, entry.fd, entry.events);
            if ready == 0 {
                continue;
            }
            (*reply).regs[1 + count * 2] = ready as u64;
            (*reply).regs[2 + count * 2] = entry.data;
            count += 1;
            if count >= maxevents {
                break;
            }
        }
        (*reply).regs[0] = count as u64;
        (*reply).length = 1 + (count as u64) * 2;
        Ok(count as u64)
    }
}

pub(crate) unsafe fn handle_epoll_wait_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let epfd = (*msg).regs[0] as i32;
        let maxevents = core::cmp::min((*msg).regs[1] as usize, EPOLL_INLINE_MAX_EVENTS);
        let timeout_ms = (*msg).regs[2] as i32;
        match fill_epoll_wait_reply(state, cli_handle, epfd, maxevents, reply) {
            Ok(count) if count != 0 || timeout_ms == 0 => {}
            Ok(_) => {
                crate::fileops::tty_wait::defer_epoll_wait(
                    state, cli_handle, epfd, maxevents, timeout_ms, reply,
                );
            }
            Err(label) => {
                (*reply).label = label;
                (*reply).length = 0;
            }
        }
    }
}
