// SPDX-License-Identifier: GPL-2.0-only
//! Poll and epoll subsystem for event multiplexing.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::arena::Handle;
use crate::fileops::open::reserve_fd_owned;
use crate::ipc::timer_wheel::{self, TimerKind};
use crate::owner::dispatch::resolve_fd;
use crate::owner::loop_::OWNER_STATE_PTR;
use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::personality::posix::types::{EpollEntry, EpollInstance, PipeState, PollWaiter, SocketState};
use crate::server::consts::*;
use crate::server::types::{ClientHandle, ObjectKind, ObjectSlot, MAX_CLIENT_OBJECTS};
use crate::{ipc_ctx, vfs_alloc_array};

static mut LOGGED_POLL_REGISTRATIONS: u8 = 0;
static mut LOGGED_POLL_WAKES: u8 = 0;
const POLL_WAITER_KIND_POLL: u8 = 1;
const POLL_WAITER_KIND_EPOLL: u8 = 2;
const MAX_WAITER_BATCH: usize = 128;
static POLL_TIMER_COOKIE: AtomicU32 = AtomicU32::new(1);
static POLL_TIMER_DEADLINE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn monotonic_now_ns() -> u64 {
    trona::syscall::syscall(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC as u64, 0, 0, 0, 0, 0).value
}

fn timeout_deadline_ns(timeout_ms: i32) -> u64 {
    if timeout_ms <= 0 {
        0
    } else {
        monotonic_now_ns().saturating_add((timeout_ms as u64).saturating_mul(1_000_000))
    }
}

unsafe fn owner_state() -> Option<&'static mut VfsState> {
    unsafe {
        let ptr = OWNER_STATE_PTR;
        if ptr.is_null() {
            None
        } else {
            Some(&mut *ptr)
        }
    }
}

fn next_poll_timer_cookie() -> u32 {
    POLL_TIMER_COOKIE.fetch_add(1, Ordering::AcqRel).wrapping_add(1)
}

fn arm_poll_deadline(deadline_ns: u64) {
    if deadline_ns == 0 {
        return;
    }
    loop {
        let armed = POLL_TIMER_DEADLINE.load(Ordering::Acquire);
        if armed != 0 && armed <= deadline_ns {
            return;
        }
        if POLL_TIMER_DEADLINE
            .compare_exchange(armed, deadline_ns, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            timer_wheel::register_timer(deadline_ns, TimerKind::PollDeadline, next_poll_timer_cookie());
            return;
        }
    }
}

fn release_waiter(state: &mut VfsState, waiter_handle: Handle<PollWaiter>) {
    if let Some(waiter) = state.poll_waiters.get_mut(waiter_handle) {
        waiter.active = 0;
        waiter.deadline_ns = 0;
    }
    let _ = state.poll_waiters.release(waiter_handle);
}

fn release_epoll(state: &mut VfsState, epoll_handle: Handle<EpollInstance>) {
    if let Some(epoll) = state.epolls.get_mut(epoll_handle) {
        epoll.active = 0;
    }
    let _ = state.epolls.release(epoll_handle);
}

fn find_client_handle_by_badge(state: &VfsState, badge: u64) -> Option<ClientHandle> {
    let (slot, epoch) = state.badge_map.lookup(badge)?;
    Some(ClientHandle::new(slot, epoch))
}

fn find_socket<'a>(
    state: &'a VfsState,
    socket_handle: Handle<SocketState>,
) -> Option<&'a SocketState> {
    state.sockets.get(socket_handle)
}

fn sock_buf_len(sock: &SocketState) -> u16 {
    if sock.data_head >= sock.data_tail {
        sock.data_head - sock.data_tail
    } else {
        SOCK_BUF_SIZE as u16 - sock.data_tail + sock.data_head
    }
}

fn sock_buf_free(sock: &SocketState) -> u16 {
    (SOCK_BUF_SIZE as u16 - 1) - sock_buf_len(sock)
}

fn pipe_buf_len(pipe: &PipeState) -> u16 {
    if pipe.data_head >= pipe.data_tail {
        pipe.data_head - pipe.data_tail
    } else {
        PIPE_BUF_SIZE as u16 - pipe.data_tail + pipe.data_head
    }
}

fn pipe_buf_free(pipe: &PipeState) -> u16 {
    (PIPE_BUF_SIZE as u16 - 1) - pipe_buf_len(pipe)
}

fn check_fd_readiness(state: &VfsState, cli_handle: ClientHandle, fd: i32, events: u32) -> u32 {
    let Some(slot) = resolve_fd(state, cli_handle, fd) else {
        return 0x020;
    };

    let mut revents = 0u32;
    match slot.kind() {
        ObjectKind::File | ObjectKind::Directory | ObjectKind::Shm => {
            if events & 0x001 != 0 {
                revents |= 0x001;
            }
            if events & 0x004 != 0 {
                revents |= 0x004;
            }
        }
        ObjectKind::Device => {
            if let Some(device) = slot.device_info() {
            if device.dev_type == DEV_PTY_SLAVE || device.dev_type == DEV_PTMX {
                unsafe {
                    let mut req = TronaMsg::zeroed();
                    let mut rep = TronaMsg::zeroed();
                    req.label = POSIX_TTYSRV_PTY_POLL;
                    req.regs[0] = device.pty_id as u64;
                    req.regs[1] = events as u64;
                    req.regs[2] = if device.dev_type == DEV_PTMX { 1 } else { 0 };
                    req.length = 3;
                    let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const req, &raw mut rep);
                    if err == 0 && rep.label == TRONA_OK {
                        revents = rep.regs[0] as u32;
                    }
                }
            } else {
                if events & 0x004 != 0 {
                    revents |= 0x004;
                }
                if events & 0x001 != 0 {
                    revents |= 0x001;
                }
            }
            }
        }
        ObjectKind::UnixSocket => {
            let socket_handle = slot.unix_socket_handle();
            if socket_handle.is_valid() {
                if let Some(sock) = find_socket(state, socket_handle) {
                if sock.state == SOCK_CONNECTED {
                    if events & 0x001 != 0 && (sock_buf_len(sock) > 0 || sock.peer_closed != 0) {
                        revents |= 0x001;
                    }
                    if events & 0x004 != 0 {
                        if let Some(peer) = find_socket(state, sock.peer_socket) {
                            if sock_buf_free(peer) > 0 {
                                revents |= 0x004;
                            }
                        }
                    }
                    if sock.peer_closed != 0 {
                        revents |= 0x010;
                    }
                } else if sock.state == SOCK_LISTENING {
                    if events & 0x001 != 0 && sock.pending_count > 0 {
                        revents |= 0x001;
                    }
                }
                }
            }
        }
        ObjectKind::Pipe => {
            if let Some(pipe) = state.pipes.get(slot.pipe_handle()) {
                let is_read_end = (slot.rights & OBJ_RIGHT_READ) != 0;
                if is_read_end {
                    if events & 0x001 != 0 && pipe_buf_len(pipe) > 0 {
                        revents |= 0x001;
                    }
                    if pipe.write_refcount == 0 {
                        revents |= 0x010;
                    }
                } else {
                    if events & 0x004 != 0 && pipe_buf_free(pipe) > 0 {
                        revents |= 0x004;
                    }
                    if pipe.read_refcount == 0 {
                        revents |= 0x008;
                    }
                }
            }
        }
        ObjectKind::InetSocket => unsafe {
            let mut req = TronaMsg::zeroed();
            let mut rep = TronaMsg::zeroed();
            req.label = NET_POLL_STATUS;
            req.regs[0] = slot.inet_socket_id().unwrap_or(0) as u64;
            req.regs[1] = events as u64;
            req.length = 2;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const req, &raw mut rep);
            if err == 0 && rep.label == TRONA_OK {
                revents = rep.regs[0] as u32;
            }
        },
        _ => return 0x020,
    }

    revents
}

fn try_deliver_ready_waiter(state: &mut VfsState, cli_handle: ClientHandle, waiter_handle: Handle<PollWaiter>) -> bool {
    let (kind, reply_slot, nfds, objects, data) = match state.poll_waiters.get(waiter_handle) {
        Some(waiter) if waiter.active != 0 => {
            (waiter.kind, waiter.reply_slot, waiter.nfds, waiter.objects, waiter.data)
        }
        _ => return false,
    };

    let mut reply = TronaMsg::zeroed();
    reply.label = TRONA_OK;
    match kind {
        POLL_WAITER_KIND_POLL => {
            let mut ready_count = 0u64;
            for i in 0..nfds as usize {
                let rev = check_fd_readiness(state, cli_handle, objects[i].0, objects[i].1 as u32) as u16;
                reply.regs[1 + i] = rev as u64;
                if rev != 0 {
                    ready_count += 1;
                }
            }
            if ready_count == 0 {
                return false;
            }
            reply.regs[0] = ready_count;
            reply.length = 1 + nfds as u64;
        }
        POLL_WAITER_KIND_EPOLL => {
            let mut ready_count = 0usize;
            for i in 0..nfds as usize {
                let rev = check_fd_readiness(state, cli_handle, objects[i].0, objects[i].1 as u32);
                if rev == 0 {
                    continue;
                }
                reply.regs[1 + ready_count * 2] = rev as u64;
                reply.regs[2 + ready_count * 2] = data[i];
                ready_count += 1;
            }
            if ready_count == 0 {
                return false;
            }
            reply.regs[0] = ready_count as u64;
            reply.length = 1 + (ready_count as u64 * 2);
        }
        _ => return false,
    }

    unsafe {
        ipc::send_ctx(ipc_ctx(), reply_slot, &raw const reply);
    }
    release_waiter(state, waiter_handle);
    true
}

pub(crate) unsafe fn next_poll_deadline_ns() -> u64 {
    let Some(state) = (unsafe { owner_state() }) else {
        return 0;
    };
    let mut earliest = u64::MAX;
    state.poll_waiters.for_each_active(|_, waiter| {
        if waiter.active != 0 && waiter.deadline_ns != 0 && waiter.deadline_ns < earliest {
            earliest = waiter.deadline_ns;
        }
        true
    });
    if earliest == u64::MAX { 0 } else { earliest }
}

pub(crate) unsafe fn next_poll_timeout_ns(now_ns: u64) -> u64 {
    let deadline = unsafe { next_poll_deadline_ns() };
    if deadline == 0 {
        0
    } else if deadline <= now_ns {
        1
    } else {
        deadline.saturating_sub(now_ns)
    }
}

pub(crate) unsafe fn expire_poll_timeouts(now_ns: u64) -> bool {
    let Some(state) = (unsafe { owner_state() }) else {
        return false;
    };

    let mut expired_any = false;
    loop {
        let mut batch = [Handle::<PollWaiter>::INVALID; MAX_WAITER_BATCH];
        let mut count = 0usize;
        state.poll_waiters.for_each_active(|handle, waiter| {
            if waiter.active != 0 && waiter.deadline_ns != 0 && waiter.deadline_ns <= now_ns {
                batch[count] = handle;
                count += 1;
                if count == MAX_WAITER_BATCH {
                    return false;
                }
            }
            true
        });

        if count == 0 {
            break;
        }

        for handle in batch.into_iter().take(count) {
            let reply_slot = match state.poll_waiters.get(handle) {
                Some(waiter) if waiter.active != 0 => waiter.reply_slot,
                _ => continue,
            };
            let mut reply = TronaMsg::zeroed();
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = 0;
            unsafe { ipc::send_ctx(ipc_ctx(), reply_slot, &raw const reply) };
            release_waiter(state, handle);
            expired_any = true;
        }
    }

    expired_any
}

unsafe fn rearm_poll_deadline_from_state() {
    let next_deadline = unsafe { next_poll_deadline_ns() };
    if next_deadline != 0 {
        arm_poll_deadline(next_deadline);
    }
}

pub(crate) unsafe fn handle_poll_timer(cookie: u32, now_ns: u64) {
    unsafe {
        if cookie != POLL_TIMER_COOKIE.load(Ordering::Acquire) {
            return;
        }
        POLL_TIMER_DEADLINE.store(0, Ordering::Release);
        let _ = expire_poll_timeouts(now_ns);
        rearm_poll_deadline_from_state();
    }
}

pub(crate) unsafe fn wake_poll_waiters(badge: u64, fd: i32, revents: u16) {
    let Some(state) = (unsafe { owner_state() }) else {
        return;
    };

    loop {
        let mut batch = [Handle::<PollWaiter>::INVALID; MAX_WAITER_BATCH];
        let mut count = 0usize;
        state.poll_waiters.for_each_active(|handle, waiter| {
            if waiter.active != 0 && waiter.badge == badge {
                batch[count] = handle;
                count += 1;
                if count == MAX_WAITER_BATCH {
                    return false;
                }
            }
            true
        });
        if count == 0 {
            break;
        }

        let mut matched_targeted = false;
        for handle in batch.into_iter().take(count) {
            let waiter = match state.poll_waiters.get(handle) {
                Some(waiter) if waiter.active != 0 => *waiter,
                _ => continue,
            };

            let mut wake_reply = TronaMsg::zeroed();
            wake_reply.label = TRONA_OK;
            let mut ready_count = 0u64;
            for j in 0..waiter.nfds as usize {
                if fd != -1 && waiter.objects[j].0 != fd {
                    continue;
                }
                if fd != -1 {
                    matched_targeted = true;
                }
                let requested = waiter.objects[j].1;
                let matched = revents & (requested | 0x010 | 0x008);
                if matched == 0 {
                    continue;
                }
                if waiter.kind == POLL_WAITER_KIND_EPOLL {
                    wake_reply.regs[1 + ready_count as usize * 2] = matched as u64;
                    wake_reply.regs[2 + ready_count as usize * 2] = waiter.data[j];
                } else {
                    wake_reply.regs[1 + j] = matched as u64;
                }
                ready_count += 1;
            }

            if ready_count == 0 {
                continue;
            }

            wake_reply.regs[0] = ready_count;
            wake_reply.length = if waiter.kind == POLL_WAITER_KIND_EPOLL {
                1 + ready_count * 2
            } else {
                1 + waiter.nfds as u64
            };
            unsafe { ipc::send_ctx(ipc_ctx(), waiter.reply_slot, &raw const wake_reply) };
            release_waiter(state, handle);

            unsafe {
                if *(&raw const LOGGED_POLL_WAKES) < 32 {
                    *(&raw mut LOGGED_POLL_WAKES) += 1;
                    trona::udebug!(|_lb| {
                        _lb.str(b"[VFS] poll wake badge=");
                        _lb.hex(badge);
                        _lb.str(b" fd=");
                        _lb.dec(fd as u64);
                        _lb.str(b" revents=");
                        _lb.hex(revents as u64);
                        _lb.putc(b'\n');
                    });
                }
            }
        }

        if fd != -1 && !matched_targeted {
            unsafe {
                if *(&raw const LOGGED_POLL_WAKES) < 32 {
                    *(&raw mut LOGGED_POLL_WAKES) += 1;
                    trona::udebug!(|_lb| {
                        _lb.str(b"[VFS] poll wake miss badge=");
                        _lb.hex(badge);
                        _lb.str(b" fd=");
                        _lb.dec(fd as u64);
                        _lb.str(b" revents=");
                        _lb.hex(revents as u64);
                        _lb.putc(b'\n');
                    });
                }
            }
        }

        if count < MAX_WAITER_BATCH {
            break;
        }
    }
}

/// Wake all poll/epoll waiters whose descriptors reference the given PTY slave.
///
/// `wake_poll_waiters` keys on (badge, fd), but the PTY notification path only
/// knows `pty_id` — ttysrv has no handle on individual client fds. So we walk
/// every active waiter, resolve its client by badge, and report POLLIN on any
/// fd backed by DEV_PTY_SLAVE with a matching `pty_id`. Without this, a
/// `poll()` that went to sleep before data arrived is never woken by canonical
/// line delivery, so readers like `openpam_ttyconv` (which does poll+read)
/// hang forever.
pub(crate) unsafe fn wake_pty_poll_waiters(pty_id: u32) {
    let Some(state) = (unsafe { owner_state() }) else {
        return;
    };

    loop {
        let mut batch = [Handle::<PollWaiter>::INVALID; MAX_WAITER_BATCH];
        let mut count = 0usize;
        state.poll_waiters.for_each_active(|handle, waiter| {
            if waiter.active != 0 {
                batch[count] = handle;
                count += 1;
                if count == MAX_WAITER_BATCH {
                    return false;
                }
            }
            true
        });
        if count == 0 {
            break;
        }

        let mut any_released = false;
        for handle in batch.into_iter().take(count) {
            let waiter = match state.poll_waiters.get(handle) {
                Some(w) if w.active != 0 => *w,
                _ => continue,
            };

            let Some(cli_handle) = find_client_handle_by_badge(state, waiter.badge) else {
                continue;
            };
            let cli = match state.clients.get(cli_handle) {
                Some(c) => c,
                None => continue,
            };

            let mut wake_reply = TronaMsg::zeroed();
            wake_reply.label = TRONA_OK;
            let mut ready_count = 0u64;
            for j in 0..waiter.nfds as usize {
                let fd = waiter.objects[j].0;
                if fd < 0 || (fd as usize) >= MAX_CLIENT_OBJECTS {
                    continue;
                }
                let matches_pty = match cli.objects[fd as usize].device_info() {
                    Some(d) => d.dev_type == DEV_PTY_SLAVE && d.pty_id == pty_id,
                    None => false,
                };
                if !matches_pty {
                    continue;
                }
                let requested = waiter.objects[j].1;
                // POLLIN is the only event PTY readability signals. Hangup/error
                // bits are always reportable, mirroring `wake_poll_waiters`.
                let revents: u16 = POLLIN as u16;
                let matched = revents & (requested | 0x010 | 0x008);
                if matched == 0 {
                    continue;
                }
                if waiter.kind == POLL_WAITER_KIND_EPOLL {
                    wake_reply.regs[1 + ready_count as usize * 2] = matched as u64;
                    wake_reply.regs[2 + ready_count as usize * 2] = waiter.data[j];
                } else {
                    wake_reply.regs[1 + j] = matched as u64;
                }
                ready_count += 1;
            }

            if ready_count == 0 {
                continue;
            }

            wake_reply.regs[0] = ready_count;
            wake_reply.length = if waiter.kind == POLL_WAITER_KIND_EPOLL {
                1 + ready_count * 2
            } else {
                1 + waiter.nfds as u64
            };
            unsafe { ipc::send_ctx(ipc_ctx(), waiter.reply_slot, &raw const wake_reply) };
            release_waiter(state, handle);
            any_released = true;
        }

        if !any_released {
            break;
        }
    }
}

pub(crate) unsafe fn handle_epoll_create(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    reply: *mut TronaMsg,
) {
    let badge = state.clients.get(cli_handle).map(|cli| cli.badge).unwrap_or(0);

    let Some(epoll_handle) = state.epolls.alloc() else {
        unsafe { (*reply).label = TRONA_OUT_OF_MEMORY; }
        return;
    };

    let init_ok = if let Some(epoll) = state.epolls.get_mut(epoll_handle) {
        epoll.active = 1;
        epoll.owner_badge = badge;
        if epoll.entries.is_null() {
            let entries = unsafe { vfs_alloc_array::<EpollEntry>(INITIAL_EPOLL_ENTRIES) };
            if entries.is_null() {
                false
            } else {
                epoll.entries = entries;
                epoll.entries_cap = INITIAL_EPOLL_ENTRIES as u16;
                true
            }
        } else {
            true
        }
    } else {
        false
    };

    if !init_ok {
        release_epoll(state, epoll_handle);
        unsafe { (*reply).label = TRONA_OUT_OF_MEMORY; }
        return;
    }

    if let Some(epoll) = state.epolls.get_mut(epoll_handle) {
        for i in 0..epoll.entries_cap as usize {
            unsafe {
                *epoll.entries.add(i) = EpollEntry::zeroed();
            }
        }
    }

    let Some(fd) = reserve_fd_owned(state, cli_handle) else {
        release_epoll(state, epoll_handle);
        unsafe { (*reply).label = TRONA_OUT_OF_MEMORY; }
        return;
    };

    if let Some(cli) = state.clients.get_mut(cli_handle) {
        let slot = &mut cli.objects[fd as usize];
        slot.set_epoll(epoll_handle);
    }

    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

pub(crate) unsafe fn handle_epoll_ctl(
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

        let Some(ep_slot) = resolve_fd(state, cli_handle, epfd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };
        if ep_slot.kind() != ObjectKind::Epoll || !ep_slot.epoll_handle().is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        if resolve_fd(state, cli_handle, fd).is_none() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(epoll) = state.epolls.get_mut(ep_slot.epoll_handle()) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        match op {
            1 => {
                for i in 0..epoll.entries_cap as usize {
                    if (*epoll.entries.add(i)).active != 0 && (*epoll.entries.add(i)).fd == fd {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                }
                let mut free_idx = None;
                for i in 0..epoll.entries_cap as usize {
                    if (*epoll.entries.add(i)).active == 0 {
                        free_idx = Some(i);
                        break;
                    }
                }
                let Some(idx) = free_idx else {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                };
                (*epoll.entries.add(idx)).active = 1;
                (*epoll.entries.add(idx)).fd = fd;
                (*epoll.entries.add(idx)).events = events;
                (*epoll.entries.add(idx)).data = data;
            }
            2 => {
                let mut found = false;
                for i in 0..epoll.entries_cap as usize {
                    if (*epoll.entries.add(i)).active != 0 && (*epoll.entries.add(i)).fd == fd {
                        (*epoll.entries.add(i)).active = 0;
                        found = true;
                        break;
                    }
                }
                if !found {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
            }
            3 => {
                let mut found = false;
                for i in 0..epoll.entries_cap as usize {
                    if (*epoll.entries.add(i)).active != 0 && (*epoll.entries.add(i)).fd == fd {
                        (*epoll.entries.add(i)).events = events;
                        (*epoll.entries.add(i)).data = data;
                        found = true;
                        break;
                    }
                }
                if !found {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_epoll_wait(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let epfd = (*msg).regs[0] as i32;
        let max_events = (*msg).regs[1] as usize;
        let timeout = (*msg).regs[2] as i32;

        let Some(ep_slot) = resolve_fd(state, cli_handle, epfd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        if ep_slot.kind() != ObjectKind::Epoll || !ep_slot.epoll_handle().is_valid() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let epoll_handle = ep_slot.epoll_handle();
        let Some(epoll) = state.epolls.get(epoll_handle) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        let entries = epoll.entries;
        let entries_cap = epoll.entries_cap as usize;

        let cap = if max_events > 8 { 8 } else { max_events };
        let mut ready_count = 0usize;
        for i in 0..entries_cap {
            if (*entries.add(i)).active == 0 {
                continue;
            }
            if ready_count >= cap {
                break;
            }
            let rev = check_fd_readiness(state, cli_handle, (*entries.add(i)).fd, (*entries.add(i)).events);
            if rev != 0 {
                (*reply).regs[1 + ready_count * 2] = rev as u64;
                (*reply).regs[2 + ready_count * 2] = (*entries.add(i)).data;
                ready_count += 1;
            }
        }

        if ready_count > 0 || timeout == 0 {
            (*reply).label = TRONA_OK;
            (*reply).regs[0] = ready_count as u64;
            (*reply).length = 1 + (ready_count as u64 * 2);
            return false;
        }

        let reply_slot = state.alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let Some(waiter_handle) = state.poll_waiters.alloc() else {
            let mut err_reply = TronaMsg::zeroed();
            err_reply.label = TRONA_OUT_OF_MEMORY;
            ipc::send_ctx(ipc_ctx(), reply_slot, &raw const err_reply);
            return true;
        };

        let badge = state.clients.get(cli_handle).map(|cli| cli.badge).unwrap_or(0);
        let deadline_ns = timeout_deadline_ns(timeout);
        if let Some(waiter) = state.poll_waiters.get_mut(waiter_handle) {
            waiter.active = 1;
            waiter.kind = POLL_WAITER_KIND_EPOLL;
            waiter.badge = badge;
            waiter.reply_slot = reply_slot;
            waiter.deadline_ns = deadline_ns;
            waiter.nfds = 0;

            let mut n = 0u8;
            for i in 0..entries_cap {
                if (*entries.add(i)).active == 0 || n >= 8 {
                    continue;
                }
                waiter.objects[n as usize].0 = (*entries.add(i)).fd;
                waiter.objects[n as usize].1 = (*entries.add(i)).events as u16;
                waiter.data[n as usize] = (*entries.add(i)).data;
                n += 1;
            }
            waiter.nfds = n;
        }

        if deadline_ns != 0 {
            arm_poll_deadline(deadline_ns);
        }

        if try_deliver_ready_waiter(state, cli_handle, waiter_handle) {
            return true;
        }

        true
    }
}

pub(crate) unsafe fn handle_poll(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let nfds = (*msg).regs[0] as u32;
        let timeout = (*msg).regs[1] as i32;
        let actual_nfds = if nfds > 8 { 8 } else { nfds };

        let mut ready_count = 0i32;
        let mut revents_arr = [0u16; 8];
        for i in 0..actual_nfds as usize {
            let fd = (*msg).regs[2 + i * 2] as i32;
            let events = (*msg).regs[2 + i * 2 + 1] as u16;
            let rev = check_fd_readiness(state, cli_handle, fd, events as u32) as u16;
            revents_arr[i] = rev;
            if rev != 0 {
                ready_count += 1;
            }
        }

        if ready_count > 0 || timeout == 0 {
            (*reply).label = TRONA_OK;
            (*reply).regs[0] = ready_count as u64;
            for i in 0..actual_nfds as usize {
                (*reply).regs[1 + i] = revents_arr[i] as u64;
            }
            (*reply).length = 1 + actual_nfds as u64;
            return false;
        }

        let reply_slot = state.alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let Some(waiter_handle) = state.poll_waiters.alloc() else {
            let mut err_reply = TronaMsg::zeroed();
            err_reply.label = TRONA_OUT_OF_MEMORY;
            ipc::send_ctx(ipc_ctx(), reply_slot, &raw const err_reply);
            return true;
        };

        let badge = state.clients.get(cli_handle).map(|cli| cli.badge).unwrap_or(0);
        let deadline_ns = timeout_deadline_ns(timeout);
        if let Some(waiter) = state.poll_waiters.get_mut(waiter_handle) {
            waiter.active = 1;
            waiter.kind = POLL_WAITER_KIND_POLL;
            waiter.badge = badge;
            waiter.reply_slot = reply_slot;
            waiter.deadline_ns = deadline_ns;
            waiter.nfds = actual_nfds as u8;
            for i in 0..actual_nfds as usize {
                waiter.objects[i].0 = (*msg).regs[2 + i * 2] as i32;
                waiter.objects[i].1 = (*msg).regs[2 + i * 2 + 1] as u16;
                waiter.data[i] = 0;
            }
        }

        if deadline_ns != 0 {
            arm_poll_deadline(deadline_ns);
        }

        if try_deliver_ready_waiter(state, cli_handle, waiter_handle) {
            return true;
        }

        if *(&raw const LOGGED_POLL_REGISTRATIONS) < 32 {
            *(&raw mut LOGGED_POLL_REGISTRATIONS) += 1;
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] poll wait badge=");
                _lb.hex(badge);
                _lb.str(b" nfds=");
                _lb.dec(actual_nfds as u64);
                _lb.str(b" timeout=");
                _lb.dec(timeout as u64);
                _lb.putc(b'\n');
            });
        }

        true
    }
}
