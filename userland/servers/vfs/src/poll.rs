// SPDX-License-Identifier: GPL-2.0-only
//! Poll and epoll subsystem for event multiplexing.

use trona::consts::*;
use trona::ipc;
use trona::types::*;

use crate::client::get_client;
use crate::consts::*;
use crate::pipe::{find_pipe, pipe_buf_free, pipe_buf_len};
use crate::socket::{alloc_reply_slot, find_socket, sock_buf_free, sock_buf_len};
use crate::types::*;
use crate::{
    ipc_ctx, max_epoll_instances, max_poll_waiters, vfs_alloc_array, vfs_grow_pool, EPOLLS,
    EPOLLS_CAP, EPOLLS_PTR, POLL_WAITERS, POLL_WAITERS_CAP, POLL_WAITERS_PTR,
};

static mut LOGGED_POLL_REGISTRATIONS: u8 = 0;
static mut LOGGED_POLL_WAKES: u8 = 0;
const POLL_WAITER_KIND_POLL: u8 = 1;
const POLL_WAITER_KIND_EPOLL: u8 = 2;

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

unsafe fn send_waiter_timeout_reply(waiter: *mut PollWaiter) {
    unsafe {
        let mut reply = TronaMsg::zeroed();
        reply.label = TRONA_OK;
        reply.regs[0] = 0;
        reply.length = 1;
        ipc::send_ctx(ipc_ctx(), (*waiter).reply_slot, &raw const reply);
        (*waiter).active = 0;
        (*waiter).deadline_ns = 0;
    }
}

unsafe fn try_deliver_ready_waiter(cli: *const ClientState, waiter_idx: usize) -> bool {
    unsafe {
        let waiter = &mut POLL_WAITERS!()[waiter_idx];
        if waiter.active == 0 {
            return false;
        }

        let mut reply = TronaMsg::zeroed();
        reply.label = TRONA_OK;

        match waiter.kind {
            POLL_WAITER_KIND_POLL => {
                let mut ready_count: u64 = 0;
                for i in 0..waiter.nfds as usize {
                    let rev = check_fd_readiness(cli, waiter.fds[i].0, waiter.fds[i].1 as u32) as u16;
                    reply.regs[1 + i] = rev as u64;
                    if rev != 0 {
                        ready_count += 1;
                    }
                }
                if ready_count == 0 {
                    return false;
                }
                reply.regs[0] = ready_count;
                reply.length = 1 + waiter.nfds as u64;
            }
            POLL_WAITER_KIND_EPOLL => {
                let mut ready_count: usize = 0;
                for i in 0..waiter.nfds as usize {
                    let rev = check_fd_readiness(cli, waiter.fds[i].0, waiter.fds[i].1 as u32);
                    if rev == 0 {
                        continue;
                    }
                    reply.regs[1 + ready_count * 2] = rev as u64;
                    reply.regs[2 + ready_count * 2] = waiter.data[i];
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

        ipc::send_ctx(ipc_ctx(), waiter.reply_slot, &raw const reply);
        waiter.active = 0;
        waiter.deadline_ns = 0;
        true
    }
}

pub(crate) unsafe fn expire_poll_timeouts(now_ns: u64) -> bool {
    unsafe {
        let mut expired = false;
        for i in 0..max_poll_waiters() {
            let waiter = &raw mut POLL_WAITERS!()[i];
            if (*waiter).active == 0 || (*waiter).deadline_ns == 0 || (*waiter).deadline_ns > now_ns {
                continue;
            }
            send_waiter_timeout_reply(waiter);
            expired = true;
        }
        expired
    }
}

pub(crate) unsafe fn next_poll_timeout_ns(now_ns: u64) -> u64 {
    unsafe {
        let mut earliest = u64::MAX;
        for i in 0..max_poll_waiters() {
            let waiter = &raw const POLL_WAITERS!()[i];
            if (*waiter).active == 0 || (*waiter).deadline_ns == 0 {
                continue;
            }
            let deadline = (*waiter).deadline_ns;
            if deadline <= now_ns {
                return 1;
            }
            if deadline < earliest {
                earliest = deadline;
            }
        }
        if earliest == u64::MAX {
            0
        } else {
            earliest.saturating_sub(now_ns)
        }
    }
}

/// Wake poll waiters that match a given fd for a given badge.
/// When fd == -1, broadcast: wake waiter for ANY fd with matching requested events.
pub(crate) unsafe fn wake_poll_waiters(badge: u64, fd: i32, revents: u16) {
    unsafe {
        let mut matched_targeted = false;
        for i in 0..max_poll_waiters() {
            if POLL_WAITERS!()[i].active == 0 || POLL_WAITERS!()[i].badge != badge {
                continue;
            }
            if fd == -1 {
                // Broadcast: report revents on all fds that requested matching events.
                let mut wake_reply = TronaMsg::zeroed();
                wake_reply.label = TRONA_OK;
                let mut ready_count: u64 = 0;
                for j in 0..POLL_WAITERS!()[i].nfds as usize {
                    let requested = POLL_WAITERS!()[i].fds[j].1;
                    let matched = revents & (requested | 0x010 | 0x008);
                    if matched != 0 {
                        if POLL_WAITERS!()[i].kind == POLL_WAITER_KIND_EPOLL {
                            wake_reply.regs[1 + ready_count as usize * 2] = matched as u64;
                            wake_reply.regs[2 + ready_count as usize * 2] = POLL_WAITERS!()[i].data[j];
                        } else {
                            wake_reply.regs[1 + j] = matched as u64;
                        }
                        ready_count += 1;
                    }
                }
                if ready_count > 0 {
                    wake_reply.regs[0] = ready_count;
                    wake_reply.length = if POLL_WAITERS!()[i].kind == POLL_WAITER_KIND_EPOLL {
                        1 + ready_count * 2
                    } else {
                        1 + POLL_WAITERS!()[i].nfds as u64
                    };
                    ipc::send_ctx(
                        ipc_ctx(),
                        POLL_WAITERS!()[i].reply_slot,
                        &raw const wake_reply,
                    );
                    POLL_WAITERS!()[i].active = 0;
                    POLL_WAITERS!()[i].deadline_ns = 0;
                }
            } else {
                // Targeted: match specific fd
                let mut wake_reply = TronaMsg::zeroed();
                wake_reply.label = TRONA_OK;
                let mut ready_count: u64 = 0;
                for j in 0..POLL_WAITERS!()[i].nfds as usize {
                    if POLL_WAITERS!()[i].fds[j].0 == fd {
                        matched_targeted = true;
                        let requested = POLL_WAITERS!()[i].fds[j].1;
                        let matched = revents & (requested | 0x010 | 0x008);
                        if matched != 0 {
                            if POLL_WAITERS!()[i].kind == POLL_WAITER_KIND_EPOLL {
                                wake_reply.regs[1 + ready_count as usize * 2] = matched as u64;
                                wake_reply.regs[2 + ready_count as usize * 2] = POLL_WAITERS!()[i].data[j];
                            } else {
                                wake_reply.regs[1 + j] = matched as u64;
                            }
                            ready_count += 1;
                        }
                    }
                }
                if ready_count > 0 {
                    wake_reply.regs[0] = ready_count;
                    wake_reply.length = if POLL_WAITERS!()[i].kind == POLL_WAITER_KIND_EPOLL {
                        1 + ready_count * 2
                    } else {
                        1 + POLL_WAITERS!()[i].nfds as u64
                    };
                    ipc::send_ctx(
                        ipc_ctx(),
                        POLL_WAITERS!()[i].reply_slot,
                        &raw const wake_reply,
                    );
                    POLL_WAITERS!()[i].active = 0;
                    POLL_WAITERS!()[i].deadline_ns = 0;
                    if *(&raw const LOGGED_POLL_WAKES) < 32 {
                        *(&raw mut LOGGED_POLL_WAKES) += 1;
                        trona::udebug!(|_lb| {
                            _lb.str(b"[VFS] poll wake badge=");
                            _lb.hex(badge);
                            _lb.str(b" fd=");
                            _lb.dec(fd as u64);
                            _lb.str(b" revents=");
                            _lb.hex(revents as u64);
                            _lb.str(b" waiter=");
                            _lb.dec(i as u64);
                            _lb.putc(b'\n');
                        });
                    }
                }
            }
        }

        if fd != -1 && !matched_targeted && *(&raw const LOGGED_POLL_WAKES) < 32 {
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

/// Check readiness of a single fd for given events. Returns revents bitmask.
pub(crate) unsafe fn check_fd_readiness(cli: *const ClientState, fd: i32, events: u32) -> u32 {
    unsafe {
        if fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            return 0x020; // POLLNVAL
        }

        let fde = *(*cli).fds.add(fd as usize);
        let mut rev: u32 = 0;

        match fde.fd_type {
            FD_TYPE_FILE | FD_TYPE_DIR => {
                if events & 0x001 != 0 {
                    rev |= 0x001;
                }
                if events & 0x004 != 0 {
                    rev |= 0x004;
                }
            }
            FD_TYPE_DEVICE => {
                if fde.dev_type == DEV_PTY_SLAVE {
                    // Query ttyd for PTY readiness
                    let mut treq = TronaMsg::zeroed();
                    let mut treply = TronaMsg::zeroed();
                    treq.label = TTYD_PTY_POLL;
                    treq.regs[0] = fde.sock_id as u64; // pty_id
                    treq.regs[1] = events as u64;
                    treq.length = 2;
                    let err =
                        ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                    if err == 0 && treply.label == TRONA_OK {
                        rev = treply.regs[0] as u32;
                    }
                } else {
                    if events & 0x004 != 0 {
                        rev |= 0x004;
                    }
                    if events & 0x001 != 0 {
                        rev |= 0x001;
                    }
                }
            }
            FD_TYPE_SOCKET => {
                let sock = find_socket(fde.sock_id);
                if !sock.is_null() && (*sock).state == SOCK_CONNECTED {
                    if events & 0x001 != 0 {
                        if sock_buf_len(sock) > 0 || (*sock).peer_closed != 0 {
                            rev |= 0x001;
                        }
                    }
                    if events & 0x004 != 0 {
                        let peer = find_socket((*sock).peer_sock_id);
                        if !peer.is_null() && sock_buf_free(peer) > 0 {
                            rev |= 0x004;
                        }
                    }
                    if (*sock).peer_closed != 0 {
                        rev |= 0x010;
                    }
                } else if !sock.is_null() && (*sock).state == SOCK_LISTENING {
                    if events & 0x001 != 0 && (*sock).pending_count > 0 {
                        rev |= 0x001;
                    }
                }
            }
            FD_TYPE_PIPE => {
                let pipe = find_pipe(fde.pipe_id());
                if !pipe.is_null() {
                    let is_read = (fde.flags & O_ACCMODE) == 0;
                    if is_read {
                        if events & 0x001 != 0 && pipe_buf_len(pipe) > 0 {
                            rev |= 0x001;
                        }
                        if (*pipe).write_refcount == 0 {
                            rev |= 0x010;
                        }
                    } else {
                        if events & 0x004 != 0 && pipe_buf_free(pipe) > 0 {
                            rev |= 0x004;
                        }
                        if (*pipe).read_refcount == 0 {
                            rev |= 0x008;
                        }
                    }
                }
            }
            FD_TYPE_INET_SOCKET => {
                // Query netsrv for inet socket readiness
                let mut nreq = TronaMsg::zeroed();
                let mut nreply = TronaMsg::zeroed();
                nreq.label = NET_POLL_STATUS;
                nreq.regs[0] = fde.sock_id as u64;
                nreq.regs[1] = events as u64;
                nreq.length = 2;
                let err = ipc::call_ctx(
                    ipc_ctx(),
                    VFS_CAP_NETSRV_EP,
                    &raw const nreq,
                    &raw mut nreply,
                );
                if err == 0 && nreply.label == TRONA_OK {
                    rev = nreply.regs[0] as u32;
                }
            }
            _ => {
                return 0x020; // POLLNVAL
            }
        }

        rev
    }
}

pub(crate) unsafe fn handle_epoll_create(reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Find free epoll instance
        let mut epoll_idx: i32 = -1;
        for i in 0..max_epoll_instances() {
            if EPOLLS!()[i].active == 0 {
                epoll_idx = i as i32;
                break;
            }
        }
        if epoll_idx < 0 {
            // No free slot: grow the pool and retry
            if vfs_grow_pool(
                &raw mut EPOLLS_PTR as *mut *mut u8,
                &raw mut EPOLLS_CAP,
                core::mem::size_of::<EpollInstance>(),
            ) != 0
            {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
            // Retry scan from old_cap
            for i in 0..max_epoll_instances() {
                if EPOLLS!()[i].active == 0 {
                    epoll_idx = i as i32;
                    break;
                }
            }
            if epoll_idx < 0 {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        // Find free fd
        let mut fd: i32 = -1;
        for i in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(i)).active == 0 {
                fd = i as i32;
                break;
            }
        }
        if fd < 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Init epoll instance
        EPOLLS!()[epoll_idx as usize].active = 1;
        EPOLLS!()[epoll_idx as usize].owner_badge = badge;
        // Allocate entries array if not yet allocated
        if EPOLLS!()[epoll_idx as usize].entries.is_null() {
            let ptr = vfs_alloc_array::<EpollEntry>(INITIAL_EPOLL_ENTRIES);
            if ptr.is_null() {
                EPOLLS!()[epoll_idx as usize].active = 0;
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
            EPOLLS!()[epoll_idx as usize].entries = ptr;
            EPOLLS!()[epoll_idx as usize].entries_cap = INITIAL_EPOLL_ENTRIES as u16;
        }
        for j in 0..EPOLLS!()[epoll_idx as usize].entries_cap as usize {
            (*EPOLLS!()[epoll_idx as usize].entries.add(j)).active = 0;
        }

        // Init fd entry
        (*(*cli).fds.add(fd as usize)).active = 1;
        (*(*cli).fds.add(fd as usize)).fd_type = FD_TYPE_EPOLL;
        (*(*cli).fds.add(fd as usize)).sock_id = epoll_idx as u32; // reuse sock_id for epoll index
        (*(*cli).fds.add(fd as usize)).inode = 0;
        (*(*cli).fds.add(fd as usize)).offset = 0;
        (*(*cli).fds.add(fd as usize)).flags = 0;

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

pub(crate) unsafe fn handle_epoll_ctl(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let epfd = (*msg).regs[0] as i32;
        let op = (*msg).regs[1] as i32;
        let fd = (*msg).regs[2] as i32;
        let events = (*msg).regs[3] as u32;
        let data = (*msg).regs[4];

        let cli = get_client(badge);
        if cli.is_null()
            || epfd < 0
            || epfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(epfd as usize)).active == 0
            || (*(*cli).fds.add(epfd as usize)).fd_type != FD_TYPE_EPOLL
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let ep_idx = (*(*cli).fds.add(epfd as usize)).sock_id as usize;
        if ep_idx >= max_epoll_instances() || EPOLLS!()[ep_idx].active == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Validate target fd
        if fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let ep = &mut EPOLLS!()[ep_idx];

        match op {
            1 => {
                // EPOLL_CTL_ADD
                // Check not already present
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active != 0 && (*ep.entries.add(i)).fd == fd {
                        (*reply).label = TRONA_INVALID_ARGUMENT; // EEXIST
                        return;
                    }
                }
                // Find free slot
                let mut slot: i32 = -1;
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active == 0 {
                        slot = i as i32;
                        break;
                    }
                }
                if slot < 0 {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
                (*ep.entries.add(slot as usize)).active = 1;
                (*ep.entries.add(slot as usize)).fd = fd;
                (*ep.entries.add(slot as usize)).events = events;
                (*ep.entries.add(slot as usize)).data = data;
            }
            2 => {
                // EPOLL_CTL_DEL
                let mut found = false;
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active != 0 && (*ep.entries.add(i)).fd == fd {
                        (*ep.entries.add(i)).active = 0;
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
                // EPOLL_CTL_MOD
                let mut found = false;
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active != 0 && (*ep.entries.add(i)).fd == fd {
                        (*ep.entries.add(i)).events = events;
                        (*ep.entries.add(i)).data = data;
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
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let epfd = (*msg).regs[0] as i32;
        let max_events = (*msg).regs[1] as usize;
        let timeout = (*msg).regs[2] as i32;

        let cli = get_client(badge);
        if cli.is_null()
            || epfd < 0
            || epfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(epfd as usize)).active == 0
            || (*(*cli).fds.add(epfd as usize)).fd_type != FD_TYPE_EPOLL
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let ep_idx = (*(*cli).fds.add(epfd as usize)).sock_id as usize;
        if ep_idx >= max_epoll_instances() || EPOLLS!()[ep_idx].active == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let ep = &EPOLLS!()[ep_idx];
        let cap = if max_events > 8 { 8 } else { max_events };
        let mut ready_count: usize = 0;

        // Check readiness for each entry in the interest list
        for i in 0..(*ep).entries_cap as usize {
            if (*ep.entries.add(i)).active == 0 {
                continue;
            }
            if ready_count >= cap {
                break;
            }

            let rev = check_fd_readiness(cli, (*ep.entries.add(i)).fd, (*ep.entries.add(i)).events);
            if rev != 0 {
                // Pack: regs[1 + ready*2] = events, regs[2 + ready*2] = data
                (*reply).regs[1 + ready_count * 2] = rev as u64;
                (*reply).regs[2 + ready_count * 2] = (*ep.entries.add(i)).data;
                ready_count += 1;
            }
        }

        if ready_count > 0 || timeout == 0 {
            (*reply).label = TRONA_OK;
            (*reply).regs[0] = ready_count as u64;
            (*reply).length = 1 + (ready_count as u64 * 2);
            return false;
        }

        // Blocking: use poll waiter infrastructure
        let slot = alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        // Build a synthetic poll waiter from epoll entries
        let mut found = false;
        let mut waiter_idx = 0usize;
        for w in 0..max_poll_waiters() {
            if POLL_WAITERS!()[w].active == 0 {
                POLL_WAITERS!()[w].active = 1;
                POLL_WAITERS!()[w].kind = POLL_WAITER_KIND_EPOLL;
                POLL_WAITERS!()[w].badge = badge;
                POLL_WAITERS!()[w].reply_slot = slot;
                POLL_WAITERS!()[w].deadline_ns = timeout_deadline_ns(timeout);
                let mut n: u8 = 0;
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active == 0 || n >= 8 {
                        continue;
                    }
                    POLL_WAITERS!()[w].fds[n as usize].0 = (*ep.entries.add(i)).fd;
                    POLL_WAITERS!()[w].fds[n as usize].1 = (*ep.entries.add(i)).events as u16;
                    POLL_WAITERS!()[w].data[n as usize] = (*ep.entries.add(i)).data;
                    n += 1;
                }
                POLL_WAITERS!()[w].nfds = n;
                found = true;
                waiter_idx = w;
                break;
            }
        }

        if !found {
            let mut err_reply = TronaMsg::zeroed();
            err_reply.label = TRONA_OUT_OF_MEMORY;
            ipc::send_ctx(ipc_ctx(), slot, &raw const err_reply);
        }

        if found && try_deliver_ready_waiter(cli, waiter_idx) {
            return true;
        }

        true // deferred
    }
}

pub(crate) unsafe fn handle_poll(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) -> bool {
    unsafe {
        let nfds = (*msg).regs[0] as u32;
        let timeout = (*msg).regs[1] as i32;
        let actual_nfds = if nfds > 8 { 8 } else { nfds };

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let mut ready_count: i32 = 0;
        let mut revents_arr: [u16; 8] = [0; 8];

        for i in 0..actual_nfds as usize {
            let pfd = (*msg).regs[2 + i * 2] as i32;
            let events = (*msg).regs[2 + i * 2 + 1] as u16;

            if pfd < 0
                || pfd >= (*cli).fds_cap as i32
                || (*(*cli).fds.add(pfd as usize)).active == 0
            {
                revents_arr[i] = 0x020; // POLLNVAL
                ready_count += 1;
                continue;
            }

            let rev = check_fd_readiness(cli, pfd, events as u32) as u16;
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

        // Block — register poll waiter
        let slot = alloc_reply_slot();
        let err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let mut found = false;
        let mut waiter_idx = 0usize;
        for i in 0..max_poll_waiters() {
            if POLL_WAITERS!()[i].active == 0 {
                POLL_WAITERS!()[i].active = 1;
                POLL_WAITERS!()[i].kind = POLL_WAITER_KIND_POLL;
                POLL_WAITERS!()[i].badge = badge;
                POLL_WAITERS!()[i].reply_slot = slot;
                POLL_WAITERS!()[i].deadline_ns = timeout_deadline_ns(timeout);
                POLL_WAITERS!()[i].nfds = actual_nfds as u8;
                for j in 0..actual_nfds as usize {
                    POLL_WAITERS!()[i].fds[j].0 = (*msg).regs[2 + j * 2] as i32;
                    POLL_WAITERS!()[i].fds[j].1 = (*msg).regs[2 + j * 2 + 1] as u16;
                    POLL_WAITERS!()[i].data[j] = 0;
                }
                found = true;
                waiter_idx = i;
                break;
            }
        }

        if !found {
            // No free waiter slot: grow and retry
            if vfs_grow_pool(
                &raw mut POLL_WAITERS_PTR as *mut *mut u8,
                &raw mut POLL_WAITERS_CAP,
                core::mem::size_of::<PollWaiter>(),
            ) == 0
            {
                for i in 0..max_poll_waiters() {
                    if POLL_WAITERS!()[i].active == 0 {
                        POLL_WAITERS!()[i].active = 1;
                        POLL_WAITERS!()[i].kind = POLL_WAITER_KIND_POLL;
                        POLL_WAITERS!()[i].badge = badge;
                        POLL_WAITERS!()[i].reply_slot = slot;
                        POLL_WAITERS!()[i].deadline_ns = timeout_deadline_ns(timeout);
                        POLL_WAITERS!()[i].nfds = actual_nfds as u8;
                        for j in 0..actual_nfds as usize {
                            POLL_WAITERS!()[i].fds[j].0 = (*msg).regs[2 + j * 2] as i32;
                            POLL_WAITERS!()[i].fds[j].1 = (*msg).regs[2 + j * 2 + 1] as u16;
                            POLL_WAITERS!()[i].data[j] = 0;
                        }
                        found = true;
                        waiter_idx = i;
                        break;
                    }
                }
            }
            if !found {
                // Still no slot — reply with error via saved cap
                let mut err_reply = TronaMsg::zeroed();
                err_reply.label = TRONA_OUT_OF_MEMORY;
                ipc::send_ctx(ipc_ctx(), slot, &raw const err_reply);
            }
        }

        if found && try_deliver_ready_waiter(cli, waiter_idx) {
            return true;
        }

        if found && *(&raw const LOGGED_POLL_REGISTRATIONS) < 32 {
            *(&raw mut LOGGED_POLL_REGISTRATIONS) += 1;
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] poll wait badge=");
                _lb.hex(badge);
                _lb.str(b" nfds=");
                _lb.dec(actual_nfds as u64);
                _lb.str(b" timeout=");
                _lb.dec(timeout as u64);
                for j in 0..actual_nfds as usize {
                    _lb.str(b" fd[");
                    _lb.dec(j as u64);
                    _lb.str(b"]=");
                    _lb.dec((*msg).regs[2 + j * 2] as u64);
                    _lb.str(b"/");
                    _lb.hex((*msg).regs[2 + j * 2 + 1]);
                }
                _lb.putc(b'\n');
            });
        }

        true // deferred (already replied via saved cap)
    }
}
