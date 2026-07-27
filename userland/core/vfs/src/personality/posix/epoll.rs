// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_EPOLL_CREATE` / `VFS_EPOLL_CTL` / `VFS_EPOLL_WAIT` —
//! Linux-style epoll instance management.
//!
//! An epoll instance is an [`EpollInstance`] arena entry; it owns
//! a fixed-stride table of registered fds (`(fd, events_mask,
//! user_data)` triples) and pins those fds via [`OpenObject`]
//! refcount so that `close()` against an fd does not silently
//! evict it from a watching epoll set.
//!
//! Wait semantics:
//!
//! * `VFS_EPOLL_CREATE` allocates the instance and returns an fd
//!   pointing at a synthetic vnode whose [`VnodeKind`] is
//!   [`VnodeKind::EpollEvent`]. The vnode's `personality_aux`
//!   field stores the epoll arena index.
//! * `VFS_EPOLL_CTL(EPOLL_CTL_ADD / MOD / DEL)` mutates the
//!   instance's registration table. Adding bumps the watched
//!   fd's `OpenObject` refcount; `EPOLL_CTL_DEL` drops it.
//! * `VFS_EPOLL_WAIT` walks the instance's registrations, computes
//!   each fd's current readiness via the same code path as
//!   [`crate::personality::posix::poll`], and either returns the ready set or
//!   parks the caller on the per-instance wait queue. The wakeup
//!   driver advances the queue whenever any registered fd's
//!   readiness changes — which the per-fd wait queues already
//!   notify — so a single advance can wake multiple parked
//!   epoll waiters.
//!
//! Wire layout:
//! - `VFS_EPOLL_CREATE`: `regs[0]` = `flags` (`EPOLL_CLOEXEC`).
//!   Reply `regs[0] = fd`.
//! - `VFS_EPOLL_CTL`: `regs[0]` = epfd, `regs[1]` = op
//!   (`EPOLL_CTL_ADD/MOD/DEL`), `regs[2]` = target_fd, `regs[3]` =
//!   events_mask, `regs[4]` = user_data. Reply: empty on success.
//! - `VFS_EPOLL_WAIT`: `regs[0]` = epfd, `regs[1]` = max_events
//!   (clamped to inline cap), `regs[2]` = `timeout_ns`. Reply
//!   `regs[0] = ready_count`, `regs[1..1 + 3*ready_count]` triples
//!   `(fd, events, user_data)`.

use trona_kernel::core_types::TronaMsg;

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::vnode::VnodeKind;
use crate::owner::VfsState;
use crate::personality::posix::types::{EpollEvent, EpollInstance};
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::open_object::{OpenObject, OpenObjectAccess, OpenObjectFlags, OpenObjectKind};
use crate::server::types::ClientHandle;
use trona_protocol::vfs::public::{
    VFS_EPOLL_CREATE, VFS_EPOLL_CTL, VFS_EPOLL_WAIT, VFS_PUBLIC_REPLY_OK,
};

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;

const EPOLL_CLOEXEC: u64 = 0o2_000_000;

const EPOLL_INLINE_MAX: usize = 10;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        match msg.label {
            VFS_EPOLL_CREATE => handle_create(state, client, msg, reply_lease),
            VFS_EPOLL_CTL => handle_ctl(state, client, msg, reply_lease),
            VFS_EPOLL_WAIT => handle_wait(state, client, msg, reply_lease),
            _ => send_reply_err_for_client(state, client, reply_lease, VfsError::Inval),
        }
    }
}

unsafe fn handle_create(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let flags = msg.regs[0];
    let cloexec = (flags & EPOLL_CLOEXEC) != 0;

    let inst_h = match state.epolls.alloc() {
        Some(h) => h,
        None => return send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem),
    };
    if let Some(inst) = state.epolls.get_mut(inst_h) {
        *inst = EpollInstance::zeroed();
        inst.active = 1;
    }

    let obj_h = match state.open_objects.alloc() {
        Some(h) => h,
        None => {
            let _ = state.epolls.release(inst_h);
            return send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
        }
    };
    if let Some(obj) = state.open_objects.get_mut(obj_h) {
        *obj = OpenObject::EMPTY;
        obj.refcount = 1;
        obj.kind = OpenObjectKind::Epoll;
        obj.personality_aux = inst_h.slot();
        obj.flags = OpenObjectFlags::READABLE;
        obj.access = OpenObjectAccess::READ;
        obj.share = crate::ops::SharePolicy::permissive().bits();
    }

    let cli = match state.clients.get_mut(client) {
        Some(c) => c,
        None => {
            let _ = state.open_objects.release(obj_h);
            let _ = state.epolls.release(inst_h);
            return send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
        }
    };
    let fd = match cli.slot_table.find_first_empty_from(0) {
        Ok(f) => f,
        Err(_) => {
            let _ = state.open_objects.release(obj_h);
            let _ = state.epolls.release(inst_h);
            return send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
        }
    };
    if cli.slot_table.set(fd, obj_h).is_err() {
        let _ = state.open_objects.release(obj_h);
        let _ = state.epolls.release(inst_h);
        return send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
    }
    if cloexec {
        cli.slot_table.set_slot_flag_bit(
            fd,
            crate::personality::posix::consts::POSIX_FD_CLOEXEC,
            true,
        );
    }
    send_reply_ok_for_client(state, client, reply_lease, &[fd as u64]);
}

unsafe fn handle_ctl(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let epfd = msg.regs[0] as i32;
    let op = msg.regs[1];
    let target_fd = msg.regs[2] as i32;
    let events = msg.regs[3] as u32;
    let user_data = msg.regs[4];

    let inst_h = match resolve_epoll(state, client, epfd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let target_obj_h = match resolve_target_open_object(state, client, target_fd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };

    match op {
        EPOLL_CTL_ADD => {
            let inst = state.epolls.get_mut(inst_h).ok_or(VfsError::Io);
            let inst = match inst {
                Ok(i) => i,
                Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
            };
            if inst.count as usize >= inst.entries.len() {
                return send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            }
            for i in 0..inst.count as usize {
                if inst.entries[i].target_obj_slot == target_obj_h.slot() {
                    return send_reply_err_for_client(state, client, reply_lease, VfsError::Exist);
                }
            }
            let idx = inst.count as usize;
            inst.entries[idx].target_obj_slot = target_obj_h.slot();
            inst.entries[idx].target_obj_epoch = target_obj_h.epoch();
            inst.entries[idx].events_mask = events;
            inst.entries[idx].user_data = user_data;
            inst.count += 1;
            crate::ops::dup::bump_open_object_refcount(state, target_obj_h);
            send_reply_ok_for_client(state, client, reply_lease, &[]);
        }
        EPOLL_CTL_MOD => {
            let inst = match state.epolls.get_mut(inst_h) {
                Some(i) => i,
                None => return send_reply_err_for_client(state, client, reply_lease, VfsError::Io),
            };
            for i in 0..inst.count as usize {
                if inst.entries[i].target_obj_slot == target_obj_h.slot() {
                    inst.entries[i].events_mask = events;
                    inst.entries[i].user_data = user_data;
                    return send_reply_ok_for_client(state, client, reply_lease, &[]);
                }
            }
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoEnt);
        }
        EPOLL_CTL_DEL => {
            let inst = match state.epolls.get_mut(inst_h) {
                Some(i) => i,
                None => return send_reply_err_for_client(state, client, reply_lease, VfsError::Io),
            };
            let mut idx = None;
            for i in 0..inst.count as usize {
                if inst.entries[i].target_obj_slot == target_obj_h.slot() {
                    idx = Some(i);
                    break;
                }
            }
            let removed_idx = match idx {
                Some(i) => i,
                None => {
                    return send_reply_err_for_client(state, client, reply_lease, VfsError::NoEnt);
                }
            };
            // Compact the table (entries are unordered so swap-with-last suffices).
            let last = inst.count as usize - 1;
            inst.entries[removed_idx] = inst.entries[last];
            inst.count -= 1;
            crate::ops::dup::release_open_object(state, target_obj_h);
            send_reply_ok_for_client(state, client, reply_lease, &[]);
        }
        _ => send_reply_err_for_client(state, client, reply_lease, VfsError::Inval),
    }
}

unsafe fn handle_wait(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let epfd = msg.regs[0] as i32;
    let max_events = msg.regs[1] as usize;
    let _timeout_ns = msg.regs[2];
    let inst_h = match resolve_epoll(state, client, epfd) {
        Ok(h) => h,
        Err(e) => return send_reply_err_for_client(state, client, reply_lease, e),
    };
    let cap = ::core::cmp::min(max_events, EPOLL_INLINE_MAX);

    // Compute readiness for each registration. Today the wait
    // arm runs synchronously: parking would require a per-instance
    // wait queue and netsrv / unix-socket notifications to
    // promote it. The synchronous arm satisfies poll(2)-style
    // callers that supply timeout 0; callers that pass a non-zero
    // timeout receive whatever events happen to be ready right
    // now and must retry.

    let inst = match state.epolls.get(inst_h) {
        Some(i) => i,
        None => return send_reply_err_for_client(state, client, reply_lease, VfsError::Io),
    };
    let mut ready: [(u32, EpollEvent); EPOLL_INLINE_MAX] =
        [(0, EpollEvent::default()); EPOLL_INLINE_MAX];
    let mut ready_count = 0usize;
    for i in 0..inst.count as usize {
        if ready_count >= cap {
            break;
        }
        let entry = inst.entries[i];
        let target_h: Handle<OpenObject> =
            Handle::new(entry.target_obj_slot, entry.target_obj_epoch);
        let revents = current_obj_revents(state, target_h, entry.events_mask);
        if revents != 0 {
            // Translate the OpenObjectHandle back to a fd in the
            // caller's slot table so the caller sees a stable fd.
            let fd = locate_fd_for_obj(state, client, target_h).unwrap_or(u32::MAX);
            ready[ready_count] = (
                fd,
                EpollEvent {
                    events: revents,
                    data: entry.user_data,
                },
            );
            ready_count += 1;
        }
    }

    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[0] = ready_count as u64;
    for i in 0..ready_count {
        let base = 1 + i * 3;
        let fd = ready[i].0;
        let event = ready[i].1;
        out.regs[base] = fd as u64;
        out.regs[base + 1] = event.events as u64;
        out.regs[base + 2] = event.data;
    }
    out.length = (1 + ready_count * 3) as u64;
    crate::owner::op::reply_send(reply_lease, &out);
}

fn resolve_epoll(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<Handle<EpollInstance>, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get(client).ok_or(VfsError::Io)?;
    let oh = cli.slot_table.lookup(fd as u32).ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(oh).ok_or(VfsError::BadF)?;
    if obj.vnode.is_valid() {
        return Err(VfsError::Inval);
    }
    state
        .epolls
        .handle_from_slot(obj.personality_aux)
        .ok_or(VfsError::Inval)
}

fn resolve_target_open_object(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<Handle<OpenObject>, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get(client).ok_or(VfsError::Io)?;
    let oh = cli.slot_table.lookup(fd as u32).ok_or(VfsError::BadF)?;
    Ok(oh)
}

fn locate_fd_for_obj(
    state: &VfsState,
    client: ClientHandle,
    obj: Handle<OpenObject>,
) -> Option<u32> {
    let cli = state.clients.get(client)?;
    let mut found = None;
    cli.slot_table.iter_active(|fd, h| {
        if h == obj {
            found = Some(fd);
            false
        } else {
            true
        }
    });
    found
}

fn current_obj_revents(state: &VfsState, obj_h: Handle<OpenObject>, events_mask: u32) -> u32 {
    let obj = match state.open_objects.get(obj_h) {
        Some(o) => o,
        None => return 0,
    };
    let kind = state
        .vnodes
        .get(obj.vnode)
        .map(|v| v.kind)
        .unwrap_or(VnodeKind::Empty);
    let mut revents: u32 = 0;
    const EPOLLIN: u32 = 0x001;
    const EPOLLOUT: u32 = 0x004;
    match kind {
        VnodeKind::Pipe | VnodeKind::Fifo => {
            let h = match state.pipes.handle_from_slot(obj.personality_aux) {
                Some(h) => h,
                None => return 0,
            };
            if (events_mask & EPOLLIN) != 0
                && state
                    .pipes
                    .get(h)
                    .map(|p| p.data_head != p.data_tail)
                    .unwrap_or(false)
            {
                revents |= EPOLLIN;
            }
        }
        VnodeKind::Socket => {
            let h = match state.sockets.handle_from_slot(obj.personality_aux) {
                Some(h) => h,
                None => return 0,
            };
            if (events_mask & EPOLLIN) != 0
                && state
                    .sockets
                    .get(h)
                    .map(|s| s.rx.head != s.rx.tail)
                    .unwrap_or(false)
            {
                revents |= EPOLLIN;
            }
        }
        VnodeKind::Regular | VnodeKind::CharDev => {
            revents |= events_mask & (EPOLLIN | EPOLLOUT);
        }
        _ => {}
    }
    revents
}
