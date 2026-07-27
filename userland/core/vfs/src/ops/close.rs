// SPDX-License-Identifier: GPL-2.0-only
//
//! Close logic helper. POSIX `close` and Win32 close entries. Drops the
//! caller's fd → OpenObject mapping; reaching refcount 0
//! releases the underlying vnode reference.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::server::open_object::OpenObjectKind;
use crate::server::types::{ClientHandle, OpenObjectHandle};

pub(crate) unsafe fn do_close_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        let result = release_fd(state, client, fd);
        crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, result);
    }
}

/// Drop the `(client, fd)` entry from the slot table and
/// decrement the underlying OpenObject's refcount.
pub(crate) fn release_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<(), VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get_mut(client).ok_or(VfsError::Io)?;
    let handle = cli.slot_table.lookup(fd as u32).ok_or(VfsError::BadF)?;
    if cli
        .slot_table
        .set(fd as u32, OpenObjectHandle::INVALID)
        .is_err()
    {
        return Err(VfsError::Io);
    }
    drop_open_object_ref(state, handle);
    Ok(())
}

/// Sweep every `FD_CLOEXEC` fd in `client`'s slot table —
/// driven by the personality `execve` boundary.
pub(crate) fn cloexec_sweep(state: &mut VfsState, client: ClientHandle) {
    sweep_fd_table(state, client, |cli, fd| {
        (cli.slot_table.slot_flags(fd) & crate::server::open_object::FD_FLAG_CLOEXEC) != 0
    });
}

/// Drop every fd owned by `client`. Used by client teardown before
/// the arena slot is reset, so `OpenObject` and vnode refcounts
/// cannot survive a PEER_CLOSED / explicit client-exit path.
pub(crate) fn release_all_fds(state: &mut VfsState, client: ClientHandle) {
    sweep_fd_table(state, client, |_cli, _fd| true);
}

fn sweep_fd_table(
    state: &mut VfsState,
    client: ClientHandle,
    mut should_release: impl FnMut(&crate::owner::clients::ClientState, u32) -> bool,
) {
    use crate::arena::segmented_array::{MmapAllocator, SegmentedArray};

    let mut victims: SegmentedArray<u32> = SegmentedArray::new_empty();
    let mut alloc = MmapAllocator::new();
    {
        let cli = match state.clients.get(client) {
            Some(c) => c,
            None => return,
        };
        if cli.slot_table.capacity() == 0 {
            return;
        }
        cli.slot_table.iter_active(|fd, _| {
            if should_release(cli, fd) {
                unsafe {
                    let _ = victims.push(fd, &mut alloc);
                }
            }
            true
        });
    }
    for entry in victims.iter() {
        let _ = release_fd(state, client, *entry as i32);
    }
}

/// Decrement an OpenObject's refcount. On zero, release the
/// vnode reference or synthetic side arena, then free the arena slot.
pub(crate) fn drop_open_object_ref(state: &mut VfsState, handle: OpenObjectHandle) {
    let finalizer = match state.open_objects.get_mut(handle) {
        Some(obj) => {
            if obj.refcount == 0 {
                return;
            }
            obj.refcount -= 1;
            if obj.refcount == 0 {
                Some((
                    obj.kind,
                    obj.vnode,
                    obj.personality_aux,
                    obj.flags,
                    obj.named_state,
                ))
            } else {
                return;
            }
        }
        None => return,
    };
    if let Some((kind, vnode_h, aux_slot, flags, named_state)) = finalizer {
        match kind {
            OpenObjectKind::Vnode => {
                finalize_vnode_open_object(state, handle, vnode_h, aux_slot, named_state)
            }
            OpenObjectKind::Pipe => finalize_pipe_open_object(state, vnode_h, aux_slot, flags),
            OpenObjectKind::Socket => finalize_socket_open_object(state, aux_slot),
            OpenObjectKind::Shm => finalize_shm_open_object(state, aux_slot),
            OpenObjectKind::Epoll => finalize_epoll_open_object(state, aux_slot),
        }
    }
    state.open_objects.release(handle);
}

fn finalize_vnode_open_object(
    state: &mut VfsState,
    handle: OpenObjectHandle,
    vnode_h: crate::core::vnode::VnodeHandle,
    win32_slot: u32,
    named_h: crate::arena::Handle<crate::server::open_object::OpenObjectNamedState>,
) {
    unsafe {
        crate::ops::lock::release_locks_for_open(state, handle, vnode_h);
    }
    if named_h.is_valid() {
        let named = state.open_object_named_states.get(named_h).copied();
        if let Some(named) = named {
            if named.deferred_unlink != 0 {
                unsafe {
                    crate::ops::unlink_leaf::delete_anchor_on_close(state, named.anchor);
                }
            }
        }
        state.open_object_named_states.release(named_h);
    }
    if win32_slot != u32::MAX {
        crate::personality::win32::open_state::release_by_slot(state, win32_slot);
    }
    if let Some(vn) = state.vnodes.get_mut(vnode_h) {
        vn.open_refcount = vn.open_refcount.saturating_sub(1);
    }
}

fn finalize_pipe_open_object(
    state: &mut VfsState,
    vnode_h: crate::core::vnode::VnodeHandle,
    aux_slot: u32,
    flags: u8,
) {
    let Some(pipe_h) = state.pipes.handle_from_slot(aux_slot) else {
        return;
    };
    if vnode_h.is_valid() {
        unsafe {
            crate::ops::pipe::drop_pipe_open_ref(state, vnode_h, pipe_h, flags);
        }
    }
}

fn finalize_socket_open_object(state: &mut VfsState, aux_slot: u32) {
    let Some(sock_h) = state.sockets.handle_from_slot(aux_slot) else {
        return;
    };
    crate::personality::posix::socket::release_socket(state, sock_h);
}

fn finalize_shm_open_object(state: &mut VfsState, aux_slot: u32) {
    let Some(shm_h) = state.shm_data.handle_from_slot(aux_slot) else {
        return;
    };
    crate::personality::posix::shm::drop_shm_open_ref(state, shm_h);
}

fn finalize_epoll_open_object(state: &mut VfsState, aux_slot: u32) {
    let Some(epoll_h) = state.epolls.handle_from_slot(aux_slot) else {
        return;
    };
    let mut victims: [OpenObjectHandle; crate::personality::posix::types::EPOLL_MAX_INTERESTS] =
        [OpenObjectHandle::INVALID; crate::personality::posix::types::EPOLL_MAX_INTERESTS];
    let mut count = 0usize;
    if let Some(inst) = state.epolls.get_mut(epoll_h) {
        let limit = usize::from(inst.count).min(victims.len());
        for i in 0..limit {
            let entry = inst.entries[i];
            if entry.target_obj_slot != u32::MAX {
                victims[count] =
                    OpenObjectHandle::new(entry.target_obj_slot, entry.target_obj_epoch);
                count += 1;
            }
        }
        *inst = crate::personality::posix::types::EpollInstance::zeroed();
    }
    for handle in victims.iter().take(count) {
        drop_open_object_ref(state, *handle);
    }
    let _ = state.epolls.release(epoll_h);
}
