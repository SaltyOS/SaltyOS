// SPDX-License-Identifier: GPL-2.0-only
//! POSIX file descriptor operations — dup, dup2, dup3, clone_fds.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::server::types::*;

unsafe fn rollback_cloned_child(
    state: &mut VfsState,
    child_handle: ClientHandle,
    child_badge: u64,
    parent_cwd_ref: crate::vfs_core::cached_ref::CachedRef<
        crate::vfs_core::identity::VnodeKey,
        crate::vfs_core::vnode::VnodeHandle,
    >,
    parent_mount_ns: crate::vfs_core::mount_ns::MountNsHandle,
) {
    unsafe {
        super::dispatch::cleanup_client_objects(state, child_handle, child_badge);

        let parent_cwd_vh = parent_cwd_ref.handle_hint();
        if parent_cwd_vh.is_valid() {
            if let Some(vn) = state.vnodes.get_mut(parent_cwd_vh) {
                vn.unpin();
            }
        }

        if parent_mount_ns.is_valid() {
            let mut should_release = false;
            if let Some(ns) = state.mount_ns.get_mut(parent_mount_ns) {
                ns.refcount = ns.refcount.saturating_sub(1);
                should_release = ns.refcount == 0 && parent_mount_ns != state.global_ns;
            }
            if should_release {
                let _ = state.mount_ns.release(parent_mount_ns);
            }
        }

        state.badge_map.remove(child_badge);
        let _ = state.clients.release(child_handle);
    }
}

/// Look up the `OpenObject` handle backing `(cli_handle, fd)`, or
/// return `None` if the slot is stale / out of range.
unsafe fn oldfd_src_handle(
    state: &VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) -> Option<crate::server::open_object::OpenObjectHandle> {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return None;
    }
    let cli = state.clients.get(cli_handle)?;
    let r = cli.slots[fd as usize];
    if r.is_free() {
        return None;
    }
    Some(r.open_object)
}

fn client_badge(state: &VfsState, cli_handle: ClientHandle) -> u64 {
    state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0)
}

pub(crate) unsafe fn handle_dup(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let Some(src_handle) = oldfd_src_handle(state, cli_handle, oldfd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let cli = match state.clients.get(cli_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let mut newfd: i32 = -1;
        for i in 0..MAX_CLIENT_OBJECTS {
            if cli.slots[i].is_free() {
                newfd = i as i32;
                break;
            }
        }
        if newfd < 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let badge = client_badge(state, cli_handle);
        if state
            .slot_share(cli_handle, newfd as usize, src_handle, 0, badge)
            .is_none()
        {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

pub(crate) unsafe fn handle_dup2(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let newfd = (*msg).regs[1] as i32;

        if newfd < 0 || newfd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(src_handle) = oldfd_src_handle(state, cli_handle, oldfd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        // POSIX dup2(oldfd, newfd) with oldfd == newfd is a no-op
        // once oldfd is valid — short-circuit before `slot_share`
        // would otherwise evict the very slot we are about to
        // install.
        if oldfd == newfd {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = newfd as u64;
            return;
        }

        let badge = client_badge(state, cli_handle);
        if state
            .slot_share(cli_handle, newfd as usize, src_handle, 0, badge)
            .is_none()
        {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

pub(crate) unsafe fn handle_dup3(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let newfd = (*msg).regs[1] as i32;
        let flags = (*msg).regs[2] as u32;

        if newfd < 0 || newfd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        if oldfd == newfd {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(src_handle) = oldfd_src_handle(state, cli_handle, oldfd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };

        let cloexec = if (flags & O_CLOEXEC) != 0 { 1 } else { 0 };
        let badge = client_badge(state, cli_handle);
        if state
            .slot_share(cli_handle, newfd as usize, src_handle, cloexec, badge)
            .is_none()
        {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

/// Clone all fds from parent to child process.
pub(crate) unsafe fn handle_clone_fds(
    state: &mut VfsState,
    _cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let parent_badge = (*msg).regs[0];
        let child_badge = (*msg).regs[1];

        // Parent may not have touched VFS yet. In that case there is no
        // client-state to clone, and fork should still succeed with an empty
        // child VFS state that will auto-register on first real VFS use.
        let parent_handle = match state.badge_map.lookup(parent_badge) {
            Some((slot, epoch)) => {
                let h = ClientHandle::new(slot, epoch);
                if state.clients.is_alive(h) {
                    Some(h)
                } else {
                    state.badge_map.remove(parent_badge);
                    None
                }
            }
            None => None,
        };
        let Some(parent_handle) = parent_handle else {
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
            return;
        };

        // Look up or register child client.
        let child_handle = match state.badge_map.lookup(child_badge) {
            Some((slot, epoch)) => {
                let h = ClientHandle::new(slot, epoch);
                if state.clients.is_alive(h) {
                    h
                } else {
                    match state.alloc_client_slot(b"clone_fds/revive_child") {
                        Some(h2) => {
                            if let Some(c) = state.clients.get_mut(h2) {
                                *c = ClientState::zeroed();
                                c.badge = child_badge;
                                c.mount_ns = state.global_ns;
                                c.cwd[0] = b'/';
                            }
                            if state
                                .badge_map
                                .insert(child_badge, h2.slot(), h2.epoch())
                                .is_err()
                            {
                                trona_runtime::uwarn!(|_lb| {
                                    _lb.str(b"[VFS] badge-map insert failed ctx=clone_fds/revive_child badge=");
                                    _lb.hex(child_badge);
                                    _lb.str(b" len=");
                                    _lb.dec(state.badge_map.len() as u64);
                                    _lb.str(b" cap=");
                                    _lb.dec(state.badge_map.capacity() as u64);
                                    _lb.str(b"\n");
                                });
                                let _ = state.clients.release(h2);
                                state.clients.sweep();
                                (*reply).label = TRONA_OUT_OF_MEMORY;
                                return;
                            }
                            h2
                        }
                        None => {
                            (*reply).label = TRONA_OUT_OF_MEMORY;
                            return;
                        }
                    }
                }
            }
            None => match state.alloc_client_slot(b"clone_fds/new_child") {
                Some(h) => {
                    if let Some(c) = state.clients.get_mut(h) {
                        *c = ClientState::zeroed();
                        c.badge = child_badge;
                        c.mount_ns = state.global_ns;
                        c.cwd[0] = b'/';
                    }
                    if state
                        .badge_map
                        .insert(child_badge, h.slot(), h.epoch())
                        .is_err()
                    {
                        trona_runtime::uwarn!(|_lb| {
                            _lb.str(
                                b"[VFS] badge-map insert failed ctx=clone_fds/new_child badge=",
                            );
                            _lb.hex(child_badge);
                            _lb.str(b" len=");
                            _lb.dec(state.badge_map.len() as u64);
                            _lb.str(b" cap=");
                            _lb.dec(state.badge_map.capacity() as u64);
                            _lb.str(b"\n");
                        });
                        let _ = state.clients.release(h);
                        state.clients.sweep();
                        (*reply).label = TRONA_OUT_OF_MEMORY;
                        return;
                    }
                    h
                }
                None => {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            },
        };

        // Snapshot parent fields.
        let (
            parent_personality,
            parent_cwd_ref,
            parent_mount_ns,
            cwd_copy,
            parent_cred_uid,
            parent_cred_gid,
            parent_cred_groups,
            parent_cred_ngroups,
            parent_creds_valid,
            parent_bulk_shm_vaddr,
            parent_bulk_shm_id,
        ) = match state.clients.get(parent_handle) {
            Some(parent) => {
                let mut cwd = [0u8; 128];
                cwd.copy_from_slice(&parent.cwd);
                (
                    parent.personality,
                    parent.cwd_ref,
                    parent.mount_ns,
                    cwd,
                    parent.cred_uid,
                    parent.cred_gid,
                    parent.cred_groups,
                    parent.cred_ngroups,
                    parent.creds_valid,
                    parent.bulk_shm_vaddr,
                    parent.bulk_shm_id,
                )
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        if parent_mount_ns.is_valid() {
            if let Some(ns) = state.mount_ns.get_mut(parent_mount_ns) {
                ns.refcount = ns.refcount.saturating_add(1);
            }
        }

        // Reset child scalars and slot table (no obj_count here —
        // `slot_install` bumps it per live parent slot below).
        {
            let child = match state.clients.get_mut(child_handle) {
                Some(c) => c,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            };
            for i in 0..MAX_CLIENT_OBJECTS {
                child.slots[i] = crate::server::open_object::ObjectRef::empty();
            }
            child.personality = parent_personality;
            child.obj_count = 0;
            child.cwd_ref = parent_cwd_ref;
            child.mount_ns = parent_mount_ns;
            child.cwd = cwd_copy;
            child.cred_uid = parent_cred_uid;
            child.cred_gid = parent_cred_gid;
            child.cred_groups = parent_cred_groups;
            child.cred_ngroups = parent_cred_ngroups;
            child.creds_valid = parent_creds_valid;
            child.bulk_shm_vaddr = parent_bulk_shm_vaddr;
            child.bulk_shm_id = parent_bulk_shm_id;
        }
        // Independently pin the inherited cwd on behalf of the child
        // so the handle survives parent exit + saltyfs churn until the
        // child itself exits or chdirs.
        let parent_cwd_vh = parent_cwd_ref.handle_hint();
        if parent_cwd_vh.is_valid() {
            if let Some(vn) = state.vnodes.get_mut(parent_cwd_vh) {
                vn.pin();
            }
        }

        // Share each live parent OpenObject into the same child slot.
        // Per-slot refcount++ — the same underlying OFD is observed
        // by parent and child, matching POSIX fork() semantics
        // (offset / flags / arbitration hold follow the OFD, not the
        // fd). Child `cloexec` is inherited from the parent slot.
        let child_badge_for_share = state
            .clients
            .get(child_handle)
            .map(|c| c.badge)
            .unwrap_or(child_badge);
        for i in 0..MAX_CLIENT_OBJECTS {
            let (src_handle, parent_cloexec) = {
                let cli = match state.clients.get(parent_handle) {
                    Some(c) => c,
                    None => break,
                };
                let r = cli.slots[i];
                if r.is_free() {
                    continue;
                }
                (r.open_object, r.cloexec)
            };
            if state
                .slot_share(
                    child_handle,
                    i,
                    src_handle,
                    parent_cloexec,
                    child_badge_for_share,
                )
                .is_none()
            {
                rollback_cloned_child(
                    state,
                    child_handle,
                    child_badge,
                    parent_cwd_ref,
                    parent_mount_ns,
                );
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        (*reply).label = TRONA_OK;
    }
}
