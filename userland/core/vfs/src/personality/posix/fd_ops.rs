// SPDX-License-Identifier: GPL-2.0-only
//! POSIX file descriptor operations — dup, dup2, dup3, clone_fds.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::server::client::object_open_flags;
use crate::server::types::*;

pub(crate) unsafe fn handle_dup(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        if oldfd < 0 || oldfd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cli = match state.clients.get(cli_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if !cli.objects[oldfd as usize].is_live() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Find a free slot.
        let mut newfd: i32 = -1;
        for i in 0..MAX_CLIENT_OBJECTS {
            if cli.objects[i].is_free() {
                newfd = i as i32;
                break;
            }
        }
        if newfd < 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let src = cli.objects[oldfd as usize];
        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let mut dup_slot = src;
        dup_slot.cloexec = 0;
        cli.obj_count += 1;
        cli.objects[newfd as usize] = dup_slot;

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

        if oldfd < 0
            || oldfd as usize >= MAX_CLIENT_OBJECTS
            || newfd < 0
            || newfd as usize >= MAX_CLIENT_OBJECTS
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cli = match state.clients.get(cli_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if !cli.objects[oldfd as usize].is_live() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if oldfd == newfd {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = newfd as u64;
            return;
        }

        let src = cli.objects[oldfd as usize];

        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if cli.objects[newfd as usize].is_free() {
            cli.obj_count += 1;
        }
        let mut dup_slot = src;
        dup_slot.cloexec = 0;
        cli.objects[newfd as usize] = dup_slot;

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

        if oldfd < 0
            || oldfd as usize >= MAX_CLIENT_OBJECTS
            || newfd < 0
            || newfd as usize >= MAX_CLIENT_OBJECTS
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if oldfd == newfd {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cli = match state.clients.get(cli_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if !cli.objects[oldfd as usize].is_live() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let src = cli.objects[oldfd as usize];

        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if cli.objects[newfd as usize].is_free() {
            cli.obj_count += 1;
        }
        let mut dup_slot = src;
        dup_slot.cloexec = if (flags & O_CLOEXEC) != 0 { 1 } else { 0 };
        cli.objects[newfd as usize] = dup_slot;

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

        // Look up parent client.
        let parent_handle = match state.badge_map.lookup(parent_badge) {
            Some((slot, epoch)) => {
                let h = ClientHandle::new(slot, epoch);
                if state.clients.is_alive(h) {
                    h
                } else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        // Look up or register child client.
        let child_handle = match state.badge_map.lookup(child_badge) {
            Some((slot, epoch)) => {
                let h = ClientHandle::new(slot, epoch);
                if state.clients.is_alive(h) {
                    h
                } else {
                    match state.clients.alloc() {
                        Some(h2) => {
                            if let Some(c) = state.clients.get_mut(h2) {
                                *c = ClientState::zeroed();
                                c.badge = child_badge;
                                c.mount_ns = state.global_ns;
                                c.cwd[0] = b'/';
                            }
                            state.badge_map.insert(child_badge, h2.slot(), h2.epoch());
                            h2
                        }
                        None => {
                            (*reply).label = TRONA_OUT_OF_MEMORY;
                            return;
                        }
                    }
                }
            }
            None => match state.clients.alloc() {
                Some(h) => {
                    if let Some(c) = state.clients.get_mut(h) {
                        *c = ClientState::zeroed();
                        c.badge = child_badge;
                        c.mount_ns = state.global_ns;
                        c.cwd[0] = b'/';
                    }
                    state.badge_map.insert(child_badge, h.slot(), h.epoch());
                    h
                }
                None => {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            },
        };

        // Copy all objects from parent to child.
        let parent = match state.clients.get(parent_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let mut objects_copy = [ObjectSlot::zeroed(); MAX_CLIENT_OBJECTS];
        for i in 0..MAX_CLIENT_OBJECTS {
            objects_copy[i] = parent.objects[i];
        }
        let mut cwd_copy = [0u8; 128];
        cwd_copy.copy_from_slice(&parent.cwd);
        let parent_personality = parent.personality;
        let parent_obj_count = parent.obj_count;
        let parent_cwd_vnode = parent.cwd_vnode;
        let parent_mount_ns = parent.mount_ns;
        let parent_cred_uid = parent.cred_uid;
        let parent_cred_gid = parent.cred_gid;
        let parent_cred_groups = parent.cred_groups;
        let parent_cred_ngroups = parent.cred_ngroups;
        let parent_creds_valid = parent.creds_valid;
        let parent_bulk_shm_vaddr = parent.bulk_shm_vaddr;
        let parent_bulk_shm_id = parent.bulk_shm_id;

        if parent_mount_ns.is_valid() {
            if let Some(ns) = state.mount_ns.get_mut(parent_mount_ns) {
                ns.refcount = ns.refcount.saturating_add(1);
            }
        }

        let child = match state.clients.get_mut(child_handle) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        for i in 0..MAX_CLIENT_OBJECTS {
            child.objects[i] = objects_copy[i];
        }
        child.personality = parent_personality;
        child.obj_count = parent_obj_count;
        child.cwd_vnode = parent_cwd_vnode;
        child.mount_ns = parent_mount_ns;
        child.cwd = cwd_copy;
        child.cred_uid = parent_cred_uid;
        child.cred_gid = parent_cred_gid;
        child.cred_groups = parent_cred_groups;
        child.cred_ngroups = parent_cred_ngroups;
        child.creds_valid = parent_creds_valid;
        child.bulk_shm_vaddr = parent_bulk_shm_vaddr;
        child.bulk_shm_id = parent_bulk_shm_id;

        (*reply).label = TRONA_OK;
    }
}
