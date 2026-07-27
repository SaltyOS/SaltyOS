// SPDX-License-Identifier: GPL-2.0-only
//
//! `fork_clone` — copy a parent client's fd-table onto a freshly
//! spawned child client.
//!
//! POSIX `fork(2)` requires the child to inherit every open file
//! descriptor with the same offset, the same `OpenObject` body, and
//! a `FD_CLOEXEC` bit that mirrors the parent. The semantic is fd
//! aliasing, not deep cloning: parent and child observe each other's
//! reads / writes / seeks until one of them closes its alias. The
//! kernel cap topology never sees the inheritance — vfs's
//! `OpenObject` arena owns it.
//!
//! init drives the call: after `INIT_FORK` retypes the child TCB +
//! VSpace + CSpace it sends a privileged RPC into vfs that resolves
//! to [`clone_fd_table`]. The parent / child `ClientHandle`s have
//! already been registered by the time this runs (init's spawn path
//! always touches namesrv / vfs in the same order it touches mmsrv).

use crate::arena::segmented_array::{MmapAllocator, SegmentedArray};
use crate::core::error::VfsError;
use crate::owner::VfsState;
use crate::server::types::{ClientHandle, ObjectSlot, OpenObjectHandle};

/// Cardinality of the parent / child fd-table snapshot used during
/// the clone. The pair is heap-allocated via [`SegmentedArray`] so
/// the snapshot grows alongside the parent's fd footprint without a
/// fixed cap.
type FdSnapshot = SegmentedArray<(ObjectSlot, OpenObjectHandle)>;

/// Copy every active fd from `parent` into `child`. Each entry's
/// `OpenObject` refcount is bumped so the parent's later `close`
/// does not free a slot the child still references.
///
/// Two-pass design: collect the parent's `(fd, handle)` set first
/// (read-only borrow), then mutate the child. Single-pass would
/// require holding two `&mut ClientState` at once, which the arena
/// does not let us prove safe.
///
/// On a partial failure (child segment grow runs out of memory
/// halfway through) the function rolls back every `set` it has
/// already performed and returns `Err(NoMem)`. The caller — init —
/// propagates the failure as a fork-time `ENOMEM` and tears the
/// half-built child down before responding to the parent.
pub(crate) fn clone_fd_table(
    state: &mut VfsState,
    parent: ClientHandle,
    child: ClientHandle,
) -> Result<u32, VfsError> {
    let parent_ref = state.clients.get(parent).ok_or(VfsError::Io)?;

    let mut snapshot: FdSnapshot = SegmentedArray::new_empty();
    let mut alloc = MmapAllocator::new();
    let mut push_err: Option<VfsError> = None;
    parent_ref.slot_table.iter_active(|fd, handle| {
        // Fail closed on snapshot OOM: a forked child must inherit the
        // parent's full fd set, so a dropped entry is a correctness bug,
        // not a tolerable truncation.
        unsafe {
            if snapshot.push((fd, handle), &mut alloc).is_err() {
                push_err = Some(VfsError::NoMem);
                return false;
            }
        }
        true
    });
    if let Some(err) = push_err {
        return Err(err);
    }

    // Snapshot the parent's per-slot flag bytes alongside the
    // (fd, handle) pair so cloexec / personality flags survive
    // the fork — POSIX requires fork to inherit FD_CLOEXEC bits
    // unchanged.
    let mut flag_snapshot: SegmentedArray<u8> = SegmentedArray::new_empty();
    {
        let parent_ref = state.clients.get(parent).ok_or(VfsError::Io)?;
        for entry in snapshot.iter() {
            let (fd, _) = *entry;
            let flags = parent_ref.slot_table.slot_flags(fd);
            unsafe {
                if flag_snapshot.push(flags, &mut alloc).is_err() {
                    return Err(VfsError::NoMem);
                }
            }
        }
    }

    let mut installed: u32 = 0;
    let mut last_err: Option<VfsError> = None;
    let mut idx = 0u32;
    for entry in snapshot.iter() {
        let (fd, handle) = *entry;
        let child_mut = match state.clients.get_mut(child) {
            Some(c) => c,
            None => {
                last_err = Some(VfsError::Io);
                break;
            }
        };
        if let Err(_) = child_mut.slot_table.ensure_grown_to(fd) {
            last_err = Some(VfsError::NoMem);
            break;
        }
        if child_mut.slot_table.set(fd, handle).is_err() {
            last_err = Some(VfsError::NoMem);
            break;
        }
        let flags = flag_snapshot.get(idx).copied().unwrap_or(0);
        if flags != 0 {
            child_mut.slot_table.set_slot_flags(fd, flags);
        }
        idx += 1;
        crate::ops::dup::bump_open_object_refcount(state, handle);
        installed += 1;
    }

    if let Some(err) = last_err {
        // Roll back: walk the partial child fd-table, reverse each
        // refcount bump, and clear the slot. The child has not yet
        // started running so no other thread observes the rollback.
        rollback_partial_clone(state, child, &snapshot, installed);
        return Err(err);
    }

    Ok(installed)
}

/// Full fork inheritance into the child control client: copy the parent's
/// personality, credentials, cwd, and mount namespace, mirror the win32
/// per-client sidecar, then clone the fd-table (aliased OpenObject handles +
/// FD_CLOEXEC flags). The parent and child are resolved by init from their
/// control caps; the child is a freshly pre-created control client and init
/// drives this before the child runs. Returns the number of fds cloned, or
/// `Err` — the caller fails the fork and tears the half-built child down.
pub(crate) fn clone_client_for_fork(
    state: &mut VfsState,
    parent: ClientHandle,
    child: ClientHandle,
) -> Result<u32, VfsError> {
    if child == parent {
        return Err(VfsError::Inval);
    }
    let child_pid = state.clients.get(child).map(|c| c.cred.pid).unwrap_or(0);
    let (
        personality,
        mut cred,
        cwd_vnode_slot,
        cwd_vnode_epoch,
        cwd_path,
        cwd_path_len,
        mount_ns_slot,
    ) = match state.clients.get(parent) {
        Some(parent_cli) => (
            parent_cli.personality,
            parent_cli.cred,
            parent_cli.cwd_vnode_slot,
            parent_cli.cwd_vnode_epoch,
            parent_cli.cwd_path,
            parent_cli.cwd_path_len,
            parent_cli.mount_ns_slot,
        ),
        None => return Err(VfsError::Inval),
    };
    if child_pid != 0 {
        cred.pid = child_pid;
    }
    if let Some(child_cli) = state.clients.get_mut(child) {
        child_cli.personality = personality;
        child_cli.cred = cred;
        child_cli.cwd_vnode_slot = cwd_vnode_slot;
        child_cli.cwd_vnode_epoch = cwd_vnode_epoch;
        child_cli.cwd_path = cwd_path;
        child_cli.cwd_path_len = cwd_path_len;
        child_cli.mount_ns_slot = mount_ns_slot;
    }
    if personality == crate::personality::Personality::Win32 {
        crate::personality::win32::lifecycle::clone_client_state(state, parent, child);
    } else {
        crate::personality::win32::lifecycle::drop_client_state(state, child);
    }
    clear_fd_table(state, child);
    clone_fd_table(state, parent, child)
}

fn clear_fd_table(state: &mut VfsState, client: ClientHandle) {
    let Some(cli) = state.clients.get(client) else {
        return;
    };
    let mut snapshot: FdSnapshot = SegmentedArray::new_empty();
    let mut alloc = MmapAllocator::new();
    cli.slot_table.iter_active(|fd, handle| {
        unsafe {
            let _ = snapshot.push((fd, handle), &mut alloc);
        }
        true
    });
    for entry in snapshot.iter() {
        let (fd, handle) = *entry;
        if let Some(cli_mut) = state.clients.get_mut(client) {
            cli_mut.slot_table.clear(fd);
        }
        crate::ops::dup::release_open_object(state, handle);
    }
}

/// Reverse the first `installed` `(fd, handle)` pairs that
/// [`clone_fd_table`] published into `child`. Used only on the
/// roll-back arm of a partial clone failure.
fn rollback_partial_clone(
    state: &mut VfsState,
    child: ClientHandle,
    snapshot: &FdSnapshot,
    installed: u32,
) {
    let mut idx: u32 = 0;
    for entry in snapshot.iter() {
        if idx >= installed {
            break;
        }
        let (fd, handle) = *entry;
        if let Some(child_mut) = state.clients.get_mut(child) {
            child_mut.slot_table.clear(fd);
        }
        crate::ops::dup::release_open_object(state, handle);
        idx += 1;
    }
}
