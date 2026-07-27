// SPDX-License-Identifier: GPL-2.0-only
//
//! `dup` / `dup2` / `dup3` / Win32 handle duplication logic helper.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::server::open_object::FD_FLAG_CLOEXEC;
use crate::server::types::{ClientHandle, OpenObjectHandle};

/// `dup(old_fd)` — allocate the lowest free fd. Reply emit
/// dispatches through `personality::reply::emit_ack` carrying
/// the new fd as `information`.
pub(crate) unsafe fn do_dup_lowest(
    state: &mut VfsState,
    client: ClientHandle,
    old_fd: i32,
    cloexec: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if old_fd < 0 {
            crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Err(VfsError::BadF));
            return;
        }
        match dup_with_target(state, client, old_fd as u32, None, cloexec) {
            Ok(new_fd) => crate::personality::reply::emit_dup(
                reply_lease,
                reply_intent,
                new_fd as u64,
                Ok(()),
            ),
            Err(e) => crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Err(e)),
        }
    }
}

/// `dup2(old_fd, new_fd)` / `dup3(old_fd, new_fd, flags)` — alias
/// at a caller-named slot. POSIX no-op short-circuit when
/// `old_fd == new_fd`.
pub(crate) unsafe fn do_dup_to_target(
    state: &mut VfsState,
    client: ClientHandle,
    old_fd: i32,
    new_fd: i32,
    cloexec: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if old_fd < 0 || new_fd < 0 {
            crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Err(VfsError::BadF));
            return;
        }
        if old_fd == new_fd {
            let cli_ok = state
                .clients
                .get(client)
                .map(|c| c.slot_table.lookup(old_fd as u32).is_some())
                .unwrap_or(false);
            if cli_ok {
                crate::personality::reply::emit_dup(
                    reply_lease,
                    reply_intent,
                    new_fd as u64,
                    Ok(()),
                );
            } else {
                crate::personality::reply::emit_ack(
                    reply_lease,
                    reply_intent,
                    0,
                    Err(VfsError::BadF),
                );
            }
            return;
        }
        match dup_with_target(state, client, old_fd as u32, Some(new_fd as u32), cloexec) {
            Ok(_) => crate::personality::reply::emit_dup(
                reply_lease,
                reply_intent,
                new_fd as u64,
                Ok(()),
            ),
            Err(e) => crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Err(e)),
        }
    }
}

/// Common back end for `dup` / `dup2` / `dup3` /
/// `fcntl(F_DUPFD)`. `target_fd = None` → lowest free;
/// `Some(n)` → install at `n`, closing the previous occupant.
pub(crate) fn dup_with_target(
    state: &mut VfsState,
    client: ClientHandle,
    old_fd: u32,
    target_fd: Option<u32>,
    cloexec: bool,
) -> Result<u32, VfsError> {
    let old_handle = {
        let cli = state.clients.get(client).ok_or(VfsError::Io)?;
        cli.slot_table.lookup(old_fd).ok_or(VfsError::BadF)?
    };
    if !old_handle.is_valid() {
        return Err(VfsError::BadF);
    }

    let new_fd = {
        let cli = state.clients.get_mut(client).ok_or(VfsError::Io)?;
        match target_fd {
            None => cli
                .slot_table
                .find_first_empty_from(0)
                .map_err(|_| VfsError::NoMem)?,
            Some(fd) => {
                cli.slot_table
                    .ensure_grown_to(fd)
                    .map_err(|_| VfsError::NoMem)?;
                fd
            }
        }
    };

    if let Some(prev_handle) = state
        .clients
        .get(client)
        .and_then(|c| c.slot_table.lookup(new_fd))
    {
        if prev_handle.is_valid() {
            release_open_object(state, prev_handle);
        }
    }

    bump_open_object_refcount(state, old_handle);
    let cli = state.clients.get_mut(client).ok_or(VfsError::Io)?;
    if cli.slot_table.set(new_fd, old_handle).is_err() {
        release_open_object(state, old_handle);
        return Err(VfsError::NoMem);
    }
    if cloexec {
        cli.slot_table
            .set_slot_flag_bit(new_fd, FD_FLAG_CLOEXEC, true);
    }
    Ok(new_fd)
}

pub(crate) fn release_open_object(state: &mut VfsState, handle: OpenObjectHandle) {
    crate::ops::close::drop_open_object_ref(state, handle);
}

pub(crate) fn bump_open_object_refcount(state: &mut VfsState, handle: OpenObjectHandle) {
    if let Some(obj) = state.open_objects.get_mut(handle) {
        obj.refcount = obj.refcount.saturating_add(1);
    }
}

pub(crate) fn set_cloexec_on_fd(state: &mut VfsState, client: ClientHandle, fd: u32, on: bool) {
    if let Some(cli) = state.clients.get_mut(client) {
        cli.slot_table.set_slot_flag_bit(fd, FD_FLAG_CLOEXEC, on);
    }
}

pub(crate) fn fd_cloexec(state: &VfsState, client: ClientHandle, fd: u32) -> bool {
    state
        .clients
        .get(client)
        .map(|c| (c.slot_table.slot_flags(fd) & FD_FLAG_CLOEXEC) != 0)
        .unwrap_or(false)
}
