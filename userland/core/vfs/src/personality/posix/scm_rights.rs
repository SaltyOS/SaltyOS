// SPDX-License-Identifier: GPL-2.0-only
//
//! SCM_RIGHTS — install a batch of `OpenObjectHandle` references
//! into the receiving client's fd-table after a UNIX-domain
//! `recvmsg` arm dequeues a control payload that carries them.
//!
//! There is no public `VFS_SCM_RIGHTS_RECV` round-trip. The recv
//! path on UNIX sockets / pipes / fifos walks the dequeued
//! ancillary payload, calls [`install_received_object_handles`] to
//! populate the receiver's fd-table, and packs the resulting fds
//! into the same reply that carries the rest of the message body.
//! POSIX `recvmsg` callers see the fds via the control message
//! header in their reply; vfs never asks the caller for a
//! follow-up "now actually install" round trip.
//!
//! Each handle in the batch already carries an `OpenObject`
//! refcount the sender bumped when its matching `sendmsg` arm
//! enqueued it. On full success that refcount migrates onto the
//! receiver's fd-table entry. On partial failure
//! [`install_received_object_handles`] clears any slot it has
//! already populated and drops one refcount per handle in the
//! batch — the entire batch becomes a no-op so the caller can
//! report the failure without leaking arena slots.

use crate::arena::segmented_array::{MmapAllocator, SegmentedArray};
use crate::core::error::VfsError;
use crate::owner::VfsState;
use crate::server::types::{ClientHandle, ObjectSlot, OpenObjectHandle};

/// Install `handles` into `client`'s fd-table at the lowest free
/// fd in each segment. Returns the assigned fds in insertion
/// order. On any failure the receiver's fd-table is unchanged
/// from its pre-call state and every handle's refcount is
/// dropped (atomic batch semantic).
pub(crate) fn install_received_object_handles(
    state: &mut VfsState,
    client: ClientHandle,
    handles: &[OpenObjectHandle],
) -> Result<SegmentedArray<ObjectSlot>, VfsError> {
    let mut fds: SegmentedArray<ObjectSlot> = SegmentedArray::new_empty();
    let mut alloc = MmapAllocator::new();
    let mut last_err: Option<VfsError> = None;
    let mut last_unrecorded_fd: Option<ObjectSlot> = None;

    for handle in handles.iter().copied() {
        let assigned = match install_one(state, client, handle) {
            Ok(fd) => fd,
            Err(err) => {
                last_err = Some(err);
                break;
            }
        };
        unsafe {
            if fds.push(assigned, &mut alloc).is_err() {
                last_err = Some(VfsError::NoMem);
                last_unrecorded_fd = Some(assigned);
                break;
            }
        }
    }

    if let Some(err) = last_err {
        rollback_partial_install(state, client, &fds, last_unrecorded_fd, handles);
        return Err(err);
    }

    Ok(fds)
}

/// Install a single handle at the receiver's lowest free fd.
/// On success the handle's existing refcount (the one the sender
/// bumped at enqueue time) now belongs to the receiver's fd-table
/// entry; the caller does not bump again.
fn install_one(
    state: &mut VfsState,
    client: ClientHandle,
    handle: OpenObjectHandle,
) -> Result<ObjectSlot, VfsError> {
    let cli = state.clients.get_mut(client).ok_or(VfsError::Io)?;
    let fd = cli
        .slot_table
        .find_first_empty_from(0)
        .map_err(|_| VfsError::NoMem)?;
    cli.slot_table
        .set(fd, handle)
        .map_err(|_| VfsError::NoMem)?;
    Ok(fd)
}

/// Reverse a partial install. Two clean-up tasks:
///
///   1. Every fd in `installed_fds` (and the trailing
///      `last_unrecorded_fd`, if `Some`) was set in the
///      receiver's `slot_table`. Clear each slot back to
///      `Handle::INVALID` so the receiver does not see a partial
///      view of the batch.
///
///   2. Every handle in `handles` carries one outstanding
///      refcount the sender bumped. Drop it for each — the batch
///      as a whole is being abandoned, so the sender's
///      bookkeeping must not survive on the receiver side.
fn rollback_partial_install(
    state: &mut VfsState,
    client: ClientHandle,
    installed_fds: &SegmentedArray<ObjectSlot>,
    last_unrecorded_fd: Option<ObjectSlot>,
    handles: &[OpenObjectHandle],
) {
    if let Some(cli) = state.clients.get_mut(client) {
        for fd in installed_fds.iter() {
            cli.slot_table.clear(*fd);
        }
        if let Some(fd) = last_unrecorded_fd {
            cli.slot_table.clear(fd);
        }
    }
    for handle in handles.iter().copied() {
        crate::ops::dup::release_open_object(state, handle);
    }
}
