// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `fcntl` logic helper. Windows does not surface this op.
//!
//! Supported commands:
//! - `F_DUPFD` / `F_DUPFD_CLOEXEC` — alias `fd` at lowest free
//!   slot ≥ `arg`.
//! - `F_GETFD` / `F_SETFD` — read/write `FD_CLOEXEC`.
//! - `F_GETFL` / `F_SETFL` — read/write the open flags mask.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{AckReplyIntent, OpenOptions};
use crate::owner::VfsState;
use crate::server::open_object::OpenObjectFlags;
use crate::server::types::ClientHandle;

const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const F_DUPFD_CLOEXEC: u32 = 1030;

const FD_CLOEXEC: u32 = 1;
const POSIX_O_NONBLOCK: u32 = 0x800;
const POSIX_O_APPEND: u32 = 0x400;
const POSIX_O_ACCMODE: u32 = 0x3;

pub(crate) unsafe fn do_fcntl(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    cmd: u32,
    arg: u64,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            emit_err(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            emit_err(reply_lease, reply_intent, VfsError::BadF);
            return;
        };

        match cmd {
            F_DUPFD | F_DUPFD_CLOEXEC => {
                let cloexec = cmd == F_DUPFD_CLOEXEC;
                let start = arg as u32;
                if state.clients.get(client).is_none() {
                    emit_err(reply_lease, reply_intent, VfsError::Io);
                    return;
                }
                let target_fd = match state
                    .clients
                    .get_mut(client)
                    .and_then(|c| c.slot_table.find_first_empty_from(start).ok())
                {
                    Some(fd) => fd,
                    None => {
                        emit_err(reply_lease, reply_intent, VfsError::NoMem);
                        return;
                    }
                };
                match crate::ops::dup::dup_with_target(
                    state,
                    client,
                    fd as u32,
                    Some(target_fd),
                    cloexec,
                ) {
                    Ok(new_fd) => crate::personality::reply::emit_ack(
                        reply_lease,
                        reply_intent,
                        new_fd as u64,
                        Ok(()),
                    ),
                    Err(e) => emit_err(reply_lease, reply_intent, e),
                }
            }
            F_GETFD => {
                let bit = if crate::ops::dup::fd_cloexec(state, client, fd as u32) {
                    FD_CLOEXEC
                } else {
                    0
                };
                crate::personality::reply::emit_ack(reply_lease, reply_intent, bit as u64, Ok(()));
            }
            F_SETFD => {
                let on = (arg as u32 & FD_CLOEXEC) != 0;
                crate::ops::dup::set_cloexec_on_fd(state, client, fd as u32, on);
                crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
            }
            F_GETFL => {
                let (flags, options) = state
                    .open_objects
                    .get(open_h)
                    .map(|o| (o.flags, OpenOptions::from_bits(o.options)))
                    .unwrap_or((0, OpenOptions::empty()));
                let mut mask = 0u32;
                if (flags & OpenObjectFlags::READABLE) != 0
                    && (flags & OpenObjectFlags::WRITABLE) != 0
                {
                    mask |= 2;
                } else if (flags & OpenObjectFlags::WRITABLE) != 0 {
                    mask |= 1;
                }
                if options.contains(OpenOptions::NON_BLOCKING) {
                    mask |= POSIX_O_NONBLOCK;
                }
                if options.contains(OpenOptions::APPEND) {
                    mask |= POSIX_O_APPEND;
                }
                crate::personality::reply::emit_ack(reply_lease, reply_intent, mask as u64, Ok(()));
            }
            F_SETFL => {
                let arg_u32 = arg as u32;
                let drop_access = arg_u32 & !POSIX_O_ACCMODE;
                if let Some(obj) = state.open_objects.get_mut(open_h) {
                    if (drop_access & POSIX_O_NONBLOCK) != 0 {
                        obj.flags |= OpenObjectFlags::O_NONBLOCK;
                    } else {
                        obj.flags &= !OpenObjectFlags::O_NONBLOCK;
                    }
                    if (drop_access & POSIX_O_APPEND) != 0 {
                        obj.flags |= OpenObjectFlags::O_APPEND;
                    } else {
                        obj.flags &= !OpenObjectFlags::O_APPEND;
                    }
                    let mut options = OpenOptions::from_bits(obj.options);
                    if (drop_access & POSIX_O_NONBLOCK) != 0 {
                        options = options.with(OpenOptions::NON_BLOCKING);
                    } else {
                        options =
                            OpenOptions::from_bits(options.bits() & !OpenOptions::NON_BLOCKING);
                    }
                    if (drop_access & POSIX_O_APPEND) != 0 {
                        options = options.with(OpenOptions::APPEND);
                    } else {
                        options = OpenOptions::from_bits(options.bits() & !OpenOptions::APPEND);
                    }
                    obj.options = options.bits();
                }
                crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
            }
            _ => emit_err(reply_lease, reply_intent, VfsError::Inval),
        }
    }
}

unsafe fn emit_err(reply_lease: ReplyLease, intent: AckReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, intent, 0, Err(err));
    }
}
