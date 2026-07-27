// SPDX-License-Identifier: GPL-2.0-only
//! fcntl handler: F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::server::client::{flags_append_writes, flags_nonblocking};
use crate::server::consts::*;
use crate::server::types::*;

pub(crate) unsafe fn handle_fcntl(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cmd = (*msg).regs[1] as i32;
        let arg = (*msg).regs[2] as i64;

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
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
        if state.open_object_at(cli_handle, fd as usize).is_none() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        match cmd {
            // F_DUPFD (0) and F_DUPFD_CLOEXEC (1030)
            0 | 1030 => {
                let min_fd = if arg < 0 { 0 } else { arg as usize };
                let (src_handle, badge) = match state.clients.get(cli_handle) {
                    Some(c) => {
                        let r = c.slots[fd as usize];
                        if r.is_free() {
                            (*reply).label = TRONA_INVALID_ARGUMENT;
                            return;
                        }
                        (r.open_object, c.badge)
                    }
                    None => {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                };
                let mut newfd: i32 = -1;
                let cli = match state.clients.get(cli_handle) {
                    Some(c) => c,
                    None => {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                };
                for i in min_fd..MAX_CLIENT_OBJECTS {
                    if cli.slots[i].is_free() {
                        newfd = i as i32;
                        break;
                    }
                }
                if newfd < 0 {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }

                let cloexec = if cmd == 1030 { 1 } else { 0 };
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
            // F_GETFD
            1 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = cli.slots[fd as usize].cloexec as u64;
            }
            // F_SETFD
            2 => {
                let cli = match state.clients.get_mut(cli_handle) {
                    Some(c) => c,
                    None => {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                };
                cli.slots[fd as usize].cloexec = if (arg & 1) != 0 { 1 } else { 0 };
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            // F_GETFL
            3 => {
                let flags = state
                    .open_object_at(cli_handle, fd as usize)
                    .map(|o| o.flags)
                    .unwrap_or(0);
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = flags as u64;
            }
            // F_SETFL (only O_APPEND, O_NONBLOCK are changeable)
            4 => {
                let changeable = O_APPEND | O_NONBLOCK;
                let current_flags = match state.open_object_at(cli_handle, fd as usize) {
                    Some(o) => o.flags,
                    None => {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                };
                let preserved = current_flags & !changeable;
                let updated = preserved | (arg as u32 & changeable);
                let append = if flags_append_writes(updated) { 1 } else { 0 };
                let nonblock = if flags_nonblocking(updated) { 1 } else { 0 };
                if let Some(obj) = state.open_object_at_mut(cli_handle, fd as usize) {
                    obj.flags = updated;
                    obj.append_on_write = append;
                    obj.nonblocking = nonblock;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}
