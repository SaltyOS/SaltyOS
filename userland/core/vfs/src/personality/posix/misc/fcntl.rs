// SPDX-License-Identifier: GPL-2.0-only
//! fcntl handler: F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::server::client::{flags_append_writes, flags_nonblocking};
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;

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
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        if !cli.objects[fd as usize].is_live() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        match cmd {
            // F_DUPFD (0) and F_DUPFD_CLOEXEC (1030)
            0 | 1030 => {
                let min_fd = if arg < 0 { 0 } else { arg as usize };
                let mut newfd: i32 = -1;
                for i in min_fd..MAX_CLIENT_OBJECTS {
                    if cli.objects[i].is_free() {
                        newfd = i as i32;
                        break;
                    }
                }
                if newfd < 0 {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }

                let src = cli.objects[fd as usize];
                let cli = match state.clients.get_mut(cli_handle) {
                    Some(c) => c,
                    None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
                };
                let mut dup_slot = src;
                dup_slot.cloexec = if cmd == 1030 { 1 } else { 0 };
                cli.obj_count += 1;
                cli.objects[newfd as usize] = dup_slot;

                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = newfd as u64;
            }
            // F_GETFD
            1 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = cli.objects[fd as usize].cloexec as u64;
            }
            // F_SETFD
            2 => {
                let cli = match state.clients.get_mut(cli_handle) {
                    Some(c) => c,
                    None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
                };
                cli.objects[fd as usize].cloexec = if (arg & 1) != 0 { 1 } else { 0 };
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            // F_GETFL
            3 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = cli.objects[fd as usize].flags as u64;
            }
            // F_SETFL (only O_APPEND, O_NONBLOCK are changeable)
            4 => {
                let cli = match state.clients.get_mut(cli_handle) {
                    Some(c) => c,
                    None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
                };
                let changeable = O_APPEND | O_NONBLOCK;
                let preserved = cli.objects[fd as usize].flags & !changeable;
                let updated = preserved | (arg as u32 & changeable);
                cli.objects[fd as usize].flags = updated;
                cli.objects[fd as usize].append_on_write = if flags_append_writes(updated) { 1 } else { 0 };
                cli.objects[fd as usize].nonblocking = if flags_nonblocking(updated) { 1 } else { 0 };
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
