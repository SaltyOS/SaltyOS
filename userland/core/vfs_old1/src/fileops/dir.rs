// SPDX-License-Identifier: GPL-2.0-only
//! Directory iteration over the bootstrap tree.

use trona_kernel::core_types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::open_file::{DIR_CURSOR_BACKEND, DIR_CURSOR_BOOTSTRAP, DIR_CURSOR_EOF};
use crate::server::types::ClientHandle;
use crate::vfs_core::vops::{ReaddirEntry, VfsOpResult};

struct DirEntryResult {
    next_state: u8,
    next_cursor: u64,
    name_len: u8,
    ino: u64,
    d_type: u8,
}

fn map_backend_readdir_result(
    result: crate::vfs_core::vops::ReaddirResult,
    reply: *mut TronaMsg,
) -> Option<DirEntryResult> {
    unsafe {
        match result {
            Ok(VfsOpResult::Complete(Some(entry))) => Some(DirEntryResult {
                next_state: if entry.eof_after {
                    DIR_CURSOR_EOF
                } else {
                    DIR_CURSOR_BACKEND
                },
                next_cursor: if entry.eof_after {
                    0
                } else {
                    entry.next_cursor
                },
                name_len: entry.name_len,
                ino: entry.ino,
                d_type: entry.d_type,
            }),
            Ok(VfsOpResult::Complete(None)) => None,
            Ok(VfsOpResult::Deferred(op_id)) => {
                crate::owner::pending_ops::free(op_id);
                (*reply).label = TRONA_NOT_SUPPORTED;
                (*reply).length = 0;
                None
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                None
            }
        }
    }
}

pub(crate) unsafe fn handle_readdir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let Some((vh, cursor_state, cursor)) = state.client_directory_slot(cli_handle, fd as usize)
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        let mut name = [0u8; 128];
        let personality = state.client_personality(cli_handle);
        let ignore_case = personality == crate::server::types::PERS_WIN32;
        let result = if cursor_state == DIR_CURSOR_EOF {
            None
        } else if cursor_state == DIR_CURSOR_BOOTSTRAP {
            if let Some((next_cursor, name_len, ino, d_type)) =
                state.bootstrap_readdir_entry_for_personality(vh, cursor, &mut name, personality)
            {
                Some(DirEntryResult {
                    next_state: DIR_CURSOR_BOOTSTRAP,
                    next_cursor,
                    name_len,
                    ino,
                    d_type,
                })
            } else {
                let backend = crate::vfs_core::vops::readdir_dir(
                    state,
                    Some(cli_handle),
                    vh,
                    0,
                    ignore_case,
                    &mut name,
                );
                match backend {
                    Some(result) => {
                        let mapped = map_backend_readdir_result(result, reply);
                        if mapped.is_none() && (*reply).label != 0 {
                            return;
                        }
                        mapped
                    }
                    None => None,
                }
            }
        } else if cursor_state == DIR_CURSOR_BACKEND {
            // procfs root pid-enumeration cursors require an init RPC
            // (`INIT_LIST_PIDS_BUF`) — defer to a worker so the owner
            // does not block here.
            if let Some(pid_index) = crate::fs::procfs::procfs_readdir_pid_index(state, vh, cursor)
            {
                if crate::fs::procfs::defer_procfs_readdir(
                    state, cli_handle, fd, vh, cursor, pid_index, reply,
                ) {
                    return;
                }
            }
            let backend = crate::vfs_core::vops::readdir_dir(
                state,
                Some(cli_handle),
                vh,
                cursor,
                ignore_case,
                &mut name,
            );
            match backend {
                Some(result) => {
                    let mapped = map_backend_readdir_result(result, reply);
                    if mapped.is_none() && (*reply).label != 0 {
                        return;
                    }
                    mapped
                }
                None => None,
            }
        } else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        let Some(result) = result else {
            if let Some(of) = state.client_open_file_mut(cli_handle, fd as usize) {
                if of.kind == crate::server::types::OBJ_DIRECTORY {
                    of.dir_cursor_state = DIR_CURSOR_EOF;
                    of.dir_cursor = 0;
                }
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        };

        if let Some(of) = state.client_open_file_mut(cli_handle, fd as usize) {
            if of.kind != crate::server::types::OBJ_DIRECTORY {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
            of.dir_cursor_state = result.next_state;
            of.dir_cursor = result.next_cursor;
        } else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 5 + ((result.name_len as u64 + 7) / 8);
        (*reply).regs[0] = result.name_len as u64;
        (*reply).regs[1] = 0;
        (*reply).regs[2] = result.ino;
        (*reply).regs[3] = result.d_type as u64;
        for idx in 4..20 {
            (*reply).regs[idx] = 0;
        }
        let dst = &raw mut (*reply).regs[4] as *mut u8;
        for idx in 0..result.name_len as usize {
            *dst.add(idx) = name[idx];
        }
    }
}
