// SPDX-License-Identifier: GPL-2.0-only
//! Shared-memory bulk I/O for large file transfers.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::types::{ClientHandle, OBJ_DIRECTORY, OBJ_FILE, OBJ_SHM};

fn client_bulk_window(state: &VfsState, cli_handle: ClientHandle) -> Option<(u64, u64)> {
    let client = state.clients.get(cli_handle)?;
    if client.bulk_shm_vaddr == 0 || client.bulk_shm_pages == 0 {
        return None;
    }
    Some((client.bulk_shm_vaddr, client.bulk_shm_pages as u64 * 4096))
}

pub(crate) unsafe fn handle_bulk_setup_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_pages = (*msg).regs[1];
        if shm_id == 0 || client_pages < BULK_SHM_PAGES {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        if let Some(client) = state.clients.get(cli_handle) {
            if client.bulk_shm_id == shm_id && client.bulk_shm_vaddr != 0 {
                (*reply).label = TRONA_OK;
                (*reply).length = 0;
                return;
            }
        }

        let mut req = TronaMsg::zeroed();
        let mut mm_reply = TronaMsg::zeroed();
        req.label = MM_SHM_MAP;
        req.length = 4;
        req.regs[0] = shm_id;
        req.regs[1] = 0;
        req.regs[2] = 0;
        req.regs[3] = 0x3;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const req,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            (*reply).label = if err != 0 {
                TRONA_INVALID_OPERATION
            } else {
                mm_reply.label
            };
            (*reply).length = 0;
            return;
        }

        let Some(client) = state.clients.get_mut(cli_handle) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        client.bulk_shm_vaddr = mm_reply.regs[0];
        client.bulk_shm_id = shm_id;
        client.bulk_shm_pages = client_pages as u32;
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_bulk_read_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let want_count = (*msg).regs[1];
        let shm_offset = (*msg).regs[2];
        let Some((bulk_vaddr, bulk_len)) = client_bulk_window(state, cli_handle) else {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        };
        if shm_offset >= bulk_len {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (vnode, offset, kind, flags) = match state.client_open_file(cli_handle, fd) {
            Some(of) => (of.vnode, of.offset, of.kind, of.status_flags),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        if kind == OBJ_DIRECTORY {
            (*reply).label = TRONA_IS_DIRECTORY;
            (*reply).length = 0;
            return;
        }
        if kind == OBJ_SHM {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if kind != OBJ_FILE {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if (flags & O_ACCMODE) == O_WRONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        let actual = match crate::fileops::regular::read_into(
            state,
            Some(cli_handle),
            vnode,
            offset,
            (bulk_vaddr + shm_offset) as *mut u8,
            core::cmp::min(want_count, bulk_len - shm_offset) as usize,
        ) {
            Ok(actual) => actual as u64,
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        if let Some(of) = state.client_open_file_mut(cli_handle, fd) {
            of.offset = of.offset.saturating_add(actual);
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual;
    }
}

pub(crate) unsafe fn handle_bulk_pwrite_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as usize;
        let want_count = (*msg).regs[1];
        let offset = (*msg).regs[2] as i64;
        let shm_offset = (*msg).regs[3];
        if offset < 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let Some((bulk_vaddr, bulk_len)) = client_bulk_window(state, cli_handle) else {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        };
        if shm_offset >= bulk_len {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (vnode, kind, flags) = match state.client_open_file(cli_handle, fd) {
            Some(of) => (of.vnode, of.kind, of.status_flags),
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        if kind == OBJ_DIRECTORY {
            (*reply).label = TRONA_IS_DIRECTORY;
            (*reply).length = 0;
            return;
        }
        if kind == OBJ_SHM {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if kind != OBJ_FILE {
            (*reply).label = TRONA_NOT_SUPPORTED;
            (*reply).length = 0;
            return;
        }
        if (flags & O_ACCMODE) == O_RDONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        let actual = core::cmp::min(want_count, bulk_len - shm_offset);
        let src = (bulk_vaddr + shm_offset) as *const u8;
        let written = match crate::fileops::regular::write_from(
            state,
            vnode,
            offset as u64,
            src,
            actual as usize,
        ) {
            Ok(written) => written,
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written;
    }
}
