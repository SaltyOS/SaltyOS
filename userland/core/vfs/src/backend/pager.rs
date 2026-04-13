// SPDX-License-Identifier: GPL-2.0-only
//! Backend pager callback handlers.

use trona::consts::kernel::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::server::consts::*;

use super::{read_backing_bytes, write_backing_bytes};

static mut MMSRV_PAGER_CALLBACK_REGISTERED: bool = false;

pub(crate) unsafe fn ensure_mmsrv_pager_callback_registered() -> bool {
    unsafe {
        if MMSRV_PAGER_CALLBACK_REGISTERED {
            return true;
        }

        if !crate::backend::prepare_backend_callback_endpoint() {
            return false;
        }

        ipc::set_send_cap_ctx(ipc_ctx(), 0, VFS_CAP_BACKEND_CALLBACK_EP);

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_REGISTER_PAGER_EP;
        msg.length = 0;

        let err = ipc::call_ctx(ipc_ctx(), trona::caps::mmsrv_ep(), &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }

        MMSRV_PAGER_CALLBACK_REGISTERED = true;
        true
    }
}

unsafe fn with_recv_mo_page<T>(
    mo_page_idx: u64,
    func: impl FnOnce(*mut u8) -> Option<T>,
) -> Option<T> {
    unsafe {
        let recv_slot = crate::current_recv_slot();
        if recv_slot == 0 {
            return None;
        }

        let count_and_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let (err, mapped) = invoke::vspace_map_mo_with_count(
            CAP_SELF_VSPACE,
            recv_slot,
            VFS_FILE_MMAP_SCRATCH_VADDR,
            mo_page_idx,
            count_and_flags,
        );
        if err != 0 || mapped != 1 {
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
            return None;
        }

        let page = VFS_FILE_MMAP_SCRATCH_VADDR as *mut u8;
        let result = func(page);

        let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, recv_slot);
        result
    }
}

pub(crate) unsafe fn handle_pager_read(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let backing_kind = (*msg).regs[0];
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let file_offset = (*msg).regs[3];
        let mo_page_idx = (*msg).regs[4];
        let bytes = core::cmp::min((*msg).regs[5], 4096);

        let result = with_recv_mo_page(mo_page_idx, |page| {
            core::ptr::write_bytes(page, 0, 4096);
            if bytes == 0 {
                return Some(0u64);
            }
            read_backing_bytes(
                state,
                backing_kind,
                backing_id0,
                backing_id1,
                file_offset,
                page,
                bytes,
            )
        });

        match result {
            Some(read) => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = read;
            }
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
            }
        }
    }
}

pub(crate) unsafe fn handle_pager_write(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let backing_kind = (*msg).regs[0];
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let file_offset = (*msg).regs[3];
        let mo_page_idx = (*msg).regs[4];
        let bytes = core::cmp::min((*msg).regs[5], 4096);

        if bytes == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let result = with_recv_mo_page(mo_page_idx, |page| {
            write_backing_bytes(
                state,
                backing_kind,
                backing_id0,
                backing_id1,
                file_offset,
                page as *const u8,
                bytes,
            )
        });

        match result {
            Some(written) => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = written;
            }
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
            }
        }
    }
}
