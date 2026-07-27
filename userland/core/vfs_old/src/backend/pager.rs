// SPDX-License-Identifier: GPL-2.0-only
//! Backend pager callback handlers.

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::posix::*;
use uapi::*;

use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::server::consts::*;

use super::{read_backing_bytes, write_backing_bytes};

pub(crate) unsafe fn ensure_mmsrv_pager_callback_registered(state: &mut VfsState) -> bool {
    unsafe {
        if state.mmsrv_pager_registered {
            return true;
        }

        if !crate::backend::prepare_backend_callback_endpoint(state) {
            return false;
        }

        ipc::set_send_cap_ctx(ipc_ctx(), 0, crate::backend::backend_callback_ep());

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_REGISTER_PAGER_EP;
        msg.length = 0;

        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }

        state.mmsrv_pager_registered = true;
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
            Some(read) if read == bytes => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = read;
            }
            Some(read) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] pager read short backing=");
                    _lb.hex(backing_kind);
                    _lb.str(b" id0=");
                    _lb.hex(backing_id0);
                    _lb.str(b" id1=");
                    _lb.hex(backing_id1);
                    _lb.str(b" off=");
                    _lb.hex(file_offset);
                    _lb.str(b" page=");
                    _lb.dec(mo_page_idx);
                    _lb.str(b" got=");
                    _lb.dec(read);
                    _lb.str(b" want=");
                    _lb.dec(bytes);
                    _lb.str(b"\n");
                });
                (*reply).label = TRONA_IO_ERROR;
            }
            _ => {
                (*reply).label = TRONA_IO_ERROR;
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
