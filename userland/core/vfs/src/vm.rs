// SPDX-License-Identifier: GPL-2.0-only
//! Anonymous VM helpers for VFS core.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::mmsrv::*;
use trona::types::core::*;

use crate::consts::VFS_CAP_MMSRV_EP;

pub(crate) unsafe fn map_anon_rw(length: u64) -> *mut u8 {
    unsafe {
        if length == 0 {
            return core::ptr::null_mut();
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MMAP;
        msg.length = 4;
        msg.regs[0] = 0;
        msg.regs[1] = length;
        msg.regs[2] = (PROT_READ | PROT_WRITE) as u64;
        msg.regs[3] = (MAP_PRIVATE | MAP_ANONYMOUS) as u64;

        let err = ipc::call_ctx(trona::current_ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return usize::MAX as *mut u8;
        }

        reply.regs[0] as *mut u8
    }
}

pub(crate) unsafe fn unmap(addr: *mut u8, length: u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_MUNMAP;
        msg.length = 2;
        msg.regs[0] = addr as u64;
        msg.regs[1] = length;

        let err = ipc::call_ctx(trona::current_ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return -1;
        }

        0
    }
}