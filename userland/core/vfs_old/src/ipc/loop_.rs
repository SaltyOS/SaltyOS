// SPDX-License-Identifier: GPL-2.0-only
//! VFS IPC event-loop helpers.
//!
//! The asymmetric owner + worker architecture (one owner thread driving
//! the VFS service EP, N workers executing blocking backend I/O) is the
//! only supported model. The legacy symmetric `trona_runtime::thread::worker::run_workers`
//! pool hooks that used to live here (`vfs_worker_*` callbacks,
//! `compute_vfs_worker_count`, `vfs_cpus_N` cfg threading) have been
//! retired entirely — `owner::worker` owns spawn / drain / routing now.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use uapi::*;

use crate::current_recv_slot;

#[inline]
#[allow(dead_code)]
pub(crate) unsafe fn arm_current_recv_slot(ctx: *mut IpcContext) {
    unsafe {
        let slot = current_recv_slot();
        if slot != 0 {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, slot, 0);
        }
    }
}

#[inline]
#[allow(dead_code)]
pub(crate) unsafe fn recycle_current_recv_slot(ctx: *mut IpcContext) {
    unsafe {
        let slot = current_recv_slot();
        if slot != 0 {
            let _ = trona_kernel::invoke::cnode_delete(CAP_SELF_CSPACE, slot);
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, slot, 0);
        }
    }
}
