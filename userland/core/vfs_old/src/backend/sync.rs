// SPDX-License-Identifier: GPL-2.0-only
//! Backend mmap invalidation and truncate sync helpers.

use trona_kernel::core_types::*;
use trona_protocol::mm::{MM_SYNC_BACKING_TRUNCATE, MMAP_BACKING_FILE, MMAP_BACKING_MOUNT};
use trona_protocol::posix::*;

use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::open_object::OpenObject;
use crate::server::types::*;

fn file_backing_identity(state: &VfsState, slot: &OpenObject) -> Option<(u64, u64, u64)> {
    if slot.kind() != ObjectKind::File || !slot.vnode_handle().is_valid() {
        return None;
    }
    let vh = slot.vnode_handle();
    let vnode = state.vnodes.get(vh)?;
    Some(match state.resolve_vnode_mount(vh) {
        Some(mh) => match state.mounts.get(mh) {
            Some(mp) => (MMAP_BACKING_MOUNT, mp.id as u64, vnode.id),
            None => (MMAP_BACKING_FILE, vnode.id, 0u64),
        },
        None => (MMAP_BACKING_FILE, vnode.id, 0u64),
    })
}

pub(crate) unsafe fn notify_mmsrv_mmap_write(
    state: &VfsState,
    slot: &OpenObject,
    offset: u64,
    count: u64,
    old_size: u64,
    new_size: u64,
) {
    let Some((backing_kind, id0, id1)) = file_backing_identity(state, slot) else {
        return;
    };

    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_SYNC_MMAP_WRITE;
        msg.length = 7;
        msg.regs[0] = backing_kind;
        msg.regs[1] = id0;
        msg.regs[2] = id1;
        msg.regs[3] = offset;
        msg.regs[4] = count;
        msg.regs[5] = old_size;
        msg.regs[6] = new_size;
        let _ = trona_kernel::ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
    }
}

pub(crate) unsafe fn notify_mmsrv_mmap_truncate(
    state: &VfsState,
    slot: &OpenObject,
    old_size: u64,
    new_size: u64,
) {
    let Some((backing_kind, id0, id1)) = file_backing_identity(state, slot) else {
        return;
    };

    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_SYNC_FILE_BACKING;
        msg.length = 5;
        msg.regs[0] = backing_kind;
        msg.regs[1] = id0;
        msg.regs[2] = id1;
        msg.regs[3] = new_size;
        msg.regs[4] = if new_size < old_size {
            MM_SYNC_BACKING_TRUNCATE
        } else {
            0
        };
        let _ = trona_kernel::ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const msg,
            &raw mut reply,
        );
    }
}
