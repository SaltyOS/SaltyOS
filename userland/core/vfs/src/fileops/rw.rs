// SPDX-License-Identifier: GPL-2.0-only
//! Sequential read and write — VopDataOps dispatch.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::backend::notify_mmsrv_mmap_write;
use crate::owner::VfsState;
use crate::owner::dispatch::{resolve_fd, resolve_fd_mut, build_data_ctx};
use crate::personality::posix::consts::DEV_URANDOM as POSIX_DEV_URANDOM;
use crate::server::consts::*;
use crate::server::types::*;
use crate::ipc_ctx;
use crate::vfs_core::file::VAttr;
pub(crate) unsafe fn handle_read_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];
        if count > 152 { count = 152; }

        let (kind, device, vnode_h, offset, append_on_write, rights) = {
            match resolve_fd(state, cli_handle, fd) {
                Some(s) => (
                    s.kind(),
                    s.device_info(),
                    s.vnode_handle(),
                    s.offset,
                    s.append_on_write != 0,
                    s.rights,
                ),
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
            }
        };

        if (rights & OBJ_RIGHT_READ) == 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        match kind {
            ObjectKind::Device => {
                let Some(device) = device else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                };
                device_read(device.dev_type, device.pty_id, count, msg, reply);
                return false;
            }
            ObjectKind::File => {
                if !vnode_h.is_valid() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                let data_ctx = match build_data_ctx(state, vnode_h) {
                    Some(dc) => dc,
                    None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
                };
                let vnode = match state.vnodes.get(vnode_h) {
                    Some(v) => v,
                    None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
                };
                let ops = vnode.ops;
                if ops.is_null() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }

                let dst = &raw mut (*reply).regs[1] as *mut u8;
                match ((*ops).data.read)(&data_ctx, offset, dst, count) {
                    Ok(actual) => {
                        (*reply).label = TRONA_OK;
                        (*reply).length = 1 + (actual + 7) / 8;
                        (*reply).regs[0] = actual;
                        // Update offset
                        if let Some(slot) = resolve_fd_mut(state, cli_handle, fd) {
                            slot.offset = offset + actual;
                        }
                    }
                    Err(e) => {
                        (*reply).label = e.to_trona();
                    }
                }
                return false;
            }
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
        }
    }
}

/// Write — owner-loop version.
pub(crate) unsafe fn handle_write_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];
        if count > 152 { count = 152; }

        let (kind, device, vnode_h, offset, append_on_write, rights) = {
            match resolve_fd(state, cli_handle, fd) {
                Some(s) => (
                    s.kind(),
                    s.device_info(),
                    s.vnode_handle(),
                    s.offset,
                    s.append_on_write != 0,
                    s.rights,
                ),
                None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
            }
        };

        if (rights & OBJ_RIGHT_WRITE) == 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        match kind {
            ObjectKind::Device => {
                let Some(device) = device else {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                };
                device_write(device.dev_type, device.pty_id, count, msg, reply);
                return false;
            }
            ObjectKind::File => {
                if !vnode_h.is_valid() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                let data_ctx = match build_data_ctx(state, vnode_h) {
                    Some(dc) => dc,
                    None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
                };
                let vnode = match state.vnodes.get(vnode_h) {
                    Some(v) => v,
                    None => { (*reply).label = TRONA_INVALID_ARGUMENT; return false; }
                };
                let ops = vnode.ops;
                if ops.is_null() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }

                // Append-on-write uses the current file size as the write offset.
                let write_offset = if append_on_write {
                    if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vnode_h) {
                        let mut attr = VAttr::zeroed();
                        let _ = ((*(*ctx.vnode).ops).meta.getattr)(&ctx, &raw mut attr);
                        crate::vfs_core::mount_ctl::clear_trampolines();
                        attr.size
                    } else { offset }
                } else { offset };

                let src = &(*msg).regs[2] as *const u64 as *const u8;
                let mut old_size = 0;
                if let Some(ctx) = crate::vfs_core::mount_ctl::build_vop_context(state, vnode_h) {
                    let mut attr = VAttr::zeroed();
                    let _ = ((*(*ctx.vnode).ops).meta.getattr)(&ctx, &raw mut attr);
                    crate::vfs_core::mount_ctl::clear_trampolines();
                    old_size = attr.size;
                }
                match ((*ops).data.write)(&data_ctx, write_offset, src, count) {
                    Ok(actual) => {
                        (*reply).label = TRONA_OK;
                        (*reply).length = 1;
                        (*reply).regs[0] = actual;
                        let new_size = core::cmp::max(old_size, write_offset.saturating_add(actual));
                        if let Some(slot) = resolve_fd_mut(state, cli_handle, fd) {
                            slot.offset = write_offset + actual;
                        }
                        if let Some(slot) = resolve_fd(state, cli_handle, fd) {
                            notify_mmsrv_mmap_write(state, slot, write_offset, actual, old_size, new_size);
                        }
                    }
                    Err(e) => {
                        (*reply).label = e.to_trona();
                    }
                }
                return false;
            }
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
        }
    }
}

// =========================================================================
// Device dispatch (stateless IPC — no VFS state needed)
// =========================================================================

unsafe fn device_read(
    dev_type: u8,
    pty_id: u32,
    count: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        match dev_type {
            DEV_CONSOLE => {
                let mut creq = TronaMsg::zeroed();
                let mut creply = TronaMsg::zeroed();
                creq.label = trona::protocol::server::CONSOLE_READ;
                creq.length = 0;
                let err = ipc::call_ctx(
                    ipc_ctx(),
                    trona::caps::console_ep(),
                    &raw const creq,
                    &raw mut creply,
                );
                if err != 0 || creply.label != TRONA_OK {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                let read_count = creply.regs[0];
                let actual = if read_count > count { count } else { read_count };
                (*reply).label = TRONA_OK;
                (*reply).length = 1 + (actual + 7) / 8;
                (*reply).regs[0] = actual;
                if actual > 0 {
                    let src = &creply.regs[1] as *const u64 as *const u8;
                    let dst = &raw mut (*reply).regs[1] as *mut u8;
                    for i in 0..actual as usize {
                        *dst.add(i) = *src.add(i);
                    }
                }
            }
            DEV_NULL => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            DEV_ZERO => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1 + (count + 7) / 8;
                (*reply).regs[0] = count;
                let data = &raw mut (*reply).regs[1] as *mut u8;
                for i in 0..count as usize {
                    *data.add(i) = 0;
                }
            }
            POSIX_DEV_URANDOM => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1 + (count + 7) / 8;
                (*reply).regs[0] = count;
                let data = &raw mut (*reply).regs[1] as *mut u8;
                let mut i: u64 = 0;
                while i + 8 <= count {
                    let v = crate::urandom_next();
                    let bytes = v.to_le_bytes();
                    for j in 0..8 {
                        *data.add(i as usize + j) = bytes[j];
                    }
                    i += 8;
                }
                if i < count {
                    let v = crate::urandom_next();
                    let bytes = v.to_le_bytes();
                    let mut j = 0usize;
                    while i < count {
                        *data.add(i as usize) = bytes[j];
                        i += 1;
                        j += 1;
                    }
                }
            }
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
            }
        }
    }
}

unsafe fn device_write(
    dev_type: u8,
    pty_id: u32,
    count: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        match dev_type {
            DEV_CONSOLE => {
                let src = &(*msg).regs[2] as *const u64 as *const u8;
                let mut sent: u64 = 0;
                while sent < count {
                    let mut creq = TronaMsg::zeroed();
                    let mut creply = TronaMsg::zeroed();
                    let mut chunk = count - sent;
                    if chunk > 24 { chunk = 24; }
                    creq.label = trona::protocol::server::CONSOLE_WRITE;
                    creq.length = 1 + (chunk + 7) / 8;
                    creq.regs[0] = chunk;
                    let dst = &raw mut creq.regs[1] as *mut u8;
                    for i in 0..chunk as usize {
                        *dst.add(i) = *src.add(sent as usize + i);
                    }
                    let err = ipc::call_ctx(
                        ipc_ctx(),
                        trona::caps::console_ep(),
                        &raw const creq,
                        &raw mut creply,
                    );
                    if err != 0 || creply.label != TRONA_OK { break; }
                    sent += chunk;
                }
                (*reply).label = if sent > 0 { TRONA_OK } else { TRONA_INVALID_OPERATION };
                (*reply).length = 1;
                (*reply).regs[0] = sent;
            }
            DEV_NULL | DEV_ZERO | POSIX_DEV_URANDOM => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = count;
            }
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
            }
        }
    }
}
