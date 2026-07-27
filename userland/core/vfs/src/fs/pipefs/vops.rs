// SPDX-License-Identifier: GPL-2.0-only
//
//! pipefs `VopVector` — per-vnode operations for the named-pipe
//! filesystem.
//!
//! `lookup` walks the static slot pool by name. `create` allocates
//! a fresh pipe backing through `core::pipe`, takes a
//! free slot, and registers a new vnode-id on the mount-data
//! parallel arrays. `read` / `write` resolve the pipe handle and
//! drive the ring through the same `core::pipe` helpers used by
//! anonymous pipes.

use crate::core::cred::VfsCred;
use crate::core::error::VfsError;
use crate::core::file::{VAttr, VStatfs};
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::outcome::{Ready, VopOutcome};
use crate::core::pipe::{
    alloc_pipe_from_owner, owner_pipe_ptr, pipe_buf_len, pipe_buf_read, pipe_buf_write,
    release_pipe_from_owner,
};
use crate::core::vnode::{VT_FIFO, VnodeHandle, VnodeKind};
use crate::core::vop::ReaddirEmit;
use crate::core::vop_context::{OwnerVopCtx, VopDataCtx};

use super::types::{MAX_NAMED_PIPES, MAX_PIPE_NAME_LEN, NamedPipeSlot, NamedPipeState};
use super::{PipefsMountData, PipefsVnodeData};

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut PipefsVnodeData {
    ctx.data as *mut PipefsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataCtx) -> *mut PipefsVnodeData {
    ctx.data as *mut PipefsVnodeData
}

#[inline]
unsafe fn mdata(ctx: &OwnerVopCtx<'_>) -> *mut PipefsMountData {
    ctx.mount_data as *mut PipefsMountData
}

#[inline]
unsafe fn mdata_d(ctx: &VopDataCtx) -> *mut PipefsMountData {
    ctx.mount_data as *mut PipefsMountData
}

fn name_eq(a: *const u8, a_len: u8, b: &[u8], b_len: u8) -> bool {
    if a_len != b_len {
        return false;
    }
    for i in 0..a_len as usize {
        if unsafe { *a.add(i) } != b[i] {
            return false;
        }
    }
    true
}

// =========================================================================
// MetaOps
// =========================================================================

pub(crate) unsafe fn pipefs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let md = mdata(ctx);
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            return Ok(Ready(ctx.handle));
        }
        for i in 0..MAX_NAMED_PIPES {
            let slot = &(*md).slots[i];
            if slot.state == NamedPipeState::Created {
                continue;
            }
            if !name_eq(name, name_len, &slot.name, slot.name_len) {
                continue;
            }
            for j in 0..(*md).count {
                let vnode_h = (*md).vnode_handles[j];
                if !vnode_h.is_valid() {
                    continue;
                }
                if (*md).vnode_ids[j] == slot.vnode_id {
                    return Ok(Ready(vnode_h));
                }
            }
        }
        Ok(Ready(VnodeHandle::INVALID))
    }
}

pub(crate) unsafe fn pipefs_create(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        if name_len == 0 || name_len as usize > MAX_PIPE_NAME_LEN {
            return Err(VfsError::NameTooLong);
        }
        let md = mdata(ctx);

        for i in 0..MAX_NAMED_PIPES {
            let slot = &(*md).slots[i];
            if slot.state == NamedPipeState::Created {
                continue;
            }
            if name_eq(name, name_len, &slot.name, slot.name_len) {
                return Err(VfsError::Exist);
            }
        }
        let mut free_idx: Option<usize> = None;
        for i in 0..MAX_NAMED_PIPES {
            if (*md).slots[i].state == NamedPipeState::Created {
                free_idx = Some(i);
                break;
            }
        }
        let slot_idx = free_idx.ok_or(VfsError::NoMem)?;

        let pipe_handle = alloc_pipe_from_owner(&mut *ctx.state).ok_or(VfsError::NoMem)?;

        let id = (*md).next_id;
        (*md).next_id += 1;

        let slot = &raw mut (*md).slots[slot_idx];
        *slot = NamedPipeSlot::zeroed();
        for i in 0..name_len as usize {
            (*slot).name[i] = *name.add(i);
        }
        (*slot).name_len = name_len;
        (*slot).state = NamedPipeState::Listening;
        (*slot).pipe = pipe_handle;
        (*slot).vnode_id = id;
        (*slot).server_badge = 0;
        (*slot).client_badge = 0;

        let (child_vh, child_vp) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let fs_id = (*ctx.mount).fs_instance_id;
        (*child_vp).kind = VnodeKind::Fifo;
        (*child_vp).key = VnodeKey {
            fs_instance_id: fs_id,
            backend_id: BackendNodeId::new(id, 0),
        };
        (*child_vp).backend_seq = 0;
        (*child_vp).mount = ctx.mount_handle;
        (*child_vp).fs_instance_id = fs_id;
        (*child_vp).ops = (*ctx.vnode).ops;
        (*child_vp).nlink = 1;

        let vd_idx = super::alloc_vdata_slot(md);
        if vd_idx.is_none() {
            (*slot).state = NamedPipeState::Closed;
            release_pipe_from_owner(&mut *ctx.state, pipe_handle);
            *slot = NamedPipeSlot::zeroed();
            return Err(VfsError::NoMem);
        }
        let vd_idx = vd_idx.unwrap();
        let vdata = &raw mut (*md).vdata[vd_idx];
        *vdata = PipefsVnodeData::zeroed();
        (*vdata).slot_idx = slot_idx as u32;
        (*vdata).is_root = 0;
        (*child_vp).data = vdata as *mut u8;

        super::record_vnode(md, child_vh, id);

        Ok(Ready(child_vh))
    }
}

pub(crate) unsafe fn pipefs_open(ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);
        if (*vdata).is_root != 0 {
            return Ok(Ready(()));
        }
        let md = mdata(ctx);
        let idx = (*vdata).slot_idx as usize;
        if idx >= MAX_NAMED_PIPES {
            return Err(VfsError::Io);
        }
        let slot = &raw mut (*md).slots[idx];
        match (*slot).state {
            NamedPipeState::Listening => {
                (*slot).state = NamedPipeState::Connected;
                Ok(Ready(()))
            }
            NamedPipeState::Connected => Ok(Ready(())),
            _ => Err(VfsError::Io),
        }
    }
}

pub(crate) unsafe fn pipefs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(crate) unsafe fn pipefs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        (*attr).fs_instance_id = fs_id;
        (*attr).backend_node_id = (*ctx.vnode).id();
        (*attr).backend_seq = 0;
        (*attr).uid = 0;
        (*attr).gid = 0;
        (*attr).nlink = (*ctx.vnode).nlink;
        (*attr).atime = 0;
        (*attr).mtime = 0;
        (*attr).ctime = 0;
        (*attr).blocks = 0;
        if (*vdata).is_root != 0 {
            (*attr).kind = VnodeKind::Directory;
            (*attr).mode = 0o040755;
            (*attr).size = 0;
        } else {
            (*attr).kind = VnodeKind::Fifo;
            (*attr).mode = 0o010666;
            (*attr).size = 0;
        }
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn pipefs_access(
    _ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(crate) unsafe fn pipefs_unlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let md = mdata(ctx);
        for i in 0..MAX_NAMED_PIPES {
            let slot = &raw mut (*md).slots[i];
            if (*slot).state == NamedPipeState::Created {
                continue;
            }
            if !name_eq(name, name_len, &(*slot).name, (*slot).name_len) {
                continue;
            }
            if (*slot).pipe.is_valid() {
                release_pipe_from_owner(&mut *ctx.state, (*slot).pipe);
            }
            (*slot).state = NamedPipeState::Closed;
            let target_id = (*slot).vnode_id;
            for j in 0..(*md).count {
                if (*md).vnode_ids[j] == target_id && (*md).vnode_handles[j].is_valid() {
                    (*md).vnode_handles[j] = VnodeHandle::INVALID;
                    break;
                }
            }
            *slot = NamedPipeSlot::zeroed();
            return Ok(Ready(()));
        }
        Err(VfsError::NoEnt)
    }
}

pub(crate) unsafe fn pipefs_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        crate::owner::pager_rpc::release_mo_binding_for_vnode(ctx.state, ctx.handle);
    }
    Ok(Ready(()))
}

// =========================================================================
// DataOps
// =========================================================================

pub(crate) unsafe fn pipefs_read(
    ctx: &VopDataCtx,
    _offset: u64,
    dst: *mut u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        if (*vdata).is_root != 0 {
            return Err(VfsError::IsDir);
        }
        let md = mdata_d(ctx);
        let idx = (*vdata).slot_idx as usize;
        if idx >= MAX_NAMED_PIPES {
            return Err(VfsError::Io);
        }
        let slot = &(*md).slots[idx];
        if slot.state != NamedPipeState::Connected {
            return Err(VfsError::Io);
        }
        let Some(owner_state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let pipe = owner_pipe_ptr(owner_state, slot.pipe);
        if pipe.is_null() {
            return Err(VfsError::Io);
        }
        let avail = pipe_buf_len(pipe);
        if avail == 0 {
            return Ok(Ready(0));
        }
        let mut count = avail as u64;
        if count > len {
            count = len;
        }
        if count > 4096 {
            count = 4096;
        }
        let actual = pipe_buf_read(pipe, dst, count as u16);
        Ok(Ready(actual as u64))
    }
}

pub(crate) unsafe fn pipefs_write(
    ctx: &VopDataCtx,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        if (*vdata).is_root != 0 {
            return Err(VfsError::IsDir);
        }
        let md = mdata_d(ctx);
        let idx = (*vdata).slot_idx as usize;
        if idx >= MAX_NAMED_PIPES {
            return Err(VfsError::Io);
        }
        let slot = &(*md).slots[idx];
        if slot.state != NamedPipeState::Connected {
            return Err(VfsError::Io);
        }
        let Some(owner_state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let pipe = owner_pipe_ptr(owner_state, slot.pipe);
        if pipe.is_null() {
            return Err(VfsError::Io);
        }
        let mut count = len;
        if count > 4096 {
            count = 4096;
        }
        let actual = pipe_buf_write(pipe, src, count as u16);
        Ok(Ready(actual as u64))
    }
}

pub(crate) unsafe fn pipefs_readdir(
    ctx: &VopDataCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let md = mdata_d(ctx);
        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        if pos == 0 {
            if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }
        if pos == 1 {
            if !emit(ctx.id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }

        let base = 2u64;
        for i in 0..MAX_NAMED_PIPES {
            let slot = &(*md).slots[i];
            if slot.state == NamedPipeState::Created {
                continue;
            }
            let entry_pos = base + i as u64;
            if pos > entry_pos {
                continue;
            }
            // DT_FIFO = 1
            if !emit(slot.vnode_id, slot.name.as_ptr(), slot.name_len, 1, &attr) {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }
        let _ = VT_FIFO;
        *cookie = pos;
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn pipefs_statfs(ctx: &VopDataCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        let md = mdata_d(ctx);
        (*out).bsize = 4096;
        (*out).frsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = (*md).count as u64;
        (*out).ffree = (super::MAX_PIPEFS_VNODES - (*md).count) as u64;
        (*out).favail = (*out).ffree;
        (*out).fsid = ctx.fs_instance_id.0;
        (*out).flag = 0;
        (*out).namemax = 128;
        (*out).set_fs_name(b"pipefs");
        Ok(Ready(()))
    }
}
