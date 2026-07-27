// SPDX-License-Identifier: GPL-2.0-only
//! pipefs `VopVector` — per-vnode operations for the named pipe filesystem.
//!
//! MetaOps handle lookup, create, open, close, unlink, getattr, access.
//! DataOps handle read, write, readdir, statfs.
//! All operations receive `&VopContext` or `&WorkerIoCtx` — no raw vnode
//! pointers. Vnode allocation goes through `ctx.alloc`.

use crate::fileops::pipe::{
    alloc_pipe_from_owner, owner_pipe_ptr, pipe_buf_len, pipe_buf_read, pipe_buf_write,
    release_pipe_from_owner,
};
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::outcome::{Ready, VopOutcome};
use crate::vfs_core::vnode::{VT_FIFO, VnodeHandle};
use crate::vfs_core::vop::{
    DATA_OPS_DEFAULT, DataExecMode, META_OPS_DEFAULT, ReaddirEmit, VopDataOps, VopMetaOps,
    VopVector,
};
use crate::vfs_core::vop_context::{OwnerVopCtx, WorkerIoCtx};

use super::PipefsMountData;
use super::types::{MAX_NAMED_PIPES, MAX_PIPE_NAME_LEN, PipeState};

// =========================================================================
// Helpers
// =========================================================================

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut super::PipefsVnodeData {
    ctx.data as *mut super::PipefsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &WorkerIoCtx) -> *mut super::PipefsVnodeData {
    ctx.data as *mut super::PipefsVnodeData
}

#[inline]
unsafe fn mdata(ctx: &OwnerVopCtx<'_>) -> *mut PipefsMountData {
    ctx.mount_data as *mut PipefsMountData
}

#[inline]
unsafe fn mdata_d(ctx: &WorkerIoCtx) -> *mut PipefsMountData {
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

unsafe fn pipefs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let md = mdata(ctx);

        // "." — self reference.
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }

        // ".." — parent is self (mount layer handles cross-mount).
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            return Ok(Ready(ctx.handle));
        }

        // Search named pipe slots by name, return the corresponding VnodeHandle.
        for i in 0..MAX_NAMED_PIPES {
            let slot = &(*md).slots[i];
            if slot.state == PipeState::Created {
                continue;
            }
            if !name_eq(name, name_len, &slot.name, slot.name_len) {
                continue;
            }

            // Find the handle in the vnode_handles array.
            for j in 0..(*md).count {
                let vh = (*md).vnode_handles[j];
                if !vh.is_valid() {
                    continue;
                }
                if (*md).vnode_ids[j] == slot.vnode_id {
                    return Ok(Ready(vh));
                }
            }
        }

        Ok(Ready(VnodeHandle::INVALID))
    }
}

unsafe fn pipefs_create(
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

        // Reject duplicate names.
        for i in 0..MAX_NAMED_PIPES {
            let slot = &(*md).slots[i];
            if slot.state == PipeState::Created {
                continue;
            }
            if name_eq(name, name_len, &slot.name, slot.name_len) {
                return Err(VfsError::Exists);
            }
        }

        // Find a free slot.
        let mut free_idx: Option<usize> = None;
        for i in 0..MAX_NAMED_PIPES {
            if (*md).slots[i].state == PipeState::Created {
                free_idx = Some(i);
                break;
            }
        }
        let slot_idx = free_idx.ok_or(VfsError::NoSpace)?;

        // Allocate a backing anonymous pipe.
        let Some(pipe_handle) = alloc_pipe_from_owner(&mut *ctx.state) else {
            return Err(VfsError::NoSpace);
        };

        // Assign a vnode id.
        let id = (*md).next_id;
        (*md).next_id += 1;

        // Populate the slot.
        let slot = &raw mut (*md).slots[slot_idx];
        for i in 0..name_len as usize {
            (*slot).name[i] = *name.add(i);
        }
        (*slot).name_len = name_len;
        (*slot).state = PipeState::Listening;
        (*slot).pipe = pipe_handle;
        (*slot).vnode_id = id;
        (*slot).server_badge = 0;
        (*slot).client_badge = 0;

        // Allocate a vnode via arena callback.
        let (child_vh, child_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        (*child_vp).vtype = VT_FIFO;
        (*child_vp).id = id;
        (*child_vp)
            .mount
            .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
        (*child_vp).fs_instance_id = (*ctx.mount).fs_instance_id;
        (*child_vp).ops = (*ctx.vnode).ops;
        (*child_vp).nlink = 1;

        // Set up vnode data.
        let vd_idx = super::alloc_vdata_slot(md);
        if vd_idx.is_none() {
            // Roll back slot allocation.
            (*slot).state = PipeState::Created;
            (*slot).name_len = 0;
            (*slot).pipe = crate::arena::Handle::INVALID;
            release_pipe_from_owner(&mut *ctx.state, pipe_handle);
            return Err(VfsError::NoSpace);
        }
        let vd_idx = vd_idx.unwrap();
        let vd = &raw mut (*md).vdata[vd_idx];
        (*vd).slot_idx = slot_idx as u32;
        (*vd).is_root = 0;
        (*child_vp).data = vd as *mut u8;

        // Record the handle.
        super::record_vnode(md, child_vh, id);

        Ok(Ready(child_vh))
    }
}

unsafe fn pipefs_open(ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if (*vd).is_root != 0 {
            return Ok(Ready(()));
        }

        let md = mdata(ctx);
        let idx = (*vd).slot_idx as usize;
        if idx >= MAX_NAMED_PIPES {
            return Err(VfsError::Io);
        }

        let slot = &raw mut (*md).slots[idx];
        match (*slot).state {
            PipeState::Listening => {
                (*slot).state = PipeState::Connected;
                Ok(Ready(()))
            }
            PipeState::Connected => Ok(Ready(())),
            _ => Err(VfsError::Io),
        }
    }
}

unsafe fn pipefs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn pipefs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);

        (*attr).uid = 0;
        (*attr).gid = 0;
        (*attr).nlink = (*ctx.vnode).nlink;
        (*attr).atime = 0;
        (*attr).mtime = 0;
        (*attr).ctime = 0;
        (*attr).btime = 0;
        (*attr).blocks = 0;
        (*attr).dev_id = 0;
        (*attr).rdev = 0;

        if (*vd).is_root != 0 {
            (*attr).mode = 0o040755;
            (*attr).size = 0;
        } else {
            (*attr).mode = 0o010666;
            (*attr).size = 0;
        }

        Ok(Ready(()))
    }
}

unsafe fn pipefs_access(
    _ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn pipefs_unlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let md = mdata(ctx);

        for i in 0..MAX_NAMED_PIPES {
            let slot = &raw mut (*md).slots[i];
            if (*slot).state == PipeState::Created {
                continue;
            }
            if !name_eq(name, name_len, &(*slot).name, (*slot).name_len) {
                continue;
            }

            // Mark the backing anonymous pipe as inactive.
            if (*slot).pipe.is_valid() {
                release_pipe_from_owner(&mut *ctx.state, (*slot).pipe);
            }

            // Deactivate the corresponding vnode handle entry.
            let target_id = (*slot).vnode_id;
            for j in 0..(*md).count {
                if (*md).vnode_ids[j] == target_id && (*md).vnode_handles[j].is_valid() {
                    (*md).vnode_handles[j] = VnodeHandle::INVALID;
                    break;
                }
            }

            // Reset slot to free.
            (*slot).state = PipeState::Created;
            (*slot).name_len = 0;
            (*slot).pipe = crate::arena::Handle::INVALID;
            (*slot).vnode_id = 0;
            (*slot).server_badge = 0;
            (*slot).client_badge = 0;

            return Ok(Ready(()));
        }

        Err(VfsError::NotFound)
    }
}

unsafe fn pipefs_inactive(_ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    Ok(Ready(()))
}

// =========================================================================
// DataOps
// =========================================================================

unsafe fn pipefs_read(ctx: &WorkerIoCtx, _offset: u64, dst: *mut u8, len: u64) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if (*vd).is_root != 0 {
            return Err(VfsError::IsDir);
        }

        let md = mdata_d(ctx);
        let idx = (*vd).slot_idx as usize;
        if idx >= MAX_NAMED_PIPES {
            return Err(VfsError::Io);
        }

        let slot = &(*md).slots[idx];
        if slot.state != PipeState::Connected {
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

unsafe fn pipefs_write(
    ctx: &WorkerIoCtx,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if (*vd).is_root != 0 {
            return Err(VfsError::IsDir);
        }

        let md = mdata_d(ctx);
        let idx = (*vd).slot_idx as usize;
        if idx >= MAX_NAMED_PIPES {
            return Err(VfsError::Io);
        }

        let slot = &(*md).slots[idx];
        if slot.state != PipeState::Connected {
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

unsafe fn pipefs_readdir(
    ctx: &WorkerIoCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let md = mdata_d(ctx);
        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        // "."
        if pos == 0 {
            if !emit(ctx.id, b".".as_ptr(), 1, 4 /* DT_DIR */, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }

        // ".."
        if pos == 1 {
            if !emit(ctx.id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }

        // Named pipe entries.
        let base = 2u64;
        for i in 0..MAX_NAMED_PIPES {
            let slot = &(*md).slots[i];
            if slot.state == PipeState::Created {
                continue;
            }

            let entry_pos = base + i as u64;
            if pos > entry_pos {
                continue;
            }

            if !emit(
                slot.vnode_id,
                slot.name.as_ptr(),
                slot.name_len,
                1, // DT_FIFO
                &attr,
            ) {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }

        *cookie = pos;
        Ok(Ready(()))
    }
}

unsafe fn pipefs_statfs(ctx: &WorkerIoCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        let md = mdata_d(ctx);
        (*out).bsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = (*md).count as u64;
        (*out).ffree = (super::MAX_PIPEFS_VNODES - (*md).count) as u64;
        (*out).fs_type = [0; 16];
        (&mut (*out).fs_type)[..6].copy_from_slice(b"pipefs");
        (*out).flags = 0;
        (*out).name_max = 128;
        Ok(Ready(()))
    }
}

// =========================================================================
// Static dispatch table
// =========================================================================

pub(super) static PIPEFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: pipefs_lookup,
        create: pipefs_create,
        open: pipefs_open,
        close: pipefs_close,
        getattr: pipefs_getattr,
        access: pipefs_access,
        unlink: pipefs_unlink,
        inactive: pipefs_inactive,
        ..META_OPS_DEFAULT
    },
    data: VopDataOps {
        readdir_mode: DataExecMode::WorkerSafe,
        read: pipefs_read,
        write: pipefs_write,
        readdir: pipefs_readdir,
        statfs: pipefs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
