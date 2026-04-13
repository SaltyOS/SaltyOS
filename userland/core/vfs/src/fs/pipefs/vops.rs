// SPDX-License-Identifier: GPL-2.0-only
//! pipefs `VopVector` — per-vnode operations for the named pipe filesystem.
//!
//! MetaOps handle lookup, create, open, close, unlink, getattr, access.
//! DataOps handle read, write, readdir, statfs.
//! All operations receive `&VopContext` or `&VopDataContext` — no raw vnode
//! pointers. Vnode allocation goes through `ctx.alloc`.

use crate::fileops::pipe::{
    alloc_pipe_from_owner, owner_pipe_ptr, pipe_buf_len, pipe_buf_read, pipe_buf_write,
    release_pipe_from_owner,
};
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::vnode::{VnodeHandle, VT_FIFO};
use crate::vfs_core::vop::{
    ReaddirEmit, VopDataOps, VopMetaOps, VopVector, DATA_OPS_DEFAULT, META_OPS_DEFAULT,
};
use crate::vfs_core::vop_context::{VopContext, VopDataContext};

use super::types::{PipeState, MAX_NAMED_PIPES, MAX_PIPE_NAME_LEN};
use super::PipefsMountData;

// =========================================================================
// Helpers
// =========================================================================

#[inline]
unsafe fn vdata(ctx: &VopContext) -> *mut super::PipefsVnodeData {
    ctx.data as *mut super::PipefsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataContext) -> *mut super::PipefsVnodeData {
    ctx.data as *mut super::PipefsVnodeData
}

#[inline]
unsafe fn mdata(ctx: &VopContext) -> *mut PipefsMountData {
    ctx.mount_data as *mut PipefsMountData
}

#[inline]
unsafe fn mdata_d(ctx: &VopDataContext) -> *mut PipefsMountData {
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
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = mdata(ctx);

        // "." — self reference.
        if name_len == 1 && *name == b'.' {
            return Ok(ctx.handle);
        }

        // ".." — parent is self (mount layer handles cross-mount).
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            return Ok(ctx.handle);
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
                    return Ok(vh);
                }
            }
        }

        Ok(VnodeHandle::INVALID)
    }
}

unsafe fn pipefs_create(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
    _mode: u32,
    _cred: *const VfsCred,
) -> VfsResult<VnodeHandle> {
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
        let Some(pipe_handle) = alloc_pipe_from_owner() else {
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
        let (child_vh, child_vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
        (*child_vp).vtype = VT_FIFO;
        (*child_vp).id = id;
        (*child_vp).mount = ctx.mount_handle;
        (*child_vp).ops = (*ctx.vnode).ops;
        (*child_vp).nlink = 1;

        // Set up vnode data.
        let vd_idx = super::alloc_vdata_slot(md);
        if vd_idx.is_none() {
            // Roll back slot allocation.
            (*slot).state = PipeState::Created;
            (*slot).name_len = 0;
            (*slot).pipe = crate::arena::Handle::INVALID;
            release_pipe_from_owner(pipe_handle);
            return Err(VfsError::NoSpace);
        }
        let vd_idx = vd_idx.unwrap();
        let vd = &raw mut (*md).vdata[vd_idx];
        (*vd).slot_idx = slot_idx as u32;
        (*vd).is_root = 0;
        (*child_vp).data = vd as *mut u8;

        // Record the handle.
        super::record_vnode(md, child_vh, id);

        Ok(child_vh)
    }
}

unsafe fn pipefs_open(ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    unsafe {
        let vd = vdata(ctx);
        if (*vd).is_root != 0 {
            return Ok(());
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
                Ok(())
            }
            PipeState::Connected => Ok(()),
            _ => Err(VfsError::Io),
        }
    }
}

unsafe fn pipefs_close(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

unsafe fn pipefs_getattr(ctx: &VopContext, attr: *mut VAttr) -> VfsResult<()> {
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

        Ok(())
    }
}

unsafe fn pipefs_access(
    _ctx: &VopContext,
    _mode: u32,
    _cred: *const VfsCred,
) -> VfsResult<()> {
    Ok(())
}

unsafe fn pipefs_unlink(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<()> {
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
                release_pipe_from_owner((*slot).pipe);
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

            return Ok(());
        }

        Err(VfsError::NotFound)
    }
}

unsafe fn pipefs_inactive(_ctx: &VopContext) {}

// =========================================================================
// DataOps
// =========================================================================

unsafe fn pipefs_read(
    ctx: &VopDataContext,
    _offset: u64,
    dst: *mut u8,
    len: u64,
) -> VfsResult<u64> {
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

        let pipe = owner_pipe_ptr(slot.pipe);
        if pipe.is_null() {
            return Err(VfsError::Io);
        }

        let avail = pipe_buf_len(pipe);
        if avail == 0 {
            return Ok(0);
        }

        let mut count = avail as u64;
        if count > len {
            count = len;
        }
        if count > 4096 {
            count = 4096;
        }

        let actual = pipe_buf_read(pipe, dst, count as u16);
        Ok(actual as u64)
    }
}

unsafe fn pipefs_write(
    ctx: &VopDataContext,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VfsResult<u64> {
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

        let pipe = owner_pipe_ptr(slot.pipe);
        if pipe.is_null() {
            return Err(VfsError::Io);
        }

        let mut count = len;
        if count > 4096 {
            count = 4096;
        }

        let actual = pipe_buf_write(pipe, src, count as u16);
        Ok(actual as u64)
    }
}

unsafe fn pipefs_readdir(
    ctx: &VopDataContext,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VfsResult<()> {
    unsafe {
        let md = mdata_d(ctx);
        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        // "."
        if pos == 0 {
            if !emit(ctx.id, b".".as_ptr(), 1, 4 /* DT_DIR */, &attr) {
                *cookie = pos + 1;
                return Ok(());
            }
            pos += 1;
        }

        // ".."
        if pos == 1 {
            if !emit(ctx.id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = pos + 1;
                return Ok(());
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
                return Ok(());
            }
            pos = entry_pos + 1;
        }

        *cookie = pos;
        Ok(())
    }
}

unsafe fn pipefs_statfs(ctx: &VopDataContext, out: *mut VStatfs) -> VfsResult<()> {
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
        Ok(())
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
        read: pipefs_read,
        write: pipefs_write,
        readdir: pipefs_readdir,
        statfs: pipefs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
