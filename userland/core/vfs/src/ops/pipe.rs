// SPDX-License-Identifier: GPL-2.0-only
//
//! Anonymous pipe allocation shared by POSIX `pipe(2)` and
//! Win32 pipe creation.

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::identity::FsInstanceId;
use crate::core::mount::MountKind;
use crate::core::pipe::{ANONPIPE_VOPS, PipeState, alloc_pipe_from_owner, release_pipe_from_owner};
use crate::core::vnode::{VnodeHandle, VnodeKind};
use crate::owner::VfsState;
use crate::server::open_object::FD_FLAG_CLOEXEC;
use crate::server::open_object::{OpenObjectAccess, OpenObjectFlags, OpenObjectKind};
use crate::server::types::{ClientHandle, OpenObjectHandle};

const OPEN_NONBLOCK: u32 = 0x800;
const OPEN_CLOEXEC: u32 = 0x80000;

pub(crate) unsafe fn do_create_anonymous_pipe_pair(
    state: &mut VfsState,
    client: ClientHandle,
    flags: u32,
) -> Result<(u32, u32), VfsError> {
    unsafe {
        if (flags & !(OPEN_CLOEXEC | OPEN_NONBLOCK)) != 0 {
            return Err(VfsError::Inval);
        }
        let cloexec = (flags & OPEN_CLOEXEC) != 0;
        let nonblock = (flags & OPEN_NONBLOCK) != 0;

        let pipe_h = alloc_pipe_from_owner(state).ok_or(VfsError::NoMem)?;
        let pipe_ptr = state
            .pipes
            .raw_ptr(pipe_h)
            .unwrap_or(::core::ptr::null_mut());
        if pipe_ptr.is_null() {
            release_pipe_from_owner(state, pipe_h);
            return Err(VfsError::Io);
        }

        let vnode_h = match state.vnodes.alloc() {
            Some(h) => h,
            None => {
                release_pipe_from_owner(state, pipe_h);
                return Err(VfsError::NoMem);
            }
        };
        if let Some(vn) = state.vnodes.get_mut(vnode_h) {
            *vn = crate::core::vnode::Vnode::EMPTY;
            vn.kind = VnodeKind::Pipe;
            vn.mount = Handle::INVALID;
            vn.fs_instance_id = FsInstanceId::INVALID;
            vn.key = crate::core::identity::VnodeKey::NONE;
            vn.ops = &raw const ANONPIPE_VOPS;
            vn.data = pipe_ptr as *mut u8;
            vn.flags = 0;
            vn.nlink = 1;
            vn.open_refcount = 0;
            vn.cache_pin = 0;
            vn.backend_seq = 0;
            vn.covered_by_fs = FsInstanceId::INVALID;
        }

        let read_oo = match state.open_objects.alloc() {
            Some(h) => h,
            None => {
                let _ = state.vnodes.release(vnode_h);
                release_pipe_from_owner(state, pipe_h);
                return Err(VfsError::NoMem);
            }
        };
        if let Some(obj) = state.open_objects.get_mut(read_oo) {
            *obj = crate::server::open_object::OpenObject::EMPTY;
            obj.vnode = vnode_h;
            obj.offset = 0;
            obj.refcount = 1;
            obj.kind = OpenObjectKind::Pipe;
            obj.flags = OpenObjectFlags::READABLE
                | if nonblock {
                    OpenObjectFlags::O_NONBLOCK
                } else {
                    0
                };
            obj.access = OpenObjectAccess::READ;
            obj.share = crate::ops::SharePolicy::permissive().bits();
            obj.personality_aux = pipe_h.slot();
            obj.named_state = crate::arena::Handle::INVALID;
        }

        let write_oo = match state.open_objects.alloc() {
            Some(h) => h,
            None => {
                state.open_objects.release(read_oo);
                let _ = state.vnodes.release(vnode_h);
                release_pipe_from_owner(state, pipe_h);
                return Err(VfsError::NoMem);
            }
        };
        if let Some(obj) = state.open_objects.get_mut(write_oo) {
            *obj = crate::server::open_object::OpenObject::EMPTY;
            obj.vnode = vnode_h;
            obj.offset = 0;
            obj.refcount = 1;
            obj.kind = OpenObjectKind::Pipe;
            obj.flags = OpenObjectFlags::WRITABLE
                | if nonblock {
                    OpenObjectFlags::O_NONBLOCK
                } else {
                    0
                };
            obj.access = OpenObjectAccess::WRITE;
            obj.share = crate::ops::SharePolicy::permissive().bits();
            obj.personality_aux = pipe_h.slot();
            obj.named_state = crate::arena::Handle::INVALID;
        }
        if let Some(vn) = state.vnodes.get_mut(vnode_h) {
            vn.open_refcount = 2;
        }

        let read_fd = match state
            .clients
            .get_mut(client)
            .and_then(|c| c.slot_table.find_first_empty_from(0).ok())
        {
            Some(fd) => fd,
            None => {
                rollback_pipe_alloc(state, vnode_h, pipe_h, read_oo, write_oo);
                return Err(VfsError::NoMem);
            }
        };
        let read_set = state
            .clients
            .get_mut(client)
            .map(|c| c.slot_table.set(read_fd, read_oo))
            .unwrap_or_else(|| Err(crate::arena::segmented_array::SegError::OutOfMemory));
        if read_set.is_err() {
            rollback_pipe_alloc(state, vnode_h, pipe_h, read_oo, write_oo);
            return Err(VfsError::NoMem);
        }

        let write_fd = match state
            .clients
            .get_mut(client)
            .and_then(|c| c.slot_table.find_first_empty_from(read_fd + 1).ok())
        {
            Some(fd) => fd,
            None => {
                if let Some(c) = state.clients.get_mut(client) {
                    c.slot_table.clear(read_fd);
                }
                rollback_pipe_alloc(state, vnode_h, pipe_h, read_oo, write_oo);
                return Err(VfsError::NoMem);
            }
        };
        let write_set = state
            .clients
            .get_mut(client)
            .map(|c| c.slot_table.set(write_fd, write_oo))
            .unwrap_or_else(|| Err(crate::arena::segmented_array::SegError::OutOfMemory));
        if write_set.is_err() {
            if let Some(c) = state.clients.get_mut(client) {
                c.slot_table.clear(read_fd);
            }
            rollback_pipe_alloc(state, vnode_h, pipe_h, read_oo, write_oo);
            return Err(VfsError::NoMem);
        }

        if cloexec {
            if let Some(c) = state.clients.get_mut(client) {
                c.slot_table
                    .set_slot_flag_bit(read_fd, FD_FLAG_CLOEXEC, true);
                c.slot_table
                    .set_slot_flag_bit(write_fd, FD_FLAG_CLOEXEC, true);
            }
        }

        Ok((read_fd, write_fd))
    }
}

pub(crate) unsafe fn ensure_fifo_pipe(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
) -> Result<Handle<PipeState>, VfsError> {
    unsafe {
        let (mount_h, data_ptr) = match state.vnodes.get(vnode_h) {
            Some(vn) if vn.kind == VnodeKind::Fifo => (vn.mount, vn.data),
            Some(_) => return Err(VfsError::Inval),
            None => return Err(VfsError::NoEnt),
        };
        if data_ptr.is_null() {
            return Err(VfsError::Io);
        }
        let mount_kind = state
            .mounts
            .get(mount_h)
            .map(|m| m.kind)
            .ok_or(VfsError::Io)?;
        let slot = match mount_kind {
            MountKind::Initrd | MountKind::Ramfs => {
                let vd = data_ptr as *mut crate::fs::ramfs::types::RamfsVnodeData;
                &mut (*vd).fifo_pipe
            }
            MountKind::Tmpfs => {
                let vd = data_ptr as *mut crate::fs::tmpfs::types::TmpfsVnodeData;
                &mut (*vd).fifo_pipe
            }
            _ => return Err(VfsError::NotSup),
        };
        if slot.is_valid() {
            return Ok(*slot);
        }
        let pipe_h = alloc_pipe_from_owner(state).ok_or(VfsError::NoMem)?;
        if let Some(pipe) = state.pipes.get_mut(pipe_h) {
            pipe.read_refcount = 0;
            pipe.write_refcount = 0;
        }
        *slot = pipe_h;
        Ok(pipe_h)
    }
}

pub(crate) unsafe fn drop_pipe_open_ref(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
    pipe_h: Handle<PipeState>,
    flags: u8,
) {
    unsafe {
        if let Some(vn) = state.vnodes.get_mut(vnode_h) {
            vn.open_refcount = vn.open_refcount.saturating_sub(1);
        }
        let mut release_pipe = false;
        if let Some(pipe) = state.pipes.get_mut(pipe_h) {
            if (flags & OpenObjectFlags::READABLE) != 0 {
                pipe.read_refcount = pipe.read_refcount.saturating_sub(1);
            }
            if (flags & OpenObjectFlags::WRITABLE) != 0 {
                pipe.write_refcount = pipe.write_refcount.saturating_sub(1);
            }
            release_pipe = pipe.read_refcount == 0 && pipe.write_refcount == 0;
        }
        if !release_pipe {
            return;
        }
        clear_fifo_pipe_slot(state, vnode_h, pipe_h);
        release_pipe_from_owner(state, pipe_h);
    }
}

fn clear_fifo_pipe_slot(state: &mut VfsState, vnode_h: VnodeHandle, pipe_h: Handle<PipeState>) {
    unsafe {
        let (mount_h, data_ptr, kind) = match state.vnodes.get(vnode_h) {
            Some(vn) => (vn.mount, vn.data, vn.kind),
            None => return,
        };
        if kind != VnodeKind::Fifo || data_ptr.is_null() {
            return;
        }
        let Some(mount_kind) = state.mounts.get(mount_h).map(|m| m.kind) else {
            return;
        };
        let slot = match mount_kind {
            MountKind::Initrd | MountKind::Ramfs => {
                let vd = data_ptr as *mut crate::fs::ramfs::types::RamfsVnodeData;
                &mut (*vd).fifo_pipe
            }
            MountKind::Tmpfs => {
                let vd = data_ptr as *mut crate::fs::tmpfs::types::TmpfsVnodeData;
                &mut (*vd).fifo_pipe
            }
            _ => return,
        };
        if *slot == pipe_h {
            *slot = Handle::INVALID;
        }
    }
}

unsafe fn rollback_pipe_alloc(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
    pipe_h: Handle<PipeState>,
    read_oo: OpenObjectHandle,
    write_oo: OpenObjectHandle,
) {
    unsafe {
        state.open_objects.release(read_oo);
        state.open_objects.release(write_oo);
        if let Some(vn) = state.vnodes.get_mut(vnode_h) {
            vn.open_refcount = 0;
        }
        let _ = state.vnodes.release(vnode_h);
        release_pipe_from_owner(state, pipe_h);
    }
}
