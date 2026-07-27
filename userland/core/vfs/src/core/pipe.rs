// SPDX-License-Identifier: GPL-2.0-only
//
//! Pipe backing shared by anonymous pipes, FIFOs, and pipefs.
//!
//! This module is intentionally below personalities: it owns the
//! ring buffer, pipe arena lifetime helpers, and mount-less
//! anonymous-pipe vop table. POSIX and Win32 decode their own wire
//! requests and call `ops::pipe`; backends such as pipefs call the
//! ring helpers directly.

use crate::arena::handle::Handle;
use crate::core::cred::VfsCred;
use crate::core::error::VfsError;
use crate::core::file::{VAttr, VStatfs};
use crate::core::outcome::{Ready, VopOutcome};
use crate::core::vnode::{VT_FIFO, VnodeKind};
use crate::core::vop::{META_OPS_DEFAULT, ReaddirEmit, VopDataOps, VopMetaOps, VopVector};
use crate::core::vop_context::{OwnerVopCtx, VopDataCtx};
use crate::owner::VfsState;
use crate::server::consts::PIPE_BUF_SIZE;

#[repr(C)]
pub(crate) struct PipeState {
    pub(crate) active: u8,
    pub(crate) read_refcount: u16,
    pub(crate) write_refcount: u16,
    pub(crate) data_buf: [u8; PIPE_BUF_SIZE],
    pub(crate) data_head: u16,
    pub(crate) data_tail: u16,
    /// Head slot in `VfsState.poll_waiters` for pipe/FIFO
    /// readiness waiters parked on this pipe-backed object.
    pub(crate) readiness_wait_head: u32,
}

impl PipeState {
    pub(crate) const fn zeroed() -> Self {
        Self {
            active: 0,
            read_refcount: 0,
            write_refcount: 0,
            data_buf: [0; PIPE_BUF_SIZE],
            data_head: 0,
            data_tail: 0,
            readiness_wait_head: u32::MAX,
        }
    }
}

// SAFETY: Pipe state is mutated by the VFS owner thread. Readiness
// waiters are arena handles in `VfsState.poll_waiters` and do not
// cross threads.
unsafe impl Sync for PipeState {}

pub(crate) unsafe fn alloc_pipe_from_owner(state: &mut VfsState) -> Option<Handle<PipeState>> {
    unsafe {
        let h = state.pipes.alloc()?;
        let p = state.pipes.raw_ptr(h)?;
        *p = PipeState::zeroed();
        (*p).active = 1;
        (*p).read_refcount = 1;
        (*p).write_refcount = 1;
        Some(h)
    }
}

pub(crate) unsafe fn release_pipe_from_owner(state: &mut VfsState, h: Handle<PipeState>) {
    unsafe {
        crate::owner::pipe_wait::drain_all(state, h);
        if let Some(p) = state.pipes.raw_ptr(h) {
            (*p).active = 0;
            (*p).read_refcount = 0;
            (*p).write_refcount = 0;
            (*p).data_head = 0;
            (*p).data_tail = 0;
            (*p).readiness_wait_head = u32::MAX;
        }
        let _ = state.pipes.release(h);
    }
}

pub(crate) unsafe fn owner_pipe_ptr(state: &mut VfsState, h: Handle<PipeState>) -> *mut PipeState {
    unsafe { state.pipes.raw_ptr(h).unwrap_or(::core::ptr::null_mut()) }
}

pub(crate) unsafe fn pipe_buf_len(p: *mut PipeState) -> u16 {
    unsafe {
        let head = (*p).data_head as usize;
        let tail = (*p).data_tail as usize;
        let len = if tail >= head {
            tail - head
        } else {
            PIPE_BUF_SIZE - head + tail
        };
        len as u16
    }
}

pub(crate) unsafe fn pipe_buf_avail(p: *mut PipeState) -> u16 {
    unsafe {
        let len = pipe_buf_len(p) as usize;
        ((PIPE_BUF_SIZE - 1) - len) as u16
    }
}

pub(crate) unsafe fn pipe_buf_read(p: *mut PipeState, dst: *mut u8, count: u16) -> u16 {
    unsafe {
        let avail = pipe_buf_len(p);
        let want = if count < avail { count } else { avail };
        if want == 0 {
            return 0;
        }
        let mut head = (*p).data_head as usize;
        for i in 0..want as usize {
            *dst.add(i) = (*p).data_buf[head];
            head += 1;
            if head == PIPE_BUF_SIZE {
                head = 0;
            }
        }
        (*p).data_head = head as u16;
        want
    }
}

pub(crate) unsafe fn pipe_buf_write(p: *mut PipeState, src: *const u8, count: u16) -> u16 {
    unsafe {
        let avail = pipe_buf_avail(p);
        let want = if count < avail { count } else { avail };
        if want == 0 {
            return 0;
        }
        let mut tail = (*p).data_tail as usize;
        for i in 0..want as usize {
            (*p).data_buf[tail] = *src.add(i);
            tail += 1;
            if tail == PIPE_BUF_SIZE {
                tail = 0;
            }
        }
        (*p).data_tail = tail as u16;
        want
    }
}

unsafe fn anonpipe_meta_open(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn anonpipe_meta_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn anonpipe_meta_getattr(ctx: &mut OwnerVopCtx<'_>, out: *mut VAttr) -> VopOutcome<()> {
    unsafe {
        let pipe = (*ctx.vnode).data as *mut PipeState;
        let size = if pipe.is_null() {
            0
        } else {
            pipe_buf_len(pipe) as u64
        };
        let vnode_id = (*ctx.vnode).id();
        let attr = &mut *out;
        attr.fs_instance_id = crate::core::identity::FsInstanceId::INVALID;
        attr.backend_node_id = vnode_id;
        attr.backend_seq = 0;
        attr.kind = VnodeKind::Pipe;
        attr.mode = (VT_FIFO as u32) | 0o666;
        attr.uid = 0;
        attr.gid = 0;
        attr.nlink = 1;
        attr.size = size;
        attr.blocks = (size + 511) / 512;
        attr.atime = 0;
        attr.mtime = 0;
        attr.ctime = 0;
        Ok(Ready(()))
    }
}

unsafe fn anonpipe_meta_access(
    _ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn anonpipe_meta_inactive(_ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn anonpipe_data_read(
    ctx: &VopDataCtx,
    _offset: u64,
    dst: *mut u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let pipe = ctx.data as *mut PipeState;
        if pipe.is_null() {
            return Err(VfsError::Io);
        }
        let count = len.min(4096);
        let actual = pipe_buf_read(pipe, dst, count as u16);
        Ok(Ready(actual as u64))
    }
}

unsafe fn anonpipe_data_write(
    ctx: &VopDataCtx,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let pipe = ctx.data as *mut PipeState;
        if pipe.is_null() {
            return Err(VfsError::Io);
        }
        let count = len.min(4096);
        let actual = pipe_buf_write(pipe, src, count as u16);
        Ok(Ready(actual as u64))
    }
}

unsafe fn anonpipe_data_fsync(_ctx: &VopDataCtx) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn anonpipe_data_readdir(
    _ctx: &VopDataCtx,
    _cookie: *mut u64,
    _emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    Err(VfsError::NotDir)
}

unsafe fn anonpipe_data_statfs(_ctx: &VopDataCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        *out = VStatfs::EMPTY;
        (*out).bsize = PIPE_BUF_SIZE as u32;
        (*out).set_fs_name(b"anonpipe");
        Ok(Ready(()))
    }
}

unsafe fn anonpipe_data_unsupported_xattr_buf(
    _ctx: &VopDataCtx,
    _name: *const u8,
    _name_len: u8,
    _buf: *mut u8,
    _buf_len: usize,
) -> VopOutcome<usize> {
    Err(VfsError::NotSup)
}

unsafe fn anonpipe_data_unsupported_setxattr(
    _ctx: &VopDataCtx,
    _name: *const u8,
    _name_len: u8,
    _value: *const u8,
    _value_len: usize,
    _flags: u32,
) -> VopOutcome<()> {
    Err(VfsError::NotSup)
}

unsafe fn anonpipe_data_unsupported_listxattr(
    _ctx: &VopDataCtx,
    _buf: *mut u8,
    _buf_len: usize,
) -> VopOutcome<usize> {
    Err(VfsError::NotSup)
}

unsafe fn anonpipe_data_unsupported_removexattr(
    _ctx: &VopDataCtx,
    _name: *const u8,
    _name_len: u8,
) -> VopOutcome<()> {
    Err(VfsError::NotSup)
}

unsafe fn anonpipe_data_unsupported_ioctl(
    _ctx: &VopDataCtx,
    _cmd: u32,
    _arg: u64,
) -> crate::core::vop::IoctlResult {
    Err(VfsError::NotSup)
}

unsafe fn anonpipe_data_unsupported_mmap(
    _ctx: &VopDataCtx,
    _page_idx: u64,
    _write: bool,
    _out_cap: *mut u64,
) -> VopOutcome<()> {
    Err(VfsError::NotSup)
}

pub(crate) static ANONPIPE_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: META_OPS_DEFAULT.lookup,
        lookup_ci: META_OPS_DEFAULT.lookup_ci,
        create: META_OPS_DEFAULT.create,
        mkdir: META_OPS_DEFAULT.mkdir,
        symlink: META_OPS_DEFAULT.symlink,
        mkfifo: META_OPS_DEFAULT.mkfifo,
        unlink: META_OPS_DEFAULT.unlink,
        rmdir: META_OPS_DEFAULT.rmdir,
        link: META_OPS_DEFAULT.link,
        rename: META_OPS_DEFAULT.rename,
        open: anonpipe_meta_open,
        close: anonpipe_meta_close,
        getattr: anonpipe_meta_getattr,
        setattr: META_OPS_DEFAULT.setattr,
        access: anonpipe_meta_access,
        readlink: META_OPS_DEFAULT.readlink,
        truncate: META_OPS_DEFAULT.truncate,
        data_size: META_OPS_DEFAULT.data_size,
        inactive: anonpipe_meta_inactive,
    },
    data: VopDataOps {
        read: anonpipe_data_read,
        write: anonpipe_data_write,
        writeback: anonpipe_data_write,
        fsync: anonpipe_data_fsync,
        readdir: anonpipe_data_readdir,
        statfs: anonpipe_data_statfs,
        getxattr: anonpipe_data_unsupported_xattr_buf,
        setxattr: anonpipe_data_unsupported_setxattr,
        listxattr: anonpipe_data_unsupported_listxattr,
        removexattr: anonpipe_data_unsupported_removexattr,
        ioctl: anonpipe_data_unsupported_ioctl,
        mmap_get_page: anonpipe_data_unsupported_mmap,
    },
};
