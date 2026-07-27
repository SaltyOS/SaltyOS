// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_FIFO_OPEN` — open a named pipe (`mkfifo`-created node).
//!
//! A FIFO is a vnode of kind [`VnodeKind::Fifo`] living inside a
//! filesystem mount (typically ramfs / tmpfs). The vnode itself
//! has no payload until the first `open` populates `vnode.data`
//! with a [`PipeState`] handle that the read and write ends share.
//! Subsequent `open` calls on the same vnode reuse that handle and
//! bump its read- or write-side refcount; `close` drops the
//! refcount and reclaims the [`PipeState`] when both sides reach
//! zero.
//!
//! Wire layout:
//! - `regs[0]` = `dirfd` (i32) — directory fd the path resolves
//!   relative to (`AT_FDCWD` legal sentinel).
//! - `regs[1..7]` = inline name bytes (48 bytes).
//! - `regs[7]` = `name_len`.
//! - `regs[8]` = `flags` (`O_RDONLY` / `O_WRONLY` / `O_RDWR` plus
//!   `O_NONBLOCK`).
//!
//! Reply: `regs[0] = fd`. Errors fall through `vfs_error_to_public_reply`.
//!
//! Open semantics follow POSIX `mkfifo(3)`:
//!   * `O_RDONLY` blocks until a writer opens, unless `O_NONBLOCK`
//!     is set (in which case the open succeeds immediately and
//!     subsequent reads return `EAGAIN` until a writer arrives).
//!   * `O_WRONLY` blocks until a reader opens; with `O_NONBLOCK`
//!     it fails with `ENXIO` if no reader is currently attached.
//!   * `O_RDWR` opens both sides synchronously; the caller acts as
//!     its own peer until another opener attaches.
//!
//! Today the parking on the read-side `O_RDONLY` wait runs on the
//! pipe's wait queue (driven by [`crate::core::pipe`]); the
//! `O_WRONLY` `ENXIO` path is synchronous since vfs has full
//! visibility into the current refcount state.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::vnode::{VnodeHandle, VnodeKind};
use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::open_object::{OpenObject, OpenObjectAccess, OpenObjectFlags, OpenObjectKind};
use crate::server::types::ClientHandle;

const FIFO_NAME_INLINE_MAX: usize = 48;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_ACCMODE: u64 = 3;
const O_NONBLOCK: u64 = 0o4000;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let dirfd = msg.regs[0] as i32;
        let name_len = msg.regs[7] as u8;
        let flags = msg.regs[8];

        if name_len as usize == 0 || name_len as usize > FIFO_NAME_INLINE_MAX {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
        let acc_mode = flags & O_ACCMODE;
        let nonblock = (flags & O_NONBLOCK) != 0;

        // Project the inline name out of the message regs into a
        // stack buffer the namei driver can read.
        let mut name = [0u8; FIFO_NAME_INLINE_MAX];
        let src = (&raw const msg.regs[1]) as *const u8;
        for i in 0..name_len as usize {
            name[i] = *src.add(i);
        }

        // Resolve the FIFO vnode using the same namei driver every
        // path-bearing handler shares. The walk demands the final
        // component exist; missing path → ENOENT.
        let parent_vh = match crate::ops::anchor::resolve_dirfd_handle(state, client, dirfd) {
            Ok(h) => h,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        let target_vh = match resolve_fifo_child(state, parent_vh, &name[..name_len as usize]) {
            Ok(h) => h,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        let kind = match state.vnodes.get(target_vh) {
            Some(v) => v.kind,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                return;
            }
        };
        if kind != VnodeKind::Fifo {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }

        // Allocate (or reuse) the PipeState backing this FIFO.
        let pipe_handle = match crate::ops::pipe::ensure_fifo_pipe(state, target_vh) {
            Ok(h) => h,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        // Validate the requested side against the current peer
        // counts. `O_WRONLY | O_NONBLOCK` with no reader fails fast.
        if acc_mode == O_WRONLY && nonblock {
            let has_reader = state
                .pipes
                .get(pipe_handle)
                .map(|p| p.read_refcount > 0)
                .unwrap_or(false);
            if !has_reader {
                send_reply_err_for_client(state, client, reply_lease, VfsError::NotSup);
                return;
            }
        }

        // Bump the appropriate refcount. The PipeState's read /
        // write counts model the open ends; close decrements.
        if let Some(p) = state.pipes.get_mut(pipe_handle) {
            match acc_mode {
                O_RDONLY => p.read_refcount = p.read_refcount.saturating_add(1),
                O_WRONLY => p.write_refcount = p.write_refcount.saturating_add(1),
                O_RDWR => {
                    p.read_refcount = p.read_refcount.saturating_add(1);
                    p.write_refcount = p.write_refcount.saturating_add(1);
                }
                _ => {
                    send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                    return;
                }
            }
        }

        // Allocate an OpenObject pointing at the FIFO vnode plus
        // wire it through the pipe's PipeState handle as the
        // personality_aux scratch.
        let obj_handle = match state.open_objects.alloc() {
            Some(h) => h,
            None => {
                rollback_refcount(state, pipe_handle, acc_mode);
                send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
                return;
            }
        };
        if let Some(obj) = state.open_objects.get_mut(obj_handle) {
            *obj = OpenObject::EMPTY;
            obj.vnode = target_vh;
            obj.refcount = 1;
            obj.kind = OpenObjectKind::Pipe;
            obj.personality_aux = pipe_handle.slot();
            let mut f = 0u8;
            if acc_mode == O_RDONLY || acc_mode == O_RDWR {
                f |= OpenObjectFlags::READABLE;
            }
            if acc_mode == O_WRONLY || acc_mode == O_RDWR {
                f |= OpenObjectFlags::WRITABLE;
            }
            if nonblock {
                f |= OpenObjectFlags::O_NONBLOCK;
            }
            obj.flags = f;
            let mut access = 0u8;
            if acc_mode == O_RDONLY || acc_mode == O_RDWR {
                access |= OpenObjectAccess::READ;
            }
            if acc_mode == O_WRONLY || acc_mode == O_RDWR {
                access |= OpenObjectAccess::WRITE;
            }
            obj.access = access;
            obj.share = crate::ops::SharePolicy::permissive().bits();
        }
        if let Some(vn) = state.vnodes.get_mut(target_vh) {
            vn.open_refcount = vn.open_refcount.saturating_add(1);
        }

        // Install the handle into the caller's fd-table.
        let cli = match state.clients.get_mut(client) {
            Some(c) => c,
            None => {
                state.open_objects.release(obj_handle);
                if let Some(vn) = state.vnodes.get_mut(target_vh) {
                    vn.open_refcount = vn.open_refcount.saturating_sub(1);
                }
                rollback_refcount(state, pipe_handle, acc_mode);
                send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                return;
            }
        };
        let fd = match cli.slot_table.find_first_empty_from(0) {
            Ok(f) => f,
            Err(_) => {
                state.open_objects.release(obj_handle);
                if let Some(vn) = state.vnodes.get_mut(target_vh) {
                    vn.open_refcount = vn.open_refcount.saturating_sub(1);
                }
                rollback_refcount(state, pipe_handle, acc_mode);
                send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
                return;
            }
        };
        if cli.slot_table.set(fd, obj_handle).is_err() {
            state.open_objects.release(obj_handle);
            if let Some(vn) = state.vnodes.get_mut(target_vh) {
                vn.open_refcount = vn.open_refcount.saturating_sub(1);
            }
            rollback_refcount(state, pipe_handle, acc_mode);
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }

        send_reply_ok_for_client(state, client, reply_lease, &[fd as u64]);
    }
}

/// Walk the parent directory's `lookup` vop for `name` synchronously.
/// FIFO open does not honour symlinks (POSIX is silent here, but
/// every mainstream UNIX resolves the FIFO directly), so the
/// resolution stops at the first non-directory match. Returns
/// `NoEnt` when the entry does not exist.
unsafe fn resolve_fifo_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
) -> Result<VnodeHandle, VfsError> {
    use crate::core::outcome::Ready;
    use crate::core::vop_context::OwnerVopCtx;

    // SAFETY: FIFO creation/open runs on the owner thread and `parent_vh` was
    // resolved from the caller's directory context.
    let mut ctx = unsafe { OwnerVopCtx::from_state(state, parent_vh) }.ok_or(VfsError::Io)?;
    // SAFETY: `ctx.vnode` is the live vnode pointer owned by the context.
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return Err(VfsError::Io);
    }
    // SAFETY: `ops` is the live vop vector for `ctx.vnode`; the name slice is
    // valid for the duration of the synchronous lookup call.
    match unsafe { ((*ops).meta.lookup)(&mut ctx, name.as_ptr(), name.len() as u8) } {
        Ok(Ready(child)) => Ok(child),
        Ok(_) => Err(VfsError::Inval),
        Err(e) => Err(e),
    }
}

fn rollback_refcount(
    state: &mut VfsState,
    pipe_handle: crate::arena::handle::Handle<crate::core::pipe::PipeState>,
    acc_mode: u64,
) {
    if let Some(p) = state.pipes.get_mut(pipe_handle) {
        match acc_mode {
            O_RDONLY => p.read_refcount = p.read_refcount.saturating_sub(1),
            O_WRONLY => p.write_refcount = p.write_refcount.saturating_sub(1),
            O_RDWR => {
                p.read_refcount = p.read_refcount.saturating_sub(1);
                p.write_refcount = p.write_refcount.saturating_sub(1);
            }
            _ => {}
        }
    }
}
