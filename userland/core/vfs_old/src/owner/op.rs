// SPDX-License-Identifier: GPL-2.0-only
//! Owner-side operation core for saved-reply worker jobs.
//!
//! This is the first slice of a larger unification effort: instead of
//! every worker-capable file op manually allocating a reply slot,
//! saving the caller, applying owner follow-up, and releasing the slot,
//! those steps now hang off a single `OpCore`.

use core::sync::atomic::{AtomicU64, Ordering};

use trona_kernel::core_types::TronaMsg;
use uapi::{CAP_SELF_CSPACE, TRONA_INVALID_OPERATION, TRONA_OUT_OF_MEMORY};

use crate::server::types::ClientHandle;

use super::VfsState;

static NEXT_OP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(crate) enum BeginOpError {
    OutOfMemory,
    InvalidOperation,
}

impl BeginOpError {
    pub(crate) const fn to_trona(self) -> u64 {
        match self {
            Self::OutOfMemory => TRONA_OUT_OF_MEMORY,
            Self::InvalidOperation => TRONA_INVALID_OPERATION,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum OpKind {
    Read,
    Write,
    PRead,
    PWrite,
    BulkRead,
    BulkWrite,
    Readdir,
    Fsync,
    Poll,
    EpollWait,
    PtyRead,
    SocketAccept,
    SocketConnect,
    SocketRecv,
    InetConnect,
    InetAccept,
    InetRecv,
    InetRecvFrom,
    PipeRead,
    PipeWrite,
    RemoteLookup,
    NetBridge,
    FsAsync,
    NetAsync,
    DeferredBackend,
}

#[derive(Clone, Copy)]
pub(crate) struct OpCore {
    pub(crate) request_id: u64,
    pub(crate) reply_slot: u64,
    pub(crate) kind: OpKind,
}

impl OpCore {
    pub(crate) const INVALID: Self = Self {
        request_id: 0,
        reply_slot: 0,
        kind: OpKind::Poll,
    };
}

#[derive(Clone, Copy)]
pub(crate) enum OwnerPostOp {
    None,
    SetFileOffset {
        client: ClientHandle,
        fd: i32,
        new_offset: u64,
    },
    SetDirCursor {
        client: ClientHandle,
        fd: i32,
        new_cursor: u32,
    },
    CompleteWrite {
        client: ClientHandle,
        fd: i32,
        update_fd_offset: bool,
        write_offset: u64,
        new_offset: u64,
        written: u64,
        old_size: u64,
        new_size: u64,
    },
}

#[inline]
fn next_op_id() -> u64 {
    NEXT_OP_ID.fetch_add(1, Ordering::Relaxed)
}

fn apply_owner_post_op(state: &mut VfsState, owner_post: OwnerPostOp) {
    match owner_post {
        OwnerPostOp::None => {}
        OwnerPostOp::SetFileOffset {
            client,
            fd,
            new_offset,
        } => {
            if fd < 0 {
                return;
            }
            if let Some(obj) = state.open_object_at_mut(client, fd as usize) {
                obj.offset = new_offset;
            }
        }
        OwnerPostOp::SetDirCursor {
            client,
            fd,
            new_cursor,
        } => {
            if fd < 0 {
                return;
            }
            if let Some(obj) = state.open_object_at_mut(client, fd as usize) {
                obj.dir_cursor = new_cursor;
            }
        }
        OwnerPostOp::CompleteWrite {
            client,
            fd,
            update_fd_offset,
            write_offset,
            new_offset,
            written,
            old_size,
            new_size,
        } => {
            if fd < 0 {
                return;
            }
            if update_fd_offset {
                if let Some(obj) = state.open_object_at_mut(client, fd as usize) {
                    obj.offset = new_offset;
                }
            }
            if let Some(slot) = state.open_object_at(client, fd as usize) {
                unsafe {
                    crate::backend::notify_mmsrv_mmap_write(
                        state,
                        slot,
                        write_offset,
                        written,
                        old_size,
                        new_size,
                    );
                }
            }
        }
    }
}

impl VfsState {
    pub(crate) fn begin_op_for_badge(
        &mut self,
        badge: u64,
        kind: OpKind,
    ) -> Result<OpCore, BeginOpError> {
        let Some(reply_slot) = self.alloc_reply_slot_for(badge) else {
            return Err(BeginOpError::OutOfMemory);
        };
        let save_err = trona_kernel::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
        if save_err != 0 {
            self.release_reply_slot(reply_slot);
            return Err(BeginOpError::InvalidOperation);
        }
        Ok(OpCore {
            request_id: next_op_id(),
            reply_slot,
            kind,
        })
    }

    pub(crate) fn begin_op_for_client(
        &mut self,
        client: ClientHandle,
        kind: OpKind,
    ) -> Result<OpCore, BeginOpError> {
        let badge = self.clients.get(client).map(|c| c.badge).unwrap_or(0);
        self.begin_op_for_badge(badge, kind)
    }

    pub(crate) fn begin_worker_op_for_badge(
        &mut self,
        badge: u64,
        kind: OpKind,
    ) -> Result<OpCore, BeginOpError> {
        self.begin_op_for_badge(badge, kind)
    }

    pub(crate) fn begin_worker_op_for_client(
        &mut self,
        client: ClientHandle,
        kind: OpKind,
    ) -> Result<OpCore, BeginOpError> {
        self.begin_op_for_client(client, kind)
    }

    pub(crate) fn cancel_op(&mut self, op: OpCore) {
        if op.reply_slot == 0 {
            return;
        }
        self.release_reply_slot(op.reply_slot);
    }

    pub(crate) fn cancel_worker_op(&mut self, op: OpCore) {
        self.cancel_op(op)
    }

    pub(crate) unsafe fn complete_op(
        &mut self,
        op: OpCore,
        owner_post: OwnerPostOp,
        msg: *const TronaMsg,
    ) {
        let _ = op.request_id;
        let _ = op.kind;
        apply_owner_post_op(self, owner_post);
        if op.reply_slot != 0 {
            unsafe {
                self.send_saved_reply(op.reply_slot, msg);
            }
        }
    }

    pub(crate) unsafe fn complete_worker_op(
        &mut self,
        op: OpCore,
        owner_post: OwnerPostOp,
        msg: *const TronaMsg,
    ) {
        unsafe { self.complete_op(op, owner_post, msg) }
    }
}
