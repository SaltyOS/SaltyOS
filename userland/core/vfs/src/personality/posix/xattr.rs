// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX fd-based extended-attribute entry points.
//!
//! Path-based `getxattr` / `setxattr` variants will route through
//! the namei terminal layer. These fd-based forms are the minimal
//! public surface needed to connect the existing VopDataOps xattr
//! implementation to parked backend completions.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::outcome::{Parked, Ready};
use crate::core::vop::{XATTR_CREATE, XATTR_REPLACE};
use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::owner::pending::WALK_NAME_MAX;
use crate::owner::resume::{FsResume, Resume};
use crate::personality::Personality;
use crate::server::open_object::OpenObjectFlags;
use crate::server::types::ClientHandle;

const XATTR_REPLY_INLINE_CAP: usize = 31 * 8;

pub(crate) unsafe fn handle_fgetxattr(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let requested_len = msg.regs[1] as usize;
        let name_len = msg.regs[2] as usize;
        let mut name = [0u8; WALK_NAME_MAX];
        if !copy_from_regs(msg, 3, name_len, &mut name) {
            emit_xattr_get_err(reply_lease, VfsError::Inval);
            return;
        }
        do_fgetxattr(
            state,
            client,
            fd,
            &name[..name_len],
            requested_len,
            reply_lease,
        );
    }
}

pub(crate) unsafe fn handle_flistxattr(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let requested_len = msg.regs[1] as usize;
        do_flistxattr(state, client, fd, requested_len, reply_lease);
    }
}

pub(crate) unsafe fn handle_fsetxattr(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let flags = msg.regs[1] as u32;
        let name_len = msg.regs[2] as usize;
        let value_len = msg.regs[3] as usize;
        let mut name = [0u8; WALK_NAME_MAX];
        let mut value = [0u8; WALK_NAME_MAX];
        if !copy_from_regs(msg, 4, name_len, &mut name) {
            emit_ack_err(reply_lease, VfsError::Inval);
            return;
        }
        let value_reg = 4 + words_for_len(name_len);
        if !copy_from_regs(msg, value_reg, value_len, &mut value) {
            emit_ack_err(reply_lease, VfsError::Inval);
            return;
        }
        do_fsetxattr(
            state,
            client,
            fd,
            &name[..name_len],
            &value[..value_len],
            flags,
            reply_lease,
        );
    }
}

pub(crate) unsafe fn handle_fremovexattr(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let name_len = msg.regs[1] as usize;
        let mut name = [0u8; WALK_NAME_MAX];
        if !copy_from_regs(msg, 2, name_len, &mut name) {
            emit_ack_err(reply_lease, VfsError::Inval);
            return;
        }
        do_fremovexattr(state, client, fd, &name[..name_len], reply_lease);
    }
}

unsafe fn do_fgetxattr(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    name: &[u8],
    requested_len: usize,
    reply_lease: ReplyLease,
) {
    unsafe {
        if name.is_empty() || name.len() > WALK_NAME_MAX {
            emit_xattr_get_err(reply_lease, VfsError::Inval);
            return;
        }
        let vnode_h = match vnode_for_fd(state, client, fd, false) {
            Ok(vnode_h) => vnode_h,
            Err(e) => {
                emit_xattr_get_err(reply_lease, e);
                return;
            }
        };
        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_xattr_get_err(reply_lease, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            emit_xattr_get_err(reply_lease, VfsError::Io);
            return;
        }
        let vkey = (*ctx_owner.vnode).key;
        let fs_id = ctx_owner.fs_instance_id();
        let data_ctx = ctx_owner.data_ctx();
        let mut scratch = [0u8; XATTR_REPLY_INLINE_CAP];
        let copy_cap = requested_len.min(XATTR_REPLY_INLINE_CAP);
        match ((*ops).data.getxattr)(
            &data_ctx,
            name.as_ptr(),
            name.len() as u8,
            scratch.as_mut_ptr(),
            copy_cap,
        ) {
            Ok(Ready(total_len)) => {
                let copy_len = total_len.min(copy_cap);
                crate::personality::reply::emit_xattr_get(
                    reply_lease,
                    Personality::Posix,
                    Ok((total_len, &scratch[..copy_len])),
                );
            }
            Ok(Parked(handle)) => stamp_xattr_get(
                state,
                client,
                handle,
                vkey,
                fs_id,
                reply_lease,
                XattrOp::Get,
            ),
            Err(e) => emit_xattr_get_err(reply_lease, e),
        }
    }
}

unsafe fn do_flistxattr(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    requested_len: usize,
    reply_lease: ReplyLease,
) {
    unsafe {
        let vnode_h = match vnode_for_fd(state, client, fd, false) {
            Ok(vnode_h) => vnode_h,
            Err(e) => {
                emit_xattr_list_err(reply_lease, e);
                return;
            }
        };
        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_xattr_list_err(reply_lease, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            emit_xattr_list_err(reply_lease, VfsError::Io);
            return;
        }
        let vkey = (*ctx_owner.vnode).key;
        let fs_id = ctx_owner.fs_instance_id();
        let data_ctx = ctx_owner.data_ctx();
        let mut scratch = [0u8; XATTR_REPLY_INLINE_CAP];
        let copy_cap = requested_len.min(XATTR_REPLY_INLINE_CAP);
        match ((*ops).data.listxattr)(&data_ctx, scratch.as_mut_ptr(), copy_cap) {
            Ok(Ready(total_len)) => {
                let copy_len = total_len.min(copy_cap);
                crate::personality::reply::emit_xattr_list(
                    reply_lease,
                    Personality::Posix,
                    Ok((total_len, &scratch[..copy_len])),
                );
            }
            Ok(Parked(handle)) => stamp_xattr_get(
                state,
                client,
                handle,
                vkey,
                fs_id,
                reply_lease,
                XattrOp::List,
            ),
            Err(e) => emit_xattr_list_err(reply_lease, e),
        }
    }
}

unsafe fn do_fsetxattr(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    name: &[u8],
    value: &[u8],
    flags: u32,
    reply_lease: ReplyLease,
) {
    unsafe {
        if name.is_empty()
            || name.len() > WALK_NAME_MAX
            || value.len() > WALK_NAME_MAX
            || (flags & !(XATTR_CREATE | XATTR_REPLACE)) != 0
            || (flags & (XATTR_CREATE | XATTR_REPLACE)) == (XATTR_CREATE | XATTR_REPLACE)
        {
            emit_ack_err(reply_lease, VfsError::Inval);
            return;
        }
        let vnode_h = match vnode_for_fd(state, client, fd, true) {
            Ok(vnode_h) => vnode_h,
            Err(e) => {
                emit_ack_err(reply_lease, e);
                return;
            }
        };
        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_ack_err(reply_lease, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            emit_ack_err(reply_lease, VfsError::Io);
            return;
        }
        let vkey = (*ctx_owner.vnode).key;
        let data_ctx = ctx_owner.data_ctx();
        match ((*ops).data.setxattr)(
            &data_ctx,
            name.as_ptr(),
            name.len() as u8,
            value.as_ptr(),
            value.len(),
            flags,
        ) {
            Ok(Ready(())) => emit_ack_ok(reply_lease),
            Ok(Parked(handle)) => stamp_xattr_ack(state, client, handle, vkey, reply_lease),
            Err(e) => emit_ack_err(reply_lease, e),
        }
    }
}

unsafe fn do_fremovexattr(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    name: &[u8],
    reply_lease: ReplyLease,
) {
    unsafe {
        if name.is_empty() || name.len() > WALK_NAME_MAX {
            emit_ack_err(reply_lease, VfsError::Inval);
            return;
        }
        let vnode_h = match vnode_for_fd(state, client, fd, true) {
            Ok(vnode_h) => vnode_h,
            Err(e) => {
                emit_ack_err(reply_lease, e);
                return;
            }
        };
        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_ack_err(reply_lease, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            emit_ack_err(reply_lease, VfsError::Io);
            return;
        }
        let vkey = (*ctx_owner.vnode).key;
        let data_ctx = ctx_owner.data_ctx();
        match ((*ops).data.removexattr)(&data_ctx, name.as_ptr(), name.len() as u8) {
            Ok(Ready(())) => emit_ack_ok(reply_lease),
            Ok(Parked(handle)) => stamp_xattr_ack(state, client, handle, vkey, reply_lease),
            Err(e) => emit_ack_err(reply_lease, e),
        }
    }
}

#[derive(Clone, Copy)]
enum XattrOp {
    Get,
    List,
}

fn vnode_for_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    require_write: bool,
) -> Result<crate::core::vnode::VnodeHandle, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let Some(open_h) = state.open_object_at(client, fd as usize) else {
        return Err(VfsError::BadF);
    };
    match state.open_objects.get(open_h) {
        Some(obj) if !require_write || (obj.flags & OpenObjectFlags::WRITABLE) != 0 => {
            Ok(obj.vnode)
        }
        Some(_) => Err(VfsError::Acces),
        None => Err(VfsError::BadF),
    }
}

unsafe fn stamp_xattr_get(
    state: &mut VfsState,
    client: ClientHandle,
    handle: crate::owner::pending::PendingOpHandle,
    vkey: crate::core::identity::VnodeKey,
    fs_id: crate::core::identity::FsInstanceId,
    reply_lease: ReplyLease,
    op: XattrOp,
) {
    let badge = state
        .clients
        .get(client)
        .map(|c| c.client_badge)
        .unwrap_or(0);
    let resume = match op {
        XattrOp::Get => FsResume::FillXattrGetReply {
            client,
            vkey,
            fs_id,
        },
        XattrOp::List => FsResume::FillListXattrReply {
            client,
            vkey,
            fs_id,
        },
    };
    if let Err(Some(reply_lease)) =
        state.stamp_resume_ctx(handle, badge, Some(reply_lease), Resume::Fs(resume))
    {
        match op {
            XattrOp::Get => emit_xattr_get_err(reply_lease, VfsError::Busy),
            XattrOp::List => emit_xattr_list_err(reply_lease, VfsError::Busy),
        }
    }
}

unsafe fn stamp_xattr_ack(
    state: &mut VfsState,
    client: ClientHandle,
    handle: crate::owner::pending::PendingOpHandle,
    vkey: crate::core::identity::VnodeKey,
    reply_lease: ReplyLease,
) {
    let badge = state
        .clients
        .get(client)
        .map(|c| c.client_badge)
        .unwrap_or(0);
    if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
        handle,
        badge,
        Some(reply_lease),
        Resume::Fs(FsResume::AckMutation {
            client,
            vkey,
            reply: AckReplyIntent::PosixAck,
        }),
    ) {
        emit_ack_err(reply_lease, VfsError::Busy);
    }
}

fn emit_xattr_get_err(reply_lease: ReplyLease, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_xattr_get(reply_lease, Personality::Posix, Err(err));
    }
}

fn emit_xattr_list_err(reply_lease: ReplyLease, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_xattr_list(reply_lease, Personality::Posix, Err(err));
    }
}

fn emit_ack_ok(reply_lease: ReplyLease) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, AckReplyIntent::PosixAck, 0, Ok(()));
    }
}

fn emit_ack_err(reply_lease: ReplyLease, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, AckReplyIntent::PosixAck, 0, Err(err));
    }
}

fn copy_from_regs(msg: &TronaMsg, reg_start: usize, len: usize, out: &mut [u8]) -> bool {
    if len > out.len() {
        return false;
    }
    if len == 0 {
        return true;
    }
    let words = words_for_len(len);
    if reg_start.saturating_add(words) > msg.regs.len() {
        return false;
    }
    for i in 0..len {
        let word = msg.regs[reg_start + i / 8];
        let lane = i % 8;
        out[i] = ((word >> (lane * 8)) & 0xff) as u8;
    }
    true
}

#[inline]
fn words_for_len(len: usize) -> usize {
    (len + 7) / 8
}
