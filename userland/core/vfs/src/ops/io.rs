// SPDX-License-Identifier: GPL-2.0-only
//
//! Fd-based I/O logic helpers (read / write / seek / fsync /
//! truncate). Resolve the open object, drive the matching
//! `data.*` vop, and dispatch the reply through
//! `personality::reply::emit_*`.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::file::VAttr;
use crate::core::identity::FsInstanceId;
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::ops::{AckReplyIntent, ReadReplyIntent, SeekReplyIntent, WriteReplyIntent};
use crate::owner::VfsState;
use crate::owner::client_shm::{ClientShmHandle, const_slice_in_region, slice_in_region};
use crate::owner::resume::{FsResume, Resume};
use crate::server::open_object::{OpenObjectFlags, OpenObjectKind};
use crate::server::types::{ClientHandle, OpenObjectHandle};

/// Maximum byte count handled inline in the reply's `regs[]`
/// area. Inline reads are short-read-legal — a caller asking
/// for more than this gets clamped at this length.
pub(crate) const INLINE_READ_MAX: usize = 224;

/// Mirror of [`INLINE_READ_MAX`] for the write fast path.
pub(crate) const INLINE_WRITE_MAX: usize = 224;

#[inline]
fn log_read_error(
    mode: &[u8],
    reason: &[u8],
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
    offset_in: u64,
    file_offset: u64,
    count: usize,
    shm_offset: u64,
    shm_len: u64,
    err: VfsError,
    open_h: Option<OpenObjectHandle>,
    vnode_h: Option<VnodeHandle>,
) {
    let badge = state
        .clients
        .get(client)
        .map(|c| c.client_badge)
        .unwrap_or(0);
    let (mount_kind, fs_id) = vnode_h
        .and_then(|vh| state.vnodes.get(vh))
        .and_then(|vn| {
            state
                .mounts
                .get(vn.mount)
                .map(|m| (m.kind as u8, m.fs_instance_id.raw()))
        })
        .unwrap_or((0, 0));
    trona_runtime::uerror!(|_lb| {
        _lb.str(b"[VFSDBG] read ");
        _lb.str(mode);
        _lb.str(b" err=");
        _lb.dec(err as u32 as u64);
        _lb.str(b" reason=");
        _lb.str(reason);
        _lb.str(b" c=");
        _lb.dec(client.slot() as u64);
        _lb.str(b" badge=");
        _lb.hex(badge);
        _lb.str(b" fd=");
        if fd < 0 {
            _lb.str(b"-");
            _lb.dec(fd.wrapping_neg() as u64);
        } else {
            _lb.dec(fd as u64);
        }
        _lb.str(b" cnt=");
        _lb.dec(count as u64);
        _lb.str(b" off=");
        _lb.hex(offset_in);
        _lb.str(b" foff=");
        _lb.hex(file_offset);
        if shm_len != 0 || shm_offset != 0 {
            _lb.str(b" shm=");
            _lb.hex(shm_offset);
            _lb.str(b"/");
            _lb.hex(shm_len);
        }
        if let Some(oh) = open_h {
            _lb.str(b" oh=");
            _lb.dec(oh.slot() as u64);
        }
        if let Some(vh) = vnode_h {
            _lb.str(b" vh=");
            _lb.dec(vh.slot() as u64);
        }
        _lb.str(b" mk=");
        _lb.dec(mount_kind as u64);
        _lb.str(b" fs=");
        _lb.hex(fs_id);
        _lb.str(b"\n");
    });
}

/// Outcome of a read whose data is delivered inline in the reply
/// regs (short-read fast path).
pub(crate) struct InlineReadResult<'a> {
    pub(crate) data: &'a [u8],
}

/// `whence` values forwarded from the personality wire decoder
/// onto [`do_seek_fd`]. Numeric values match POSIX `SEEK_SET` /
/// `SEEK_CUR` / `SEEK_END`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeekWhence {
    Set,
    Cur,
    End,
}

impl SeekWhence {
    pub(crate) fn from_posix(whence: u32) -> Option<Self> {
        Some(match whence {
            0 => SeekWhence::Set,
            1 => SeekWhence::Cur,
            2 => SeekWhence::End,
            _ => return None,
        })
    }
}

// ============================================================
// read — inline path
// ============================================================

/// Inline-mode read on `fd`. The result lands in the reply regs
/// directly (short-read fast path). Sync hit emits via
/// [`crate::personality::reply::emit_read_inline`]; backend park
/// stamps `FsResume::BulkReadStage`.
pub(crate) unsafe fn do_read_fd_inline(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    offset_in: u64,
    count: usize,
    reply_intent: ReadReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            log_read_error(
                b"inline",
                b"bad_fd",
                state,
                client,
                fd,
                offset_in,
                0,
                count,
                0,
                0,
                VfsError::BadF,
                None,
                None,
            );
            emit_read_inline_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        if count == 0 {
            crate::personality::reply::emit_read_inline(
                reply_lease,
                reply_intent,
                Ok(InlineReadResult { data: &[] }),
            );
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            log_read_error(
                b"inline",
                b"no_open",
                state,
                client,
                fd,
                offset_in,
                0,
                count,
                0,
                0,
                VfsError::BadF,
                None,
                None,
            );
            emit_read_inline_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let (vnode_h, file_offset) = match state.open_objects.get(open_h) {
            Some(obj) => {
                if (obj.flags & OpenObjectFlags::READABLE) == 0 {
                    log_read_error(
                        b"inline",
                        b"not_readable",
                        state,
                        client,
                        fd,
                        offset_in,
                        0,
                        count,
                        0,
                        0,
                        VfsError::Acces,
                        Some(open_h),
                        Some(obj.vnode),
                    );
                    emit_read_inline_error(reply_lease, reply_intent, VfsError::Acces);
                    return;
                }
                let off = if offset_in == u64::MAX {
                    obj.offset
                } else {
                    offset_in
                };
                (obj.vnode, off)
            }
            None => {
                log_read_error(
                    b"inline",
                    b"missing_open",
                    state,
                    client,
                    fd,
                    offset_in,
                    0,
                    count,
                    0,
                    0,
                    VfsError::BadF,
                    Some(open_h),
                    None,
                );
                emit_read_inline_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };
        let vkey = match state.vnodes.get(vnode_h) {
            Some(v) => v.key,
            None => {
                log_read_error(
                    b"inline",
                    b"missing_vnode",
                    state,
                    client,
                    fd,
                    offset_in,
                    file_offset,
                    count,
                    0,
                    0,
                    VfsError::Io,
                    Some(open_h),
                    Some(vnode_h),
                );
                emit_read_inline_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };
        let fs_id = state
            .vnodes
            .get(vnode_h)
            .and_then(|v| state.mounts.get(v.mount).map(|m| m.fs_instance_id))
            .unwrap_or(FsInstanceId::INVALID);

        let cap = count.min(INLINE_READ_MAX);
        let mut scratch = [0u8; INLINE_READ_MAX];
        crate::owner::pager_rpc::issue_writebacks_for_vnode_range(
            state,
            vnode_h,
            file_offset,
            cap as u64,
        );

        // Caller badge captured before `from_state` borrows state, so an
        // init-async procfs read vop (e.g. /proc/<pid>/stat) can tag its
        // parked op for client-teardown reaping.
        let caller_badge = state
            .clients
            .get(client)
            .map(|c| c.client_badge)
            .unwrap_or(0);
        let Some(mut ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            log_read_error(
                b"inline",
                b"ctx",
                state,
                client,
                fd,
                offset_in,
                file_offset,
                count,
                0,
                0,
                VfsError::Io,
                Some(open_h),
                Some(vnode_h),
            );
            emit_read_inline_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        ctx_owner.caller_badge = caller_badge;
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            log_read_error(
                b"inline",
                b"ops_null",
                state,
                client,
                fd,
                offset_in,
                file_offset,
                count,
                0,
                0,
                VfsError::Io,
                Some(open_h),
                Some(vnode_h),
            );
            emit_read_inline_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let data_ctx = ctx_owner.data_ctx();

        let result = ((*ops).data.read)(&data_ctx, file_offset, scratch.as_mut_ptr(), cap as u64);

        match result {
            Ok(Ready(n)) => {
                let n_clamped = (n as usize).min(cap);
                if offset_in == u64::MAX {
                    if let Some(obj) = state.open_objects.get_mut(open_h) {
                        obj.offset = file_offset.saturating_add(n_clamped as u64);
                    }
                }
                wake_pipe_waiters_after_io(state, open_h, PipeIoDirection::Read);
                crate::personality::reply::emit_read_inline(
                    reply_lease,
                    reply_intent,
                    Ok(InlineReadResult {
                        data: &scratch[..n_clamped],
                    }),
                );
            }
            Ok(Parked(handle)) => {
                // init-async procfs reads (e.g. /proc/<pid>/stat) carry
                // `Resume::Init` and own a snapshot that holds the lease
                // across the init-query chain — park it there. Backend
                // reads fall through to the BulkReadStage stamp below.
                let reply_lease = match crate::owner::init_rpc::attach_lease_if_init(
                    state,
                    handle,
                    reply_lease,
                ) {
                    Ok(()) => {
                        // Record the caller's read-reply framing (the vop
                        // only knew it needed init data, not the
                        // personality) before the reply lands.
                        crate::owner::init_rpc::stamp_read_intent(state, handle, reply_intent);
                        return;
                    }
                    Err(lease) => lease,
                };
                let badge = state
                    .clients
                    .get(client)
                    .map(|c| c.client_badge)
                    .unwrap_or(0);
                if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                    handle,
                    badge,
                    Some(reply_lease),
                    Resume::Fs(FsResume::BulkReadStage {
                        client,
                        vkey,
                        fs_id,
                        fd: if offset_in == u64::MAX { fd } else { -1 },
                        shm_offset: file_offset,
                        reply: reply_intent,
                    }),
                ) {
                    log_read_error(
                        b"inline",
                        b"resume_busy",
                        state,
                        client,
                        fd,
                        offset_in,
                        file_offset,
                        count,
                        0,
                        0,
                        VfsError::Busy,
                        Some(open_h),
                        Some(vnode_h),
                    );
                    emit_read_inline_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => {
                log_read_error(
                    b"inline",
                    b"vop",
                    state,
                    client,
                    fd,
                    offset_in,
                    file_offset,
                    count,
                    0,
                    0,
                    e,
                    Some(open_h),
                    Some(vnode_h),
                );
                emit_read_inline_error(reply_lease, reply_intent, e);
            }
        }
    }
}

// ============================================================
// read — SHM path
// ============================================================

/// SHM-mode read on `fd`. The data lands in the caller's bulk
/// SHM region; the reply just carries the byte count. Sync hit
/// emits via [`crate::personality::reply::emit_read_shm`];
/// backend park stamps `FsResume::BulkReadStageShm`.
pub(crate) unsafe fn do_read_fd_shm(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    offset_in: u64,
    count: usize,
    client_shm_offset: u64,
    client_shm_len: u64,
    reply_intent: ReadReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            log_read_error(
                b"shm",
                b"bad_fd",
                state,
                client,
                fd,
                offset_in,
                0,
                count,
                client_shm_offset,
                client_shm_len,
                VfsError::BadF,
                None,
                None,
            );
            emit_read_shm_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        if client_shm_len == 0 || (client_shm_len as usize) < count {
            log_read_error(
                b"shm",
                b"bad_shm_len",
                state,
                client,
                fd,
                offset_in,
                0,
                count,
                client_shm_offset,
                client_shm_len,
                VfsError::Inval,
                None,
                None,
            );
            emit_read_shm_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            log_read_error(
                b"shm",
                b"no_open",
                state,
                client,
                fd,
                offset_in,
                0,
                count,
                client_shm_offset,
                client_shm_len,
                VfsError::BadF,
                None,
                None,
            );
            emit_read_shm_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let (vnode_h, file_offset) = match state.open_objects.get(open_h) {
            Some(obj) => {
                if (obj.flags & OpenObjectFlags::READABLE) == 0 {
                    log_read_error(
                        b"shm",
                        b"not_readable",
                        state,
                        client,
                        fd,
                        offset_in,
                        0,
                        count,
                        client_shm_offset,
                        client_shm_len,
                        VfsError::Acces,
                        Some(open_h),
                        Some(obj.vnode),
                    );
                    emit_read_shm_error(reply_lease, reply_intent, VfsError::Acces);
                    return;
                }
                let off = if offset_in == u64::MAX {
                    obj.offset
                } else {
                    offset_in
                };
                (obj.vnode, off)
            }
            None => {
                log_read_error(
                    b"shm",
                    b"missing_open",
                    state,
                    client,
                    fd,
                    offset_in,
                    0,
                    count,
                    client_shm_offset,
                    client_shm_len,
                    VfsError::BadF,
                    Some(open_h),
                    None,
                );
                emit_read_shm_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };
        let vkey = match state.vnodes.get(vnode_h) {
            Some(v) => v.key,
            None => {
                log_read_error(
                    b"shm",
                    b"missing_vnode",
                    state,
                    client,
                    fd,
                    offset_in,
                    file_offset,
                    count,
                    client_shm_offset,
                    client_shm_len,
                    VfsError::Io,
                    Some(open_h),
                    Some(vnode_h),
                );
                emit_read_shm_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };
        let fs_id = state
            .vnodes
            .get(vnode_h)
            .and_then(|v| state.mounts.get(v.mount).map(|m| m.fs_instance_id))
            .unwrap_or(FsInstanceId::INVALID);

        let region_h = state
            .clients
            .get(client)
            .map(|c| c.bulk_shm)
            .unwrap_or(ClientShmHandle::INVALID);
        let region = match state.client_shm_regions.get(region_h) {
            Some(r) if !r.is_empty() && r.owner_client == client => r,
            _ => {
                log_read_error(
                    b"shm",
                    b"no_shm_region",
                    state,
                    client,
                    fd,
                    offset_in,
                    file_offset,
                    count,
                    client_shm_offset,
                    client_shm_len,
                    VfsError::Inval,
                    Some(open_h),
                    Some(vnode_h),
                );
                emit_read_shm_error(reply_lease, reply_intent, VfsError::Inval);
                return;
            }
        };
        let dst_ptr = match slice_in_region(region, client_shm_offset, client_shm_len) {
            Some(p) => p,
            None => {
                log_read_error(
                    b"shm",
                    b"bad_shm_slice",
                    state,
                    client,
                    fd,
                    offset_in,
                    file_offset,
                    count,
                    client_shm_offset,
                    client_shm_len,
                    VfsError::Inval,
                    Some(open_h),
                    Some(vnode_h),
                );
                emit_read_shm_error(reply_lease, reply_intent, VfsError::Inval);
                return;
            }
        };
        crate::owner::pager_rpc::issue_writebacks_for_vnode_range(
            state,
            vnode_h,
            file_offset,
            count as u64,
        );

        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            log_read_error(
                b"shm",
                b"ctx",
                state,
                client,
                fd,
                offset_in,
                file_offset,
                count,
                client_shm_offset,
                client_shm_len,
                VfsError::Io,
                Some(open_h),
                Some(vnode_h),
            );
            emit_read_shm_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            log_read_error(
                b"shm",
                b"ops_null",
                state,
                client,
                fd,
                offset_in,
                file_offset,
                count,
                client_shm_offset,
                client_shm_len,
                VfsError::Io,
                Some(open_h),
                Some(vnode_h),
            );
            emit_read_shm_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let data_ctx = ctx_owner.data_ctx();

        let result = ((*ops).data.read)(&data_ctx, file_offset, dst_ptr, count as u64);

        match result {
            Ok(Ready(n)) => {
                let n_clamped = (n as usize).min(count);
                if offset_in == u64::MAX {
                    if let Some(obj) = state.open_objects.get_mut(open_h) {
                        obj.offset = file_offset.saturating_add(n_clamped as u64);
                    }
                }
                wake_pipe_waiters_after_io(state, open_h, PipeIoDirection::Read);
                crate::personality::reply::emit_read_shm(
                    reply_lease,
                    reply_intent,
                    Ok(n_clamped as u64),
                );
            }
            Ok(Parked(handle)) => {
                let badge = state
                    .clients
                    .get(client)
                    .map(|c| c.client_badge)
                    .unwrap_or(0);
                if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                    handle,
                    badge,
                    Some(reply_lease),
                    Resume::Fs(FsResume::BulkReadStageShm {
                        client,
                        vkey,
                        fs_id,
                        fd: if offset_in == u64::MAX { fd } else { -1 },
                        client_shm_offset,
                        client_shm_len,
                        reply: reply_intent,
                    }),
                ) {
                    log_read_error(
                        b"shm",
                        b"resume_busy",
                        state,
                        client,
                        fd,
                        offset_in,
                        file_offset,
                        count,
                        client_shm_offset,
                        client_shm_len,
                        VfsError::Busy,
                        Some(open_h),
                        Some(vnode_h),
                    );
                    emit_read_shm_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => {
                log_read_error(
                    b"shm",
                    b"vop",
                    state,
                    client,
                    fd,
                    offset_in,
                    file_offset,
                    count,
                    client_shm_offset,
                    client_shm_len,
                    e,
                    Some(open_h),
                    Some(vnode_h),
                );
                emit_read_shm_error(reply_lease, reply_intent, e);
            }
        }
    }
}

// ============================================================
// write — inline path
// ============================================================

/// Inline-mode write on `fd`. `payload` carries the bytes to
/// persist; clamped at [`INLINE_WRITE_MAX`] short-write rules.
pub(crate) unsafe fn do_write_fd_inline(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    offset_in: u64,
    payload: &[u8],
    reply_intent: WriteReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            emit_write_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        if payload.is_empty() {
            crate::personality::reply::emit_write(reply_lease, reply_intent, Ok(0));
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            emit_write_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let (vnode_h, file_offset) = match state.open_objects.get(open_h) {
            Some(obj) => {
                if (obj.flags & OpenObjectFlags::WRITABLE) == 0 {
                    emit_write_error(reply_lease, reply_intent, VfsError::Acces);
                    return;
                }
                let off = if offset_in == u64::MAX {
                    obj.offset
                } else {
                    offset_in
                };
                (obj.vnode, off)
            }
            None => {
                emit_write_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };
        let vkey = match state.vnodes.get(vnode_h) {
            Some(v) => v.key,
            None => {
                emit_write_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_write_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            emit_write_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let data_ctx = ctx_owner.data_ctx();

        let result = ((*ops).data.write)(
            &data_ctx,
            file_offset,
            payload.as_ptr(),
            payload.len() as u64,
        );

        match result {
            Ok(Ready(n)) => {
                let n_clamped = (n as usize).min(payload.len());
                if offset_in == u64::MAX {
                    if let Some(obj) = state.open_objects.get_mut(open_h) {
                        obj.offset = file_offset.saturating_add(n_clamped as u64);
                    }
                }
                wake_pipe_waiters_after_io(state, open_h, PipeIoDirection::Write);
                crate::personality::reply::emit_write(
                    reply_lease,
                    reply_intent,
                    Ok(n_clamped as u64),
                );
            }
            Ok(Parked(handle)) => {
                let badge = state
                    .clients
                    .get(client)
                    .map(|c| c.client_badge)
                    .unwrap_or(0);
                if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                    handle,
                    badge,
                    Some(reply_lease),
                    Resume::Fs(FsResume::BulkWriteStage {
                        client,
                        vkey,
                        fs_id: vkey.fs_instance_id,
                        fd: if offset_in == u64::MAX { fd } else { -1 },
                        file_offset,
                        requested_len: payload.len() as u64,
                        reply: reply_intent,
                    }),
                ) {
                    emit_write_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => emit_write_error(reply_lease, reply_intent, e),
        }
    }
}

// ============================================================
// write — SHM path
// ============================================================

/// SHM-mode write on `fd`. The bytes live in the caller's bulk
/// SHM region; the reply carries the byte count.
pub(crate) unsafe fn do_write_fd_shm(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    offset_in: u64,
    count: usize,
    client_shm_offset: u64,
    client_shm_len: u64,
    reply_intent: WriteReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            emit_write_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        if client_shm_len == 0 || (client_shm_len as usize) < count {
            emit_write_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            emit_write_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let (vnode_h, file_offset) = match state.open_objects.get(open_h) {
            Some(obj) => {
                if (obj.flags & OpenObjectFlags::WRITABLE) == 0 {
                    emit_write_error(reply_lease, reply_intent, VfsError::Acces);
                    return;
                }
                let off = if offset_in == u64::MAX {
                    obj.offset
                } else {
                    offset_in
                };
                (obj.vnode, off)
            }
            None => {
                emit_write_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };
        let vkey = match state.vnodes.get(vnode_h) {
            Some(v) => v.key,
            None => {
                emit_write_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        let region_h = state
            .clients
            .get(client)
            .map(|c| c.bulk_shm)
            .unwrap_or(ClientShmHandle::INVALID);
        let region = match state.client_shm_regions.get(region_h) {
            Some(r) if !r.is_empty() && r.owner_client == client => r,
            _ => {
                emit_write_error(reply_lease, reply_intent, VfsError::Inval);
                return;
            }
        };
        let src_ptr = match const_slice_in_region(region, client_shm_offset, count as u64) {
            Some(p) => p,
            None => {
                emit_write_error(reply_lease, reply_intent, VfsError::Inval);
                return;
            }
        };

        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_write_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            emit_write_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let data_ctx = ctx_owner.data_ctx();

        let result = ((*ops).data.write)(&data_ctx, file_offset, src_ptr, count as u64);

        match result {
            Ok(Ready(n)) => {
                let n_clamped = (n as usize).min(count);
                if offset_in == u64::MAX {
                    if let Some(obj) = state.open_objects.get_mut(open_h) {
                        obj.offset = file_offset.saturating_add(n_clamped as u64);
                    }
                }
                wake_pipe_waiters_after_io(state, open_h, PipeIoDirection::Write);
                crate::personality::reply::emit_write(
                    reply_lease,
                    reply_intent,
                    Ok(n_clamped as u64),
                );
            }
            Ok(Parked(handle)) => {
                let badge = state
                    .clients
                    .get(client)
                    .map(|c| c.client_badge)
                    .unwrap_or(0);
                if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                    handle,
                    badge,
                    Some(reply_lease),
                    Resume::Fs(FsResume::BulkWriteStage {
                        client,
                        vkey,
                        fs_id: vkey.fs_instance_id,
                        fd: if offset_in == u64::MAX { fd } else { -1 },
                        file_offset,
                        requested_len: count as u64,
                        reply: reply_intent,
                    }),
                ) {
                    emit_write_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => emit_write_error(reply_lease, reply_intent, e),
        }
    }
}

// ============================================================
// seek
// ============================================================

/// Adjust the file offset on a regular-file open object. Sync —
/// the offset is owner-thread-local state. `SEEK_END` triggers a
/// synchronous `meta.getattr`; backends that would park surface
/// `Again` so the caller can retry via `fstat` + `SEEK_SET`.
pub(crate) unsafe fn do_seek_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    offset: i64,
    whence: SeekWhence,
    reply_intent: SeekReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            emit_seek_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            emit_seek_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let (vnode_h, current, is_dir) = match state.open_objects.get(open_h) {
            Some(obj) => (
                obj.vnode,
                obj.offset as i64,
                (obj.flags & OpenObjectFlags::O_DIRECTORY) != 0,
            ),
            None => {
                emit_seek_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };

        let end_size = if matches!(whence, SeekWhence::End) {
            let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
            else {
                emit_seek_error(reply_lease, reply_intent, VfsError::Io);
                return;
            };
            let ops = (*ctx.vnode).ops;
            if ops.is_null() {
                emit_seek_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
            let mut attr = VAttr::zeroed();
            match ((*ops).meta.getattr)(&mut ctx, &raw mut attr) {
                Ok(Ready(())) => attr.size as i64,
                Ok(Parked(_)) => {
                    emit_seek_error(reply_lease, reply_intent, VfsError::Again);
                    return;
                }
                Err(e) => {
                    emit_seek_error(reply_lease, reply_intent, e);
                    return;
                }
            }
        } else {
            0
        };

        let new_offset = match whence {
            SeekWhence::Set => offset,
            SeekWhence::Cur => current.wrapping_add(offset),
            SeekWhence::End => end_size.wrapping_add(offset),
        };
        if new_offset < 0 {
            emit_seek_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        if is_dir && !(matches!(whence, SeekWhence::Set) && offset == 0) {
            emit_seek_error(reply_lease, reply_intent, VfsError::IsDir);
            return;
        }

        if let Some(obj) = state.open_objects.get_mut(open_h) {
            obj.offset = new_offset as u64;
        }
        crate::personality::reply::emit_seek(reply_lease, reply_intent, Ok(new_offset as u64));
    }
}

// ============================================================
// fsync
// ============================================================

/// `fsync` / `fdatasync` / Win32 flush on a fd. Drives
/// the `data.fsync` vop and surfaces an ack reply.
pub(crate) unsafe fn do_fsync_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            emit_ack_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            emit_ack_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let vnode_h = match state.open_objects.get(open_h) {
            Some(obj) => obj.vnode,
            None => {
                emit_ack_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };
        let vkey = match state.vnodes.get(vnode_h) {
            Some(v) => v.key,
            None => {
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        // Flush pager-backed MAP_SHARED pages through the same
        // backend data.write path normal writes use. The helper
        // registers each async writeback on the vnode ordering lane
        // before `data.fsync` installs its barrier, so fsync waits
        // for dirty page writeback and then issues BACKEND_FSYNC.
        crate::owner::pager_rpc::issue_writebacks_for_vnode(state, vnode_h);

        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let data_ctx = ctx_owner.data_ctx();

        match ((*ops).data.fsync)(&data_ctx) {
            Ok(Ready(())) => {
                crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
            }
            Ok(Parked(handle)) => {
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
                        reply: reply_intent,
                    }),
                ) {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => emit_ack_error(reply_lease, reply_intent, e),
        }
    }
}

// ============================================================
// truncate
// ============================================================

/// `ftruncate` / Win32 end-of-file updates on a writable fd.
pub(crate) unsafe fn do_truncate_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    new_size: u64,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            emit_ack_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            emit_ack_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let (vnode_h, kind, aux_slot, writable) = match state.open_objects.get(open_h) {
            Some(obj) => (
                obj.vnode,
                obj.kind,
                obj.personality_aux,
                (obj.flags & OpenObjectFlags::WRITABLE) != 0,
            ),
            None => {
                emit_ack_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };
        if !writable {
            emit_ack_error(reply_lease, reply_intent, VfsError::Acces);
            return;
        }
        // POSIX shm carries no vnode — its size lives in `ShmData` and its
        // storage is a vfs-owned anon MO. Resize the MO and record the new
        // size instead of walking the (absent) truncate vop.
        if kind == OpenObjectKind::Shm {
            finish_truncate_shm(state, aux_slot, new_size, reply_intent, reply_lease);
            return;
        }
        finish_truncate_for_vnode(
            state,
            client,
            vnode_h,
            fd,
            new_size,
            reply_intent,
            reply_lease,
        );
    }
}

/// `ftruncate` on a POSIX shm fd. shm carries no vnode: the backing
/// store is a vfs-owned anonymous MO and the logical size is recorded
/// in `ShmData`. Resize the MO so a later `mmap` of the new length
/// lands every page, then stamp the size. mmsrv requires a >= 1-page
/// MO, so round up to whole pages with a one-page floor.
unsafe fn finish_truncate_shm(
    state: &mut VfsState,
    aux_slot: u32,
    new_size: u64,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        let Some(shm_h) = state.shm_data.handle_from_slot(aux_slot) else {
            emit_ack_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let page_bytes = uapi::KERNITE_PAGE_BYTES as u64;
        let new_pages = new_size.div_ceil(page_bytes).max(1);
        let mo_ref = match state.shm_data.get(shm_h) {
            Some(s) => s.mo_cap.borrow(),
            None => {
                emit_ack_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };
        let resize_rc = trona_kernel::invoke::mo_resize(mo_ref, new_pages);
        if resize_rc != 0 {
            // A live tail mapping makes the kernel reject the shrink as busy;
            // surface that as EBUSY rather than a generic EIO so callers can
            // unmap and retry.
            let err = if resize_rc == uapi::KERNITE_ERR_BUSY as i32 {
                VfsError::Busy
            } else {
                VfsError::Io
            };
            emit_ack_error(reply_lease, reply_intent, err);
            return;
        }
        if let Some(s) = state.shm_data.get_mut(shm_h) {
            s.size = new_size;
        }
        crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
    }
}

/// Apply a size change to an already-resolved vnode through the
/// dedicated `meta.truncate` vop. This is shared by fd-based
/// `ftruncate` and path-based `truncate`; both need the same
/// backend completion shape so backend clients can refresh size
/// metadata and decommit file-backed MO pages after the ack.
pub(crate) unsafe fn finish_truncate_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: crate::core::vnode::VnodeHandle,
    fd: i32,
    new_size: u64,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        let (vkey, old_size, result) = {
            let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
            else {
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            };
            let ops = (*ctx.vnode).ops;
            if ops.is_null() {
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
            let vkey = (*ctx.vnode).key;
            let old_size = ((*ops).meta.data_size)(&mut ctx);
            let result = ((*ops).meta.truncate)(&mut ctx, new_size);
            (vkey, old_size, result)
        };

        match result {
            Ok(Ready(())) => {
                crate::owner::pager_rpc::invoke_mo_decommit_for_truncate(state, vnode_h, new_size);
                crate::personality::reply::emit_ack(reply_lease, reply_intent, 0, Ok(()));
            }
            Ok(Parked(handle)) => {
                let badge = state
                    .clients
                    .get(client)
                    .map(|c| c.client_badge)
                    .unwrap_or(0);
                if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                    handle,
                    badge,
                    Some(reply_lease),
                    Resume::Fs(FsResume::FinalOpAckTruncate {
                        client,
                        file_vkey: vkey,
                        fd,
                        old_size,
                        reply: reply_intent,
                    }),
                ) {
                    emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => emit_ack_error(reply_lease, reply_intent, e),
        }
    }
}

// ============================================================
// Readiness wake helpers
// ============================================================

#[derive(Clone, Copy)]
enum PipeIoDirection {
    Read,
    Write,
}

fn wake_pipe_waiters_after_io(
    state: &mut VfsState,
    open_h: OpenObjectHandle,
    direction: PipeIoDirection,
) {
    let (vnode_h, pipe_slot) = match state.open_objects.get(open_h) {
        Some(obj) => (obj.vnode, obj.personality_aux),
        None => return,
    };
    let is_pipe_backed = state
        .vnodes
        .get(vnode_h)
        .map(|v| {
            matches!(
                v.kind,
                crate::core::vnode::VnodeKind::Pipe | crate::core::vnode::VnodeKind::Fifo
            )
        })
        .unwrap_or(false);
    if !is_pipe_backed {
        return;
    }
    let Some(pipe_h) = state.pipes.handle_from_slot(pipe_slot) else {
        return;
    };
    let wake_kind = match direction {
        PipeIoDirection::Read => crate::owner::pipe_wait::PipeWaitKind::Write,
        PipeIoDirection::Write => crate::owner::pipe_wait::PipeWaitKind::Read,
    };
    crate::owner::pipe_wait::wake_matching(state, pipe_h, wake_kind);
}

// ============================================================
// Error emit shims
// ============================================================

unsafe fn emit_read_inline_error(reply_lease: ReplyLease, intent: ReadReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_read_inline(reply_lease, intent, Err(err));
    }
}

unsafe fn emit_read_shm_error(reply_lease: ReplyLease, intent: ReadReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_read_shm(reply_lease, intent, Err(err));
    }
}

unsafe fn emit_write_error(reply_lease: ReplyLease, intent: WriteReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_write(reply_lease, intent, Err(err));
    }
}

unsafe fn emit_seek_error(reply_lease: ReplyLease, intent: SeekReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_seek(reply_lease, intent, Err(err));
    }
}

unsafe fn emit_ack_error(reply_lease: ReplyLease, intent: AckReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, intent, 0, Err(err));
    }
}
