// SPDX-License-Identifier: GPL-2.0-only
//
//! Metadata operations — `VFS_STAT` / `VFS_LSTAT` / `VFS_FSTAT` /
//! `VFS_FSTATAT` / `VFS_ACCESS` / `VFS_FACCESSAT`.
//!
//! Path-based stat/access now route through `ops::attr` /
//! `ops::access`. This module keeps only the POSIX exec-preflight
//! terminal helpers; generic stat/access resume emission lives in
//! `personality::reply`.
//!
//! ## Wire layouts
//!
//! - `VFS_FSTAT` request: `regs[0] = fd`. Reply (8 regs): vnode id,
//!   mode, nlink, size, uid, gid, mtime_sec, vnode kind.
//! - `VFS_STAT` / `VFS_LSTAT` / `VFS_FSTATAT` request: path bytes
//!   in IPC buffer's reserved area, `regs[0] = path_len`,
//!   `regs[1] = dir_fd` (for `FSTATAT`), `regs[2] = flags`.
//! - `VFS_ACCESS` / `VFS_FACCESSAT` request: same path layout +
//!   `regs[N] = mode` (R_OK / W_OK / X_OK).

use crate::core::error::VfsError;
use crate::core::file::VAttr;
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::{VnodeHandle, kind_to_vtype};
use crate::owner::VfsState;
use crate::owner::resume::{FsResume, Resume};
use crate::server::types::ClientHandle;

/// POSIX `X_OK` mode bit — exec preflight accessor.
const X_OK: u32 = 1;

/// Two-stage exec stat — `access(X_OK)` then `getattr` packed into
/// the compact exec-preflight shape. Either stage can park, so both
/// have dedicated `FsResume` variants.
pub(crate) unsafe fn send_stat_for_exec_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    reply_lease: trona_server::ReplyLease,
    personality: crate::personality::Personality,
) {
    unsafe {
        let vkey = match state.vnodes.get(vnode_h) {
            Some(v) => v.key,
            None => {
                crate::personality::wire::send_reply_err_typed(
                    personality,
                    reply_lease,
                    VfsError::NoEnt,
                );
                return;
            }
        };
        let cred = crate::core::cred::VfsCred::root();
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoEnt,
            );
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoEnt,
            );
            return;
        }
        match ((*ops).meta.access)(&mut ctx, X_OK, &raw const cred) {
            Ok(Ready(())) => {
                send_stat_for_exec_attr_reply_for_vnode(
                    state,
                    client,
                    vnode_h,
                    vkey,
                    reply_lease,
                    personality,
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
                    Resume::Fs(FsResume::FillStatForExecAccessReply { client, vkey }),
                ) {
                    crate::personality::wire::send_reply_err_typed(
                        personality,
                        reply_lease,
                        VfsError::Busy,
                    );
                }
            }
            Err(_) => {
                crate::personality::wire::send_reply_err_typed(
                    personality,
                    reply_lease,
                    VfsError::Acces,
                );
            }
        }
    }
}

/// Second stage of `stat_for_exec` — harvest `getattr` after the
/// access(X_OK) preflight has cleared. Packs the same 6-register
/// compact reply as the async resume path.
unsafe fn send_stat_for_exec_attr_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    vkey: crate::core::identity::VnodeKey,
    reply_lease: trona_server::ReplyLease,
    personality: crate::personality::Personality,
) {
    unsafe {
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoEnt,
            );
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoEnt,
            );
            return;
        }
        let mut attr = VAttr::zeroed();
        match ((*ops).meta.getattr)(&mut ctx, &raw mut attr) {
            Ok(Ready(())) => {
                let kind = (*ctx.vnode).kind;
                crate::personality::wire::send_reply_ok_typed(
                    personality,
                    reply_lease,
                    &[
                        attr.mode as u64,
                        attr.uid as u64,
                        attr.gid as u64,
                        attr.size,
                        attr.mtime,
                        kind_to_vtype(kind) as u64,
                    ],
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
                    Resume::Fs(FsResume::FillStatForExecAttrReply { client, vkey }),
                ) {
                    crate::personality::wire::send_reply_err_typed(
                        personality,
                        reply_lease,
                        VfsError::Busy,
                    );
                }
            }
            Err(e) => {
                crate::personality::wire::send_reply_err_typed(personality, reply_lease, e);
            }
        }
    }
}

pub(crate) unsafe fn resume_fill_stat_for_exec_access_reply(
    state: &mut VfsState,
    client: ClientHandle,
    vkey: crate::core::identity::VnodeKey,
    reply_lease: trona_server::ReplyLease,
    ack: Result<(), VfsError>,
    personality: crate::personality::Personality,
) {
    unsafe {
        let Some(vnode_h) = state.lookup_resolve_cache(vkey) else {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoEnt,
            );
            return;
        };
        if ack.is_err() {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::Acces,
            );
            return;
        }
        send_stat_for_exec_attr_reply_for_vnode(
            state,
            client,
            vnode_h,
            vkey,
            reply_lease,
            personality,
        );
    }
}

pub(crate) unsafe fn resume_fill_stat_for_exec_attr_reply(
    _state: &mut VfsState,
    _client: ClientHandle,
    _vkey: crate::core::identity::VnodeKey,
    reply_lease: trona_server::ReplyLease,
    attr: Result<VAttr, VfsError>,
    personality: crate::personality::Personality,
) {
    match attr {
        Ok(a) => crate::personality::wire::send_reply_ok_typed(
            personality,
            reply_lease,
            &[
                a.mode as u64,
                a.uid as u64,
                a.gid as u64,
                a.size,
                a.mtime,
                kind_to_vtype(a.kind) as u64,
            ],
        ),
        Err(e) => crate::personality::wire::send_reply_err_typed(personality, reply_lease, e),
    }
}

// ---------------------------------------------------------------------------
// VFS_OPEN_FOR_EXEC — `execve` binary open.
// ---------------------------------------------------------------------------

/// Stage 1 of `open_for_exec` — `access(X_OK)` preflight against the
/// caller credential (root today, until the cred-handoff lands). On
/// success, stage 2 checks Regular-file / `MNT_NOEXEC` policy and issues
/// the backing MO. Only the access stage can park; stage 2 is synchronous.
pub(crate) unsafe fn send_open_for_exec_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    reply_lease: trona_server::ReplyLease,
    personality: crate::personality::Personality,
) {
    unsafe {
        let vkey = match state.vnodes.get(vnode_h) {
            Some(v) => v.key,
            None => {
                crate::personality::wire::send_reply_err_typed(
                    personality,
                    reply_lease,
                    VfsError::NoEnt,
                );
                return;
            }
        };
        let cred = state
            .clients
            .get(client)
            .map(|c| c.cred)
            .unwrap_or_else(crate::core::cred::VfsCred::root);
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoEnt,
            );
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoEnt,
            );
            return;
        }
        match ((*ops).meta.access)(&mut ctx, X_OK, &raw const cred) {
            Ok(Ready(())) => {
                send_open_for_exec_mo_reply_for_vnode(state, vnode_h, reply_lease, personality);
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
                    Resume::Fs(FsResume::FillOpenForExecAccessReply { client, vkey }),
                ) {
                    crate::personality::wire::send_reply_err_typed(
                        personality,
                        reply_lease,
                        VfsError::Busy,
                    );
                }
            }
            Err(_) => {
                crate::personality::wire::send_reply_err_typed(
                    personality,
                    reply_lease,
                    VfsError::Acces,
                );
            }
        }
    }
}

/// Stage 2 of `open_for_exec` — Regular-file / `MNT_NOEXEC` policy, then
/// issue a read-only (non-executable) backing MemoryObject and reply with
/// the cap. EXECUTE is a conferred authority (`mo_mark_executable`), never
/// minted by the filesystem, so the binary image leaves vfs as plain
/// read-only data. Synchronous: the `MM_FILE_MMAP` RPC inside
/// `ensure_backing_mo_for_vnode` blocks the owner thread.
unsafe fn send_open_for_exec_mo_reply_for_vnode(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
    reply_lease: trona_server::ReplyLease,
    personality: crate::personality::Personality,
) {
    unsafe {
        let (kind, mount_h) = match state.vnodes.get(vnode_h) {
            Some(v) => (v.kind, v.mount),
            None => {
                crate::personality::wire::send_reply_err_typed(
                    personality,
                    reply_lease,
                    VfsError::NoEnt,
                );
                return;
            }
        };
        if kind != crate::core::vnode::VnodeKind::Regular {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::Acces,
            );
            return;
        }
        if let Some(m) = state.mounts.get(mount_h) {
            if m.mount_flags & trona_protocol::posix::MNT_NOEXEC as u64 != 0 {
                crate::personality::wire::send_reply_err_typed(
                    personality,
                    reply_lease,
                    VfsError::Acces,
                );
                return;
            }
        }
        let info = match crate::owner::mm_ipc::ensure_backing_mo_for_vnode(state, vnode_h) {
            Ok(i) => i,
            Err(e) => {
                crate::personality::wire::send_reply_err_typed(personality, reply_lease, e);
                return;
            }
        };
        let Some(cap) = trona_runtime::core::slot_alloc::dup_for_transfer_with_rights(
            trona_runtime::core::slot_alloc::resolved_cap_ref(info.mo_cap),
            // Read-only binary backing — least-privilege, no WRITE, no EXECUTE:
            //   READ — read the image bytes; the exec-authority holder validates
            //     READ to confer R-X on a CDT child via `mo_mark_executable`.
            //   TRANSFER — the kernel gates every IPC cap hop on it; without it
            //     the hop to the loader fails.
            //   GRANT — the kernel gates cnode_copy on the source holding GRANT,
            //     used to forward / per-region map the image. GRANT permits
            //     copying only, never WRITE.
            // EXECUTE is a conferred authority, never minted by the filesystem;
            // the image leaves vfs as plain read-only data.
            (uapi::KERNITE_RIGHT_READ | uapi::KERNITE_RIGHT_GRANT | uapi::KERNITE_RIGHT_TRANSFER)
                as u64,
        ) else {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoMem,
            );
            return;
        };
        let mut out = trona_kernel::core_types::TronaMsg::default();
        out.label = trona_protocol::common::TRONA_OK;
        out.regs[0] = info.size;
        out.regs[1] = info.file_offset;
        out.length = 2;
        crate::owner::op::reply_send_with_cap(reply_lease, &out, cap);
    }
}

/// Resume after the `open_for_exec` `access(X_OK)` RPC completes — re-resolve
/// the vnode, deny on access failure, else run stage 2 (policy + MO issue).
pub(crate) unsafe fn resume_fill_open_for_exec_access_reply(
    state: &mut VfsState,
    _client: ClientHandle,
    vkey: crate::core::identity::VnodeKey,
    reply_lease: trona_server::ReplyLease,
    ack: Result<(), VfsError>,
    personality: crate::personality::Personality,
) {
    unsafe {
        let Some(vnode_h) = state.lookup_resolve_cache(vkey) else {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::NoEnt,
            );
            return;
        };
        if ack.is_err() {
            crate::personality::wire::send_reply_err_typed(
                personality,
                reply_lease,
                VfsError::Acces,
            );
            return;
        }
        send_open_for_exec_mo_reply_for_vnode(state, vnode_h, reply_lease, personality);
    }
}
