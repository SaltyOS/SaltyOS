// SPDX-License-Identifier: GPL-2.0-only
//
//! Rename / hardlink logic helper.
//!
//! Both ops walk a dual-stage path:
//! - **Rename**: source walk (`StopAtParent`) stashes the old
//!   parent + old name; dest walk (`StopAtParent`) resolves the
//!   new parent + new name; `meta.rename` ties them together.
//! - **Link**: source walk (`FinalMustExist`) stashes the target
//!   leaf's vkey; dest walk (`StopAtParent`) resolves the new
//!   parent + new name; `meta.link` adds the alias.
//!
//! State between the two walks lives in
//! [`crate::owner::namei_aux::NameiAuxState::Rename`] /
//! [`Link`]. Reply emit goes through
//! `personality::reply::emit_ack`.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::identity::VnodeKey;
use crate::core::namei_async::{NameiAsyncResult, begin_path_walk_from_bytes};
use crate::core::namei_common::{NAMEI_FOLLOW, NAMEI_NOFOLLOW_FINAL};
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::ops::{AckReplyIntent, RenameLinkKind};
use crate::owner::VfsState;
use crate::owner::namei_aux::{LinkStage, NameiAuxHandle, NameiAuxState, RenameStage};
use crate::owner::pending::{WALK_NAME_MAX, WALK_PATH_MAX, WalkPolicy};
use crate::owner::resume::{FsResume, NameiTerminal, Resume};
use crate::server::open_object::OpenObjectAnchor;
use crate::server::types::ClientHandle;

/// POSIX `rename` / Win32 rename entry. Drives the dual-
/// stage walker — source path with `StopAtParent`, then dest
/// path with `StopAtParent`, then `meta.rename`.
pub(crate) unsafe fn do_rename_from_paths(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_old_vkey: VnodeKey,
    old_path: &[u8],
    old_path_len: usize,
    anchor_new_vkey: VnodeKey,
    new_path: &[u8],
    new_path_len: usize,
    no_replace: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if old_path_len == 0 || old_path_len > WALK_PATH_MAX {
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        if new_path_len == 0 || new_path_len > WALK_PATH_MAX {
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let Some(aux_h) = state.namei_aux.alloc() else {
            emit_ack_error(reply_lease, reply_intent, VfsError::NoMem);
            return;
        };

        let mut new_path_buf = [0u8; WALK_PATH_MAX];
        let copy_len = new_path_len.min(new_path.len()).min(WALK_PATH_MAX);
        new_path_buf[..copy_len].copy_from_slice(&new_path[..copy_len]);

        if let Some(slot) = state.namei_aux.get_mut(aux_h) {
            *slot = NameiAuxState::Rename {
                stage: RenameStage::SourceWalk,
                new_path: new_path_buf,
                new_path_len: new_path_len as u16,
                old_dir_vkey: VnodeKey::NONE,
                old_name: [0u8; WALK_NAME_MAX],
                old_name_len: 0,
                new_anchor_vkey: anchor_new_vkey,
            };
        }

        begin_path_walk_from_bytes(
            state,
            client,
            anchor_old_vkey,
            old_path,
            old_path_len,
            WalkPolicy::StopAtParentLookup {
                final_name: [0u8; WALK_NAME_MAX],
                final_name_len: 0,
                missing_ok: false,
            },
            NAMEI_NOFOLLOW_FINAL,
            NameiTerminal::RenameOrLink {
                kind: RenameLinkKind::Rename { no_replace },
                aux_handle: aux_h,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

/// Rename using a handle-derived source anchor and a path-derived
/// destination. Used by NT `NtRenameFile` and
/// `FileRenameInformation`, where the source object is identified
/// by handle rather than by path text.
pub(crate) unsafe fn do_rename_from_anchor_to_path(
    state: &mut VfsState,
    client: ClientHandle,
    old_anchor: OpenObjectAnchor,
    anchor_new_vkey: VnodeKey,
    new_path: &[u8],
    new_path_len: usize,
    no_replace: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if !old_anchor.is_valid() || new_path_len == 0 || new_path_len > WALK_PATH_MAX {
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let Some(aux_h) = state.namei_aux.alloc() else {
            emit_ack_error(reply_lease, reply_intent, VfsError::NoMem);
            return;
        };
        let mut new_path_buf = [0u8; WALK_PATH_MAX];
        let copy_len = new_path_len.min(new_path.len()).min(WALK_PATH_MAX);
        new_path_buf[..copy_len].copy_from_slice(&new_path[..copy_len]);
        if let Some(slot) = state.namei_aux.get_mut(aux_h) {
            *slot = NameiAuxState::Rename {
                stage: RenameStage::DestWalk,
                new_path: new_path_buf,
                new_path_len: copy_len as u16,
                old_dir_vkey: old_anchor.parent_vkey,
                old_name: old_anchor.name,
                old_name_len: old_anchor.name_len,
                new_anchor_vkey: anchor_new_vkey,
            };
        }
        begin_path_walk_from_bytes(
            state,
            client,
            anchor_new_vkey,
            &new_path_buf[..copy_len],
            copy_len,
            WalkPolicy::StopAtParentLookup {
                final_name: [0u8; WALK_NAME_MAX],
                final_name_len: 0,
                missing_ok: true,
            },
            NAMEI_NOFOLLOW_FINAL,
            NameiTerminal::RenameOrLink {
                kind: RenameLinkKind::Rename { no_replace },
                aux_handle: aux_h,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

/// POSIX `link` / Win32 hard-link entry
/// entry. Source-lookup walk (`FinalMustExist`) → dest-parent
/// walk (`StopAtParent`) → `meta.link`.
pub(crate) unsafe fn do_link_from_paths(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_old_vkey: VnodeKey,
    target_path: &[u8],
    target_path_len: usize,
    anchor_new_vkey: VnodeKey,
    link_path: &[u8],
    link_path_len: usize,
    follow_target_symlink: bool,
    no_replace: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if target_path_len == 0 || target_path_len > WALK_PATH_MAX {
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        if link_path_len == 0 || link_path_len > WALK_PATH_MAX {
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let Some(aux_h) = state.namei_aux.alloc() else {
            emit_ack_error(reply_lease, reply_intent, VfsError::NoMem);
            return;
        };

        let mut link_path_buf = [0u8; WALK_PATH_MAX];
        let copy_len = link_path_len.min(link_path.len()).min(WALK_PATH_MAX);
        link_path_buf[..copy_len].copy_from_slice(&link_path[..copy_len]);

        if let Some(slot) = state.namei_aux.get_mut(aux_h) {
            *slot = NameiAuxState::Link {
                stage: LinkStage::SourceLookup,
                new_path: link_path_buf,
                new_path_len: link_path_len as u16,
                target_vkey: VnodeKey::NONE,
                new_anchor_vkey: anchor_new_vkey,
            };
        }

        let walk_flags = if follow_target_symlink {
            NAMEI_FOLLOW
        } else {
            NAMEI_NOFOLLOW_FINAL
        };
        begin_path_walk_from_bytes(
            state,
            client,
            anchor_old_vkey,
            target_path,
            target_path_len,
            WalkPolicy::FinalMustExist,
            walk_flags,
            NameiTerminal::RenameOrLink {
                kind: RenameLinkKind::Link { no_replace },
                aux_handle: aux_h,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

/// Hard-link a handle-resolved target vnode at a path-derived
/// destination. Used by NT `FileLinkInformation`, where the
/// source object is a handle rather than source path text.
pub(crate) unsafe fn do_link_from_vkey_to_path(
    state: &mut VfsState,
    client: ClientHandle,
    target_vkey: VnodeKey,
    anchor_new_vkey: VnodeKey,
    link_path: &[u8],
    link_path_len: usize,
    no_replace: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if !target_vkey.is_valid() || link_path_len == 0 || link_path_len > WALK_PATH_MAX {
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let Some(aux_h) = state.namei_aux.alloc() else {
            emit_ack_error(reply_lease, reply_intent, VfsError::NoMem);
            return;
        };
        let mut link_path_buf = [0u8; WALK_PATH_MAX];
        let copy_len = link_path_len.min(link_path.len()).min(WALK_PATH_MAX);
        link_path_buf[..copy_len].copy_from_slice(&link_path[..copy_len]);
        if let Some(slot) = state.namei_aux.get_mut(aux_h) {
            *slot = NameiAuxState::Link {
                stage: LinkStage::DestParent,
                new_path: link_path_buf,
                new_path_len: copy_len as u16,
                target_vkey,
                new_anchor_vkey: anchor_new_vkey,
            };
        }
        begin_path_walk_from_bytes(
            state,
            client,
            anchor_new_vkey,
            &link_path_buf[..copy_len],
            copy_len,
            WalkPolicy::StopAtParentLookup {
                final_name: [0u8; WALK_NAME_MAX],
                final_name_len: 0,
                missing_ok: true,
            },
            NAMEI_NOFOLLOW_FINAL,
            NameiTerminal::RenameOrLink {
                kind: RenameLinkKind::Link { no_replace },
                aux_handle: aux_h,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

/// `NameiTerminal::RenameOrLink` callback. Routes to the matching
/// stage handler based on the aux state's stage marker.
pub(crate) unsafe fn dispatch_phase(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    kind: RenameLinkKind,
    aux_h: NameiAuxHandle,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        match kind {
            RenameLinkKind::Rename { no_replace } => {
                let stage = match state.namei_aux.get(aux_h) {
                    Some(NameiAuxState::Rename { stage, .. }) => *stage,
                    _ => {
                        let _ = state.namei_aux.release(aux_h);
                        emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                        return;
                    }
                };
                match stage {
                    RenameStage::SourceWalk => advance_to_dest_rename(
                        state,
                        client,
                        result,
                        aux_h,
                        no_replace,
                        reply_intent,
                        reply_lease,
                    ),
                    RenameStage::DestWalk => execute_rename(
                        state,
                        client,
                        result,
                        aux_h,
                        no_replace,
                        reply_intent,
                        reply_lease,
                    ),
                }
            }
            RenameLinkKind::Link { no_replace } => {
                let stage = match state.namei_aux.get(aux_h) {
                    Some(NameiAuxState::Link { stage, .. }) => *stage,
                    _ => {
                        let _ = state.namei_aux.release(aux_h);
                        emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                        return;
                    }
                };
                match stage {
                    LinkStage::SourceLookup => advance_to_dest_link(
                        state,
                        client,
                        result,
                        aux_h,
                        no_replace,
                        reply_intent,
                        reply_lease,
                    ),
                    LinkStage::DestParent => execute_link(
                        state,
                        client,
                        result,
                        aux_h,
                        no_replace,
                        reply_intent,
                        reply_lease,
                    ),
                }
            }
        }
    }
}

// ============================================================
// Rename — stage transitions
// ============================================================

unsafe fn advance_to_dest_rename(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    aux_h: NameiAuxHandle,
    no_replace: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if !result.dir_vnode_h.is_valid() {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        if result.last_name_len == 0 || result.last_name_len as usize > WALK_NAME_MAX {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let name_slice = &result.last_name[..result.last_name_len as usize];
        if name_slice == b"." || name_slice == b".." {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        if result.vnode_h.is_valid()
            && crate::core::mount_ctl::covering_mount_for_vnode(state, result.vnode_h).is_some()
        {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
            return;
        }
        let old_dir_vkey = match state.vnodes.get(result.dir_vnode_h) {
            Some(v) => v.key,
            None => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        let (new_path_buf, new_path_len, new_anchor_vkey) = match state.namei_aux.get_mut(aux_h) {
            Some(NameiAuxState::Rename {
                stage,
                new_path,
                new_path_len,
                old_dir_vkey: odk,
                old_name,
                old_name_len,
                new_anchor_vkey,
            }) => {
                *stage = RenameStage::DestWalk;
                *odk = old_dir_vkey;
                *old_name = result.last_name;
                *old_name_len = result.last_name_len;
                (*new_path, *new_path_len as usize, *new_anchor_vkey)
            }
            _ => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        begin_path_walk_from_bytes(
            state,
            client,
            new_anchor_vkey,
            &new_path_buf[..new_path_len],
            new_path_len,
            WalkPolicy::StopAtParentLookup {
                final_name: [0u8; WALK_NAME_MAX],
                final_name_len: 0,
                missing_ok: true,
            },
            NAMEI_NOFOLLOW_FINAL,
            NameiTerminal::RenameOrLink {
                kind: RenameLinkKind::Rename { no_replace },
                aux_handle: aux_h,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

unsafe fn execute_rename(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    aux_h: NameiAuxHandle,
    _no_replace: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if !result.dir_vnode_h.is_valid() {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        if result.last_name_len == 0 || result.last_name_len as usize > WALK_NAME_MAX {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }
        let name_slice = &result.last_name[..result.last_name_len as usize];
        if name_slice == b"." || name_slice == b".." {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }

        let (old_dir_vkey, old_name_buf, old_name_len) = match state.namei_aux.get(aux_h) {
            Some(NameiAuxState::Rename {
                old_dir_vkey,
                old_name,
                old_name_len,
                ..
            }) => (*old_dir_vkey, *old_name, *old_name_len),
            _ => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        let Some(old_parent_h) = resolve_vkey(state, old_dir_vkey) else {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        };

        let new_dir_h = result.dir_vnode_h;
        let new_name_buf = result.last_name;
        let new_name_len = result.last_name_len;
        if result.vnode_h.is_valid()
            && crate::core::mount_ctl::covering_mount_for_vnode(state, result.vnode_h).is_some()
        {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
            return;
        }

        // Cross-mount rename rejection — POSIX `rename(2)` mandates
        // EXDEV when source and target reside on different mounts.
        let old_mount = state.vnodes.get(old_parent_h).map(|v| v.mount);
        let new_mount = state.vnodes.get(new_dir_h).map(|v| v.mount);
        match (old_mount, new_mount) {
            (Some(om), Some(nm)) if om != nm => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::XDev);
                return;
            }
            (Some(_), Some(_)) => {}
            _ => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        }
        let new_parent_vkey = match state.vnodes.get(new_dir_h) {
            Some(v) => v.key,
            None => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, old_parent_h)
        else {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }

        let outcome = ((*ops).meta.rename)(
            &mut ctx,
            old_name_buf.as_ptr(),
            old_name_len,
            new_dir_h,
            new_name_buf.as_ptr(),
            new_name_len,
        );
        let _ = state.namei_aux.release(aux_h);

        match outcome {
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
                    Resume::Fs(FsResume::FinalOpAckRename {
                        client,
                        new_parent_vkey,
                        old_parent_vkey: old_dir_vkey,
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
// Link — stage transitions
// ============================================================

unsafe fn advance_to_dest_link(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    aux_h: NameiAuxHandle,
    no_replace: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if !result.vnode_h.is_valid() {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        let target_vkey = match state.vnodes.get(result.vnode_h) {
            Some(v) => v.key,
            None => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        let (link_path_buf, link_path_len, new_anchor_vkey) = match state.namei_aux.get_mut(aux_h) {
            Some(NameiAuxState::Link {
                stage,
                new_path,
                new_path_len,
                target_vkey: tk,
                new_anchor_vkey,
            }) => {
                *stage = LinkStage::DestParent;
                *tk = target_vkey;
                (*new_path, *new_path_len as usize, *new_anchor_vkey)
            }
            _ => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        begin_path_walk_from_bytes(
            state,
            client,
            new_anchor_vkey,
            &link_path_buf[..link_path_len],
            link_path_len,
            WalkPolicy::StopAtParentLookup {
                final_name: [0u8; WALK_NAME_MAX],
                final_name_len: 0,
                missing_ok: true,
            },
            NAMEI_NOFOLLOW_FINAL,
            NameiTerminal::RenameOrLink {
                kind: RenameLinkKind::Link { no_replace },
                aux_handle: aux_h,
                reply: reply_intent,
            },
            reply_lease,
        );
    }
}

unsafe fn execute_link(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    aux_h: NameiAuxHandle,
    no_replace: bool,
    reply_intent: AckReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if !result.dir_vnode_h.is_valid() {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        if result.last_name_len == 0 || result.last_name_len as usize > WALK_NAME_MAX {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Inval);
            return;
        }

        let target_vkey = match state.namei_aux.get(aux_h) {
            Some(NameiAuxState::Link { target_vkey, .. }) => *target_vkey,
            _ => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };
        let Some(target_h) = resolve_vkey(state, target_vkey) else {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::NoEnt);
            return;
        };
        if !no_replace {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::NotSup);
            return;
        }

        let new_parent_h = result.dir_vnode_h;
        let new_name_buf = result.last_name;
        let new_name_len = result.last_name_len;
        if result.vnode_h.is_valid()
            && crate::core::mount_ctl::covering_mount_for_vnode(state, result.vnode_h).is_some()
        {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Busy);
            return;
        }
        let target_mount = state.vnodes.get(target_h).map(|v| v.mount);
        let new_mount = state.vnodes.get(new_parent_h).map(|v| v.mount);
        match (target_mount, new_mount) {
            (Some(tm), Some(nm)) if tm == nm => {}
            (Some(_), Some(_)) => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::XDev);
                return;
            }
            _ => {
                let _ = state.namei_aux.release(aux_h);
                emit_ack_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        }

        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, new_parent_h)
        else {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            let _ = state.namei_aux.release(aux_h);
            emit_ack_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        let new_parent_vkey = (*ctx.vnode).key;

        let outcome = ((*ops).meta.link)(&mut ctx, new_name_buf.as_ptr(), new_name_len, target_h);
        let _ = state.namei_aux.release(aux_h);

        match outcome {
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
                    Resume::Fs(FsResume::FinalOpAckLink {
                        client,
                        new_parent_vkey,
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
// Helpers
// ============================================================

fn resolve_vkey(state: &VfsState, vkey: VnodeKey) -> Option<VnodeHandle> {
    if !vkey.is_valid() {
        return None;
    }
    if let Some(h) = state.lookup_resolve_cache(vkey) {
        return Some(h);
    }
    let mut found = None;
    state.vnodes.for_each_active(|h, v| {
        if v.key == vkey {
            found = Some(h);
            false
        } else {
            true
        }
    });
    found
}

unsafe fn emit_ack_error(reply_lease: ReplyLease, intent: AckReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_ack(reply_lease, intent, 0, Err(err));
    }
}
