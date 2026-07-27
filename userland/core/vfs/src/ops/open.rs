// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-neutral open + create-mode logic helper.
//!
//! Both POSIX (`personality/posix/open.rs::handle`) and Win32
//! (`personality/win32/open.rs::handle_nt_create_file` /
//! `handle_nt_open_file`) decode their own wire shape into a
//! [`VfsOpenSpec`] + [`OpenReplyIntent`] and call into this
//! helper. The helper drives the shared async namei walker
//! through to the matching [`NameiTerminal::Open`] terminal,
//! whose callback (in `crate::core::namei_async`) resolves
//! the final-component vop, installs an `OpenObject` + fd, and
//! routes the reply through `personality::reply::emit_open`.
//!
//! Nothing in this module references `kernel IPC message`, POSIX `O_*` /
//! `S_*` literals, Windows `create-disposition` / `status` literals, or wire
//! protocol labels — POSIX and Windows meet the vop chain on equal
//! footing through this seam.

use trona_server::ReplyLease;

use crate::core::error::{VfsError, VfsResult};
use crate::core::identity::VnodeKey;
use crate::core::namei_async::NameiAsyncResult;
use crate::core::namei_common::{NAMEI_CASE_INSENSITIVE, NAMEI_FOLLOW, NAMEI_NOFOLLOW_FINAL};
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::{VnodeHandle, VnodeKind};
use crate::ops::{
    CreateMode, OpenAccess, OpenCreateAction, OpenOptions, OpenReplyIntent, OpenResult, VfsOpenSpec,
};
use crate::owner::VfsState;
use crate::owner::pending::{WALK_NAME_MAX, WalkPolicy};
use crate::owner::resume::{FsResume, NameiTerminal, Resume};
use crate::personality::win32::security::{self, NtAclCheck};
use crate::server::open_object::{
    OpenObject, OpenObjectAccess, OpenObjectAnchor, OpenObjectFlags, OpenObjectKind,
    OpenObjectNamedState,
};
use crate::server::types::{ClientHandle, OpenObjectHandle};

/// Drive the async namei walker to the [`NameiTerminal::Open`]
/// terminal with the supplied `spec` + `reply_intent`. The walker
/// either resolves the leaf synchronously (the terminal callback
/// installs the fd inline and emits the reply) or parks on a
/// backend RPC (`FsResume::FillOpenReply { spec, reply }` is
/// stamped on the reserved `PendingOp`).
///
/// `path_bytes[..path_len]` is the canonical path the walker
/// resolves. POSIX entries pass the wire path verbatim; Win32
/// entries pass the result of [`canonicalize_nt_path`] (drive
/// letter resolved + separators normalised + Windows prefix stripped).
///
/// `anchor_vkey` is the resolved `dirfd` for `openat`-style
/// callers; pass `VnodeKey::NONE` for absolute-path callers and
/// the walker falls back to the namespace root.
///
/// [`canonicalize_nt_path`]: crate::personality::win32::path::canonicalize_nt_path
pub(crate) unsafe fn do_namei_open_from_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_vkey: VnodeKey,
    path_bytes: &[u8],
    path_len: usize,
    spec: VfsOpenSpec,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    let policy = match spec.create {
        CreateMode::Open | CreateMode::Truncate => WalkPolicy::FinalMustExist,
        CreateMode::OpenAlways
        | CreateMode::CreateAlways
        | CreateMode::Supersede
        | CreateMode::Create => WalkPolicy::CreateOrOpen {
            final_name: [0u8; WALK_NAME_MAX],
            final_name_len: 0,
            final_missing: false,
        },
    };
    let mut walker_flags = if spec.options.contains(OpenOptions::NO_FOLLOW_LEAF) {
        NAMEI_NOFOLLOW_FINAL
    } else {
        NAMEI_FOLLOW
    };
    if matches!(
        reply_intent,
        OpenReplyIntent::NtCreateFile { .. } | OpenReplyIntent::NtOpenFile { .. }
    ) {
        walker_flags |= NAMEI_CASE_INSENSITIVE;
    }
    unsafe {
        let terminal = NameiTerminal::Open {
            spec,
            reply: reply_intent,
        };
        crate::core::namei_async::begin_path_walk_from_bytes(
            state,
            client,
            anchor_vkey,
            path_bytes,
            path_len,
            policy,
            walker_flags,
            terminal,
            reply_lease,
        );
    }
}

/// `NameiTerminal::Open { spec, reply }` callback. Invoked by
/// `crate::core::namei_async` when the async walker reaches
/// the leaf (or, for create-class disposition, the parent + a
/// missing final component).
///
/// Three terminal shapes:
///
/// 1. `result.vnode_h.is_valid()` — leaf resolved. Honour the
///    create-mode's "must not exist" guard ([`CreateMode::Create`]
///    rejects with `VfsError::Exist`), then run `meta.open` on
///    the leaf and install an `OpenObject` + fd.
/// 2. `result.vnode_h` invalid + `result.dir_vnode_h` valid +
///    create-mode allows creation — final component missing.
///    Run `meta.create` on the parent with `result.last_name`,
///    install fd on the materialised child once the backend acks.
/// 3. `result.vnode_h` invalid + create-mode forbids creation —
///    `VfsError::NoEnt`.
pub(crate) unsafe fn resume_open_walk_result(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    spec: VfsOpenSpec,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if state.clients.get(client).is_none() {
            return;
        }

        if result.vnode_h.is_valid() {
            // Path 1: leaf resolved.
            if matches!(spec.create, CreateMode::Create) {
                // Both POSIX `O_CREAT|O_EXCL` and Windows `Windows-specific value`
                // require the leaf to be freshly created. An
                // existing leaf is a hard error.
                emit_open_error(state, client, reply_lease, reply_intent, VfsError::Exist);
                return;
            }
            open_resolved_leaf(
                state,
                client,
                result.vnode_h,
                result.leaf_anchor,
                spec,
                reply_intent,
                reply_lease,
            );
            return;
        }

        // Paths 2 / 3: leaf missing.
        let allows_create = matches!(
            spec.create,
            CreateMode::OpenAlways
                | CreateMode::Create
                | CreateMode::CreateAlways
                | CreateMode::Supersede
        );
        if !allows_create {
            emit_open_error(state, client, reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        if !result.dir_vnode_h.is_valid() || result.last_name_len == 0 {
            emit_open_error(state, client, reply_lease, reply_intent, VfsError::NoEnt);
            return;
        }
        create_and_open_child(state, client, result, spec, reply_intent, reply_lease);
    }
}

/// Run `meta.open` on the resolved leaf, then install the
/// `OpenObject` + fd inline (Ready) or stamp
/// `FsResume::FillOpenReply` on the parked PendingOp so the
/// backend completion route lands through
/// [`finish_open_resolved_leaf`] once the open is acknowledged.
unsafe fn open_resolved_leaf(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    anchor: OpenObjectAnchor,
    spec: VfsOpenSpec,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        open_resolved_leaf_common(
            state,
            client,
            vnode_h,
            anchor,
            spec,
            reply_intent,
            reply_lease,
            false,
        );
    }
}

/// Re-enter a Win32 open after a parked `security.NTACL` xattr
/// fetch has completed and passed access evaluation. The generic
/// open checks (leaf kind, share policy, backend `meta.open`) are
/// intentionally re-run because other handles may have appeared
/// while the xattr request was in flight.
pub(crate) unsafe fn resume_open_after_nt_acl(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    anchor: OpenObjectAnchor,
    spec: VfsOpenSpec,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        open_resolved_leaf_common(
            state,
            client,
            vnode_h,
            anchor,
            spec,
            reply_intent,
            reply_lease,
            true,
        );
    }
}

/// Maximum raw `security.NTACL` descriptor bytes an open-time backend
/// completion should copy before handing the payload back to this module.
pub(crate) const NT_ACL_LOOKUP_MAX: usize = security::MAX_SECURITY_DESCRIPTOR_SIZE;

/// Complete a parked Win32 open-time NTACL lookup.
///
/// Filesystem completion routers own backend-protocol parsing and SHM copy.
/// They pass only generic xattr bytes or a `VfsError` here; NT security
/// descriptor interpretation and the fallback policy stay with the Win32 open
/// path rather than leaking into filesystem-specific completion code.
pub(crate) unsafe fn resume_open_after_nt_acl_lookup(
    state: &mut VfsState,
    client: ClientHandle,
    vkey: VnodeKey,
    anchor: OpenObjectAnchor,
    spec: VfsOpenSpec,
    reply: OpenReplyIntent,
    desired_access: u32,
    acl_lookup: VfsResult<&[u8]>,
    reply_lease: ReplyLease,
) {
    unsafe {
        let client_ptr = state
            .clients
            .raw_ptr(client)
            .map(|p| p as *const crate::owner::clients::ClientState)
            .unwrap_or(::core::ptr::null());
        let acl = match acl_lookup {
            Ok(bytes) if bytes.len() > NT_ACL_LOOKUP_MAX => Err(VfsError::Range),
            Ok(bytes) => security::check_nt_acl_descriptor_bytes(bytes, desired_access, client_ptr),
            Err(e) if e.is_optional_metadata_absent() => Ok(()),
            Err(e) => Err(e),
        };

        match acl.and_then(|()| resolve_open_vkey_handle(state, vkey)) {
            Ok(vnode_h) => {
                resume_open_after_nt_acl(state, client, vnode_h, anchor, spec, reply, reply_lease)
            }
            Err(e) => {
                crate::personality::reply::emit_open(reply_lease, reply, Err(e));
            }
        }
    }
}

unsafe fn open_resolved_leaf_common(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    anchor: OpenObjectAnchor,
    spec: VfsOpenSpec,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
    nt_acl_checked: bool,
) {
    unsafe {
        // Reject directory-against-write up front — POSIX mandates
        // EISDIR for any open whose access requests data writes
        // on a directory leaf, and Windows raises status value
        // for the same case.
        let kind = match state.vnodes.get(vnode_h) {
            Some(v) => v.kind,
            None => {
                emit_open_error(state, client, reply_lease, reply_intent, VfsError::NoEnt);
                return;
            }
        };
        if matches!(kind, VnodeKind::Directory) && open_is_writable(spec.access) {
            emit_open_error(state, client, reply_lease, reply_intent, VfsError::IsDir);
            return;
        }
        if spec.options.contains(OpenOptions::DIRECTORY) && !matches!(kind, VnodeKind::Directory) {
            emit_open_error(state, client, reply_lease, reply_intent, VfsError::NotDir);
            return;
        }
        if !share_policy_allows_open(state, vnode_h, spec) {
            emit_open_error(state, client, reply_lease, reply_intent, VfsError::Busy);
            return;
        }

        let client_ptr = state
            .clients
            .raw_ptr(client)
            .map(|p| p as *const crate::owner::clients::ClientState)
            .unwrap_or(::core::ptr::null());
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_open_error(state, client, reply_lease, reply_intent, VfsError::Io);
            return;
        };
        if let Some(access_mask) = win32_open_attrs(reply_intent).map(|attrs| attrs.granted_access)
        {
            if nt_acl_checked {
                // The ACL was evaluated by the completion router
                // immediately before re-entering this helper.
            } else {
                if client_ptr.is_null() {
                    emit_open_error(state, client, reply_lease, reply_intent, VfsError::Io);
                    return;
                }
                match crate::personality::win32::security::check_nt_acl_or_park(
                    &ctx,
                    access_mask,
                    client_ptr,
                ) {
                    NtAclCheck::Allowed => {}
                    NtAclCheck::Denied(e) => {
                        emit_open_error(state, client, reply_lease, reply_intent, e);
                        return;
                    }
                    NtAclCheck::Parked(handle) => {
                        let vkey = (*ctx.vnode).key;
                        drop(ctx);
                        let badge = state
                            .clients
                            .get(client)
                            .map(|c| c.client_badge)
                            .unwrap_or(0);
                        if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                            handle,
                            badge,
                            Some(reply_lease),
                            Resume::Fs(FsResume::FillNtAclOpenReply {
                                client,
                                vkey,
                                anchor,
                                spec,
                                reply: reply_intent,
                                desired_access: access_mask,
                            }),
                        ) {
                            emit_open_error(
                                state,
                                client,
                                reply_lease,
                                reply_intent,
                                VfsError::Busy,
                            );
                        }
                        return;
                    }
                }
            }
        }
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            // No vop chain — bootstrap ramfs vnodes that are pre-
            // baked without a backend round-trip. Fall straight
            // to the install path.
            let action = pick_open_action(spec.create, /* leaf_was_missing = */ false);
            finish_open_resolved_leaf_with_anchor(
                state,
                client,
                vnode_h,
                anchor,
                spec,
                action,
                reply_intent,
                reply_lease,
            );
            return;
        }
        let vkey = (*ctx.vnode).key;
        // `meta.open` takes a single u32 flag word in the legacy
        // vop ABI; the create-mode vs access-mode split lives at
        // the personality wire layer, but the vop only needs a
        // Linux-style `O_*` projection. We reconstruct just enough
        // for the existing backend implementations.
        let legacy_flags = legacy_open_flags(spec);
        match ((*ops).meta.open)(&mut ctx, legacy_flags) {
            Ok(Ready(())) => {
                let action = pick_open_action(spec.create, /* leaf_was_missing = */ false);
                finish_open_resolved_leaf_with_anchor(
                    state,
                    client,
                    vnode_h,
                    anchor,
                    spec,
                    action,
                    reply_intent,
                    reply_lease,
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
                    Resume::Fs(FsResume::FillOpenReply {
                        client,
                        vkey,
                        anchor,
                        spec,
                        reply: reply_intent,
                    }),
                ) {
                    emit_open_error(state, client, reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => emit_open_error(state, client, reply_lease, reply_intent, e),
        }
    }
}

/// `O_CREAT` short-circuit. Issue `meta.create` on the parent
/// directory with `result.last_name`. On `Ready` the new vnode
/// is materialised inline and the fd installs immediately. On
/// `Parked` the completion router resumes through
/// `FsResume::FinalOpChild` (kind=Create, spec=Some(spec),
/// open_reply=reply_intent) and the mutation router calls back
/// into [`finish_open_resolved_leaf`] once the backend acks.
unsafe fn create_and_open_child(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    spec: VfsOpenSpec,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        let dir_h = result.dir_vnode_h;
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, dir_h) else {
            emit_open_error(state, client, reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            emit_open_error(state, client, reply_lease, reply_intent, VfsError::NotSup);
            return;
        }
        let parent_vkey = (*ctx.vnode).key;
        let cred = crate::core::cred::VfsCred::root();
        let name = result.last_name.as_ptr();
        let name_len = result.last_name_len;
        match ((*ops).meta.create)(&mut ctx, name, name_len, spec.mode, &raw const cred) {
            Ok(Ready(new_vnode_h)) => {
                if !new_vnode_h.is_valid() {
                    emit_open_error(state, client, reply_lease, reply_intent, VfsError::Io);
                    return;
                }
                let action = pick_open_action(spec.create, /* leaf_was_missing = */ true);
                let anchor = OpenObjectAnchor::from_component(
                    parent_vkey,
                    &result.last_name[..result.last_name_len as usize],
                    result.last_name_len,
                );
                finish_open_resolved_leaf_with_anchor(
                    state,
                    client,
                    new_vnode_h,
                    anchor,
                    spec,
                    action,
                    reply_intent,
                    reply_lease,
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
                    Resume::Fs(FsResume::FinalOpChild {
                        client,
                        parent_vkey,
                        kind_hint: crate::owner::resume::FinalOpKind::Create,
                        spec: Some(spec),
                        open_reply: reply_intent,
                        ack_reply: crate::ops::AckReplyIntent::PosixAck,
                        creds_uid: 0,
                        creds_gid: 0,
                    }),
                ) {
                    emit_open_error(state, client, reply_lease, reply_intent, VfsError::Busy);
                }
            }
            Err(e) => emit_open_error(state, client, reply_lease, reply_intent, e),
        }
    }
}

/// Install the `OpenObject` for `vnode_h`, allocate a fd, emit
/// the personality-aware reply via
/// [`crate::personality::reply::emit_open`].
pub(crate) unsafe fn finish_open_resolved_leaf(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    spec: VfsOpenSpec,
    action: OpenCreateAction,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        finish_open_resolved_leaf_with_anchor(
            state,
            client,
            vnode_h,
            OpenObjectAnchor::EMPTY,
            spec,
            action,
            reply_intent,
            reply_lease,
        );
    }
}

pub(crate) unsafe fn finish_open_resolved_leaf_with_anchor(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    anchor: OpenObjectAnchor,
    spec: VfsOpenSpec,
    action: OpenCreateAction,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        // `/dev/tty` resolves per-session to the caller's controlling
        // terminal. Defer the open: ask posix_ttysrv which pty the
        // caller's session owns, then install + bind on completion.
        if vnode_is_dev_tty(state, vnode_h) {
            issue_ctty_bind_open(
                state,
                client,
                vnode_h,
                anchor,
                spec,
                action,
                reply_intent,
                reply_lease,
            );
            return;
        }
        let result =
            match install_open_for_vnode(state, client, vnode_h, spec, anchor, reply_intent) {
                Ok((_open_h, fd)) => Ok(OpenResult { fd, action }),
                Err(e) => Err(e),
            };
        crate::personality::reply::emit_open(reply_lease, reply_intent, result);
    }
}

/// True when `vnode_h` is the `/dev/tty` devfs node.
fn vnode_is_dev_tty(state: &VfsState, vnode_h: VnodeHandle) -> bool {
    let Some(vnode) = state.vnodes.get(vnode_h) else {
        return false;
    };
    if !::core::ptr::eq(vnode.ops, &raw const crate::fs::devfs::DEVFS_VOPS) {
        return false;
    }
    if vnode.data.is_null() {
        return false;
    }
    let data = unsafe { &*(vnode.data as *const crate::fs::devfs::DevfsVnodeData) };
    matches!(data.kind, crate::fs::devfs::DevKind::Tty)
}

/// Begin an `open("/dev/tty")`: resolve the caller's POSIX session, ask
/// posix_ttysrv which pty owns it as a controlling terminal (async), and
/// park the open until the answer lands. The OpenObject is installed only
/// on success, so a session with no ctty cleanly fails the open.
unsafe fn issue_ctty_bind_open(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    anchor: OpenObjectAnchor,
    spec: VfsOpenSpec,
    action: OpenCreateAction,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        let caller_badge = state
            .clients
            .get(client)
            .map(|c| c.client_badge)
            .unwrap_or(0);
        // Resolve the caller's POSIX session from init asynchronously (a
        // blocking VFS→init query would risk the init↔VFS reactor cycle).
        // The pty ctty-lookup + ctty bind run at finalize via
        // `CttyAction::OpenBind`, which carries the prebuilt resume.
        let resume =
            crate::owner::resume::Resume::Fs(crate::owner::resume::FsResume::BindCttyOpen {
                client,
                vnode_h,
                anchor,
                spec,
                action,
                reply: reply_intent,
            });
        let plan = [crate::owner::init_rpc::InitStep {
            label: trona_protocol::posix::INIT_PGRP_SESSION,
            sub_op: trona_protocol::posix::INIT_PGRP_SUB_GET_SID_PGID_BY_BADGE,
            arg: caller_badge,
        }];
        crate::owner::init_rpc::begin_init_read(
            state,
            &plan,
            crate::owner::init_rpc::InitReadState::Ctty {
                client,
                action: crate::owner::init_rpc::CttyAction::OpenBind {
                    resume,
                    err_intent: reply_intent,
                },
                sid: 0,
                pgid: 0,
            },
            0,
            caller_badge,
            reply_lease,
        );
    }
}

/// Completion for [`issue_ctty_bind_open`]: install the OpenObject, bind
/// the resolved ctty pty, and emit the open — or fail with `NotTty` when
/// posix_ttysrv reports the session owns no controlling terminal.
pub(crate) unsafe fn resume_bind_ctty_open(
    state: &mut VfsState,
    found: bool,
    pty_id: u32,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    anchor: OpenObjectAnchor,
    spec: VfsOpenSpec,
    action: OpenCreateAction,
    reply_intent: OpenReplyIntent,
    reply_lease: Option<ReplyLease>,
) {
    unsafe {
        let Some(reply_lease) = reply_lease else {
            return;
        };
        if !found {
            crate::personality::reply::emit_open(reply_lease, reply_intent, Err(VfsError::NotTty));
            return;
        }
        let result =
            match install_open_for_vnode(state, client, vnode_h, spec, anchor, reply_intent) {
                Ok((open_h, fd)) => {
                    if let Some(obj) = state.open_objects.get_mut(open_h) {
                        obj.ctty_pty = pty_id;
                    }
                    Ok(OpenResult { fd, action })
                }
                Err(e) => Err(e),
            };
        crate::personality::reply::emit_open(reply_lease, reply_intent, result);
    }
}

/// Allocate a fresh `OpenObject` for `vnode_h`, install it at
/// the caller's first free fd, and return `(handle, fd)`. Bumps
/// both the `OpenObject` refcount and the vnode's
/// `open_refcount` on behalf of the new fd alias.
fn install_open_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vnode_h: VnodeHandle,
    spec: VfsOpenSpec,
    anchor: OpenObjectAnchor,
    reply_intent: OpenReplyIntent,
) -> Result<(OpenObjectHandle, u32), VfsError> {
    let kind = state.vnodes.get(vnode_h).map(|v| v.kind);
    let Some(kind) = kind else {
        return Err(VfsError::NoEnt);
    };

    let open_h = state.open_objects.alloc().ok_or(VfsError::NoMem)?;
    let named_state = if anchor.is_valid() {
        let handle = match state.open_object_named_states.alloc() {
            Some(handle) => handle,
            None => {
                state.open_objects.release(open_h);
                return Err(VfsError::NoMem);
            }
        };
        if let Some(named) = state.open_object_named_states.get_mut(handle) {
            *named = OpenObjectNamedState::EMPTY;
            named.anchor = anchor;
        }
        handle
    } else {
        crate::arena::Handle::INVALID
    };
    let win32_state = if let Some(attrs) = win32_open_attrs(reply_intent) {
        match crate::personality::win32::open_state::install(
            state,
            attrs.granted_access,
            attrs.share_access,
            attrs.create_options,
        ) {
            Some(handle) => handle,
            None => {
                state.open_objects.release(open_h);
                if named_state.is_valid() {
                    state.open_object_named_states.release(named_state);
                }
                return Err(VfsError::NoMem);
            }
        }
    } else {
        crate::arena::Handle::INVALID
    };
    if let Some(obj) = state.open_objects.get_mut(open_h) {
        // Start from EMPTY so fields the arena zeroed but this path does not set
        // (notably `ctty_pty`) get their non-zero defaults — `ctty_pty` must be
        // `u32::MAX` ("not a /dev/tty handle") or pty routing hijacks file I/O.
        *obj = OpenObject::EMPTY;
        obj.vnode = vnode_h;
        obj.offset = 0;
        obj.refcount = 1;
        obj.flags = open_object_flags_from_spec(kind, spec);
        obj.access = open_object_access_from_spec(spec);
        obj.kind = OpenObjectKind::Vnode;
        obj.share = spec.share.bits();
        obj.options = spec.options.bits();
        obj.personality_aux = if win32_state.is_valid() {
            win32_state.slot()
        } else {
            u32::MAX
        };
        obj.named_state = named_state;
    }
    if let Some(vnode) = state.vnodes.get_mut(vnode_h) {
        vnode.open_refcount = vnode.open_refcount.saturating_add(1);
    }

    let fd = match reserve_fd_owned(state, client) {
        Ok(fd) => fd,
        Err(e) => {
            state.open_objects.release(open_h);
            if named_state.is_valid() {
                state.open_object_named_states.release(named_state);
            }
            if win32_state.is_valid() {
                state.win32_handle_states.release(win32_state);
            }
            if let Some(vnode) = state.vnodes.get_mut(vnode_h) {
                vnode.open_refcount = vnode.open_refcount.saturating_sub(1);
            }
            return Err(e);
        }
    };
    let cli = match state.clients.get_mut(client) {
        Some(c) => c,
        None => {
            state.open_objects.release(open_h);
            if named_state.is_valid() {
                state.open_object_named_states.release(named_state);
            }
            if win32_state.is_valid() {
                state.win32_handle_states.release(win32_state);
            }
            if let Some(vnode) = state.vnodes.get_mut(vnode_h) {
                vnode.open_refcount = vnode.open_refcount.saturating_sub(1);
            }
            return Err(VfsError::Io);
        }
    };
    if cli.slot_table.set(fd, open_h).is_err() {
        state.open_objects.release(open_h);
        if named_state.is_valid() {
            state.open_object_named_states.release(named_state);
        }
        if win32_state.is_valid() {
            state.win32_handle_states.release(win32_state);
        }
        if let Some(vnode) = state.vnodes.get_mut(vnode_h) {
            vnode.open_refcount = vnode.open_refcount.saturating_sub(1);
        }
        return Err(VfsError::NoMem);
    }
    if (spec.fd_flags & 0x01) != 0 {
        cli.slot_table
            .set_slot_flag_bit(fd, crate::server::open_object::FD_FLAG_CLOEXEC, true);
    }
    Ok((open_h, fd))
}

#[derive(Clone, Copy)]
struct Win32OpenAttrs {
    granted_access: u32,
    share_access: u32,
    create_options: u32,
}

#[inline]
fn win32_open_attrs(reply_intent: OpenReplyIntent) -> Option<Win32OpenAttrs> {
    match reply_intent {
        OpenReplyIntent::NtCreateFile {
            desired_access,
            share_access,
            create_options,
        }
        | OpenReplyIntent::NtOpenFile {
            desired_access,
            share_access,
            create_options,
        } => Some(Win32OpenAttrs {
            granted_access: desired_access,
            share_access,
            create_options,
        }),
        OpenReplyIntent::PosixOpen => None,
    }
}

fn resolve_open_vkey_handle(state: &VfsState, vkey: VnodeKey) -> VfsResult<VnodeHandle> {
    state.lookup_resolve_cache(vkey).ok_or(VfsError::NoEnt)
}

/// Reserve a free fd slot in the client's segmented slot table.
/// Grows the table on demand — no fixed cap.
pub(crate) fn reserve_fd_owned(
    state: &mut VfsState,
    client: ClientHandle,
) -> Result<u32, VfsError> {
    let cli = state.clients.get_mut(client).ok_or(VfsError::Io)?;
    cli.slot_table
        .find_first_empty_from(0)
        .map_err(|_| VfsError::NoMem)
}

/// Project the spec onto the legacy `meta.open` flag word the
/// existing backend vops still consume. The conversion is a
/// thin POSIX-shape projection for the vop's benefit; it does
/// not flow into the wire reply (the personality reply layer
/// owns wire emit).
fn legacy_open_flags(spec: VfsOpenSpec) -> u32 {
    const O_RDONLY: u32 = 0x0;
    const O_WRONLY: u32 = 0x1;
    const O_RDWR: u32 = 0x2;
    const O_CREAT: u32 = 0x40;
    const O_EXCL: u32 = 0x80;
    const O_TRUNC: u32 = 0x200;
    const O_APPEND: u32 = 0x400;
    const O_NONBLOCK: u32 = 0x800;
    const O_DIRECTORY: u32 = 0x10000;
    const O_NOFOLLOW: u32 = 0x20000;
    let mut bits = match spec.access {
        OpenAccess::Read | OpenAccess::AttributesOnly => O_RDONLY,
        OpenAccess::Write => O_WRONLY,
        OpenAccess::ReadWrite => O_RDWR,
    };
    match spec.create {
        CreateMode::Open => {}
        CreateMode::OpenAlways => bits |= O_CREAT,
        CreateMode::Create => bits |= O_CREAT | O_EXCL,
        CreateMode::CreateAlways | CreateMode::Supersede => bits |= O_CREAT | O_TRUNC,
        CreateMode::Truncate => bits |= O_TRUNC,
    }
    if spec.options.contains(OpenOptions::APPEND) {
        bits |= O_APPEND;
    }
    if spec.options.contains(OpenOptions::NON_BLOCKING) {
        bits |= O_NONBLOCK;
    }
    if spec.options.contains(OpenOptions::DIRECTORY) {
        bits |= O_DIRECTORY;
    }
    if spec.options.contains(OpenOptions::NO_FOLLOW_LEAF) {
        bits |= O_NOFOLLOW;
    }
    bits
}

/// Project the spec's access + options onto the
/// [`OpenObjectFlags`] byte stored on the open file description.
fn open_object_flags_from_spec(kind: VnodeKind, spec: VfsOpenSpec) -> u8 {
    let mut out = 0u8;
    match spec.access {
        OpenAccess::Read => out |= OpenObjectFlags::READABLE,
        OpenAccess::Write => out |= OpenObjectFlags::WRITABLE,
        OpenAccess::ReadWrite => {
            out |= OpenObjectFlags::READABLE | OpenObjectFlags::WRITABLE;
        }
        OpenAccess::AttributesOnly => {}
    }
    if spec.options.contains(OpenOptions::NON_BLOCKING) {
        out |= OpenObjectFlags::O_NONBLOCK;
    }
    if spec.options.contains(OpenOptions::APPEND) {
        out |= OpenObjectFlags::O_APPEND;
    }
    if matches!(kind, VnodeKind::Directory) {
        out |= OpenObjectFlags::O_DIRECTORY;
    }
    out
}

/// Project the spec's requested access onto share-arbitration
/// bits. Delete access is wired when the Win32 delete-on-close /
/// rename-disposition vertical slice starts passing delete intent
/// through `VfsOpenSpec`; read/write arbitration is already live.
fn open_object_access_from_spec(spec: VfsOpenSpec) -> u8 {
    let mut out = 0u8;
    match spec.access {
        OpenAccess::Read => out |= OpenObjectAccess::READ,
        OpenAccess::Write => out |= OpenObjectAccess::WRITE,
        OpenAccess::ReadWrite => {
            out |= OpenObjectAccess::READ | OpenObjectAccess::WRITE;
        }
        OpenAccess::AttributesOnly => {}
    }
    if spec.delete_access {
        out |= OpenObjectAccess::DELETE;
    }
    out
}

/// Enforce Windows-style share access across all personalities.
/// POSIX opens install a permissive share policy, while NT opens
/// can deny future readers / writers / deleters. A new open is
/// legal only if the existing handle's share allows the new access
/// and the new handle's share allows every existing handle's
/// access. That second half is what makes an exclusive NT open
/// fail if a POSIX fd is already live on the vnode.
fn share_policy_allows_open(state: &VfsState, vnode_h: VnodeHandle, spec: VfsOpenSpec) -> bool {
    let requested = open_object_access_from_spec(spec);
    let mut allowed = true;
    state.open_objects.for_each_active(|_, obj| {
        if obj.vnode != vnode_h || obj.refcount == 0 {
            return true;
        }
        if !share_allows_access(obj.share, requested) {
            allowed = false;
            return false;
        }
        if !share_allows_access(spec.share.bits(), obj.access) {
            allowed = false;
            return false;
        }
        true
    });
    allowed
}

fn share_allows_access(share_bits: u32, access: u8) -> bool {
    let share = crate::ops::SharePolicy::from_bits(share_bits);
    if (access & OpenObjectAccess::READ) != 0
        && !share.contains(crate::ops::SharePolicy::SHARE_READ)
    {
        return false;
    }
    if (access & OpenObjectAccess::WRITE) != 0
        && !share.contains(crate::ops::SharePolicy::SHARE_WRITE)
    {
        return false;
    }
    if (access & OpenObjectAccess::DELETE) != 0
        && !share.contains(crate::ops::SharePolicy::SHARE_DELETE)
    {
        return false;
    }
    true
}

/// Whether the open access mode allows writes. Used to reject
/// directory-against-write at the leaf check.
#[inline]
fn open_is_writable(access: OpenAccess) -> bool {
    matches!(access, OpenAccess::Write | OpenAccess::ReadWrite)
}

/// Pick the [`OpenCreateAction`] that surfaced from the create
/// mode + whether the leaf was missing before the operation.
pub(crate) fn pick_open_action(create: CreateMode, leaf_was_missing: bool) -> OpenCreateAction {
    match (create, leaf_was_missing) {
        // POSIX/Windows: leaf created fresh.
        (CreateMode::Create, _) => OpenCreateAction::Created,
        (CreateMode::OpenAlways, true) => OpenCreateAction::Created,
        (CreateMode::OpenAlways, false) => OpenCreateAction::Opened,
        (CreateMode::CreateAlways, true) => OpenCreateAction::Created,
        // Existing leaf overwritten / superseded.
        (CreateMode::CreateAlways, false) => OpenCreateAction::Overwritten,
        (CreateMode::Supersede, true) => OpenCreateAction::Created,
        (CreateMode::Supersede, false) => OpenCreateAction::Superseded,
        (CreateMode::Truncate, _) => OpenCreateAction::Overwritten,
        // Plain open of existing leaf.
        (CreateMode::Open, _) => OpenCreateAction::Opened,
    }
}

/// Emit a personality-aware error reply for the open request.
unsafe fn emit_open_error(
    _state: &mut VfsState,
    _client: ClientHandle,
    reply_lease: ReplyLease,
    reply_intent: OpenReplyIntent,
    err: VfsError,
) {
    unsafe {
        crate::personality::reply::emit_open(reply_lease, reply_intent, Err(err));
    }
}
