// SPDX-License-Identifier: GPL-2.0-only
//
//! Async path-walk state machine.
//!
//! Path resolution that can park on backend RPC boundaries. `stat`,
//! `fstatat`, `lstat`, `access`, `faccessat`, `stat_for_exec`,
//! `opendir`, `readlinkat`, plain path-based `open`, and POSIX
//! `openat` route through this module.
//!
//! ## Structure
//!
//! - [`WalkStepOutcome`] — outcome of one `walk_step` call.
//! - [`walk_step`] — consume one chunk of synchronous progress.
//!   Either advances the cursor by one component, detects a final
//!   state, or parks on a backend RPC.
//! - [`namei_walk_async`] — driver loop. Runs `walk_step` until
//!   one of the terminal outcomes fires.
//! - [`resume_namei_after_lookup`] / [`resume_namei_after_readlink`]
//!   — re-entry after a backend completion router has translated
//!   the wire reply into generic VFS outcomes.
//! - [`splice_symlink_target`] — shift-left buffer surgery for
//!   mid-walk symlink follow.
//! - [`consume_next_component`] — pops the next `/`-separated
//!   component from the front of `remaining_path` and shift-lefts
//!   the tail.

use crate::core::error::{VfsError, VfsResult};
use crate::core::identity::VnodeKey;
use crate::core::namei_common::{
    NAMEI_CREATE, NAMEI_DIRECTORY, NAMEI_FOLLOW, NAMEI_NOFOLLOW_ANY, NAMEI_NOFOLLOW_FINAL,
    NAMEI_SYMLINK_MAX_DEPTH, NAMEI_WANTPARENT, NameiPersonality, is_directory, is_symlink,
    personality_from_flags, walk_dotdot,
};
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::ops::CaseFoldPolicy;
use crate::owner::VfsState;
use crate::owner::pending::{
    PendingOpHandle, WALK_NAME_MAX, WALK_PATH_MAX, WALK_SYMLINK_TARGET_MAX, WalkCursor, WalkPhase,
    WalkPolicy,
};
use crate::owner::resume::{FsResume, NameiTerminal, Resume};
use crate::server::open_object::OpenObjectAnchor;
use crate::server::types::ClientHandle;

// =========================================================================
// NameiAsyncResult — terminal walk output
// =========================================================================

/// Terminal output of a successful async path walk. `vnode_h` is
/// the resolved leaf. It remains `INVALID` for plain
/// `WalkPolicy::StopAtParent`, and carries the raw final vnode for
/// `WalkPolicy::StopAtParentLookup` when the final component exists.
/// `dir_vnode_h` is the parent directory (valid when a parent-stopping
/// policy was active or when `CreateOrOpen` ran with the final
/// component missing), and `last_name[..last_name_len]` is the inline
/// final component bytes (identity-safe across park / resume).
#[derive(Clone, Copy)]
pub(crate) struct NameiAsyncResult {
    pub(crate) vnode_h: VnodeHandle,
    pub(crate) dir_vnode_h: VnodeHandle,
    pub(crate) last_name: [u8; WALK_NAME_MAX],
    pub(crate) last_name_len: u8,
    pub(crate) leaf_anchor: OpenObjectAnchor,
}

impl NameiAsyncResult {
    pub(crate) const fn empty() -> Self {
        NameiAsyncResult {
            vnode_h: VnodeHandle::INVALID,
            dir_vnode_h: VnodeHandle::INVALID,
            last_name: [0u8; WALK_NAME_MAX],
            last_name_len: 0,
            leaf_anchor: OpenObjectAnchor::EMPTY,
        }
    }
}

// =========================================================================
// WalkStepOutcome — single-step result
// =========================================================================

pub(crate) enum WalkStepOutcome {
    /// Walk finished successfully.
    Done(NameiAsyncResult),
    /// Cursor advanced; call `walk_step` again.
    Continue,
    /// Backend RPC was parked. The leaf VOP has reserved a
    /// `PendingOp` with backend-owned correlation state. The
    /// caller of `namei_walk_async` is responsible for stamping
    /// `Resume::Fs(FsResume::NameiStep { .. })` after saving its
    /// reply cap.
    Parked {
        handle: PendingOpHandle,
        phase: WalkPhase,
    },
    /// Terminal error.
    Error(VfsError),
}

// =========================================================================
// Driver loop
// =========================================================================

pub(crate) enum NameiWalkOutcome {
    Done(NameiAsyncResult),
    Parked {
        handle: PendingOpHandle,
        phase: WalkPhase,
    },
    Error(VfsError),
}

/// Variant of `begin_path_walk` that accepts the path as a raw
/// byte slice. Used by personality wire wrappers and by dual-path
/// mutations (rename / link) whose second-stage path bytes live in
/// `state.namei_aux[..]`.
pub(crate) unsafe fn begin_path_walk_from_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    anchor_override: crate::core::identity::VnodeKey,
    path_bytes: &[u8],
    path_len: usize,
    policy: WalkPolicy,
    flags: u32,
    terminal: NameiTerminal,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let root_vkey = match resolve_root_vkey(state) {
            Some(k) => k,
            None => {
                send_walk_error(state, client, reply_lease, VfsError::Io);
                return;
            }
        };
        let path_is_absolute = path_bytes.first().copied() == Some(b'/');
        let cwd_vkey = if path_is_absolute {
            root_vkey
        } else if anchor_override.is_valid() {
            anchor_override
        } else {
            resolve_client_cwd_vkey(state, client).unwrap_or(root_vkey)
        };

        let copied = path_len.min(WALK_PATH_MAX).min(path_bytes.len());
        if copied == 0 {
            send_walk_error(state, client, reply_lease, VfsError::Inval);
            return;
        }
        let mut buf = [0u8; WALK_PATH_MAX];
        buf[..copied].copy_from_slice(&path_bytes[..copied]);

        if state.clients.get(client).is_none() {
            send_walk_error(state, client, reply_lease, VfsError::Io);
            return;
        }
        let cred = state
            .clients
            .get(client)
            .map(|c| c.cred)
            .unwrap_or_else(crate::core::cred::VfsCred::root);
        let flags = match policy {
            WalkPolicy::StopAtParent { .. } | WalkPolicy::StopAtParentLookup { .. } => {
                flags | NAMEI_WANTPARENT
            }
            WalkPolicy::CreateOrOpen { .. } => flags | NAMEI_CREATE,
            _ => flags,
        };
        let cursor = WalkCursor {
            cwd_vkey,
            root_vkey,
            remaining_path: buf,
            remaining_len: copied as u16,
            follow_depth: 0,
            flags,
            policy,
            lookup_anchor: OpenObjectAnchor::EMPTY,
            leaf_anchor: OpenObjectAnchor::EMPTY,
            cred,
        };
        continue_namei_after_apply(state, client, cursor, terminal, reply_lease, Ok(()));
    }
}

/// Resolve the caller's recorded cwd back to a `VnodeKey`. Returns
/// `None` when the client either has no cwd yet or the recorded
/// vnode handle has been recycled (in which case the caller falls
/// back to the namespace root).
unsafe fn resolve_client_cwd_vkey(
    state: &VfsState,
    client: ClientHandle,
) -> Option<crate::core::identity::VnodeKey> {
    let cli = state.clients.get(client)?;
    if cli.cwd_vnode_slot == u32::MAX {
        return None;
    }
    let handle = crate::arena::handle::Handle::<crate::core::vnode::Vnode>::new(
        cli.cwd_vnode_slot,
        cli.cwd_vnode_epoch,
    );
    state.vnodes.get(handle).map(|v| v.key)
}

/// Locate the namespace root's `VnodeKey`. Today vfs hosts a
/// single global namespace; the root is the mount whose
/// `covered_key` is `VnodeKey::NONE`.
unsafe fn resolve_root_vkey(state: &VfsState) -> Option<crate::core::identity::VnodeKey> {
    if let Some(root_mount) = state.mounts.get(state.root_mount) {
        if let Some(vnode) = state.vnodes.get(root_mount.root) {
            if vnode.key.is_valid() {
                return Some(vnode.key);
            }
        }
    }
    let mut found = None;
    state.mounts.for_each_active(|_h, m| {
        if !m.covered_key.is_valid() {
            if let Some(v) = state.vnodes.get(m.root) {
                found = Some(v.key);
                return false;
            }
        }
        true
    });
    found
}

/// Drive the state machine until a terminal outcome fires.
pub(crate) unsafe fn namei_walk_async(
    state: &mut VfsState,
    cursor: &mut WalkCursor,
) -> NameiWalkOutcome {
    loop {
        match unsafe { walk_step(state, cursor) } {
            WalkStepOutcome::Continue => continue,
            WalkStepOutcome::Done(r) => return NameiWalkOutcome::Done(r),
            WalkStepOutcome::Parked { handle, phase } => {
                return NameiWalkOutcome::Parked { handle, phase };
            }
            WalkStepOutcome::Error(e) => return NameiWalkOutcome::Error(e),
        }
    }
}

// =========================================================================
// Single-step worker
// =========================================================================

pub(crate) unsafe fn walk_step(state: &mut VfsState, cursor: &mut WalkCursor) -> WalkStepOutcome {
    // -- Terminal: path exhausted ----------------------------------
    if cursor.remaining_len == 0 {
        let Some(cwd_vnode_h) = resolve_vnode_key(state, cursor.cwd_vkey) else {
            return WalkStepOutcome::Error(VfsError::NoEnt);
        };
        return match cursor.policy {
            WalkPolicy::FinalMustExist => {
                if (cursor.flags & NAMEI_DIRECTORY) != 0 {
                    let Some(vnode) = state.vnodes.get(cwd_vnode_h) else {
                        return WalkStepOutcome::Error(VfsError::Io);
                    };
                    if !is_directory(vnode.kind) {
                        return WalkStepOutcome::Error(VfsError::NotDir);
                    }
                }
                let mut out = NameiAsyncResult::empty();
                out.vnode_h = cwd_vnode_h;
                out.leaf_anchor = cursor.leaf_anchor;
                WalkStepOutcome::Done(out)
            }
            WalkPolicy::CreateOrOpen {
                final_name,
                final_name_len,
                final_missing,
            } => {
                let mut out = NameiAsyncResult::empty();
                if final_missing {
                    out.dir_vnode_h = cwd_vnode_h;
                    out.last_name = final_name;
                    out.last_name_len = final_name_len;
                } else {
                    if (cursor.flags & NAMEI_DIRECTORY) != 0 {
                        let Some(vnode) = state.vnodes.get(cwd_vnode_h) else {
                            return WalkStepOutcome::Error(VfsError::Io);
                        };
                        if !is_directory(vnode.kind) {
                            return WalkStepOutcome::Error(VfsError::NotDir);
                        }
                    }
                    out.vnode_h = cwd_vnode_h;
                    out.leaf_anchor = cursor.leaf_anchor;
                }
                WalkStepOutcome::Done(out)
            }
            WalkPolicy::StopAtParent {
                final_name,
                final_name_len,
            }
            | WalkPolicy::StopAtParentLookup {
                final_name,
                final_name_len,
                ..
            } => {
                let mut out = NameiAsyncResult::empty();
                out.dir_vnode_h = cwd_vnode_h;
                out.last_name = final_name;
                out.last_name_len = final_name_len;
                if let WalkPolicy::StopAtParentLookup { .. } = cursor.policy {
                    if cursor.lookup_anchor.parent_vkey.is_valid() {
                        if let Some(parent_h) =
                            resolve_vnode_key(state, cursor.lookup_anchor.parent_vkey)
                        {
                            out.dir_vnode_h = parent_h;
                        }
                        if cursor.cwd_vkey != cursor.lookup_anchor.parent_vkey {
                            out.vnode_h = cwd_vnode_h;
                        }
                    }
                }
                WalkStepOutcome::Done(out)
            }
        };
    }

    // -- Consume one component -------------------------------------
    let mut name_buf = [0u8; WALK_NAME_MAX];
    let consume = consume_next_component(cursor, &mut name_buf);
    let Some((name_len, is_last)) = consume else {
        return WalkStepOutcome::Continue;
    };

    let Some(cwd_vnode_h) = resolve_vnode_key(state, cursor.cwd_vkey) else {
        return WalkStepOutcome::Error(VfsError::NoEnt);
    };

    // `.` stays on the current vnode.
    if name_len == 1 && name_buf[0] == b'.' {
        if is_last {
            let effective = chase_covering_mounts(state, cwd_vnode_h);
            if let Err(e) = install_cursor_vnode(state, cursor, effective) {
                return WalkStepOutcome::Error(e);
            }
            mark_create_or_open_hit(cursor);
        }
        return WalkStepOutcome::Continue;
    }

    // `..` is partly structural (namespace root / mount root) and
    // partly backend lookup-driven.
    if name_len == 2 && name_buf[0] == b'.' && name_buf[1] == b'.' {
        match unsafe { walk_dotdot(state, cwd_vnode_h, cursor.root_vkey) } {
            Ok(Ready(parent_vnode_h)) => {
                if let Err(e) = install_cursor_vnode(state, cursor, parent_vnode_h) {
                    return WalkStepOutcome::Error(e);
                }
                if is_last {
                    mark_create_or_open_hit(cursor);
                }
                return WalkStepOutcome::Continue;
            }
            Ok(Parked(handle)) => {
                return WalkStepOutcome::Parked {
                    handle,
                    phase: WalkPhase::Lookup,
                };
            }
            Err(e) => return WalkStepOutcome::Error(e),
        }
    }

    let Some(cwd_vnode) = state.vnodes.get(cwd_vnode_h) else {
        return WalkStepOutcome::Error(VfsError::Io);
    };
    if !is_directory(cwd_vnode.kind) {
        return WalkStepOutcome::Error(VfsError::NotDir);
    }
    let lookup_dir_vnode_h = chase_covering_mounts(state, cwd_vnode_h);
    if lookup_dir_vnode_h != cwd_vnode_h {
        if let Err(e) = install_cursor_vnode(state, cursor, lookup_dir_vnode_h) {
            return WalkStepOutcome::Error(e);
        }
    }
    if is_last {
        if let WalkPolicy::StopAtParent { .. } = cursor.policy {
            let mut out = NameiAsyncResult::empty();
            out.dir_vnode_h = lookup_dir_vnode_h;
            out.last_name[..name_len as usize].copy_from_slice(&name_buf[..name_len as usize]);
            out.last_name_len = name_len;
            return WalkStepOutcome::Done(out);
        }
        if let WalkPolicy::StopAtParentLookup { missing_ok, .. } = cursor.policy {
            let mut final_name = [0u8; WALK_NAME_MAX];
            final_name[..name_len as usize].copy_from_slice(&name_buf[..name_len as usize]);
            cursor.policy = WalkPolicy::StopAtParentLookup {
                final_name,
                final_name_len: name_len,
                missing_ok,
            };
        }
        remember_create_or_open_final_name(cursor, &name_buf, name_len);
    }
    let Some(lookup_parent_vkey) = state.vnodes.get(lookup_dir_vnode_h).map(|v| v.key) else {
        return WalkStepOutcome::Error(VfsError::Io);
    };
    cursor.lookup_anchor = anchor_from_component(lookup_parent_vkey, &name_buf, name_len);

    // -- VOP lookup -------------------------------------------------
    let Some(mut ctx) =
        (unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, lookup_dir_vnode_h) })
    else {
        return WalkStepOutcome::Error(VfsError::Io);
    };
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return WalkStepOutcome::Error(VfsError::Io);
    }
    let case_fold = unsafe {
        match personality_from_flags(cursor.flags) {
            NameiPersonality::Win32 => CaseFoldPolicy::InsensitivePreserving,
            NameiPersonality::Posix if !ctx.mount.is_null() => (*ctx.mount).case_fold,
            NameiPersonality::Posix => CaseFoldPolicy::Sensitive,
        }
    };
    let lookup_fn = unsafe {
        if matches!(case_fold, CaseFoldPolicy::InsensitivePreserving) {
            (*ops).meta.lookup_ci
        } else {
            (*ops).meta.lookup
        }
    };
    let lookup_result = unsafe { lookup_fn(&mut ctx, name_buf.as_ptr(), name_len) };

    match lookup_result {
        Ok(Ready(child_vnode_h)) if child_vnode_h.is_valid() => {
            if is_last {
                if let WalkPolicy::StopAtParentLookup {
                    final_name,
                    final_name_len,
                    ..
                } = cursor.policy
                {
                    if let Some(v) = state.vnodes.get(child_vnode_h) {
                        state.install_resolve_cache(v.key, child_vnode_h);
                    }
                    let mut out = NameiAsyncResult::empty();
                    out.vnode_h = child_vnode_h;
                    out.dir_vnode_h = lookup_dir_vnode_h;
                    out.last_name = final_name;
                    out.last_name_len = final_name_len;
                    return WalkStepOutcome::Done(out);
                }
            }
            let effective = chase_covering_mounts(state, child_vnode_h);
            let Some((child_key, child_kind)) =
                state.vnodes.get(effective).map(|v| (v.key, v.kind))
            else {
                return WalkStepOutcome::Error(VfsError::Io);
            };
            state.install_resolve_cache(child_key, effective);

            let should_follow = is_symlink(child_kind)
                && should_follow_symlink(cursor.flags, is_last)
                && !mount_nosymfollow_for_vnode(state, effective);

            if should_follow {
                let restart_vnode_h = lookup_dir_vnode_h;
                if let Err(e) = install_cursor_vnode(state, cursor, restart_vnode_h) {
                    return WalkStepOutcome::Error(e);
                }
                match unsafe { issue_readlink(state, effective, &cursor.cred) } {
                    Ok(Ready((target, target_len))) => {
                        if let Err(e) = install_symlink_restart(
                            state,
                            cursor,
                            restart_vnode_h,
                            &target[..target_len],
                        ) {
                            return WalkStepOutcome::Error(e);
                        }
                        // SAFETY: the inline readlink target slice is valid
                        // for this synchronous restart update.
                        if let Err(e) =
                            unsafe { apply_readlink_completion(cursor, Ok(&target[..target_len])) }
                        {
                            return WalkStepOutcome::Error(e);
                        }
                        WalkStepOutcome::Continue
                    }
                    Ok(Parked(handle)) => WalkStepOutcome::Parked {
                        handle,
                        phase: WalkPhase::Readlink,
                    },
                    Err(e) => WalkStepOutcome::Error(e),
                }
            } else {
                cursor.cwd_vkey = child_key;
                if is_last {
                    cursor.leaf_anchor = cursor.lookup_anchor;
                    mark_create_or_open_hit(cursor);
                }
                WalkStepOutcome::Continue
            }
        }
        Ok(Ready(_invalid)) => {
            if is_last {
                if let WalkPolicy::CreateOrOpen {
                    final_name,
                    final_name_len,
                    ..
                } = cursor.policy
                {
                    cursor.policy = WalkPolicy::CreateOrOpen {
                        final_name,
                        final_name_len,
                        final_missing: true,
                    };
                    return WalkStepOutcome::Continue;
                }
                if let WalkPolicy::StopAtParent {
                    final_name,
                    final_name_len,
                } = cursor.policy
                {
                    let mut out = NameiAsyncResult::empty();
                    out.dir_vnode_h = lookup_dir_vnode_h;
                    out.last_name = final_name;
                    out.last_name_len = final_name_len;
                    return WalkStepOutcome::Done(out);
                }
                if let WalkPolicy::StopAtParentLookup {
                    final_name,
                    final_name_len,
                    missing_ok,
                } = cursor.policy
                {
                    if missing_ok {
                        let mut out = NameiAsyncResult::empty();
                        out.dir_vnode_h = lookup_dir_vnode_h;
                        out.last_name = final_name;
                        out.last_name_len = final_name_len;
                        return WalkStepOutcome::Done(out);
                    }
                }
            }
            WalkStepOutcome::Error(VfsError::NoEnt)
        }
        Ok(Parked(handle)) => WalkStepOutcome::Parked {
            handle,
            phase: WalkPhase::Lookup,
        },
        Err(e) => WalkStepOutcome::Error(e),
    }
}

/// Follow the `covered_by` chain starting at `vnode_h`. Returns
/// the input unchanged when no covering mount is present.
fn chase_covering_mounts(state: &VfsState, vnode_h: VnodeHandle) -> VnodeHandle {
    crate::core::namei_common::cross_covered(state, vnode_h)
}

// =========================================================================
// Resume entries
// =========================================================================

pub(crate) unsafe fn resume_namei_after_lookup(
    state: &mut VfsState,
    client: ClientHandle,
    mut cursor: WalkCursor,
    terminal: NameiTerminal,
    reply_lease: trona_server::ReplyLease,
    lookup: VfsResult<Option<VnodeHandle>>,
) {
    unsafe {
        let apply_result = apply_lookup_completion(state, &mut cursor, lookup);
        continue_namei_after_apply(state, client, cursor, terminal, reply_lease, apply_result);
    }
}

pub(crate) unsafe fn resume_namei_after_readlink(
    state: &mut VfsState,
    client: ClientHandle,
    mut cursor: WalkCursor,
    terminal: NameiTerminal,
    reply_lease: trona_server::ReplyLease,
    target: VfsResult<&[u8]>,
) {
    unsafe {
        let apply_result = match target {
            Ok(bytes) => {
                let parent_vnode_h = match resolve_cursor_cwd(state, &cursor) {
                    Some(h) => h,
                    None => {
                        continue_namei_after_apply(
                            state,
                            client,
                            cursor,
                            terminal,
                            reply_lease,
                            Err(VfsError::Io),
                        );
                        return;
                    }
                };
                if let Err(e) = install_symlink_restart(state, &mut cursor, parent_vnode_h, bytes) {
                    Err(e)
                } else {
                    apply_readlink_completion(&mut cursor, Ok(bytes))
                }
            }
            Err(e) => Err(e),
        };
        continue_namei_after_apply(state, client, cursor, terminal, reply_lease, apply_result);
    }
}

unsafe fn continue_namei_after_apply(
    state: &mut VfsState,
    client: ClientHandle,
    mut cursor: WalkCursor,
    terminal: NameiTerminal,
    reply_lease: trona_server::ReplyLease,
    apply_result: VfsResult<()>,
) {
    unsafe {
        if state.clients.get(client).is_none() {
            return;
        }
        if let Err(e) = apply_result {
            send_walk_error(state, client, reply_lease, e);
            return;
        }
        match namei_walk_async(state, &mut cursor) {
            NameiWalkOutcome::Done(result) => match terminal {
                // ===== Personality-bipolar terminals =====
                NameiTerminal::Open { spec, reply } => {
                    crate::ops::open::resume_open_walk_result(
                        state,
                        client,
                        &result,
                        spec,
                        reply,
                        reply_lease,
                    );
                }
                NameiTerminal::GetAttr { reply } => {
                    crate::ops::attr::resume_getattr_walk_result(
                        state,
                        client,
                        &result,
                        reply,
                        reply_lease,
                    );
                }
                NameiTerminal::SetAttr { kind, reply } => {
                    crate::ops::set_attr::resume_setattr_walk_result(
                        state,
                        client,
                        &result,
                        kind,
                        reply,
                        reply_lease,
                    );
                }
                NameiTerminal::Access { mode, reply } => {
                    crate::ops::access::resume_access_walk_result(
                        state,
                        client,
                        &result,
                        mode,
                        reply,
                        reply_lease,
                    );
                }
                NameiTerminal::UnlinkLeaf { kind, reply } => {
                    crate::ops::unlink_leaf::resume_unlink_walk_result(
                        state,
                        client,
                        &result,
                        kind,
                        reply,
                        reply_lease,
                    );
                }
                NameiTerminal::RenameOrLink {
                    kind,
                    aux_handle,
                    reply,
                } => {
                    crate::ops::rename_link::dispatch_phase(
                        state,
                        client,
                        &result,
                        kind,
                        aux_handle,
                        reply,
                        reply_lease,
                    );
                }
                NameiTerminal::CreateLeaf {
                    kind,
                    aux_handle,
                    reply,
                } => {
                    crate::ops::create_leaf::resume_create_leaf_walk_result(
                        state,
                        client,
                        &result,
                        kind,
                        aux_handle,
                        reply,
                        reply_lease,
                    );
                }
                // ===== POSIX-only terminals =====
                NameiTerminal::Readlink
                | NameiTerminal::Chdir { .. }
                | NameiTerminal::CanonPath { .. }
                | NameiTerminal::StatForExec
                | NameiTerminal::OpenForExec => {
                    crate::personality::namei_terminal::dispatch_posix_terminal(
                        state,
                        client,
                        &result,
                        terminal,
                        reply_lease,
                    );
                }
            },
            NameiWalkOutcome::Parked { handle, phase } => {
                if matches!(phase, WalkPhase::Readlink) {
                    let reply_lease = match crate::owner::init_rpc::attach_namei_readlink_if_init(
                        state,
                        handle,
                        client,
                        cursor,
                        terminal,
                        reply_lease,
                    ) {
                        Ok(()) => return,
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
                        Resume::Fs(FsResume::NameiStep {
                            client,
                            cursor,
                            phase,
                            terminal,
                        }),
                    ) {
                        send_walk_error(state, client, reply_lease, VfsError::Io);
                    }
                    return;
                }
                let badge = state
                    .clients
                    .get(client)
                    .map(|c| c.client_badge)
                    .unwrap_or(0);
                if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                    handle,
                    badge,
                    Some(reply_lease),
                    Resume::Fs(FsResume::NameiStep {
                        client,
                        cursor,
                        phase,
                        terminal,
                    }),
                ) {
                    send_walk_error(state, client, reply_lease, VfsError::Io);
                }
            }
            NameiWalkOutcome::Error(e) => {
                send_walk_error(state, client, reply_lease, e);
            }
        }
    }
}

// =========================================================================
// Reply application
// =========================================================================

unsafe fn apply_lookup_completion(
    state: &mut VfsState,
    cursor: &mut WalkCursor,
    lookup: VfsResult<Option<VnodeHandle>>,
) -> VfsResult<()> {
    let child_vnode_h = match lookup? {
        Some(h) => h,
        None => {
            if cursor.remaining_len == 0 {
                if let WalkPolicy::StopAtParentLookup { missing_ok, .. } = cursor.policy {
                    if missing_ok {
                        return Ok(());
                    }
                    return Err(VfsError::NoEnt);
                }
                if let WalkPolicy::CreateOrOpen {
                    final_name,
                    final_name_len,
                    ..
                } = cursor.policy
                {
                    cursor.policy = WalkPolicy::CreateOrOpen {
                        final_name,
                        final_name_len,
                        final_missing: true,
                    };
                    return Ok(());
                }
            }
            return Err(VfsError::NoEnt);
        }
    };

    if cursor.remaining_len == 0 {
        if let WalkPolicy::StopAtParentLookup { .. } = cursor.policy {
            let child_key = state
                .vnodes
                .get(child_vnode_h)
                .map(|v| v.key)
                .ok_or(VfsError::Io)?;
            state.install_resolve_cache(child_key, child_vnode_h);
            cursor.cwd_vkey = child_key;
            return Ok(());
        }
    }

    let effective = chase_covering_mounts(state, child_vnode_h);
    let child_key = state
        .vnodes
        .get(effective)
        .map(|v| v.key)
        .ok_or(VfsError::Io)?;
    state.install_resolve_cache(child_key, effective);
    cursor.cwd_vkey = child_key;
    if cursor.remaining_len == 0 {
        cursor.leaf_anchor = cursor.lookup_anchor;
        mark_create_or_open_hit(cursor);
    }

    Ok(())
}

unsafe fn apply_readlink_completion(
    cursor: &mut WalkCursor,
    target: VfsResult<&[u8]>,
) -> VfsResult<()> {
    let target = target?;
    if cursor.follow_depth as u32 >= NAMEI_SYMLINK_MAX_DEPTH {
        return Err(VfsError::Loop);
    }
    splice_symlink_target(cursor, target, target.len())
}

// =========================================================================
// Cursor mutation helpers
// =========================================================================

const PATH_SEP: u8 = b'/';

/// Pop the next component from the front of the cursor's
/// remaining path (Approach Y shift-left).
pub(crate) fn consume_next_component(
    cursor: &mut WalkCursor,
    out_name: &mut [u8],
) -> Option<(u8, bool)> {
    let len = cursor.remaining_len as usize;
    if len == 0 {
        return None;
    }
    let buf = &mut cursor.remaining_path[..len];

    let mut start = 0usize;
    while start < len && buf[start] == PATH_SEP {
        start += 1;
    }
    if start == len {
        cursor.remaining_len = 0;
        return None;
    }

    let mut end = start;
    while end < len && buf[end] != PATH_SEP {
        end += 1;
    }

    let name_len = end - start;
    if name_len > out_name.len() || name_len > WALK_NAME_MAX {
        return None;
    }

    out_name[..name_len].copy_from_slice(&buf[start..end]);

    let mut tail_start = end;
    if tail_start < len && buf[tail_start] == PATH_SEP {
        tail_start += 1;
    }

    let is_last = tail_start >= len;
    let tail_len = len - tail_start;

    cursor
        .remaining_path
        .copy_within(tail_start..tail_start + tail_len, 0);
    cursor.remaining_len = tail_len as u16;
    for i in tail_len..len {
        cursor.remaining_path[i] = 0;
    }

    Some((name_len as u8, is_last))
}

/// Splice a symlink target into the front of the cursor's
/// remaining path (Approach Y: shift right + write at front).
pub(crate) fn splice_symlink_target(
    cursor: &mut WalkCursor,
    target: &[u8],
    target_len: usize,
) -> VfsResult<()> {
    if target_len > target.len() {
        return Err(VfsError::Inval);
    }
    let old_len = cursor.remaining_len as usize;
    let new_len = target_len
        .checked_add(1)
        .and_then(|n| n.checked_add(old_len))
        .ok_or(VfsError::NameTooLong)?;
    if new_len > WALK_PATH_MAX {
        return Err(VfsError::NameTooLong);
    }

    if old_len > 0 {
        cursor
            .remaining_path
            .copy_within(0..old_len, target_len + 1);
    }
    cursor.remaining_path[..target_len].copy_from_slice(&target[..target_len]);
    cursor.remaining_path[target_len] = PATH_SEP;
    cursor.remaining_len = new_len as u16;
    cursor.follow_depth = cursor.follow_depth.saturating_add(1);
    Ok(())
}

#[inline]
fn mark_create_or_open_hit(cursor: &mut WalkCursor) {
    if let WalkPolicy::CreateOrOpen {
        final_name,
        final_name_len,
        ..
    } = cursor.policy
    {
        cursor.policy = WalkPolicy::CreateOrOpen {
            final_name,
            final_name_len,
            final_missing: false,
        };
    }
}

#[inline]
fn should_follow_symlink(flags: u32, is_last: bool) -> bool {
    if is_last {
        (flags & NAMEI_FOLLOW) != 0
            && (flags & NAMEI_NOFOLLOW_ANY) == 0
            && (flags & NAMEI_NOFOLLOW_FINAL) == 0
    } else {
        (flags & NAMEI_NOFOLLOW_ANY) == 0
    }
}

/// The new vfs Mount struct carries no per-mount flags field;
/// the `nosymfollow` mount option is reserved for future
/// personality extensions and currently always allows symlink
/// follow at the mount-point boundary.
#[inline]
fn mount_nosymfollow_for_vnode(_state: &VfsState, _vnode_h: VnodeHandle) -> bool {
    false
}

fn install_cursor_vnode(
    state: &mut VfsState,
    cursor: &mut WalkCursor,
    vnode_h: VnodeHandle,
) -> VfsResult<()> {
    let key = state
        .vnodes
        .get(vnode_h)
        .map(|v| v.key)
        .ok_or(VfsError::Io)?;
    state.install_resolve_cache(key, vnode_h);
    cursor.cwd_vkey = key;
    Ok(())
}

fn install_symlink_restart(
    state: &mut VfsState,
    cursor: &mut WalkCursor,
    parent_vnode_h: VnodeHandle,
    target: &[u8],
) -> VfsResult<()> {
    let restart_vnode_h = if target.first().copied() == Some(PATH_SEP) {
        resolve_vnode_key(state, cursor.root_vkey).ok_or(VfsError::Io)?
    } else {
        parent_vnode_h
    };
    install_cursor_vnode(state, cursor, restart_vnode_h)
}

fn anchor_from_component(
    parent_vkey: VnodeKey,
    name: &[u8; WALK_NAME_MAX],
    name_len: u8,
) -> OpenObjectAnchor {
    let mut anchor = OpenObjectAnchor::EMPTY;
    if parent_vkey.is_valid() && name_len != 0 {
        anchor.parent_vkey = parent_vkey;
        anchor.name_len = name_len;
        anchor.name[..name_len as usize].copy_from_slice(&name[..name_len as usize]);
    }
    anchor
}

fn remember_create_or_open_final_name(
    cursor: &mut WalkCursor,
    name: &[u8; WALK_NAME_MAX],
    name_len: u8,
) {
    if let WalkPolicy::CreateOrOpen { .. } = cursor.policy {
        let mut final_name = [0u8; WALK_NAME_MAX];
        final_name[..name_len as usize].copy_from_slice(&name[..name_len as usize]);
        cursor.policy = WalkPolicy::CreateOrOpen {
            final_name,
            final_name_len: name_len,
            final_missing: false,
        };
    }
}

unsafe fn issue_readlink(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
    cred: &crate::core::cred::VfsCred,
) -> VfsResult<crate::core::outcome::VopControl<([u8; WALK_SYMLINK_TARGET_MAX], usize)>> {
    unsafe {
        let Some(mut ctx) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            return Err(VfsError::Io);
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            return Err(VfsError::Io);
        }
        let mut buf = [0u8; WALK_SYMLINK_TARGET_MAX];
        match ((*ops).meta.readlink)(&mut ctx, buf.as_mut_ptr(), buf.len(), &raw const *cred) {
            Ok(Ready(len)) => {
                if len == 0 || len > buf.len() {
                    Err(VfsError::Io)
                } else {
                    Ok(Ready((buf, len)))
                }
            }
            Ok(Parked(handle)) => Ok(Parked(handle)),
            Err(e) => Err(e),
        }
    }
}

// =========================================================================
// Private helpers
// =========================================================================

unsafe fn send_walk_error(
    state: &VfsState,
    client: crate::server::types::ClientHandle,
    reply_lease: trona_server::ReplyLease,
    err: VfsError,
) {
    let personality = state
        .clients
        .get(client)
        .map(|c| c.personality)
        .unwrap_or(crate::personality::Personality::Posix);
    crate::personality::wire::send_reply_err_typed(personality, reply_lease, err)
}

pub(crate) fn resolve_cursor_cwd(state: &VfsState, cursor: &WalkCursor) -> Option<VnodeHandle> {
    resolve_vnode_key(state, cursor.cwd_vkey)
}

fn resolve_vnode_key(state: &VfsState, key: VnodeKey) -> Option<VnodeHandle> {
    if !key.is_valid() {
        return None;
    }
    if let Some(vnode_h) = state.lookup_resolve_cache(key) {
        return Some(vnode_h);
    }
    let mut found = None;
    state.vnodes.for_each_active(|vnode_h, vnode| {
        if vnode.key == key {
            found = Some(vnode_h);
            false
        } else {
            true
        }
    });
    found
}
