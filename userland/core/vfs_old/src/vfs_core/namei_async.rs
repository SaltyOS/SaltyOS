// SPDX-License-Identifier: GPL-2.0-only
//! Async path-walk state machine.
//!
//! Path resolution that can park on backend RPC boundaries. `stat`,
//! `fstatat`, `lstat`, `access`, `faccessat`, `stat_for_exec`,
//! `opendir`, `readlinkat`, plain path-based `open`, and POSIX
//! `openat` route through this module. The remaining path-walk users
//! are mostly mutating `*at()` operations plus a few personality-local
//! helpers (socket path resolution, shm, cwd) that still use the
//! synchronous walker in `namei_common.rs`.
//!
//! Design contract — see the "Async path-walk" docblock at the top
//! of `namei_common.rs` for the six decisions that govern this
//! module (state machine shape, ESTALE semantics, cancellation,
//! symlink target buffer, partial-apply safety, no compound RPC).
//!
//! ## Structure
//!
//! - [`WalkStepOutcome`] — the outcome of one `walk_step` call.
//! - [`walk_step`] — consume exactly one chunk of synchronous
//!   progress. Either advances the cursor by one component, or
//!   detects a final state (Done / Error), or parks on a backend
//!   RPC (Parked).
//! - [`namei_walk_async`] — driver loop. Runs `walk_step` until
//!   one of the terminal outcomes fires.
//! - [`resume_namei_after_lookup`] / [`resume_namei_after_readlink`] /
//!   [`resume_namei_after_cross_mount_vget`] — re-entry after a
//!   backend-specific completion router has translated the wire
//!   reply into generic VFS outcomes.
//! - [`splice_symlink_target`] — shift-left path buffer surgery for
//!   mid-walk symlink follow (Approach Y).
//! - [`consume_next_component`] — pops the next `/`-separated
//!   component from the front of `remaining_path` and shift-lefts
//!   the tail.
//!
//! ## Live resume paths
//!
//! - `apply_lookup_completion` — mid-walk component resolution from a
//!   translated child-vnode completion.
//! - `apply_final_op_completion` — read-only terminal ack.
//! - `apply_readlink_completion` — intermediate symlink follow via
//!   `splice_symlink_target` (Approach Y path buffer surgery).
//! - `apply_cross_mount_vget_completion` — installs a covering mount's
//!   root vnode after backend materialisation.

use trona_kernel::core_types::TronaMsg;

use crate::owner::VfsState;
use crate::owner::pending::{
    PendingOpHandle, WALK_NAME_MAX, WALK_PATH_MAX, WalkCursor, WalkPhase, WalkPolicy,
};
use crate::owner::resume::{
    Resume,
    fs::{FsResume, NameiTerminal},
};
use crate::server::types::ClientHandle;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::identity::VnodeKey;
use crate::vfs_core::namei_common::{
    NAMEI_DIRECTORY, NAMEI_FOLLOW, NAMEI_NOFOLLOW_ANY, NAMEI_NOFOLLOW_FINAL,
    NAMEI_SYMLINK_MAX_DEPTH,
};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::{VN_ROOT, VT_DIR, VT_LNK, VnodeHandle};

// =========================================================================
// NameiAsyncResult — terminal walk output
// =========================================================================

/// Terminal output of a successful async path walk.
///
/// Distinct from `namei_common::NameiResult` because the sync form
/// carries a `*const u8` pointer into the caller's path buffer,
/// which cannot cross park/resume boundaries. The async form
/// inlines the final component name bytes so resume handlers can
/// materialise the result without re-reading the original path.
#[derive(Clone, Copy)]
pub(crate) struct NameiAsyncResult {
    /// Resolved target vnode handle. `VnodeHandle::INVALID` when
    /// `WalkPolicy::StopAtParent` applied and the final component
    /// does not exist — in that case `dvp` is the parent.
    pub(crate) vp: VnodeHandle,
    /// Parent directory vnode handle (valid when
    /// `WalkPolicy::StopAtParent` was active, else
    /// `VnodeHandle::INVALID`).
    pub(crate) dvp: VnodeHandle,
    /// Final component bytes (inline, identity-safe across park).
    pub(crate) last_name: [u8; WALK_NAME_MAX],
    pub(crate) last_name_len: u8,
}

impl NameiAsyncResult {
    pub(crate) const fn empty() -> Self {
        NameiAsyncResult {
            vp: VnodeHandle::INVALID,
            dvp: VnodeHandle::INVALID,
            last_name: [0u8; WALK_NAME_MAX],
            last_name_len: 0,
        }
    }
}

// =========================================================================
// WalkStepOutcome — single-step result
// =========================================================================

/// Result of one `walk_step` invocation.
///
/// The driver loop (`namei_walk_async`) dispatches on this enum.
/// `Continue` means the step advanced the cursor synchronously —
/// the loop calls `walk_step` again. `Done` / `Error` / `Parked`
/// are terminal for the current driver invocation; the caller
/// (fileops or resume handler) decides what to do next.
///
/// `Parked` returns the leaf-reserved `PendingOpHandle` *without*
/// stamping a `Resume`: the fileops caller above the driver owns the
/// reply-slot lifecycle (via `alloc_reply_slot` + `cnode_save_caller`)
/// and therefore stamps the `NameiStep` continuation after catching
/// `NameiWalkOutcome::Parked` out of `namei_walk_async`. This mirrors
/// the leaf pattern used by
/// `fileops::stat::fill_stat_reply_handle` and keeps the sync
/// success/error reply path unchanged.
///
/// `Parked` carries `phase` so the fileops caller can stamp the
/// correct `WalkPhase` without inferring it from the VOP that
/// returned `Parked`.
pub(crate) enum WalkStepOutcome {
    /// Walk finished successfully. Driver returns `Ok(result)`.
    Done(NameiAsyncResult),
    /// Cursor advanced; call `walk_step` again.
    Continue,
    /// Backend RPC was parked. The leaf VOP has reserved a
    /// `PendingOp` with backend-owned correlation state. The caller
    /// of `namei_walk_async` is responsible for stamping
    /// `Resume::Fs(FsResume::NameiStep { .. })` with the client,
    /// saved reply slot, and terminal action before returning to the
    /// owner loop, using `phase` as the authoritative park kind.
    Parked {
        handle: PendingOpHandle,
        phase: WalkPhase,
    },
    /// Terminal error (NotFound, Loop, Perm, …). Driver returns
    /// `Err(err)`.
    Error(VfsError),
}

// =========================================================================
// Driver loop
// =========================================================================

/// Drive the state machine until a terminal outcome fires.
///
/// Terminal outcome of [`namei_walk_async`]. Shares the shape of
/// [`WalkStepOutcome`] minus the `Continue` variant (the driver
/// loop consumes `Continue` internally). Exposes `Parked.phase` so
/// fileops callers can stamp the correct `WalkPhase` when
/// converting `NameiWalkOutcome::Parked` into `Resume::Fs`.
pub(crate) enum NameiWalkOutcome {
    Done(NameiAsyncResult),
    Parked {
        handle: PendingOpHandle,
        phase: WalkPhase,
    },
    Error(VfsError),
}

/// On `Done(result)` the caller formats a client reply. On
/// `Parked { handle, phase }` the caller unwinds to the owner
/// loop; when the reply eventually arrives,
/// `dispatch_pending_reply` routes it to one of the
/// `resume_namei_after_*` helpers which re-enter this driver with the
/// updated cursor. On
/// `Error(e)` the caller emits a synchronous error reply.
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

/// Advance the walk by one synchronous chunk, or park.
///
/// Three outcome classes:
///
/// - `remaining_len == 0` — walk exhausted. Returns `Done`. For
///   `Continue` / `FinalMustExist` the result carries the live
///   `VnodeHandle` for `cursor.cwd_vkey` (re-resolved via the
///   resolve cache) and `dvp = INVALID`. For `StopAtParent` the
///   result carries `dvp = current cwd` and `last_name` from the
///   policy.
///
/// - Non-empty path — pop one component, build a `OwnerVopCtx` on
///   the current cwd, call `meta.lookup`. Three sub-outcomes:
///
///   1. `Ok(child_vh)` with a valid handle — chase the child's
///      covering-mount chain to handle mount transparency (e.g.
///      `/dev`), then advance `cursor.cwd_vkey` to the resulting
///      vnode's identity. Returns `Continue`.
///   2. `Ok(VnodeHandle::INVALID)` — clean ENOENT. If `is_last`
///      and the policy tolerates a missing final component
///      (`StopAtParent`), returns `Done` with `dvp = current cwd`
///      and `last_name` from the policy. Otherwise returns
///      `Error(NotFound)`.
///   3. `Ok(VopOutcome::Parked(h))` — the backend parked the lookup.
///      Returns `Parked(h)` without stamping; the fileops caller
///      (above `namei_walk_async`) stamps `Resume::Fs(FsResume::NameiStep { .. })`
///      after saving its reply cap. See the `WalkStepOutcome::
///      Parked` docblock for the reasoning.
///
/// # Safety
///
/// Must be called from the owner loop's single-threaded VOP
/// dispatch context. Trampoline setup via `mount_ctl::
/// build_vop_context` is the established pattern; this function
/// pairs `build_vop_context` with `clear_trampolines` on every
/// exit (success and error alike).
pub(crate) unsafe fn walk_step(state: &mut VfsState, cursor: &mut WalkCursor) -> WalkStepOutcome {
    // -- Terminal: path exhausted ----------------------------------
    if cursor.remaining_len == 0 {
        let Some(cwd_vh) = resolve_vnode_key(state, cursor.cwd_vkey) else {
            // Walk started on (or resumed at) a `VnodeKey` that no
            // longer resolves. Treat as ESTALE — the client will see
            // `TRONA_NOT_FOUND` which is the closest stable error
            // for "the name was fine when you asked but the target
            // disappeared between park and resume". The sync walker
            // reports `Io` in the same shape of failure, but
            // `NotFound` is the better shape for the async path
            // where cache-level eviction is expected.
            return WalkStepOutcome::Error(VfsError::NotFound);
        };
        return match cursor.policy {
            WalkPolicy::Continue | WalkPolicy::FinalMustExist => {
                if (cursor.flags & NAMEI_DIRECTORY) != 0 {
                    let Some(vnode) = state.vnodes.get(cwd_vh) else {
                        return WalkStepOutcome::Error(VfsError::Io);
                    };
                    if vnode.vtype != VT_DIR {
                        return WalkStepOutcome::Error(VfsError::NotDir);
                    }
                }
                let mut out = NameiAsyncResult::empty();
                out.vp = cwd_vh;
                WalkStepOutcome::Done(out)
            }
            WalkPolicy::CreateOrOpen {
                final_name,
                final_name_len,
                final_missing,
            } => {
                let mut out = NameiAsyncResult::empty();
                if final_missing {
                    out.dvp = cwd_vh;
                    out.last_name = final_name;
                    out.last_name_len = final_name_len;
                } else {
                    if (cursor.flags & NAMEI_DIRECTORY) != 0 {
                        let Some(vnode) = state.vnodes.get(cwd_vh) else {
                            return WalkStepOutcome::Error(VfsError::Io);
                        };
                        if vnode.vtype != VT_DIR {
                            return WalkStepOutcome::Error(VfsError::NotDir);
                        }
                    }
                    out.vp = cwd_vh;
                }
                WalkStepOutcome::Done(out)
            }
            WalkPolicy::StopAtParent {
                final_name,
                final_name_len,
            } => {
                let mut out = NameiAsyncResult::empty();
                out.dvp = cwd_vh;
                out.last_name = final_name;
                out.last_name_len = final_name_len;
                WalkStepOutcome::Done(out)
            }
        };
    }

    // -- Consume one component -------------------------------------
    let mut name_buf = [0u8; WALK_NAME_MAX];
    let consume = consume_next_component(cursor, &mut name_buf);
    let Some((name_len, is_last)) = consume else {
        // Path was all separators or empty after consumption.
        // `consume_next_component` has already zeroed `remaining_len`
        // in the all-separator case, so the next driver iteration
        // will hit the terminal branch above. Return `Continue` to
        // keep the driver loop spinning; no lookup required.
        return WalkStepOutcome::Continue;
    };

    // -- Resolve current cwd to a live handle ----------------------
    let Some(cwd_vh) = resolve_vnode_key(state, cursor.cwd_vkey) else {
        return WalkStepOutcome::Error(VfsError::NotFound);
    };

    // `.` stays on the current vnode. Only the final component
    // needs the mount-covering transfer to match sync POSIX namei.
    if name_len == 1 && name_buf[0] == b'.' {
        if is_last {
            let effective = chase_covering_mounts(state, cwd_vh);
            if let Err(e) = install_cursor_vnode(state, cursor, effective) {
                return WalkStepOutcome::Error(e);
            }
            mark_create_or_open_hit(cursor);
        }
        return WalkStepOutcome::Continue;
    }

    // `..` is partly structural (namespace root / mount root) and
    // partly backend lookup-driven. The helper below returns either
    // the resolved parent vnode or a parked lookup handle.
    if name_len == 2 && name_buf[0] == b'.' && name_buf[1] == b'.' {
        match unsafe { lookup_dotdot(state, cwd_vh, cursor.root_vkey) } {
            Ok(Ready(parent_vh)) => {
                if let Err(e) = install_cursor_vnode(state, cursor, parent_vh) {
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

    let Some(cwd_vnode) = state.vnodes.get(cwd_vh) else {
        return WalkStepOutcome::Error(VfsError::Io);
    };
    if cwd_vnode.vtype != VT_DIR {
        return WalkStepOutcome::Error(VfsError::NotDir);
    }
    let lookup_dir_vh = chase_covering_mounts(state, cwd_vh);
    if lookup_dir_vh != cwd_vh {
        if let Err(e) = install_cursor_vnode(state, cursor, lookup_dir_vh) {
            return WalkStepOutcome::Error(e);
        }
    }

    // -- VOP lookup -------------------------------------------------
    // SAFETY: owner-loop single-threaded VOP dispatch. Pairs with
    // `clear_trampolines()` on every exit below.
    let Some(mut ctx) =
        (unsafe { crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, lookup_dir_vh) })
    else {
        return WalkStepOutcome::Error(VfsError::Io);
    };
    // SAFETY: `build_vop_context` returns a context whose `vnode`
    // pointer was read from the live arena for `lookup_dir_vh`.
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return WalkStepOutcome::Error(VfsError::Io);
    }
    // SAFETY: `ops` is the vnode's static vtable pointer (checked
    // non-null above); `meta.lookup` is a function pointer with
    // the documented `OwnerVopCtx` + name/len contract.
    let lookup_result = unsafe { ((*ops).meta.lookup)(&mut ctx, name_buf.as_ptr(), name_len) };

    match lookup_result {
        Ok(Ready(child_vh)) if child_vh.is_valid() => {
            // Mount transparency: if the child is covered by a
            // mount, transfer into the mount's root; keep chasing
            // in case that root is itself covered.
            let effective = chase_covering_mounts(state, child_vh);
            let Some((child_key, child_vtype)) = state
                .vnodes
                .get(effective)
                .map(|v| (v.vnode_key(), v.vtype))
            else {
                return WalkStepOutcome::Error(VfsError::Io);
            };
            // Warm the resolve cache so the terminal branch and any
            // future `cursor.cwd_vkey` → handle translation
            // (including resume-path re-entry) can translate back
            // to the live handle without walking the mount graph.
            // This mirrors what `ctx.install_resolve_cache`
            // does for backends that cooperate, but covers
            // backends that do not yet call it from their lookup.
            state.install_resolve_cache(child_key, effective);

            let should_follow = child_vtype == VT_LNK
                && should_follow_symlink(cursor.flags, is_last)
                && !mount_nosymfollow_for_vnode(state, effective);

            if should_follow {
                let restart_vh = lookup_dir_vh;
                if let Err(e) = install_cursor_vnode(state, cursor, restart_vh) {
                    return WalkStepOutcome::Error(e);
                }
                match unsafe { issue_readlink(state, effective, &cursor.cred) } {
                    Ok(Ready((target, target_len))) => {
                        if let Err(e) = install_symlink_restart(
                            state,
                            cursor,
                            restart_vh,
                            &target[..target_len],
                        ) {
                            return WalkStepOutcome::Error(e);
                        }
                        if let Err(e) = apply_readlink_completion(cursor, Ok(&target[..target_len]))
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
                    mark_create_or_open_hit(cursor);
                }
                WalkStepOutcome::Continue
            }
        }
        Ok(Ready(_invalid)) => {
            // Clean ENOENT. Policy decides whether that is a
            // terminal success (StopAtParent on last component) or
            // a hard error.
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
                    out.dvp = lookup_dir_vh;
                    out.last_name = final_name;
                    out.last_name_len = final_name_len;
                    return WalkStepOutcome::Done(out);
                }
            }
            WalkStepOutcome::Error(VfsError::NotFound)
        }
        Ok(Parked(handle)) => WalkStepOutcome::Parked {
            handle,
            phase: WalkPhase::Lookup,
        },
        Err(e) => WalkStepOutcome::Error(e),
    }
}

/// Follow the `covered_by` chain starting at `vp`. Used after a
/// successful child lookup to honour mount transparency (e.g.
/// the `/dev` stub on rootfs's root vnode transfers the walk into
/// devfs's root vnode). Returns the input unchanged when no
/// covering mount is present.
fn chase_covering_mounts(state: &VfsState, vp: VnodeHandle) -> VnodeHandle {
    let mut cur = vp;
    loop {
        let Some(mh) = crate::vfs_core::mount_ctl::covering_mount_for_vnode(state, cur) else {
            return cur;
        };
        let Some(mount) = state.mounts.get(mh) else {
            return cur;
        };
        if !mount.root_vnode.is_valid() {
            return cur;
        }
        if mount.root_vnode == cur {
            // Defensive guard against self-covering (would not
            // happen in practice — the authoritative
            // `covered_by` path rejects self-links — but an
            // ill-formed mount graph must not spin here).
            return cur;
        }
        cur = mount.root_vnode;
    }
}

// =========================================================================
// Resume entry
// =========================================================================

/// Re-enter the driver after a correlated lookup completion arrives
/// for a parked walk. The backend completion router has already
/// translated the wire reply into a generic child-vnode outcome.
pub(crate) unsafe fn resume_namei_after_lookup(
    state: &mut VfsState,
    client: ClientHandle,
    mut cursor: WalkCursor,
    terminal: NameiTerminal,
    reply_slot: u64,
    lookup: VfsResult<Option<VnodeHandle>>,
) {
    unsafe {
        let apply_result = apply_lookup_completion(state, &mut cursor, lookup);
        continue_namei_after_apply(state, client, cursor, terminal, reply_slot, apply_result);
    }
}

/// Re-enter the driver after a correlated readlink completion arrives
/// for a parked walk. The backend completion router supplies the
/// target bytes directly.
pub(crate) unsafe fn resume_namei_after_readlink(
    state: &mut VfsState,
    client: ClientHandle,
    mut cursor: WalkCursor,
    terminal: NameiTerminal,
    reply_slot: u64,
    target: VfsResult<&[u8]>,
) {
    unsafe {
        let apply_result = match target {
            Ok(bytes) => {
                let parent_vh = match resolve_cursor_cwd(state, &cursor) {
                    Some(vh) => vh,
                    None => {
                        continue_namei_after_apply(
                            state,
                            client,
                            cursor,
                            terminal,
                            reply_slot,
                            Err(VfsError::Io),
                        );
                        return;
                    }
                };
                if let Err(e) = install_symlink_restart(state, &mut cursor, parent_vh, bytes) {
                    Err(e)
                } else {
                    apply_readlink_completion(&mut cursor, Ok(bytes))
                }
            }
            Err(e) => Err(e),
        };
        continue_namei_after_apply(state, client, cursor, terminal, reply_slot, apply_result);
    }
}

/// Re-enter the driver after a cross-mount root materialisation
/// completion arrives.
pub(crate) unsafe fn resume_namei_after_cross_mount_vget(
    state: &mut VfsState,
    client: ClientHandle,
    mut cursor: WalkCursor,
    terminal: NameiTerminal,
    reply_slot: u64,
    root_vh: VfsResult<VnodeHandle>,
) {
    unsafe {
        let apply_result = apply_cross_mount_vget_completion(state, &mut cursor, root_vh);
        continue_namei_after_apply(state, client, cursor, terminal, reply_slot, apply_result);
    }
}

/// Re-enter the driver after a terminal read-only metadata ack.
pub(crate) unsafe fn resume_namei_after_final_op(
    state: &mut VfsState,
    client: ClientHandle,
    cursor: WalkCursor,
    terminal: NameiTerminal,
    reply_slot: u64,
    ack: VfsResult<()>,
) {
    unsafe {
        continue_namei_after_apply(
            state,
            client,
            cursor,
            terminal,
            reply_slot,
            apply_final_op_completion(ack),
        );
    }
}

unsafe fn continue_namei_after_apply(
    state: &mut VfsState,
    client: ClientHandle,
    mut cursor: WalkCursor,
    terminal: NameiTerminal,
    reply_slot: u64,
    apply_result: VfsResult<()>,
) {
    unsafe {
        // Completion routing above this function has already translated
        // backend wire state into a generic VFS outcome for one parked
        // walker phase. This helper is the single re-entry point that
        // either continues the walk or dispatches the resolved vnode to
        // the caller-chosen terminal operation.
        if state.clients.get(client).is_none() {
            return;
        }
        if let Err(e) = apply_result {
            send_walk_error(state, reply_slot, e);
            return;
        }
        match namei_walk_async(state, &mut cursor) {
            NameiWalkOutcome::Done(result) => match terminal {
                NameiTerminal::Access { mode } => {
                    if !result.vp.is_valid() {
                        send_walk_error(state, reply_slot, VfsError::NotFound);
                        return;
                    }
                    crate::fileops::stat::send_access_reply_for_vnode(
                        state, client, result.vp, mode, reply_slot,
                    );
                }
                NameiTerminal::StatForExec => {
                    if !result.vp.is_valid() {
                        send_walk_error(state, reply_slot, VfsError::NotFound);
                        return;
                    }
                    crate::fileops::stat::send_stat_for_exec_reply_for_vnode(
                        state, client, result.vp, reply_slot,
                    );
                }
                NameiTerminal::OpenDir => {
                    if !result.vp.is_valid() {
                        send_walk_error(state, reply_slot, VfsError::NotFound);
                        return;
                    }
                    crate::fileops::dir::send_opendir_reply_for_vnode(
                        state, client, result.vp, reply_slot,
                    );
                }
                NameiTerminal::Stat => {
                    if !result.vp.is_valid() {
                        send_walk_error(state, reply_slot, VfsError::NotFound);
                        return;
                    }
                    send_stat_reply_for_vnode(state, client, result.vp, reply_slot);
                }
                NameiTerminal::Readlink => {
                    if !result.vp.is_valid() {
                        send_walk_error(state, reply_slot, VfsError::NotFound);
                        return;
                    }
                    crate::fileops::attr::send_readlink_reply_for_vnode(
                        state, client, result.vp, reply_slot,
                    );
                }
                NameiTerminal::Open { request } => {
                    crate::fileops::open::resume_open_walk_result(
                        state, client, &result, request, reply_slot,
                    );
                }
            },
            NameiWalkOutcome::Parked { handle, phase } => {
                let badge = state.clients.get(client).map(|c| c.badge).unwrap_or(0);
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    Resume::Fs(FsResume::NameiStep {
                        client,
                        cursor,
                        phase,
                        terminal,
                    }),
                ) {
                    send_walk_error(state, reply_slot, VfsError::Io);
                }
            }
            NameiWalkOutcome::Error(e) => {
                send_walk_error(state, reply_slot, e);
            }
        }
    }
}

/// Harvest `VAttr` for `vh` via the vnode's terminal `meta.getattr`
/// VOP and emit a stat-shaped reply to `reply_slot`.
///
/// The path walk is already finished when this runs. If `getattr`
/// itself parks, we stamp `FsResume::FillStatAfterWalk` so completion
/// resumes directly into stat reply formatting rather than re-driving
/// namei. Keeping this helper here lets the async walker own the
/// walk/terminal handoff without pulling stat-formatting policy back
/// into the fileops entry points.
///
/// `vh` must resolve to a live arena slot; callers ensure that.
unsafe fn send_stat_reply_for_vnode(
    state: &mut VfsState,
    client: ClientHandle,
    vh: VnodeHandle,
    reply_slot: u64,
) {
    unsafe {
        if reply_slot == 0 {
            return;
        }
        let mut out = TronaMsg::zeroed();

        // Capture vnode identity before building the VOP context so
        // that `FillStatAfterWalk` can re-resolve the vnode on
        // resume even if the arena slot has been recycled.
        let vkey = match state.vnodes.get(vh) {
            Some(v) => v.vnode_key(),
            None => {
                out.label = VfsError::Io.to_trona();
                state.send_saved_reply(reply_slot, &raw const out);
                return;
            }
        };

        let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
            out.label = VfsError::Io.to_trona();
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        };
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            out.label = VfsError::Io.to_trona();
            state.send_saved_reply(reply_slot, &raw const out);
            return;
        }
        let vnode_id = (*ctx.vnode).id;
        let vnode_vtype = (*ctx.vnode).vtype as u64;
        let mut attr = crate::vfs_core::file::VAttr::zeroed();
        let call_result = ((*ops).meta.getattr)(&mut ctx, &raw mut attr);

        match call_result {
            Ok(Ready(())) => {
                out.label = uapi::TRONA_OK;
                out.length = 8;
                out.regs[0] = vnode_id;
                out.regs[1] = attr.mode as u64;
                out.regs[2] = attr.nlink as u64;
                out.regs[3] = attr.size;
                out.regs[4] = attr.uid as u64;
                out.regs[5] = attr.gid as u64;
                out.regs[6] = attr.mtime / 1_000_000_000;
                out.regs[7] = vnode_vtype;
                state.send_saved_reply(reply_slot, &raw const out);
            }
            Ok(Parked(handle)) => {
                // getattr parked on the terminal vnode. Stamp the
                // pending op so the
                // backend completion resumes into the stat reply
                // path without re-driving the walk. The reply slot
                // is already allocated and the caller cap already
                // saved by the NameiStep that got us here — reuse
                // them as-is.
                let badge = state.clients.get(client).map(|c| c.badge).unwrap_or(0);
                if !state.stamp_resume_ctx(
                    handle,
                    badge,
                    reply_slot,
                    Resume::Fs(FsResume::FillStatAfterWalk { client, vkey }),
                ) {
                    out.label = VfsError::Io.to_trona();
                    state.send_saved_reply(reply_slot, &raw const out);
                }
            }
            Err(e) => {
                out.label = e.to_trona();
                state.send_saved_reply(reply_slot, &raw const out);
            }
        }
    }
}

// =========================================================================
// Phase reply application
// =========================================================================

/// Apply a translated lookup completion to a parked walk cursor.
/// The backend completion router has already materialised any child
/// vnode; the walker only handles VFS semantics from here.
unsafe fn apply_lookup_completion(
    state: &mut VfsState,
    cursor: &mut WalkCursor,
    lookup: VfsResult<Option<VnodeHandle>>,
) -> VfsResult<()> {
    unsafe {
        let child_vh = match lookup? {
            Some(vh) => vh,
            None => {
                if cursor.remaining_len == 0 {
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
                return Err(VfsError::NotFound);
            }
        };

        // Mount transparency: same chase loop as `walk_step`.
        let effective = chase_covering_mounts(state, child_vh);
        let child_key = state
            .vnodes
            .get(effective)
            .map(|v| v.vnode_key())
            .ok_or(VfsError::Io)?;
        state.install_resolve_cache(child_key, effective);
        cursor.cwd_vkey = child_key;
        if cursor.remaining_len == 0 {
            mark_create_or_open_hit(cursor);
        }

        Ok(())
    }
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

/// Apply the `VGET` completion for a cross-mount boundary crossing.
///
/// Invoked when the async walker observed a mount-point crossing
/// mid-walk and parked on a synthetic `VGET` issued against the
/// covering mount's backend so its root vnode could be materialised
/// on demand. The reply carries a stat-shaped attribute snapshot
/// (`ino`, `seq`, `mode`, `size`, `nlink`, `mtime`, `uid`, `gid`,
/// `dir_type`, `blocks`); this function parses the snapshot,
/// installs a fresh root vnode into the covering mount's
/// personality backend via its `vget` VFS op, and rewrites
/// `cursor.cwd_vkey` to the new root's identity so the walker's
/// next step resolves against the covering mount.
///
/// Failure paths: a malformed reply, a missing backend `vget`
/// hook, or arena exhaustion surface to the caller as a walk error
/// — no partial state is left behind because the pending-op slot
/// has already been released before this function runs.
unsafe fn apply_cross_mount_vget_completion(
    state: &mut VfsState,
    cursor: &mut WalkCursor,
    root_vh: VfsResult<VnodeHandle>,
) -> VfsResult<()> {
    let root_vh = root_vh?;
    if !root_vh.is_valid() {
        return Err(VfsError::Io);
    }
    let new_key = state
        .vnodes
        .get(root_vh)
        .map(|v| v.vnode_key())
        .ok_or(VfsError::Io)?;
    cursor.cwd_vkey = new_key;
    state.install_resolve_cache(new_key, root_vh);
    Ok(())
}

/// Terminal-completion arm for `WalkPhase::FinalOp`.
///
unsafe fn apply_final_op_completion(ack: VfsResult<()>) -> VfsResult<()> {
    ack
}

// =========================================================================
// Cursor mutation helpers
// =========================================================================

/// Separator byte used by POSIX path grammar. The async walk is
/// personality-neutral but consumes `/`-separated components —
/// per-personality walkers that use a different separator (Win32
/// `\\`) either feed a pre-normalised POSIX path into the async
/// driver or supply a grammar adapter.
const PATH_SEP: u8 = b'/';

/// Pop the next component from the front of the cursor's
/// remaining path. Consumes leading separators, then the first
/// component-worth of bytes, then one trailing separator (if
/// present). Shift-lefts the tail in place (Approach Y).
///
/// Returns `None` when the cursor has no more components. The
/// second tuple slot (`is_last`) is `true` when the component
/// was the final one in the remaining path (i.e. no separator
/// followed it). Used to drive
/// `WalkPolicy::StopAtParent` hand-off.
///
/// Output is written into `out_name` + `out_len` to avoid
/// returning a reference into the cursor (which would prevent
/// further mutation). `out_name` must hold at least
/// `WALK_NAME_MAX` bytes.
pub(crate) fn consume_next_component(
    cursor: &mut WalkCursor,
    out_name: &mut [u8],
) -> Option<(u8, bool)> {
    let len = cursor.remaining_len as usize;
    if len == 0 {
        return None;
    }
    let buf = &mut cursor.remaining_path[..len];

    // Skip leading separators.
    let mut start = 0usize;
    while start < len && buf[start] == PATH_SEP {
        start += 1;
    }
    if start == len {
        // Path was all separators — consume all, report none.
        cursor.remaining_len = 0;
        return None;
    }

    // Find end of component.
    let mut end = start;
    while end < len && buf[end] != PATH_SEP {
        end += 1;
    }

    let name_len = end - start;
    if name_len > out_name.len() || name_len > crate::owner::pending::WALK_NAME_MAX {
        // Caller will surface as NameTooLong after observing a
        // 0-return plus a live remaining_len.
        return None;
    }

    // Copy the component out.
    out_name[..name_len].copy_from_slice(&buf[start..end]);

    // Skip exactly one trailing separator (if present). Preserves
    // any following slashes for the next component to consume,
    // matching POSIX "many-slashes-between-components" semantics.
    let mut tail_start = end;
    if tail_start < len && buf[tail_start] == PATH_SEP {
        tail_start += 1;
    }

    let is_last = tail_start >= len;
    let tail_len = len - tail_start;

    // Shift the tail down to index 0 (Approach Y).
    cursor
        .remaining_path
        .copy_within(tail_start..tail_start + tail_len, 0);
    cursor.remaining_len = tail_len as u16;
    // Zero the vacated bytes so parked cursors dump cleanly.
    for i in tail_len..len {
        cursor.remaining_path[i] = 0;
    }

    Some((name_len as u8, is_last))
}

/// Splice a symlink target into the front of the cursor's
/// remaining path, followed by a single `/`, followed by the
/// existing remaining bytes.
///
/// Approach Y: we build the new string at index 0 by first
/// shifting the current tail right by `target_len + 1`, then
/// writing `target + '/'` at the front. Fails with
/// `VfsError::NameTooLong` when the result would exceed
/// `WALK_PATH_MAX`. Also bumps `follow_depth`; caller must
/// check against `NAMEI_SYMLINK_MAX_DEPTH` before invoking.
pub(crate) fn splice_symlink_target(
    cursor: &mut WalkCursor,
    target: &[u8],
    target_len: usize,
) -> VfsResult<()> {
    if target_len > target.len() {
        return Err(VfsError::Inval);
    }
    let old_len = cursor.remaining_len as usize;
    // New layout: target (target_len) + '/' (1) + old tail (old_len)
    let new_len = target_len
        .checked_add(1)
        .and_then(|n| n.checked_add(old_len))
        .ok_or(VfsError::NameTooLong)?;
    if new_len > WALK_PATH_MAX {
        return Err(VfsError::NameTooLong);
    }

    // Shift the existing tail right.
    if old_len > 0 {
        cursor
            .remaining_path
            .copy_within(0..old_len, target_len + 1);
    }
    // Write the target at the front.
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

fn mount_nosymfollow_for_vnode(state: &VfsState, vh: VnodeHandle) -> bool {
    let Some(mh) = state.resolve_vnode_mount(vh) else {
        return false;
    };
    match state.mounts.get(mh) {
        Some(mount) => (mount.flags & crate::vfs_core::mount::MNT_NOSYMFOLLOW) != 0,
        None => false,
    }
}

fn install_cursor_vnode(
    state: &mut VfsState,
    cursor: &mut WalkCursor,
    vh: VnodeHandle,
) -> VfsResult<()> {
    let key = state
        .vnodes
        .get(vh)
        .map(|v| v.vnode_key())
        .ok_or(VfsError::Io)?;
    state.install_resolve_cache(key, vh);
    cursor.cwd_vkey = key;
    Ok(())
}

fn install_symlink_restart(
    state: &mut VfsState,
    cursor: &mut WalkCursor,
    parent_vh: VnodeHandle,
    target: &[u8],
) -> VfsResult<()> {
    let restart_vh = if target.first().copied() == Some(PATH_SEP) {
        resolve_vnode_key(state, cursor.root_vkey).ok_or(VfsError::Io)?
    } else {
        parent_vh
    };
    install_cursor_vnode(state, cursor, restart_vh)
}

unsafe fn issue_readlink(
    state: &mut VfsState,
    vh: VnodeHandle,
    cred: &crate::vfs_core::cred::VfsCred,
) -> VfsResult<
    crate::vfs_core::outcome::VopControl<(
        [u8; crate::owner::pending::WALK_SYMLINK_TARGET_MAX],
        usize,
    )>,
> {
    let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
        return Err(VfsError::Io);
    };
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return Err(VfsError::Io);
    }
    let mut buf = [0u8; crate::owner::pending::WALK_SYMLINK_TARGET_MAX];
    match unsafe { ((*ops).meta.readlink)(&mut ctx, buf.as_mut_ptr(), buf.len(), &raw const *cred) }
    {
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

unsafe fn lookup_dotdot(
    state: &mut VfsState,
    vh: VnodeHandle,
    root_vkey: VnodeKey,
) -> VfsResult<crate::vfs_core::outcome::VopControl<VnodeHandle>> {
    let vnode = state.vnodes.get(vh).ok_or(VfsError::Io)?;
    if root_vkey.is_valid() && vnode.vnode_key() == root_vkey {
        return Ok(Ready(vh));
    }
    if (vnode.flags & VN_ROOT) != 0 {
        let mh = vnode.mount.resolve_ro(state).ok_or(VfsError::Io)?;
        let mount = state.mounts.get(mh).ok_or(VfsError::Io)?;
        let covered = mount
            .covered
            .resolve_ro(state)
            .unwrap_or(VnodeHandle::INVALID);
        return Ok(Ready(if covered.is_valid() { covered } else { vh }));
    }
    let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) else {
        return Err(VfsError::Io);
    };
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return Err(VfsError::Io);
    }
    unsafe { ((*ops).meta.lookup)(&mut ctx, b"..".as_ptr(), 2) }
}

// =========================================================================
// Private helpers
// =========================================================================

/// Reply to the parked client with a single-label error. Used by
/// the `resume_namei_after_*` helpers to propagate terminal errors back after
/// the walk has unwound through the owner loop.
unsafe fn send_walk_error(state: &mut VfsState, reply_slot: u64, err: VfsError) {
    unsafe {
        if reply_slot == 0 {
            return;
        }
        let mut out = TronaMsg::zeroed();
        out.label = err.to_trona();
        state.send_saved_reply(reply_slot, &raw const out);
    }
}

/// Helper used by resume handlers to re-resolve `cursor.cwd_vkey`
/// to a live `VnodeHandle`. `walk_step` inlines the cache lookup
/// because it always holds `&mut VfsState`; this indirection
/// exists so apply helpers (which receive `&mut cursor` through
/// the async resume helpers) share a single policy for cwd resolution
/// without re-implementing the invariant.
pub(crate) fn resolve_cursor_cwd(state: &VfsState, cursor: &WalkCursor) -> Option<VnodeHandle> {
    resolve_vnode_key(state, cursor.cwd_vkey)
}

fn resolve_vnode_key(state: &VfsState, key: VnodeKey) -> Option<VnodeHandle> {
    if !key.is_valid() {
        return None;
    }
    if let Some(vh) = state.lookup_resolve_cache(key) {
        return Some(vh);
    }
    let mut found = None;
    state.vnodes.for_each_active(|vh, vnode| {
        if vnode.vnode_key() == key {
            found = Some(vh);
            return false;
        }
        true
    });
    found
}
