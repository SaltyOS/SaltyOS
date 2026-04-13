// SPDX-License-Identifier: GPL-2.0-only
//! Common path-walk infrastructure shared by per-personality `namei`
//! implementations.
//!
//! Per-personality `namei` lives in `personality/posix/namei.rs` and
//! `personality/win32/namei.rs`. Each owns its own grammar (component
//! separator, reserved names, case sensitivity, canonicalization) but
//! delegates to the helpers in this module for cross-cutting concerns:
//!
//! - `..` containment at mount roots
//! - Traversal into a covered mount
//! - Symbolic link depth limit
//!
//! # Handle-based model
//!
//! All vnode and mount references use `VnodeHandle` / `MountHandle`
//! (epoch-counted arena handles). There are no raw-pointer refcounts
//! (`vref`/`vrele`). Handle validity is checked via `Arena::is_alive()`.
//! The `NameiCtx` struct carries arena references needed for resolution.

use super::cred::VfsCred;
use super::error::{VfsError, VfsResult};
use super::mount::{Mount, MountHandle, MNT_NOSYMFOLLOW, MNT_POSIX_ONLY, MNT_WIN32_ONLY};
use super::vnode::{Vnode, VnodeHandle, VN_ROOT, VT_DIR};
use super::vop::VopVector;
use super::vop_context::{MountResolveFn, VnodeAllocFn, VnodeResolveFn, VopContext};
use crate::arena::Arena;

// =========================================================================
// Namei flags
// =========================================================================

/// Follow a symbolic link found at the final path component.
pub(crate) const NAMEI_FOLLOW: u32 = 1 << 0;
/// Return the parent directory in `NameiResult.dvp` in addition to the target.
pub(crate) const NAMEI_WANTPARENT: u32 = 1 << 1;
/// Do not follow any symbolic link, including intermediate ones (`O_NOFOLLOW`
/// applied to every component — primarily used by `lstat`-style callers).
pub(crate) const NAMEI_NOFOLLOW_ANY: u32 = 1 << 2;
/// The final component must resolve to a directory (`O_DIRECTORY`).
pub(crate) const NAMEI_DIRECTORY: u32 = 1 << 3;
/// Tolerate ENOENT on the final component — used by `open(O_CREAT)` and
/// `mkdir`/`symlink` where the caller will create the missing entry.
pub(crate) const NAMEI_CREATE: u32 = 1 << 4;
/// Case-insensitive lookup (Win32 `namei_win32` sets this, POSIX never does).
pub(crate) const NAMEI_CASE_INSENSITIVE: u32 = 1 << 5;
/// Do not follow the final symbolic link component, but allow following
/// intermediate symlinks needed to reach it.
pub(crate) const NAMEI_NOFOLLOW_FINAL: u32 = 1 << 6;

/// Maximum depth of symbolic link resolution before returning `VfsError::Loop`.
pub(crate) const NAMEI_SYMLINK_MAX_DEPTH: u32 = 8;

// =========================================================================
// NameiCtx — arena context for path resolution
// =========================================================================

/// Arena context passed to all namei helpers.
///
/// Carries references to the vnode and mount arenas so that handle-based
/// resolution can read vnode/mount fields and dispatch VopMetaOps calls.
/// Constructed by the dispatch layer from `&mut VfsState` before calling
/// `namei_posix` or `namei_win32`.
pub(crate) struct NameiCtx<'a> {
    pub(crate) vnodes: &'a Arena<Vnode>,
    pub(crate) mounts: &'a Arena<Mount>,
    pub(crate) alloc: VnodeAllocFn,
    pub(crate) resolve_vnode: VnodeResolveFn,
    pub(crate) resolve_mount: MountResolveFn,
}

// =========================================================================
// NameiArgs / NameiResult
// =========================================================================

/// Input to a `namei` walk.
pub(crate) struct NameiArgs {
    /// Starting vnode handle. For absolute paths the walker replaces this
    /// with the namespace root; for relative paths this is the walk origin
    /// (typically the client's cwd vnode).
    pub(crate) start: VnodeHandle,
    /// Path bytes. No ownership implied — the walk reads but does not copy
    /// (symbolic link follow may rewrite into a caller-provided scratch
    /// buffer; per-personality walkers handle that themselves).
    pub(crate) path: *const u8,
    /// Length of `path` in bytes.
    pub(crate) path_len: u16,
    /// `NAMEI_*` flags.
    pub(crate) flags: u32,
    /// Caller credential (for `access` checks along the walk).
    pub(crate) cred: VfsCred,
    /// Namespace root vnode handle. Absolute paths resolve relative to this
    /// vnode instead of the global root mount. When mount namespaces are
    /// active, this is the root of the client's mount namespace; otherwise
    /// it is the global root vnode.
    pub(crate) root: VnodeHandle,
}

/// Result of a `namei` walk.
pub(crate) struct NameiResult {
    /// Resolved target vnode. `VnodeHandle::INVALID` when `NAMEI_CREATE`
    /// was set and the final component was missing — in that case `dvp` is
    /// the parent and `last_name` / `last_name_len` identify the requested
    /// name.
    pub(crate) vp: VnodeHandle,
    /// Parent directory vnode (valid when `NAMEI_WANTPARENT` was set, else
    /// `VnodeHandle::INVALID`).
    pub(crate) dvp: VnodeHandle,
    /// Pointer to the final component inside `NameiArgs.path`.
    pub(crate) last_name: *const u8,
    /// Length of the final component.
    pub(crate) last_name_len: u8,
}

impl NameiResult {
    pub(crate) const fn empty() -> Self {
        NameiResult {
            vp: VnodeHandle::INVALID,
            dvp: VnodeHandle::INVALID,
            last_name: core::ptr::null(),
            last_name_len: 0,
        }
    }
}

// =========================================================================
// `..` traversal
// =========================================================================

/// Walk one step up the directory tree, crossing mount boundaries as needed.
///
/// If `vp` is a mount root (`VN_ROOT` set) and the mount has a
/// `covered_vnode`, control transfers to that covered vnode on the parent
/// filesystem. At the namespace root (`ns_root`), `..` maps to itself.
///
/// Returns the parent `VnodeHandle`. No refcount management needed —
/// handles are stable identity tokens validated by generation.
pub(crate) fn walk_dotdot(
    ctx: &NameiCtx<'_>,
    vp: VnodeHandle,
    ns_root: VnodeHandle,
) -> VfsResult<VnodeHandle> {
    let vnode = ctx.vnodes.get(vp).ok_or(VfsError::Io)?;

    // Namespace root containment — `..` at the namespace root is self.
    if ns_root.is_valid() && vp == ns_root {
        return Ok(vp);
    }

    if (vnode.flags & VN_ROOT) != 0 && vnode.mount.is_valid() {
        let mount = ctx.mounts.get(vnode.mount).ok_or(VfsError::Io)?;
        if !mount.covered_vnode.is_valid() {
            // System root — `..` is self.
            return Ok(vp);
        }
        // Cross the mount boundary upwards.
        return Ok(mount.covered_vnode);
    }

    // Not a mount root — delegate to the filesystem's lookup with "..".
    let ops = vnode.ops;
    if ops.is_null() {
        return Err(VfsError::Io);
    }
    let vop_ctx = build_vop_context(ctx, vp, vnode)?;
    unsafe { ((*ops).meta.lookup)(&vop_ctx, b"..".as_ptr(), 2) }
}

// =========================================================================
// Mount coverage traversal
// =========================================================================

/// If `vp` is covered by a child mount, transfer into that mount's root
/// vnode (following the covering chain until no further mounts cover the
/// current node). Otherwise return `vp` unchanged.
///
/// POSIX personality — sees everything except `MNT_WIN32_ONLY` mounts.
pub(crate) fn cross_covered(ctx: &NameiCtx<'_>, vp: VnodeHandle) -> VfsResult<VnodeHandle> {
    cross_covered_inner(ctx, vp, false, true)
}

/// Personality-aware mount coverage traversal.
///
/// - `skip_posix_only`: when true, mounts with `MNT_POSIX_ONLY` are
///   treated as invisible (Win32 callers set this).
/// - `skip_win32_only`: when true, mounts with `MNT_WIN32_ONLY` are
///   treated as invisible (POSIX callers set this).
///
/// Win32 `namei` should call this with `skip_posix_only=true`.
pub(crate) fn cross_covered_personality(
    ctx: &NameiCtx<'_>,
    vp: VnodeHandle,
    skip_posix_only: bool,
) -> VfsResult<VnodeHandle> {
    cross_covered_inner(ctx, vp, skip_posix_only, false)
}

fn cross_covered_inner(
    ctx: &NameiCtx<'_>,
    vp: VnodeHandle,
    skip_posix_only: bool,
    skip_win32_only: bool,
) -> VfsResult<VnodeHandle> {
    let mut cur = vp;
    loop {
        let Some(child_mount_h) = covering_mount_for_vnode(ctx, cur) else {
            return Ok(cur);
        };
        let child_mount = ctx.mounts.get(child_mount_h).ok_or(VfsError::Io)?;
        let flags = child_mount.flags;

        // Skip mounts invisible to the calling personality.
        if skip_posix_only && (flags & MNT_POSIX_ONLY) != 0 {
            return Ok(cur);
        }
        if skip_win32_only && (flags & MNT_WIN32_ONLY) != 0 {
            return Ok(cur);
        }

        let root = child_mount.root_vnode;
        if !root.is_valid() {
            return Ok(cur);
        }
        // Continue checking whether the root is also covered.
        cur = root;
    }
}

fn covering_mount_for_vnode(ctx: &NameiCtx<'_>, vp: VnodeHandle) -> Option<MountHandle> {
    let vnode = ctx.vnodes.get(vp)?;
    if vnode.covered_by.is_valid() && ctx.mounts.get(vnode.covered_by).is_some() {
        return Some(vnode.covered_by);
    }

    let parent_mh = vnode.mount;
    if !parent_mh.is_valid() {
        return None;
    }
    let vnode_id = vnode.id;
    let mut found = None;

    ctx.mounts.for_each_active(|mh, mp| {
        if mp.parent != parent_mh || !mp.covered_vnode.is_valid() {
            return true;
        }
        let Some(covered_vnode) = ctx.vnodes.get(mp.covered_vnode) else {
            return true;
        };
        if covered_vnode.id == vnode_id {
            found = Some(mh);
            return false;
        }
        true
    });

    found
}

// =========================================================================
// VopContext construction helper
// =========================================================================

/// Build a `VopContext` for dispatching a `VopMetaOps` call on `vh`.
///
/// Resolves the vnode's mount handle to get mount data, and captures the
/// arena's allocation callback.
pub(crate) fn build_vop_context(
    ctx: &NameiCtx<'_>,
    vh: VnodeHandle,
    vnode: &Vnode,
) -> VfsResult<VopContext> {
    let (mount_ptr, mount_data) = if vnode.mount.is_valid() {
        match ctx.mounts.get(vnode.mount) {
            Some(m) => (m as *const Mount, m.data),
            None => (core::ptr::null(), core::ptr::null_mut()),
        }
    } else {
        (core::ptr::null(), core::ptr::null_mut())
    };

    Ok(VopContext {
        handle: vh,
        vnode: vnode as *const Vnode as *mut Vnode,
        mount_handle: vnode.mount,
        mount: mount_ptr,
        data: vnode.data,
        mount_data,
        alloc: ctx.alloc,
        resolve_vnode: ctx.resolve_vnode,
        resolve_mount: ctx.resolve_mount,
    })
}

// =========================================================================
// Component lookup helpers
// =========================================================================

/// Perform a single-component lookup via `VopMetaOps::lookup`.
///
/// Builds a `VopContext` for the directory vnode `dir_vh` and calls the
/// backend's lookup function. Returns the child `VnodeHandle`, or
/// `Ok(VnodeHandle::INVALID)` on clean ENOENT.
pub(crate) fn lookup_component(
    ctx: &NameiCtx<'_>,
    dir_vh: VnodeHandle,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    let vnode = ctx.vnodes.get(dir_vh).ok_or(VfsError::Io)?;
    let ops = vnode.ops;
    if ops.is_null() {
        return Err(VfsError::Io);
    }
    let vop_ctx = build_vop_context(ctx, dir_vh, vnode)?;
    unsafe { ((*ops).meta.lookup)(&vop_ctx, name, name_len) }
}

/// Perform a case-insensitive single-component lookup via
/// `VopMetaOps::lookup_ci`.
pub(crate) fn lookup_component_ci(
    ctx: &NameiCtx<'_>,
    dir_vh: VnodeHandle,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    let vnode = ctx.vnodes.get(dir_vh).ok_or(VfsError::Io)?;
    let ops = vnode.ops;
    if ops.is_null() {
        return Err(VfsError::Io);
    }
    let vop_ctx = build_vop_context(ctx, dir_vh, vnode)?;
    unsafe { ((*ops).meta.lookup_ci)(&vop_ctx, name, name_len) }
}

/// Read a symbolic link target via `VopMetaOps::readlink`.
pub(crate) fn readlink_vnode(
    ctx: &NameiCtx<'_>,
    vh: VnodeHandle,
    buf: *mut u8,
    buf_len: usize,
    cred: &VfsCred,
) -> VfsResult<usize> {
    let vnode = ctx.vnodes.get(vh).ok_or(VfsError::Io)?;
    let ops = vnode.ops;
    if ops.is_null() {
        return Err(VfsError::Io);
    }
    let vop_ctx = build_vop_context(ctx, vh, vnode)?;
    unsafe { ((*ops).meta.readlink)(&vop_ctx, buf, buf_len, &raw const *cred) }
}

// =========================================================================
// Finish helper
// =========================================================================

/// Build the final `NameiResult`, conditionally retaining or dropping the
/// parent directory handle depending on `NAMEI_WANTPARENT`.
pub(crate) fn finish_namei(
    vp: VnodeHandle,
    dvp: VnodeHandle,
    last_name: *const u8,
    last_name_len: u8,
    flags: u32,
) -> VfsResult<NameiResult> {
    let mut res = NameiResult::empty();
    res.vp = vp;
    res.last_name = last_name;
    res.last_name_len = last_name_len;

    if (flags & NAMEI_WANTPARENT) != 0 {
        res.dvp = dvp;
    }
    // When WANTPARENT is not set, dvp is simply not propagated.
    // No vrele needed — handles have no refcount.

    Ok(res)
}

// =========================================================================
// Vnode field accessors (convenience)
// =========================================================================

/// Read the vtype of a vnode handle. Returns `Err(Io)` if the handle is stale.
#[inline]
pub(crate) fn vnode_vtype(ctx: &NameiCtx<'_>, vh: VnodeHandle) -> VfsResult<u8> {
    ctx.vnodes.get(vh).map(|v| v.vtype).ok_or(VfsError::Io)
}

/// Check whether a mount has `MNT_NOSYMFOLLOW` set.
#[inline]
pub(crate) fn mount_nosymfollow(ctx: &NameiCtx<'_>, vh: VnodeHandle) -> bool {
    let vnode = match ctx.vnodes.get(vh) {
        Some(v) => v,
        None => return false,
    };
    if !vnode.mount.is_valid() {
        return false;
    }
    match ctx.mounts.get(vnode.mount) {
        Some(m) => (m.flags & MNT_NOSYMFOLLOW) != 0,
        None => false,
    }
}
