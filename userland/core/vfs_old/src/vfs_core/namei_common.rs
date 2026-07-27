// SPDX-License-Identifier: GPL-2.0-only
//! Common path-walk infrastructure shared by per-personality `namei`
//! implementations.

use super::cred::VfsCred;
use super::error::{VfsError, VfsResult};
use super::mount::{MNT_NOSYMFOLLOW, MNT_POSIX_ONLY, MNT_WIN32_ONLY, MountHandle};
use super::outcome::{Parked, Ready};
use super::vnode::{VN_ROOT, VT_DIR, Vnode, VnodeHandle};
use super::vop::VopVector;
use super::vop_context::OwnerVopCtx;
use crate::owner::VfsState;

// =========================================================================
// Namei flags
// =========================================================================

pub(crate) const NAMEI_FOLLOW: u32 = 1 << 0;
pub(crate) const NAMEI_WANTPARENT: u32 = 1 << 1;
pub(crate) const NAMEI_NOFOLLOW_ANY: u32 = 1 << 2;
pub(crate) const NAMEI_DIRECTORY: u32 = 1 << 3;
pub(crate) const NAMEI_CREATE: u32 = 1 << 4;
pub(crate) const NAMEI_CASE_INSENSITIVE: u32 = 1 << 5;
pub(crate) const NAMEI_NOFOLLOW_FINAL: u32 = 1 << 6;

/// Maximum depth of symbolic link resolution before returning `VfsError::Loop`.
pub(crate) const NAMEI_SYMLINK_MAX_DEPTH: u32 = 8;

// =========================================================================
// NameiCtx — arena context for path resolution
// =========================================================================

/// Arena context passed to all namei helpers. Wraps the owner-loop's
/// `&'a mut VfsState` so handle-based resolution can read vnode/mount
/// fields and dispatch `VopMetaOps` via `OwnerVopCtx`.
pub(crate) struct NameiCtx<'a> {
    pub(crate) state: &'a mut VfsState,
}

impl<'a> NameiCtx<'a> {
    #[inline]
    pub(crate) fn vnodes(&self) -> &crate::arena::Arena<Vnode> {
        &self.state.vnodes
    }

    #[inline]
    pub(crate) fn mounts(&self) -> &crate::arena::Arena<super::mount::Mount> {
        &self.state.mounts
    }

    /// Resolve a vnode's owning mount through its `CachedRef<FsInstanceId,
    /// MountHandle>`.
    pub(crate) fn resolve_vnode_mount_handle(&self, vnode: &Vnode) -> Option<MountHandle> {
        let id = vnode.mount.id();
        if !id.is_valid() {
            return None;
        }
        let hint = vnode.mount.handle_hint();
        if let Some(m) = self.mounts().get(hint) {
            if m.fs_instance_id == id {
                return Some(hint);
            }
        }
        let mut found = None;
        self.mounts().for_each_active(|mh, mp| {
            if mp.fs_instance_id == id {
                found = Some(mh);
                return false;
            }
            true
        });
        found
    }
}

// =========================================================================
// NameiArgs / NameiResult
// =========================================================================

/// Input to a `namei` walk.
pub(crate) struct NameiArgs {
    pub(crate) start: VnodeHandle,
    pub(crate) path: *const u8,
    pub(crate) path_len: u16,
    pub(crate) flags: u32,
    pub(crate) cred: VfsCred,
    pub(crate) root: VnodeHandle,
}

/// Result of a `namei` walk.
pub(crate) struct NameiResult {
    pub(crate) vp: VnodeHandle,
    pub(crate) dvp: VnodeHandle,
    pub(crate) last_name: *const u8,
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

pub(crate) fn walk_dotdot(
    ctx: &mut NameiCtx<'_>,
    vp: VnodeHandle,
    ns_root: VnodeHandle,
) -> VfsResult<VnodeHandle> {
    let (is_ns_root, is_mount_root_with_mount_id, ops_ptr) = {
        let vnode = ctx.vnodes().get(vp).ok_or(VfsError::Io)?;
        (
            ns_root.is_valid() && vp == ns_root,
            (vnode.flags & VN_ROOT) != 0 && vnode.mount.id().is_valid(),
            vnode.ops,
        )
    };

    if is_ns_root {
        return Ok(vp);
    }

    if is_mount_root_with_mount_id {
        let covered_vh = {
            let vnode = ctx.vnodes().get(vp).ok_or(VfsError::Io)?;
            let mh = ctx.resolve_vnode_mount_handle(vnode).ok_or(VfsError::Io)?;
            let mount = ctx.mounts().get(mh).ok_or(VfsError::Io)?;
            mount.covered.handle_hint()
        };
        if !covered_vh.is_valid() {
            return Ok(vp);
        }
        return Ok(covered_vh);
    }

    if ops_ptr.is_null() {
        return Err(VfsError::Io);
    }
    let mut vop_ctx = unsafe { OwnerVopCtx::from_state(ctx.state, vp).ok_or(VfsError::Io)? };
    match unsafe { ((*ops_ptr).meta.lookup)(&mut vop_ctx, b"..".as_ptr(), 2) } {
        Ok(Ready(vh)) => Ok(vh),
        Ok(Parked(_)) => Err(VfsError::Busy),
        Err(e) => Err(e),
    }
}

// =========================================================================
// Mount coverage traversal
// =========================================================================

pub(crate) fn cross_covered(ctx: &NameiCtx<'_>, vp: VnodeHandle) -> VfsResult<VnodeHandle> {
    cross_covered_inner(ctx, vp, false, true)
}

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
        let child_mount = ctx.mounts().get(child_mount_h).ok_or(VfsError::Io)?;
        let flags = child_mount.flags;

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
        cur = root;
    }
}

fn covering_mount_for_vnode(ctx: &NameiCtx<'_>, vp: VnodeHandle) -> Option<MountHandle> {
    let vnode = ctx.vnodes().get(vp)?;
    if vnode.covered_by.id().is_valid() {
        let target_fs_id = vnode.covered_by.id();
        let mut found: Option<MountHandle> = None;
        ctx.mounts().for_each_active(|mh, mp| {
            if mp.fs_instance_id == target_fs_id {
                found = Some(mh);
                return false;
            }
            true
        });
        if found.is_some() {
            return found;
        }
    }

    let parent_fs_id = vnode.mount.id();
    if !parent_fs_id.is_valid() {
        return None;
    }
    let target_key = vnode.vnode_key();
    let mut found = None;

    ctx.mounts().for_each_active(|mh, mp| {
        if mp.parent.id() != parent_fs_id || !mp.covered.id().is_valid() {
            return true;
        }
        if mp.covered.id() == target_key {
            found = Some(mh);
            return false;
        }
        true
    });

    found
}

// =========================================================================
// Component lookup helpers
// =========================================================================

pub(crate) fn lookup_component(
    ctx: &mut NameiCtx<'_>,
    dir_vh: VnodeHandle,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    let ops_ptr = {
        let vnode = ctx.vnodes().get(dir_vh).ok_or(VfsError::Io)?;
        if vnode.ops.is_null() {
            return Err(VfsError::Io);
        }
        vnode.ops
    };
    let mut vop_ctx = unsafe { OwnerVopCtx::from_state(ctx.state, dir_vh).ok_or(VfsError::Io)? };
    match unsafe { ((*ops_ptr).meta.lookup)(&mut vop_ctx, name, name_len) } {
        Ok(Ready(vh)) => Ok(vh),
        Ok(Parked(_)) => Err(VfsError::Busy),
        Err(e) => Err(e),
    }
}

pub(crate) fn lookup_component_ci(
    ctx: &mut NameiCtx<'_>,
    dir_vh: VnodeHandle,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    let ops_ptr = {
        let vnode = ctx.vnodes().get(dir_vh).ok_or(VfsError::Io)?;
        if vnode.ops.is_null() {
            return Err(VfsError::Io);
        }
        vnode.ops
    };
    let mut vop_ctx = unsafe { OwnerVopCtx::from_state(ctx.state, dir_vh).ok_or(VfsError::Io)? };
    match unsafe { ((*ops_ptr).meta.lookup_ci)(&mut vop_ctx, name, name_len) } {
        Ok(Ready(vh)) => Ok(vh),
        Ok(Parked(_)) => Err(VfsError::Busy),
        Err(e) => Err(e),
    }
}

pub(crate) fn readlink_vnode(
    ctx: &mut NameiCtx<'_>,
    vh: VnodeHandle,
    buf: *mut u8,
    buf_len: usize,
    cred: &VfsCred,
) -> VfsResult<usize> {
    let ops_ptr = {
        let vnode = ctx.vnodes().get(vh).ok_or(VfsError::Io)?;
        if vnode.ops.is_null() {
            return Err(VfsError::Io);
        }
        vnode.ops
    };
    let mut vop_ctx = unsafe { OwnerVopCtx::from_state(ctx.state, vh).ok_or(VfsError::Io)? };
    match unsafe { ((*ops_ptr).meta.readlink)(&mut vop_ctx, buf, buf_len, &raw const *cred) } {
        Ok(Ready(len)) => Ok(len),
        Ok(Parked(_)) => Err(VfsError::Busy),
        Err(e) => Err(e),
    }
}

// =========================================================================
// Finish helper
// =========================================================================

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

    Ok(res)
}

// =========================================================================
// Vnode field accessors (convenience)
// =========================================================================

#[inline]
pub(crate) fn vnode_vtype(ctx: &NameiCtx<'_>, vh: VnodeHandle) -> VfsResult<u8> {
    ctx.vnodes().get(vh).map(|v| v.vtype).ok_or(VfsError::Io)
}

#[inline]
pub(crate) fn mount_nosymfollow(ctx: &NameiCtx<'_>, vh: VnodeHandle) -> bool {
    let vnode = match ctx.vnodes().get(vh) {
        Some(v) => v,
        None => return false,
    };
    let mh = match ctx.resolve_vnode_mount_handle(vnode) {
        Some(mh) => mh,
        None => return false,
    };
    match ctx.mounts().get(mh) {
        Some(m) => (m.flags & MNT_NOSYMFOLLOW) != 0,
        None => false,
    }
}

// Quiet unused-import when callers only touch a subset of the re-exports.
#[allow(dead_code)]
type _WalkOpsReference = VopVector;
