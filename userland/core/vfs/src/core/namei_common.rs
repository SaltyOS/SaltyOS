// SPDX-License-Identifier: GPL-2.0-only
//
//! Shared namei constants + sync helpers used by both the async
//! path-walk state machine ([`crate::core::namei_async`]) and
//! the personality `namei` shims (POSIX socket / shm path
//! resolution, Win32 drive letter mapping). The async driver
//! consumes the flag bits directly; sync helpers exist for the
//! short-circuit cases where path resolution can complete inline
//! against in-memory mounts (devfs / procfs / sysctlfs / pipefs)
//! without ever parking.

use crate::core::error::{VfsError, VfsResult};
use crate::core::identity::VnodeKey;
use crate::core::outcome::{Ready, VopControl};
use crate::core::vnode::{VN_ROOT, VnodeHandle, VnodeKind};
use crate::core::vop_context::OwnerVopCtx;
use crate::owner::VfsState;

// =========================================================================
// Namei flags — matched bit positions to vfs_old's namei_common so
// posix / personality / core code paths can share one flag
// vocabulary. Unused bits stay reserved.
// =========================================================================

/// Follow the symlink at the final component (POSIX `open` /
/// `stat`). Mid-walk symlinks always follow.
pub(crate) const NAMEI_FOLLOW: u32 = 1 << 0;
/// Stop at the parent directory; surface the final component name
/// to the caller. Used by `mkdir`, `unlink`, `rename`, `link`,
/// `symlink`.
pub(crate) const NAMEI_WANTPARENT: u32 = 1 << 1;
/// Refuse to follow any symlink (including mid-walk). Used by
/// `lchown`, `lstat`, `realpath`-style probes.
pub(crate) const NAMEI_NOFOLLOW_ANY: u32 = 1 << 2;
/// Final component must be a directory. Used by `chdir`,
/// `opendir`, mount targets.
pub(crate) const NAMEI_DIRECTORY: u32 = 1 << 3;
/// `O_CREAT` / `mkdir` etc — caller wants the parent + final name
/// even if the final name does not exist.
pub(crate) const NAMEI_CREATE: u32 = 1 << 4;
/// Win32 case-folded comparison. Personality-specific but routed
/// through the same async walker.
pub(crate) const NAMEI_CASE_INSENSITIVE: u32 = 1 << 5;
/// Final-component-only nofollow (POSIX `lstat` semantics).
/// Distinct from `NAMEI_NOFOLLOW_ANY` because mid-walk symlinks
/// must still be followed.
pub(crate) const NAMEI_NOFOLLOW_FINAL: u32 = 1 << 6;

/// Maximum depth of symlink resolution before returning
/// `VfsError::Loop`. Matches POSIX SYMLOOP_MAX of 8.
pub(crate) const NAMEI_SYMLINK_MAX_DEPTH: u32 = 8;

// =========================================================================
// Shared `..` walk
// =========================================================================

/// Resolve `..` starting at `vnode_h`.
///
/// The structural cases (namespace root and mounted filesystem
/// roots) complete immediately. The ordinary directory case falls
/// through to the backend's `lookup("..")`, so the helper returns a
/// `VopControl` and can be used directly by the async path walker
/// without losing a parked backend operation.
pub(crate) unsafe fn walk_dotdot(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
    root_vkey: VnodeKey,
) -> VfsResult<VopControl<VnodeHandle>> {
    unsafe {
        // Pull every read-only field from the live arena up front so
        // the subsequent VOP dispatch can borrow `&mut VfsState`.
        let (is_ns_root, mount_h_opt, ops_ptr) = {
            let vnode = state.vnodes.get(vnode_h).ok_or(VfsError::Io)?;
            let is_ns_root = root_vkey.is_valid() && vnode.key == root_vkey;
            let mount_h = if (vnode.flags & VN_ROOT) != 0 && vnode.mount.is_valid() {
                Some(vnode.mount)
            } else {
                None
            };
            (is_ns_root, mount_h, vnode.ops)
        };

        if is_ns_root {
            return Ok(Ready(vnode_h));
        }

        // Mount root: rebound to the covered vnode in the parent
        // mount. The covered_key is the composite identity; resolve
        // it via the resolver cache or a direct arena scan.
        if let Some(mount_h) = mount_h_opt {
            let covered_key = state
                .mounts
                .get(mount_h)
                .map(|m| m.covered_key)
                .ok_or(VfsError::Io)?;
            if !covered_key.is_valid() {
                return Ok(Ready(vnode_h));
            }
            if let Some(covered_vh) = state.lookup_resolve_cache(covered_key) {
                return Ok(Ready(covered_vh));
            }
            // Cache miss: linear-scan the vnode arena for the
            // covered_key. The mount tree is small (one entry per
            // active mount) so this is bounded by mount count, not
            // file count.
            let mut found = VnodeHandle::INVALID;
            state.vnodes.for_each_active(|vh, vnode| {
                if vnode.key == covered_key {
                    found = vh;
                    false
                } else {
                    true
                }
            });
            if found.is_valid() {
                return Ok(Ready(found));
            }
            return Ok(Ready(vnode_h));
        }

        if ops_ptr.is_null() {
            return Err(VfsError::Io);
        }
        let mut vop_ctx = OwnerVopCtx::from_state(state, vnode_h).ok_or(VfsError::Io)?;
        ((*ops_ptr).meta.lookup)(&mut vop_ctx, b"..".as_ptr(), 2)
    }
}

// =========================================================================
// Mount-coverage traversal — sync form
// =========================================================================

/// Follow the `covered_by` chain starting at `vnode_h`. Returns the
/// effective leaf — the deepest mount root reachable via mount
/// transparency. Mirror of `namei_async::chase_covering_mounts`
/// for sync code paths (POSIX socket address resolution, Win32
/// drive letter chase) that do not need to park.
pub(crate) fn cross_covered(state: &VfsState, vnode_h: VnodeHandle) -> VnodeHandle {
    let mut cur = vnode_h;
    loop {
        let Some(mount_h) = crate::core::mount_ctl::covering_mount_for_vnode(state, cur) else {
            return cur;
        };
        let Some(mount) = state.mounts.get(mount_h) else {
            return cur;
        };
        if !mount.root.is_valid() {
            return cur;
        }
        if mount.root == cur {
            // Defensive guard against self-covering loops.
            return cur;
        }
        cur = mount.root;
    }
}

// =========================================================================
// Personality discriminator — selects POSIX vs Win32 namei rules
// =========================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameiPersonality {
    Posix = 0,
    Win32 = 1,
}

#[inline]
pub(crate) fn personality_from_flags(flags: u32) -> NameiPersonality {
    if (flags & NAMEI_CASE_INSENSITIVE) != 0 {
        NameiPersonality::Win32
    } else {
        NameiPersonality::Posix
    }
}

// =========================================================================
// Helpers shared with async walker
// =========================================================================

/// Test whether `kind` represents a directory — the sole permitted
/// terminal type when the caller passed `NAMEI_DIRECTORY`.
#[inline]
pub(crate) fn is_directory(kind: VnodeKind) -> bool {
    matches!(kind, VnodeKind::Directory)
}

/// Test whether `kind` represents a symbolic link — controls the
/// "should we issue a readlink?" branch in the async walker.
#[inline]
pub(crate) fn is_symlink(kind: VnodeKind) -> bool {
    matches!(kind, VnodeKind::Symlink)
}
