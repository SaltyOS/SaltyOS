// SPDX-License-Identifier: GPL-2.0-only
//! POSIX path resolution (`namei`).
//!
//! Implements the standard POSIX path walk: slash-separated components,
//! case-sensitive lookup, `..` crossing mount boundaries, symbolic link
//! resolution (up to `NAMEI_SYMLINK_MAX_DEPTH`), and mount-coverage
//! traversal.
//!
//! Uses the common helpers from `vfs_core::namei_common` (`walk_dotdot`,
//! `cross_covered`, `lookup_component`, `readlink_vnode`) and delegates
//! single-component lookup through `VopMetaOps::lookup` via `VopContext`.

use crate::server::consts::MAX_PATH_LEN;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::namei_common::{
    NAMEI_CREATE, NAMEI_DIRECTORY, NAMEI_FOLLOW, NAMEI_NOFOLLOW_ANY, NAMEI_NOFOLLOW_FINAL,
    NAMEI_SYMLINK_MAX_DEPTH, NameiArgs, NameiCtx, NameiResult, cross_covered, finish_namei,
    lookup_component, mount_nosymfollow, readlink_vnode, vnode_vtype, walk_dotdot,
};
use crate::vfs_core::vnode::{VT_DIR, VT_LNK, VnodeHandle};

/// POSIX path resolution.
///
/// Walks the path described by `args`, resolving each slash-delimited
/// component through `VopMetaOps::lookup`. Handles `.`, `..`, symlinks,
/// mount-point crossing, and the `NAMEI_*` flag set.
///
/// On success the returned `NameiResult` contains:
/// - `vp`: the resolved vnode handle, or `VnodeHandle::INVALID` when
///   `NAMEI_CREATE` is set and the final component is missing.
/// - `dvp`: the parent directory handle when `NAMEI_WANTPARENT` is set.
/// - `last_name` / `last_name_len`: final component pointer+length (into
///   `args.path` or a symlink scratch buffer).
///
/// # Safety
///
/// `args.path` must point to `args.path_len` readable bytes.
pub(crate) fn namei_posix(ctx: &mut NameiCtx<'_>, args: &NameiArgs) -> VfsResult<NameiResult> {
    namei_posix_inner(ctx, args, 0)
}

/// Inner walk with symlink depth tracking.
fn namei_posix_inner(
    ctx: &mut NameiCtx<'_>,
    args: &NameiArgs,
    sym_depth: u32,
) -> VfsResult<NameiResult> {
    let path = args.path;
    let path_len = args.path_len as usize;
    let flags = args.flags;

    if path.is_null() || path_len == 0 {
        return Err(VfsError::Inval);
    }

    // ---- Determine starting vnode ----
    let mut vp: VnodeHandle;

    if unsafe { *path } == b'/' {
        // Absolute path — start from the namespace root vnode.
        if !args.root.is_valid() {
            return Err(VfsError::Io);
        }
        vp = args.root;
    } else {
        // Relative path — use the caller's start handle.
        vp = args.start;
    }

    // Handle bare "/" — just return the root.
    if path_len == 1 && unsafe { *path } == b'/' {
        let mut res = NameiResult::empty();
        res.vp = vp;
        res.last_name = path;
        res.last_name_len = 1;
        return Ok(res);
    }

    let mut pos: usize = 0;

    // Skip leading slashes for absolute paths.
    while pos < path_len && unsafe { *path.add(pos) } == b'/' {
        pos += 1;
    }

    // Symlink scratch buffer — used when we need to concatenate a
    // symlink target with the remaining path tail.
    let mut sym_buf = [0u8; MAX_PATH_LEN];

    // ---- Main component loop ----
    while pos < path_len {
        // Parse next component: advance past non-'/' bytes.
        let comp_start = pos;
        while pos < path_len && unsafe { *path.add(pos) } != b'/' {
            pos += 1;
        }
        let comp_len = pos - comp_start;

        // Skip trailing slashes after this component.
        while pos < path_len && unsafe { *path.add(pos) } == b'/' {
            pos += 1;
        }

        let is_last = pos >= path_len;

        // Empty component (consecutive slashes) — skip.
        if comp_len == 0 {
            continue;
        }

        // ---- "." — stay at current vnode ----
        if comp_len == 1 && unsafe { *path.add(comp_start) } == b'.' {
            if is_last && (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
                return Err(VfsError::NotDir);
            }
            if is_last {
                vp = cross_covered(ctx, vp)?;
                return finish_namei(
                    vp,
                    VnodeHandle::INVALID,
                    unsafe { path.add(comp_start) },
                    1,
                    flags,
                );
            }
            continue;
        }

        // ---- ".." — walk up ----
        if comp_len == 2
            && unsafe { *path.add(comp_start) } == b'.'
            && unsafe { *path.add(comp_start + 1) } == b'.'
        {
            vp = walk_dotdot(ctx, vp, args.root)?;
            if is_last {
                if (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
                    return Err(VfsError::NotDir);
                }
                return finish_namei(
                    vp,
                    VnodeHandle::INVALID,
                    unsafe { path.add(comp_start) },
                    2,
                    flags,
                );
            }
            continue;
        }

        // ---- Regular component lookup ----

        // The current vnode must be a directory to descend into.
        if vnode_vtype(ctx, vp)? != VT_DIR {
            return Err(VfsError::NotDir);
        }

        // Cross into a covering mount before looking up the component.
        vp = cross_covered(ctx, vp)?;

        // Perform a single-component lookup via VopMetaOps::lookup.
        let comp_ptr = unsafe { path.add(comp_start) };
        let result = lookup_component(ctx, vp, comp_ptr, comp_len as u8);

        match result {
            Ok(child) if !child.is_valid() => {
                // ENOENT — lookup returned Ok(INVALID).
                if is_last && (flags & NAMEI_CREATE) != 0 {
                    let mut res = NameiResult::empty();
                    res.dvp = vp;
                    res.last_name = comp_ptr;
                    res.last_name_len = comp_len as u8;
                    return Ok(res);
                }
                return Err(VfsError::NotFound);
            }
            Ok(child) => {
                let dvp = vp;
                vp = child;

                // ---- Symbolic link handling ----
                if vnode_vtype(ctx, vp)? == VT_LNK {
                    let should_follow = if is_last {
                        (flags & NAMEI_FOLLOW) != 0
                            && (flags & NAMEI_NOFOLLOW_ANY) == 0
                            && (flags & NAMEI_NOFOLLOW_FINAL) == 0
                    } else {
                        (flags & NAMEI_NOFOLLOW_ANY) == 0
                    };

                    let mount_nosym = mount_nosymfollow(ctx, vp);

                    if should_follow && !mount_nosym {
                        if sym_depth >= NAMEI_SYMLINK_MAX_DEPTH {
                            return Err(VfsError::Loop);
                        }

                        // Read the symlink target.
                        let mut target_buf = [0u8; MAX_PATH_LEN];
                        let target_len = readlink_vnode(
                            ctx,
                            vp,
                            target_buf.as_mut_ptr(),
                            MAX_PATH_LEN,
                            &args.cred,
                        )?;

                        if target_len == 0 {
                            return Err(VfsError::Io);
                        }

                        // Build the new path: target + "/" + remaining.
                        let remaining = path_len - pos;
                        let new_len = target_len + if remaining > 0 { 1 + remaining } else { 0 };
                        if new_len > MAX_PATH_LEN {
                            return Err(VfsError::NameTooLong);
                        }

                        for i in 0..target_len {
                            sym_buf[i] = target_buf[i];
                        }
                        if remaining > 0 {
                            sym_buf[target_len] = b'/';
                            for i in 0..remaining {
                                sym_buf[target_len + 1 + i] = unsafe { *path.add(pos + i) };
                            }
                        }

                        // Determine the new start vnode for the recursive walk.
                        let new_start = if target_buf[0] == b'/' {
                            // Absolute symlink target — start from namespace root.
                            if !args.root.is_valid() {
                                return Err(VfsError::Io);
                            }
                            args.root
                        } else {
                            // Relative symlink target — start from parent dir.
                            dvp
                        };

                        let inner_args = NameiArgs {
                            start: new_start,
                            path: sym_buf.as_ptr(),
                            path_len: new_len as u16,
                            flags,
                            cred: args.cred,
                            root: args.root,
                        };
                        return namei_posix_inner(ctx, &inner_args, sym_depth + 1);
                    }

                    // Not following the symlink (lstat / O_NOFOLLOW).
                    if is_last {
                        return finish_namei(vp, dvp, comp_ptr, comp_len as u8, flags);
                    }
                    // Intermediate non-followed symlink is an error — cannot
                    // traverse through a non-directory.
                    return Err(VfsError::NotDir);
                }

                // ---- Non-symlink child ----

                // If this is the last component, we're done.
                if is_last {
                    vp = cross_covered(ctx, vp)?;
                    if (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
                        return Err(VfsError::NotDir);
                    }
                    return finish_namei(vp, dvp, comp_ptr, comp_len as u8, flags);
                }

                // Not the last component — continue with child as current.
                // No vrele needed — handles are lightweight identity tokens.
            }
            Err(e) => {
                // Lookup error on an intermediate or final component.
                if is_last && (flags & NAMEI_CREATE) != 0 && e == VfsError::NotFound {
                    let mut res = NameiResult::empty();
                    res.dvp = vp;
                    res.last_name = comp_ptr;
                    res.last_name_len = comp_len as u8;
                    return Ok(res);
                }
                return Err(e);
            }
        }
    }

    // Walked the entire path without hitting a return — the final vnode
    // is the target. This happens when the path ended with trailing
    // slashes (all consumed by the skip-slash loop).
    vp = cross_covered(ctx, vp)?;
    if (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
        return Err(VfsError::NotDir);
    }

    let mut res = NameiResult::empty();
    res.vp = vp;
    Ok(res)
}
