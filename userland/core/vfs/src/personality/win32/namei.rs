// SPDX-License-Identifier: GPL-2.0-only
//! Win32 path resolution (`namei`).
//!
//! Implements the Win32 path walk: backslash-or-slash separated components,
//! case-insensitive lookup (exact first, then `lookup_ci` fallback),
//! drive letter roots, reserved device name interception, trailing
//! dot/space stripping, forbidden character rejection, and `\\?\`/`\\.\`
//! prefix handling.
//!
//! Uses the common helpers from `vfs_core::namei_common` (`walk_dotdot`,
//! `cross_covered_personality`, `lookup_component`, `lookup_component_ci`)
//! and delegates single-component lookup through `VopMetaOps` via
//! `VopContext`.
//!
//! ## Win32 path grammar
//!
//! ```text
//! path = [prefix] [drive ":"] separator? components
//! prefix = "\\?\" | "\\.\"
//! drive = [A-Za-z]
//! separator = "\" | "/"
//! components = component (separator component)*
//! ```
//!
//! ## Case-insensitive lookup strategy
//!
//! For each component, `namei_win32` performs a two-phase lookup:
//! 1. **Exact lookup** via `VopMetaOps::lookup` — O(1) for hash-indexed
//!    backends, catches the common case where the caller's casing matches
//!    the on-disk casing.
//! 2. **CI fallback** via `VopMetaOps::lookup_ci` — only if the exact
//!    lookup returns ENOENT. `lookup_ci` defaults to a `readdir` scan
//!    with Unicode Simple Case-Folding but can be overridden by
//!    filesystems with a native CI index (saltyfs `SALTY_INODE_CASEFOLD`).

use crate::server::consts::MAX_PATH_LEN;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::namei_common::{
    cross_covered_personality, finish_namei, lookup_component, lookup_component_ci,
    mount_nosymfollow, readlink_vnode, vnode_vtype, walk_dotdot, NameiArgs, NameiCtx, NameiResult,
    NAMEI_CREATE, NAMEI_DIRECTORY, NAMEI_FOLLOW, NAMEI_NOFOLLOW_ANY, NAMEI_NOFOLLOW_FINAL,
    NAMEI_SYMLINK_MAX_DEPTH,
};
use crate::vfs_core::vnode::{VnodeHandle, VT_DIR, VT_LNK};

use super::casefold::drive_letter_index;
use super::drives::resolve_drive_root;
use super::path::{
    check_path_length, normalize_separators, strip_nt_prefix, trim_trailing_dots_spaces,
    validate_no_forbidden_chars,
};
use super::reserved;

/// Win32 path resolution.
///
/// Walks the path described by `args`, resolving each component through
/// Win32 semantics: case-insensitive, drive-letter aware, reserved-name
/// intercepting.
///
/// On success the returned `NameiResult` contains:
/// - `vp`: the resolved vnode handle, or `VnodeHandle::INVALID` when
///   `NAMEI_CREATE` is set and the final component is missing.
/// - `dvp`: the parent directory handle when `NAMEI_WANTPARENT` is set.
/// - `last_name` / `last_name_len`: final component pointer+length.
///
/// # Safety
///
/// `args.path` must point to `args.path_len` readable bytes.
pub(crate) fn namei_win32(ctx: &NameiCtx<'_>, args: &NameiArgs) -> VfsResult<NameiResult> {
    namei_win32_inner(ctx, args, 0)
}

/// Inner walk with symlink depth tracking.
fn namei_win32_inner(
    ctx: &NameiCtx<'_>,
    args: &NameiArgs,
    sym_depth: u32,
) -> VfsResult<NameiResult> {
    let path = args.path;
    let path_len = args.path_len as usize;
    let flags = args.flags;

    if path.is_null() || path_len == 0 {
        return Err(VfsError::Inval);
    }

    // ---- Phase 1: Canonicalization ----

    // Check for \\?\ or \\.\ prefix.
    let prefix = unsafe { strip_nt_prefix(path, path_len) };
    let is_verbatim = prefix.is_verbatim;
    let content_offset = prefix.offset;
    let content_ptr = unsafe { path.add(content_offset) };
    let content_len = path_len - content_offset;

    // \\.\pipe\<name> — route to pipefs root and walk the pipe name
    // from there. The prefix detector already consumed "\\.\pipe\",
    // so content_ptr points at the pipe name.
    if prefix.is_pipe_ns {
        return resolve_pipe_path(ctx, args, content_ptr, content_len, flags);
    }

    // Normalize separators (backslash → slash, collapse runs).
    let mut norm_buf = [0u8; MAX_PATH_LEN];
    let norm_len = if content_len > MAX_PATH_LEN {
        return Err(VfsError::NameTooLong);
    } else {
        unsafe { normalize_separators(content_ptr, content_len, norm_buf.as_mut_ptr()) }
    };

    // Check path length against Win32 limits.
    check_path_length(norm_len, prefix.had_prefix)?;

    if norm_len == 0 {
        return Err(VfsError::Inval);
    }

    let norm = &norm_buf[..norm_len];

    // ---- Phase 2: Determine starting vnode ----

    let mut vp: VnodeHandle;
    let mut pos: usize = 0;

    // Check for drive letter prefix: X:/ or X:
    if norm_len >= 2 && norm[1] == b':' {
        if let Some(drive_idx) = drive_letter_index(norm[0]) {
            vp = match unsafe { resolve_drive_root(drive_idx) } {
                Some(root) => root,
                None => return Err(VfsError::NotFound),
            };
            pos = 2;
            // Skip separator after drive letter.
            if pos < norm_len && norm[pos] == b'/' {
                pos += 1;
            }
        } else {
            // Not a valid drive letter — treat as relative path.
            vp = args.start;
        }
    } else if norm[0] == b'/' {
        // Absolute path without drive letter — start from namespace root.
        if !args.root.is_valid() {
            return Err(VfsError::Io);
        }
        vp = args.root;
        pos = 1;
        // Skip additional leading slashes.
        while pos < norm_len && norm[pos] == b'/' {
            pos += 1;
        }
    } else {
        // Relative path — use the caller's start handle.
        vp = args.start;
    }

    // Handle bare path (just drive letter "C:" or "/" with nothing after).
    if pos >= norm_len {
        let mut res = NameiResult::empty();
        res.vp = vp;
        // Point last_name at the normalized path start for the drive letter.
        res.last_name = norm_buf.as_ptr();
        res.last_name_len = if norm_len > 0 { 1 } else { 0 };
        return Ok(res);
    }

    // ---- Phase 3: Component-by-component walk ----

    // Symlink scratch buffer.
    let mut sym_buf = [0u8; MAX_PATH_LEN];

    while pos < norm_len {
        // Parse next component.
        let comp_start = pos;
        while pos < norm_len && norm[pos] != b'/' {
            pos += 1;
        }
        let raw_comp = &norm[comp_start..pos];

        // Skip trailing slashes.
        while pos < norm_len && norm[pos] == b'/' {
            pos += 1;
        }

        let is_last = pos >= norm_len;

        // Empty component (consecutive slashes) — skip.
        if raw_comp.is_empty() {
            continue;
        }

        // Trim trailing dots and spaces (unless verbatim \\?\ path).
        let comp = if is_verbatim {
            raw_comp
        } else {
            trim_trailing_dots_spaces(raw_comp)
        };

        // After trimming, component may be empty.
        if comp.is_empty() {
            if is_last {
                // Trailing dots/spaces only — treat as current dir.
                if (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
                    return Err(VfsError::NotDir);
                }
                let mut res = NameiResult::empty();
                res.vp = vp;
                return Ok(res);
            }
            continue;
        }

        // Validate no forbidden characters (unless verbatim).
        if !is_verbatim {
            validate_no_forbidden_chars(comp)?;
        }

        // ---- "." — stay at current vnode ----
        if comp.len() == 1 && comp[0] == b'.' {
            if is_last && (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
                return Err(VfsError::NotDir);
            }
            if is_last {
                vp = cross_covered_personality(ctx, vp, true)?;
                return finish_namei(
                    vp,
                    VnodeHandle::INVALID,
                    unsafe { norm_buf.as_ptr().add(comp_start) },
                    1,
                    flags,
                );
            }
            continue;
        }

        // ---- ".." — walk up ----
        if comp.len() == 2 && comp[0] == b'.' && comp[1] == b'.' {
            vp = walk_dotdot(ctx, vp, args.root)?;
            if is_last {
                if (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
                    return Err(VfsError::NotDir);
                }
                return finish_namei(
                    vp,
                    VnodeHandle::INVALID,
                    unsafe { norm_buf.as_ptr().add(comp_start) },
                    2,
                    flags,
                );
            }
            continue;
        }

        // ---- Reserved device name interception ----
        if !is_verbatim {
            if let Some(dev) = reserved::intercept(comp) {
                let dev_vp = lookup_devfs_device(ctx, args.root, reserved::devfs_name(dev));
                if let Some(dev_vp) = dev_vp {
                    if is_last {
                        return finish_namei(
                            dev_vp,
                            VnodeHandle::INVALID,
                            unsafe { norm_buf.as_ptr().add(comp_start) },
                            comp.len() as u8,
                            flags,
                        );
                    }
                    // Reserved devices are not directories — can't traverse further.
                    return Err(VfsError::NotDir);
                }
                // If devfs lookup fails, fall through to normal lookup.
            }
        }

        // ---- Regular component lookup ----

        // Current vnode must be a directory.
        if vnode_vtype(ctx, vp)? != VT_DIR {
            return Err(VfsError::NotDir);
        }

        // Cross into a covering mount (skip MNT_POSIX_ONLY mounts).
        vp = cross_covered_personality(ctx, vp, true)?;

        // Two-phase lookup: exact first, then case-insensitive.
        let comp_ptr = comp.as_ptr();
        let comp_len_u8 = comp.len() as u8;
        let result = lookup_component(ctx, vp, comp_ptr, comp_len_u8);

        let lookup_result = match result {
            Ok(child) if child.is_valid() => Ok(child),
            Ok(_invalid) => {
                // Exact lookup returned ENOENT — try CI fallback.
                lookup_component_ci(ctx, vp, comp_ptr, comp_len_u8)
            }
            Err(VfsError::NotFound) => {
                // Exact lookup error ENOENT — try CI fallback.
                lookup_component_ci(ctx, vp, comp_ptr, comp_len_u8)
            }
            Err(e) => Err(e),
        };

        match lookup_result {
            Ok(child) if !child.is_valid() => {
                // ENOENT after both exact and CI lookup.
                if is_last && (flags & NAMEI_CREATE) != 0 {
                    let mut res = NameiResult::empty();
                    res.dvp = vp;
                    res.last_name = unsafe { norm_buf.as_ptr().add(comp_start) };
                    res.last_name_len = comp.len() as u8;
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

                        // Build new path: target + "/" + remaining.
                        let remaining = norm_len - pos;
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
                                sym_buf[target_len + 1 + i] = norm[pos + i];
                            }
                        }

                        let new_start = if target_buf[0] == b'/' {
                            if !args.root.is_valid() {
                                return Err(VfsError::Io);
                            }
                            args.root
                        } else {
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
                        return namei_win32_inner(ctx, &inner_args, sym_depth + 1);
                    }

                    // Not following symlink.
                    if is_last {
                        return finish_namei(
                            vp,
                            dvp,
                            unsafe { norm_buf.as_ptr().add(comp_start) },
                            comp.len() as u8,
                            flags,
                        );
                    }
                    return Err(VfsError::NotDir);
                }

                // ---- Non-symlink child ----
                if is_last {
                    vp = cross_covered_personality(ctx, vp, true)?;
                    if (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
                        return Err(VfsError::NotDir);
                    }
                    return finish_namei(
                        vp,
                        dvp,
                        unsafe { norm_buf.as_ptr().add(comp_start) },
                        comp.len() as u8,
                        flags,
                    );
                }

                // Not last — continue with child as current.
            }
            Err(e) => {
                if is_last && (flags & NAMEI_CREATE) != 0 && e == VfsError::NotFound {
                    let mut res = NameiResult::empty();
                    res.dvp = vp;
                    res.last_name = unsafe { norm_buf.as_ptr().add(comp_start) };
                    res.last_name_len = comp.len() as u8;
                    return Ok(res);
                }
                return Err(e);
            }
        }
    }

    // Walked entire path — final vnode is the target.
    vp = cross_covered_personality(ctx, vp, true)?;
    if (flags & NAMEI_DIRECTORY) != 0 && vnode_vtype(ctx, vp)? != VT_DIR {
        return Err(VfsError::NotDir);
    }

    let mut res = NameiResult::empty();
    res.vp = vp;
    Ok(res)
}

/// Resolve a `\\.\pipe\<name>` path by routing to the pipefs root vnode.
///
/// The caller has already consumed the `\\.\pipe\` prefix — `pipe_path`
/// points at the remaining pipe name (e.g. `mypipe` for `\\.\pipe\mypipe`).
fn resolve_pipe_path(
    ctx: &NameiCtx<'_>,
    args: &NameiArgs,
    pipe_path: *const u8,
    pipe_len: usize,
    flags: u32,
) -> VfsResult<NameiResult> {
    let pipefs_root = lookup_pipefs_root(ctx, args.root).ok_or(VfsError::NotFound)?;

    if pipe_len == 0 {
        // Bare \\.\pipe — return the pipefs root directory.
        let mut res = NameiResult::empty();
        res.vp = pipefs_root;
        return Ok(res);
    }

    // Walk the pipe name under the pipefs root using a sub-namei call.
    let inner_args = NameiArgs {
        start: pipefs_root,
        path: pipe_path,
        path_len: pipe_len as u16,
        flags,
        cred: args.cred,
        root: args.root,
    };
    namei_win32_inner(ctx, &inner_args, 0)
}

/// Locate the pipefs root vnode by walking `/pipe` from the VFS root.
///
/// Walks `args.root` → cross mount → lookup "pipe" → cross mount to reach
/// the pipefs root. Returns the pipefs root vnode handle, or `None` if
/// pipefs is not mounted.
fn lookup_pipefs_root(ctx: &NameiCtx<'_>, root_vh: VnodeHandle) -> Option<VnodeHandle> {
    if !root_vh.is_valid() {
        return None;
    }
    let root = cross_covered_personality(ctx, root_vh, true).ok()?;
    let pipe_dir = lookup_component(ctx, root, b"pipe".as_ptr(), 4).ok()?;
    if !pipe_dir.is_valid() {
        return None;
    }
    let pipe_root = cross_covered_personality(ctx, pipe_dir, true).ok()?;
    Some(pipe_root)
}

/// Look up a device by name in devfs.
///
/// Walks from the root vnode to `/dev` and performs an exact lookup of
/// `device_name`. Returns the device vnode handle, or `None` if the
/// device cannot be found.
///
/// This is used by the reserved device name intercept to redirect names
/// like `CON` → `/dev/console`, `NUL` → `/dev/null`, etc.
fn lookup_devfs_device(
    ctx: &NameiCtx<'_>,
    root_vh: VnodeHandle,
    device_name: &[u8],
) -> Option<VnodeHandle> {
    if !root_vh.is_valid() || device_name.is_empty() {
        return None;
    }
    let root = cross_covered_personality(ctx, root_vh, true).ok()?;
    let dev_dir = lookup_component(ctx, root, b"dev".as_ptr(), 3).ok()?;
    if !dev_dir.is_valid() {
        return None;
    }
    let dev_root = cross_covered_personality(ctx, dev_dir, true).ok()?;
    let device =
        lookup_component(ctx, dev_root, device_name.as_ptr(), device_name.len() as u8).ok()?;
    if !device.is_valid() {
        return None;
    }
    Some(device)
}
