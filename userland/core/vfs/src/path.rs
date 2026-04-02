// SPDX-License-Identifier: GPL-2.0-only
//! Path resolution with symlink following and mount point detection.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::client::get_client;
use crate::consts::*;
use crate::fileops::normalize_path_for_client;
use crate::ramfs::{dir_find_entry, inode_by_ino};
use crate::types::*;

fn proc_dirlike(dev_type: u8) -> bool {
    matches!(dev_type, PROC_FILE_ROOT | PROC_FILE_PID_DIR | PROC_FILE_NET_DIR)
}

/// Check if a dirfd refers to a mount FD. Returns (mount_idx, dir_remote_ino) if so.
pub(crate) unsafe fn resolve_at_mount(badge: u64, dirfd: i32) -> Option<(usize, u64)> {
    unsafe {
        if dirfd < 0 || dirfd == AT_FDCWD_VAL {
            return None;
        }
        let cli = get_client(badge);
        if cli.is_null() {
            return None;
        }
        if dirfd >= (*cli).objects_cap as i32 {
            return None;
        }
        let fde = &*(*cli).objects.add(dirfd as usize);
        let ext = &*(*cli).posix_ext.add(dirfd as usize);
        if fde.active == 0 {
            return None;
        }
        if fde.obj_type == OBJ_TYPE_MOUNT {
            Some((ext.mount_idx as usize, ext.mount_remote_ino))
        } else {
            None
        }
    }
}

/// Read the symlink target from an inode.
/// For writable symlinks, target is in rw_data (symlink pool).
/// For readonly (CPIO) symlinks, target is in ro_data.
/// Returns the target pointer and length.
pub(crate) unsafe fn symlink_target(inode: *const RamfsInode) -> (*const u8, u8) {
    unsafe {
        if !(*inode).rw_data.is_null() {
            return ((*inode).rw_data as *const u8, (*inode).size as u8);
        }
        if !(*inode).ro_data.is_null() {
            return ((*inode).ro_data, (*inode).size as u8);
        }
        (core::ptr::null(), 0)
    }
}

/// Inner path resolution with symlink following.
/// `follow_final`: if true, follow symlink on the last component.
/// `depth`: recursion depth for cycle detection (max 8).
unsafe fn resolve_path_raw_inner(
    path: *const u8,
    path_len: u8,
    follow_final: bool,
    depth: u8,
) -> *mut RamfsInode {
    unsafe {
        if path_len == 0 || depth > 8 {
            return core::ptr::null_mut();
        }

        let mut current = inode_by_ino(ROOT_INO);
        if current.is_null() {
            return core::ptr::null_mut();
        }

        if path_len == 1 && *path == b'/' {
            return current;
        }

        let mut pos: usize = 0;
        if *path == b'/' {
            pos = 1;
        }

        let plen = path_len as usize;
        while pos < plen {
            let is_proc_dir = (*current).ftype == FTYPE_PROC_FILE && proc_dirlike((*current).dev_type);
            if (*current).ftype != FTYPE_DIRECTORY && (*current).ftype != FTYPE_MOUNT_POINT && !is_proc_dir {
                return core::ptr::null_mut();
            }

            // Mount point with remaining path: return the mount point itself.
            // The caller (handle_open etc.) detects FTYPE_MOUNT_POINT and proxies.
            if (*current).ftype == FTYPE_MOUNT_POINT {
                return current;
            }

            let start = pos;
            while pos < plen && *path.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - start;
            if comp_len == 0 {
                pos += 1;
                continue;
            }

            if pos < plen && *path.add(pos) == b'/' {
                pos += 1;
            }

            if comp_len == 1 && *path.add(start) == b'.' {
                continue;
            }
            if comp_len == 2 && *path.add(start) == b'.' && *path.add(start + 1) == b'.' {
                current = inode_by_ino((*current).parent_ino);
                if current.is_null() {
                    current = inode_by_ino(ROOT_INO);
                    if current.is_null() {
                        return core::ptr::null_mut();
                    }
                }
                continue;
            }

            let de = dir_find_entry(current, path.add(start), comp_len as u8);
            if de.is_null() {
                return core::ptr::null_mut();
            }

            current = inode_by_ino((*de).ino);
            if current.is_null() {
                return core::ptr::null_mut();
            }

            // Check if this component is a symlink
            if (*current).ftype == FTYPE_SYMLINK {
                let is_last = pos >= plen;
                if is_last && !follow_final {
                    // Return the symlink inode itself (for lstat/readlink)
                    return current;
                }
                // Follow the symlink
                let (target, target_len) = symlink_target(current);
                if target.is_null() || target_len == 0 {
                    return core::ptr::null_mut();
                }
                if pos >= plen {
                    // Last component: just resolve target
                    return resolve_path_raw_inner(target, target_len, true, depth + 1);
                }
                // Not last component: concatenate target + remaining path
                let remaining_len = plen - pos;
                let total = target_len as usize + 1 + remaining_len; // target + "/" + rest
                if total >= MAX_PATH_LEN {
                    return core::ptr::null_mut();
                }
                let mut combined = [0u8; MAX_PATH_LEN];
                for i in 0..target_len as usize {
                    combined[i] = *target.add(i);
                }
                combined[target_len as usize] = b'/';
                for i in 0..remaining_len {
                    combined[target_len as usize + 1 + i] = *path.add(pos + i);
                }
                return resolve_path_raw_inner(
                    combined.as_ptr(),
                    total as u8,
                    follow_final,
                    depth + 1,
                );
            }
        }

        current
    }
}

pub(crate) unsafe fn resolve_path_raw(path: *const u8, path_len: u8) -> *mut RamfsInode {
    unsafe { resolve_path_raw_inner(path, path_len, true, 0) }
}

/// Resolve path without following the final symlink component.
pub(crate) unsafe fn resolve_path_raw_nofollow(path: *const u8, path_len: u8) -> *mut RamfsInode {
    unsafe { resolve_path_raw_inner(path, path_len, false, 0) }
}

pub(crate) fn is_initrd_prefixed_path(path: *const u8, path_len: u8) -> bool {
    unsafe {
        const PREFIX: &[u8] = b"/initrd";
        let plen = path_len as usize;
        if plen < PREFIX.len() {
            return false;
        }
        for (i, b) in PREFIX.iter().enumerate() {
            if *path.add(i) != *b {
                return false;
            }
        }
        plen == PREFIX.len() || *path.add(PREFIX.len()) == b'/'
    }
}

pub(crate) fn path_has_component_prefix(path: *const u8, path_len: u8, prefix: &[u8]) -> bool {
    unsafe {
        let plen = path_len as usize;
        if plen < prefix.len() {
            return false;
        }
        for (i, b) in prefix.iter().enumerate() {
            if *path.add(i) != *b {
                return false;
            }
        }
        plen == prefix.len() || *path.add(prefix.len()) == b'/'
    }
}

pub(crate) unsafe fn resolve_path(path: *const u8, path_len: u8) -> *mut RamfsInode {
    unsafe {
        let direct = resolve_path_raw(path, path_len);
        if !direct.is_null() {
            return direct;
        }

        // Root path fallback for immutable initrd command trees.
        // Keep this narrow so writable paths (/tmp, /dev, ...) are not remapped.
        let allow_fallback = path_has_component_prefix(path, path_len, b"/bin")
            || path_has_component_prefix(path, path_len, b"/usr");

        if allow_fallback && !is_initrd_prefixed_path(path, path_len) {
            const PREFIX: &[u8] = b"/initrd";
            let in_len = path_len as usize;
            let out_len = PREFIX.len() + in_len;
            if out_len <= MAX_PATH_LEN {
                let mut prefixed = [0u8; MAX_PATH_LEN];
                for (i, b) in PREFIX.iter().enumerate() {
                    prefixed[i] = *b;
                }
                for i in 0..in_len {
                    prefixed[PREFIX.len() + i] = *path.add(i);
                }
                return resolve_path_raw(prefixed.as_ptr(), out_len as u8);
            }
        }

        core::ptr::null_mut()
    }
}

pub(crate) unsafe fn resolve_parent(
    path: *const u8,
    path_len: u8,
    child_name: &mut *const u8,
    child_len: &mut u8,
) -> *mut RamfsInode {
    unsafe {
        if path_len == 0 {
            return core::ptr::null_mut();
        }

        let plen = path_len as usize;
        let mut last_slash: i32 = -1;
        for i in (0..plen).rev() {
            if *path.add(i) == b'/' {
                last_slash = i as i32;
                break;
            }
        }

        if last_slash < 0 {
            return core::ptr::null_mut();
        }

        let mut parent_buf = [0u8; MAX_PATH_LEN];
        let parent_len: u8;
        if last_slash == 0 {
            parent_buf[0] = b'/';
            parent_len = 1;
        } else {
            parent_len = last_slash as u8;
            for i in 0..parent_len as usize {
                parent_buf[i] = *path.add(i);
            }
        }

        *child_name = path.add(last_slash as usize + 1);
        *child_len = (plen - last_slash as usize - 1) as u8;

        // Strip trailing slash from child name
        while *child_len > 0 && *(*child_name).add(*child_len as usize - 1) == b'/' {
            *child_len -= 1;
        }

        resolve_path(parent_buf.as_ptr(), parent_len)
    }
}

/// Resolve a path starting from a given inode (for *at() semantics).
/// Absolute paths always start from ROOT_INO regardless of start_ino.
/// Empty path returns the start inode itself (for AT_EMPTY_PATH).
/// Follows intermediate and final symlinks.
pub(crate) unsafe fn resolve_path_from(
    start_ino: u32,
    path: *const u8,
    path_len: u8,
) -> *mut RamfsInode {
    unsafe { resolve_path_from_inner(start_ino, path, path_len, true, 0) }
}

/// Like `resolve_path_from` but does not follow the final symlink component.
pub(crate) unsafe fn resolve_path_from_nofollow(
    start_ino: u32,
    path: *const u8,
    path_len: u8,
) -> *mut RamfsInode {
    unsafe { resolve_path_from_inner(start_ino, path, path_len, false, 0) }
}

/// Inner implementation of *at()-style path resolution with symlink support.
/// `follow_final`: if true, follow symlink on the last component.
/// `depth`: recursion depth for cycle detection (max 8).
unsafe fn resolve_path_from_inner(
    start_ino: u32,
    path: *const u8,
    path_len: u8,
    follow_final: bool,
    depth: u8,
) -> *mut RamfsInode {
    unsafe {
        if depth > 8 {
            return core::ptr::null_mut();
        }

        if path_len == 0 {
            return inode_by_ino(start_ino);
        }

        // Absolute path always from root
        if *path == b'/' {
            return resolve_path_raw_inner(path, path_len, follow_final, depth);
        }

        // Relative path from start_ino
        let mut current = inode_by_ino(start_ino);
        if current.is_null() {
            return core::ptr::null_mut();
        }

        let mut pos: usize = 0;
        let plen = path_len as usize;
        while pos < plen {
            if (*current).ftype != FTYPE_DIRECTORY && (*current).ftype != FTYPE_MOUNT_POINT {
                return core::ptr::null_mut();
            }
            if (*current).ftype == FTYPE_MOUNT_POINT {
                return current;
            }

            let start = pos;
            while pos < plen && *path.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - start;
            if comp_len == 0 {
                pos += 1;
                continue;
            }

            if pos < plen && *path.add(pos) == b'/' {
                pos += 1;
            }

            // Handle "." — stay at current directory
            if comp_len == 1 && *path.add(start) == b'.' {
                continue;
            }
            // Handle ".." — move to parent
            if comp_len == 2 && *path.add(start) == b'.' && *path.add(start + 1) == b'.' {
                current = inode_by_ino((*current).parent_ino);
                if current.is_null() {
                    current = inode_by_ino(ROOT_INO);
                    if current.is_null() {
                        return core::ptr::null_mut();
                    }
                }
                continue;
            }

            let de = dir_find_entry(current, path.add(start), comp_len as u8);
            if de.is_null() {
                return core::ptr::null_mut();
            }

            current = inode_by_ino((*de).ino);
            if current.is_null() {
                return core::ptr::null_mut();
            }

            // Check if this component is a symlink
            if (*current).ftype == FTYPE_SYMLINK {
                let is_last = pos >= plen;
                if is_last && !follow_final {
                    return current;
                }
                let (target, target_len) = symlink_target(current);
                if target.is_null() || target_len == 0 {
                    return core::ptr::null_mut();
                }
                if pos >= plen {
                    // Last component: resolve the symlink target.
                    // Relative targets resolve from the symlink's parent directory.
                    if *target == b'/' {
                        return resolve_path_raw_inner(target, target_len, true, depth + 1);
                    } else {
                        return resolve_path_from_inner(
                            (*inode_by_ino((*current).parent_ino)).ino,
                            target,
                            target_len,
                            true,
                            depth + 1,
                        );
                    }
                }
                // Intermediate component: concatenate target + remaining path
                let remaining_len = plen - pos;
                let total = target_len as usize + 1 + remaining_len;
                if total >= MAX_PATH_LEN {
                    return core::ptr::null_mut();
                }
                let mut combined = [0u8; MAX_PATH_LEN];
                for i in 0..target_len as usize {
                    combined[i] = *target.add(i);
                }
                combined[target_len as usize] = b'/';
                for i in 0..remaining_len {
                    combined[target_len as usize + 1 + i] = *path.add(pos + i);
                }
                // Absolute symlink target: resolve from root
                if *target == b'/' {
                    return resolve_path_raw_inner(
                        combined.as_ptr(),
                        total as u8,
                        follow_final,
                        depth + 1,
                    );
                }
                // Relative symlink target: resolve from symlink's parent
                let parent = inode_by_ino((*current).parent_ino);
                if parent.is_null() {
                    return core::ptr::null_mut();
                }
                return resolve_path_from_inner(
                    (*parent).ino,
                    combined.as_ptr(),
                    total as u8,
                    follow_final,
                    depth + 1,
                );
            }
        }

        current
    }
}

/// Resolve parent directory from a given start inode (for *at() semantics).
/// If path is absolute, delegates to resolve_parent.
/// If path has no slash (pure filename), parent is start_ino.
pub(crate) unsafe fn resolve_parent_from(
    start_ino: u32,
    path: *const u8,
    path_len: u8,
    child_name: &mut *const u8,
    child_len: &mut u8,
) -> *mut RamfsInode {
    unsafe {
        if path_len == 0 {
            return core::ptr::null_mut();
        }

        // Absolute path — delegate to resolve_parent (always from root)
        if *path == b'/' {
            return resolve_parent(path, path_len, child_name, child_len);
        }

        let plen = path_len as usize;

        // Find last slash
        let mut last_slash: i32 = -1;
        for i in (0..plen).rev() {
            if *path.add(i) == b'/' {
                last_slash = i as i32;
                break;
            }
        }

        if last_slash < 0 {
            // No slash — path is just a filename, parent is start_ino
            *child_name = path;
            *child_len = path_len;
            while *child_len > 0 && *(*child_name).add(*child_len as usize - 1) == b'/' {
                *child_len -= 1;
            }
            return inode_by_ino(start_ino);
        }

        // Has a slash — resolve parent portion from start_ino
        let parent_len = last_slash as u8;
        *child_name = path.add(last_slash as usize + 1);
        *child_len = (plen - last_slash as usize - 1) as u8;
        while *child_len > 0 && *(*child_name).add(*child_len as usize - 1) == b'/' {
            *child_len -= 1;
        }

        resolve_path_from(start_ino, path, parent_len)
    }
}

/// Determine the start inode for an *at() call given dirfd and path.
/// Returns 0 on error.
pub(crate) unsafe fn resolve_at_start(
    badge: u64,
    dirfd: i32,
    path: *const u8,
    path_len: u8,
) -> u32 {
    unsafe {
        // Absolute path always starts from root
        if path_len > 0 && *path == b'/' {
            return ROOT_INO;
        }

        // AT_FDCWD: use client's cwd
        if dirfd == AT_FDCWD_VAL {
            let cli = get_client(badge);
            if cli.is_null() {
                return 0;
            }
            let mut cwd_len: u8 = 0;
            while (cwd_len as usize) < 128 && (*cli).cwd[cwd_len as usize] != 0 {
                cwd_len += 1;
            }
            if cwd_len == 0 {
                return ROOT_INO;
            }
            let inode = resolve_path((*cli).cwd.as_ptr(), cwd_len);
            if inode.is_null() {
                return 0; // Signal to handler: cwd not in ramfs
            }
            return (*inode).ino;
        }

        // dirfd: look up the caller's object table slot
        let cli = get_client(badge);
        if cli.is_null() {
            return 0;
        }
        if dirfd < 0
            || dirfd >= (*cli).objects_cap as i32
            || (*(*cli).objects.add(dirfd as usize)).active == 0
        {
            return 0;
        }
        (*(*cli).posix_ext.add(dirfd as usize)).inode
    }
}

/// Result of resolving a dirfd for an *at() operation.
pub(crate) enum AtResolution {
    /// dirfd refers to a ramfs inode (or absolute path -> ROOT_INO).
    Ramfs { start_ino: u32 },
    /// dirfd refers to a mount FD with the given mount index and remote dir inode.
    MountFd { mount_idx: usize, dir_rino: u64 },
    /// Resolution failed; reply error code has been set.
    Error,
}

/// Common helper encapsulating the repeated dirfd resolution pattern
/// used by all *at() handlers. On success returns either a Ramfs start_ino
/// or a MountFd pair. On AT_FDCWD fallback, rewrites `path`/`path_len`
/// to the normalized absolute path. On failure, sets reply error and returns
/// Error.
///
/// # Safety
/// `path` must point to a buffer of at least MAX_PATH_LEN bytes.
/// `reply` must be a valid mutable pointer to a TronaMsg.
pub(crate) unsafe fn resolve_at_base(
    badge: u64,
    dirfd: i32,
    path: *mut u8,
    path_len: &mut u8,
    reply: *mut TronaMsg,
) -> AtResolution {
    unsafe {
        let start_ino = resolve_at_start(badge, dirfd, path, *path_len);
        if start_ino != 0 {
            return AtResolution::Ramfs { start_ino };
        }

        // Check for mount FD
        if let Some((mi, dir_rino)) = resolve_at_mount(badge, dirfd) {
            return AtResolution::MountFd {
                mount_idx: mi,
                dir_rino,
            };
        }

        // AT_FDCWD with underlay cwd: normalize to absolute, rewrite path in place
        if dirfd == AT_FDCWD_VAL {
            let mut norm_buf = [0u8; MAX_PATH_LEN];
            if let Some((abs_ptr, abs_len)) =
                normalize_path_for_client(badge, path, *path_len, norm_buf.as_mut_ptr())
            {
                for i in 0..abs_len as usize {
                    *path.add(i) = *abs_ptr.add(i);
                }
                *path_len = abs_len;
                return AtResolution::Ramfs {
                    start_ino: ROOT_INO,
                };
            }
            (*reply).label = TRONA_NOT_FOUND;
            return AtResolution::Error;
        }

        (*reply).label = TRONA_INVALID_ARGUMENT;
        AtResolution::Error
    }
}
