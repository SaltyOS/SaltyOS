// SPDX-License-Identifier: GPL-2.0-only
//! Remote mount point proxy for SaltyFS integration.

use trona::consts::*;
use trona::ipc;
use trona::types::*;

use crate::consts::*;
use crate::types::*;
use crate::ipc_ctx;

/// Maximum size of the work buffer used during mount path traversal.
/// Must accommodate a symlink target (up to 152 bytes) plus "/" plus the
/// remaining path (up to MAX_PATH_LEN bytes), so 256 is a safe upper bound.
const MOUNT_PATH_BUF_LEN: usize = 256;

/// Ensure the root underlay mount is initialized. Returns Some(mount_idx) on success.
unsafe fn ensure_root_underlay() -> Option<usize> {
    unsafe {
        let mut idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
        if idx < 0 {
            if crate::MOUNT_TRIED < 3 {
                setup_saltyfs_mount();
            }
            idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
            if idx < 0 {
                return None;
            }
        }
        Some(idx as usize)
    }
}

/// Try resolving a path against the root underlay mount (rootfs disk).
/// Follows symlinks including the final component.
/// Returns Some((mount_idx, remote_ino)) if found, None otherwise.
pub(crate) unsafe fn try_root_underlay(
    path_ptr: *const u8,
    path_len: u8,
) -> Option<(usize, u64)> {
    unsafe {
        let mi = ensure_root_underlay()?;

        // Strip leading '/' from path
        let mut off: usize = 0;
        let plen = path_len as usize;
        while off < plen && *path_ptr.add(off) == b'/' {
            off += 1;
        }
        if off >= plen {
            // Root path "/" — return the mount root inode
            let root_ino = (*(&raw const crate::MOUNTS[mi])).root_ino as u64;
            return Some((mi, root_ino));
        }

        let sub_ptr = path_ptr.add(off);
        let sub_len = (plen - off) as u8;
        let remote_ino = mount_lookup(mi, sub_ptr, sub_len);
        if remote_ino != 0 {
            Some((mi, remote_ino))
        } else {
            None
        }
    }
}

/// Like `try_root_underlay` but does NOT follow the final path component if it is a symlink.
/// Use for readlinkat and lstat-style operations on the underlay mount.
pub(crate) unsafe fn try_root_underlay_nofollow(
    path_ptr: *const u8,
    path_len: u8,
) -> Option<(usize, u64)> {
    unsafe {
        let mi = ensure_root_underlay()?;

        // Strip leading '/' from path
        let mut off: usize = 0;
        let plen = path_len as usize;
        while off < plen && *path_ptr.add(off) == b'/' {
            off += 1;
        }
        if off >= plen {
            // Root path "/" — return the mount root inode
            let root_ino = (*(&raw const crate::MOUNTS[mi])).root_ino as u64;
            return Some((mi, root_ino));
        }

        let sub_ptr = path_ptr.add(off);
        let sub_len = (plen - off) as u8;
        let remote_ino = mount_lookup_nofollow(mi, sub_ptr, sub_len);
        if remote_ino != 0 {
            Some((mi, remote_ino))
        } else {
            None
        }
    }
}

/// Fill a stat reply from mount-resolved metadata.
pub(crate) unsafe fn fill_mount_stat_reply(
    reply: *mut TronaMsg,
    remote_ino: u64,
    size: u64,
    mode: u32,
    nlink: u32,
    mtime: u64,
) {
    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).length = 8;
        (*reply).regs[0] = remote_ino;
        (*reply).regs[1] = mode as u64;
        (*reply).regs[2] = nlink as u64;
        (*reply).regs[3] = size;
        (*reply).regs[4] = 0; // uid
        (*reply).regs[5] = 0; // gid
        (*reply).regs[6] = mtime;
        (*reply).regs[7] = if (mode & S_IFMT_L) == S_IFDIR_L {
            FTYPE_DIRECTORY as u64
        } else if (mode & S_IFMT_L) == S_IFLNK_L {
            FTYPE_SYMLINK as u64
        } else {
            FTYPE_REGULAR as u64
        };
    }
}

pub(crate) unsafe fn mount_lookup(mount_idx: usize, sub_path: *const u8, sub_path_len: u8) -> u64 {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        mount_lookup_from(mount_idx, m.root_ino as u64, sub_path, sub_path_len)
    }
}

/// Like `mount_lookup` but does not follow the final path component if it is a symlink.
pub(crate) unsafe fn mount_lookup_nofollow(
    mount_idx: usize,
    sub_path: *const u8,
    sub_path_len: u8,
) -> u64 {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        mount_lookup_from_nofollow(mount_idx, m.root_ino as u64, sub_path, sub_path_len)
    }
}

/// Like `mount_lookup_from` but follows symlinks at every component including the final one.
pub(crate) unsafe fn mount_lookup_from(
    mount_idx: usize,
    start_ino: u64,
    sub_path: *const u8,
    sub_path_len: u8,
) -> u64 {
    unsafe { mount_lookup_from_inner(mount_idx, start_ino, sub_path, sub_path_len, true) }
}

/// Like `mount_lookup_from` but does NOT follow the final path component if it is a symlink.
/// Intermediate components are still followed. Use for readlinkat, lstat, and linkat nofollow.
pub(crate) unsafe fn mount_lookup_from_nofollow(
    mount_idx: usize,
    start_ino: u64,
    sub_path: *const u8,
    sub_path_len: u8,
) -> u64 {
    unsafe { mount_lookup_from_inner(mount_idx, start_ino, sub_path, sub_path_len, false) }
}

/// Ask SaltyFS for the parent inode of a given inode.
/// Returns the parent inode number on success (TRONA_OK).
/// Returns 0 if the inode has no INODE_REF (TRONA_NOT_FOUND — root or orphan).
/// Returns u64::MAX on IPC or structural errors (any other reply label).
unsafe fn mount_getparent(mount_idx: usize, child_ino: u64) -> u64 {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_GETPARENT;
        req.regs[0] = child_ino;
        req.length = 1;
        let mut reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);
        if reply.label == TRONA_OK {
            reply.regs[0]
        } else if reply.label == TRONA_NOT_FOUND {
            0 // no parent ref (root or orphan)
        } else {
            u64::MAX // IPC/structural error
        }
    }
}

/// Core symlink-aware path traversal on a mounted SaltyFS filesystem.
/// `follow_final` controls whether the last component is followed if it is a symlink.
/// Returns the resolved inode number, or 0 on any error (not found, loop, path too long).
unsafe fn mount_lookup_from_inner(
    mount_idx: usize,
    start_ino: u64,
    sub_path: *const u8,
    sub_path_len: u8,
    follow_final: bool,
) -> u64 {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];

        if sub_path_len == 0 {
            return start_ino;
        }

        // Validate that start_ino is a directory when doing dirfd-relative traversal.
        // Root inode is always a directory; skip the check for it.
        if start_ino != (*m).root_ino as u64 {
            if let Some((_size, _mode, _nlink, _mtime, is_dir)) =
                mount_stat(mount_idx, start_ino)
            {
                if !is_dir {
                    return 0;
                }
            }
        }

        // Working buffer holds the path being traversed (original + symlink expansions).
        let mut work_buf = [0u8; MOUNT_PATH_BUF_LEN];
        let mut work_len = sub_path_len as usize;
        if work_len >= MOUNT_PATH_BUF_LEN {
            return 0;
        }
        // SAFETY: work_len < MOUNT_PATH_BUF_LEN; sub_path has sub_path_len valid bytes.
        for i in 0..work_len {
            work_buf[i] = *sub_path.add(i);
        }

        let mut current_ino = start_ino;
        let mut depth: usize = 0; // Symlink nesting depth; cap at 9 expansions (depth > 8) to match ramfs
        let mut pos: usize = 0;
        let mut parent_stack = [0u64; 128];
        let mut stack_depth: usize = 0;

        while pos < work_len {
            // Skip slashes
            while pos < work_len && work_buf[pos] == b'/' {
                pos += 1;
            }
            if pos >= work_len {
                break;
            }

            // Identify the next path component
            let comp_start = pos;
            while pos < work_len && work_buf[pos] != b'/' {
                pos += 1;
            }
            let comp_len = pos - comp_start;
            if comp_len == 0 {
                continue;
            }
            if comp_len > 144 {
                return 0;
            }

            // Handle "." -- stay at current directory
            if comp_len == 1 && work_buf[comp_start] == b'.' {
                continue;
            }
            // Handle ".." -- move to parent
            if comp_len == 2 && work_buf[comp_start] == b'.' && work_buf[comp_start + 1] == b'.' {
                if stack_depth > 0 {
                    stack_depth -= 1;
                    current_ino = parent_stack[stack_depth];
                } else if current_ino != (*m).root_ino as u64 {
                    // Stack empty but not at mount root — ask SaltyFS for the actual parent.
                    // This handles dirfd-relative paths where start_ino is not the mount root.
                    let parent = mount_getparent(mount_idx, current_ino);
                    if parent == u64::MAX || parent == 0 {
                        // u64::MAX = IPC error; 0 = missing INODE_REF for non-root inode.
                        // Both are errors — fail path resolution.
                        return 0;
                    }
                    current_ino = parent;
                }
                // At mount root with empty stack: /.. == / (POSIX: stay at root)
                continue;
            }

            // Determine if this is the final (last non-slash) component
            let is_final = {
                let mut ahead = pos;
                while ahead < work_len && work_buf[ahead] == b'/' {
                    ahead += 1;
                }
                ahead >= work_len
            };

            // Send SALTYFS_LOOKUP IPC — reply now includes dir_type in regs[1]
            let mut req = TronaMsg::zeroed();
            req.label = SALTYFS_LOOKUP;
            req.regs[0] = current_ino;
            req.regs[1] = comp_len as u64;
            // SAFETY: comp_len <= 144; regs[2] starts the 144-byte name region.
            let name_dst = &raw mut req.regs[2] as *mut u8;
            for i in 0..comp_len {
                *name_dst.add(i) = work_buf[comp_start + i];
            }
            req.length = 2 + ((comp_len as u64) + 7) / 8;

            let mut reply = TronaMsg::zeroed();
            ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);

            if reply.label != TRONA_OK {
                return 0;
            }

            let child_ino = reply.regs[0];
            let dir_type = reply.regs[1] as u8;

            if dir_type == FTYPE_SYMLINK {
                // Symlink
                if is_final && !follow_final {
                    // Caller requested nofollow for the final component: return symlink inode.
                    return child_ino;
                }
                if depth > 8 {
                    return 0; // Too many levels of symlinks (ELOOP)
                }
                depth += 1;

                // Read symlink target into a local buffer
                let mut target_buf = [0u8; 152];
                let tlen = mount_readlink_raw(mount_idx, child_ino, target_buf.as_mut_ptr(), 152);
                if tlen == 0 {
                    return 0;
                }

                // Remaining path = work_buf[pos..work_len] (bytes after the current component)
                let remaining_len = work_len - pos;

                // New work path = target + (if remaining: "/" + remaining)
                let new_len = if remaining_len > 0 {
                    tlen as usize + 1 + remaining_len
                } else {
                    tlen as usize
                };
                if new_len >= MOUNT_PATH_BUF_LEN {
                    return 0; // Expanded path too long
                }

                // Build the new work buffer in a temporary, then copy back
                let mut new_buf = [0u8; MOUNT_PATH_BUF_LEN];
                // SAFETY: tlen <= 152, new_len < MOUNT_PATH_BUF_LEN.
                for i in 0..tlen as usize {
                    new_buf[i] = target_buf[i];
                }
                if remaining_len > 0 {
                    new_buf[tlen as usize] = b'/';
                    for i in 0..remaining_len {
                        new_buf[tlen as usize + 1 + i] = work_buf[pos + i];
                    }
                }
                for i in 0..new_len {
                    work_buf[i] = new_buf[i];
                }
                work_len = new_len;
                pos = 0;

                // Absolute symlink: restart traversal from the mount root
                if tlen > 0 && target_buf[0] == b'/' {
                    current_ino = (*m).root_ino as u64;
                    stack_depth = 0; // Reset parent tracking for absolute symlink
                }
                // Relative symlink: current_ino stays as the symlink's parent directory
            } else {
                // Push parent before descending (for ".." support)
                if stack_depth < 128 {
                    parent_stack[stack_depth] = current_ino;
                    stack_depth += 1;
                } else {
                    return 0; // Path too deep
                }
                current_ino = child_ino;
            }
        }

        current_ino
    }
}

pub(crate) unsafe fn mount_stat(
    mount_idx: usize,
    remote_ino: u64,
) -> Option<(u64, u32, u32, u64, bool)> {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_STAT;
        req.regs[0] = remote_ino;
        req.length = 1;

        let mut reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);

        if reply.label != TRONA_OK {
            return None;
        }

        let size = reply.regs[1];
        let mode = reply.regs[2] as u32;
        let nlink = reply.regs[3] as u32;
        let mtime = reply.regs[4];
        let is_dir = (mode & S_IFMT_L) == S_IFDIR_L;
        Some((size, mode, nlink, mtime, is_dir))
    }
}

pub(crate) unsafe fn mount_read_inline(
    mount_idx: usize,
    remote_ino: u64,
    offset: u64,
    count: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READ_INLINE;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.length = 3;

        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != TRONA_OK {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let bytes_read = fs_reply.regs[0];
        (*reply).label = TRONA_OK;
        (*reply).length = 1 + (bytes_read + 7) / 8;
        (*reply).regs[0] = bytes_read;

        if bytes_read > 0 {
            let src = &fs_reply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for i in 0..bytes_read as usize {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

pub(crate) unsafe fn mount_create(
    mount_idx: usize,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
    mode: u32,
) -> u64 {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_CREATE;
        req.regs[0] = parent_ino;
        req.regs[1] = mode as u64;
        req.regs[2] = name_len as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 3 + ((name_len as u64) + 7) / 8;
        let mut reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);
        if reply.label != TRONA_OK {
            return 0;
        }
        reply.regs[0]
    }
}

pub(crate) unsafe fn mount_write_inline(
    mount_idx: usize,
    remote_ino: u64,
    offset: u64,
    data: *const u8,
    count: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_WRITE_INLINE;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..count as usize {
            *dst.add(i) = *data.add(i);
        }
        req.length = 3 + (count + 7) / 8;
        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        if fs_reply.label != TRONA_OK {
            (*reply).label = fs_reply.label;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fs_reply.regs[0];
    }
}

pub(crate) unsafe fn mount_mkdir(
    mount_idx: usize,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
    mode: u32,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_MKDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = mode as u64;
        req.regs[2] = name_len as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 3 + ((name_len as u64) + 7) / 8;
        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

pub(crate) unsafe fn mount_unlink(
    mount_idx: usize,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_UNLINK;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + ((name_len as u64) + 7) / 8;
        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

pub(crate) unsafe fn mount_rmdir(
    mount_idx: usize,
    parent_ino: u64,
    name: *const u8,
    name_len: u8,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_RMDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + ((name_len as u64) + 7) / 8;
        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

pub(crate) unsafe fn mount_rename(
    mount_idx: usize,
    old_parent_ino: u64,
    old_name: *const u8,
    old_name_len: u8,
    new_parent_ino: u64,
    new_name: *const u8,
    new_name_len: u8,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_RENAME;
        // MR4..MR11 = old name (64 bytes), MR12..MR19 = new name (64 bytes)
        if old_name_len > 64 || new_name_len > 64 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        req.regs[0] = old_parent_ino;
        req.regs[1] = old_name_len as u64;
        req.regs[2] = new_parent_ino;
        req.regs[3] = new_name_len as u64;
        let dst = &raw mut req.regs[4] as *mut u8;
        for i in 0..old_name_len as usize {
            *dst.add(i) = *old_name.add(i);
        }
        let dst2 = &raw mut req.regs[12] as *mut u8;
        for i in 0..new_name_len as usize {
            *dst2.add(i) = *new_name.add(i);
        }
        req.length = 20;
        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

pub(crate) unsafe fn mount_truncate(
    mount_idx: usize,
    remote_ino: u64,
    new_size: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_TRUNCATE;
        req.regs[0] = remote_ino;
        req.regs[1] = new_size;
        req.length = 2;
        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

/// SHM-based read from mounted filesystem. Data is placed in VFS-SaltyFS SHM.
pub(crate) unsafe fn mount_read_shm(
    mount_idx: usize, remote_ino: u64, offset: u64, count: u64,
    shm_offset: u64, reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READ;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.regs[3] = shm_offset;
        req.length = 4;

        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != TRONA_OK {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fs_reply.regs[0]; // bytes_read
    }
}

/// SHM-based write to mounted filesystem. Data is in VFS-SaltyFS SHM.
pub(crate) unsafe fn mount_write_shm(
    mount_idx: usize, remote_ino: u64, offset: u64, count: u64,
    shm_offset: u64, reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_WRITE;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.regs[3] = shm_offset;
        req.length = 4;

        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        (*reply).label = fs_reply.label;
        if fs_reply.label == TRONA_OK {
            (*reply).length = 1;
            (*reply).regs[0] = fs_reply.regs[0]; // bytes_written
        }
    }
}

pub(crate) fn split_mount_sub_path(
    sub_path: *const u8, sub_len: u8,
) -> (usize, u8, usize, u8) {
    let mut last_slash: i32 = -1;
    for i in (0..sub_len as usize).rev() {
        if unsafe { *sub_path.add(i) } == b'/' {
            last_slash = i as i32;
            break;
        }
    }
    if last_slash < 0 {
        (0, 0, 0, sub_len)
    } else {
        (
            0,
            last_slash as u8,
            (last_slash + 1) as usize,
            sub_len - (last_slash as u8 + 1),
        )
    }
}

pub(crate) unsafe fn mount_readdir_emit_cached(fde: *mut FdEntry, reply: *mut TronaMsg) {
    unsafe {
        let fd = &mut *fde;
        let idx = fd.mount_batch_index as usize;
        let ent = &fd.mount_batch[idx];

        (*reply).label = TRONA_OK;
        (*reply).length = 5 + ((ent.name_len as u64 + 7) / 8);
        (*reply).regs[0] = ent.name_len as u64;
        (*reply).regs[1] = 0;
        (*reply).regs[2] = ent.ino;
        (*reply).regs[3] = ent.d_type as u64;
        for j in 4..20 {
            (*reply).regs[j] = 0;
        }
        let dst = &raw mut (*reply).regs[4] as *mut u8;
        for j in 0..ent.name_len as usize {
            *dst.add(j) = ent.name[j];
        }

        fd.mount_batch_index = fd.mount_batch_index.saturating_add(1);
        if fd.mount_batch_index >= fd.mount_batch_count {
            fd.mount_batch_index = 0;
            fd.mount_batch_count = 0;
            fd.dir_cursor = if fd.mount_batch_next_cursor == 0 {
                u32::MAX
            } else {
                fd.mount_batch_next_cursor
            };
        }
    }
}

pub(crate) unsafe fn mount_readdir(
    mount_idx: usize,
    fde: *mut FdEntry,
    dir_ino: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = &mut *fde;

        if fd.dir_cursor == u32::MAX {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        if fd.mount_batch_count > 0 && fd.mount_batch_index < fd.mount_batch_count {
            mount_readdir_emit_cached(fde, reply);
            return;
        }

        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READDIR;
        req.regs[0] = dir_ino;
        req.regs[1] = fd.dir_cursor as u64;
        req.length = 2;

        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != TRONA_OK {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            fd.dir_cursor = u32::MAX;
            return;
        }

        let next_cursor = fs_reply.regs[0] as u32;
        let num_entries = (fs_reply.length.saturating_sub(1)) / 6;
        if num_entries == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            fd.dir_cursor = u32::MAX;
            return;
        }

        let take = core::cmp::min(num_entries as usize, MOUNT_READDIR_BATCH_MAX);
        for n in 0..take {
            let base = 1 + n * 6;
            let child_ino = fs_reply.regs[base];
            let dir_type = fs_reply.regs[base + 1] as u8;
            let name_regs = [
                fs_reply.regs[base + 2],
                fs_reply.regs[base + 3],
                fs_reply.regs[base + 4],
                fs_reply.regs[base + 5],
            ];

            let mut name = [0u8; 32];
            for r in 0..4 {
                let bytes = name_regs[r].to_le_bytes();
                for j in 0..8 {
                    name[r * 8 + j] = bytes[j];
                }
            }
            let mut name_len: u8 = 0;
            for b in name.iter() {
                if *b == 0 {
                    break;
                }
                name_len += 1;
            }

            let d_type = match dir_type {
                1 => 8,
                2 => 4,
                _ => 0,
            };

            fd.mount_batch[n].ino = child_ino;
            fd.mount_batch[n].d_type = d_type;
            fd.mount_batch[n].name_len = name_len;
            fd.mount_batch[n].name = name;
        }

        fd.mount_batch_count = take as u8;
        fd.mount_batch_index = 0;
        fd.mount_batch_next_cursor = next_cursor;
        mount_readdir_emit_cached(fde, reply);
    }
}

pub(crate) unsafe fn setup_saltyfs_mount() {
    unsafe {
        crate::MOUNT_TRIED += 1;

        let fs_slot = match trona::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[VFS] saltyfs: no slot available\n");
                });
                return;
            }
        };

        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, fs_slot, 16);

        let mut ns_req = TronaMsg::zeroed();
        ns_req.label = POSIX_NS_LOOKUP;
        let name = b"saltyfs";
        ns_req.regs[0] = name.len() as u64;
        ns_req.length = 1 + (name.len() as u64 + 7) / 8;
        let ns_dst = &raw mut ns_req.regs[1] as *mut u8;
        for i in 0..name.len() {
            *ns_dst.add(i) = name[i];
        }

        let mut ns_reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            ipc_ctx(),
            VFS_CAP_NAMESERV_EP,
            &raw const ns_req,
            &raw mut ns_reply,
        );

        if err != 0 || ns_reply.label != TRONA_OK {
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] saltyfs not found in nameserv (ok if no data disk)\n");
            });
            return;
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[VFS] Found saltyfs endpoint via nameserv\n");
        });

        let mut mnt_req = TronaMsg::zeroed();
        mnt_req.label = SALTYFS_MOUNT;
        mnt_req.length = 0;

        let mut mnt_reply = TronaMsg::zeroed();
        let merr = ipc::call_ctx(ipc_ctx(), fs_slot, &raw const mnt_req, &raw mut mnt_reply);

        if merr != 0 || (mnt_reply.label != TRONA_OK && mnt_reply.label != TRONA_ALREADY_EXISTS) {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] saltyfs mount failed err=");
                _lb.hex(merr as u64);
                _lb.str(b" label=");
                _lb.hex(mnt_reply.label);
                _lb.str(b"\n");
            });
            return;
        }

        let root_ino = mnt_reply.regs[0] as u32;

        let mounts = &raw mut crate::MOUNTS;
        for i in 0..MAX_MOUNTS {
            if (*mounts)[i].active == 0 {
                (*mounts)[i].active = 1;
                (*mounts)[i].mount_ino = 0;
                (*mounts)[i].fs_cap = fs_slot;
                (*mounts)[i].root_ino = root_ino;
                *(&raw mut crate::ROOT_UNDERLAY_IDX) = i as i32;
                break;
            }
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[VFS] Mounted saltyfs as root underlay root_ino=");
            _lb.hex(root_ino as u64);
            _lb.str(b"\n");
        });

        // Set up VFS-SaltyFS SHM for bulk data transport
        let mut shm_create = TronaMsg::zeroed();
        shm_create.label = MM_SHM_CREATE;
        shm_create.length = 2;
        shm_create.regs[0] = VFS_SALTYFS_SHM_ID;
        shm_create.regs[1] = VFS_SALTYFS_SHM_PAGES;

        let mut shm_reply = TronaMsg::zeroed();
        let serr = ipc::call_ctx(
            ipc_ctx(), VFS_CAP_MMSRV_EP,
            &raw const shm_create, &raw mut shm_reply,
        );
        if serr != 0 || (shm_reply.label != 0 && shm_reply.label != TRONA_ALREADY_EXISTS) {
            trona::uwarn!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM create failed (non-fatal)\n");
            });
        } else {
            // Map SHM into VFS address space
            let mut shm_map = TronaMsg::zeroed();
            shm_map.label = MM_SHM_MAP;
            shm_map.length = 4;
            shm_map.regs[0] = VFS_SALTYFS_SHM_ID;
            shm_map.regs[1] = 0;
            shm_map.regs[2] = VFS_SALTYFS_SHM_VADDR;
            shm_map.regs[3] = 0x3; // RW

            let mut map_reply = TronaMsg::zeroed();
            let merr2 = ipc::call_ctx(
                ipc_ctx(), VFS_CAP_MMSRV_EP,
                &raw const shm_map, &raw mut map_reply,
            );
            if merr2 != 0 || map_reply.label != 0 {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[VFS] saltyfs SHM map failed (non-fatal)\n");
                });
            } else {
                // Send SHM ID to SaltyFS so it can map the same region
                let mut setup_msg = TronaMsg::zeroed();
                setup_msg.label = SALTYFS_SHM_SETUP;
                setup_msg.regs[0] = VFS_SALTYFS_SHM_ID;
                setup_msg.length = 1;

                let mut setup_reply = TronaMsg::zeroed();
                let serr2 = ipc::call_ctx(
                    ipc_ctx(), fs_slot,
                    &raw const setup_msg, &raw mut setup_reply,
                );
                if serr2 == 0 && setup_reply.label == TRONA_OK {
                    trona::uinfo!(|_lb| {
                        _lb.str(b"[VFS] saltyfs SHM transport established\n");
                    });
                    *(&raw mut crate::VFS_SHM_ACTIVE) = true;
                } else {
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[VFS] saltyfs SHM setup failed (non-fatal)\n");
                    });
                    // Cleanup: unmap VFS SHM since SaltyFS didn't establish transport
                    let mut shm_unmap = TronaMsg::zeroed();
                    shm_unmap.label = MM_SHM_UNMAP;
                    shm_unmap.length = 3;
                    shm_unmap.regs[0] = VFS_SALTYFS_SHM_ID;
                    shm_unmap.regs[1] = 0; // 0 = caller's own badge
                    shm_unmap.regs[2] = VFS_SALTYFS_SHM_VADDR;
                    let mut unmap_reply = TronaMsg::zeroed();
                    let _ = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const shm_unmap, &raw mut unmap_reply);
                }
            }
        }
    }
}

/// Create a symlink on the mounted SaltyFS filesystem.
/// parent_ino = inode of parent directory on the remote FS
/// name/name_len = name of the symlink entry
/// target/target_len = symlink target path
pub(crate) unsafe fn mount_symlink(
    mount_idx: usize, parent_ino: u64,
    name: *const u8, name_len: u8,
    target: *const u8, target_len: u8,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_SYMLINK;
        req.regs[0] = parent_ino;
        if name_len as usize > 72 || target_len as usize > 64 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        req.regs[1] = name_len as u64;
        req.regs[2] = target_len as u64;
        // MR3..MR11 = link name (72 bytes max)
        let dst_name = &raw mut req.regs[3] as *mut u8;
        let copy_name = name_len as usize;
        for i in 0..copy_name {
            *dst_name.add(i) = *name.add(i);
        }
        // MR12..MR19 = target (64 bytes max)
        let dst_target = &raw mut req.regs[12] as *mut u8;
        let copy_target = target_len as usize;
        for i in 0..copy_target {
            *dst_target.add(i) = *target.add(i);
        }
        req.length = 20;
        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
        if fs_reply.label == TRONA_OK {
            (*reply).regs[0] = fs_reply.regs[0]; // new_ino
        }
    }
}

/// Read a symlink target into a raw buffer. Returns the number of bytes written (0 on failure).
/// Unlike `mount_readlink`, this writes into a caller-provided byte buffer rather than an IPC reply.
pub(crate) unsafe fn mount_readlink_raw(
    mount_idx: usize,
    remote_ino: u64,
    buf: *mut u8,
    buf_cap: usize,
) -> u8 {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READLINK;
        req.regs[0] = remote_ino;
        req.length = 1;

        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != TRONA_OK {
            return 0;
        }
        let target_len = fs_reply.regs[0] as usize;
        if target_len == 0 {
            return 0;
        }
        if target_len > buf_cap {
            return 0; // Target too long for buffer — refuse to truncate
        }
        let copy = target_len;
        // SAFETY: copy <= buf_cap (caller guarantees buf has at least buf_cap bytes);
        // src is regs[1..], bounded to copy bytes from the IPC reply buffer.
        let src = &fs_reply.regs[1] as *const u64 as *const u8;
        for i in 0..copy {
            *buf.add(i) = *src.add(i);
        }
        copy as u8
    }
}

/// Read a symlink target from the mounted SaltyFS filesystem.
pub(crate) unsafe fn mount_readlink(
    mount_idx: usize, remote_ino: u64, reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READLINK;
        req.regs[0] = remote_ino;
        req.length = 1;

        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != TRONA_OK {
            (*reply).label = fs_reply.label;
            return;
        }

        // Copy target data from SaltyFS reply to VFS reply
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = fs_reply.regs[0]; // target_len
        (*reply).length = fs_reply.length;
        let target_len = fs_reply.regs[0] as usize;
        if target_len > 0 {
            let src = &fs_reply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            let copy = core::cmp::min(target_len, 152);
            for i in 0..copy {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

/// Create a hard link on the mounted SaltyFS filesystem.
pub(crate) unsafe fn mount_link(
    mount_idx: usize, existing_ino: u64,
    new_parent_ino: u64, name: *const u8, name_len: u8,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_LINK;
        req.regs[0] = existing_ino;
        req.regs[1] = new_parent_ino;
        if name_len as usize > 136 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let copy = name_len as usize;
        req.regs[2] = copy as u64;
        // MR3..MR19 = name (136 bytes max)
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..copy {
            *dst.add(i) = *name.add(i);
        }
        req.length = 3 + ((copy as u64) + 7) / 8;
        let mut fs_reply = TronaMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}
