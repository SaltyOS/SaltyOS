// SPDX-License-Identifier: GPL-2.0-only
//! POSIX *at() family: openat, fstatat, unlinkat, renameat, and related operations.

use trona::consts::*;
use trona::types::*;

use crate::client::{extract_dual_paths, extract_path, flags_allow_write, get_client, get_client_noalloc};
use crate::consts::*;
use crate::fileops::{fill_stat_reply, normalize_path_for_client, open_mount_inode};
use crate::mount::{
    fill_mount_stat_reply, mount_create, mount_lookup, mount_lookup_from, mount_lookup_from_nofollow,
    mount_mkdir, mount_rename, mount_rmdir, mount_stat, mount_unlink, split_mount_sub_path,
    mount_symlink, mount_readlink, mount_link, try_root_underlay, try_root_underlay_nofollow,
};
use crate::path::{
    resolve_at_base, resolve_at_mount, resolve_at_start, resolve_parent, resolve_parent_from,
    resolve_path, resolve_path_from, resolve_path_from_nofollow, resolve_path_raw,
    resolve_path_raw_nofollow, symlink_target, AtResolution,
};
use crate::pipe::find_pipe;
use crate::procfs::{handle_proc_open, handle_proc_stat};
use crate::ramfs::{
    alloc_inode, alloc_symlink_target, chain_truncate, dir_add_entry, dir_find_entry,
    dir_remove_entry, free_inode, free_symlink_target, inode_by_ino, inode_open,
};
use crate::types::*;

/// Inner open logic parameterized by start_ino.
/// Reused by handle_open (start_ino=ROOT_INO) and handle_openat.
pub(crate) unsafe fn do_open(
    start_ino: u32,
    path: *const u8,
    path_len: u8,
    flags: u32,
    mode: u32,
    reply: *mut TronaMsg,
    badge: u64,
) {
    unsafe {
        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // /proc virtual paths — intercept absolute paths before resolve
        if path_len >= 6 {
            let p = path;
            if *p == b'/'
                && *p.add(1) == b'p'
                && *p.add(2) == b'r'
                && *p.add(3) == b'o'
                && *p.add(4) == b'c'
                && *p.add(5) == b'/'
            {
                if handle_proc_open(path, path_len, reply, badge) {
                    return;
                }
            }
        }

        let mut inode = resolve_path_from(start_ino, path, path_len);

        // Root underlay fallback
        if inode.is_null() {
            // Normalize relative path to absolute for root underlay lookup
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            let (ul_ptr, ul_len) = if *path != b'/' {
                if let Some(pair) =
                    normalize_path_for_client(badge, path, path_len, ul_abs.as_mut_ptr())
                {
                    pair
                } else {
                    (path, path_len)
                }
            } else {
                (path, path_len)
            };
            if let Some((mi, rino)) = try_root_underlay(ul_ptr, ul_len) {
                if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
                    (*reply).label = TRONA_ALREADY_EXISTS;
                    return;
                }
                open_mount_inode(mi, rino, flags, reply, badge);
                return;
            }
        }

        if inode.is_null() {
            if (flags & O_CREAT) == 0 {
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }

            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent =
                resolve_parent_from(start_ino, path, path_len, &mut child_name, &mut child_len);
            if !parent.is_null()
                && (*parent).ftype == FTYPE_DIRECTORY
                && (*parent).readonly == 0
                && child_len > 0
            {
                inode = alloc_inode();
                if !inode.is_null() {
                    (*inode).ftype = FTYPE_REGULAR;
                    (*inode).mode = S_IFREG_L | (mode & 0o777);
                    (*inode).parent_ino = (*parent).ino;
                    (*inode).rw_data = core::ptr::null_mut();
                    dir_add_entry(parent, child_name, child_len, (*inode).ino);
                }
            }

            if inode.is_null() {
                // Ramfs create failed (parent not in ramfs) — try underlay
                let mut ul_abs2 = [0u8; MAX_PATH_LEN];
                let (ul2_ptr, ul2_len) = if *path != b'/' {
                    if let Some(pair) = normalize_path_for_client(
                        badge,
                        path,
                        path_len,
                        ul_abs2.as_mut_ptr(),
                    ) {
                        pair
                    } else {
                        (path, path_len)
                    }
                } else {
                    (path, path_len)
                };
                let idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
                if idx >= 0 {
                    let mi = idx as usize;
                    let plen = ul2_len as usize;
                    let mut off: usize = 0;
                    while off < plen && *ul2_ptr.add(off) == b'/' {
                        off += 1;
                    }
                    if off < plen {
                        let sub_ptr = ul2_ptr.add(off);
                        let sub_len = (plen - off) as u8;
                        let (p_start, p_len, l_start, l_len) =
                            split_mount_sub_path(sub_ptr, sub_len);
                        let parent_ino = if p_len == 0 {
                            (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                        } else {
                            mount_lookup(mi, sub_ptr.add(p_start), p_len)
                        };
                        if parent_ino != 0 && l_len > 0 {
                            let new_ino = mount_create(
                                mi,
                                parent_ino,
                                sub_ptr.add(l_start),
                                l_len,
                                mode,
                            );
                            if new_ino != 0 {
                                open_mount_inode(mi, new_ino, flags, reply, badge);
                                return;
                            }
                        }
                    }
                }
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
        } else if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        if (*inode).ftype == FTYPE_DIRECTORY {
            if flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
        }

        // Mount point: open as FD_TYPE_MOUNT backed by the mounted FS
        if (*inode).ftype == FTYPE_MOUNT_POINT {
            for i in 0..crate::consts::MAX_MOUNTS {
                let m = &*(&raw const crate::MOUNTS[i]);
                if m.active != 0 && m.mount_ino == (*inode).ino {
                    let cli = get_client(badge);
                    if cli.is_null() {
                        (*reply).label = TRONA_OUT_OF_MEMORY;
                        return;
                    }
                    for fd in 0..(*cli).fds_cap as usize {
                        if (*(*cli).fds.add(fd)).active == 0 {
                            (*(*cli).fds.add(fd)).active = 1;
                            (*(*cli).fds.add(fd)).fd_type = FD_TYPE_MOUNT;
                            (*(*cli).fds.add(fd)).inode = (*inode).ino;
                            (*(*cli).fds.add(fd)).offset = 0;
                            (*(*cli).fds.add(fd)).dir_cursor = 0;
                            (*(*cli).fds.add(fd)).sock_id = m.root_ino;
                            (*(*cli).fds.add(fd)).dev_type = i as u8;
                            (*(*cli).fds.add(fd)).flags = flags;
                            (*(*cli).fds.add(fd)).mount_batch_count = 0;
                            (*(*cli).fds.add(fd)).mount_batch_index = 0;
                            (*(*cli).fds.add(fd)).mount_batch_next_cursor = 0;
                            (*reply).label = TRONA_OK;
                            (*reply).length = 1;
                            (*reply).regs[0] = fd as u64;
                            return;
                        }
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        if (*inode).ftype == FTYPE_REGULAR {
            if (*inode).readonly != 0
                && (flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0)
            {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            if (flags & O_TRUNC) != 0 && flags_allow_write(flags) {
                if !(*inode).rw_data.is_null() {
                    chain_truncate((*inode).rw_data, 0);
                }
                (*inode).size = 0;
            }
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).dir_cursor = 0;
                (*(*cli).fds.add(fd)).flags = flags;

                if (*inode).ftype == FTYPE_CHAR_DEVICE {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DEVICE;
                    (*(*cli).fds.add(fd)).dev_type = (*inode).dev_type;
                    if (*inode).dev_type == DEV_PTY_SLAVE {
                        (*(*cli).fds.add(fd)).sock_id = (*inode).size as u32; // pty_id
                    }
                } else if (*inode).ftype == FTYPE_DIRECTORY {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DIR;
                } else if (*inode).ftype == FTYPE_FIFO {
                    let pipe_id = (*inode).size as u32;
                    let pipe = find_pipe(pipe_id);
                    if pipe.is_null() {
                        (*(*cli).fds.add(fd)).active = 0;
                        (*reply).label = TRONA_INVALID_OPERATION;
                        return;
                    }
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_PIPE;
                    (*(*cli).fds.add(fd)).sock_id = pipe_id;
                    if flags_allow_write(flags) {
                        (*(*cli).fds.add(fd)).flags = O_WRONLY;
                        (*pipe).write_refcount += 1;
                    } else {
                        (*(*cli).fds.add(fd)).flags = 0;
                        (*pipe).read_refcount += 1;
                    }
                } else {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_FILE;
                    if (flags & O_APPEND) != 0 {
                        (*(*cli).fds.add(fd)).offset = (*inode).size;
                    }
                }

                inode_open((*inode).ino);
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return;
            }
        }

        (*reply).label = TRONA_OUT_OF_MEMORY;
    }
}

/// openat(dirfd, path, flags, mode)
/// IPC: reg[0]=dirfd, reg[1]=open_flags, reg[2]=mode, reg[3..]=path(len+data)
pub(crate) unsafe fn handle_openat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let flags = (*msg).regs[1] as u32;
        let mode = (*msg).regs[2] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 3, path.as_mut_ptr());

        let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                if (flags & O_CREAT) != 0 {
                    let (p_start, p_len, l_start, l_len) =
                        split_mount_sub_path(path.as_ptr(), path_len);
                    let parent_rino = if p_len == 0 {
                        dir_rino
                    } else {
                        mount_lookup_from(mi, dir_rino, path.as_ptr().add(p_start), p_len)
                    };
                    if parent_rino != 0 && l_len > 0 {
                        let child_ptr = path.as_ptr().add(l_start);
                        let existing = mount_lookup_from(mi, parent_rino, child_ptr, l_len);
                        if existing != 0 {
                            if (flags & O_EXCL) != 0 {
                                (*reply).label = TRONA_ALREADY_EXISTS;
                                return;
                            }
                            open_mount_inode(mi, existing, flags, reply, badge);
                            return;
                        }
                        let new_ino = mount_create(mi, parent_rino, child_ptr, l_len, mode);
                        if new_ino != 0 {
                            open_mount_inode(mi, new_ino, flags, reply, badge);
                            return;
                        }
                    }
                } else {
                    let target = mount_lookup_from(mi, dir_rino, path.as_ptr(), path_len);
                    if target != 0 {
                        open_mount_inode(mi, target, flags, reply, badge);
                        return;
                    }
                }
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            AtResolution::Error => return,
        };

        do_open(start_ino, path.as_ptr(), path_len, flags, mode, reply, badge);
    }
}

/// fstatat(dirfd, path, statbuf, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub(crate) unsafe fn handle_fstatat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 2, path.as_mut_ptr());

        let inode = if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 {
            // AT_EMPTY_PATH: stat the fd itself
            if dirfd < 0 {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            let cli = get_client(badge);
            if cli.is_null()
                || dirfd >= (*cli).fds_cap as i32
                || (*(*cli).fds.add(dirfd as usize)).active == 0
            {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            let fde = &*(*cli).fds.add(dirfd as usize);
            if fde.fd_type == FD_TYPE_MOUNT {
                let mi = fde.dev_type as usize;
                let rino = fde.sock_id as u64;
                if let Some((size, mode, nlink, mtime, _)) = mount_stat(mi, rino) {
                    fill_mount_stat_reply(reply, rino, size, mode, nlink, mtime);
                    return;
                }
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            inode_by_ino(fde.inode)
        } else {
            let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
                AtResolution::Ramfs { start_ino } => start_ino,
                AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                    let rino = if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
                        mount_lookup_from_nofollow(mi, dir_rino, path.as_ptr(), path_len)
                    } else {
                        mount_lookup_from(mi, dir_rino, path.as_ptr(), path_len)
                    };
                    if rino != 0 {
                        if let Some((size, mode, nlink, mtime, _)) = mount_stat(mi, rino) {
                            fill_mount_stat_reply(reply, rino, size, mode, nlink, mtime);
                            return;
                        }
                    }
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
                AtResolution::Error => return,
            };
            if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
                resolve_path_from_nofollow(start_ino, path.as_ptr(), path_len)
            } else {
                resolve_path_from(start_ino, path.as_ptr(), path_len)
            }
        };

        if inode.is_null() {
            // Try /proc virtual paths
            if path_len >= 6
                && path[0] == b'/'
                && path[1] == b'p'
                && path[2] == b'r'
                && path[3] == b'o'
                && path[4] == b'c'
                && path[5] == b'/'
            {
                if handle_proc_stat(path.as_ptr(), path_len, reply, badge) {
                    return;
                }
            }
            // Root underlay fallback — normalize to absolute path
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            if let Some((norm_ptr, norm_len)) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
            {
                let underlay_result = if (at_flags & AT_SYMLINK_NOFOLLOW_VAL) != 0 {
                    try_root_underlay_nofollow(norm_ptr, norm_len)
                } else {
                    try_root_underlay(norm_ptr, norm_len)
                };
                if let Some((mi, rino)) = underlay_result {
                    if let Some((size, mode, nlink, mtime, _)) = mount_stat(mi, rino) {
                        fill_mount_stat_reply(reply, rino, size, mode, nlink, mtime);
                        return;
                    }
                }
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

/// unlinkat(dirfd, path, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub(crate) unsafe fn handle_unlinkat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                let (p_start, p_len, l_start, l_len) =
                    split_mount_sub_path(path.as_ptr(), path_len);
                let parent_rino = if p_len == 0 {
                    dir_rino
                } else {
                    mount_lookup_from(mi, dir_rino, path.as_ptr().add(p_start), p_len)
                };
                if parent_rino != 0 && l_len > 0 {
                    if (at_flags & AT_REMOVEDIR_VAL) != 0 {
                        mount_rmdir(mi, parent_rino, path.as_ptr().add(l_start), l_len, reply);
                    } else {
                        mount_unlink(mi, parent_rino, path.as_ptr().add(l_start), l_len, reply);
                    }
                    return;
                }
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            AtResolution::Error => return,
        };

        if (at_flags & AT_REMOVEDIR_VAL) != 0 {
            // AT_REMOVEDIR: act like rmdir
            let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
            if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
                // Root underlay fallback (Fix 1a)
                let mut ul_abs = [0u8; MAX_PATH_LEN];
                if let Some((norm_ptr, norm_len)) =
                    normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
                {
                    let idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
                    if idx >= 0 {
                        let mi = idx as usize;
                        let plen = norm_len as usize;
                        let mut off: usize = 0;
                        while off < plen && *norm_ptr.add(off) == b'/' { off += 1; }
                        if off < plen {
                            let sub_ptr = norm_ptr.add(off);
                            let sub_len = (plen - off) as u8;
                            let (p_start, p_len, l_start, l_len) =
                                split_mount_sub_path(sub_ptr, sub_len);
                            let parent_ino = if p_len == 0 {
                                (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                            } else {
                                mount_lookup(mi, sub_ptr.add(p_start), p_len)
                            };
                            if parent_ino != 0 && l_len > 0 {
                                mount_rmdir(mi, parent_ino, sub_ptr.add(l_start), l_len, reply);
                                return;
                            }
                        }
                    }
                }
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            if (*inode).readonly != 0 {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            for i in 0..(*inode).dirents_cap as usize {
                if (*(*inode).dirents.add(i)).active != 0 {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
            }
            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent = resolve_parent_from(
                start_ino,
                path.as_ptr(),
                path_len,
                &mut child_name,
                &mut child_len,
            );
            if !parent.is_null() {
                dir_remove_entry(parent, child_name, child_len);
            }
            (*inode).active = 0;
            (*reply).label = TRONA_OK;
        } else {
            // Regular unlink
            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent = resolve_parent_from(
                start_ino,
                path.as_ptr(),
                path_len,
                &mut child_name,
                &mut child_len,
            );
            if parent.is_null() || (*parent).readonly != 0 {
                // Root underlay fallback (Fix 1a)
                let mut ul_abs = [0u8; MAX_PATH_LEN];
                if let Some((norm_ptr, norm_len)) =
                    normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
                {
                    let idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
                    if idx >= 0 {
                        let mi = idx as usize;
                        let plen = norm_len as usize;
                        let mut off: usize = 0;
                        while off < plen && *norm_ptr.add(off) == b'/' { off += 1; }
                        if off < plen {
                            let sub_ptr = norm_ptr.add(off);
                            let sub_len = (plen - off) as u8;
                            let (p_start, p_len, l_start, l_len) =
                                split_mount_sub_path(sub_ptr, sub_len);
                            let parent_ino = if p_len == 0 {
                                (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                            } else {
                                mount_lookup(mi, sub_ptr.add(p_start), p_len)
                            };
                            if parent_ino != 0 && l_len > 0 {
                                mount_unlink(mi, parent_ino, sub_ptr.add(l_start), l_len, reply);
                                return;
                            }
                        }
                    }
                }
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            let de = dir_find_entry(parent, child_name, child_len);
            if de.is_null() {
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            let inode = inode_by_ino((*de).ino);
            if inode.is_null() || (*inode).ftype == FTYPE_DIRECTORY {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*de).active = 0;
            (*inode).nlink = (*inode).nlink.saturating_sub(1);
            if (*inode).nlink == 0 && (*inode).open_count == 0 {
                free_inode(inode);
            }
            (*reply).label = TRONA_OK;
        }
    }
}

/// renameat(old_dirfd, old_path, new_dirfd, new_path)
/// IPC: reg[0]=old_dirfd, reg[1]=new_dirfd, reg[2]=old_len, reg[3]=new_len, reg[4..]=paths
pub(crate) unsafe fn handle_renameat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;

        // Validated extraction: hdr_regs=2 (old_dirfd, new_dirfd), then old_len, new_len, data
        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let (mut old_len, mut new_len) = match extract_dual_paths(
            msg, 2, old_path.as_mut_ptr(), new_path.as_mut_ptr(), reply,
        ) {
            Some(pair) => pair,
            None => return,
        };
        let mut old_start = resolve_at_start(badge, old_dirfd, old_path.as_ptr(), old_len);
        let mut new_start = resolve_at_start(badge, new_dirfd, new_path.as_ptr(), new_len);

        // AT_FDCWD normalization for each side independently
        if old_start == 0 && old_dirfd == AT_FDCWD_VAL {
            let mut norm_buf = [0u8; MAX_PATH_LEN];
            if let Some((abs_ptr, abs_len)) =
                normalize_path_for_client(badge, old_path.as_ptr(), old_len, norm_buf.as_mut_ptr())
            {
                for i in 0..abs_len as usize { old_path[i] = *abs_ptr.add(i); }
                old_len = abs_len;
                old_start = ROOT_INO;
            }
        }
        if new_start == 0 && new_dirfd == AT_FDCWD_VAL {
            let mut norm_buf = [0u8; MAX_PATH_LEN];
            if let Some((abs_ptr, abs_len)) =
                normalize_path_for_client(badge, new_path.as_ptr(), new_len, norm_buf.as_mut_ptr())
            {
                for i in 0..abs_len as usize { new_path[i] = *abs_ptr.add(i); }
                new_len = abs_len;
                new_start = ROOT_INO;
            }
        }

        if old_start == 0 || new_start == 0 {
            // Fix 2 + Fix 1b: mount FD dirfd / underlay fallback for renameat
            let old_mount = if old_start == 0 {
                resolve_at_mount(badge, old_dirfd)
            } else { None };
            let new_mount = if new_start == 0 {
                resolve_at_mount(badge, new_dirfd)
            } else { None };
            // Both sides must be mount FDs on the same mount
            if let (Some((omi, od)), Some((nmi, nd))) = (old_mount, new_mount) {
                if omi == nmi {
                    let (op_start, op_len, ol_start, ol_len) =
                        split_mount_sub_path(old_path.as_ptr(), old_len);
                    let old_parent_rino = if op_len == 0 {
                        od
                    } else {
                        mount_lookup_from(omi, od, old_path.as_ptr().add(op_start), op_len)
                    };
                    let (np_start, np_len, nl_start, nl_len) =
                        split_mount_sub_path(new_path.as_ptr(), new_len);
                    let new_parent_rino = if np_len == 0 {
                        nd
                    } else {
                        mount_lookup_from(nmi, nd, new_path.as_ptr().add(np_start), np_len)
                    };
                    if old_parent_rino != 0 && new_parent_rino != 0
                        && ol_len > 0 && nl_len > 0
                    {
                        mount_rename(
                            omi, old_parent_rino,
                            old_path.as_ptr().add(ol_start), ol_len,
                            new_parent_rino,
                            new_path.as_ptr().add(nl_start), nl_len,
                            reply,
                        );
                        return;
                    }
                }
            }
            // Fallback: try underlay with absolute paths
            if old_start == 0 && new_start == 0 && old_mount.is_none() && new_mount.is_none() {
                let mut ul_old = [0u8; MAX_PATH_LEN];
                let mut ul_new = [0u8; MAX_PATH_LEN];
                if let (Some((old_ptr, old_nlen)), Some((new_ptr, new_nlen))) = (
                    normalize_path_for_client(badge, old_path.as_ptr(), old_len, ul_old.as_mut_ptr()),
                    normalize_path_for_client(badge, new_path.as_ptr(), new_len, ul_new.as_mut_ptr()),
                ) {
                    let idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
                    if idx >= 0 {
                        let mi = idx as usize;
                        let strip = |p: *const u8, l: u8| -> (*const u8, u8) {
                            let mut o = 0usize;
                            while o < l as usize && unsafe { *p.add(o) } == b'/' { o += 1; }
                            (unsafe { p.add(o) }, l.saturating_sub(o as u8))
                        };
                        let (old_sub, old_sl) = strip(old_ptr, old_nlen);
                        let (new_sub, new_sl) = strip(new_ptr, new_nlen);
                        if old_sl > 0 && new_sl > 0 {
                            let (op_start, op_len, ol_start, ol_len) =
                                split_mount_sub_path(old_sub, old_sl);
                            let old_parent_ino = if op_len == 0 {
                                (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                            } else {
                                mount_lookup(mi, old_sub.add(op_start), op_len)
                            };
                            let (np_start, np_len, nl_start, nl_len) =
                                split_mount_sub_path(new_sub, new_sl);
                            let new_parent_ino = if np_len == 0 {
                                (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                            } else {
                                mount_lookup(mi, new_sub.add(np_start), np_len)
                            };
                            if old_parent_ino != 0 && new_parent_ino != 0
                                && ol_len > 0 && nl_len > 0
                            {
                                mount_rename(
                                    mi, old_parent_ino,
                                    old_sub.add(ol_start), ol_len,
                                    new_parent_ino,
                                    new_sub.add(nl_start), nl_len,
                                    reply,
                                );
                                return;
                            }
                        }
                    }
                }
            }
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mut old_child: *const u8 = core::ptr::null();
        let mut old_child_len: u8 = 0;
        let old_parent = resolve_parent_from(
            old_start,
            old_path.as_ptr(),
            old_len,
            &mut old_child,
            &mut old_child_len,
        );
        if old_parent.is_null() || (*old_parent).readonly != 0 {
            // Root underlay fallback (Fix 1b)
            let mut ul_old = [0u8; MAX_PATH_LEN];
            let mut ul_new = [0u8; MAX_PATH_LEN];
            if let (Some((old_ptr, old_nlen)), Some((new_ptr, new_nlen))) = (
                normalize_path_for_client(badge, old_path.as_ptr(), old_len, ul_old.as_mut_ptr()),
                normalize_path_for_client(badge, new_path.as_ptr(), new_len, ul_new.as_mut_ptr()),
            ) {
                let idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
                if idx >= 0 {
                    let mi = idx as usize;
                    let strip = |p: *const u8, l: u8| -> (*const u8, u8) {
                        let mut o = 0usize;
                        while o < l as usize && unsafe { *p.add(o) } == b'/' { o += 1; }
                        (unsafe { p.add(o) }, l.saturating_sub(o as u8))
                    };
                    let (old_sub, old_sl) = strip(old_ptr, old_nlen);
                    let (new_sub, new_sl) = strip(new_ptr, new_nlen);
                    if old_sl > 0 && new_sl > 0 {
                        let (op_start, op_len, ol_start, ol_len) =
                            split_mount_sub_path(old_sub, old_sl);
                        let old_pino = if op_len == 0 {
                            (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                        } else {
                            mount_lookup(mi, old_sub.add(op_start), op_len)
                        };
                        let (np_start, np_len, nl_start, nl_len) =
                            split_mount_sub_path(new_sub, new_sl);
                        let new_pino = if np_len == 0 {
                            (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                        } else {
                            mount_lookup(mi, new_sub.add(np_start), np_len)
                        };
                        if old_pino != 0 && new_pino != 0 && ol_len > 0 && nl_len > 0 {
                            mount_rename(
                                mi, old_pino,
                                old_sub.add(ol_start), ol_len,
                                new_pino,
                                new_sub.add(nl_start), nl_len,
                                reply,
                            );
                            return;
                        }
                    }
                }
            }
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let de = dir_find_entry(old_parent, old_child, old_child_len);
        if de.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        let ino = (*de).ino;

        let mut new_child: *const u8 = core::ptr::null();
        let mut new_child_len: u8 = 0;
        let new_parent = resolve_parent_from(
            new_start,
            new_path.as_ptr(),
            new_len,
            &mut new_child,
            &mut new_child_len,
        );
        if new_parent.is_null() || (*new_parent).readonly != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        (*de).active = 0;

        let existing = dir_find_entry(new_parent, new_child, new_child_len);
        if !existing.is_null() {
            let old_inode = inode_by_ino((*existing).ino);
            if !old_inode.is_null() {
                (*old_inode).nlink = (*old_inode).nlink.saturating_sub(1);
                if (*old_inode).nlink == 0 && (*old_inode).open_count == 0 {
                    free_inode(old_inode);
                }
            }
            (*existing).active = 0;
        }

        dir_add_entry(new_parent, new_child, new_child_len, ino);
        (*reply).label = TRONA_OK;
    }
}

/// mkdirat(dirfd, path, mode)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2..]=path(len+data)
pub(crate) unsafe fn handle_mkdirat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                let (p_start, p_len, l_start, l_len) =
                    split_mount_sub_path(path.as_ptr(), path_len);
                let parent_rino = if p_len == 0 {
                    dir_rino
                } else {
                    mount_lookup_from(mi, dir_rino, path.as_ptr().add(p_start), p_len)
                };
                if parent_rino != 0 && l_len > 0 {
                    mount_mkdir(mi, parent_rino, path.as_ptr().add(l_start), l_len, mode, reply);
                    return;
                }
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            AtResolution::Error => return,
        };

        let existing = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if !existing.is_null() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent_from(
            start_ino,
            path.as_ptr(),
            path_len,
            &mut child_name,
            &mut child_len,
        );
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            // Root underlay fallback (Fix 1c)
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            if let Some((norm_ptr, norm_len)) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
            {
                let idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
                if idx >= 0 {
                    let mi = idx as usize;
                    let plen = norm_len as usize;
                    let mut off: usize = 0;
                    while off < plen && *norm_ptr.add(off) == b'/' { off += 1; }
                    if off < plen {
                        let sub_ptr = norm_ptr.add(off);
                        let sub_len = (plen - off) as u8;
                        let (p_start, p_len, l_start, l_len) =
                            split_mount_sub_path(sub_ptr, sub_len);
                        let parent_ino = if p_len == 0 {
                            (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                        } else {
                            mount_lookup(mi, sub_ptr.add(p_start), p_len)
                        };
                        if parent_ino != 0 && l_len > 0 {
                            mount_mkdir(mi, parent_ino, sub_ptr.add(l_start), l_len, mode, reply);
                            return;
                        }
                    }
                }
            }
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let dir = alloc_inode();
        if dir.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*dir).ftype = FTYPE_DIRECTORY;
        (*dir).mode = S_IFDIR_L | (mode & 0o777);
        (*dir).nlink = 2;
        (*dir).parent_ino = (*parent).ino;

        dir_add_entry(parent, child_name, child_len, (*dir).ino);
        (*reply).label = TRONA_OK;
    }
}

/// faccessat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
pub(crate) unsafe fn handle_faccessat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 3, path.as_mut_ptr());

        let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                let rino = mount_lookup_from(mi, dir_rino, path.as_ptr(), path_len);
                if rino != 0 {
                    (*reply).label = TRONA_OK;
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                }
                return;
            }
            AtResolution::Error => return,
        };

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            // Root underlay fallback
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            let (ul_ptr, ul_len) = if path[0] == b'/' {
                (path.as_ptr() as *const u8, path_len)
            } else if let Some(pair) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
            {
                pair
            } else {
                (path.as_ptr() as *const u8, path_len)
            };
            if try_root_underlay(ul_ptr, ul_len).is_some() {
                (*reply).label = TRONA_OK;
                return;
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        (*reply).label = TRONA_OK;
    }
}

/// fchmodat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
/// Single-user OS — resolve path, verify exists, return OK.
pub(crate) unsafe fn handle_fchmodat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 3, path.as_mut_ptr());

        let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                let rino = mount_lookup_from(mi, dir_rino, path.as_ptr(), path_len);
                if rino != 0 {
                    (*reply).label = TRONA_OK;
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                }
                return;
            }
            AtResolution::Error => return,
        };

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            let (ul_ptr, ul_len) = if path[0] == b'/' {
                (path.as_ptr() as *const u8, path_len)
            } else if let Some(pair) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
            {
                pair
            } else {
                (path.as_ptr() as *const u8, path_len)
            };
            if try_root_underlay(ul_ptr, ul_len).is_some() {
                (*reply).label = TRONA_OK;
                return;
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        (*reply).label = TRONA_OK;
    }
}

/// fchownat(dirfd, path, uid, gid, flags)
/// IPC: reg[0]=dirfd, reg[1]=uid, reg[2]=gid, reg[3]=at_flags, reg[4..]=path(len+data)
/// Single-user OS — resolve path, verify exists, return OK.
pub(crate) unsafe fn handle_fchownat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 4, path.as_mut_ptr());

        let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                let rino = mount_lookup_from(mi, dir_rino, path.as_ptr(), path_len);
                if rino != 0 {
                    (*reply).label = TRONA_OK;
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                }
                return;
            }
            AtResolution::Error => return,
        };

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            let (ul_ptr, ul_len) = if path[0] == b'/' {
                (path.as_ptr() as *const u8, path_len)
            } else if let Some(pair) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
            {
                pair
            } else {
                (path.as_ptr() as *const u8, path_len)
            };
            if try_root_underlay(ul_ptr, ul_len).is_some() {
                (*reply).label = TRONA_OK;
                return;
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        (*reply).label = TRONA_OK;
    }
}

/// fchmod(fd, mode) — change mode on open fd
/// IPC: reg[0]=fd, reg[1]=mode
/// Single-user OS — verify fd exists, return OK.
pub(crate) unsafe fn handle_fchmod(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        (*reply).label = TRONA_OK;
    }
}

/// fchown(fd, uid, gid) — change owner on open fd
/// IPC: reg[0]=fd, reg[1]=uid, reg[2]=gid
/// Single-user OS — verify fd exists, return OK.
pub(crate) unsafe fn handle_fchown(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        (*reply).label = TRONA_OK;
    }
}

/// utimensat(dirfd, path, times, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2]=atime_sec, reg[3]=atime_nsec,
///      reg[4]=mtime_sec, reg[5]=mtime_nsec, reg[6..]=path(len+data)
pub(crate) unsafe fn handle_utimensat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let _atime_sec = (*msg).regs[2] as i64;
        let _atime_nsec = (*msg).regs[3] as i64;
        let mtime_sec = (*msg).regs[4] as i64;
        let mtime_nsec = (*msg).regs[5] as i64;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 6, path.as_mut_ptr());

        let inode = if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 {
            // Operate on dirfd itself
            if dirfd < 0 || dirfd == AT_FDCWD_VAL {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            let cli = get_client(badge);
            if cli.is_null()
                || dirfd >= (*cli).fds_cap as i32
                || (*(*cli).fds.add(dirfd as usize)).active == 0
            {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            let fde = &*(*cli).fds.add(dirfd as usize);
            if fde.fd_type == FD_TYPE_MOUNT {
                (*reply).label = TRONA_OK;
                return;
            }
            inode_by_ino(fde.inode)
        } else {
            let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
                AtResolution::Ramfs { start_ino } => start_ino,
                AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                    let rino = mount_lookup_from(mi, dir_rino, path.as_ptr(), path_len);
                    if rino != 0 {
                        (*reply).label = TRONA_OK;
                    } else {
                        (*reply).label = TRONA_NOT_FOUND;
                    }
                    return;
                }
                AtResolution::Error => return,
            };
            resolve_path_from(start_ino, path.as_ptr(), path_len)
        };

        if inode.is_null() {
            // Root underlay: no utimensat support — return OK silently if file exists
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            if let Some((norm_ptr, norm_len)) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
            {
                if try_root_underlay(norm_ptr, norm_len).is_some() {
                    (*reply).label = TRONA_OK;
                    return;
                }
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // UTIME_OMIT = (1<<30)-2 — don't change
        // UTIME_NOW = (1<<30)-1 — set to current time
        // Otherwise use provided value
        const UTIME_NOW_VAL: i64 = (1 << 30) - 1;
        const UTIME_OMIT_VAL: i64 = (1 << 30) - 2;

        if mtime_nsec != UTIME_OMIT_VAL {
            if mtime_nsec == UTIME_NOW_VAL {
                // Get current monotonic time
                let res =
                    trona::syscall::syscall(trona::consts::SYS_CLOCK_GETTIME, 0, 0, 0, 0, 0, 0);
                let now_sec = res.value / 1_000_000_000;
                (*inode).mtime = now_sec as u32;
            } else {
                (*inode).mtime = mtime_sec as u32;
            }
        }

        (*reply).label = TRONA_OK;
    }
}

/// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
/// IPC: regs[0]=old_dirfd, regs[1]=new_dirfd, regs[2]=flags,
///      regs[3]=old_len, regs[4]=new_len, regs[5..]=oldpath||newpath (8-byte aligned)
pub(crate) unsafe fn handle_linkat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let flags = (*msg).regs[2] as i32;

        // AT_SYMLINK_FOLLOW: follow symlinks on oldpath when flag is set
        const AT_SYMLINK_FOLLOW: i32 = 0x400;
        // Reject unknown flags
        if flags & !AT_SYMLINK_FOLLOW != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let follow_old = (flags & AT_SYMLINK_FOLLOW) != 0;

        // Validated extraction: hdr_regs=3 (old_dirfd, new_dirfd, flags), then old_len, new_len, data
        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let (mut old_len, mut new_len) = match extract_dual_paths(
            msg, 3, old_path.as_mut_ptr(), new_path.as_mut_ptr(), reply,
        ) {
            Some(pair) => pair,
            None => return,
        };

        // Resolve old side
        let old_start = match resolve_at_base(badge, old_dirfd, old_path.as_mut_ptr(), &mut old_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                // Old is on a mount — respect follow_old for symlink resolution
                let old_rino = if follow_old {
                    mount_lookup_from(mi, dir_rino, old_path.as_ptr(), old_len)
                } else {
                    mount_lookup_from_nofollow(mi, dir_rino, old_path.as_ptr(), old_len)
                };
                if old_rino == 0 {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
                // New side must also be on the same mount for cross-mount link
                let new_start = match resolve_at_base(badge, new_dirfd, new_path.as_mut_ptr(), &mut new_len, reply) {
                    AtResolution::MountFd { mount_idx: nmi, dir_rino: nd } if nmi == mi => {
                        let (np_start, np_len, nl_start, nl_len) =
                            split_mount_sub_path(new_path.as_ptr(), new_len);
                        let new_parent_rino = if np_len == 0 {
                            nd
                        } else {
                            mount_lookup_from(nmi, nd, new_path.as_ptr().add(np_start), np_len)
                        };
                        if new_parent_rino != 0 && nl_len > 0 {
                            mount_link(mi, old_rino, new_parent_rino, new_path.as_ptr().add(nl_start), nl_len, reply);
                            return;
                        }
                        (*reply).label = TRONA_NOT_FOUND;
                        return;
                    }
                    _ => {
                        (*reply).label = TRONA_INVALID_OPERATION;
                        return;
                    }
                };
            }
            AtResolution::Error => return,
        };

        // Resolve old path in ramfs
        let target = if follow_old {
            resolve_path_from(old_start, old_path.as_ptr(), old_len)
        } else {
            resolve_path_from_nofollow(old_start, old_path.as_ptr(), old_len)
        };
        if target.is_null() {
            // Root underlay fallback for linkat
            let mut ul_old = [0u8; MAX_PATH_LEN];
            let (ul_ptr, ul_len) = if old_path[0] == b'/' {
                (old_path.as_ptr() as *const u8, old_len)
            } else if let Some(pair) =
                normalize_path_for_client(badge, old_path.as_ptr(), old_len, ul_old.as_mut_ptr())
            {
                pair
            } else {
                (old_path.as_ptr() as *const u8, old_len)
            };
            // Respect follow_old: AT_SYMLINK_FOLLOW follows the final component
            let underlay_old = if follow_old {
                try_root_underlay(ul_ptr, ul_len)
            } else {
                try_root_underlay_nofollow(ul_ptr, ul_len)
            };
            if let Some((mi, existing_ino)) = underlay_old {
                // Normalize new path for underlay
                let mut ul_new = [0u8; MAX_PATH_LEN];
                let (new_ptr, new_nlen) = if new_path[0] == b'/' {
                    (new_path.as_ptr() as *const u8, new_len)
                } else if let Some(pair) =
                    normalize_path_for_client(badge, new_path.as_ptr(), new_len, ul_new.as_mut_ptr())
                {
                    pair
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                };
                let mut off: usize = 0;
                while off < new_nlen as usize && *new_ptr.add(off) == b'/' { off += 1; }
                if off < new_nlen as usize {
                    let new_sub = new_ptr.add(off);
                    let new_sl = (new_nlen as usize - off) as u8;
                    let (np_start, np_len, nl_start, nl_len) =
                        split_mount_sub_path(new_sub, new_sl);
                    let new_parent_ino = if np_len == 0 {
                        (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                    } else {
                        mount_lookup(mi, new_sub.add(np_start), np_len)
                    };
                    if new_parent_ino != 0 {
                        mount_link(mi, existing_ino, new_parent_ino, new_sub.add(nl_start), nl_len, reply);
                        return;
                    }
                }
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Cannot hard-link directories
        if (*target).ftype == FTYPE_DIRECTORY {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        // Resolve new side
        let new_start = match resolve_at_base(badge, new_dirfd, new_path.as_mut_ptr(), &mut new_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { .. } => {
                // Cannot hard-link from ramfs to mount
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            AtResolution::Error => return,
        };

        // Resolve new path parent
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let new_parent = resolve_parent_from(
            new_start,
            new_path.as_ptr(),
            new_len,
            &mut child_name,
            &mut child_len,
        );
        if new_parent.is_null() || (*new_parent).readonly != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        // Check new name doesn't already exist
        let existing = dir_find_entry(new_parent, child_name, child_len);
        if !existing.is_null() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        // Add new directory entry pointing to the same inode
        if dir_add_entry(new_parent, child_name, child_len, (*target).ino) != 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*target).nlink += 1;
        (*reply).label = TRONA_OK;
    }
}

/// symlinkat(target, newdirfd, linkpath)
/// IPC: regs[0]=newdirfd, regs[1]=target_len, regs[2..10]=target(64B), regs[10]=link_len, regs[11..19]=link(64B)
pub(crate) unsafe fn handle_symlinkat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let newdirfd = (*msg).regs[0] as i32;

        let target_len = (*msg).regs[1] as u8;
        if target_len == 0 || target_len > 64 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let mut target = [0u8; MAX_PATH_LEN];
        let raw_target = &(*msg).regs[2] as *const u64 as *const u8;
        for i in 0..target_len as usize {
            target[i] = *raw_target.add(i);
        }

        let mut link_len = (*msg).regs[10] as u8;
        if link_len == 0 || link_len > 64 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let mut link_path = [0u8; MAX_PATH_LEN];
        let raw_link = &(*msg).regs[11] as *const u64 as *const u8;
        for i in 0..link_len as usize {
            link_path[i] = *raw_link.add(i);
        }

        // Resolve start inode for the link path using newdirfd
        let start_ino = match resolve_at_base(badge, newdirfd, link_path.as_mut_ptr(), &mut link_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                let (p_start, p_len, l_start, l_len) =
                    split_mount_sub_path(link_path.as_ptr(), link_len);
                let parent_rino = if p_len == 0 {
                    dir_rino
                } else {
                    mount_lookup_from(mi, dir_rino, link_path.as_ptr().add(p_start), p_len)
                };
                if parent_rino != 0 && l_len > 0 {
                    mount_symlink(
                        mi, parent_rino,
                        link_path.as_ptr().add(l_start), l_len,
                        target.as_ptr(), target_len,
                        reply,
                    );
                    return;
                }
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            AtResolution::Error => return,
        };

        // Resolve parent of the link
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent_from(
            start_ino,
            link_path.as_ptr(),
            link_len,
            &mut child_name,
            &mut child_len,
        );
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            // Root underlay fallback for symlinkat
            // link_path is absolute after resolve_at_base normalization
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            let (ul_ptr, ul_len) = if link_path[0] == b'/' {
                (link_path.as_ptr() as *const u8, link_len)
            } else if let Some(pair) =
                normalize_path_for_client(badge, link_path.as_ptr(), link_len, ul_abs.as_mut_ptr())
            {
                pair
            } else {
                (link_path.as_ptr() as *const u8, link_len)
            };
            let idx = *(&raw const crate::ROOT_UNDERLAY_IDX);
            if idx >= 0 {
                let mi = idx as usize;
                let mut off: usize = 0;
                let plen = ul_len as usize;
                while off < plen && *ul_ptr.add(off) == b'/' { off += 1; }
                if off < plen {
                    let sub_ptr = ul_ptr.add(off);
                    let sub_len = (plen - off) as u8;
                    let (p_start, p_len, l_start, l_len) =
                        split_mount_sub_path(sub_ptr, sub_len);
                    let parent_ino = if p_len == 0 {
                        (*(&raw const crate::MOUNTS[mi])).root_ino as u64
                    } else {
                        mount_lookup(mi, sub_ptr.add(p_start), p_len)
                    };
                    if parent_ino != 0 {
                        mount_symlink(
                            mi, parent_ino,
                            sub_ptr.add(l_start), l_len,
                            target.as_ptr(), target_len,
                            reply,
                        );
                        return;
                    }
                }
            }
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        if child_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Check that target name doesn't already exist
        let existing = dir_find_entry(parent, child_name, child_len);
        if !existing.is_null() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        // Allocate symlink target in pool
        let sym_data = alloc_symlink_target(target.as_ptr(), target_len);
        if sym_data.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Allocate inode
        let inode = alloc_inode();
        if inode.is_null() {
            free_symlink_target(sym_data);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*inode).ftype = FTYPE_SYMLINK;
        (*inode).mode = S_IFLNK_L | 0o777;
        (*inode).nlink = 1;
        (*inode).size = target_len as u64;
        (*inode).rw_data = sym_data;
        (*inode).parent_ino = (*parent).ino;

        dir_add_entry(parent, child_name, child_len, (*inode).ino);
        (*reply).label = TRONA_OK;
    }
}

/// readlinkat(dirfd, path) -> target
/// IPC in: regs[0]=dirfd, regs[1]=path_len, regs[2..]=path
/// IPC out: regs[0]=target_len, regs[1..]=target
pub(crate) unsafe fn handle_readlinkat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut path_len = extract_path(msg, 1, path.as_mut_ptr());

        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let start_ino = match resolve_at_base(badge, dirfd, path.as_mut_ptr(), &mut path_len, reply) {
            AtResolution::Ramfs { start_ino } => start_ino,
            AtResolution::MountFd { mount_idx: mi, dir_rino } => {
                // Use nofollow: readlink must not follow the final symlink component
                let rino = mount_lookup_from_nofollow(mi, dir_rino, path.as_ptr(), path_len);
                if rino != 0 {
                    mount_readlink(mi, rino, reply);
                    return;
                }
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            AtResolution::Error => return,
        };

        // Use nofollow for the final component (readlink should not follow)
        let inode = resolve_path_from_nofollow(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            // Root underlay fallback for readlink
            let mut ul_abs = [0u8; MAX_PATH_LEN];
            let (ul_ptr, ul_len) = if path[0] == b'/' {
                (path.as_ptr() as *const u8, path_len)
            } else if let Some(pair) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, ul_abs.as_mut_ptr())
            {
                pair
            } else {
                (path.as_ptr() as *const u8, path_len)
            };
            // Use nofollow: readlink must not follow the final symlink component
            if let Some((mi, rino)) = try_root_underlay_nofollow(ul_ptr, ul_len) {
                mount_readlink(mi, rino, reply);
                return;
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        if (*inode).ftype != FTYPE_SYMLINK {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let (target, target_len) = symlink_target(inode);
        if target.is_null() || target_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).regs[0] = target_len as u64;
        (*reply).length = 1 + ((target_len as u64 + 7) / 8);
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        for i in 0..target_len as usize {
            *dst.add(i) = *target.add(i);
        }
    }
}

/// lstat: stat without following final symlink
pub(crate) unsafe fn handle_lstat(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };
        let inode = resolve_path_raw_nofollow(path_ptr, path_len);
        if inode.is_null() {
            // Try /proc virtual paths
            if path_len >= 6
                && *path_ptr == b'/'
                && *path_ptr.add(1) == b'p'
                && *path_ptr.add(2) == b'r'
                && *path_ptr.add(3) == b'o'
                && *path_ptr.add(4) == b'c'
                && *path_ptr.add(5) == b'/'
            {
                if handle_proc_stat(path_ptr, path_len, reply, badge) {
                    return;
                }
            }
            // Root underlay fallback
            if let Some((mi, rino)) = try_root_underlay(path_ptr, path_len) {
                if let Some((size, mode, nlink, mtime, _)) = mount_stat(mi, rino) {
                    fill_mount_stat_reply(reply, rino, size, mode, nlink, mtime);
                    return;
                }
            }
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}
