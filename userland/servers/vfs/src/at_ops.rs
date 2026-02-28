// SPDX-License-Identifier: GPL-2.0-only
//! POSIX *at() family: openat, fstatat, unlinkat, renameat, and related operations.

use besalt::consts::*;
use besalt::types::*;

use crate::client::{extract_path, flags_allow_write, get_client, get_client_noalloc};
use crate::consts::*;
use crate::fileops::{fill_stat_reply, normalize_path_for_client};
use crate::mount::{find_mount_for_path, mount_lookup, mount_stat, parse_mount_path, split_mount_sub_path, mount_symlink, mount_readlink, mount_link};
use crate::path::{
    resolve_at_start, resolve_parent, resolve_parent_from, resolve_path, resolve_path_from,
    resolve_path_raw, resolve_path_raw_nofollow, symlink_target,
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
    reply: *mut BesaltMsg,
    badge: u64,
) {
    unsafe {
        if path_len == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
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

        // Mount point intercept — normalize relative paths to absolute first
        let mut abs_buf = [0u8; MAX_PATH_LEN];
        let (check_ptr, check_len): (*const u8, u8) = if *path != b'/' {
            if let Some(pair) =
                normalize_path_for_client(badge, path, path_len, abs_buf.as_mut_ptr())
            {
                pair
            } else {
                (path, path_len)
            }
        } else {
            (path, path_len)
        };
        let check_slice = core::slice::from_raw_parts(check_ptr, check_len as usize);
        if let Some(mount_idx) = find_mount_for_path(check_slice, check_len) {
            let (_, sub_start, sub_len) = parse_mount_path(check_slice, check_len);
            if sub_len > 0 {
                let mut remote_ino = mount_lookup(mount_idx, check_ptr.add(sub_start), sub_len);
                if remote_ino == 0 {
                    if (flags & O_CREAT) == 0 {
                        (*reply).label = BESALT_NOT_FOUND;
                        return;
                    }
                    let (p_start, p_len, l_start, l_len) =
                        split_mount_sub_path(check_ptr.add(sub_start), sub_len);
                    let parent_ino = if p_len == 0 {
                        (*(&raw const crate::MOUNTS[mount_idx])).root_ino as u64
                    } else {
                        mount_lookup(mount_idx, check_ptr.add(sub_start + p_start), p_len)
                    };
                    if parent_ino == 0 {
                        (*reply).label = BESALT_NOT_FOUND;
                        return;
                    }
                    use crate::mount::mount_create;
                    remote_ino = mount_create(
                        mount_idx, parent_ino,
                        check_ptr.add(sub_start + l_start), l_len, mode & 0o777,
                    );
                    if remote_ino == 0 {
                        (*reply).label = BESALT_INVALID_OPERATION;
                        return;
                    }
                }
                // Open existing remote file
                let cli = get_client(badge);
                if cli.is_null() {
                    (*reply).label = BESALT_OUT_OF_MEMORY;
                    return;
                }
                for fd in 0..(*cli).fds_cap as usize {
                    if (*(*cli).fds.add(fd)).active == 0 {
                        (*(*cli).fds.add(fd)).active = 1;
                        (*(*cli).fds.add(fd)).fd_type = FD_TYPE_MOUNT;
                        (*(*cli).fds.add(fd)).inode = crate::MOUNT_DATA_INO;
                        (*(*cli).fds.add(fd)).offset = 0;
                        (*(*cli).fds.add(fd)).dir_cursor = 0;
                        (*(*cli).fds.add(fd)).sock_id = remote_ino as u32;
                        (*(*cli).fds.add(fd)).dev_type = mount_idx as u8;
                        (*(*cli).fds.add(fd)).flags = flags;
                        (*(*cli).fds.add(fd)).mount_batch_count = 0;
                        (*(*cli).fds.add(fd)).mount_batch_index = 0;
                        (*(*cli).fds.add(fd)).mount_batch_next_cursor = 0;
                        (*reply).label = BESALT_OK;
                        (*reply).length = 1;
                        (*reply).regs[0] = fd as u64;
                        return;
                    }
                }
                (*reply).label = BESALT_OUT_OF_MEMORY;
                return;
            }
        }

        let mut inode = resolve_path_from(start_ino, path, path_len);

        if inode.is_null() {
            if (flags & O_CREAT) == 0 {
                (*reply).label = BESALT_NOT_FOUND;
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
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }
        } else if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
            (*reply).label = BESALT_ALREADY_EXISTS;
            return;
        }

        if (*inode).ftype == FTYPE_DIRECTORY {
            if flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0 {
                (*reply).label = BESALT_INVALID_OPERATION;
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
                        (*reply).label = BESALT_OUT_OF_MEMORY;
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
                            (*reply).label = BESALT_OK;
                            (*reply).length = 1;
                            (*reply).regs[0] = fd as u64;
                            return;
                        }
                    }
                    (*reply).label = BESALT_OUT_OF_MEMORY;
                    return;
                }
            }
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }

        if (*inode).ftype == FTYPE_REGULAR {
            if (*inode).readonly != 0
                && (flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0)
            {
                (*reply).label = BESALT_INVALID_OPERATION;
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
            (*reply).label = BESALT_OUT_OF_MEMORY;
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
                        (*reply).label = BESALT_INVALID_OPERATION;
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
                (*reply).label = BESALT_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return;
            }
        }

        (*reply).label = BESALT_OUT_OF_MEMORY;
    }
}

/// openat(dirfd, path, flags, mode)
/// IPC: reg[0]=dirfd, reg[1]=open_flags, reg[2]=mode, reg[3..]=path(len+data)
pub(crate) unsafe fn handle_openat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let flags = (*msg).regs[1] as u32;
        let mode = (*msg).regs[2] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        do_open(start_ino, path.as_ptr(), path_len, flags, mode, reply, badge);
    }
}

/// fstatat(dirfd, path, statbuf, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub(crate) unsafe fn handle_fstatat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 && !((at_flags & AT_EMPTY_PATH_VAL) != 0 && path_len == 0) {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let inode = if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 {
            // AT_EMPTY_PATH: stat the fd itself
            if dirfd < 0 {
                (*reply).label = BESALT_INVALID_ARGUMENT;
                return;
            }
            let cli = get_client(badge);
            if cli.is_null()
                || dirfd >= (*cli).fds_cap as i32
                || (*(*cli).fds.add(dirfd as usize)).active == 0
            {
                (*reply).label = BESALT_INVALID_ARGUMENT;
                return;
            }
            inode_by_ino((*(*cli).fds.add(dirfd as usize)).inode)
        } else {
            // Normalize relative paths and check for mount points
            let mut abs_buf = [0u8; MAX_PATH_LEN];
            if let Some((norm_ptr, norm_len)) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, abs_buf.as_mut_ptr())
            {
                let norm_slice = core::slice::from_raw_parts(norm_ptr, norm_len as usize);
                if let Some(mount_idx) = find_mount_for_path(norm_slice, norm_len) {
                    let (_, sub_start, sub_len) = parse_mount_path(norm_slice, norm_len);
                    if sub_len > 0 {
                        let remote_ino = mount_lookup(mount_idx, norm_ptr.add(sub_start), sub_len);
                        if remote_ino == 0 {
                            (*reply).label = BESALT_NOT_FOUND;
                            return;
                        }
                        match mount_stat(mount_idx, remote_ino) {
                            Some((size, mode, nlink, mtime, _)) => {
                                (*reply).label = BESALT_OK;
                                (*reply).length = 8;
                                (*reply).regs[0] = remote_ino;
                                (*reply).regs[1] = mode as u64;
                                (*reply).regs[2] = nlink as u64;
                                (*reply).regs[3] = size;
                                (*reply).regs[4] = 0;
                                (*reply).regs[5] = 0;
                                (*reply).regs[6] = mtime;
                                (*reply).regs[7] = if (mode & S_IFMT_L) == S_IFDIR_L {
                                    FTYPE_DIRECTORY as u64
                                } else {
                                    FTYPE_REGULAR as u64
                                };
                            }
                            None => {
                                (*reply).label = BESALT_NOT_FOUND;
                            }
                        }
                        return;
                    }
                }
            }
            resolve_path_from(start_ino, path.as_ptr(), path_len)
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
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

/// unlinkat(dirfd, path, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
pub(crate) unsafe fn handle_unlinkat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        if (at_flags & AT_REMOVEDIR_VAL) != 0 {
            // AT_REMOVEDIR: act like rmdir
            let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
            if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }
            if (*inode).readonly != 0 {
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }
            for i in 0..(*inode).dirents_cap as usize {
                if (*(*inode).dirents.add(i)).active != 0 {
                    (*reply).label = BESALT_INVALID_OPERATION;
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
            (*reply).label = BESALT_OK;
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
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }
            let de = dir_find_entry(parent, child_name, child_len);
            if de.is_null() {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }
            let inode = inode_by_ino((*de).ino);
            if inode.is_null() || (*inode).ftype == FTYPE_DIRECTORY {
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }
            (*de).active = 0;
            (*inode).nlink = (*inode).nlink.saturating_sub(1);
            if (*inode).nlink == 0 && (*inode).open_count == 0 {
                free_inode(inode);
            }
            (*reply).label = BESALT_OK;
        }
    }
}

/// renameat(old_dirfd, old_path, new_dirfd, new_path)
/// IPC: reg[0]=old_dirfd, reg[1]=new_dirfd, reg[2]=old_len, reg[3]=new_len, reg[4..]=paths
pub(crate) unsafe fn handle_renameat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let mut old_len = (*msg).regs[2] as u8;
        let mut new_len = (*msg).regs[3] as u8;
        if (old_len as usize) > MAX_PATH_LEN {
            old_len = MAX_PATH_LEN as u8;
        }
        if (new_len as usize) > MAX_PATH_LEN {
            new_len = MAX_PATH_LEN as u8;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let raw = &(*msg).regs[4] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }

        let old_start = resolve_at_start(badge, old_dirfd, old_path.as_ptr(), old_len);
        let new_start = resolve_at_start(badge, new_dirfd, new_path.as_ptr(), new_len);
        if old_start == 0 || new_start == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
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
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        let de = dir_find_entry(old_parent, old_child, old_child_len);
        if de.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
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
            (*reply).label = BESALT_INVALID_OPERATION;
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
        (*reply).label = BESALT_OK;
    }
}

/// mkdirat(dirfd, path, mode)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2..]=path(len+data)
pub(crate) unsafe fn handle_mkdirat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let existing = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if !existing.is_null() {
            (*reply).label = BESALT_ALREADY_EXISTS;
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
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        let dir = alloc_inode();
        if dir.is_null() {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return;
        }

        (*dir).ftype = FTYPE_DIRECTORY;
        (*dir).mode = S_IFDIR_L | (mode & 0o777);
        (*dir).nlink = 2;
        (*dir).parent_ino = (*parent).ino;

        dir_add_entry(parent, child_name, child_len, (*dir).ino);
        (*reply).label = BESALT_OK;
    }
}

/// faccessat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
pub(crate) unsafe fn handle_faccessat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }
        (*reply).label = BESALT_OK;
    }
}

/// fchmodat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
/// Single-user OS — resolve path, verify exists, return OK.
pub(crate) unsafe fn handle_fchmodat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }
        (*reply).label = BESALT_OK;
    }
}

/// fchownat(dirfd, path, uid, gid, flags)
/// IPC: reg[0]=dirfd, reg[1]=uid, reg[2]=gid, reg[3]=at_flags, reg[4..]=path(len+data)
/// Single-user OS — resolve path, verify exists, return OK.
pub(crate) unsafe fn handle_fchownat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 4, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }
        (*reply).label = BESALT_OK;
    }
}

/// fchmod(fd, mode) — change mode on open fd
/// IPC: reg[0]=fd, reg[1]=mode
/// Single-user OS — verify fd exists, return OK.
pub(crate) unsafe fn handle_fchmod(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }
        (*reply).label = BESALT_OK;
    }
}

/// fchown(fd, uid, gid) — change owner on open fd
/// IPC: reg[0]=fd, reg[1]=uid, reg[2]=gid
/// Single-user OS — verify fd exists, return OK.
pub(crate) unsafe fn handle_fchown(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }
        (*reply).label = BESALT_OK;
    }
}

/// utimensat(dirfd, path, times, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2]=atime_sec, reg[3]=atime_nsec,
///      reg[4]=mtime_sec, reg[5]=mtime_nsec, reg[6..]=path(len+data)
pub(crate) unsafe fn handle_utimensat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let _atime_sec = (*msg).regs[2] as i64;
        let _atime_nsec = (*msg).regs[3] as i64;
        let mtime_sec = (*msg).regs[4] as i64;
        let mtime_nsec = (*msg).regs[5] as i64;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 6, path.as_mut_ptr());

        let inode = if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 {
            // Operate on dirfd itself
            if dirfd < 0 || dirfd == AT_FDCWD_VAL {
                (*reply).label = BESALT_INVALID_ARGUMENT;
                return;
            }
            let cli = get_client(badge);
            if cli.is_null()
                || dirfd >= (*cli).fds_cap as i32
                || (*(*cli).fds.add(dirfd as usize)).active == 0
            {
                (*reply).label = BESALT_INVALID_ARGUMENT;
                return;
            }
            inode_by_ino((*(*cli).fds.add(dirfd as usize)).inode)
        } else {
            let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
            if start_ino == 0 {
                (*reply).label = BESALT_INVALID_ARGUMENT;
                return;
            }
            // Normalize relative paths and check for mount points
            let mut abs_buf = [0u8; MAX_PATH_LEN];
            if let Some((norm_ptr, norm_len)) =
                normalize_path_for_client(badge, path.as_ptr(), path_len, abs_buf.as_mut_ptr())
            {
                let norm_slice = core::slice::from_raw_parts(norm_ptr, norm_len as usize);
                if let Some(_mount_idx) = find_mount_for_path(norm_slice, norm_len) {
                    // No SaltyFS utimensat support yet — return OK silently
                    (*reply).label = BESALT_OK;
                    return;
                }
            }
            resolve_path_from(start_ino, path.as_ptr(), path_len)
        };

        if inode.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
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
                    besalt::syscall::syscall(besalt::consts::SYS_CLOCK_GETTIME, 0, 0, 0, 0, 0, 0);
                let now_sec = res.value / 1_000_000_000;
                (*inode).mtime = now_sec as u32;
            } else {
                (*inode).mtime = mtime_sec as u32;
            }
        }

        (*reply).label = BESALT_OK;
    }
}

/// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
/// IPC: regs[0]=old_len, regs[1..9]=oldpath(64B), regs[9]=new_len, regs[10..18]=newpath(64B)
pub(crate) unsafe fn handle_linkat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let old_len = (*msg).regs[0] as u8;
        if old_len == 0 || old_len as usize > 64 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }
        let new_len = (*msg).regs[9] as u8;
        if new_len == 0 || new_len as usize > 64 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        // Extract old path
        let mut old_path = [0u8; MAX_PATH_LEN];
        let src_old = &(*msg).regs[1] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *src_old.add(i);
        }

        // Extract new path
        let mut new_path = [0u8; MAX_PATH_LEN];
        let src_new = &(*msg).regs[10] as *const u64 as *const u8;
        for i in 0..new_len as usize {
            new_path[i] = *src_new.add(i);
        }

        // Build absolute paths for mount check
        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        let mut abs_old = [0u8; MAX_PATH_LEN];
        let abs_old_len: u8;
        if old_path[0] == b'/' {
            for i in 0..old_len as usize { abs_old[i] = old_path[i]; }
            abs_old_len = old_len;
        } else {
            let mut cwd_len: usize = 0;
            while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
                cwd_len += 1;
            }
            let total = cwd_len + 1 + old_len as usize;
            if total > MAX_PATH_LEN {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }
            for i in 0..cwd_len { abs_old[i] = (*cli).cwd[i]; }
            abs_old[cwd_len] = b'/';
            for i in 0..old_len as usize { abs_old[cwd_len + 1 + i] = old_path[i]; }
            abs_old_len = total as u8;
        }

        let mut abs_new = [0u8; MAX_PATH_LEN];
        let abs_new_len: u8;
        if new_path[0] == b'/' {
            for i in 0..new_len as usize {
                abs_new[i] = new_path[i];
            }
            abs_new_len = new_len;
        } else {
            let mut cwd_len: usize = 0;
            while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
                cwd_len += 1;
            }
            let total = cwd_len + 1 + new_len as usize;
            if total > MAX_PATH_LEN {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }
            for i in 0..cwd_len {
                abs_new[i] = (*cli).cwd[i];
            }
            abs_new[cwd_len] = b'/';
            for i in 0..new_len as usize {
                abs_new[cwd_len + 1 + i] = new_path[i];
            }
            abs_new_len = total as u8;
        }

        // Mount path intercept — both paths must be on the same mount
        let old_mount = find_mount_for_path(&abs_old, abs_old_len);
        let new_mount = find_mount_for_path(&abs_new, abs_new_len);
        if old_mount.is_some() || new_mount.is_some() {
            if old_mount != new_mount {
                // Cross-filesystem link not supported
                (*reply).label = BESALT_INVALID_OPERATION;
                return;
            }
            let mount_idx = old_mount.unwrap();
            let (_, old_sub_start, old_sub_len) = parse_mount_path(&abs_old, abs_old_len);
            let (_, new_sub_start, new_sub_len) = parse_mount_path(&abs_new, abs_new_len);

            // Resolve old path to existing inode on SaltyFS
            let existing_ino = mount_lookup(mount_idx, abs_old.as_ptr().add(old_sub_start), old_sub_len);
            if existing_ino == 0 {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }

            // Split new path into parent + leaf
            let (np_start, np_len, nl_start, nl_len) =
                split_mount_sub_path(abs_new.as_ptr().add(new_sub_start), new_sub_len);
            let new_parent_ino = if np_len == 0 {
                (*(&raw const crate::MOUNTS[mount_idx])).root_ino as u64
            } else {
                mount_lookup(mount_idx, abs_new.as_ptr().add(new_sub_start + np_start), np_len)
            };
            if new_parent_ino == 0 {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }

            mount_link(
                mount_idx, existing_ino, new_parent_ino,
                abs_new.as_ptr().add(new_sub_start + nl_start), nl_len,
                reply,
            );
            return;
        }

        // Resolve old path (absolute or relative to cwd)
        let target = if old_path[0] == b'/' {
            resolve_path_raw(old_path.as_ptr(), old_len)
        } else {
            resolve_path_raw(abs_old.as_ptr(), abs_old_len)
        };
        if target.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }

        // Cannot hard-link directories
        if (*target).ftype == FTYPE_DIRECTORY {
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        // Resolve new path parent (already have abs_new from mount check above)
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let new_parent = resolve_parent(
            abs_new.as_ptr(),
            abs_new_len,
            &mut child_name,
            &mut child_len,
        );
        if new_parent.is_null() || (*new_parent).readonly != 0 {
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        // Check new name doesn't already exist
        let existing = dir_find_entry(new_parent, child_name, child_len);
        if !existing.is_null() {
            (*reply).label = BESALT_ALREADY_EXISTS;
            return;
        }

        // Add new directory entry pointing to the same inode
        if dir_add_entry(new_parent, child_name, child_len, (*target).ino) != 0 {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return;
        }

        (*target).nlink += 1;
        (*reply).label = BESALT_OK;
    }
}

/// symlinkat(target, newdirfd, linkpath)
/// IPC: regs[0]=newdirfd, regs[1]=target_len, regs[2..10]=target(64B), regs[10]=link_len, regs[11..19]=link(64B)
pub(crate) unsafe fn handle_symlinkat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let newdirfd = (*msg).regs[0] as i32;

        let target_len = (*msg).regs[1] as u8;
        if target_len == 0 || target_len > 64 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }
        let mut target = [0u8; MAX_PATH_LEN];
        let raw_target = &(*msg).regs[2] as *const u64 as *const u8;
        for i in 0..target_len as usize {
            target[i] = *raw_target.add(i);
        }

        let link_len = (*msg).regs[10] as u8;
        if link_len == 0 || link_len > 64 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }
        let mut link_path = [0u8; MAX_PATH_LEN];
        let raw_link = &(*msg).regs[11] as *const u64 as *const u8;
        for i in 0..link_len as usize {
            link_path[i] = *raw_link.add(i);
        }

        // Build absolute link path for mount check
        let mut abs_link = [0u8; MAX_PATH_LEN];
        let abs_link_len: u8;
        if link_path[0] == b'/' {
            for i in 0..link_len as usize { abs_link[i] = link_path[i]; }
            abs_link_len = link_len;
        } else {
            let cli = get_client(badge);
            if cli.is_null() {
                (*reply).label = BESALT_INVALID_ARGUMENT;
                return;
            }
            let mut cwd_len: usize = 0;
            while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 { cwd_len += 1; }
            let total = cwd_len + 1 + link_len as usize;
            if total > MAX_PATH_LEN {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }
            for i in 0..cwd_len { abs_link[i] = (*cli).cwd[i]; }
            abs_link[cwd_len] = b'/';
            for i in 0..link_len as usize { abs_link[cwd_len + 1 + i] = link_path[i]; }
            abs_link_len = total as u8;
        }

        // Mount path intercept
        if let Some(mount_idx) = find_mount_for_path(&abs_link, abs_link_len) {
            let (_, sub_start, sub_len) = parse_mount_path(&abs_link, abs_link_len);
            let (p_start, p_len, l_start, l_len) =
                split_mount_sub_path(abs_link.as_ptr().add(sub_start), sub_len);
            let parent_ino = if p_len == 0 {
                (*(&raw const crate::MOUNTS[mount_idx])).root_ino as u64
            } else {
                mount_lookup(mount_idx, abs_link.as_ptr().add(sub_start + p_start), p_len)
            };
            if parent_ino == 0 {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }
            mount_symlink(
                mount_idx, parent_ino,
                abs_link.as_ptr().add(sub_start + l_start), l_len,
                target.as_ptr(), target_len,
                reply,
            );
            return;
        }

        // Resolve start inode for the link path using newdirfd
        let start_ino = resolve_at_start(badge, newdirfd, link_path.as_ptr(), link_len);
        if start_ino == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

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
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }
        if child_len == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        // Check that target name doesn't already exist
        let existing = dir_find_entry(parent, child_name, child_len);
        if !existing.is_null() {
            (*reply).label = BESALT_ALREADY_EXISTS;
            return;
        }

        // Allocate symlink target in pool
        let sym_data = alloc_symlink_target(target.as_ptr(), target_len);
        if sym_data.is_null() {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return;
        }

        // Allocate inode
        let inode = alloc_inode();
        if inode.is_null() {
            free_symlink_target(sym_data);
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return;
        }

        (*inode).ftype = FTYPE_SYMLINK;
        (*inode).mode = S_IFLNK_L | 0o777;
        (*inode).nlink = 1;
        (*inode).size = target_len as u64;
        (*inode).rw_data = sym_data;
        (*inode).parent_ino = (*parent).ino;

        dir_add_entry(parent, child_name, child_len, (*inode).ino);
        (*reply).label = BESALT_OK;
    }
}

/// readlinkat(dirfd, path) -> target
/// IPC in: regs[0]=path_len, regs[1..]=path
/// IPC out: regs[0]=target_len, regs[1..]=target
pub(crate) unsafe fn handle_readlinkat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());

        if raw_len == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        };

        // Mount path intercept for readlink
        if let Some(mount_idx) = find_mount_for_path(
            core::slice::from_raw_parts(path_ptr, path_len as usize), path_len,
        ) {
            let (_, sub_start, sub_len) = parse_mount_path(
                core::slice::from_raw_parts(path_ptr, path_len as usize), path_len,
            );
            let remote_ino = mount_lookup(mount_idx, path_ptr.add(sub_start), sub_len);
            if remote_ino == 0 {
                (*reply).label = BESALT_NOT_FOUND;
                return;
            }
            mount_readlink(mount_idx, remote_ino, reply);
            return;
        }

        let inode = resolve_path_raw_nofollow(path_ptr, path_len);
        if inode.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }

        if (*inode).ftype != FTYPE_SYMLINK {
            (*reply).label = BESALT_INVALID_OPERATION;
            return;
        }

        let (target, target_len) = symlink_target(inode);
        if target.is_null() || target_len == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        (*reply).label = BESALT_OK;
        (*reply).regs[0] = target_len as u64;
        (*reply).length = 1 + ((target_len as u64 + 7) / 8);
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        for i in 0..target_len as usize {
            *dst.add(i) = *target.add(i);
        }
    }
}

/// lstat: stat without following final symlink
pub(crate) unsafe fn handle_lstat(msg: *const BesaltMsg, reply: *mut BesaltMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = BESALT_INVALID_ARGUMENT;
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
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}
