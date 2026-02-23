// SPDX-License-Identifier: GPL-2.0-only
//! Core file operations: open, read, write, close, stat, lseek, and mkdir.

use salty::consts::*;
use salty::ipc;
use salty::types::*;

use crate::client::{
    extract_path, flags_allow_read, flags_allow_write, get_client, get_client_noalloc,
};
use crate::consts::*;
use crate::ipc_ctx;
use crate::mount::{
    find_mount_for_path, mount_create, mount_lookup, mount_mkdir, mount_rename, mount_rmdir,
    mount_stat, mount_truncate, mount_unlink, parse_mount_path, split_mount_sub_path,
};
use crate::path::{resolve_parent, resolve_path};
use crate::pipe::{alloc_pipe, find_pipe};
use crate::procfs::{handle_proc_open, handle_proc_read, handle_proc_readdir, handle_proc_stat};
use crate::ramfs::{
    alloc_inode, alloc_writable, chain_read, chain_truncate, chain_write, dir_add_entry,
    dir_find_entry, dir_remove_entry, free_inode, inode_by_ino, inode_close, inode_open,
};
use crate::types::*;

/// Normalize a user path to canonical absolute form using the caller's cwd.
/// This collapses repeated '/', '.' and '..' components.
/// Returns (absolute_path_ptr, absolute_len).
pub(crate) unsafe fn normalize_path_for_client(
    badge: u64,
    in_path: *const u8,
    in_len: u8,
    tmp_abs: *mut u8,
) -> Option<(*const u8, u8)> {
    unsafe {
        if in_len == 0 {
            return None;
        }
        let mut raw_abs = [0u8; MAX_PATH_LEN];
        let raw_len: usize;

        if *in_path == b'/' {
            raw_len = in_len as usize;
            if raw_len == 0 || raw_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..raw_len {
                raw_abs[i] = *in_path.add(i);
            }
        } else {
            let cli = get_client_noalloc(badge);
            if cli.is_null() {
                return None;
            }

            let mut cwd_len: usize = 0;
            while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
                cwd_len += 1;
            }
            if cwd_len == 0 {
                cwd_len = 1;
            }

            let cwd_is_root = cwd_len == 1 && (*cli).cwd[0] == b'/';
            let rel_len = in_len as usize;
            raw_len = if cwd_is_root {
                1 + rel_len
            } else {
                cwd_len + 1 + rel_len
            };
            if raw_len > MAX_PATH_LEN {
                return None;
            }

            if cwd_is_root {
                raw_abs[0] = b'/';
                for i in 0..rel_len {
                    raw_abs[1 + i] = *in_path.add(i);
                }
            } else {
                for i in 0..cwd_len {
                    raw_abs[i] = (*cli).cwd[i];
                }
                raw_abs[cwd_len] = b'/';
                for i in 0..rel_len {
                    raw_abs[cwd_len + 1 + i] = *in_path.add(i);
                }
            }
        }

        // Canonicalize absolute path in raw_abs into tmp_abs.
        // Output always starts with '/' and has no trailing slash except root.
        let mut out_len: usize = 1;
        *tmp_abs = b'/';
        let mut comp_starts = [0usize; MAX_PATH_LEN / 2];
        let mut depth: usize = 0;

        let mut pos: usize = 0;
        if raw_len > 0 && raw_abs[0] == b'/' {
            pos = 1;
        }

        while pos < raw_len {
            while pos < raw_len && raw_abs[pos] == b'/' {
                pos += 1;
            }
            if pos >= raw_len {
                break;
            }

            let start = pos;
            while pos < raw_len && raw_abs[pos] != b'/' {
                pos += 1;
            }
            let seg_len = pos - start;
            if seg_len == 0 {
                continue;
            }

            if seg_len == 1 && raw_abs[start] == b'.' {
                continue;
            }
            if seg_len == 2 && raw_abs[start] == b'.' && raw_abs[start + 1] == b'.' {
                if depth > 0 {
                    depth -= 1;
                    out_len = comp_starts[depth];
                    if out_len == 0 {
                        out_len = 1;
                        *tmp_abs = b'/';
                    }
                }
                continue;
            }

            if depth >= comp_starts.len() {
                return None;
            }
            if out_len > 1 {
                if out_len >= MAX_PATH_LEN {
                    return None;
                }
                *tmp_abs.add(out_len) = b'/';
                out_len += 1;
            }
            comp_starts[depth] = out_len;
            depth += 1;

            if out_len + seg_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..seg_len {
                *tmp_abs.add(out_len + i) = raw_abs[start + i];
            }
            out_len += seg_len;
        }

        if out_len == 0 || out_len > u8::MAX as usize {
            return None;
        }
        Some((tmp_abs as *const u8, out_len as u8))
    }
}

pub(crate) unsafe fn handle_open(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let mode = (*msg).regs[0] as u32;
        let flags = (*msg).regs[1] as u32;
        let raw_len = extract_path(msg, 2, path.as_mut_ptr());

        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);

        // /proc virtual paths — intercept before resolve
        if path_len >= 6
            && *path_ptr == b'/'
            && *path_ptr.add(1) == b'p'
            && *path_ptr.add(2) == b'r'
            && *path_ptr.add(3) == b'o'
            && *path_ptr.add(4) == b'c'
            && *path_ptr.add(5) == b'/'
        {
            if handle_proc_open(path_ptr, path_len, reply, badge) {
                return;
            }
        }

        // Mount point intercept: paths under /mnt/data/
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            if sub_len > 0 {
                // File within mount — lookup and open
                let mut remote_ino = mount_lookup(mount_idx, path_ptr.add(sub_start), sub_len);
                if remote_ino == 0 {
                    if (flags & O_CREAT) == 0 {
                        (*reply).label = SALTY_NOT_FOUND;
                        return;
                    }
                    // O_CREAT: create the file via mount FS server
                    let (p_start, p_len, l_start, l_len) =
                        split_mount_sub_path(path_ptr.add(sub_start), sub_len);
                    let parent_ino = if p_len == 0 {
                        (*(&raw const crate::MOUNTS[mount_idx])).root_ino as u64
                    } else {
                        mount_lookup(mount_idx, path_ptr.add(sub_start + p_start), p_len)
                    };
                    if parent_ino == 0 {
                        (*reply).label = SALTY_NOT_FOUND;
                        return;
                    }
                    remote_ino = mount_create(
                        mount_idx, parent_ino,
                        path_ptr.add(sub_start + l_start), l_len, mode & 0o777,
                    );
                    if remote_ino == 0 {
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }
                }

                // Stat the remote inode for metadata
                let stat = mount_stat(mount_idx, remote_ino);
                let (_size, _mode, _nlink, _mtime, is_dir) = match stat {
                    Some(s) => s,
                    None => {
                        (*reply).label = SALTY_NOT_FOUND;
                        return;
                    }
                };

                if is_dir {
                    // Directory open: use handle_opendir-style logic
                    let cli = get_client(badge);
                    if cli.is_null() {
                        (*reply).label = SALTY_OUT_OF_MEMORY;
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
                            (*reply).label = SALTY_OK;
                            (*reply).length = 1;
                            (*reply).regs[0] = fd as u64;
                            return;
                        }
                    }
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                // Regular file: allow both read and write
                // Handle O_TRUNC
                if (flags & O_TRUNC) != 0 && flags_allow_write(flags) {
                    let mut trunc_reply = SaltyMsg::zeroed();
                    mount_truncate(mount_idx, remote_ino, 0, &raw mut trunc_reply);
                    if trunc_reply.label != SALTY_OK {
                        (*reply).label = trunc_reply.label;
                        return;
                    }
                }

                let cli = get_client(badge);
                if cli.is_null() {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
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
                        (*reply).label = SALTY_OK;
                        (*reply).length = 1;
                        (*reply).regs[0] = fd as u64;
                        return;
                    }
                }
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            // Exact "/mnt/data" — falls through to resolve_path (it's a local dir)
        }

        let mut inode = resolve_path(path_ptr, path_len);

        if inode.is_null() {
            if (flags & O_CREAT) == 0 {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }

            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
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
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }
        } else if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        // Validate access mode
        if (*inode).ftype == FTYPE_DIRECTORY {
            if flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        if (*inode).ftype == FTYPE_REGULAR {
            if (*inode).readonly != 0
                && (flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0)
            {
                (*reply).label = SALTY_INVALID_OPERATION;
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
            (*reply).label = SALTY_OUT_OF_MEMORY;
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
                    // FIFO: create pipe fd using the pipe_id stored in inode.size
                    let pipe_id = (*inode).size as u32;
                    let pipe = find_pipe(pipe_id);
                    if pipe.is_null() {
                        (*(*cli).fds.add(fd)).active = 0;
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_PIPE;
                    (*(*cli).fds.add(fd)).sock_id = pipe_id;
                    if flags_allow_write(flags) {
                        (*(*cli).fds.add(fd)).flags = O_WRONLY;
                        (*pipe).write_refcount += 1;
                    } else {
                        (*(*cli).fds.add(fd)).flags = 0; // O_RDONLY
                        (*pipe).read_refcount += 1;
                    }
                } else {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_FILE;
                    if (flags & O_APPEND) != 0 {
                        (*(*cli).fds.add(fd)).offset = (*inode).size;
                    }
                }

                inode_open((*inode).ino);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return;
            }
        }

        (*reply).label = SALTY_OUT_OF_MEMORY;
    }
}

pub(crate) unsafe fn handle_read(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if count > 152 {
            count = 152;
        }

        if !flags_allow_read((*(*cli).fds.add(fd as usize)).flags) {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let fde = &mut *(*cli).fds.add(fd as usize);

        match fde.fd_type {
            FD_TYPE_DEVICE => match fde.dev_type {
                DEV_CONSOLE => {
                    let mut creq = SaltyMsg::zeroed();
                    let mut creply = SaltyMsg::zeroed();
                    creq.label = CONSOLE_READ;
                    creq.length = 0;

                    let err = ipc::call_ctx(
                        ipc_ctx(),
                        VFS_CAP_CONSOLE_EP,
                        &raw const creq,
                        &raw mut creply,
                    );
                    if err != 0 || creply.label != SALTY_OK {
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }

                    let read_count = creply.regs[0];
                    if read_count == 0 {
                        (*reply).label = SALTY_OK;
                        (*reply).length = 1;
                        (*reply).regs[0] = 0;
                    } else {
                        let actual = if read_count > count {
                            count
                        } else {
                            read_count
                        };
                        (*reply).label = SALTY_OK;
                        (*reply).length = 1 + (actual + 7) / 8;
                        (*reply).regs[0] = actual;
                        let src = &creply.regs[1] as *const u64 as *const u8;
                        let dst = &raw mut (*reply).regs[1] as *mut u8;
                        for i in 0..actual as usize {
                            *dst.add(i) = *src.add(i);
                        }
                    }
                }
                DEV_NULL => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                }
                DEV_ZERO => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1 + (count + 7) / 8;
                    (*reply).regs[0] = count;
                    let data = &raw mut (*reply).regs[1] as *mut u8;
                    for i in 0..count as usize {
                        *data.add(i) = 0;
                    }
                }
                DEV_URANDOM => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1 + (count + 7) / 8;
                    (*reply).regs[0] = count;
                    let data = &raw mut (*reply).regs[1] as *mut u8;
                    let mut i: u64 = 0;
                    while i + 8 <= count {
                        let v = crate::urandom_next();
                        let bytes = v.to_le_bytes();
                        for j in 0..8 {
                            *data.add(i as usize + j) = bytes[j];
                        }
                        i += 8;
                    }
                    if i < count {
                        let v = crate::urandom_next();
                        let bytes = v.to_le_bytes();
                        let mut j = 0usize;
                        while i < count {
                            *data.add(i as usize) = bytes[j];
                            i += 1;
                            j += 1;
                        }
                    }
                }
                DEV_FB0 => {
                    (*reply).label = SALTY_INVALID_OPERATION;
                }
                DEV_PTY_SLAVE => {
                    // PTY reads should go through main loop dispatch for deferred support.
                    // If we end up here, do a non-blocking try-read.
                    let pty_id = fde.sock_id as u64;
                    let mut treq = SaltyMsg::zeroed();
                    let mut treply = SaltyMsg::zeroed();
                    treq.label = TTYD_PTY_READ;
                    treq.regs[0] = pty_id;
                    treq.regs[1] = count;
                    treq.length = 2;
                    let err =
                        ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                    if err != 0 || treply.label != SALTY_OK {
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }
                    let actual = treply.regs[0];
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1 + (actual + 7) / 8;
                    (*reply).regs[0] = actual;
                    if actual > 0 {
                        let src = &treply.regs[1] as *const u64 as *const u8;
                        let dst = &raw mut (*reply).regs[1] as *mut u8;
                        for i in 0..actual as usize {
                            *dst.add(i) = *src.add(i);
                        }
                    }
                }
                _ => {
                    (*reply).label = SALTY_INVALID_OPERATION;
                }
            },
            FD_TYPE_FILE => {
                let inode = inode_by_ino(fde.inode);
                if inode.is_null() {
                    (*reply).label = SALTY_INVALID_ARGUMENT;
                    return;
                }

                // /proc virtual files
                if (*inode).ftype == FTYPE_PROC_FILE {
                    let offset = fde.offset;
                    handle_proc_read(inode, offset, reply);
                    let bytes_read = (*reply).regs[0];
                    (*(*cli).fds.add(fd as usize)).offset += bytes_read;
                    return;
                }

                let offset = fde.offset;
                if offset >= (*inode).size {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return;
                }

                let avail = (*inode).size - offset;
                if count > avail {
                    count = avail;
                }

                let dst = &raw mut (*reply).regs[1] as *mut u8;
                if !(*inode).ro_data.is_null() {
                    let src = (*inode).ro_data.add(offset as usize);
                    for i in 0..count as usize {
                        *dst.add(i) = *src.add(i);
                    }
                } else if !(*inode).rw_data.is_null() {
                    let actual = chain_read((*inode).rw_data, offset, dst, count);
                    count = actual;
                } else {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return;
                }

                (*reply).label = SALTY_OK;
                (*reply).length = 1 + (count + 7) / 8;
                (*reply).regs[0] = count;

                fde.offset = offset + count;
            }
            _ => {
                (*reply).label = SALTY_INVALID_OPERATION;
            }
        }
    }
}

pub(crate) unsafe fn handle_write(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if count > 144 {
            count = 144;
        }

        if !flags_allow_write((*(*cli).fds.add(fd as usize)).flags) {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let fde = &mut *(*cli).fds.add(fd as usize);

        match fde.fd_type {
            FD_TYPE_DEVICE => match fde.dev_type {
                DEV_CONSOLE => {
                    let src = &(*msg).regs[2] as *const u64 as *const u8;
                    let mut sent: u64 = 0;
                    while sent < count {
                        let mut creq = SaltyMsg::zeroed();
                        let mut creply = SaltyMsg::zeroed();
                        let mut chunk = count - sent;
                        if chunk > 24 {
                            chunk = 24;
                        }

                        creq.label = CONSOLE_WRITE;
                        creq.length = 1 + (chunk + 7) / 8;
                        creq.regs[0] = chunk;

                        let dst = &raw mut creq.regs[1] as *mut u8;
                        for i in 0..chunk as usize {
                            *dst.add(i) = *src.add(sent as usize + i);
                        }

                        let err = ipc::call_ctx(
                            ipc_ctx(),
                            VFS_CAP_CONSOLE_EP,
                            &raw const creq,
                            &raw mut creply,
                        );
                        if err != 0 || creply.label != SALTY_OK {
                            break;
                        }
                        sent += chunk;
                    }
                    (*reply).label = if sent > 0 {
                        SALTY_OK
                    } else {
                        SALTY_INVALID_OPERATION
                    };
                    (*reply).length = 1;
                    (*reply).regs[0] = sent;
                }
                DEV_NULL | DEV_ZERO | DEV_URANDOM => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = count;
                }
                DEV_PTY_SLAVE => {
                    // Forward write to ttyd for OPOST processing + serial/display output
                    let pty_id = fde.sock_id as u64;
                    let src = &(*msg).regs[2] as *const u64 as *const u8;
                    let mut sent: u64 = 0;
                    while sent < count {
                        let mut treq = SaltyMsg::zeroed();
                        let mut treply = SaltyMsg::zeroed();
                        let mut chunk = count - sent;
                        if chunk > 136 {
                            // 17 regs * 8 bytes (regs[2..19])
                            chunk = 136;
                        }
                        treq.label = TTYD_PTY_WRITE;
                        treq.regs[0] = pty_id;
                        treq.regs[1] = chunk;
                        let dst = &raw mut treq.regs[2] as *mut u8;
                        for i in 0..chunk as usize {
                            *dst.add(i) = *src.add(sent as usize + i);
                        }
                        treq.length = 2 + (chunk + 7) / 8;
                        let err = ipc::call_ctx(
                            ipc_ctx(),
                            VFS_CAP_TTYD_EP,
                            &raw const treq,
                            &raw mut treply,
                        );
                        if err != 0 || treply.label != SALTY_OK {
                            break;
                        }
                        sent += chunk;
                    }
                    (*reply).label = if sent > 0 {
                        SALTY_OK
                    } else {
                        SALTY_INVALID_OPERATION
                    };
                    (*reply).length = 1;
                    (*reply).regs[0] = sent;
                }
                DEV_FB0 => {
                    (*reply).label = SALTY_INVALID_OPERATION;
                }
                _ => {
                    (*reply).label = SALTY_INVALID_OPERATION;
                }
            },
            FD_TYPE_FILE => {
                let inode = inode_by_ino(fde.inode);
                if inode.is_null() || (*inode).readonly != 0 {
                    (*reply).label = SALTY_INVALID_OPERATION;
                    return;
                }

                if (*inode).rw_data.is_null() {
                    (*inode).rw_data = alloc_writable();
                    if (*inode).rw_data.is_null() {
                        (*reply).label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                }

                let mut offset = fde.offset;
                if (fde.flags & O_APPEND) != 0 {
                    offset = (*inode).size;
                }

                let src = &(*msg).regs[2] as *const u64 as *const u8;
                let written = chain_write((*inode).rw_data, offset, src, count);
                if written == 0 && count > 0 {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                count = written;

                fde.offset = offset + count;
                if fde.offset > (*inode).size {
                    (*inode).size = fde.offset;
                }

                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = count;
            }
            _ => {
                (*reply).label = SALTY_INVALID_OPERATION;
            }
        }
    }
}

/// Positioned read: read at an explicit offset without updating the fd cursor.
/// IPC: regs[0]=fd, regs[1]=count, regs[2]=offset (i64).
/// Only supported for FD_TYPE_FILE (not devices, pipes, or sockets).
pub(crate) unsafe fn handle_pread(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];
        let offset = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if count > 152 {
            count = 152;
        }

        let fde = &*(*cli).fds.add(fd as usize);

        if !flags_allow_read(fde.flags) {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        if fde.fd_type != FD_TYPE_FILE {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let inode = inode_by_ino(fde.inode);
        if inode.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if offset >= (*inode).size {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let avail = (*inode).size - offset;
        if count > avail {
            count = avail;
        }

        let dst = &raw mut (*reply).regs[1] as *mut u8;
        if !(*inode).ro_data.is_null() {
            let src = (*inode).ro_data.add(offset as usize);
            for i in 0..count as usize {
                *dst.add(i) = *src.add(i);
            }
        } else if !(*inode).rw_data.is_null() {
            let actual = chain_read((*inode).rw_data, offset, dst, count);
            count = actual;
        } else {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1 + (count + 7) / 8;
        (*reply).regs[0] = count;
        // Note: fd cursor (fde.offset) is NOT updated
    }
}

/// Positioned write: write at an explicit offset without updating the fd cursor.
/// IPC: regs[0]=fd, regs[1]=count, regs[2]=offset (i64), regs[3..]=data.
/// Only supported for FD_TYPE_FILE (not devices, pipes, or sockets).
pub(crate) unsafe fn handle_pwrite(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];
        let offset = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Data starts at regs[3], max 17 regs available (regs[3..19]) = 136 bytes
        if count > 136 {
            count = 136;
        }

        let fde = &*(*cli).fds.add(fd as usize);

        if !flags_allow_write(fde.flags) {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        if fde.fd_type != FD_TYPE_FILE {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let inode = inode_by_ino(fde.inode);
        if inode.is_null() || (*inode).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        if (*inode).rw_data.is_null() {
            (*inode).rw_data = alloc_writable();
            if (*inode).rw_data.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        let src = &(*msg).regs[3] as *const u64 as *const u8;
        let written = chain_write((*inode).rw_data, offset, src, count);
        if written == 0 && count > 0 {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }
        count = written;

        let end = offset + count;
        if end > (*inode).size {
            (*inode).size = end;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = count;
        // Note: fd cursor (fde.offset) is NOT updated
    }
}

pub(crate) unsafe fn handle_close(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);

        // SHM close: tell mmsrv to unmap the SHM pages from this client
        if fde.fd_type == FD_TYPE_SHM && fde.offset != 0 {
            let inode = inode_by_ino(fde.inode);
            if !inode.is_null() && (*inode).ftype == FTYPE_SHM {
                let shm_idx = (*inode).dev_type as usize;
                let mut mm_msg = SaltyMsg::zeroed();
                let mut mm_reply_msg = SaltyMsg::zeroed();
                mm_msg.label = MM_SHM_UNMAP;
                mm_msg.length = 3;
                mm_msg.regs[0] = shm_idx as u64;
                mm_msg.regs[1] = badge;
                mm_msg.regs[2] = fde.offset; // mapped vaddr
                let _ = ipc::call_ctx(
                    ipc_ctx(),
                    VFS_CAP_MMSRV_EP,
                    &raw const mm_msg,
                    &raw mut mm_reply_msg,
                );
            }
        }

        // Decrement inode open count
        if fde.fd_type != FD_TYPE_PIPE && fde.fd_type != FD_TYPE_SOCKET {
            inode_close(fde.inode);
        }

        (*(*cli).fds.add(fd as usize)).active = 0;
        (*reply).label = SALTY_OK;
    }
}

pub(crate) unsafe fn handle_lseek(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let offset = (*msg).regs[1] as i64;
        let whence = (*msg).regs[2] as i32;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fdt = (*(*cli).fds.add(fd as usize)).fd_type;
        if fdt != FD_TYPE_FILE && fdt != FD_TYPE_MOUNT {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // For mount FDs, we need the file size from the remote FS for SEEK_END
        let file_size: u64 = if fdt == FD_TYPE_MOUNT {
            let fde = &*(*cli).fds.add(fd as usize);
            match mount_stat(fde.dev_type as usize, fde.sock_id as u64) {
                Some((size, _, _, _, _)) => size,
                None => 0,
            }
        } else {
            let inode = inode_by_ino((*(*cli).fds.add(fd as usize)).inode);
            if inode.is_null() {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            (*inode).size
        };

        let new_offset: i64 = match whence {
            0 => offset,                                                // SEEK_SET
            1 => (*(*cli).fds.add(fd as usize)).offset as i64 + offset, // SEEK_CUR
            2 => file_size as i64 + offset,                             // SEEK_END
            _ => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };

        if new_offset < 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        (*(*cli).fds.add(fd as usize)).offset = new_offset as u64;
        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_offset as u64;
    }
}

pub(crate) unsafe fn fill_stat_reply(reply: *mut SaltyMsg, inode: *const RamfsInode) {
    unsafe {
        (*reply).label = SALTY_OK;
        (*reply).length = 8;
        (*reply).regs[0] = (*inode).ino as u64;
        (*reply).regs[1] = (*inode).mode as u64;
        (*reply).regs[2] = (*inode).nlink as u64;
        (*reply).regs[3] = (*inode).size;
        (*reply).regs[4] = 0; // uid
        (*reply).regs[5] = 0; // gid
        (*reply).regs[6] = (*inode).mtime as u64;
        (*reply).regs[7] = if (*inode).ftype == FTYPE_MOUNT_POINT {
            FTYPE_DIRECTORY as u64
        } else {
            (*inode).ftype as u64
        };
    }
}

pub(crate) unsafe fn handle_fstat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Mount FD: proxy stat to remote FS
        if (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_MOUNT {
            let fde = &*(*cli).fds.add(fd as usize);
            let mount_idx = fde.dev_type as usize;
            let remote_ino = fde.sock_id as u64;
            match mount_stat(mount_idx, remote_ino) {
                Some((size, mode, nlink, mtime, _)) => {
                    (*reply).label = SALTY_OK;
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
                    (*reply).label = SALTY_INVALID_ARGUMENT;
                }
            }
            return;
        }

        let inode = inode_by_ino((*(*cli).fds.add(fd as usize)).inode);
        if inode.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

pub(crate) unsafe fn handle_stat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);

        // Mount point intercept for stat
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            if sub_len > 0 {
                let remote_ino = mount_lookup(mount_idx, path_ptr.add(sub_start), sub_len);
                if remote_ino == 0 {
                    (*reply).label = SALTY_NOT_FOUND;
                    return;
                }
                match mount_stat(mount_idx, remote_ino) {
                    Some((size, mode, nlink, mtime, _)) => {
                        (*reply).label = SALTY_OK;
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
                        } else {
                            FTYPE_REGULAR as u64
                        };
                    }
                    None => {
                        (*reply).label = SALTY_NOT_FOUND;
                    }
                }
                return;
            }
            // Exact mount point — fall through to local resolve
        }

        let inode = resolve_path(path_ptr, path_len);
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
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

pub(crate) unsafe fn handle_access(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() {
            // /proc virtual paths always accessible (read-only)
            if path_len >= 6
                && *path_ptr == b'/'
                && *path_ptr.add(1) == b'p'
                && *path_ptr.add(2) == b'r'
                && *path_ptr.add(3) == b'o'
                && *path_ptr.add(4) == b'c'
                && *path_ptr.add(5) == b'/'
            {
                if handle_proc_stat(path_ptr, path_len, &mut SaltyMsg::zeroed(), badge) {
                    (*reply).label = SALTY_OK;
                    return;
                }
            }
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        (*reply).label = SALTY_OK;
    }
}

pub(crate) unsafe fn handle_unlink(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        // Mount intercept
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            if sub_len > 0 {
                let (p_start, p_len, l_start, l_len) =
                    split_mount_sub_path(path_ptr.add(sub_start), sub_len);
                let parent_ino = if p_len == 0 {
                    (*(&raw const crate::MOUNTS[mount_idx])).root_ino as u64
                } else {
                    mount_lookup(mount_idx, path_ptr.add(sub_start + p_start), p_len)
                };
                if parent_ino == 0 {
                    (*reply).label = SALTY_NOT_FOUND;
                    return;
                }
                mount_unlink(
                    mount_idx,
                    parent_ino,
                    path_ptr.add(sub_start + l_start),
                    l_len,
                    reply,
                );
                return;
            }
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let de = dir_find_entry(parent, child_name, child_len);
        if de.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let inode = inode_by_ino((*de).ino);
        if inode.is_null() || (*inode).ftype == FTYPE_DIRECTORY {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        (*de).active = 0;
        (*inode).nlink = (*inode).nlink.saturating_sub(1);
        if (*inode).nlink == 0 && (*inode).open_count == 0 {
            free_inode(inode);
        }
        (*reply).label = SALTY_OK;
    }
}

pub(crate) unsafe fn handle_rename(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut old_len = (*msg).regs[0] as u8;
        let mut new_len = (*msg).regs[1] as u8;
        if (old_len as usize) > MAX_PATH_LEN {
            old_len = MAX_PATH_LEN as u8;
        }
        if (new_len as usize) > MAX_PATH_LEN {
            new_len = MAX_PATH_LEN as u8;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let mut old_abs = [0u8; MAX_PATH_LEN];
        let mut new_abs = [0u8; MAX_PATH_LEN];
        let raw = &(*msg).regs[2] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }
        if old_len == 0 || new_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((old_ptr, old_norm_len)) =
            normalize_path_for_client(badge, old_path.as_ptr(), old_len, old_abs.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let Some((new_ptr, new_norm_len)) =
            normalize_path_for_client(badge, new_path.as_ptr(), new_len, new_abs.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        // Mount intercept: both old and new must be in the same mount
        let old_slice = core::slice::from_raw_parts(old_ptr, old_norm_len as usize);
        let new_slice = core::slice::from_raw_parts(new_ptr, new_norm_len as usize);
        let old_mount = find_mount_for_path(old_slice, old_norm_len);
        let new_mount = find_mount_for_path(new_slice, new_norm_len);
        match (old_mount, new_mount) {
            (Some(oi), Some(ni)) if oi == ni => {
                // Both paths in same mount — forward to FS server
                let (_, old_sub_start, old_sub_len) = parse_mount_path(old_slice, old_norm_len);
                let (_, new_sub_start, new_sub_len) = parse_mount_path(new_slice, new_norm_len);
                if old_sub_len > 0 && new_sub_len > 0 {
                    let (op_start, op_len, ol_start, ol_len) =
                        split_mount_sub_path(old_ptr.add(old_sub_start), old_sub_len);
                    let old_parent_ino = if op_len == 0 {
                        (*(&raw const crate::MOUNTS[oi])).root_ino as u64
                    } else {
                        mount_lookup(oi, old_ptr.add(old_sub_start + op_start), op_len)
                    };
                    if old_parent_ino == 0 {
                        (*reply).label = SALTY_NOT_FOUND;
                        return;
                    }
                    let (np_start, np_len, nl_start, nl_len) =
                        split_mount_sub_path(new_ptr.add(new_sub_start), new_sub_len);
                    let new_parent_ino = if np_len == 0 {
                        (*(&raw const crate::MOUNTS[oi])).root_ino as u64
                    } else {
                        mount_lookup(oi, new_ptr.add(new_sub_start + np_start), np_len)
                    };
                    if new_parent_ino == 0 {
                        (*reply).label = SALTY_NOT_FOUND;
                        return;
                    }
                    mount_rename(
                        oi,
                        old_parent_ino,
                        old_ptr.add(old_sub_start + ol_start),
                        ol_len,
                        new_parent_ino,
                        new_ptr.add(new_sub_start + nl_start),
                        nl_len,
                        reply,
                    );
                    return;
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                // Cross-mount rename not supported
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            _ => {}
        }

        // Resolve old parent + child
        let mut old_child: *const u8 = core::ptr::null();
        let mut old_child_len: u8 = 0;
        let old_parent = resolve_parent(old_ptr, old_norm_len, &mut old_child, &mut old_child_len);
        if old_parent.is_null() || (*old_parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let de = dir_find_entry(old_parent, old_child, old_child_len);
        if de.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        let ino = (*de).ino;

        // Resolve new parent + child
        let mut new_child: *const u8 = core::ptr::null();
        let mut new_child_len: u8 = 0;
        let new_parent = resolve_parent(new_ptr, new_norm_len, &mut new_child, &mut new_child_len);
        if new_parent.is_null() || (*new_parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Remove from old
        (*de).active = 0;

        // Remove existing at new location
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
        (*reply).label = SALTY_OK;
    }
}

pub(crate) unsafe fn handle_mkdir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        // Mount intercept
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            if sub_len > 0 {
                let (p_start, p_len, l_start, l_len) =
                    split_mount_sub_path(path_ptr.add(sub_start), sub_len);
                let parent_ino = if p_len == 0 {
                    (*(&raw const crate::MOUNTS[mount_idx])).root_ino as u64
                } else {
                    mount_lookup(mount_idx, path_ptr.add(sub_start + p_start), p_len)
                };
                if parent_ino == 0 {
                    (*reply).label = SALTY_NOT_FOUND;
                    return;
                }
                let mode = (*msg).regs[0] as u32 & 0o777;
                mount_mkdir(
                    mount_idx,
                    parent_ino,
                    path_ptr.add(sub_start + l_start),
                    l_len,
                    mode,
                    reply,
                );
                return;
            }
        }

        let existing = resolve_path(path_ptr, path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let dir = alloc_inode();
        if dir.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        (*dir).ftype = FTYPE_DIRECTORY;
        (*dir).mode = S_IFDIR_L | ((*msg).regs[0] as u32 & 0o777);
        (*dir).nlink = 2;
        (*dir).parent_ino = (*parent).ino;

        dir_add_entry(parent, child_name, child_len, (*dir).ino);
        (*reply).label = SALTY_OK;
    }
}

pub(crate) unsafe fn handle_mkfifo(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        let existing = resolve_path(path_ptr, path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Allocate a pipe for the FIFO
        let pipe = alloc_pipe();
        if pipe.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        let fifo = alloc_inode();
        if fifo.is_null() {
            (*pipe).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        let mode = (*msg).regs[0] as u32 & 0o777;
        (*fifo).ftype = FTYPE_FIFO;
        (*fifo).mode = S_IFREG_L | mode;
        (*fifo).nlink = 1;
        (*fifo).parent_ino = (*parent).ino;
        (*fifo).size = (*pipe).pipe_id as u64; // Store pipe_id in size field

        dir_add_entry(parent, child_name, child_len, (*fifo).ino);
        (*reply).label = SALTY_OK;
    }
}

pub(crate) unsafe fn handle_rmdir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        // Mount intercept
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            if sub_len > 0 {
                let (p_start, p_len, l_start, l_len) =
                    split_mount_sub_path(path_ptr.add(sub_start), sub_len);
                let parent_ino = if p_len == 0 {
                    (*(&raw const crate::MOUNTS[mount_idx])).root_ino as u64
                } else {
                    mount_lookup(mount_idx, path_ptr.add(sub_start + p_start), p_len)
                };
                if parent_ino == 0 {
                    (*reply).label = SALTY_NOT_FOUND;
                    return;
                }
                mount_rmdir(
                    mount_idx,
                    parent_ino,
                    path_ptr.add(sub_start + l_start),
                    l_len,
                    reply,
                );
                return;
            }
        }

        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        if (*inode).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Check directory is empty
        for i in 0..(*inode).dirents_cap as usize {
            if (*(*inode).dirents.add(i)).active != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        // Remove from parent
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if !parent.is_null() {
            dir_remove_entry(parent, child_name, child_len);
        }

        (*inode).active = 0;
        (*reply).label = SALTY_OK;
    }
}

pub(crate) unsafe fn handle_opendir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) =
            normalize_path_for_client(badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr())
        else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);

        // /proc sub-paths that don't resolve as real inodes
        if path_len >= 6
            && *path_ptr == b'/'
            && *path_ptr.add(1) == b'p'
            && *path_ptr.add(2) == b'r'
            && *path_ptr.add(3) == b'o'
            && *path_ptr.add(4) == b'c'
            && *path_ptr.add(5) == b'/'
        {
            if handle_proc_open(path_ptr, path_len, reply, badge) {
                return;
            }
        }

        // Mount point intercept for opendir
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            let remote_ino = if sub_len > 0 {
                mount_lookup(mount_idx, path_ptr.add(sub_start), sub_len)
            } else {
                (*(&raw const crate::MOUNTS[mount_idx])).root_ino as u64
            };
            if remote_ino == 0 {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }

            let cli = get_client(badge);
            if cli.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
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
                    (*(*cli).fds.add(fd)).flags = 0;
                    (*(*cli).fds.add(fd)).mount_batch_count = 0;
                    (*(*cli).fds.add(fd)).mount_batch_index = 0;
                    (*(*cli).fds.add(fd)).mount_batch_next_cursor = 0;
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = fd as u64;
                    return;
                }
            }
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        let inode = resolve_path(path_ptr, path_len);
        let is_dir = if inode.is_null() {
            false
        } else if (*inode).ftype == FTYPE_DIRECTORY {
            true
        } else if (*inode).ftype == FTYPE_MOUNT_POINT {
            true
        } else if (*inode).ftype == FTYPE_PROC_FILE
            && ((*inode).dev_type == PROC_FILE_ROOT || (*inode).dev_type == PROC_FILE_PID_DIR)
        {
            true
        } else {
            false
        };
        if !is_dir {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        // If the resolved inode is a mount point, open it as a mount dir
        if (*inode).ftype == FTYPE_MOUNT_POINT {
            for i in 0..MAX_MOUNTS {
                let m = &*(&raw const crate::MOUNTS[i]);
                if m.active != 0 && m.mount_ino == (*inode).ino {
                    let cli = get_client(badge);
                    if cli.is_null() {
                        (*reply).label = SALTY_OUT_OF_MEMORY;
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
                            (*(*cli).fds.add(fd)).flags = 0;
                            (*(*cli).fds.add(fd)).mount_batch_count = 0;
                            (*(*cli).fds.add(fd)).mount_batch_index = 0;
                            (*(*cli).fds.add(fd)).mount_batch_next_cursor = 0;
                            (*reply).label = SALTY_OK;
                            (*reply).length = 1;
                            (*reply).regs[0] = fd as u64;
                            return;
                        }
                    }
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DIR;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).dir_cursor = 0;
                inode_open((*inode).ino);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return;
            }
        }

        (*reply).label = SALTY_OUT_OF_MEMORY;
    }
}

pub(crate) unsafe fn handle_readdir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_DIR
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let dir = inode_by_ino((*(*cli).fds.add(fd as usize)).inode);
        if dir.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // /proc virtual directories
        if (*dir).ftype == FTYPE_PROC_FILE {
            let cursor = (*(*cli).fds.add(fd as usize)).dir_cursor;
            handle_proc_readdir(dir, cursor, reply);
            if (*reply).label == SALTY_OK && (*reply).regs[0] != 0 {
                // Advance cursor: use regs[1] (next cursor) if set by proc_readdir
                (*(*cli).fds.add(fd as usize)).dir_cursor = (*reply).regs[1] as u32;
                (*reply).regs[1] = 0; // clear before returning to client
            }
            return;
        }

        let cursor = (*(*cli).fds.add(fd as usize)).dir_cursor;
        for i in (cursor as usize)..(*dir).dirents_cap as usize {
            if (*(*dir).dirents.add(i)).active != 0 {
                let child = inode_by_ino((*(*dir).dirents.add(i)).ino);
                let d_type: u8 = if !child.is_null() {
                    match (*child).ftype {
                        FTYPE_REGULAR => 8,     // DT_REG
                        FTYPE_DIRECTORY => 4,   // DT_DIR
                        FTYPE_CHAR_DEVICE => 2, // DT_CHR
                        FTYPE_SYMLINK => 10,    // DT_LNK
                        FTYPE_PROC_FILE => 4,   // DT_DIR (proc virtual dir)
                        FTYPE_MOUNT_POINT => 4, // DT_DIR (mount point)
                        _ => 0,
                    }
                } else {
                    0
                };

                let name_len = (*(*dir).dirents.add(i)).name_len;
                (*reply).label = SALTY_OK;
                (*reply).length = 5 + ((name_len as u64 + 7) / 8);
                (*reply).regs[0] = name_len as u64;
                (*reply).regs[1] = 0; // reserved
                (*reply).regs[2] = (*(*dir).dirents.add(i)).ino as u64;
                (*reply).regs[3] = d_type as u64;

                for j in 4..20 {
                    (*reply).regs[j] = 0;
                }
                let dst = &raw mut (*reply).regs[4] as *mut u8;
                for j in 0..name_len as usize {
                    *dst.add(j) = (*(*dir).dirents.add(i)).name[j];
                }

                (*(*cli).fds.add(fd as usize)).dir_cursor = (i + 1) as u32;
                return;
            }
        }

        // End of directory
        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = 0;
    }
}
