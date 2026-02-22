// SPDX-License-Identifier: GPL-2.0-only
//! /proc filesystem implementation.

use salty::consts::*;
use salty::ipc;
use salty::types::*;

use crate::consts::*;
use crate::types::*;
use crate::ramfs::{inode_by_ino, alloc_inode, inode_open};
use crate::client::{get_client, get_client_noalloc};
use crate::ipc_ctx;

pub(crate) fn parse_pid(buf: &[u8]) -> (u32, bool) {
    if buf.is_empty() || buf.len() > 10 {
        return (0, false);
    }
    let mut val: u32 = 0;
    for &b in buf {
        if b < b'0' || b > b'9' {
            return (0, false);
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u32);
    }
    (val, true)
}

/// Format u32 as decimal into buf. Returns number of bytes written.
pub(crate) fn fmt_u32(mut v: u32, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() { buf[0] = b'0'; }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while v > 0 && len < 10 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

/// Format u64 as hex into buf. Returns number of bytes written.
pub(crate) fn fmt_u64_hex(mut v: u64, buf: &mut [u8]) -> usize {
    if v == 0 {
        if buf.len() >= 3 { buf[0] = b'0'; buf[1] = b'x'; buf[2] = b'0'; return 3; }
        return 0;
    }
    let mut tmp = [0u8; 16];
    let mut len = 0usize;
    while v > 0 && len < 16 {
        let d = (v & 0xf) as u8;
        tmp[len] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v >>= 4;
        len += 1;
    }
    if buf.len() < len + 2 { return 0; }
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..len {
        buf[2 + i] = tmp[len - 1 - i];
    }
    len + 2
}

/// Query procmgr for list of PIDs. Returns count (up to 19).
unsafe fn proc_list_pids(pids: &mut [u32; 19]) -> usize {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_LIST_PIDS;
        msg.length = 0;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_PROCMGR_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            return 0;
        }
        let count = reply.regs[19] as usize;
        let n = if count > 19 { 19 } else { count };
        for i in 0..n {
            pids[i] = reply.regs[i] as u32;
        }
        n
    }
}

/// Query procmgr for process info. Returns true on success.
unsafe fn proc_get_info(
    pid: u32, ppid: &mut u32, pgid: &mut u32, sid: &mut u32,
    state: &mut u8, name: &mut [u8; 32],
) -> bool {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GET_PROC_INFO;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_PROCMGR_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            return false;
        }
        *ppid = reply.regs[1] as u32;
        *pgid = reply.regs[2] as u32;
        *sid = reply.regs[3] as u32;
        *state = reply.regs[4] as u8;
        let src = &reply.regs[5] as *const u64 as *const u8;
        for i in 0..32 {
            name[i] = *src.add(i);
        }
        true
    }
}

/// Query mmsrv for client memory stats. Returns true on success.
unsafe fn proc_get_mem_stats(
    pid: u32, heap_base: &mut u64, heap_current: &mut u64,
    region_count: &mut u64, total_pages: &mut u64,
) -> bool {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = MM_GET_CLIENT_STATS;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            return false;
        }
        *heap_base = reply.regs[0];
        *heap_current = reply.regs[1];
        *region_count = reply.regs[2];
        *total_pages = reply.regs[3];
        true
    }
}

/// Generate /proc/<pid>/status content. Returns bytes written.
unsafe fn proc_gen_status(pid: u32, buf: *mut u8, buf_size: usize) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        if !proc_get_info(pid, &mut ppid, &mut pgid, &mut sid, &mut state, &mut name) {
            return 0;
        }

        // Find name length
        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 { name_len += 1; }
        if name_len == 0 { name[0] = b'?'; name_len = 1; }

        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // "Name:\t<name>\n"
        let hdr = b"Name:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        for i in 0..name_len { if pos < buf_size { *buf.add(pos) = name[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "State:\t<R/Z/T>\n"
        let hdr = b"State:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let st_char = match state { 1 => b'R', 2 => b'Z', 3 => b'T', _ => b'?' };
        if pos < buf_size { *buf.add(pos) = st_char; pos += 1; }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "Pid:\t<pid>\n"
        let hdr = b"Pid:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "PPid:\t<ppid>\n"
        let hdr = b"PPid:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let n = fmt_u32(ppid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "Pgid:\t<pgid>\n"
        let hdr = b"Pgid:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let n = fmt_u32(pgid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "Sid:\t<sid>\n"
        let hdr = b"Sid:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        pos
    }
}

/// Generate /proc/<pid>/stat content (single-line). Returns bytes written.
unsafe fn proc_gen_stat(pid: u32, buf: *mut u8, buf_size: usize) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        if !proc_get_info(pid, &mut ppid, &mut pgid, &mut sid, &mut state, &mut name) {
            return 0;
        }

        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 { name_len += 1; }
        if name_len == 0 { name[0] = b'?'; name_len = 1; }

        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // "<pid> (<name>) <state> <ppid> <pgid> <sid>\n"
        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        if pos < buf_size { *buf.add(pos) = b'('; pos += 1; }
        for i in 0..name_len { if pos < buf_size { *buf.add(pos) = name[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b')'; pos += 1; }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        let st_char = match state { 1 => b'R', 2 => b'Z', 3 => b'T', _ => b'?' };
        if pos < buf_size { *buf.add(pos) = st_char; pos += 1; }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        let n = fmt_u32(ppid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        let n = fmt_u32(pgid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        pos
    }
}

/// Handle open for /proc paths. Creates temporary proc file inode.
/// Returns true if handled (and reply is set), false if not a /proc path.
pub(crate) unsafe fn handle_proc_open(
    path: *const u8, path_len: u8, reply: *mut SaltyMsg, badge: u64,
) -> bool {
    unsafe {
        // Check if path starts with "/proc/"
        if path_len < 6 { return false; }
        let proc_prefix = b"/proc/";
        for i in 0..6 {
            if *path.add(i) != proc_prefix[i] { return false; }
        }

        let rest = path.add(6);
        let rest_len = path_len - 6;

        // Check for /proc/self -> resolve to client's PID
        let is_self_prefix = rest_len >= 4
            && *rest == b's' && *rest.add(1) == b'e'
            && *rest.add(2) == b'l' && *rest.add(3) == b'f';

        let (pid, file_offset) = if is_self_prefix && (rest_len == 4 || *rest.add(4) == b'/') {
            let cli = get_client_noalloc(badge);
            if cli.is_null() {
                (*reply).label = SALTY_NOT_FOUND;
                return true;
            }
            // Client badge encodes PID: badge = pid
            let client_pid = (badge & 0xFFFF) as u32;
            if rest_len == 4 {
                // /proc/self (just the dir itself)
                (client_pid, 4u8)
            } else {
                (client_pid, 5u8) // skip "self/"
            }
        } else {
            // /proc/<pid>/... — parse numeric PID
            let mut pid_end = 0u8;
            while (pid_end as usize) < rest_len as usize && *rest.add(pid_end as usize) != b'/' {
                pid_end += 1;
            }
            let mut pid_buf = [0u8; 10];
            for i in 0..pid_end as usize {
                if i < 10 { pid_buf[i] = *rest.add(i); }
            }
            let (pid, ok) = parse_pid(&pid_buf[..pid_end as usize]);
            if !ok {
                (*reply).label = SALTY_NOT_FOUND;
                return true;
            }
            (pid, pid_end)
        };

        // What file under /proc/<pid>/?
        let after_pid = rest.add(file_offset as usize);
        let after_len = if file_offset < rest_len { rest_len - file_offset } else { 0 };

        if after_len == 0 {
            // /proc/<pid> — the directory itself; open as dir
            let inode = alloc_inode();
            if inode.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return true;
            }
            (*inode).ftype = FTYPE_PROC_FILE;
            (*inode).dev_type = PROC_FILE_PID_DIR;
            (*inode).mode = S_IFDIR_L | 0o555;
            (*inode).readonly = 1;
            (*inode).nlink = 0; // temp inode — freed when last FD closes
            (*inode).size = pid as u64; // store PID in size field

            let cli = get_client(badge);
            if cli.is_null() { (*reply).label = SALTY_OUT_OF_MEMORY; (*inode).active = 0; return true; }
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
                    return true;
                }
            }
            (*inode).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return true;
        }

        // Skip leading '/'
        let (file_name, file_name_len) = if after_len > 0 && *after_pid == b'/' {
            (after_pid.add(1), after_len - 1)
        } else {
            (after_pid, after_len)
        };

        // Determine file type
        let proc_type = if file_name_len == 6 && mem_eq(file_name, b"status".as_ptr(), 6) {
            PROC_FILE_STATUS
        } else if file_name_len == 4 && mem_eq(file_name, b"stat".as_ptr(), 4) {
            PROC_FILE_STAT
        } else if file_name_len == 4 && mem_eq(file_name, b"maps".as_ptr(), 4) {
            PROC_FILE_MAPS
        } else {
            (*reply).label = SALTY_NOT_FOUND;
            return true;
        };

        // Allocate temporary inode for this proc file
        let inode = alloc_inode();
        if inode.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return true;
        }
        (*inode).ftype = FTYPE_PROC_FILE;
        (*inode).dev_type = proc_type;
        (*inode).mode = S_IFREG_L | 0o444;
        (*inode).readonly = 1;
        (*inode).nlink = 0; // temp inode — freed when last FD closes
        (*inode).size = pid as u64; // store PID in size field

        let cli = get_client(badge);
        if cli.is_null() { (*reply).label = SALTY_OUT_OF_MEMORY; (*inode).active = 0; return true; }
        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_FILE;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).dir_cursor = 0;
                (*(*cli).fds.add(fd)).flags = 0; // O_RDONLY
                inode_open((*inode).ino);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return true;
            }
        }
        (*inode).active = 0;
        (*reply).label = SALTY_OUT_OF_MEMORY;
        true
    }
}

/// Simple memory comparison (no libc).
pub(crate) fn mem_eq(a: *const u8, b: *const u8, len: usize) -> bool {
    for i in 0..len {
        unsafe {
            if *a.add(i) != *b.add(i) { return false; }
        }
    }
    true
}

/// Handle stat/lstat for /proc virtual paths that don't resolve as real inodes.
/// Returns true if the path was handled (even if error).
pub(crate) unsafe fn handle_proc_stat(
    path: *const u8, path_len: u8, reply: *mut SaltyMsg, badge: u64,
) -> bool {
    unsafe {
        // Path must start with "/proc/" (caller already checked)
        if path_len < 6 { return false; }

        let rest = path.add(6);
        let rest_len = path_len - 6;

        // Parse "self" or numeric PID
        let is_self_prefix = rest_len >= 4
            && *rest == b's' && *rest.add(1) == b'e'
            && *rest.add(2) == b'l' && *rest.add(3) == b'f';

        let (pid, file_offset) = if is_self_prefix && (rest_len == 4 || *rest.add(4) == b'/') {
            let client_pid = (badge & 0xFFFF) as u32;
            if rest_len == 4 { (client_pid, 4u8) } else { (client_pid, 5u8) }
        } else {
            let mut pid_end = 0u8;
            while (pid_end as usize) < rest_len as usize && *rest.add(pid_end as usize) != b'/' {
                pid_end += 1;
            }
            let (pid, ok) = parse_pid(&core::slice::from_raw_parts(rest, pid_end as usize));
            if !ok {
                (*reply).label = SALTY_NOT_FOUND;
                return true;
            }
            (pid, pid_end)
        };

        let after_pid = rest.add(file_offset as usize);
        let after_len = if file_offset < rest_len { rest_len - file_offset } else { 0 };

        if after_len == 0 {
            // /proc/<pid> — directory
            (*reply).label = SALTY_OK;
            (*reply).length = 8;
            (*reply).regs[0] = pid as u64; // ino
            (*reply).regs[1] = (S_IFDIR_L | 0o555) as u64; // mode
            (*reply).regs[2] = 2; // nlink
            (*reply).regs[3] = 0; // size
            (*reply).regs[4] = 0; // uid
            (*reply).regs[5] = 0; // gid
            (*reply).regs[6] = 0; // mtime
            (*reply).regs[7] = FTYPE_PROC_FILE as u64;
            return true;
        }

        let (file_name, file_name_len) = if after_len > 0 && *after_pid == b'/' {
            (after_pid.add(1), after_len - 1)
        } else {
            (after_pid, after_len)
        };

        let is_known = (file_name_len == 6 && mem_eq(file_name, b"status".as_ptr(), 6))
            || (file_name_len == 4 && mem_eq(file_name, b"stat".as_ptr(), 4))
            || (file_name_len == 4 && mem_eq(file_name, b"maps".as_ptr(), 4));

        if !is_known {
            (*reply).label = SALTY_NOT_FOUND;
            return true;
        }

        // Regular file stat
        (*reply).label = SALTY_OK;
        (*reply).length = 8;
        (*reply).regs[0] = 0; // ino (virtual)
        (*reply).regs[1] = (S_IFREG_L | 0o444) as u64; // mode
        (*reply).regs[2] = 1; // nlink
        (*reply).regs[3] = 0; // size (unknown for virtual files)
        (*reply).regs[4] = 0; // uid
        (*reply).regs[5] = 0; // gid
        (*reply).regs[6] = 0; // mtime
        (*reply).regs[7] = FTYPE_PROC_FILE as u64;
        true
    }
}

/// Handle read for FTYPE_PROC_FILE inodes.
/// Generates content on-the-fly from procmgr/mmsrv.
pub(crate) unsafe fn handle_proc_read(
    inode: *const RamfsInode, offset: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let pid = (*inode).size as u32;
        let proc_type = (*inode).dev_type;

        // Generate content into a stack buffer
        let mut content = [0u8; 512];
        let content_len = match proc_type {
            PROC_FILE_STATUS => proc_gen_status(pid, content.as_mut_ptr(), 512),
            PROC_FILE_STAT => proc_gen_stat(pid, content.as_mut_ptr(), 512),
            PROC_FILE_MAPS => {
                // /proc/<pid>/maps — query mmsrv for memory stats
                let mut heap_base: u64 = 0;
                let mut heap_current: u64 = 0;
                let mut region_count: u64 = 0;
                let mut total_pages: u64 = 0;
                if proc_get_mem_stats(pid, &mut heap_base, &mut heap_current,
                    &mut region_count, &mut total_pages)
                {
                    let mut pos = 0usize;
                    let mut tmp = [0u8; 20];
                    // "heap: <base>-<current> <pages> pages\n"
                    let hdr = b"heap: ";
                    for b in hdr { if pos < 512 { content[pos] = *b; pos += 1; } }
                    let n = fmt_u64_hex(heap_base, &mut tmp);
                    for i in 0..n { if pos < 512 { content[pos] = tmp[i]; pos += 1; } }
                    if pos < 512 { content[pos] = b'-'; pos += 1; }
                    let n = fmt_u64_hex(heap_current, &mut tmp);
                    for i in 0..n { if pos < 512 { content[pos] = tmp[i]; pos += 1; } }
                    if pos < 512 { content[pos] = b'\n'; pos += 1; }
                    // "regions: <count>\n"
                    let hdr = b"regions: ";
                    for b in hdr { if pos < 512 { content[pos] = *b; pos += 1; } }
                    let n = fmt_u32(region_count as u32, &mut tmp);
                    for i in 0..n { if pos < 512 { content[pos] = tmp[i]; pos += 1; } }
                    if pos < 512 { content[pos] = b'\n'; pos += 1; }
                    // "pages: <total>\n"
                    let hdr = b"pages: ";
                    for b in hdr { if pos < 512 { content[pos] = *b; pos += 1; } }
                    let n = fmt_u32(total_pages as u32, &mut tmp);
                    for i in 0..n { if pos < 512 { content[pos] = tmp[i]; pos += 1; } }
                    if pos < 512 { content[pos] = b'\n'; pos += 1; }
                    pos
                } else {
                    0
                }
            }
            _ => 0,
        };

        if offset as usize >= content_len {
            // EOF
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let available = content_len - offset as usize;
        let max_ipc = 152; // 19 regs * 8 bytes
        let to_copy = if available < max_ipc { available } else { max_ipc };

        let dst = &mut (*reply).regs[1] as *mut u64 as *mut u8;
        for i in 0..to_copy {
            *dst.add(i) = content[offset as usize + i];
        }
        (*reply).label = SALTY_OK;
        (*reply).length = 1 + ((to_copy as u64 + 7) / 8);
        (*reply).regs[0] = to_copy as u64;
    }
}

/// Handle readdir for /proc root — returns PID entries.
pub(crate) unsafe fn handle_proc_readdir(
    inode: *const RamfsInode, cursor: u32, reply: *mut SaltyMsg,
) {
    unsafe {
        if (*inode).dev_type == PROC_FILE_ROOT {
            // /proc root readdir: list PIDs + "self"
            let mut pids = [0u32; 19];
            let count = proc_list_pids(&mut pids);

            // cursor 0 = "self", then PIDs
            if cursor == 0 {
                // Return "self" entry
                (*reply).label = SALTY_OK;
                (*reply).regs[0] = 4; // name_len = 4
                (*reply).regs[1] = cursor as u64 + 1; // next cursor
                (*reply).regs[2] = 0; // ino
                (*reply).regs[3] = 10; // DT_LNK
                let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
                *dst = b's'; *dst.add(1) = b'e'; *dst.add(2) = b'l'; *dst.add(3) = b'f';
                (*reply).length = 5;
                return;
            }

            let idx = (cursor - 1) as usize;
            if idx >= count {
                // No more entries
                (*reply).label = SALTY_OK;
                (*reply).regs[0] = 0; // name_len = 0 → end
                (*reply).length = 1;
                return;
            }

            // Format PID as string
            let mut name_buf = [0u8; 10];
            let name_len = fmt_u32(pids[idx], &mut name_buf);

            (*reply).label = SALTY_OK;
            (*reply).regs[0] = name_len as u64;
            (*reply).regs[1] = cursor as u64 + 1;
            (*reply).regs[2] = pids[idx] as u64; // ino = pid
            (*reply).regs[3] = 4; // DT_DIR
            let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
            for i in 0..name_len { *dst.add(i) = name_buf[i]; }
            (*reply).length = 5;
        } else if (*inode).dev_type == PROC_FILE_PID_DIR {
            // /proc/<pid> readdir: list status, stat, maps
            let entries: &[&[u8]] = &[b"status", b"stat", b"maps"];
            let cursor_idx = cursor as usize;
            if cursor_idx >= entries.len() {
                (*reply).label = SALTY_OK;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return;
            }
            let entry = entries[cursor_idx];
            (*reply).label = SALTY_OK;
            (*reply).regs[0] = entry.len() as u64;
            (*reply).regs[1] = cursor as u64 + 1;
            (*reply).regs[2] = 0; // ino
            (*reply).regs[3] = 8; // DT_REG
            let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
            for i in 0..entry.len() { *dst.add(i) = entry[i]; }
            (*reply).length = 5;
        } else {
            (*reply).label = SALTY_NOT_FOUND;
        }
    }
}
