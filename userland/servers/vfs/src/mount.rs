// SPDX-License-Identifier: GPL-2.0-only
//! Remote mount point proxy for SaltyFS integration.

use salty::consts::*;
use salty::ipc;
use salty::serial::LineBuf;
use salty::types::*;

use crate::consts::*;
use crate::types::*;
use crate::{ipc_ctx, puts};

pub(crate) fn parse_mount_path(path: &[u8], path_len: u8) -> (bool, usize, u8) {
    const PREFIX: &[u8] = b"/mnt/data";
    let plen = path_len as usize;
    if plen < PREFIX.len() {
        return (false, 0, 0);
    }
    for i in 0..PREFIX.len() {
        if path[i] != PREFIX[i] {
            return (false, 0, 0);
        }
    }
    if plen == PREFIX.len() {
        return (true, plen, 0);
    }
    if path[PREFIX.len()] != b'/' {
        return (false, 0, 0);
    }
    let sub_start = PREFIX.len() + 1;
    let sub_len = plen - sub_start;
    (true, sub_start, sub_len as u8)
}

pub(crate) unsafe fn find_mount_for_path(path: &[u8], path_len: u8) -> Option<usize> {
    let (is_mount, _, _) = parse_mount_path(path, path_len);
    if !is_mount {
        return None;
    }
    unsafe {
        let mounts = &raw mut crate::MOUNTS;
        let mnt_ino = crate::MOUNT_DATA_INO;
        for i in 0..MAX_MOUNTS {
            if (*mounts)[i].active != 0 && (*mounts)[i].mount_ino == mnt_ino {
                return Some(i);
            }
        }
        if crate::MOUNT_TRIED < 3 {
            setup_saltyfs_mount();
            for i in 0..MAX_MOUNTS {
                if (*mounts)[i].active != 0 && (*mounts)[i].mount_ino == mnt_ino {
                    return Some(i);
                }
            }
        }
    }
    None
}

pub(crate) unsafe fn mount_lookup(mount_idx: usize, sub_path: *const u8, sub_path_len: u8) -> u64 {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut current_ino = m.root_ino as u64;

        if sub_path_len == 0 {
            return current_ino;
        }

        let mut pos: usize = 0;
        let plen = sub_path_len as usize;

        while pos < plen {
            while pos < plen && *sub_path.add(pos) == b'/' {
                pos += 1;
            }
            if pos >= plen {
                break;
            }

            let start = pos;
            while pos < plen && *sub_path.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - start;
            if comp_len == 0 {
                continue;
            }
            if comp_len > 144 {
                return 0;
            }

            let mut req = SaltyMsg::zeroed();
            req.label = SALTYFS_LOOKUP;
            req.regs[0] = current_ino;
            req.regs[1] = comp_len as u64;
            let name_dst = &raw mut req.regs[2] as *mut u8;
            for i in 0..comp_len {
                *name_dst.add(i) = *sub_path.add(start + i);
            }
            req.length = 2 + ((comp_len as u64) + 7) / 8;

            let mut reply = SaltyMsg::zeroed();
            ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);

            if reply.label != SALTY_OK {
                return 0;
            }
            current_ino = reply.regs[0];
        }

        current_ino
    }
}

pub(crate) unsafe fn mount_stat(mount_idx: usize, remote_ino: u64) -> Option<(u64, u32, u32, u64, bool)> {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_STAT;
        req.regs[0] = remote_ino;
        req.length = 1;

        let mut reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);

        if reply.label != SALTY_OK {
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
    mount_idx: usize, remote_ino: u64, offset: u64, count: u64,
    reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_READ_INLINE;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.length = 3;

        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != SALTY_OK {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let bytes_read = fs_reply.regs[0];
        (*reply).label = SALTY_OK;
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
    mount_idx: usize, parent_ino: u64,
    name: *const u8, name_len: u8, mode: u32,
) -> u64 {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_CREATE;
        req.regs[0] = parent_ino;
        req.regs[1] = mode as u64;
        req.regs[2] = name_len as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 3 + ((name_len as u64) + 7) / 8;
        let mut reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);
        if reply.label != SALTY_OK {
            return 0;
        }
        reply.regs[0]
    }
}

pub(crate) unsafe fn mount_write_inline(
    mount_idx: usize, remote_ino: u64, offset: u64,
    data: *const u8, count: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_WRITE_INLINE;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..count as usize {
            *dst.add(i) = *data.add(i);
        }
        req.length = 3 + (count + 7) / 8;
        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        if fs_reply.label != SALTY_OK {
            (*reply).label = fs_reply.label;
            return;
        }
        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fs_reply.regs[0];
    }
}

pub(crate) unsafe fn mount_mkdir(
    mount_idx: usize, parent_ino: u64,
    name: *const u8, name_len: u8, mode: u32, reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_MKDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = mode as u64;
        req.regs[2] = name_len as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 3 + ((name_len as u64) + 7) / 8;
        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

pub(crate) unsafe fn mount_unlink(
    mount_idx: usize, parent_ino: u64,
    name: *const u8, name_len: u8, reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_UNLINK;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + ((name_len as u64) + 7) / 8;
        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

pub(crate) unsafe fn mount_rmdir(
    mount_idx: usize, parent_ino: u64,
    name: *const u8, name_len: u8, reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_RMDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for i in 0..name_len as usize {
            *dst.add(i) = *name.add(i);
        }
        req.length = 2 + ((name_len as u64) + 7) / 8;
        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

pub(crate) unsafe fn mount_rename(
    mount_idx: usize,
    old_parent_ino: u64, old_name: *const u8, old_name_len: u8,
    new_parent_ino: u64, new_name: *const u8, new_name_len: u8,
    reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_RENAME;
        // MR4..MR11 = old name (64 bytes), MR12..MR19 = new name (64 bytes)
        if old_name_len > 64 || new_name_len > 64 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
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
        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

pub(crate) unsafe fn mount_truncate(
    mount_idx: usize, remote_ino: u64, new_size: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_TRUNCATE;
        req.regs[0] = remote_ino;
        req.regs[1] = new_size;
        req.length = 2;
        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}

/// SHM-based read from mounted filesystem. Data is placed in VFS-SaltyFS SHM.
pub(crate) unsafe fn mount_read_shm(
    mount_idx: usize, remote_ino: u64, offset: u64, count: u64,
    shm_offset: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_READ;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.regs[3] = shm_offset;
        req.length = 4;

        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != SALTY_OK {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fs_reply.regs[0]; // bytes_read
    }
}

/// SHM-based write to mounted filesystem. Data is in VFS-SaltyFS SHM.
pub(crate) unsafe fn mount_write_shm(
    mount_idx: usize, remote_ino: u64, offset: u64, count: u64,
    shm_offset: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_WRITE;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.regs[3] = shm_offset;
        req.length = 4;

        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        (*reply).label = fs_reply.label;
        if fs_reply.label == SALTY_OK {
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
        (0, last_slash as u8, (last_slash + 1) as usize, sub_len - (last_slash as u8 + 1))
    }
}

pub(crate) unsafe fn mount_readdir_emit_cached(fde: *mut FdEntry, reply: *mut SaltyMsg) {
    unsafe {
        let fd = &mut *fde;
        let idx = fd.mount_batch_index as usize;
        let ent = &fd.mount_batch[idx];

        (*reply).label = SALTY_OK;
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
    mount_idx: usize, fde: *mut FdEntry, dir_ino: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let fd = &mut *fde;

        if fd.dir_cursor == u32::MAX {
            (*reply).label = SALTY_OK;
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
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_READDIR;
        req.regs[0] = dir_ino;
        req.regs[1] = fd.dir_cursor as u64;
        req.length = 2;

        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != SALTY_OK {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            fd.dir_cursor = u32::MAX;
            return;
        }

        let next_cursor = fs_reply.regs[0] as u32;
        let num_entries = (fs_reply.length.saturating_sub(1)) / 6;
        if num_entries == 0 {
            (*reply).label = SALTY_OK;
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

        let mnt_ino = crate::MOUNT_DATA_INO;
        if mnt_ino == 0 {
            puts(b"[VFS] No /mnt/data inode for mount\n");
            return;
        }

        let fs_slot = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                puts(b"[VFS] saltyfs: no slot available\n");
                return;
            }
        };

        ipc::set_receive_slot_ctx(
            ipc_ctx(), CAP_SELF_CSPACE, fs_slot, 16,
        );

        let mut ns_req = SaltyMsg::zeroed();
        ns_req.label = POSIX_NS_LOOKUP;
        let name = b"saltyfs";
        ns_req.regs[0] = name.len() as u64;
        ns_req.length = 1 + (name.len() as u64 + 7) / 8;
        let ns_dst = &raw mut ns_req.regs[1] as *mut u8;
        for i in 0..name.len() {
            *ns_dst.add(i) = name[i];
        }

        let mut ns_reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(
            ipc_ctx(), VFS_CAP_NAMESERV_EP,
            &raw const ns_req, &raw mut ns_reply,
        );

        if err != 0 || ns_reply.label != SALTY_OK {
            puts(b"[VFS] saltyfs not found in nameserv (ok if no data disk)\n");
            return;
        }

        puts(b"[VFS] Found saltyfs endpoint via nameserv\n");

        let mut mnt_req = SaltyMsg::zeroed();
        mnt_req.label = SALTYFS_MOUNT;
        mnt_req.length = 0;

        let mut mnt_reply = SaltyMsg::zeroed();
        let merr = ipc::call_ctx(ipc_ctx(), fs_slot, &raw const mnt_req, &raw mut mnt_reply);

        if merr != 0 || (mnt_reply.label != SALTY_OK && mnt_reply.label != SALTY_ALREADY_EXISTS) {
            {
                let mut lb = LineBuf::new();
                lb.str(b"[VFS] saltyfs mount failed err=");
                lb.hex(merr as u64);
                lb.str(b" label=");
                lb.hex(mnt_reply.label);
                lb.str(b"\n");
                lb.flush();
            }
            return;
        }

        let root_ino = mnt_reply.regs[0] as u32;

        let mounts = &raw mut crate::MOUNTS;
        for i in 0..MAX_MOUNTS {
            if (*mounts)[i].active == 0 {
                (*mounts)[i].active = 1;
                (*mounts)[i].mount_ino = mnt_ino;
                (*mounts)[i].fs_cap = fs_slot;
                (*mounts)[i].root_ino = root_ino;
                break;
            }
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[VFS] Mounted saltyfs at /mnt/data root_ino=");
            lb.hex(root_ino as u64);
            lb.str(b"\n");
            lb.flush();
        }

        // Set up VFS-SaltyFS SHM for bulk data transport
        let mut shm_create = SaltyMsg::zeroed();
        shm_create.label = MM_SHM_CREATE;
        shm_create.length = 2;
        shm_create.regs[0] = VFS_SALTYFS_SHM_ID;
        shm_create.regs[1] = VFS_SALTYFS_SHM_PAGES;

        let mut shm_reply = SaltyMsg::zeroed();
        let serr = ipc::call_ctx(
            ipc_ctx(), VFS_CAP_MMSRV_EP,
            &raw const shm_create, &raw mut shm_reply,
        );
        if serr != 0 || (shm_reply.label != 0 && shm_reply.label != SALTY_ALREADY_EXISTS) {
            puts(b"[VFS] saltyfs SHM create failed (non-fatal)\n");
        } else {
            // Map SHM into VFS address space
            let mut shm_map = SaltyMsg::zeroed();
            shm_map.label = MM_SHM_MAP;
            shm_map.length = 4;
            shm_map.regs[0] = VFS_SALTYFS_SHM_ID;
            shm_map.regs[1] = 0;
            shm_map.regs[2] = VFS_SALTYFS_SHM_VADDR;
            shm_map.regs[3] = 0x3; // RW

            let mut map_reply = SaltyMsg::zeroed();
            let merr2 = ipc::call_ctx(
                ipc_ctx(), VFS_CAP_MMSRV_EP,
                &raw const shm_map, &raw mut map_reply,
            );
            if merr2 != 0 || map_reply.label != 0 {
                puts(b"[VFS] saltyfs SHM map failed (non-fatal)\n");
            } else {
                // Send SHM ID to SaltyFS so it can map the same region
                let mut setup_msg = SaltyMsg::zeroed();
                setup_msg.label = SALTYFS_SHM_SETUP;
                setup_msg.regs[0] = VFS_SALTYFS_SHM_ID;
                setup_msg.length = 1;

                let mut setup_reply = SaltyMsg::zeroed();
                let serr2 = ipc::call_ctx(
                    ipc_ctx(), fs_slot,
                    &raw const setup_msg, &raw mut setup_reply,
                );
                if serr2 == 0 && setup_reply.label == SALTY_OK {
                    puts(b"[VFS] saltyfs SHM transport established\n");
                    *(&raw mut crate::VFS_SHM_ACTIVE) = true;
                } else {
                    puts(b"[VFS] saltyfs SHM setup failed (non-fatal)\n");
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
    reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_SYMLINK;
        req.regs[0] = parent_ino;
        req.regs[1] = name_len as u64;
        req.regs[2] = target_len as u64;
        // MR3..MR11 = link name (72 bytes max)
        let dst_name = &raw mut req.regs[3] as *mut u8;
        let copy_name = core::cmp::min(name_len as usize, 72);
        for i in 0..copy_name {
            *dst_name.add(i) = *name.add(i);
        }
        // MR12..MR19 = target (64 bytes max)
        let dst_target = &raw mut req.regs[12] as *mut u8;
        let copy_target = core::cmp::min(target_len as usize, 64);
        for i in 0..copy_target {
            *dst_target.add(i) = *target.add(i);
        }
        req.length = 20;
        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
        if fs_reply.label == SALTY_OK {
            (*reply).regs[0] = fs_reply.regs[0]; // new_ino
        }
    }
}

/// Read a symlink target from the mounted SaltyFS filesystem.
pub(crate) unsafe fn mount_readlink(
    mount_idx: usize, remote_ino: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_READLINK;
        req.regs[0] = remote_ino;
        req.length = 1;

        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != SALTY_OK {
            (*reply).label = fs_reply.label;
            return;
        }

        // Copy target data from SaltyFS reply to VFS reply
        (*reply).label = SALTY_OK;
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
    reply: *mut SaltyMsg,
) {
    unsafe {
        let mounts = &raw const crate::MOUNTS;
        let m = &(*mounts)[mount_idx];
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_LINK;
        req.regs[0] = existing_ino;
        req.regs[1] = new_parent_ino;
        req.regs[2] = name_len as u64;
        // MR3..MR19 = name (136 bytes max)
        let dst = &raw mut req.regs[3] as *mut u8;
        let copy = core::cmp::min(name_len as usize, 136);
        for i in 0..copy {
            *dst.add(i) = *name.add(i);
        }
        req.length = 3 + ((copy as u64) + 7) / 8;
        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);
        (*reply).label = fs_reply.label;
    }
}
