// SPDX-License-Identifier: GPL-2.0-only
//! Terminal I/O, ioctl, fcntl, shared memory, and mmap handlers.

use trona::consts::*;
use trona::ipc;
use trona::types::*;

use crate::client::{extract_path, get_client};
use crate::consts::*;
use crate::fileops::normalize_path_for_client;
use crate::mount::{mount_stat, mount_truncate, try_root_underlay};
use crate::path::{resolve_parent, resolve_path};
use crate::pipe::dup_fd_entry;
use crate::poll::wake_poll_waiters;
use crate::ramfs::{alloc_inode, chain_truncate, dir_add_entry, dir_remove_entry, inode_by_ino};
use crate::socket::alloc_reply_slot;
use crate::types::*;
use crate::{
    ipc_ctx, max_clients, max_shm_objects, max_shm_pages, vfs_grow_pool, CLIENTS, SHM_DATA,
};

const MMAP_REGION_TYPE_PRIVATE: u64 = 1;
const MMAP_REGION_TYPE_FILE_SHARED: u64 = 4;
const MMAP_CACHE_SOURCE_FILE: u8 = 1;
const MMAP_CACHE_SOURCE_MOUNT: u8 = 2;

#[derive(Clone, Copy)]
struct FileMmapCacheEntry {
    active: u8,
    source_type: u8,
    _pad0: [u8; 2],
    source_id0: u64,
    source_id1: u64,
    page_count: u32,
    _pad1: u32,
    file_size: u64,
    mo_cap: Cap,
}

impl FileMmapCacheEntry {
    const fn zeroed() -> Self {
        Self {
            active: 0,
            source_type: 0,
            _pad0: [0; 2],
            source_id0: 0,
            source_id1: 0,
            page_count: 0,
            _pad1: 0,
            file_size: 0,
            mo_cap: 0,
        }
    }
}

static mut FILE_MMAP_CACHE: [FileMmapCacheEntry; INITIAL_FILE_MMAP_CACHE] =
    [FileMmapCacheEntry::zeroed(); INITIAL_FILE_MMAP_CACHE];

#[inline]
unsafe fn mmap_prot_to_vspace_flags(prot: u64) -> u64 {
    let mut flags = VSPACE_FLAG_USER;
    if prot & PROT_WRITE as u64 != 0 {
        flags |= VSPACE_FLAG_WRITABLE;
    }
    if prot & PROT_EXEC as u64 != 0 {
        flags |= VSPACE_FLAG_EXECUTABLE;
    }
    flags
}

unsafe fn alloc_mo_cap(page_count: usize) -> Cap {
    let mut size_bits: u64 = 0;
    while (1u64 << size_bits) < page_count as u64 {
        size_bits += 1;
    }

    let slot = match trona::slot_alloc::slot_alloc() {
        Some(slot) => slot,
        None => return 0,
    };

    ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, slot, 0);

    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_ALLOC_OBJECT;
    msg.length = 2;
    msg.regs[0] = OBJ_MEMORY_OBJECT;
    msg.regs[1] = size_bits;

    let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
    if err != 0 || reply.label != TRONA_OK {
        let _ = trona::invoke::cnode_delete(CAP_SELF_CSPACE, slot);
        return 0;
    }

    slot
}

unsafe fn mmap_cache_lookup(
    source_type: u8,
    source_id0: u64,
    source_id1: u64,
    min_pages: u32,
    file_size: u64,
) -> *mut FileMmapCacheEntry {
    let cache = &raw mut FILE_MMAP_CACHE;
    for i in 0..INITIAL_FILE_MMAP_CACHE {
        let entry = &raw mut (*cache)[i];
        if (*entry).active != 0
            && (*entry).source_type == source_type
            && (*entry).source_id0 == source_id0
            && (*entry).source_id1 == source_id1
            && (*entry).page_count >= min_pages
            && (*entry).file_size == file_size
        {
            return entry;
        }
    }
    core::ptr::null_mut()
}

unsafe fn mmap_cache_find_source(source_type: u8, source_id0: u64, source_id1: u64) -> *mut FileMmapCacheEntry {
    let cache = &raw mut FILE_MMAP_CACHE;
    for i in 0..INITIAL_FILE_MMAP_CACHE {
        let entry = &raw mut (*cache)[i];
        if (*entry).active != 0
            && (*entry).source_type == source_type
            && (*entry).source_id0 == source_id0
            && (*entry).source_id1 == source_id1
        {
            return entry;
        }
    }
    core::ptr::null_mut()
}

unsafe fn mmap_cache_alloc_or_replace(source_type: u8, source_id0: u64, source_id1: u64) -> *mut FileMmapCacheEntry {
    let cache = &raw mut FILE_MMAP_CACHE;
    for i in 0..INITIAL_FILE_MMAP_CACHE {
        let entry = &raw mut (*cache)[i];
        if (*entry).active == 0 {
            return entry;
        }
    }
    for i in 0..INITIAL_FILE_MMAP_CACHE {
        let entry = &raw mut (*cache)[i];
        if (*entry).source_type == source_type
            && (*entry).source_id0 == source_id0
            && (*entry).source_id1 == source_id1
        {
            if (*entry).mo_cap != 0 {
                let _ = trona::invoke::cnode_delete(CAP_SELF_CSPACE, (*entry).mo_cap);
            }
            *entry = FileMmapCacheEntry::zeroed();
            return entry;
        }
    }
    core::ptr::null_mut()
}

pub(crate) unsafe fn invalidate_mmap_cache_source(source_type: u8, source_id0: u64, source_id1: u64) {
    let cache = &raw mut FILE_MMAP_CACHE;
    for i in 0..INITIAL_FILE_MMAP_CACHE {
        let entry = &raw mut (*cache)[i];
        if (*entry).active != 0
            && (*entry).source_type == source_type
            && (*entry).source_id0 == source_id0
            && (*entry).source_id1 == source_id1
        {
            if (*entry).mo_cap != 0 {
                let _ = trona::invoke::cnode_delete(CAP_SELF_CSPACE, (*entry).mo_cap);
            }
            *entry = FileMmapCacheEntry::zeroed();
        }
    }
}

unsafe fn backing_source_for_fd(fde: &FdEntry) -> Option<(u8, u64, u64)> {
    match fde.fd_type {
        FD_TYPE_FILE => Some((MMAP_CACHE_SOURCE_FILE, fde.inode as u64, 0)),
        FD_TYPE_MOUNT => Some((MMAP_CACHE_SOURCE_MOUNT, fde.dev_type as u64, fde.sock_id as u64)),
        _ => None,
    }
}

pub(crate) unsafe fn invalidate_mmap_cache_for_fd(fde: &FdEntry) {
    if let Some((source_type, source_id0, source_id1)) = backing_source_for_fd(fde) {
        invalidate_mmap_cache_source(source_type, source_id0, source_id1);
    }
}

unsafe fn file_mapping_size(fde: &FdEntry) -> Option<u64> {
    match fde.fd_type {
        FD_TYPE_FILE => {
            let inode = inode_by_ino(fde.inode);
            if inode.is_null() {
                None
            } else {
                Some((*inode).size)
            }
        }
        FD_TYPE_MOUNT => mount_stat(fde.dev_type as usize, fde.sock_id as u64).map(|s| s.0),
        _ => None,
    }
}

unsafe fn read_backing_bytes(
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
    offset: u64,
    dst: *mut u8,
    count: u64,
) -> Option<u64> {
    match backing_kind {
        MMAP_BACKING_FILE => {
            let inode = inode_by_ino(backing_id0 as u32);
            if inode.is_null() {
                return None;
            }
            if offset >= (*inode).size {
                return Some(0);
            }
            let mut take = count;
            let avail = (*inode).size - offset;
            if take > avail {
                take = avail;
            }
            if !(*inode).ro_data.is_null() {
                let src = (*inode).ro_data.add(offset as usize);
                for i in 0..take as usize {
                    *dst.add(i) = *src.add(i);
                }
                Some(take)
            } else if !(*inode).rw_data.is_null() {
                Some(crate::ramfs::chain_read((*inode).rw_data, offset, dst, take))
            } else {
                Some(0)
            }
        }
        MMAP_BACKING_MOUNT => {
            let mount_idx = backing_id0 as usize;
            let remote_ino = backing_id1;
            if *(&raw const crate::VFS_SHM_ACTIVE) {
                let mut total = 0u64;
                let shm_chunk_max = crate::consts::VFS_SALTYFS_SHM_PAGES * 4096;
                while total < count {
                    let chunk = core::cmp::min(count - total, shm_chunk_max);
                    let mut reply = TronaMsg::zeroed();
                    crate::mount::mount_read_shm(
                        mount_idx,
                        remote_ino,
                        offset + total,
                        chunk,
                        0,
                        &raw mut reply,
                    );
                    if reply.label != TRONA_OK {
                        break;
                    }
                    let bytes = reply.regs[0];
                    let src = VFS_SALTYFS_SHM_VADDR as *const u8;
                    if bytes == 0 {
                        break;
                    }
                    for i in 0..bytes as usize {
                        *dst.add(total as usize + i) = *src.add(i);
                    }
                    total += bytes;
                    if bytes < chunk {
                        break;
                    }
                }
                if total == count {
                    Some(total)
                } else {
                    while total < count {
                        let chunk = (count - total).min(152);
                        let mut reply = TronaMsg::zeroed();
                        crate::mount::mount_read_inline(
                            mount_idx,
                            remote_ino,
                            offset + total,
                            chunk,
                            &raw mut reply,
                        );
                        if reply.label != TRONA_OK {
                            return None;
                        }
                        let bytes = reply.regs[0];
                        if bytes == 0 {
                            break;
                        }
                        let src = &raw const reply.regs[1] as *const u8;
                        for i in 0..bytes as usize {
                            *dst.add(total as usize + i) = *src.add(i);
                        }
                        total += bytes;
                        if bytes < chunk {
                            break;
                        }
                    }
                    Some(total)
                }
            } else {
                let mut total = 0u64;
                while total < count {
                    let chunk = (count - total).min(152);
                    let mut reply = TronaMsg::zeroed();
                    crate::mount::mount_read_inline(
                        mount_idx,
                        remote_ino,
                        offset + total,
                        chunk,
                        &raw mut reply,
                    );
                    if reply.label != TRONA_OK {
                        return None;
                    }
                    let bytes = reply.regs[0];
                    if bytes == 0 {
                        break;
                    }
                    let src = &raw const reply.regs[1] as *const u8;
                    for i in 0..bytes as usize {
                        *dst.add(total as usize + i) = *src.add(i);
                    }
                    total += bytes;
                    if bytes < chunk {
                        break;
                    }
                }
                Some(total)
            }
        }
        _ => None,
    }
}

unsafe fn write_backing_bytes(
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
    offset: u64,
    src: *const u8,
    count: u64,
) -> Option<u64> {
    match backing_kind {
        MMAP_BACKING_FILE => {
            let inode = inode_by_ino(backing_id0 as u32);
            if inode.is_null() || (*inode).readonly != 0 {
                return None;
            }
            if (*inode).rw_data.is_null() && count > 0 {
                (*inode).rw_data = crate::ramfs::alloc_writable();
                if (*inode).rw_data.is_null() {
                    return None;
                }
            }
            let written = crate::ramfs::chain_write((*inode).rw_data, offset, src, count);
            if written == 0 && count > 0 {
                return None;
            }
            let end = offset + written;
            if end > (*inode).size {
                (*inode).size = end;
            }
            Some(written)
        }
        MMAP_BACKING_MOUNT => {
            let mount_idx = backing_id0 as usize;
            let remote_ino = backing_id1;
            let mut total = 0u64;
            if *(&raw const crate::VFS_SHM_ACTIVE) {
                while total < count {
                    let chunk = core::cmp::min(count - total, crate::consts::VFS_SALTYFS_SHM_PAGES * 4096);
                    let dst = crate::consts::VFS_SALTYFS_SHM_VADDR as *mut u8;
                    for i in 0..chunk as usize {
                        *dst.add(i) = *src.add(total as usize + i);
                    }
                    let mut reply = TronaMsg::zeroed();
                    crate::mount::mount_write_shm(mount_idx, remote_ino, offset + total, chunk, 0, &raw mut reply);
                    if reply.label != TRONA_OK {
                        break;
                    }
                    let wrote = reply.regs[0];
                    total += wrote;
                    if wrote < chunk {
                        break;
                    }
                }
                if total == count {
                    Some(total)
                } else {
                    while total < count {
                        let chunk = core::cmp::min(count - total, 136);
                        let mut reply = TronaMsg::zeroed();
                        crate::mount::mount_write_inline(
                            mount_idx,
                            remote_ino,
                            offset + total,
                            src.add(total as usize),
                            chunk,
                            &raw mut reply,
                        );
                        if reply.label != TRONA_OK {
                            return None;
                        }
                        let wrote = reply.regs[0];
                        total += wrote;
                        if wrote < chunk {
                            break;
                        }
                    }
                    Some(total)
                }
            } else {
                while total < count {
                    let chunk = core::cmp::min(count - total, 136);
                    let mut reply = TronaMsg::zeroed();
                    crate::mount::mount_write_inline(
                        mount_idx,
                        remote_ino,
                        offset + total,
                        src.add(total as usize),
                        chunk,
                        &raw mut reply,
                    );
                    if reply.label != TRONA_OK {
                        return None;
                    }
                    let wrote = reply.regs[0];
                    total += wrote;
                    if wrote < chunk {
                        break;
                    }
                }
                Some(total)
            }
        }
        _ => None,
    }
}

unsafe fn get_or_create_shared_file_mo(
    source_type: u8,
    source_id0: u64,
    source_id1: u64,
    file_size: u64,
) -> Cap {
    let needed_pages = ((file_size + 4095) / 4096) as u32;
    let existing = mmap_cache_lookup(source_type, source_id0, source_id1, needed_pages, file_size);
    if !existing.is_null() {
        return (*existing).mo_cap;
    }

    let slot = mmap_cache_alloc_or_replace(source_type, source_id0, source_id1);
    if slot.is_null() {
        return 0;
    }

    let mo_cap = alloc_mo_cap(needed_pages as usize);
    if mo_cap == 0 {
        return 0;
    }

    let actual_pages = match trona::invoke::mo_get_size(mo_cap) {
        (0, pages) if pages != 0 => pages as u32,
        _ => needed_pages,
    };

    *slot = FileMmapCacheEntry {
        active: 1,
        source_type,
        _pad0: [0; 2],
        source_id0,
        source_id1,
        page_count: actual_pages,
        _pad1: 0,
        file_size,
        mo_cap,
    };
    mo_cap
}

unsafe fn sync_backing_size_with_mmsrv(
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
    new_size: u64,
    sync_flags: u64,
) {
    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_SYNC_FILE_BACKING;
    msg.length = 5;
    msg.regs[0] = backing_kind;
    msg.regs[1] = backing_id0;
    msg.regs[2] = backing_id1;
    msg.regs[3] = new_size;
    msg.regs[4] = sync_flags;
    let _ = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
}

unsafe fn write_shared_mo_range(
    entry: *mut FileMmapCacheEntry,
    offset: u64,
    src: *const u8,
    count: u64,
    old_size: u64,
    new_size: u64,
) {
    if entry.is_null() || (*entry).active == 0 || count == 0 {
        if !entry.is_null() && new_size > (*entry).file_size {
            (*entry).file_size = new_size;
        }
        return;
    }

    let needed_pages = ((new_size + 4095) / 4096) as u32;
    if needed_pages > (*entry).page_count {
        if trona::invoke::mo_resize((*entry).mo_cap, needed_pages as u64) == 0 {
            let (_, pages) = trona::invoke::mo_get_size((*entry).mo_cap);
            if pages != 0 {
                (*entry).page_count = pages as u32;
            } else {
                (*entry).page_count = needed_pages;
            }
        }
    }

    if old_size < offset {
        let mut zero_pos = old_size;
        while zero_pos < offset {
            let page_idx = zero_pos / 4096;
            let page_off = zero_pos & 0xFFF;
            let page_end = (page_idx + 1) * 4096;
            let zero_len = core::cmp::min(offset, page_end) - zero_pos;
            let (has_err, has_page) = trona::invoke::mo_has_page((*entry).mo_cap, page_idx);
            if has_err == 0 && has_page {
                let map_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
                if trona::invoke::vspace_map_mo(
                    CAP_SELF_VSPACE,
                    (*entry).mo_cap,
                    VFS_FILE_MMAP_SCRATCH_VADDR,
                    page_idx,
                    map_flags,
                ) == 0 {
                    core::ptr::write_bytes(
                        (VFS_FILE_MMAP_SCRATCH_VADDR as *mut u8).add(page_off as usize),
                        0,
                        zero_len as usize,
                    );
                    let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
                }
            }
            zero_pos += zero_len;
        }
    }

    let mut copied = 0u64;
    while copied < count {
        let absolute = offset + copied;
        let page_idx = absolute / 4096;
        let page_off = absolute & 0xFFF;
        let chunk = core::cmp::min(count - copied, 4096 - page_off);
        let (has_err, has_page) = trona::invoke::mo_has_page((*entry).mo_cap, page_idx);
        if has_err == 0 && has_page {
            let map_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
            if trona::invoke::vspace_map_mo(
                CAP_SELF_VSPACE,
                (*entry).mo_cap,
                VFS_FILE_MMAP_SCRATCH_VADDR,
                page_idx,
                map_flags,
            ) == 0 {
                core::ptr::copy_nonoverlapping(
                    src.add(copied as usize),
                    (VFS_FILE_MMAP_SCRATCH_VADDR as *mut u8).add(page_off as usize),
                    chunk as usize,
                );
                let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
            }
        }
        copied += chunk;
    }

    if new_size > (*entry).file_size {
        (*entry).file_size = new_size;
    }
}

pub(crate) unsafe fn sync_shared_mmap_after_write(
    fde: &FdEntry,
    offset: u64,
    src: *const u8,
    count: u64,
    old_size: u64,
    new_size: u64,
) {
    if let Some((source_type, source_id0, source_id1)) = backing_source_for_fd(fde) {
        let backing_kind = if source_type == MMAP_CACHE_SOURCE_FILE {
            MMAP_BACKING_FILE
        } else {
            MMAP_BACKING_MOUNT
        };
        let entry = mmap_cache_find_source(source_type, source_id0, source_id1);
        write_shared_mo_range(entry, offset, src, count, old_size, new_size);
        if new_size != old_size {
            sync_backing_size_with_mmsrv(backing_kind, source_id0, source_id1, new_size, 0);
        }
    }
}

pub(crate) unsafe fn sync_shared_mmap_after_truncate(fde: &FdEntry, old_size: u64, new_size: u64) {
    let Some((source_type, source_id0, source_id1)) = backing_source_for_fd(fde) else {
        return;
    };
    let backing_kind = if source_type == MMAP_CACHE_SOURCE_FILE {
        MMAP_BACKING_FILE
    } else {
        MMAP_BACKING_MOUNT
    };

    sync_backing_size_with_mmsrv(
        backing_kind,
        source_id0,
        source_id1,
        new_size,
        if new_size < old_size { MM_SYNC_BACKING_TRUNCATE } else { 0 },
    );

    let entry = mmap_cache_find_source(source_type, source_id0, source_id1);
    if entry.is_null() || (*entry).active == 0 {
        return;
    }

    if new_size < old_size {
        let last_kept_page = new_size / 4096;
        let last_kept_off = new_size & 0xFFF;
        if last_kept_off != 0 {
            let (has_err, has_page) = trona::invoke::mo_has_page((*entry).mo_cap, last_kept_page);
            if has_err == 0 && has_page {
                let map_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
                if trona::invoke::vspace_map_mo(
                    CAP_SELF_VSPACE,
                    (*entry).mo_cap,
                    VFS_FILE_MMAP_SCRATCH_VADDR,
                    last_kept_page,
                    map_flags,
                ) == 0 {
                    core::ptr::write_bytes(
                        (VFS_FILE_MMAP_SCRATCH_VADDR as *mut u8).add(last_kept_off as usize),
                        0,
                        (4096 - last_kept_off) as usize,
                    );
                    let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
                }
            }
        }

        let first_drop_page = (new_size + 4095) / 4096;
        let mut page = first_drop_page;
        while page < (*entry).page_count as u64 {
            let (has_err, has_page) = trona::invoke::mo_has_page((*entry).mo_cap, page);
            if has_err == 0 && has_page {
                let _ = trona::invoke::mo_decommit((*entry).mo_cap, page, 1);
            }
            page += 1;
        }
    }

    (*entry).file_size = new_size;
}

unsafe fn map_object_region_into_client(
    badge: u64,
    requested_base: u64,
    page_count: usize,
    mo_offset: u64,
    flags: u64,
    region_type: u64,
    mo_cap: Cap,
    backing_kind: u64,
    backing_id0: u64,
    backing_id1: u64,
    backing_file_offset: u64,
    backing_file_size: u64,
    options: u64,
) -> Option<u64> {
    ipc::set_send_cap_ctx(ipc_ctx(), 0, mo_cap);

    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = MM_MAP_OBJECT_REGION;
    msg.length = 12;
    msg.regs[0] = badge;
    msg.regs[1] = requested_base;
    msg.regs[2] = page_count as u64;
    msg.regs[3] = mo_offset;
    msg.regs[4] = flags;
    msg.regs[5] = region_type;
    msg.regs[6] = backing_kind;
    msg.regs[7] = backing_id0;
    msg.regs[8] = backing_id1;
    msg.regs[9] = backing_file_offset;
    msg.regs[10] = backing_file_size;
    msg.regs[11] = options;

    let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
    if err != 0 || reply.label != TRONA_OK {
        None
    } else {
        Some(reply.regs[0])
    }
}

pub(crate) unsafe fn handle_mmap_pagein(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        trona::uerror!(|_lb| {
            _lb.str(b"[VFS] mmap pagein entry kind=");
            _lb.hex((*msg).regs[0]);
            _lb.str(b" id0=");
            _lb.hex((*msg).regs[1]);
            _lb.str(b" id1=");
            _lb.hex((*msg).regs[2]);
            _lb.str(b" file_off=");
            _lb.hex((*msg).regs[3]);
            _lb.str(b" mo_page=");
            _lb.dec((*msg).regs[4]);
            _lb.str(b" bytes=");
            _lb.dec((*msg).regs[5]);
            _lb.str(b" recv_slot=");
            _lb.dec(*(&raw const crate::CURRENT_RECV_SLOT));
            _lb.str(b"\n");
        });

        let mo_cap = *(&raw const crate::CURRENT_RECV_SLOT);
        if mo_cap == 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] mmap pagein: missing recv slot cap\n");
            });
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let backing_kind = (*msg).regs[0];
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let file_offset = (*msg).regs[3];
        let mo_page_idx = (*msg).regs[4];
        let bytes = (*msg).regs[5];

        let (has_err, has_page) = trona::invoke::mo_has_page(mo_cap, mo_page_idx);
        if has_err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] mmap pagein: mo_has_page failed mo=");
                _lb.dec(mo_cap);
                _lb.str(b" page=");
                _lb.dec(mo_page_idx);
                _lb.str(b" err=");
                _lb.hex(has_err as u64);
                _lb.str(b"\n");
            });
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        if has_page {
            (*reply).label = TRONA_OK;
            return;
        }

        let (commit_err, committed) = trona::invoke::mo_commit(mo_cap, mo_page_idx, 1, 0);
        if commit_err != 0 || committed != 1 {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] mmap pagein: mo_commit failed mo=");
                _lb.dec(mo_cap);
                _lb.str(b" page=");
                _lb.dec(mo_page_idx);
                _lb.str(b" err=");
                _lb.hex(commit_err as u64);
                _lb.str(b" committed=");
                _lb.dec(committed);
                _lb.str(b"\n");
            });
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let map_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let map_err = trona::invoke::vspace_map_mo(
            CAP_SELF_VSPACE,
            mo_cap,
            VFS_FILE_MMAP_SCRATCH_VADDR,
            mo_page_idx,
            map_flags,
        );
        if map_err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] mmap pagein: vspace_map_mo failed mo=");
                _lb.dec(mo_cap);
                _lb.str(b" page=");
                _lb.dec(mo_page_idx);
                _lb.str(b" vaddr=");
                _lb.hex(VFS_FILE_MMAP_SCRATCH_VADDR);
                _lb.str(b" err=");
                _lb.hex(map_err as u64);
                _lb.str(b"\n");
            });
            let _ = trona::invoke::mo_decommit(mo_cap, mo_page_idx, 1);
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let dst = VFS_FILE_MMAP_SCRATCH_VADDR as *mut u8;
        core::ptr::write_bytes(dst, 0, 4096);
        if bytes > 0 && read_backing_bytes(backing_kind, backing_id0, backing_id1, file_offset, dst, bytes).is_none() {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] mmap pagein: backing read failed kind=");
                _lb.hex(backing_kind);
                _lb.str(b" id0=");
                _lb.hex(backing_id0);
                _lb.str(b" id1=");
                _lb.hex(backing_id1);
                _lb.str(b" off=");
                _lb.hex(file_offset);
                _lb.str(b" bytes=");
                _lb.dec(bytes);
                _lb.str(b"\n");
            });
            let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
            let _ = trona::invoke::mo_decommit(mo_cap, mo_page_idx, 1);
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
        (*reply).label = TRONA_OK;
    }
}

pub(crate) unsafe fn handle_mmap_writeback(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let mo_cap = *(&raw const crate::CURRENT_RECV_SLOT);
        if mo_cap == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let backing_kind = (*msg).regs[0];
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let file_offset = (*msg).regs[3];
        let mo_page_idx = (*msg).regs[4];
        let bytes = (*msg).regs[5];

        let (has_err, has_page) = trona::invoke::mo_has_page(mo_cap, mo_page_idx);
        if has_err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        if !has_page || bytes == 0 {
            (*reply).label = TRONA_OK;
            return;
        }

        let map_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let map_err = trona::invoke::vspace_map_mo(
            CAP_SELF_VSPACE,
            mo_cap,
            VFS_FILE_MMAP_SCRATCH_VADDR,
            mo_page_idx,
            map_flags,
        );
        if map_err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let src = VFS_FILE_MMAP_SCRATCH_VADDR as *const u8;
        let wrote = write_backing_bytes(backing_kind, backing_id0, backing_id1, file_offset, src, bytes);
        let _ = trona::invoke::vspace_unmap(CAP_SELF_VSPACE, VFS_FILE_MMAP_SCRATCH_VADDR);
        if wrote == Some(bytes) {
            (*reply).label = TRONA_OK;
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}

/// Handle a deferred PTY device read. Called from main loop when fd is DEV_PTY_SLAVE.
/// Returns true if reply is deferred (skip_reply), false if reply is ready now.
pub(crate) unsafe fn handle_pty_dev_read(
    msg: *const TronaMsg,
    fde: *mut FdEntry,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let count = (*msg).regs[1];
        let max = if count > 152 { 152 } else { count };
        let pty_id = (*fde).sock_id as u64;

        // Try-read from ttyd (always returns immediately)
        let mut treq = TronaMsg::zeroed();
        let mut treply = TronaMsg::zeroed();
        treq.label = TTYD_PTY_READ;
        treq.regs[0] = pty_id;
        treq.regs[1] = max;
        treq.length = 2;

        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
        if err != 0 || treply.label != TRONA_OK {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let actual = treply.regs[0];
        if actual > 0 {
            // Data available — return immediately
            (*reply).label = TRONA_OK;
            (*reply).length = 1 + (actual + 7) / 8;
            (*reply).regs[0] = actual;
            let src = &treply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for i in 0..actual as usize {
                *dst.add(i) = *src.add(i);
            }
            return false;
        }

        // WOULD_BLOCK — save caller's reply cap, enqueue pending reader
        let pid = pty_id as usize;
        if pid >= MAX_PTYS || crate::PTY_PENDING_COUNT[pid] >= MAX_PTY_WAITERS {
            (*reply).label = TRONA_BUSY;
            return false;
        }

        let slot = alloc_reply_slot();
        let save_err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if save_err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }

        let idx = crate::PTY_PENDING_COUNT[pid];
        crate::PTY_PENDING[pid][idx] = PtyPendingReader {
            active: 1,
            badge,
            reply_slot: slot,
            max_count: max,
        };
        crate::PTY_PENDING_COUNT[pid] += 1;

        true // deferred — VFS will wake this reader when ttyd signals data-ready
    }
}

/// Handle bound notification from ttyd signalling PTY data ready.
/// Called when VFS wakes from reply_recv with a notification (msg.length==0, badge!=0).
/// Wakes pending PTY readers by collecting data from ttyd and forwarding to saved reply caps.
pub(crate) unsafe fn handle_pty_notification(ntfn_badge: u64) {
    unsafe {
        for pty_id in 0..MAX_PTYS {
            if ntfn_badge & (1u64 << pty_id) == 0 {
                continue;
            }

            // Wake pending readers for this PTY in FIFO order
            while crate::PTY_PENDING_COUNT[pty_id] > 0 {
                let reader = crate::PTY_PENDING[pty_id][0];
                if reader.active == 0 {
                    break;
                }

                // Collect data from ttyd
                let mut creq = TronaMsg::zeroed();
                let mut creply = TronaMsg::zeroed();
                creq.label = TTYD_PTY_COLLECT;
                creq.regs[0] = pty_id as u64;
                creq.regs[1] = reader.max_count;
                creq.length = 2;
                let cerr =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const creq, &raw mut creply);

                let actual = creply.regs[0];
                if actual == 0 {
                    break; // buffer drained
                }

                // Forward data to saved client reply cap
                let mut wake = TronaMsg::zeroed();
                wake.label = TRONA_OK;
                wake.length = 1 + (actual + 7) / 8;
                wake.regs[0] = actual;
                let src = &creply.regs[1] as *const u64 as *const u8;
                let dst = &raw mut wake.regs[1] as *mut u8;
                for i in 0..actual as usize {
                    *dst.add(i) = *src.add(i);
                }
                ipc::send_ctx(ipc_ctx(), reader.reply_slot, &raw const wake);

                // Shift remaining waiters forward (FIFO)
                for j in 1..crate::PTY_PENDING_COUNT[pty_id] {
                    crate::PTY_PENDING[pty_id][j - 1] = crate::PTY_PENDING[pty_id][j];
                }
                crate::PTY_PENDING_COUNT[pty_id] -= 1;
                if crate::PTY_PENDING_COUNT[pty_id] < MAX_PTY_WAITERS {
                    crate::PTY_PENDING[pty_id][crate::PTY_PENDING_COUNT[pty_id]] =
                        PtyPendingReader::zeroed();
                }
            }

            // Wake poll/epoll waiters for PTY fds (POLLIN event)
            // Iterate all clients to find PTY fds on this pty_id
            for ci in 0..max_clients() {
                let cli = &*(&raw const CLIENTS!()[ci]);
                if cli.active == 0 {
                    continue;
                }
                for fi in 0..(*cli).fds_cap as usize {
                    if (*cli.fds.add(fi)).active != 0
                        && (*cli.fds.add(fi)).fd_type == FD_TYPE_DEVICE
                        && (*cli.fds.add(fi)).dev_type == DEV_PTY_SLAVE
                        && (*cli.fds.add(fi)).sock_id as usize == pty_id
                    {
                        wake_poll_waiters(cli.badge, fi as i32, 0x001); // POLLIN
                    }
                }
            }
        }
    }
}

pub(crate) unsafe fn handle_isatty(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let is_tty = if (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_DEVICE
            && ((*(*cli).fds.add(fd as usize)).dev_type == DEV_CONSOLE
                || (*(*cli).fds.add(fd as usize)).dev_type == DEV_PTY_SLAVE)
        {
            1u64
        } else {
            0u64
        };

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = is_tty;
    }
}

/// Forward tcgetattr to ttyd (for PTY) or console server (for /dev/console)
pub(crate) unsafe fn handle_tcgetattr(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
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

        let fde = *(*cli).fds.add(fd as usize);
        if fde.fd_type != FD_TYPE_DEVICE {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if fde.dev_type == DEV_PTY_SLAVE {
            // Forward to ttyd via TTYD_PTY_TCGETATTR
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = TTYD_PTY_TCGETATTR;
            treq.regs[0] = fde.sock_id as u64; // pty_id
            treq.length = 1;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = treply.length;
            for i in 0..treply.length as usize {
                (*reply).regs[i] = treply.regs[i];
            }
        } else if fde.dev_type == DEV_CONSOLE {
            // Forward to console server
            let mut creq = TronaMsg::zeroed();
            let mut creply = TronaMsg::zeroed();
            creq.label = CONSOLE_TCGETATTR;
            creq.length = 0;
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_CONSOLE_EP,
                &raw const creq,
                &raw mut creply,
            );
            if err != 0 || creply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = creply.length;
            for i in 0..creply.length as usize {
                (*reply).regs[i] = creply.regs[i];
            }
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}

/// Forward tcsetattr to ttyd (for PTY) or console server (for /dev/console)
pub(crate) unsafe fn handle_tcsetattr(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
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

        let fde = *(*cli).fds.add(fd as usize);
        if fde.fd_type != FD_TYPE_DEVICE {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if fde.dev_type == DEV_PTY_SLAVE {
            // Forward to ttyd via TTYD_PTY_TCSETATTR
            // msg layout: regs[0]=fd, regs[1]=action, regs[2..11]=termios data
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = TTYD_PTY_TCSETATTR;
            treq.regs[0] = fde.sock_id as u64; // pty_id
                                               // Copy termios data from regs[1..] (action + flags + c_cc)
            let copy_len = if (*msg).length > 1 {
                (*msg).length - 1
            } else {
                0
            };
            for i in 0..copy_len as usize {
                treq.regs[i + 1] = (*msg).regs[i + 1];
            }
            treq.length = 1 + copy_len;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
        } else if fde.dev_type == DEV_CONSOLE {
            // Forward to console server
            let mut creq = TronaMsg::zeroed();
            let mut creply = TronaMsg::zeroed();
            creq.label = CONSOLE_TCSETATTR;
            creq.length = (*msg).length;
            for i in 0..(*msg).length as usize {
                creq.regs[i] = (*msg).regs[i];
            }
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_CONSOLE_EP,
                &raw const creq,
                &raw mut creply,
            );
            if err != 0 || creply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}

pub(crate) unsafe fn handle_ioctl(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let request = (*msg).regs[1];
        let arg = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);
        if fde.fd_type == FD_TYPE_INET_SOCKET {
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] inet ioctl fd=");
                _lb.dec(fd as u64);
                _lb.str(b" req=");
                _lb.hex(request);
                _lb.putc(b'\n');
            });
        }

        fn is_net_ioctl(request: u64) -> bool {
            matches!(
                request,
                0x8910 | 0x8912 | 0x8913 | 0x8915 | 0x8919 | 0x891B | 0x8933
            )
        }

        if fde.fd_type == FD_TYPE_DEVICE && fde.dev_type == DEV_FB0 {
            handle_ioctl_fb0(request, reply);
            return;
        }

        if fde.fd_type == FD_TYPE_INET_SOCKET && is_net_ioctl(request) {
            let mut nreq = TronaMsg::zeroed();
            let mut nreply = TronaMsg::zeroed();
            nreq.label = NET_GET_CONFIG;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const nreq, &raw mut nreply);
            if err != 0 || nreply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }

            let our_ip = nreply.regs[1] as u32;
            let subnet_mask = nreply.regs[2] as u32;
            let flags = if our_ip != 0 {
                0x1u64 | 0x2u64 | 0x40u64 | 0x1000u64
            } else {
                0
            };

            (*reply).label = TRONA_OK;
            match request {
                0x8910 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = 1;
                }
                0x8912 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = our_ip as u64;
                }
                0x8913 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = flags;
                }
                0x8915 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = our_ip as u64;
                }
                0x8919 => {
                    let broadcast = if our_ip != 0 && subnet_mask != 0 {
                        ((our_ip & subnet_mask) | !subnet_mask) as u64
                    } else {
                        0
                    };
                    (*reply).length = 1;
                    (*reply).regs[0] = broadcast;
                }
                0x891B => {
                    (*reply).length = 1;
                    (*reply).regs[0] = subnet_mask as u64;
                }
                0x8933 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = 1;
                }
                _ => {
                    (*reply).label = TRONA_INVALID_OPERATION;
                }
            }
            let _ = arg;
            return;
        }

        // Terminal ioctls — supported by both console and PTY devices
        if fde.fd_type != FD_TYPE_DEVICE
            || (fde.dev_type != DEV_CONSOLE && fde.dev_type != DEV_PTY_SLAVE)
        {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let pty_id = if fde.dev_type == DEV_PTY_SLAVE {
            fde.sock_id as u64
        } else {
            0u64
        };

        match request {
            // TIOCGPGRP: get foreground process group
            0x540F => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x540F; // TIOCGPGRP
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != TRONA_OK {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = treply.regs[0];
            }
            // TIOCSPGRP: set foreground process group
            0x5410 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5410; // TIOCSPGRP
                treq.regs[2] = (*msg).regs[2]; // pgid
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCSCTTY: acquire controlling tty
            0x540E => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x540E; // TIOCSCTTY
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCNOTTY: release controlling tty
            0x5422 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5422; // TIOCNOTTY
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            // TIOCGWINSZ: get terminal window size
            0x5413 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5413; // TIOCGWINSZ
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != TRONA_OK {
                    // Fallback to default 80x24
                    (*reply).label = TRONA_OK;
                    (*reply).length = 2;
                    (*reply).regs[0] = 24;
                    (*reply).regs[1] = 80;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 2;
                (*reply).regs[0] = treply.regs[0];
                (*reply).regs[1] = treply.regs[1];
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_ioctl_fb0(request: u64, reply: *mut TronaMsg) {
    unsafe {
        match request {
            // FBIOGET_VSCREENINFO
            0x4600 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 5;
                (*reply).regs[0] = crate::FB_WIDTH as u64;
                (*reply).regs[1] = crate::FB_HEIGHT as u64;
                (*reply).regs[2] = crate::FB_BPP as u64;
                (*reply).regs[3] = ((crate::FB_RED_POS as u64) << 24)
                    | ((crate::FB_RED_SIZE as u64) << 16)
                    | ((crate::FB_GREEN_POS as u64) << 8)
                    | (crate::FB_GREEN_SIZE as u64);
                (*reply).regs[4] =
                    ((crate::FB_BLUE_POS as u64) << 24) | ((crate::FB_BLUE_SIZE as u64) << 16);
            }
            // FBIOGET_FSCREENINFO
            0x4602 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 3;
                (*reply).regs[0] = crate::FB_PITCH as u64;
                (*reply).regs[1] = crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64;
                (*reply).regs[2] = 0; // type = packed pixels
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_munmap(_msg: *const TronaMsg, reply: *mut TronaMsg, _badge: u64) {
    unsafe {
        // VFS does not manage user virtual address space directly; munmap is
        // handled on the client side via mmsrv.  Acknowledge the request so
        // the caller is not blocked.
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_mmap(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let file_offset = (*msg).regs[1];
        let length = (*msg).regs[2];
        let prot = (*msg).regs[3];
        let map_flags = (*msg).regs[4] as i32;
        let addr_hint = if (*msg).length >= 6 { (*msg).regs[5] } else { 0 };

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);

        if (fde.fd_type == FD_TYPE_FILE || fde.fd_type == FD_TYPE_MOUNT) && length != 0 {
            if file_offset & 0xFFF != 0 {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }

            let Some(file_size) = file_mapping_size(&fde) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            };
            if file_offset >= file_size {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }

            let mapping_pages = ((length + 4095) / 4096) as usize;
            if mapping_pages == 0 {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }

            let requested_base = if (map_flags & MAP_FIXED) != 0 {
                if addr_hint & 0xFFF != 0 {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                addr_hint
            } else {
                0
            };

            let Some((source_type, source_id0, source_id1)) = backing_source_for_fd(&fde) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            };

            let backing_kind = match source_type {
                MMAP_CACHE_SOURCE_FILE => MMAP_BACKING_FILE,
                MMAP_CACHE_SOURCE_MOUNT => MMAP_BACKING_MOUNT,
                _ => MMAP_BACKING_NONE,
            };

            let vspace_flags = mmap_prot_to_vspace_flags(prot);
            let is_shared = (map_flags & MAP_SHARED) != 0;
            let wants_write = (prot & PROT_WRITE as u64) != 0;
            if is_shared && wants_write {
                if !crate::client::flags_allow_write(fde.flags) {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                if fde.fd_type == FD_TYPE_FILE {
                    let inode = inode_by_ino(fde.inode);
                    if inode.is_null() || (*inode).readonly != 0 {
                        (*reply).label = TRONA_INVALID_OPERATION;
                        return;
                    }
                }
                if file_offset.checked_add(length).is_none() || file_offset + length > file_size {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            }

            if is_shared {
                let shared_mo = get_or_create_shared_file_mo(source_type, source_id0, source_id1, file_size);
                if shared_mo == 0 {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }

                let options = MMAP_OBJECT_OPT_LAZY
                    | if wants_write { MMAP_OBJECT_OPT_WRITEBACK } else { 0 };
                let Some(base) = map_object_region_into_client(
                    badge,
                    requested_base,
                    mapping_pages,
                    file_offset / 4096,
                    vspace_flags,
                    MMAP_REGION_TYPE_FILE_SHARED,
                    shared_mo,
                    backing_kind,
                    source_id0,
                    source_id1,
                    file_offset,
                    file_size,
                    options,
                ) else {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                };

                (*reply).label = TRONA_OK;
                (*reply).length = 3;
                (*reply).regs[0] = base;
                (*reply).regs[1] = 0;
                (*reply).regs[2] = 1;
                return;
            }

            let private_mo = alloc_mo_cap(mapping_pages);
            if private_mo == 0 {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }

            let mapped = map_object_region_into_client(
                badge,
                requested_base,
                mapping_pages,
                0,
                vspace_flags,
                MMAP_REGION_TYPE_PRIVATE,
                private_mo,
                backing_kind,
                source_id0,
                source_id1,
                file_offset,
                file_size,
                MMAP_OBJECT_OPT_LAZY,
            );
            let _ = trona::invoke::cnode_delete(CAP_SELF_CSPACE, private_mo);

            let Some(base) = mapped else {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            };

            (*reply).label = TRONA_OK;
            (*reply).length = 3;
            (*reply).regs[0] = base;
            (*reply).regs[1] = 0;
            (*reply).regs[2] = 1;
            return;
        }

        // SHM mmap — delegate to mmsrv
        if fde.fd_type == FD_TYPE_SHM {
            let inode = inode_by_ino(fde.inode);
            if inode.is_null() || (*inode).ftype != FTYPE_SHM {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }

            let shm_idx = (*inode).dev_type as usize;
            if shm_idx >= max_shm_objects() {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }

            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = MM_SHM_MAP;
            mm_msg.length = 4;
            mm_msg.regs[0] = shm_idx as u64;
            mm_msg.regs[1] = badge; // client badge = pid
            mm_msg.regs[2] = 0; // vaddr = 0 (let mmsrv pick)
            mm_msg.regs[3] = prot;
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != TRONA_OK {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }

            // Store the mapped vaddr in fd.offset for MM_SHM_UNMAP on close
            (*(*cli).fds.add(fd as usize)).offset = mm_reply.regs[0];

            (*reply).label = TRONA_OK;
            (*reply).length = 3;
            (*reply).regs[0] = mm_reply.regs[0]; // mapped base addr
            (*reply).regs[1] = 0;
            (*reply).regs[2] = 1; // server-side mapped flag
            return;
        }

        // FB0 device mmap — cap transfer
        if fde.fd_type != FD_TYPE_DEVICE || fde.dev_type != DEV_FB0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if crate::FB_MMAP_BADGE != 0 && crate::FB_MMAP_BADGE != badge {
            (*reply).label = TRONA_BUSY;
            return;
        }

        let smem_len = crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64;
        if length > smem_len {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        ipc::set_send_cap_ctx(ipc_ctx(), 0, VFS_CAP_FB_UNTYPED);

        crate::FB_MMAP_BADGE = badge;

        (*reply).label = TRONA_OK;
        (*reply).length = 3;
        (*reply).regs[0] = smem_len;
        (*reply).regs[1] = crate::FB_PITCH as u64;
        (*reply).regs[2] = 0;
    }
}

pub(crate) unsafe fn handle_fcntl(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cmd = (*msg).regs[1] as i32;
        let arg = (*msg).regs[2] as i64;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_INET_SOCKET {
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] inet fcntl fd=");
                _lb.dec(fd as u64);
                _lb.str(b" cmd=");
                _lb.dec(cmd as u64);
                _lb.putc(b'\n');
            });
        }

        match cmd {
            // F_DUPFD: duplicate fd, new fd >= arg
            0 | 1030 => {
                // F_DUPFD (0) and F_DUPFD_CLOEXEC (1030)
                let min_fd = if arg < 0 { 0 } else { arg as usize };
                let mut newfd: i32 = -1;
                let mut i = min_fd;
                while i < (*cli).fds_cap as usize {
                    if (*(*cli).fds.add(i)).active == 0 {
                        newfd = i as i32;
                        break;
                    }
                    i += 1;
                }
                if newfd < 0 {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }

                dup_fd_entry(cli, fd, newfd);
                // F_DUPFD_CLOEXEC sets FD_CLOEXEC on new fd
                if cmd == 1030 {
                    *(*cli).fd_flags.add(newfd as usize) = 1; // FD_CLOEXEC
                } else {
                    *(*cli).fd_flags.add(newfd as usize) = 0;
                }

                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = newfd as u64;
            }
            // F_GETFD: get fd flags
            1 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = *(*cli).fd_flags.add(fd as usize) as u64;
            }
            // F_SETFD: set fd flags
            2 => {
                *(*cli).fd_flags.add(fd as usize) = arg as u8;
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            // F_GETFL: get file status flags
            3 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = (*(*cli).fds.add(fd as usize)).flags as u64;
            }
            // F_SETFL: set file status flags (only O_APPEND, O_NONBLOCK are changeable)
            4 => {
                let changeable = O_APPEND | O_NONBLOCK;
                let preserved = (*(*cli).fds.add(fd as usize)).flags & !changeable;
                (*(*cli).fds.add(fd as usize)).flags = preserved | (arg as u32 & changeable);
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_chdir(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
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

        // Validate that path exists and is a directory
        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() {
            // Root underlay fallback: validate path exists on disk and is a directory
            if let Some((mi, rino)) = try_root_underlay(path_ptr, path_len) {
                if let Some((_, _, _, _, is_dir)) = mount_stat(mi, rino) {
                    if !is_dir {
                        (*reply).label = TRONA_INVALID_ARGUMENT;
                        return;
                    }
                } else {
                    (*reply).label = TRONA_NOT_FOUND;
                    return;
                }
            } else {
                (*reply).label = TRONA_NOT_FOUND;
                return;
            }
            // Path exists on underlay and is a directory — store cwd string below
        } else {
            if (*inode).ftype != FTYPE_DIRECTORY && (*inode).ftype != FTYPE_MOUNT_POINT {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Store the new cwd
        let copy_len = if (path_len as usize) < 127 {
            path_len as usize
        } else {
            127
        };
        let mut i = 0;
        while i < copy_len {
            (*cli).cwd[i] = *path_ptr.add(i);
            i += 1;
        }
        // Ensure null-terminated
        (*cli).cwd[copy_len] = 0;
        // Zero rest
        i = copy_len + 1;
        while i < 128 {
            (*cli).cwd[i] = 0;
            i += 1;
        }

        (*reply).label = TRONA_OK;
    }
}

pub(crate) unsafe fn handle_getcwd(msg: *const TronaMsg, reply: *mut TronaMsg, badge: u64) {
    unsafe {
        let max_size = (*msg).regs[0] as usize;

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Measure cwd length
        let mut cwd_len: usize = 0;
        while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
            cwd_len += 1;
        }
        if cwd_len == 0 {
            // Default to "/"
            cwd_len = 1;
            (*cli).cwd[0] = b'/';
            (*cli).cwd[1] = 0;
        }

        // POSIX getcwd(): caller buffer must fit full path + trailing NUL.
        if max_size == 0 || cwd_len + 1 > max_size {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Pack cwd bytes into reply regs[1..]
        let copy_len = cwd_len;
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = copy_len as u64;
        let dst = &mut (*reply).regs[1] as *mut u64 as *mut u8;
        let mut i = 0;
        while i < copy_len {
            *dst.add(i) = (*cli).cwd[i];
            i += 1;
        }
        (*reply).length = 1 + ((copy_len as u64 + 7) / 8);
    }
}

pub(crate) unsafe fn handle_shm_open(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let flags = (*msg).regs[0] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 1, path.as_mut_ptr());

        // Build full path /dev/shm/<name>
        let mut full_path = [0u8; MAX_PATH_LEN];
        let prefix = b"/dev/shm/";
        for i in 0..prefix.len() {
            full_path[i] = prefix[i];
        }
        for i in 0..name_len as usize {
            if prefix.len() + i >= MAX_PATH_LEN {
                break;
            }
            full_path[prefix.len() + i] = path[i];
        }
        let full_len = (prefix.len() + name_len as usize) as u8;

        let existing = resolve_path(full_path.as_ptr(), full_len);

        if !existing.is_null() {
            if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
                (*reply).label = TRONA_ALREADY_EXISTS;
                return false;
            }
            // Open existing
            let cli = get_client(badge);
            if cli.is_null() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
            for fd in 0..(*cli).fds_cap as usize {
                if (*(*cli).fds.add(fd)).active == 0 {
                    (*(*cli).fds.add(fd)).active = 1;
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_SHM;
                    (*(*cli).fds.add(fd)).inode = (*existing).ino;
                    crate::ramfs::inode_open((*existing).ino);
                    (*reply).label = TRONA_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = fd as u64;
                    return false;
                }
            }
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        if (flags & O_CREAT) == 0 {
            // O_CREAT not set
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Ensure /dev/shm exists
        let shm_dir = resolve_path(b"/dev/shm".as_ptr(), 8);
        let parent = if shm_dir.is_null() {
            // Create /dev/shm
            let dev_dir = resolve_path(b"/dev".as_ptr(), 4);
            if dev_dir.is_null() {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }
            let d = alloc_inode();
            if d.is_null() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
            (*d).ftype = FTYPE_DIRECTORY;
            (*d).mode = S_IFDIR_L | 0o755;
            (*d).nlink = 2;
            (*d).parent_ino = (*dev_dir).ino;
            dir_add_entry(dev_dir, b"shm".as_ptr(), 3, (*d).ino);
            d
        } else {
            shm_dir
        };

        // Create SHM inode
        let inode = alloc_inode();
        if inode.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        (*inode).ftype = FTYPE_SHM;
        (*inode).mode = S_IFREG_L | 0o666;
        (*inode).parent_ino = (*parent).ino;
        (*inode).size = 0;
        dir_add_entry(parent, path.as_ptr(), name_len, (*inode).ino);

        // Allocate SHM data
        let mut shm_idx: i32 = -1;
        for i in 0..max_shm_objects() {
            if SHM_DATA!()[i].active == 0 {
                shm_idx = i as i32;
                SHM_DATA!()[i].active = 1;
                break;
            }
        }
        if shm_idx < 0 {
            // No free slot: grow and retry
            if vfs_grow_pool(
                &raw mut crate::SHM_DATA_PTR as *mut *mut u8,
                &raw mut crate::SHM_CAP,
                core::mem::size_of::<ShmData>(),
            ) == 0
            {
                for i in 0..max_shm_objects() {
                    if SHM_DATA!()[i].active == 0 {
                        shm_idx = i as i32;
                        SHM_DATA!()[i].active = 1;
                        break;
                    }
                }
            }
            if shm_idx < 0 {
                (*inode).active = 0;
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // Store SHM index in inode dev_type field (repurposed)
        (*inode).dev_type = shm_idx as u8;

        let cli = get_client(badge);
        if cli.is_null() {
            (*inode).active = 0;
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_SHM;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                crate::ramfs::inode_open((*inode).ino);
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return false;
            }
        }

        (*inode).active = 0;
        (*reply).label = TRONA_OUT_OF_MEMORY;
        false
    }
}

pub(crate) unsafe fn handle_shm_unlink(msg: *const TronaMsg, reply: *mut TronaMsg) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 0, path.as_mut_ptr());

        let mut full_path = [0u8; MAX_PATH_LEN];
        let prefix = b"/dev/shm/";
        for i in 0..prefix.len() {
            full_path[i] = prefix[i];
        }
        for i in 0..name_len as usize {
            if prefix.len() + i >= MAX_PATH_LEN {
                break;
            }
            full_path[prefix.len() + i] = path[i];
        }
        let full_len = (prefix.len() + name_len as usize) as u8;

        let inode = resolve_path(full_path.as_ptr(), full_len);
        if inode.is_null() || (*inode).ftype != FTYPE_SHM {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Remove from parent
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(
            full_path.as_ptr(),
            full_len,
            &mut child_name,
            &mut child_len,
        );
        if !parent.is_null() {
            dir_remove_entry(parent, child_name, child_len);
        }
        // Reset SHM data slot
        let shm_idx = (*inode).dev_type as usize;
        if shm_idx < max_shm_objects() {
            SHM_DATA!()[shm_idx].active = 0;
            SHM_DATA!()[shm_idx].num_pages = 0;
        }

        (*inode).active = 0;
        (*reply).label = TRONA_OK;
        false
    }
}

pub(crate) unsafe fn handle_ftruncate(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let length = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let fde = *(*cli).fds.add(fd as usize);

        if fde.fd_type == FD_TYPE_MOUNT {
            let old_size = mount_stat(fde.dev_type as usize, fde.sock_id as u64)
                .map(|s| s.0)
                .unwrap_or(0);
            mount_truncate(fde.dev_type as usize, fde.sock_id as u64, length, reply);
            if (*reply).label == TRONA_OK {
                sync_shared_mmap_after_truncate(&fde, old_size, length);
            }
            return false;
        }

        if fde.fd_type == FD_TYPE_SHM {
            let inode = inode_by_ino(fde.inode);
            if inode.is_null() || (*inode).ftype != FTYPE_SHM {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            let shm_idx = (*inode).dev_type as usize;
            if shm_idx >= max_shm_objects() {
                (*reply).label = TRONA_INVALID_OPERATION;
                return false;
            }

            let num_pages = ((length + 4095) / 4096) as u16;
            if num_pages as usize > max_shm_pages() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            // Delegate frame allocation to mmsrv via MM_SHM_CREATE
            let shm = &raw mut SHM_DATA!()[shm_idx];

            {
                let mut mm_msg = TronaMsg::zeroed();
                let mut mm_reply = TronaMsg::zeroed();
                mm_msg.label = MM_SHM_CREATE;
                mm_msg.length = 2;
                mm_msg.regs[0] = shm_idx as u64;
                mm_msg.regs[1] = num_pages as u64;
                let err = ipc::call_ctx(
                    ipc_ctx(),
                    VFS_CAP_MMSRV_EP,
                    &raw const mm_msg,
                    &raw mut mm_reply,
                );
                if err != 0 || mm_reply.label != TRONA_OK {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                }
            }

            (*shm).num_pages = num_pages;
            (*inode).size = length;

            (*reply).label = TRONA_OK;
            return false;
        }

        // Regular file truncate
        let inode = inode_by_ino(fde.inode);
        if inode.is_null() || (*inode).readonly != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return false;
        }
        let old_size = (*inode).size;
        if !(*inode).rw_data.is_null() && length < (*inode).size {
            chain_truncate((*inode).rw_data, length);
        }
        (*inode).size = length;
        sync_shared_mmap_after_truncate(&fde, old_size, length);
        (*reply).label = TRONA_OK;
        false
    }
}
