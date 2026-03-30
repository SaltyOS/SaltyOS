use crate::types::*;
use crate::client::{find_client_by_badge, client_add_region, find_region_by_addr};
use trona::consts::*;
use trona::invoke;
use trona::ipc;
use trona::types::*;

/// MM_BRK: client sets program break via MemoryObject.
///   MR0 = new break address
///   Badge identifies the client.
///
/// On first growth, creates a heap MO (min 256 pages). Subsequent
/// growths commit and map additional pages from the same MO. If the MO
/// is exhausted, it is resized via `mo_resize`.
pub(crate) unsafe fn handle_mm_brk(msg: *const TronaMsg, badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let new_brk = (*msg).regs[0];
        if new_brk < (*client).heap_base {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let old_page = ((*client).heap_current + 4095) & !4095u64;
        let new_page = (new_brk + 4095) & !4095u64;
        let vspace_cap = (*client).vspace_cap;

        // Find or create heap region
        let mut heap_region = core::ptr::null_mut::<MmRegion>();
        {
            let count = (*client).region_count;
            let regions = (*client).regions;
            if !regions.is_null() {
                for ri in 0..count {
                    let r = regions.add(ri);
                    if (*r).active && (*r).region_type == REGION_HEAP {
                        heap_region = r;
                        break;
                    }
                }
            }
        }
        if heap_region.is_null() {
            heap_region = client_add_region(client);
            if heap_region.is_null() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
            (*heap_region).base = (*client).heap_base;
            (*heap_region).length = 0;
            (*heap_region).prot = (PROT_READ | PROT_WRITE) as u8;
            (*heap_region).region_type = REGION_HEAP;
            (*heap_region).active = true;
        }

        if new_page > old_page {
            let grow_pages = ((new_page - old_page) / 4096) as usize;

            if (*heap_region).mo_cap == 0 {
                // First growth: create heap MO (min 256 pages = 1MB)
                let initial = if grow_pages > 256 { grow_pages } else { 256 };
                let (mo_cap, _actual) = super::create_mo(initial);
                if mo_cap == 0 {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
                (*heap_region).mo_cap = mo_cap;
            }

            let mo_cap = (*heap_region).mo_cap;
            let region_base = (*heap_region).base;
            let total_pages_after = ((new_page - region_base) / 4096) as usize;
            let existing_pages = ((old_page - region_base) / 4096) as usize;

            // Check if MO needs resizing
            let (_, mo_size) = invoke::mo_get_size(mo_cap);
            let mo_pages = mo_size as usize;
            if total_pages_after > mo_pages {
                let new_mo_pages = if total_pages_after > mo_pages * 2 {
                    total_pages_after
                } else {
                    mo_pages * 2
                };
                let err = invoke::mo_resize(mo_cap, new_mo_pages as u64);
                if err != 0 {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            }

            // Commit new pages
            let (err, committed) = super::commit_mo_pages(mo_cap, existing_pages as u64, grow_pages as u64);
            if err != 0 || committed != grow_pages as u64 {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }

            // Map new pages into client VSpace
            let cf = ((grow_pages as u64) << 32)
                | VSPACE_FLAG_WRITABLE
                | VSPACE_FLAG_USER;
            let err = invoke::vspace_map_mo(
                vspace_cap, mo_cap, old_page, existing_pages as u64, cf,
            );
            if err != 0 {
                (*reply).label = TRONA_BAD_ADDRESS;
                return;
            }

            (*heap_region).length = new_page - region_base;
        } else if new_page < old_page {
            // Shrink: unmap freed pages
            let shrink_pages = ((old_page - new_page) / 4096) as usize;
            for i in 0..shrink_pages {
                invoke::vspace_unmap(vspace_cap, new_page + i as u64 * 4096);
            }
            // Decommit freed pages from MO
            if (*heap_region).mo_cap != 0 {
                let region_base = (*heap_region).base;
                let new_mo_offset = ((new_page - region_base) / 4096) as u64;
                let _ = invoke::mo_decommit(
                    (*heap_region).mo_cap,
                    new_mo_offset,
                    shrink_pages as u64,
                );
            }
            (*heap_region).length = new_page - (*heap_region).base;
        }

        (*client).heap_current = new_brk;
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_brk;
    }
}

/// MM_SBRK: client increments break.
///   MR0 = increment (signed as u64)
///   Badge identifies the client.
///   Reply: MR0 = old break address
pub(crate) unsafe fn handle_mm_sbrk(msg: *const TronaMsg, badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let increment = (*msg).regs[0] as i64;
        let old_break = (*client).heap_current;

        if increment == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = old_break;
            return;
        }

        let new_break = if increment > 0 {
            old_break + increment as u64
        } else {
            let dec = (-increment) as u64;
            if dec > old_break - (*client).heap_base {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            old_break - dec
        };

        // Delegate to brk handler
        let mut brk_msg = TronaMsg::zeroed();
        brk_msg.regs[0] = new_break;
        handle_mm_brk(&raw const brk_msg, badge, reply);

        // On success, return old break in MR0
        if (*reply).label == TRONA_OK {
            (*reply).regs[0] = old_break;
        }
    }
}

/// MM_MMAP: client requests anonymous mmap via MemoryObject.
///   MR0 = addr hint (0=auto)
///   MR1 = length
///   MR2 = prot
///   MR3 = flags
///   Badge identifies the client.
///   Reply: MR0 = mapped base address
///
/// Creates a MemoryObject for the mapping. Eager mappings commit and map
/// all pages immediately. Lazy mappings defer commitment to VMFault time
/// (mo_commit + vspace_map_mo per faulting page).
pub(crate) unsafe fn handle_mm_mmap(msg: *const TronaMsg, badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let _addr_hint = (*msg).regs[0];
        let length = (*msg).regs[1];
        let _prot = (*msg).regs[2] as i32;
        let _flags = (*msg).regs[3] as i32;

        if length == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let num_pages = (len / 4096) as usize;
        let vspace_cap = (*client).vspace_cap;
        let base = (*client).mmap_next;

        // Map flags
        let mut map_flags = VSPACE_FLAG_USER;
        if _prot & PROT_WRITE != 0 {
            map_flags |= VSPACE_FLAG_WRITABLE;
        }
        if _prot & PROT_EXEC != 0 {
            map_flags |= VSPACE_FLAG_EXECUTABLE;
        }

        // Create MO for this mapping
        let (mo_cap, _mo_pages) = super::create_mo(num_pages);
        if mo_cap == 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Create region to track mapping
        let region = client_add_region(client);
        if region.is_null() {
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }
        (*region).base = base;
        (*region).length = len;
        (*region).prot = _prot as u8;
        (*region).region_type = REGION_MMAP;
        (*region).active = true;
        (*region).mo_cap = mo_cap;

        // Check for MAP_LAZY flag
        let is_lazy = (_flags & MAP_LAZY) != 0;
        (*region).lazy = is_lazy;

        if is_lazy {
            // Lazy: MO created but pages NOT committed.
            // On VMFault, mo_commit + vspace_map_mo per page.
            (*client).mmap_next = base + len;
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = base;
            return;
        }

        // Eager: commit all pages and map into client VSpace
        let (err, committed) = super::commit_mo_pages(mo_cap, 0, num_pages as u64);
        if err != 0 || committed != num_pages as u64 {
            (*region).active = false;
            (*region).mo_cap = 0;
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let count_and_flags = ((num_pages as u64) << 32) | map_flags;
        let err = invoke::vspace_map_mo(vspace_cap, mo_cap, base, 0, count_and_flags);
        if err != 0 {
            (*region).active = false;
            (*region).mo_cap = 0;
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_BAD_ADDRESS;
            return;
        }

        (*client).mmap_next = base + len;

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = base;
    }
}

pub(crate) unsafe fn pagein_backing_page(region: *const MmRegion, fault_page_addr: u64) -> i32 {
    unsafe {
        if region.is_null() || (*region).mo_cap == 0 || (*region).backing_kind == MMAP_BACKING_NONE as u8 {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] backing pagein: invalid region region=");
                _lb.hex(region as u64);
                _lb.str(b" mo=");
                _lb.hex(if region.is_null() { 0 } else { (*region).mo_cap });
                _lb.str(b" kind=");
                _lb.hex(if region.is_null() { 0 } else { (*region).backing_kind as u64 });
                _lb.str(b"\n");
            });
            return TRONA_INVALID_ARGUMENT as i32;
        }

        let region_page = (fault_page_addr - (*region).base) / 4096;
        let file_offset = (*region).backing_file_offset + region_page * 4096;
        let file_size = (*region).backing_file_size;
        let bytes = if file_offset >= file_size {
            0
        } else {
            core::cmp::min(4096u64, file_size - file_offset)
        };

        let vfs_ep = super::resolve_vfs_ep();
        if vfs_ep == 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] backing pagein: no vfs endpoint\n");
            });
            return TRONA_NOT_FOUND as i32;
        }

        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, (*region).mo_cap);

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = POSIX_VFS_MMAP_PAGEIN;
        msg.length = 6;
        msg.regs[0] = (*region).backing_kind as u64;
        msg.regs[1] = (*region).backing_id0;
        msg.regs[2] = (*region).backing_id1;
        msg.regs[3] = file_offset;
        msg.regs[4] = (*region).mo_offset as u64 + region_page;
        msg.regs[5] = bytes;

        let err = ipc::call_ctx(super::ipc_ctx(), vfs_ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] backing pagein rpc failed kind=");
                _lb.hex((*region).backing_kind as u64);
                _lb.str(b" id0=");
                _lb.hex((*region).backing_id0);
                _lb.str(b" id1=");
                _lb.hex((*region).backing_id1);
                _lb.str(b" file_off=");
                _lb.hex(file_offset);
                _lb.str(b" mo=");
                _lb.hex((*region).mo_cap);
                _lb.str(b" mo_page=");
                _lb.dec((*region).mo_offset as u64 + region_page);
                _lb.str(b" bytes=");
                _lb.dec(bytes);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b" reply=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return TRONA_INVALID_OPERATION as i32;
        }

        TRONA_OK as i32
    }
}

pub(crate) unsafe fn flush_writeback_region(region: *const MmRegion, start: u64, length: u64) {
    unsafe {
        if region.is_null()
            || (*region).mo_cap == 0
            || (*region).backing_kind == MMAP_BACKING_NONE as u8
            || (*region).backing_writeback == 0
            || length == 0
        {
            return;
        }

        let region_start = (*region).base;
        let region_end = region_start + (*region).length;
        let flush_start = start & !0xFFFu64;
        let flush_end = core::cmp::min((start + length + 4095) & !0xFFFu64, region_end);
        if flush_start >= flush_end {
            return;
        }

        let mut page_addr = flush_start;
        while page_addr < flush_end {
            let region_page = (page_addr - region_start) / 4096;
            let file_offset = (*region).backing_file_offset + region_page * 4096;
            if file_offset < (*region).backing_file_size {
                let bytes = core::cmp::min(4096u64, (*region).backing_file_size - file_offset);
                let vfs_ep = super::resolve_vfs_ep();
                if vfs_ep == 0 {
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[MMSRV] writeback skipped: no vfs endpoint\n");
                    });
                    page_addr += 4096;
                    continue;
                }

                ipc::set_send_cap_ctx(super::ipc_ctx(), 0, (*region).mo_cap);

                let mut msg = TronaMsg::zeroed();
                let mut reply = TronaMsg::zeroed();
                msg.label = POSIX_VFS_MMAP_WRITEBACK;
                msg.length = 6;
                msg.regs[0] = (*region).backing_kind as u64;
                msg.regs[1] = (*region).backing_id0;
                msg.regs[2] = (*region).backing_id1;
                msg.regs[3] = file_offset;
                msg.regs[4] = (*region).mo_offset as u64 + region_page;
                msg.regs[5] = bytes;

                let err = ipc::call_ctx(super::ipc_ctx(), vfs_ep, &raw const msg, &raw mut reply);
                if err != 0 || reply.label != TRONA_OK {
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[MMSRV] writeback failed addr=");
                        _lb.hex(page_addr);
                        _lb.str(b" backing=");
                        _lb.hex((*region).backing_kind as u64);
                        _lb.str(b"\n");
                    });
                }
            }
            page_addr += 4096;
        }
    }
}

/// MM_MUNMAP: client unmaps a region.
///   MR0 = base address
///   MR1 = length
///   Badge identifies the client.
pub(crate) unsafe fn handle_mm_munmap(msg: *const TronaMsg, badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let base = (*msg).regs[0];
        let length = (*msg).regs[1];
        let vspace_cap = (*client).vspace_cap;

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let num_pages = (len / 4096) as usize;

        // Look up region
        let region = find_region_by_addr(client, base);
        if !region.is_null() && (*region).active {
            flush_writeback_region(region, base, len);

            // Unmap pages
            for i in 0..num_pages {
                invoke::vspace_unmap(vspace_cap, base + i as u64 * 4096);
            }
            // If entire region unmapped, mark inactive and clean up MO cap
            if base == (*region).base && len >= (*region).length {
                if (*region).mo_cap != 0 {
                    super::recycled_cnode_delete((*region).mo_cap);
                    (*region).mo_cap = 0;
                }
                (*region).active = false;
            }
        } else {
            // No region tracking — just unmap
            for i in 0..num_pages {
                invoke::vspace_unmap(vspace_cap, base + i as u64 * 4096);
            }
        }

        (*reply).label = TRONA_OK;
    }
}

/// MM_MPROTECT: client changes protection on a mapped region.
///   MR0 = base address
///   MR1 = length
///   MR2 = prot (PROT_READ/WRITE/EXEC)
///   Badge identifies the client.
///
/// Uses vspace_mprotect to change page table flags in-place.
pub(crate) unsafe fn handle_mm_mprotect(msg: *const TronaMsg, badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let addr = (*msg).regs[0];
        let length = (*msg).regs[1];
        let prot = (*msg).regs[2] as u8;

        let region = find_region_by_addr(client, addr);
        if region.is_null() || !(*region).active {
            (*reply).label = TRONA_OK;
            return;
        }

        let mut flags = VSPACE_FLAG_USER;
        if prot & PROT_WRITE as u8 != 0 {
            flags |= VSPACE_FLAG_WRITABLE;
        } else if prot & PROT_EXEC as u8 != 0 {
            flags |= VSPACE_FLAG_EXECUTABLE;
        }

        let vspace_cap = (*client).vspace_cap;
        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let page_count = (len / 4096) as usize;
        let mprotect_end = addr + len;

        // Update page table flags
        for i in 0..page_count {
            let page_va = addr + i as u64 * 4096;
            if page_va >= (*region).base + (*region).length {
                break;
            }
            invoke::vspace_unmap(vspace_cap, page_va);
        }

        let r_base = (*region).base;
        let r_end = r_base + (*region).length;
        let r_mo_cap = (*region).mo_cap;
        let r_mo_offset = (*region).mo_offset;
        let r_type = (*region).region_type;
        let r_prot = (*region).prot;
        let r_lazy = (*region).lazy;
        let r_backing_kind = (*region).backing_kind;
        let r_backing_writeback = (*region).backing_writeback;
        let r_backing_id0 = (*region).backing_id0;
        let r_backing_id1 = (*region).backing_id1;
        let r_backing_file_offset = (*region).backing_file_offset;
        let r_backing_file_size = (*region).backing_file_size;

        // Split region if mprotect covers only part of it
        if addr == r_base && mprotect_end >= r_end {
            // Exact match or covers entire region — just update prot
            (*region).prot = prot;
        } else if addr == r_base {
            // mprotect covers the start — shrink original, create new region for start
            let mprotect_pages = page_count as u64;
            let remaining_offset = r_mo_offset as u64 + mprotect_pages;

            // Original region becomes the unchanged tail
            (*region).base = mprotect_end;
            (*region).length = r_end - mprotect_end;
            (*region).mo_offset = remaining_offset as u32;

            // New region for the mprotected range
            let new_r = client_add_region(client);
            if !new_r.is_null() {
                (*new_r).base = addr;
                (*new_r).length = len;
                (*new_r).prot = prot;
                (*new_r).region_type = r_type;
                (*new_r).active = true;
                (*new_r).lazy = r_lazy;
                (*new_r).mo_cap = r_mo_cap;
                (*new_r).mo_offset = r_mo_offset;
                (*new_r).backing_kind = r_backing_kind;
                (*new_r).backing_writeback = r_backing_writeback;
                (*new_r).backing_id0 = r_backing_id0;
                (*new_r).backing_id1 = r_backing_id1;
                (*new_r).backing_file_offset = r_backing_file_offset;
                (*new_r).backing_file_size = r_backing_file_size;
            }
        } else if mprotect_end >= r_end {
            // mprotect covers the end — shrink original, create new region for end
            let prefix_len = addr - r_base;
            (*region).length = prefix_len;

            let new_r = client_add_region(client);
            if !new_r.is_null() {
                (*new_r).base = addr;
                (*new_r).length = r_end - addr;
                (*new_r).prot = prot;
                (*new_r).region_type = r_type;
                (*new_r).active = true;
                (*new_r).lazy = r_lazy;
                (*new_r).mo_cap = r_mo_cap;
                (*new_r).mo_offset = r_mo_offset + (prefix_len / 4096) as u32;
                (*new_r).backing_kind = r_backing_kind;
                (*new_r).backing_writeback = r_backing_writeback;
                (*new_r).backing_id0 = r_backing_id0;
                (*new_r).backing_id1 = r_backing_id1;
                (*new_r).backing_file_offset = r_backing_file_offset + prefix_len;
                (*new_r).backing_file_size = r_backing_file_size;
            }
        } else {
            // mprotect in the middle — split into 3: prefix + mprotect + suffix
            let prefix_len = addr - r_base;
            let suffix_base = mprotect_end;
            let suffix_len = r_end - suffix_base;

            // Original becomes prefix
            (*region).length = prefix_len;

            // Middle: mprotected range
            let mid = client_add_region(client);
            if !mid.is_null() {
                (*mid).base = addr;
                (*mid).length = len;
                (*mid).prot = prot;
                (*mid).region_type = r_type;
                (*mid).active = true;
                (*mid).lazy = r_lazy;
                (*mid).mo_cap = r_mo_cap;
                (*mid).mo_offset = r_mo_offset + (prefix_len / 4096) as u32;
                (*mid).backing_kind = r_backing_kind;
                (*mid).backing_writeback = r_backing_writeback;
                (*mid).backing_id0 = r_backing_id0;
                (*mid).backing_id1 = r_backing_id1;
                (*mid).backing_file_offset = r_backing_file_offset + prefix_len;
                (*mid).backing_file_size = r_backing_file_size;
            }

            // Suffix: unchanged tail
            let suf = client_add_region(client);
            if !suf.is_null() {
                (*suf).base = suffix_base;
                (*suf).length = suffix_len;
                (*suf).prot = r_prot;
                (*suf).region_type = r_type;
                (*suf).active = true;
                (*suf).lazy = r_lazy;
                (*suf).mo_cap = r_mo_cap;
                (*suf).mo_offset = r_mo_offset + ((addr - r_base + len) / 4096) as u32;
                (*suf).backing_kind = r_backing_kind;
                (*suf).backing_writeback = r_backing_writeback;
                (*suf).backing_id0 = r_backing_id0;
                (*suf).backing_id1 = r_backing_id1;
                (*suf).backing_file_offset = r_backing_file_offset + (addr - r_base + len);
                (*suf).backing_file_size = r_backing_file_size;
            }
        }

        (*reply).label = TRONA_OK;
    }
}

/// MM_MAP_WINDOW: procmgr creates dual-mapped write window via MO.
///   MR0 = target client badge
///   MR1 = target start vaddr
///   MR2 = window vaddr in caller's VSpace
///   MR3 = num_pages
///   MR4 = vspace flags for target mapping
///   + cap transfer: caller's VSpace cap
///   Reply: MR0 = pages_mapped
///
/// If `target_vaddr` is already in an MO-backed region (e.g. from a
/// prior MM_MAP_BATCH), the existing MO is reused for the scratch
/// mapping. Otherwise, a new MO-backed region is created (used for
/// ELF segment loading).
pub(crate) unsafe fn handle_mm_map_window(msg: *const TronaMsg, _caller_badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let target_vaddr = (*msg).regs[1];
        let window_vaddr = (*msg).regs[2];
        let num_pages = (*msg).regs[3] as usize;
        let target_flags = (*msg).regs[4];

        let caller_vspace_cap = *(&raw const super::CURRENT_RECV_SLOT);

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let target_vspace_cap = (*client).vspace_cap;
        let page_addr = target_vaddr & !0xFFFu64;

        // Try to find an existing MO-backed region (from MAP_BATCH)
        let existing_region = find_region_by_addr(client, page_addr);
        let (mo_cap, mo_page_offset, created_region) =
            if !existing_region.is_null() && (*existing_region).mo_cap != 0 {
                // Reuse existing MO
                let off = (page_addr - (*existing_region).base) / 4096;
                ((*existing_region).mo_cap, off, false)
            } else {
                // No existing region — create new MO-backed region (ELF load path)
                let (mo, _actual) = super::create_mo(num_pages);
                if mo == 0 {
                    invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
                // Commit pages
                let (commit_err, committed) = super::commit_mo_pages(mo, 0, num_pages as u64);
                if commit_err != 0 || committed != num_pages as u64 {
                    super::recycled_cnode_delete(mo);
                    invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
                // Map into target VSpace
                let cf = ((num_pages as u64) << 32) | target_flags;
                if invoke::vspace_map_mo(target_vspace_cap, mo, page_addr, 0, cf) != 0 {
                    super::recycled_cnode_delete(mo);
                    invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                    (*reply).label = TRONA_BAD_ADDRESS;
                    return;
                }
                (mo, 0u64, true)
            };

        // Map MO pages into caller's VSpace (writable scratch window)
        let cf = ((num_pages as u64) << 32)
            | VSPACE_FLAG_WRITABLE
            | VSPACE_FLAG_USER;
        let err = invoke::vspace_map_mo(
            caller_vspace_cap, mo_cap, window_vaddr, mo_page_offset, cf,
        );

        if err != 0 {
            if created_region {
                invoke::vspace_unmap_mo(target_vspace_cap, page_addr, num_pages as u64);
                super::recycled_cnode_delete(mo_cap);
            }
            invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
            (*reply).label = TRONA_BAD_ADDRESS;
            return;
        }

        // Register new region if we created a new MO
        if created_region {
            let region = client_add_region(client);
            if !region.is_null() {
                (*region).base = page_addr;
                (*region).length = num_pages as u64 * 4096;
                (*region).prot = super::vspace_flags_to_prot(target_flags);
                (*region).region_type = REGION_SPAWN;
                (*region).active = true;
                (*region).mo_cap = mo_cap;
            }
        }

        invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = num_pages as u64;
    }
}

/// MM_UNMAP_WINDOW: procmgr removes write window from caller's VSpace.
///   MR0 = window vaddr in caller
///   MR1 = num_pages
///   + cap transfer: caller's VSpace cap
///   Reply: label = TRONA_OK
///
/// Frame caps stay in mmsrv's CSpace; target mapping persists after
/// window removal.
pub(crate) unsafe fn handle_mm_unmap_window(msg: *const TronaMsg, _caller_badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let window_vaddr = (*msg).regs[0];
        let num_pages = (*msg).regs[1] as usize;

        // The caller's VSpace cap was transferred into the current receive slot.
        let caller_vspace_cap = *(&raw const super::CURRENT_RECV_SLOT);

        for i in 0..num_pages {
            invoke::vspace_unmap(caller_vspace_cap, window_vaddr + i as u64 * 4096);
        }

        // Delete transient caller VSpace cap
        invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);

        (*reply).label = TRONA_OK;
    }
}

/// MM_FORK_REGIONS: procmgr clones parent's region state to child.
///   MR0 = parent client badge
///   MR1 = child client badge
///
/// Copies parent's heap_base, heap_current, and mmap_next to the child
/// client entry (which must already exist via MM_REGISTER).
///
/// MO-backed writable/private regions use MO clone for COW.
/// Shared library RO regions (`REGION_SHARED_RO`) must stay attached to the
/// original shared MO and be mapped read-only into the child; sending them
/// through the COW clone path risks mutating global shared-lib cache state.
pub(crate) unsafe fn handle_mm_fork_regions(msg: *const TronaMsg, _caller_badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let parent_badge = (*msg).regs[0];
        let child_badge = (*msg).regs[1];

        let parent = find_client_by_badge(parent_badge);
        if parent.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let child = find_client_by_badge(child_badge);
        if child.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Clone parent's memory layout
        (*child).heap_base = (*parent).heap_base;
        (*child).heap_current = (*parent).heap_current;
        (*child).mmap_next = (*parent).mmap_next;

        // Deep-copy parent's region list using MO clone for COW
        let parent_rc = (*parent).region_count;
        let parent_regions = (*parent).regions;
        if !parent_regions.is_null() && parent_rc > 0 {
            let child_region_cap = if parent_rc > REGION_INITIAL_CAP {
                parent_rc
            } else {
                REGION_INITIAL_CAP
            };
            let bytes = child_region_cap * core::mem::size_of::<MmRegion>();
            let pages = if bytes == 0 { 1 } else { (bytes + 4095) / 4096 };
            let ptr = super::self_mmap(pages);
            if !ptr.is_null() {
                let child_regions = ptr as *mut MmRegion;

                // Clone each region using MO clone with dedup.
                // Multiple regions may share the same MO (per-segment
                // shared lib mappings). We clone each unique MO once
                // and cnode_copy for subsequent regions.
                const DEDUP_MAX: usize = 16;
                let mut dedup: [(Cap, Cap); DEDUP_MAX] = [(0, 0); DEDUP_MAX];
                let mut dedup_count: usize = 0;
                let mut mo_clone_failed = false;

                for ri in 0..parent_rc {
                    let pr = parent_regions.add(ri);
                    let mut cr = MmRegion::zeroed();
                    cr.base = (*pr).base;
                    cr.length = (*pr).length;
                    cr.prot = (*pr).prot;
                    cr.region_type = (*pr).region_type;
                    cr.active = (*pr).active;
                    cr.lazy = (*pr).lazy;
                    cr.mo_offset = (*pr).mo_offset;
                    cr.backing_kind = (*pr).backing_kind;
                    cr.backing_writeback = (*pr).backing_writeback;
                    cr.backing_id0 = (*pr).backing_id0;
                    cr.backing_id1 = (*pr).backing_id1;
                    cr.backing_file_offset = (*pr).backing_file_offset;
                    cr.backing_file_size = (*pr).backing_file_size;

                    if cr.active && cr.length > 0 && (*pr).mo_cap != 0 {
                        let parent_mo = (*pr).mo_cap;

                        // Check dedup table: was this MO already cloned?
                        let mut found_child_mo: Cap = 0;
                        for di in 0..dedup_count {
                            if dedup[di].0 == parent_mo {
                                found_child_mo = dedup[di].1;
                                break;
                            }
                        }

                        if found_child_mo != 0 {
                            // Already cloned/copied for another region —
                            // cnode_copy to a new slot so region cleanup can
                            // drop references independently.
                            let copy_slot = match super::recycled_slot_alloc() {
                                Some(s) => s,
                                None => {
                                    mo_clone_failed = true;
                                    *child_regions.add(ri) = cr;
                                    continue;
                                }
                            };
                            let err = invoke::cnode_copy(
                                super::CAP_SELF_CSPACE,
                                found_child_mo,
                                super::CAP_SELF_CSPACE,
                                copy_slot,
                                trona::consts::CAP_RIGHTS_ALL,
                            );
                            if err != 0 {
                                super::recycle_empty_slot(copy_slot);
                                mo_clone_failed = true;
                                *child_regions.add(ri) = cr;
                                continue;
                            }
                            cr.mo_cap = copy_slot;
                        } else {
                            // First time seeing this MO.
                            let child_mo_slot = match super::recycled_slot_alloc() {
                                Some(s) => s,
                                None => {
                                    mo_clone_failed = true;
                                    *child_regions.add(ri) = cr;
                                    continue;
                                }
                            };
                            let err = if cr.region_type == crate::types::REGION_SHARED_RO
                                || cr.region_type == crate::types::REGION_FILE_SHARED {
                                invoke::cnode_copy(
                                    super::CAP_SELF_CSPACE,
                                    parent_mo,
                                    super::CAP_SELF_CSPACE,
                                    child_mo_slot,
                                    trona::consts::CAP_RIGHTS_ALL,
                                )
                            } else {
                                invoke::mo_clone(parent_mo, child_mo_slot, 0)
                            };
                            if err != 0 {
                                super::recycled_cnode_delete(child_mo_slot);
                                mo_clone_failed = true;
                                *child_regions.add(ri) = cr;
                                continue;
                            }
                            cr.mo_cap = child_mo_slot;

                            // Record in dedup table
                            if dedup_count < DEDUP_MAX {
                                dedup[dedup_count] = (parent_mo, child_mo_slot);
                                dedup_count += 1;
                            }
                        }
                    }

                    // Map the region into the child's VSpace.
                    // Shared RO regions reuse the original MO directly and
                    // must not enter the COW fork path.
                    if cr.mo_cap != 0 && cr.active && cr.length > 0 {
                        let child_vs = (*child).vspace_cap;
                        let page_count = cr.length / 4096;
                        if cr.region_type == crate::types::REGION_SHARED_RO
                            || cr.region_type == crate::types::REGION_FILE_SHARED {
                            let count_and_flags = (page_count << 32)
                                | super::prot_to_vspace_flags(cr.prot);
                            let _ = invoke::vspace_map_mo(
                                child_vs,
                                cr.mo_cap,
                                cr.base,
                                cr.mo_offset as u64,
                                count_and_flags,
                            );
                        } else {
                            let parent_vs = (*parent).vspace_cap;
                            let (_err, _forked) = invoke::vspace_fork_range(
                                parent_vs,
                                child_vs,
                                cr.mo_cap,
                                cr.base,
                                page_count,
                                cr.mo_offset as u64,
                            );
                        }
                    }

                    *child_regions.add(ri) = cr;
                }
                if mo_clone_failed {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[MMSRV] fork: mo_clone failed for some regions\n");
                    });
                }
                (*child).regions = child_regions;
                (*child).region_count = parent_rc;
                (*child).region_cap = child_region_cap;
            } else {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        // COW pool setup is a no-op with MO-based COW
        crate::pool::init_pool(child);
        crate::pool::init_pool(parent);

        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] fork-regions parent=");
            _lb.hex(parent_badge);
            _lb.str(b" child=");
            _lb.hex(child_badge);
            _lb.str(b" heap=");
            _lb.hex((*parent).heap_current);
            _lb.str(b" mmap=");
            _lb.hex((*parent).mmap_next);
            _lb.str(b"\n");
        });

        (*reply).label = TRONA_OK;
    }
}

/// MM_ALLOC_THREAD_OBJECTS: allocate TCB + SchedContext + IPC buffer Frame.
///
/// The client sends 3 destination CNode slots in MR0, MR1, MR2 where
/// the resulting caps should be placed. mmsrv retypes the objects into
/// temporary slots, then transfers them back via IPC cap transfer.
///
/// Reply: label = TRONA_OK with 3 caps transferred, or error.
pub(crate) unsafe fn handle_mm_alloc_thread_objects(
    _msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        // Allocate 3 temp slots for the new objects
        let tcb_slot = match super::recycled_slot_alloc() {
            Some(s) => s,
            None => { (*reply).label = TRONA_OUT_OF_MEMORY; return; }
        };
        let sc_slot = match super::recycled_slot_alloc() {
            Some(s) => s,
            None => { (*reply).label = TRONA_OUT_OF_MEMORY; return; }
        };
        let frame_slot = match super::recycled_slot_alloc() {
            Some(s) => s,
            None => { (*reply).label = TRONA_OUT_OF_MEMORY; return; }
        };

        // Retype: TCB (0 size_bits = default)
        let err = super::retype_any(OBJ_TCB, 0, tcb_slot);
        if err != 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Retype: SchedContext (0 size_bits = default)
        let err = super::retype_any(OBJ_SCHED_CONTEXT, 0, sc_slot);
        if err != 0 {
            // Clean up TCB
            super::recycled_cnode_delete(tcb_slot);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Retype: Frame (12 size_bits = 4K page for IPC buffer)
        let err = super::retype_any(OBJ_FRAME, 12, frame_slot);
        if err != 0 {
            super::recycled_cnode_delete(tcb_slot);
            super::recycled_cnode_delete(sc_slot);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Transfer 3 caps to the caller via IPC cap transfer
        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, tcb_slot);
        ipc::set_send_cap_ctx(super::ipc_ctx(), 1, sc_slot);
        ipc::set_send_cap_ctx(super::ipc_ctx(), 2, frame_slot);

        // Schedule cleanup of server-side temp slots after reply completes.
        // The reply_recv is atomic: the kernel transfers caps during reply,
        // then blocks for the next message. We clean up on the next iteration.
        *(&raw mut super::PENDING_CLEANUP_SLOTS) = [tcb_slot, sc_slot, frame_slot, 0];
        *(&raw mut super::PENDING_CLEANUP_COUNT) = 3;

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

/// MM_ALLOC_OBJECT: allocate a single kernel object of any type.
///
/// Request: MR0 = obj_type, MR1 = size_bits, length = 2
/// Reply: label = TRONA_OK with 1 cap transferred, or TRONA_OUT_OF_MEMORY.
pub(crate) unsafe fn handle_mm_alloc_object(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let obj_type = (*msg).regs[0];
        let size_bits = (*msg).regs[1];

        let slot = match super::recycled_slot_alloc() {
            Some(s) => s,
            None => { (*reply).label = TRONA_OUT_OF_MEMORY; return; }
        };

        let err = super::retype_any(obj_type, size_bits, slot);
        if err != 0 {
            super::recycle_empty_slot(slot);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, slot);

        *(&raw mut super::PENDING_CLEANUP_SLOTS) = [slot, 0, 0, 0];
        *(&raw mut super::PENDING_CLEANUP_COUNT) = 1;

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

/// MM_MAP_BATCH: procmgr batch-maps N pages for spawn via MemoryObject.
///   MR0 = target client badge
///   MR1 = start vaddr
///   MR2 = num_pages
///   MR3 = vspace flags
///   Reply: MR0 = pages_mapped
///
/// Creates a MemoryObject, commits all pages, and maps them into the
/// target VSpace. The MO cap is stored in the region so fork can use
/// `mo_clone` for COW semantics.
pub(crate) unsafe fn handle_mm_map_batch(msg: *const TronaMsg, _caller_badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let start_vaddr = (*msg).regs[1];
        let num_pages = (*msg).regs[2] as usize;
        let flags = (*msg).regs[3];

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let vspace_cap = (*client).vspace_cap;

        if num_pages == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        // Create MO with capacity >= num_pages
        let (mo_cap, _mo_pages) = super::create_mo(num_pages);
        if mo_cap == 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Commit all pages (kernel allocates physical frames)
        let (err, committed) = super::commit_mo_pages(mo_cap, 0, num_pages as u64);
        if err != 0 || committed != num_pages as u64 {
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Map committed pages into target VSpace
        let count_and_flags = ((num_pages as u64) << 32) | flags;
        let err = invoke::vspace_map_mo(
            vspace_cap, mo_cap, start_vaddr, 0, count_and_flags,
        );
        if err != 0 {
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_BAD_ADDRESS;
            return;
        }

        // Register region with MO cap for fork support
        let region = client_add_region(client);
        if region.is_null() {
            invoke::vspace_unmap_mo(vspace_cap, start_vaddr, num_pages as u64);
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }
        (*region).base = start_vaddr;
        (*region).length = num_pages as u64 * 4096;
        (*region).prot = super::vspace_flags_to_prot(flags);
        (*region).region_type = REGION_SPAWN;
        (*region).active = true;
        (*region).mo_cap = mo_cap;

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = num_pages as u64;
    }
}

/// MM_MAP_OBJECT_REGION: map a transferred MO into a client and register it.
///
///   MR0 = target client badge
///   MR1 = requested base (0 = auto-place)
///   MR2 = page count
///   MR3 = mo_offset
///   MR4 = VSpace flags
///   MR5 = region_type
///   MR6 = backing_kind
///   MR7 = backing_id0
///   MR8 = backing_id1
///   MR9 = backing_file_offset
///   MR10 = backing_file_size
///   MR11 = options bits
///   + cap transfer: MO cap
///   Reply: MR0 = mapped base
pub(crate) unsafe fn handle_mm_map_object_region(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let requested_base = (*msg).regs[1];
        let page_count = (*msg).regs[2] as usize;
        let mo_offset = (*msg).regs[3] as u32;
        let flags = (*msg).regs[4];
        let region_type = (*msg).regs[5] as u8;
        let backing_kind = if (*msg).length >= 7 { (*msg).regs[6] as u8 } else { 0 };
        let backing_id0 = if (*msg).length >= 8 { (*msg).regs[7] } else { 0 };
        let backing_id1 = if (*msg).length >= 9 { (*msg).regs[8] } else { 0 };
        let backing_file_offset = if (*msg).length >= 10 { (*msg).regs[9] } else { 0 };
        let backing_file_size = if (*msg).length >= 11 { (*msg).regs[10] } else { 0 };
        let options = if (*msg).length >= 12 { (*msg).regs[11] } else { 0 };
        let is_lazy = (options & MMAP_OBJECT_OPT_LAZY) != 0;
        let backing_writeback = if (options & MMAP_OBJECT_OPT_WRITEBACK) != 0 { 1 } else { 0 };

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        if page_count == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mo_cap = *(&raw const super::CURRENT_RECV_SLOT);
        if mo_cap == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let length = page_count as u64 * 4096;
        let base = if requested_base != 0 {
            requested_base
        } else {
            let auto_base = (*client).mmap_next;
            (*client).mmap_next = auto_base + length;
            auto_base
        };

        if !is_lazy {
            let count_and_flags = ((page_count as u64) << 32) | flags;
            let err = invoke::vspace_map_mo(
                (*client).vspace_cap,
                mo_cap,
                base,
                mo_offset as u64,
                count_and_flags,
            );
            if err != 0 {
                if requested_base == 0 {
                    (*client).mmap_next = base;
                }
                (*reply).label = TRONA_BAD_ADDRESS;
                return;
            }
        }

        let region = client_add_region(client);
        if region.is_null() {
            let _ = invoke::vspace_unmap_mo((*client).vspace_cap, base, page_count as u64);
            if requested_base == 0 {
                (*client).mmap_next = base;
            }
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        super::mark_recv_slot_kept();

        (*region).base = base;
        (*region).length = length;
        (*region).prot = super::vspace_flags_to_prot(flags);
        (*region).region_type = region_type;
        (*region).active = true;
        (*region).lazy = is_lazy;
        (*region).mo_cap = mo_cap;
        (*region).mo_offset = mo_offset;
        (*region).backing_kind = backing_kind;
        (*region).backing_writeback = backing_writeback;
        (*region).backing_id0 = backing_id0;
        (*region).backing_id1 = backing_id1;
        (*region).backing_file_offset = backing_file_offset;
        (*region).backing_file_size = backing_file_size;

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = base;
    }
}

/// MM_SYNC_FILE_BACKING: VFS updates backing size metadata for file-backed regions.
///
///   MR0 = backing_kind
///   MR1 = backing_id0
///   MR2 = backing_id1
///   MR3 = new_size
///   MR4 = sync_flags
pub(crate) unsafe fn handle_mm_sync_file_backing(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let backing_kind = (*msg).regs[0] as u8;
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let new_size = (*msg).regs[3];
        let sync_flags = (*msg).regs[4];
        let is_truncate = (sync_flags & MM_SYNC_BACKING_TRUNCATE) != 0;

        let ptr = *(&raw const super::CLIENTS_PTR);
        let cap = *(&raw const super::CLIENTS_CAP);
        let mut synced = 0u64;

        for i in 0..cap {
            let client = ptr.add(i);
            if !(*client).active || (*client).regions.is_null() {
                continue;
            }

            for ri in 0..(*client).region_count {
                let region = (*client).regions.add(ri);
                if !(*region).active
                    || (*region).backing_kind != backing_kind
                    || (*region).backing_id0 != backing_id0
                    || (*region).backing_id1 != backing_id1
                {
                    continue;
                }

                let old_size = (*region).backing_file_size;
                (*region).backing_file_size = new_size;
                synced += 1;

                if is_truncate && new_size < old_size {
                    let region_rel_eof = new_size.saturating_sub((*region).backing_file_offset);
                    let keep_bytes = core::cmp::min(region_rel_eof, (*region).length);
                    let first_drop_page = (keep_bytes + 4095) / 4096;
                    let total_pages = (*region).length / 4096;
                    for page in first_drop_page..total_pages {
                        let _ = invoke::vspace_unmap(
                            (*client).vspace_cap,
                            (*region).base + page * 4096,
                        );
                    }
                }
            }
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = synced;
    }
}

/// MM_REGISTER_SHARED_REGION: procmgr registers a shared library segment.
///
/// Called per-segment (not per-library). Multiple segments may share the
/// same MO cap at different mo_offsets. The MO cap is transferred only on
/// the first segment registration; subsequent segments for the same library
/// receive mo_cap=0 and must use cnode_copy from the first segment's region.
///
///   MR0 = target client badge
///   MR1 = base vaddr
///   MR2 = page count
///   MR3 = has_mo (1 if MO cap is transferred via extra cap)
///   MR4 = mo_offset (page offset within MO for this segment)
///   MR5 = VSpace flags for this segment
pub(crate) unsafe fn handle_mm_register_shared_region(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let base = (*msg).regs[1];
        let page_count = (*msg).regs[2] as usize;
        let has_mo = (*msg).regs[3] != 0;
        let mo_offset = (*msg).regs[4] as u32;
        let flags = (*msg).regs[5];

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        if page_count == 0 {
            (*reply).label = TRONA_OK;
            return;
        }

        // If MO cap was transferred, keep it in our receive slot.
        let mo_cap = if has_mo {
            let slot = *(&raw const super::CURRENT_RECV_SLOT);
            if slot != 0 {
                *(&raw mut super::RECV_SLOT_KEPT) = true;
                slot
            } else {
                0
            }
        } else {
            0
        };

        let region = client_add_region(client);
        if region.is_null() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*region).base = base;
        (*region).length = page_count as u64 * 4096;
        (*region).prot = super::vspace_flags_to_prot(flags);
        (*region).region_type = crate::types::REGION_SHARED_RO;
        (*region).active = true;
        (*region).mo_cap = mo_cap;
        (*region).mo_offset = mo_offset;

        (*reply).label = TRONA_OK;
    }
}
