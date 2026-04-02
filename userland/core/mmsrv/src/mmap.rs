use crate::types::*;
use crate::client::{client_add_region, client_reserve_regions, find_client_by_badge, find_region_by_addr};
use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;
use trona_posix::consts::*;

const INTERNAL_COPY_SRC_WINDOW_BASE: u64 = 0x1FFB_0000;
const INTERNAL_COPY_DST_WINDOW_BASE: u64 = 0x1FFD_0000;
const INTERNAL_COPY_CHUNK_PAGES: usize = 32;

#[inline]
fn checked_aligned_len(length: u64) -> Option<u64> {
    length.checked_add(4095).map(|v| v & !0xFFFu64)
}

#[inline]
fn checked_mapping_len(page_count: usize) -> Option<u64> {
    (page_count as u64).checked_mul(4096)
}

#[inline]
fn checked_page_count(len: u64) -> Option<usize> {
    usize::try_from(len / 4096).ok()
}

#[inline]
fn checked_range_end(base: u64, length: u64) -> Option<u64> {
    base.checked_add(length)
}

#[inline]
fn checked_mo_offset_add(base: u32, delta_bytes: u64) -> Option<u32> {
    let pages = u32::try_from(delta_bytes / 4096).ok()?;
    base.checked_add(pages)
}

unsafe fn unmap_self_window(base: u64, num_pages: usize) {
    unsafe {
        for i in 0..num_pages {
            invoke::vspace_unmap(super::CAP_SELF_VSPACE, base + i as u64 * 4096);
        }
    }
}

unsafe fn rollback_private_region(client: *mut MmClient, base: u64, page_count: usize) {
    unsafe {
        let Some(length) = checked_mapping_len(page_count) else {
            return;
        };
        let _ = remove_client_range(client, base, length, true, 1);
    }
}

unsafe fn copy_bootinfo_into_region(client: *mut MmClient, region_base: u64) -> u64 {
    unsafe {
        let region = find_region_by_addr(client, region_base);
        if region.is_null() || (*region).mo_cap == 0 {
            return TRONA_BAD_ADDRESS;
        }

        let count_and_flags = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let (err, mapped) = invoke::vspace_map_mo_with_count(
            super::CAP_SELF_VSPACE,
            (*region).mo_cap,
            INTERNAL_COPY_DST_WINDOW_BASE,
            0,
            count_and_flags,
        );
        if err != 0 || mapped != 1 {
            return TRONA_BAD_ADDRESS;
        }

        core::ptr::copy_nonoverlapping(
            trona::BOOTINFO_VADDR as *const u8,
            INTERNAL_COPY_DST_WINDOW_BASE as *mut u8,
            4096,
        );
        unmap_self_window(INTERNAL_COPY_DST_WINDOW_BASE, 1);
        TRONA_OK
    }
}

unsafe fn copy_initrd_into_region(
    client: *mut MmClient,
    region_base: u64,
    page_count: usize,
    copy_len: usize,
) -> u64 {
    unsafe {
        let Some(region_len) = checked_mapping_len(page_count) else {
            return TRONA_INVALID_ARGUMENT;
        };
        if copy_len > region_len as usize {
            return TRONA_INVALID_ARGUMENT;
        }

        let region = find_region_by_addr(client, region_base);
        if region.is_null() || (*region).mo_cap == 0 {
            return TRONA_BAD_ADDRESS;
        }

        let mut copied = 0usize;
        let mut page_off = 0usize;
        while page_off < page_count {
            let chunk_pages = core::cmp::min(INTERNAL_COPY_CHUNK_PAGES, page_count - page_off);
            let chunk_bytes = chunk_pages * 4096;
            let count_and_flags = ((chunk_pages as u64) << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
            let (dst_err, dst_mapped) = invoke::vspace_map_mo_with_count(
                super::CAP_SELF_VSPACE,
                (*region).mo_cap,
                INTERNAL_COPY_DST_WINDOW_BASE,
                page_off as u64,
                count_and_flags,
            );
            if dst_err != 0 || dst_mapped != chunk_pages as u64 {
                unmap_self_window(INTERNAL_COPY_DST_WINDOW_BASE, dst_mapped as usize);
                return TRONA_BAD_ADDRESS;
            }

            let dst = INTERNAL_COPY_DST_WINDOW_BASE as *mut u8;
            core::ptr::write_bytes(dst, 0, chunk_bytes);

            let remaining = copy_len.saturating_sub(copied);
            if remaining > 0 {
                let copy_bytes = core::cmp::min(remaining, chunk_bytes);
                let src_pages = (copy_bytes + 4095) / 4096;
                let (src_err, src_mapped) = invoke::vspace_map_device_range(
                    super::CAP_SELF_VSPACE,
                    super::CAP_INITRD_UNTYPED,
                    page_off as u64,
                    INTERNAL_COPY_SRC_WINDOW_BASE,
                    src_pages as u64,
                    VSPACE_FLAG_USER,
                );
                if src_err != 0 || src_mapped != src_pages as u64 {
                    unmap_self_window(INTERNAL_COPY_SRC_WINDOW_BASE, src_mapped as usize);
                    unmap_self_window(INTERNAL_COPY_DST_WINDOW_BASE, chunk_pages);
                    return TRONA_BAD_ADDRESS;
                }

                core::ptr::copy_nonoverlapping(
                    INTERNAL_COPY_SRC_WINDOW_BASE as *const u8,
                    dst,
                    copy_bytes,
                );
                copied += copy_bytes;
                unmap_self_window(INTERNAL_COPY_SRC_WINDOW_BASE, src_pages);
            }

            unmap_self_window(INTERNAL_COPY_DST_WINDOW_BASE, chunk_pages);
            page_off += chunk_pages;
        }

        TRONA_OK
    }
}

unsafe fn copy_between_client_regions(
    src_client: *mut MmClient,
    src_vaddr: u64,
    dst_client: *mut MmClient,
    dst_vaddr: u64,
    num_pages: usize,
) -> u64 {
    unsafe {
        if src_client.is_null()
            || dst_client.is_null()
            || num_pages == 0
            || (src_vaddr & 0xFFF) != 0
            || (dst_vaddr & 0xFFF) != 0
        {
            return TRONA_INVALID_ARGUMENT;
        }

        let Some(request_len) = checked_mapping_len(num_pages) else {
            return TRONA_INVALID_ARGUMENT;
        };

        let src_region = find_region_by_addr(src_client, src_vaddr);
        if src_region.is_null() || (*src_region).mo_cap == 0 {
            return TRONA_BAD_ADDRESS;
        }
        let Some(src_end) = checked_range_end(src_vaddr, request_len) else {
            return TRONA_INVALID_ARGUMENT;
        };
        let Some(src_region_end) = checked_range_end((*src_region).base, (*src_region).length) else {
            return TRONA_INVALID_ARGUMENT;
        };
        if src_end > src_region_end {
            return TRONA_BAD_ADDRESS;
        }

        let dst_region = find_region_by_addr(dst_client, dst_vaddr);
        if dst_region.is_null() || (*dst_region).mo_cap == 0 {
            return TRONA_BAD_ADDRESS;
        }
        let Some(dst_end) = checked_range_end(dst_vaddr, request_len) else {
            return TRONA_INVALID_ARGUMENT;
        };
        let Some(dst_region_end) = checked_range_end((*dst_region).base, (*dst_region).length) else {
            return TRONA_INVALID_ARGUMENT;
        };
        if dst_end > dst_region_end {
            return TRONA_BAD_ADDRESS;
        }

        let src_base_page = (src_vaddr - (*src_region).base) / 4096;
        let dst_base_page = (dst_vaddr - (*dst_region).base) / 4096;

        let mut page_off = 0usize;
        while page_off < num_pages {
            let chunk_pages = core::cmp::min(INTERNAL_COPY_CHUNK_PAGES, num_pages - page_off);
            let count_and_flags = ((chunk_pages as u64) << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;

            let (src_err, src_mapped) = invoke::vspace_map_mo_with_count(
                super::CAP_SELF_VSPACE,
                (*src_region).mo_cap,
                INTERNAL_COPY_SRC_WINDOW_BASE,
                (*src_region).mo_offset as u64 + src_base_page + page_off as u64,
                count_and_flags,
            );
            if src_err != 0 || src_mapped != chunk_pages as u64 {
                unmap_self_window(INTERNAL_COPY_SRC_WINDOW_BASE, src_mapped as usize);
                return TRONA_BAD_ADDRESS;
            }

            let (dst_err, dst_mapped) = invoke::vspace_map_mo_with_count(
                super::CAP_SELF_VSPACE,
                (*dst_region).mo_cap,
                INTERNAL_COPY_DST_WINDOW_BASE,
                (*dst_region).mo_offset as u64 + dst_base_page + page_off as u64,
                count_and_flags,
            );
            if dst_err != 0 || dst_mapped != chunk_pages as u64 {
                unmap_self_window(INTERNAL_COPY_DST_WINDOW_BASE, dst_mapped as usize);
                unmap_self_window(INTERNAL_COPY_SRC_WINDOW_BASE, chunk_pages);
                return TRONA_BAD_ADDRESS;
            }

            core::ptr::copy_nonoverlapping(
                INTERNAL_COPY_SRC_WINDOW_BASE as *const u8,
                INTERNAL_COPY_DST_WINDOW_BASE as *mut u8,
                chunk_pages * 4096,
            );

            unmap_self_window(INTERNAL_COPY_DST_WINDOW_BASE, chunk_pages);
            unmap_self_window(INTERNAL_COPY_SRC_WINDOW_BASE, chunk_pages);
            page_off += chunk_pages;
        }

        TRONA_OK
    }
}

#[inline]
unsafe fn init_region_fragment(
    region: *mut MmRegion,
    template: MmRegion,
    base: u64,
    length: u64,
    prot: u8,
    delta_bytes: u64,
) -> bool {
    unsafe {
        if region.is_null() {
            return false;
        }

        let mo_offset = match checked_mo_offset_add(template.mo_offset, delta_bytes) {
            Some(v) => v,
            None => return false,
        };
        let backing_file_offset = match template.backing_file_offset.checked_add(delta_bytes) {
            Some(v) => v,
            None => return false,
        };

        *region = template;
        (*region).base = base;
        (*region).length = length;
        (*region).prot = prot;
        (*region).active = true;
        (*region).mo_offset = mo_offset;
        (*region).backing_file_offset = backing_file_offset;
        true
    }
}

unsafe fn release_mo_cap_if_unused(client: *mut MmClient, mo_cap: Cap) {
    unsafe {
        if client.is_null() || mo_cap == 0 {
            return;
        }

        let count = (*client).region_count;
        let regions = (*client).regions;
        if regions.is_null() {
            super::recycled_cnode_delete(mo_cap);
            return;
        }

        for i in 0..count {
            let region = regions.add(i);
            if (*region).active && (*region).mo_cap == mo_cap {
                return;
            }
        }

        super::recycled_cnode_delete(mo_cap);
    }
}

pub(crate) unsafe fn retire_region(client: *mut MmClient, region: *mut MmRegion) {
    unsafe {
        if region.is_null() || !(*region).active {
            return;
        }

        let mo_cap = (*region).mo_cap;
        *region = MmRegion::zeroed();
        release_mo_cap_if_unused(client, mo_cap);
    }
}

unsafe fn count_split_regions_for_removal(client: *mut MmClient, start: u64, end: u64) -> Option<usize> {
    unsafe {
        let mut extra = 0usize;
        let count = (*client).region_count;
        let regions = (*client).regions;
        if regions.is_null() {
            return Some(0);
        }

        for i in 0..count {
            let region = regions.add(i);
            if !(*region).active || (*region).length == 0 {
                continue;
            }

            let r_base = (*region).base;
            let r_end = checked_range_end(r_base, (*region).length)?;
            if r_base >= end || r_end <= start {
                continue;
            }

            let overlap_start = core::cmp::max(r_base, start);
            let overlap_end = core::cmp::min(r_end, end);
            if overlap_start > r_base && overlap_end < r_end {
                extra = extra.checked_add(1)?;
            }
        }

        Some(extra)
    }
}

unsafe fn count_split_regions_for_mprotect(client: *mut MmClient, start: u64, end: u64) -> Option<(usize, bool)> {
    unsafe {
        let mut extra = 0usize;
        let mut found = false;
        let count = (*client).region_count;
        let regions = (*client).regions;
        if regions.is_null() {
            return Some((0, false));
        }

        for i in 0..count {
            let region = regions.add(i);
            if !(*region).active || (*region).length == 0 {
                continue;
            }

            let r_base = (*region).base;
            let r_end = checked_range_end(r_base, (*region).length)?;
            if r_base >= end || r_end <= start {
                continue;
            }

            found = true;
            let overlap_start = core::cmp::max(r_base, start);
            let overlap_end = core::cmp::min(r_end, end);
            if overlap_start == r_base && overlap_end == r_end {
                continue;
            }
            if overlap_start == r_base || overlap_end == r_end {
                extra = extra.checked_add(1)?;
            } else {
                extra = extra.checked_add(2)?;
            }
        }

        Some((extra, found))
    }
}

pub(crate) unsafe fn remove_client_range(
    client: *mut MmClient,
    start: u64,
    length: u64,
    flush_writeback: bool,
    reserve_additional: usize,
) -> u64 {
    unsafe {
        if client.is_null() || length == 0 || (start & 0xFFF) != 0 || (length & 0xFFF) != 0 {
            return TRONA_INVALID_ARGUMENT;
        }

        let end = match checked_range_end(start, length) {
            Some(v) => v,
            None => return TRONA_INVALID_ARGUMENT,
        };
        let extra = match count_split_regions_for_removal(client, start, end) {
            Some(v) => v,
            None => return TRONA_INVALID_ARGUMENT,
        };
        let reserve_total = match extra.checked_add(reserve_additional) {
            Some(v) => v,
            None => return TRONA_OUT_OF_MEMORY,
        };
        if !client_reserve_regions(client, reserve_total) {
            return TRONA_OUT_OF_MEMORY;
        }

        let orig_count = (*client).region_count;
        let regions = (*client).regions;
        for i in 0..orig_count {
            let region = regions.add(i);
            if !(*region).active || (*region).length == 0 {
                continue;
            }

            let r_base = (*region).base;
            let r_end = match checked_range_end(r_base, (*region).length) {
                Some(v) => v,
                None => return TRONA_INVALID_ARGUMENT,
            };
            if r_base >= end || r_end <= start {
                continue;
            }

            if flush_writeback {
                let overlap_start = core::cmp::max(r_base, start);
                let overlap_end = core::cmp::min(r_end, end);
                flush_writeback_region(region, overlap_start, overlap_end - overlap_start);
            }
        }

        let page_count = match checked_page_count(length) {
            Some(v) => v,
            None => return TRONA_INVALID_ARGUMENT,
        };
        for i in 0..page_count {
            invoke::vspace_unmap((*client).vspace_cap, start + i as u64 * 4096);
        }

        for i in 0..orig_count {
            let region = regions.add(i);
            if !(*region).active || (*region).length == 0 {
                continue;
            }

            let r_base = (*region).base;
            let r_end = match checked_range_end(r_base, (*region).length) {
                Some(v) => v,
                None => return TRONA_INVALID_ARGUMENT,
            };
            if r_base >= end || r_end <= start {
                continue;
            }

            let overlap_start = core::cmp::max(r_base, start);
            let overlap_end = core::cmp::min(r_end, end);

            if overlap_start == r_base && overlap_end == r_end {
                retire_region(client, region);
                continue;
            }

            if overlap_start == r_base {
                let removed_len = overlap_end - r_base;
                (*region).base = overlap_end;
                (*region).length = r_end - overlap_end;
                (*region).mo_offset = match checked_mo_offset_add((*region).mo_offset, removed_len) {
                    Some(v) => v,
                    None => return TRONA_INVALID_ARGUMENT,
                };
                (*region).backing_file_offset = match (*region).backing_file_offset.checked_add(removed_len) {
                    Some(v) => v,
                    None => return TRONA_INVALID_ARGUMENT,
                };
                continue;
            }

            if overlap_end == r_end {
                (*region).length = overlap_start - r_base;
                continue;
            }

            let suffix = client_add_region(client);
            if suffix.is_null() {
                return TRONA_OUT_OF_MEMORY;
            }
            *suffix = *region;
            (*suffix).base = overlap_end;
            (*suffix).length = r_end - overlap_end;
            (*suffix).mo_offset = match checked_mo_offset_add((*region).mo_offset, overlap_end - r_base) {
                Some(v) => v,
                None => return TRONA_INVALID_ARGUMENT,
            };
            (*suffix).backing_file_offset = match (*region).backing_file_offset.checked_add(overlap_end - r_base) {
                Some(v) => v,
                None => return TRONA_INVALID_ARGUMENT,
            };

            (*region).length = overlap_start - r_base;
        }

        TRONA_OK
    }
}

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
            let (err, mapped) = invoke::vspace_map_mo_with_count(
                vspace_cap, mo_cap, old_page, existing_pages as u64, cf,
            );
            if err != 0 || mapped != grow_pages as u64 {
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

        let addr_hint = (*msg).regs[0];
        let length = (*msg).regs[1];
        let prot = (*msg).regs[2] as i32;
        let flags = (*msg).regs[3] as i32;

        if length == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let len = match checked_aligned_len(length) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let num_pages = match checked_page_count(len) {
            Some(v) if v != 0 => v,
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let requested_base = if (flags & MAP_FIXED) != 0 {
            if (addr_hint & 0xFFF) != 0 {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            addr_hint
        } else {
            0
        };

        if !client_reserve_regions(client, 1) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Map flags
        let mut map_flags = VSPACE_FLAG_USER;
        if prot & PROT_WRITE != 0 {
            map_flags |= VSPACE_FLAG_WRITABLE;
        }
        if prot & PROT_EXEC != 0 {
            map_flags |= VSPACE_FLAG_EXECUTABLE;
        }

        // Create MO for this mapping
        let (mo_cap, _mo_pages) = super::create_mo(num_pages);
        if mo_cap == 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let base = if requested_base != 0 {
            let remove_err = remove_client_range(client, requested_base, len, true, 1);
            if remove_err != TRONA_OK {
                super::recycled_cnode_delete(mo_cap);
                (*reply).label = remove_err;
                return;
            }
            requested_base
        } else {
            (*client).mmap_next
        };
        let mapping_end = match checked_range_end(base, len) {
            Some(v) => v,
            None => {
                super::recycled_cnode_delete(mo_cap);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let vspace_cap = (*client).vspace_cap;

        // Create region to track mapping
        let region = client_add_region(client);
        if region.is_null() {
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }
        (*region).base = base;
        (*region).length = len;
        (*region).prot = prot as u8;
        (*region).region_type = REGION_MMAP;
        (*region).active = true;
        (*region).mo_cap = mo_cap;

        // Check for MAP_LAZY flag
        let is_lazy = (flags & MAP_LAZY) != 0;
        (*region).lazy = is_lazy;

        if is_lazy {
            // Lazy: MO created but pages NOT committed.
            // On VMFault, mo_commit + vspace_map_mo per page.
            if mapping_end > (*client).mmap_next {
                (*client).mmap_next = mapping_end;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = base;
            return;
        }

        // Eager: commit all pages and map into client VSpace
        let (err, committed) = super::commit_mo_pages(mo_cap, 0, num_pages as u64);
        if err != 0 || committed != num_pages as u64 {
            *region = MmRegion::zeroed();
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let count_and_flags = ((num_pages as u64) << 32) | map_flags;
        let (err, mapped) = invoke::vspace_map_mo_with_count(vspace_cap, mo_cap, base, 0, count_and_flags);
        if err != 0 || mapped != num_pages as u64 {
            *region = MmRegion::zeroed();
            super::recycled_cnode_delete(mo_cap);
            (*reply).label = TRONA_BAD_ADDRESS;
            return;
        }

        if mapping_end > (*client).mmap_next {
            (*client).mmap_next = mapping_end;
        }

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

        // Prefer the dedicated pager callback EP (breaks VFS↔MMSRV cycle).
        // Falls back to the VFS service EP if the callback EP is not registered.
        let pager_ep = unsafe { *(&raw const super::VFS_PAGER_CALLBACK_EP) };
        let vfs_ep = if pager_ep != 0 {
            pager_ep
        } else {
            super::resolve_vfs_ep()
        };
        if vfs_ep == 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] backing pagein: no vfs endpoint\n");
            });
            return TRONA_NOT_FOUND as i32;
        }

        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, (*region).mo_cap);

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        // Use MM_PAGER_REQUEST when going through callback EP, VFS_PAGER_READ otherwise
        msg.label = if pager_ep != 0 { MM_PAGER_REQUEST } else { VFS_PAGER_READ };
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
                let pager_ep = unsafe { *(&raw const super::VFS_PAGER_CALLBACK_EP) };
                let vfs_ep = if pager_ep != 0 { pager_ep } else { super::resolve_vfs_ep() };
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
                msg.label = if pager_ep != 0 { MM_PAGER_WRITE_REQUEST } else { VFS_PAGER_WRITE };
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
        let len = match checked_aligned_len(length) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let err = remove_client_range(client, base, len, true, 0);
        if err != TRONA_OK {
            (*reply).label = err;
            return;
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
/// Updates present/demand PTE protections in place and then updates region
/// metadata for every overlapping fragment in the range.
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

        let mut flags = VSPACE_FLAG_USER;
        if prot & PROT_WRITE as u8 != 0 {
            flags |= VSPACE_FLAG_WRITABLE;
        }
        if prot & PROT_EXEC as u8 != 0 {
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
        let mprotect_end = match checked_range_end(addr, len) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let (extra_regions, found_region) = match count_split_regions_for_mprotect(client, addr, mprotect_end) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if !found_region {
            (*reply).label = TRONA_OK;
            return;
        }
        if extra_regions != 0 && !client_reserve_regions(client, extra_regions) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Keep existing mappings resident and only change their permissions.
        // This avoids late executable faults on already-populated MO-backed
        // images while still updating demand PTEs when the page is not present.
        let (protect_err, _) = invoke::vspace_protect_range(vspace_cap, addr, page_count as u64, flags);
        if protect_err != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let orig_count = (*client).region_count;
        let regions = (*client).regions;
        for i in 0..orig_count {
            let region = regions.add(i);
            if !(*region).active || (*region).length == 0 {
                continue;
            }

            let template = *region;
            let r_base = template.base;
            let r_end = match checked_range_end(r_base, template.length) {
                Some(v) => v,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            };
            if r_base >= mprotect_end || r_end <= addr {
                continue;
            }

            let overlap_start = core::cmp::max(r_base, addr);
            let overlap_end = core::cmp::min(r_end, mprotect_end);

            if overlap_start == r_base && overlap_end == r_end {
                (*region).prot = prot;
                continue;
            }

            if overlap_start == r_base {
                if !init_region_fragment(region, template, r_base, overlap_end - r_base, prot, 0) {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }

                let suffix = client_add_region(client);
                if suffix.is_null() || !init_region_fragment(
                    suffix,
                    template,
                    overlap_end,
                    r_end - overlap_end,
                    template.prot,
                    overlap_end - r_base,
                ) {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
                continue;
            }

            if overlap_end == r_end {
                if !init_region_fragment(region, template, r_base, overlap_start - r_base, template.prot, 0) {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }

                let tail = client_add_region(client);
                if tail.is_null() || !init_region_fragment(
                    tail,
                    template,
                    overlap_start,
                    r_end - overlap_start,
                    prot,
                    overlap_start - r_base,
                ) {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
                continue;
            }

            if !init_region_fragment(region, template, r_base, overlap_start - r_base, template.prot, 0) {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }

            let mid = client_add_region(client);
            if mid.is_null() || !init_region_fragment(
                mid,
                template,
                overlap_start,
                overlap_end - overlap_start,
                prot,
                overlap_start - r_base,
            ) {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }

            let suffix = client_add_region(client);
            if suffix.is_null() || !init_region_fragment(
                suffix,
                template,
                overlap_end,
                r_end - overlap_end,
                template.prot,
                overlap_end - r_base,
            ) {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        (*reply).label = TRONA_OK;
    }
}

/// MM_MAP_WINDOW: procmgr creates a dual-mapped write window via MO.
///   MR0 = target client badge
///   MR1 = target window vaddr
///   MR2 = window vaddr in caller's VSpace
///   MR3 = scratch window page count
///   MR4 = target region flags (ignored once the region already exists)
///   + cap transfer: caller's VSpace cap
///   Reply: MR0 = pages_mapped in scratch window
///
/// The target-side region must already exist. Region materialization is handled
/// separately by MM_ALLOC_PRIVATE_REGION or MM_MAP_BATCH.
unsafe fn map_existing_region_window(
    client: *mut MmClient,
    caller_vspace_cap: Cap,
    target_vaddr: u64,
    window_vaddr: u64,
    num_pages: usize,
) -> Result<u64, u64> {
    unsafe {
        if client.is_null() || num_pages == 0 {
            return Err(TRONA_INVALID_ARGUMENT);
        }

        let page_addr = target_vaddr & !0xFFFu64;
        let request_len = match checked_mapping_len(num_pages) {
            Some(v) => v,
            None => return Err(TRONA_INVALID_ARGUMENT),
        };
        let request_end = match checked_range_end(page_addr, request_len) {
            Some(v) => v,
            None => return Err(TRONA_INVALID_ARGUMENT),
        };

        let existing_region = find_region_by_addr(client, page_addr);
        if existing_region.is_null() || (*existing_region).mo_cap == 0 {
            return Err(TRONA_BAD_ADDRESS);
        }

        let existing_end = match checked_range_end((*existing_region).base, (*existing_region).length) {
            Some(v) => v,
            None => return Err(TRONA_INVALID_ARGUMENT),
        };
        if request_end > existing_end {
            return Err(TRONA_BAD_ADDRESS);
        }

        let mo_cap = (*existing_region).mo_cap;
        let mo_page_offset = (page_addr - (*existing_region).base) / 4096;
        let count_and_flags = ((num_pages as u64) << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let (err, mapped) = invoke::vspace_map_mo_with_count(
            caller_vspace_cap,
            mo_cap,
            window_vaddr,
            mo_page_offset,
            count_and_flags,
        );
        if err != 0 || mapped != num_pages as u64 {
            return Err(TRONA_BAD_ADDRESS);
        }

        Ok(mapped)
    }
}

pub(crate) unsafe fn handle_mm_map_window(msg: *const TronaMsg, _caller_badge: u64, reply: *mut TronaMsg) {
    unsafe {
        if (*msg).length != 5 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let target_badge = (*msg).regs[0];
        let target_vaddr = (*msg).regs[1];
        let window_vaddr = (*msg).regs[2];
        let num_pages = (*msg).regs[3] as usize;
        let _target_flags = (*msg).regs[4];
        let caller_vspace_cap = *(&raw const super::CURRENT_RECV_SLOT);

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        if num_pages == 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let target_vspace_cap = (*client).vspace_cap;
        let mapped = match map_existing_region_window(client, caller_vspace_cap, target_vaddr, window_vaddr, num_pages) {
            Ok(v) => v,
            Err(err) => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = err;
                return;
            }
        };

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

                let mut child_rc = 0usize;

                for ri in 0..parent_rc {
                    let pr = parent_regions.add(ri);

                    // The IPC buffer is remapped explicitly by procmgr after
                    // MM_FORK_REGIONS completes. Cloning it here turns fork into
                    // a clone-then-remap race on the same VA.
                    if (*pr).active
                        && (*pr).region_type == crate::types::REGION_IPC
                    {
                        continue;
                    }

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
                                    *child_regions.add(child_rc) = cr;
                                    child_rc += 1;
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
                                *child_regions.add(child_rc) = cr;
                                child_rc += 1;
                                continue;
                            }
                            cr.mo_cap = copy_slot;
                        } else {
                            // First time seeing this MO.
                            let child_mo_slot = match super::recycled_slot_alloc() {
                                Some(s) => s,
                                None => {
                                    mo_clone_failed = true;
                                    *child_regions.add(child_rc) = cr;
                                    child_rc += 1;
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
                                *child_regions.add(child_rc) = cr;
                                child_rc += 1;
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

                    *child_regions.add(child_rc) = cr;
                    child_rc += 1;
                }
                if mo_clone_failed {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[MMSRV] fork: mo_clone failed for some regions\n");
                    });
                }
                (*child).regions = child_regions;
                (*child).region_count = child_rc;
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

unsafe fn alloc_private_region(
    client: *mut MmClient,
    requested_base: u64,
    page_count: usize,
    flags: u64,
) -> Result<u64, u64> {
    unsafe {
        if client.is_null() || page_count == 0 {
            return Err(TRONA_INVALID_ARGUMENT);
        }
        if requested_base != 0 && (requested_base & 0xFFF) != 0 {
            return Err(TRONA_INVALID_ARGUMENT);
        }

        let length = match checked_mapping_len(page_count) {
            Some(v) => v,
            None => return Err(TRONA_INVALID_ARGUMENT),
        };
        let base = if requested_base != 0 {
            requested_base
        } else {
            (*client).mmap_next
        };

        let remove_err = remove_client_range(client, base, length, true, 1);
        if remove_err != TRONA_OK {
            return Err(remove_err);
        }

        let (mo_cap, _mo_pages) = super::create_mo(page_count);
        if mo_cap == 0 {
            return Err(TRONA_OUT_OF_MEMORY);
        }

        let (commit_err, committed) = super::commit_mo_pages(mo_cap, 0, page_count as u64);
        if commit_err != 0 || committed != page_count as u64 {
            super::recycled_cnode_delete(mo_cap);
            return Err(TRONA_OUT_OF_MEMORY);
        }

        let count_and_flags = ((page_count as u64) << 32) | flags;
        let (map_err, mapped) = invoke::vspace_map_mo_with_count(
            (*client).vspace_cap,
            mo_cap,
            base,
            0,
            count_and_flags,
        );
        if map_err != 0 || mapped != page_count as u64 {
            super::recycled_cnode_delete(mo_cap);
            return Err(TRONA_BAD_ADDRESS);
        }

        let region = client_add_region(client);
        if region.is_null() {
            invoke::vspace_unmap_mo((*client).vspace_cap, base, page_count as u64);
            super::recycled_cnode_delete(mo_cap);
            return Err(TRONA_OUT_OF_MEMORY);
        }

        (*region).base = base;
        (*region).length = length;
        (*region).prot = super::vspace_flags_to_prot(flags);
        (*region).region_type = if base == trona::layout::IPC_BUF_BASE && page_count == 1 {
            REGION_IPC
        } else {
            REGION_SPAWN
        };
        (*region).active = true;
        (*region).mo_cap = mo_cap;

        let mapping_end = match checked_range_end(base, length) {
            Some(v) => v,
            None => return Err(TRONA_INVALID_ARGUMENT),
        };
        if mapping_end > (*client).mmap_next {
            (*client).mmap_next = mapping_end;
        }

        Ok(base)
    }
}

/// MM_ALLOC_PRIVATE_REGION: create an anonymous MO-backed region for a client.
///   MR0 = target client badge
///   MR1 = requested base (0 = auto-place)
///   MR2 = page count
///   MR3 = vspace flags
///   Reply: MR0 = mapped base
pub(crate) unsafe fn handle_mm_alloc_private_region(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let requested_base = (*msg).regs[1];
        let page_count = (*msg).regs[2] as usize;
        let flags = (*msg).regs[3];

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        match alloc_private_region(client, requested_base, page_count, flags) {
            Ok(base) => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = base;
            }
            Err(err) => {
                (*reply).label = err;
            }
        }
    }
}

/// MM_ALLOC_PRIVATE_WINDOW: create an anonymous MO-backed region for a client
/// and immediately open a caller scratch window into an initial subrange.
///   MR0 = target client badge
///   MR1 = requested region base
///   MR2 = region page count
///   MR3 = target window vaddr within the region
///   MR4 = window vaddr in caller's VSpace
///   MR5 = scratch window page count
///   MR6 = vspace flags
///   + cap transfer: caller's VSpace cap
///   Reply: MR0 = pages mapped in caller scratch window
pub(crate) unsafe fn handle_mm_alloc_private_window(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let caller_vspace_cap = *(&raw const super::CURRENT_RECV_SLOT);

        if (*msg).length != 7 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let target_badge = (*msg).regs[0];
        let requested_base = (*msg).regs[1];
        let region_pages = (*msg).regs[2] as usize;
        let target_vaddr = (*msg).regs[3];
        let window_vaddr = (*msg).regs[4];
        let window_pages = (*msg).regs[5] as usize;
        let flags = (*msg).regs[6];

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let region_base = match alloc_private_region(client, requested_base, region_pages, flags) {
            Ok(base) => base,
            Err(err) => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = err;
                return;
            }
        };

        let region_len = match checked_mapping_len(region_pages) {
            Some(v) => v,
            None => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let window_len = match checked_mapping_len(window_pages) {
            Some(v) => v,
            None => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let region_end = match checked_range_end(region_base, region_len) {
            Some(v) => v,
            None => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let window_start = target_vaddr & !0xFFFu64;
        let window_end = match checked_range_end(window_start, window_len) {
            Some(v) => v,
            None => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if window_pages == 0 || target_vaddr < region_base || window_start < region_base || window_end > region_end {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mapped = match map_existing_region_window(client, caller_vspace_cap, target_vaddr, window_vaddr, window_pages) {
            Ok(v) => v,
            Err(err) => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = err;
                return;
            }
        };

        invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = mapped;
    }
}

/// MM_ALLOC_INITRD_COPY: create an anonymous region for a client and populate
/// it from the initrd device mapping that mmsrv already owns.
///   MR0 = target client badge
///   MR1 = requested region base
///   MR2 = region page count
///   MR3 = bytes to copy from initrd offset 0
///   MR4 = vspace flags
///   Reply: MR0 = mapped base
pub(crate) unsafe fn handle_mm_alloc_initrd_copy(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        if (*msg).length != 5 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let target_badge = (*msg).regs[0];
        let requested_base = (*msg).regs[1];
        let page_count = (*msg).regs[2] as usize;
        let copy_len = (*msg).regs[3] as usize;
        let flags = (*msg).regs[4];

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let region_base = match alloc_private_region(client, requested_base, page_count, flags) {
            Ok(base) => base,
            Err(err) => {
                (*reply).label = err;
                return;
            }
        };

        let copy_err = copy_initrd_into_region(client, region_base, page_count, copy_len);
        if copy_err != TRONA_OK {
            rollback_private_region(client, region_base, page_count);
            (*reply).label = copy_err;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = region_base;
    }
}

/// MM_ALLOC_BOOTINFO_COPY: create an anonymous region for a client and
/// populate it from mmsrv's own bootinfo mapping.
///   MR0 = target client badge
///   MR1 = requested region base
///   MR2 = vspace flags
///   Reply: MR0 = mapped base
pub(crate) unsafe fn handle_mm_alloc_bootinfo_copy(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        if (*msg).length != 3 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let target_badge = (*msg).regs[0];
        let requested_base = (*msg).regs[1];
        let flags = (*msg).regs[2];

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let region_base = match alloc_private_region(client, requested_base, 1, flags) {
            Ok(base) => base,
            Err(err) => {
                (*reply).label = err;
                return;
            }
        };

        let copy_err = copy_bootinfo_into_region(client, region_base);
        if copy_err != TRONA_OK {
            rollback_private_region(client, region_base, 1);
            (*reply).label = copy_err;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = region_base;
    }
}

/// MM_COPY_FROM_CLIENT_REGION: copy pages from the caller's existing region
/// into an existing region owned by another client.
///   MR0 = target client badge
///   MR1 = target vaddr
///   MR2 = source vaddr in caller
///   MR3 = page count
///   Reply: MR0 = pages copied
pub(crate) unsafe fn handle_mm_copy_from_client_region(
    msg: *const TronaMsg,
    caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        if (*msg).length != 4 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let target_badge = (*msg).regs[0];
        let target_vaddr = (*msg).regs[1];
        let source_vaddr = (*msg).regs[2];
        let num_pages = (*msg).regs[3] as usize;

        let src_client = find_client_by_badge(caller_badge);
        if src_client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let dst_client = find_client_by_badge(target_badge);
        if dst_client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let copy_err = copy_between_client_regions(src_client, source_vaddr, dst_client, target_vaddr, num_pages);
        if copy_err != TRONA_OK {
            (*reply).label = copy_err;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = num_pages as u64;
    }
}

/// MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION: create an anonymous region for a
/// client and populate an initial subrange from the caller's existing region.
///   MR0 = target client badge
///   MR1 = requested region base
///   MR2 = region page count
///   MR3 = target vaddr within the region
///   MR4 = source vaddr in caller
///   MR5 = page count to copy
///   MR6 = vspace flags
///   Reply: MR0 = mapped base
pub(crate) unsafe fn handle_mm_alloc_private_copy_from_client_region(
    msg: *const TronaMsg,
    caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        if (*msg).length != 7 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let target_badge = (*msg).regs[0];
        let requested_base = (*msg).regs[1];
        let region_pages = (*msg).regs[2] as usize;
        let target_vaddr = (*msg).regs[3];
        let source_vaddr = (*msg).regs[4];
        let copy_pages = (*msg).regs[5] as usize;
        let flags = (*msg).regs[6];

        let src_client = find_client_by_badge(caller_badge);
        if src_client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let dst_client = find_client_by_badge(target_badge);
        if dst_client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let region_base = match alloc_private_region(dst_client, requested_base, region_pages, flags) {
            Ok(base) => base,
            Err(err) => {
                (*reply).label = err;
                return;
            }
        };

        let copy_err = copy_between_client_regions(src_client, source_vaddr, dst_client, target_vaddr, copy_pages);
        if copy_err != TRONA_OK {
            rollback_private_region(dst_client, region_base, region_pages);
            (*reply).label = copy_err;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = region_base;
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

        if num_pages == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        match alloc_private_region(client, start_vaddr, num_pages, flags) {
            Ok(_) => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = num_pages as u64;
            }
            Err(err) => {
                (*reply).label = err;
            }
        }
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

        let length = match checked_mapping_len(page_count) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if requested_base != 0 && (requested_base & 0xFFF) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let mo_cap = *(&raw const super::CURRENT_RECV_SLOT);
        if mo_cap == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if !client_reserve_regions(client, 1) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let base = if requested_base != 0 {
            let remove_err = remove_client_range(client, requested_base, length, true, 1);
            if remove_err != TRONA_OK {
                (*reply).label = remove_err;
                return;
            }
            requested_base
        } else {
            (*client).mmap_next
        };
        let mapping_end = match checked_range_end(base, length) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        if !is_lazy {
            let count_and_flags = ((page_count as u64) << 32) | flags;
            let (err, mapped) = invoke::vspace_map_mo_with_count(
                (*client).vspace_cap,
                mo_cap,
                base,
                mo_offset as u64,
                count_and_flags,
            );
            if err != 0 || mapped != page_count as u64 {
                (*reply).label = TRONA_BAD_ADDRESS;
                return;
            }
        }

        let region = client_add_region(client);
        if region.is_null() {
            let _ = invoke::vspace_unmap_mo((*client).vspace_cap, base, page_count as u64);
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

        if mapping_end > (*client).mmap_next {
            (*client).mmap_next = mapping_end;
        }

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

// ---------------------------------------------------------------------------
// File mmap cache (moved from VFS)
// ---------------------------------------------------------------------------

const FILE_MMAP_CACHE_SIZE: usize = 32;

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

static mut FILE_MMAP_CACHE: [FileMmapCacheEntry; FILE_MMAP_CACHE_SIZE] =
    [FileMmapCacheEntry::zeroed(); FILE_MMAP_CACHE_SIZE];

unsafe fn file_mmap_cache_lookup(
    source_type: u8,
    source_id0: u64,
    source_id1: u64,
    min_pages: u32,
    file_size: u64,
) -> *mut FileMmapCacheEntry {
    let cache = &raw mut FILE_MMAP_CACHE;
    for i in 0..FILE_MMAP_CACHE_SIZE {
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

unsafe fn file_mmap_cache_find_source(
    source_type: u8,
    source_id0: u64,
    source_id1: u64,
) -> *mut FileMmapCacheEntry {
    let cache = &raw mut FILE_MMAP_CACHE;
    for i in 0..FILE_MMAP_CACHE_SIZE {
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

unsafe fn file_mmap_cache_alloc_or_replace(
    source_type: u8,
    source_id0: u64,
    source_id1: u64,
) -> *mut FileMmapCacheEntry {
    let cache = &raw mut FILE_MMAP_CACHE;
    for i in 0..FILE_MMAP_CACHE_SIZE {
        let entry = &raw mut (*cache)[i];
        if (*entry).active == 0 {
            return entry;
        }
    }
    for i in 0..FILE_MMAP_CACHE_SIZE {
        let entry = &raw mut (*cache)[i];
        if (*entry).source_type == source_type
            && (*entry).source_id0 == source_id0
            && (*entry).source_id1 == source_id1
        {
            if (*entry).mo_cap != 0 {
                super::recycled_cnode_delete((*entry).mo_cap);
            }
            *entry = FileMmapCacheEntry::zeroed();
            return entry;
        }
    }
    core::ptr::null_mut()
}

unsafe fn get_or_create_shared_file_mo(
    source_type: u8,
    source_id0: u64,
    source_id1: u64,
    file_size: u64,
) -> Cap {
    let needed_pages = ((file_size + 4095) / 4096) as u32;
    let existing = file_mmap_cache_lookup(source_type, source_id0, source_id1, needed_pages, file_size);
    if !existing.is_null() {
        return (*existing).mo_cap;
    }

    let slot = file_mmap_cache_alloc_or_replace(source_type, source_id0, source_id1);
    if slot.is_null() {
        return 0;
    }

    let (mo_cap, _) = super::create_mo(needed_pages as usize);
    if mo_cap == 0 {
        return 0;
    }

    let actual_pages = match invoke::mo_get_size(mo_cap) {
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

// ---------------------------------------------------------------------------
// MM_FILE_MMAP: file/mount-backed mmap (moved from VFS handle_mmap)
// ---------------------------------------------------------------------------

/// MM_FILE_MMAP: client requests file-backed mmap.
///
///   MR0 = fd
///   MR1 = file_offset
///   MR2 = length
///   MR3 = prot
///   MR4 = map_flags
///   MR5 = addr_hint
///   Badge identifies the client.
///
///   Reply: MR0 = mapped base address, MR1 = 0, MR2 = 1 (server-side mapped)
pub(crate) unsafe fn handle_mm_file_mmap(
    msg: *const TronaMsg,
    badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0];
        let file_offset = (*msg).regs[1];
        let length = (*msg).regs[2];
        let prot = (*msg).regs[3];
        let map_flags = (*msg).regs[4] as i32;
        let addr_hint = if (*msg).length >= 6 { (*msg).regs[5] } else { 0 };

        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        if length == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Resolve fd backing via VFS
        let vfs_ep = super::resolve_vfs_ep();
        if vfs_ep == 0 {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Prepare receive slot for potential device cap transfer
        let recv_slot = match super::recycled_slot_alloc() {
            Some(s) => s,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };
        ipc::set_receive_slot_ctx(
            super::ipc_ctx(),
            super::CAP_SELF_CSPACE,
            recv_slot,
            0,
        );

        let mut resolve_msg = TronaMsg::zeroed();
        let mut resolve_reply = TronaMsg::zeroed();
        resolve_msg.label = VFS_RESOLVE_BACKING;
        resolve_msg.length = 2;
        resolve_msg.regs[0] = fd;
        resolve_msg.regs[1] = badge;

        let err = ipc::call_ctx(super::ipc_ctx(), vfs_ep, &raw const resolve_msg, &raw mut resolve_reply);
        if err != 0 || resolve_reply.label != TRONA_OK {
            super::recycle_empty_slot(recv_slot);
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let backing_kind = resolve_reply.regs[0];
        let backing_id0 = resolve_reply.regs[1];
        let backing_id1 = resolve_reply.regs[2];
        let file_size = resolve_reply.regs[3];
        let resolve_flags = resolve_reply.regs[4];
        let fd_writable = (resolve_flags & 1) != 0;
        let inode_readonly = (resolve_flags & 2) != 0;

        // Dispatch to device mmap if backing is DEVICE
        if backing_kind == MMAP_BACKING_DEVICE {
            handle_device_mmap_inner(
                client, badge, recv_slot,
                file_size, length, prot, map_flags, addr_hint,
                reply,
            );
            return;
        }

        // Not a device — recycle the recv slot (no cap transferred for file/mount)
        super::recycle_empty_slot(recv_slot);

        if backing_kind == MMAP_BACKING_NONE {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Validate file offset alignment and range
        if file_offset & 0xFFF != 0 || file_offset >= file_size {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let len = match checked_aligned_len(length) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let mapping_pages = match checked_page_count(len) {
            Some(v) if v != 0 => v,
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let requested_base = if (map_flags & MAP_FIXED) != 0 {
            if addr_hint & 0xFFF != 0 {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            addr_hint
        } else {
            0
        };

        let source_type = match backing_kind {
            MMAP_BACKING_FILE => MMAP_CACHE_SOURCE_FILE,
            MMAP_BACKING_MOUNT => MMAP_CACHE_SOURCE_MOUNT,
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let mut vspace_flags = VSPACE_FLAG_USER;
        if prot & PROT_WRITE as u64 != 0 {
            vspace_flags |= VSPACE_FLAG_WRITABLE;
        }
        if prot & PROT_EXEC as u64 != 0 {
            vspace_flags |= VSPACE_FLAG_EXECUTABLE;
        }

        let is_shared = (map_flags & MAP_SHARED) != 0;
        let wants_write = (prot & PROT_WRITE as u64) != 0;

        if is_shared && wants_write {
            if !fd_writable {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            if backing_kind == MMAP_BACKING_FILE && inode_readonly {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            if file_offset.checked_add(length).is_none() || file_offset + length > file_size {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        }

        if !client_reserve_regions(client, 1) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        if is_shared {
            let shared_mo = get_or_create_shared_file_mo(source_type, backing_id0, backing_id1, file_size);
            if shared_mo == 0 {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }

            let base = if requested_base != 0 {
                let remove_err = remove_client_range(client, requested_base, len, true, 1);
                if remove_err != TRONA_OK {
                    (*reply).label = remove_err;
                    return;
                }
                requested_base
            } else {
                (*client).mmap_next
            };

            let mapping_end = match checked_range_end(base, len) {
                Some(v) => v,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            };

            let region = client_add_region(client);
            if region.is_null() {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }

            (*region).base = base;
            (*region).length = len;
            (*region).prot = super::vspace_flags_to_prot(vspace_flags);
            (*region).region_type = REGION_FILE_SHARED;
            (*region).active = true;
            (*region).lazy = true;
            (*region).mo_cap = shared_mo;
            (*region).mo_offset = (file_offset / 4096) as u32;
            (*region).backing_kind = backing_kind as u8;
            (*region).backing_writeback = if wants_write { 1 } else { 0 };
            (*region).backing_id0 = backing_id0;
            (*region).backing_id1 = backing_id1;
            (*region).backing_file_offset = file_offset;
            (*region).backing_file_size = file_size;

            if mapping_end > (*client).mmap_next {
                (*client).mmap_next = mapping_end;
            }

            (*reply).label = TRONA_OK;
            (*reply).length = 3;
            (*reply).regs[0] = base;
            (*reply).regs[1] = 0;
            (*reply).regs[2] = 1;
            return;
        }

        // Private file-backed mmap
        let (private_mo, _) = super::create_mo(mapping_pages);
        if private_mo == 0 {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let base = if requested_base != 0 {
            let remove_err = remove_client_range(client, requested_base, len, true, 1);
            if remove_err != TRONA_OK {
                super::recycled_cnode_delete(private_mo);
                (*reply).label = remove_err;
                return;
            }
            requested_base
        } else {
            (*client).mmap_next
        };

        let mapping_end = match checked_range_end(base, len) {
            Some(v) => v,
            None => {
                super::recycled_cnode_delete(private_mo);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let region = client_add_region(client);
        if region.is_null() {
            super::recycled_cnode_delete(private_mo);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*region).base = base;
        (*region).length = len;
        (*region).prot = super::vspace_flags_to_prot(vspace_flags);
        (*region).region_type = REGION_MMAP;
        (*region).active = true;
        (*region).lazy = true;
        (*region).mo_cap = private_mo;
        (*region).backing_kind = backing_kind as u8;
        (*region).backing_id0 = backing_id0;
        (*region).backing_id1 = backing_id1;
        (*region).backing_file_offset = file_offset;
        (*region).backing_file_size = file_size;

        if mapping_end > (*client).mmap_next {
            (*client).mmap_next = mapping_end;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 3;
        (*reply).regs[0] = base;
        (*reply).regs[1] = 0;
        (*reply).regs[2] = 1;
    }
}

// ---------------------------------------------------------------------------
// Device mmap (FB0 etc.) — cap transferred via VFS_RESOLVE_BACKING
// ---------------------------------------------------------------------------

unsafe fn handle_device_mmap_inner(
    client: *mut MmClient,
    badge: u64,
    device_cap: Cap,
    smem_len: u64,
    length: u64,
    prot: u64,
    _map_flags: i32,
    _addr_hint: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        if device_cap == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let len = match checked_aligned_len(length) {
            Some(v) => v,
            None => {
                super::recycled_cnode_delete(device_cap);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if len > ((smem_len + 4095) & !0xFFFu64) {
            super::recycled_cnode_delete(device_cap);
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let num_pages = len / 4096;
        if num_pages == 0 || num_pages > u16::MAX as u64 {
            super::recycled_cnode_delete(device_cap);
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if !client_reserve_regions(client, 1) {
            super::recycled_cnode_delete(device_cap);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let base = (*client).mmap_next;
        let mapping_end = match checked_range_end(base, len) {
            Some(v) => v,
            None => {
                super::recycled_cnode_delete(device_cap);
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let map_flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER | VSPACE_FLAG_WRITE_THROUGH;
        let (map_err, mapped) = invoke::vspace_map_device_range(
            (*client).vspace_cap,
            device_cap,
            0,
            base,
            num_pages,
            map_flags,
        );
        if map_err != 0 || mapped != num_pages {
            for i in 0..mapped {
                invoke::vspace_unmap((*client).vspace_cap, base + i * 4096);
            }
            super::recycled_cnode_delete(device_cap);
            (*reply).label = TRONA_BAD_ADDRESS;
            return;
        }

        let region = client_add_region(client);
        if !region.is_null() {
            (*region).base = base;
            (*region).length = len;
            (*region).prot = super::vspace_flags_to_prot(
                VSPACE_FLAG_USER | if prot & PROT_WRITE as u64 != 0 { VSPACE_FLAG_WRITABLE } else { 0 },
            );
            (*region).region_type = REGION_MMAP;
            (*region).active = true;
            (*region).mo_cap = device_cap;
        }

        super::mark_recv_slot_kept();

        if mapping_end > (*client).mmap_next {
            (*client).mmap_next = mapping_end;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 3;
        (*reply).regs[0] = base;
        (*reply).regs[1] = smem_len;
        (*reply).regs[2] = 1;
    }
}

// ---------------------------------------------------------------------------
// MM_SYNC_MMAP_WRITE: invalidate cached MO pages after VFS write
// ---------------------------------------------------------------------------

/// MM_SYNC_MMAP_WRITE: VFS notifies mmsrv after writing to a file/mount.
///
///   MR0 = backing_kind
///   MR1 = backing_id0
///   MR2 = backing_id1
///   MR3 = write_offset
///   MR4 = write_count
///   MR5 = old_file_size
///   MR6 = new_file_size
///
/// For each matching cached MO that has committed pages in the write range,
/// those pages are decommitted so the next VMFault re-reads fresh data
/// from VFS via VFS_PAGER_READ. Also updates the backing_file_size on
/// all matching client regions.
pub(crate) unsafe fn handle_mm_sync_mmap_write(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let backing_kind = (*msg).regs[0] as u8;
        let backing_id0 = (*msg).regs[1];
        let backing_id1 = (*msg).regs[2];
        let write_offset = (*msg).regs[3];
        let write_count = (*msg).regs[4];
        let _old_size = (*msg).regs[5];
        let new_size = (*msg).regs[6];

        let source_type = match backing_kind as u64 {
            MMAP_BACKING_FILE => MMAP_CACHE_SOURCE_FILE,
            MMAP_BACKING_MOUNT => MMAP_CACHE_SOURCE_MOUNT,
            _ => {
                (*reply).label = TRONA_OK;
                return;
            }
        };

        // Update file_size in the shared MO cache entry and invalidate
        // committed pages in the write range so they re-fault fresh data.
        let entry = file_mmap_cache_find_source(source_type, backing_id0, backing_id1);
        if !entry.is_null() && (*entry).active != 0 {
            if write_count > 0 && (*entry).mo_cap != 0 {
                let start_page = write_offset / 4096;
                let end_page = (write_offset + write_count + 4095) / 4096;
                let max_page = (*entry).page_count as u64;
                let mut page = start_page;
                while page < end_page && page < max_page {
                    let (has_err, has_page) = invoke::mo_has_page((*entry).mo_cap, page);
                    if has_err == 0 && has_page {
                        let _ = invoke::mo_decommit((*entry).mo_cap, page, 1);
                    }
                    page += 1;
                }
            }
            if new_size > (*entry).file_size {
                (*entry).file_size = new_size;
            }
        }

        // Unmap affected pages from client VSpaces and update backing_file_size
        let ptr = *(&raw const super::CLIENTS_PTR);
        let cap = *(&raw const super::CLIENTS_CAP);
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

                if write_count > 0 {
                    let region_file_start = (*region).backing_file_offset;
                    let region_file_end = region_file_start + (*region).length;

                    let overlap_start = core::cmp::max(write_offset, region_file_start);
                    let overlap_end = core::cmp::min(write_offset + write_count, region_file_end);

                    if overlap_start < overlap_end {
                        let rel_start = overlap_start - region_file_start;
                        let rel_end = overlap_end - region_file_start;
                        let first_page = rel_start / 4096;
                        let last_page = (rel_end + 4095) / 4096;
                        let mut p = first_page;
                        while p < last_page {
                            let page_va = (*region).base + p * 4096;
                            invoke::vspace_unmap((*client).vspace_cap, page_va);
                            p += 1;
                        }
                    }
                }

                (*region).backing_file_size = new_size;
            }
        }

        (*reply).label = TRONA_OK;
    }
}
