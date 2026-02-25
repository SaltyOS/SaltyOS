use crate::types::*;
use crate::client::{find_client_by_badge, client_add_region, find_region_by_addr,
                    alloc_cow_bitmap, clear_cow_bit};
use salty::consts::*;
use salty::invoke;
use salty::ipc;
use salty::serial::LineBuf;
use salty::types::*;

unsafe fn register_tracked_region(
    client: *mut MmClient,
    base: u64,
    page_count: usize,
    flags: u64,
    region_type: u8,
    frame_caps: *mut Cap,
    frame_count: usize,
) -> bool {
    unsafe {
        if page_count == 0 || frame_caps.is_null() {
            return false;
        }
        if page_count > u16::MAX as usize || frame_count > u16::MAX as usize {
            return false;
        }

        let region = client_add_region(client);
        if region.is_null() {
            return false;
        }

        (*region).base = base;
        (*region).length = page_count as u64 * 4096;
        (*region).prot = super::vspace_flags_to_prot(flags);
        (*region).region_type = region_type;
        (*region).active = true;
        (*region).lazy = false;
        (*region).frame_caps = frame_caps;
        (*region).frame_count = frame_count as u16;
        (*region).frame_cap_capacity = page_count as u16;
        true
    }
}

/// MM_BRK: client sets program break.
///   MR0 = new break address
///   Badge identifies the client.
pub(crate) unsafe fn handle_mm_brk(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let new_brk = (*msg).regs[0];
        if new_brk < (*client).heap_base {
            (*reply).label = SALTY_INVALID_ARGUMENT;
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
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            let fcaps = super::alloc_frame_cap_array(HEAP_INITIAL_FRAME_CAP);
            if fcaps.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            (*heap_region).base = (*client).heap_base;
            (*heap_region).length = 0;
            (*heap_region).prot = (PROT_READ | PROT_WRITE) as u8;
            (*heap_region).region_type = REGION_HEAP;
            (*heap_region).active = true;
            (*heap_region).frame_caps = fcaps;
            (*heap_region).frame_count = 0;
            (*heap_region).frame_cap_capacity = HEAP_INITIAL_FRAME_CAP as u16;
        }

        if new_page > old_page {
            let grow_pages = ((new_page - old_page) / 4096) as usize;
            let new_total = (*heap_region).frame_count as usize + grow_pages;

            // Grow frame_caps array if needed
            if new_total > (*heap_region).frame_cap_capacity as usize {
                let mut new_fcap = (*heap_region).frame_cap_capacity as usize * 2;
                while new_fcap < new_total {
                    new_fcap *= 2;
                }
                let new_ptr = super::grow_frame_cap_array(
                    (*heap_region).frame_caps,
                    (*heap_region).frame_count as usize,
                    new_fcap,
                );
                if new_ptr.is_null() {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                (*heap_region).frame_caps = new_ptr;
                (*heap_region).frame_cap_capacity = new_fcap as u16;
            }

            // Grow: allocate and map new pages
            let mut va = old_page;
            let mut page_idx = (*heap_region).frame_count as usize;
            while va < new_page {
                let frame_slot = match salty::slot_alloc::slot_alloc() {
                    Some(s) => s,
                    None => {
                        let mut rva = old_page;
                        while rva < va {
                            invoke::vspace_unmap(vspace_cap, rva);
                            rva += 4096;
                        }
                        (*heap_region).frame_count = ((old_page - (*heap_region).base) / 4096) as u16;
                        (*reply).label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                };

                let err = super::retype_any(OBJ_FRAME, 0, frame_slot);
                if err != 0 {
                    let mut rva = old_page;
                    while rva < va {
                        invoke::vspace_unmap(vspace_cap, rva);
                        rva += 4096;
                    }
                    (*heap_region).frame_count = ((old_page - (*heap_region).base) / 4096) as u16;
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                let err = invoke::vspace_map(
                    vspace_cap,
                    frame_slot,
                    va,
                    VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                );
                if err != 0 {
                    invoke::cnode_delete(super::CAP_SELF_CSPACE, frame_slot);
                    let mut rva = old_page;
                    while rva < va {
                        invoke::vspace_unmap(vspace_cap, rva);
                        rva += 4096;
                    }
                    (*heap_region).frame_count = ((old_page - (*heap_region).base) / 4096) as u16;
                    (*reply).label = SALTY_BAD_ADDRESS;
                    return;
                }
                *(*heap_region).frame_caps.add(page_idx) = frame_slot;
                page_idx += 1;
                va += 4096;
            }
            (*heap_region).frame_count = page_idx as u16;
            (*heap_region).length = new_page - (*heap_region).base;
        } else if new_page < old_page {
            // Shrink: unmap freed pages and clean up frame caps
            let shrink_pages = ((old_page - new_page) / 4096) as usize;
            let old_count = (*heap_region).frame_count as usize;
            let new_count = if old_count >= shrink_pages { old_count - shrink_pages } else { 0 };

            let mut va = new_page;
            let mut idx = new_count;
            while va < old_page && idx < old_count {
                let fcap = *(*heap_region).frame_caps.add(idx);
                invoke::vspace_unmap(vspace_cap, va);
                if fcap != 0 {
                    invoke::cnode_delete(super::CAP_SELF_CSPACE, fcap);
                }
                va += 4096;
                idx += 1;
            }
            (*heap_region).frame_count = new_count as u16;
            (*heap_region).length = new_page - (*heap_region).base;
        }

        (*client).heap_current = new_brk;
        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_brk;
    }
}

/// MM_SBRK: client increments break.
///   MR0 = increment (signed as u64)
///   Badge identifies the client.
///   Reply: MR0 = old break address
pub(crate) unsafe fn handle_mm_sbrk(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let increment = (*msg).regs[0] as i64;
        let old_break = (*client).heap_current;

        if increment == 0 {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = old_break;
            return;
        }

        let new_break = if increment > 0 {
            old_break + increment as u64
        } else {
            let dec = (-increment) as u64;
            if dec > old_break - (*client).heap_base {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            old_break - dec
        };

        // Delegate to brk handler
        let mut brk_msg = SaltyMsg::zeroed();
        brk_msg.regs[0] = new_break;
        handle_mm_brk(&raw const brk_msg, badge, reply);

        // On success, return old break in MR0
        if (*reply).label == SALTY_OK {
            (*reply).regs[0] = old_break;
        }
    }
}

/// MM_MMAP: client requests anonymous mmap.
///   MR0 = addr hint (0=auto)
///   MR1 = length
///   MR2 = prot
///   MR3 = flags
///   Badge identifies the client.
///   Reply: MR0 = mapped base address
pub(crate) unsafe fn handle_mm_mmap(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let _addr_hint = (*msg).regs[0];
        let length = (*msg).regs[1];
        let _prot = (*msg).regs[2] as i32;
        let _flags = (*msg).regs[3] as i32;

        if length == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
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

        // Create region to track frame caps
        let region = client_add_region(client);
        if region.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let fcaps = super::alloc_frame_cap_array(num_pages);
        if fcaps.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }
        (*region).base = base;
        (*region).length = len;
        (*region).prot = _prot as u8;
        (*region).region_type = REGION_MMAP;
        (*region).active = true;
        (*region).frame_caps = fcaps;
        (*region).frame_count = 0;
        (*region).frame_cap_capacity = num_pages as u16;

        // Check for MAP_LAZY flag
        let is_lazy = (_flags & MAP_LAZY) != 0;
        (*region).lazy = is_lazy;

        if is_lazy {
            // Lazy path: install demand-page PTEs via kernel syscall.
            // On first access, the kernel allocates a zero-fill frame directly
            // (no VMFault IPC round-trip needed).
            let map_flags = {
                let mut f: u64 = VSPACE_FLAG_USER;
                if _prot & 0x2 != 0 { f |= VSPACE_FLAG_WRITABLE; }
                if _prot & 0x4 != 0 { f |= VSPACE_FLAG_EXECUTABLE; }
                f
            };
            let (err, mapped) = invoke::vspace_map_demand_range(
                vspace_cap, base, num_pages as u64, map_flags,
            );
            if err != 0 || mapped == 0 {
                (*region).active = false;
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            (*client).mmap_next = base + len;
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = base;
            return;
        }

        // Eager path: Allocate and map each page immediately
        for i in 0..num_pages {
            let frame_slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => {
                    for j in 0..i {
                        invoke::vspace_unmap(vspace_cap, base + j as u64 * 4096);
                    }
                    (*region).active = false;
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            };

            let err = super::retype_any(OBJ_FRAME, 0, frame_slot);
            if err != 0 {
                for j in 0..i {
                    invoke::vspace_unmap(vspace_cap, base + j as u64 * 4096);
                }
                (*region).active = false;
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }

            let err = invoke::vspace_map(vspace_cap, frame_slot, base + i as u64 * 4096, map_flags);
            if err != 0 {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, frame_slot);
                for j in 0..i {
                    invoke::vspace_unmap(vspace_cap, base + j as u64 * 4096);
                }
                (*region).active = false;
                (*reply).label = SALTY_BAD_ADDRESS;
                return;
            }

            *fcaps.add(i) = frame_slot;
            (*region).frame_count = (i + 1) as u16;
        }

        (*client).mmap_next = base + len;

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = base;
    }
}

/// MM_MUNMAP: client unmaps a region.
///   MR0 = base address
///   MR1 = length
///   Badge identifies the client.
pub(crate) unsafe fn handle_mm_munmap(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let base = (*msg).regs[0];
        let length = (*msg).regs[1];
        let vspace_cap = (*client).vspace_cap;

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };
        let num_pages = (len / 4096) as usize;

        // Look up region for frame cap cleanup
        let region = find_region_by_addr(client, base);
        if !region.is_null() && (*region).active {
            // Unmap with frame cap cleanup
            let region_start_page = ((base - (*region).base) / 4096) as usize;
            for i in 0..num_pages {
                let page_idx = region_start_page + i;
                invoke::vspace_unmap(vspace_cap, base + i as u64 * 4096);
                // Clear COW bit if set (page was kernel-managed, no cap to delete)
                clear_cow_bit(region, page_idx);
                if page_idx < (*region).frame_count as usize {
                    let fcap = *(*region).frame_caps.add(page_idx);
                    if fcap != 0 {
                        invoke::cnode_delete(super::CAP_SELF_CSPACE, fcap);
                        *(*region).frame_caps.add(page_idx) = 0;
                    }
                }
            }
            // If entire region unmapped, mark inactive
            if base == (*region).base && len >= (*region).length {
                (*region).active = false;
            }
        } else {
            // No region tracking — just unmap
            for i in 0..num_pages {
                invoke::vspace_unmap(vspace_cap, base + i as u64 * 4096);
            }
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_MPROTECT: client changes protection on a mapped region.
///   MR0 = base address
///   MR1 = length
///   MR2 = prot (PROT_READ/WRITE/EXEC)
///   Badge identifies the client.
///
/// Uses per-page frame cap tracking: unmap each page and remap with new flags.
pub(crate) unsafe fn handle_mm_mprotect(msg: *const SaltyMsg, badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client = find_client_by_badge(badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let addr = (*msg).regs[0];
        let length = (*msg).regs[1];
        let prot = (*msg).regs[2] as u8;

        let region = find_region_by_addr(client, addr);
        if region.is_null() || !(*region).active {
            // No region tracking for this address — accept silently
            (*reply).label = SALTY_OK;
            return;
        }

        // Convert PROT_* -> VSPACE_FLAG_* (W^X: W and X are mutually exclusive)
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
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };
        let start_page = ((addr - (*region).base) / 4096) as usize;
        let page_count = (len / 4096) as usize;

        for i in 0..page_count {
            let page_idx = start_page + i;
            if page_idx >= (*region).frame_count as usize {
                break;
            }
            let frame_cap = *(*region).frame_caps.add(page_idx);
            if frame_cap == 0 {
                continue;
            }
            let page_va = (*region).base + page_idx as u64 * 4096;
            invoke::vspace_unmap(vspace_cap, page_va);
            invoke::vspace_map(vspace_cap, frame_cap, page_va, flags);
        }

        (*region).prot = prot;
        (*reply).label = SALTY_OK;
    }
}

/// MM_MAP_WINDOW: procmgr creates dual-mapped write window.
///   MR0 = target client badge
///   MR1 = target start vaddr
///   MR2 = window vaddr in caller's VSpace
///   MR3 = num_pages
///   MR4 = vspace flags for target mapping
///   + cap transfer: caller's VSpace cap
///   Reply: MR0 = pages_mapped
pub(crate) unsafe fn handle_mm_map_window(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
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
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let target_vspace_cap = (*client).vspace_cap;
        let mut mapped: usize = 0;

        // Track frame caps for rollback/region registration.
        const MAX_WINDOW_PAGES: usize = 512;
        let mut frame_caps: [Cap; MAX_WINDOW_PAGES] = [0; MAX_WINDOW_PAGES];
        let effective_pages = if num_pages > MAX_WINDOW_PAGES { MAX_WINDOW_PAGES } else { num_pages };

        for i in 0..effective_pages {
            let frame_slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => break,
            };

            let err = super::retype_any(OBJ_FRAME, 0, frame_slot);
            if err != 0 {
                break;
            }

            let err = invoke::vspace_map(
                target_vspace_cap, frame_slot,
                target_vaddr + i as u64 * 4096, target_flags,
            );
            if err != 0 {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, frame_slot);
                break;
            }

            let err = invoke::vspace_map(
                caller_vspace_cap, frame_slot,
                window_vaddr + i as u64 * 4096,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                invoke::vspace_unmap(target_vspace_cap, target_vaddr + i as u64 * 4096);
                invoke::cnode_delete(super::CAP_SELF_CSPACE, frame_slot);
                break;
            }

            frame_caps[i] = frame_slot;
            mapped += 1;
        }

        // On partial failure (mapped < requested), roll back all mappings
        // to avoid leaking frames that aren't tracked anywhere
        if mapped > 0 && mapped < effective_pages {
            for i in 0..mapped {
                invoke::vspace_unmap(target_vspace_cap, target_vaddr + i as u64 * 4096);
                invoke::vspace_unmap(caller_vspace_cap, window_vaddr + i as u64 * 4096);
                if frame_caps[i] != 0 {
                    invoke::cnode_delete(super::CAP_SELF_CSPACE, frame_caps[i]);
                }
            }
            mapped = 0;
        }

        if mapped > 0 {
            let tracked_caps = super::alloc_frame_cap_array(mapped);
            if tracked_caps.is_null() {
                for i in 0..mapped {
                    invoke::vspace_unmap(target_vspace_cap, target_vaddr + i as u64 * 4096);
                    invoke::vspace_unmap(caller_vspace_cap, window_vaddr + i as u64 * 4096);
                    if frame_caps[i] != 0 {
                        invoke::cnode_delete(super::CAP_SELF_CSPACE, frame_caps[i]);
                    }
                }
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }

            for i in 0..mapped {
                *tracked_caps.add(i) = frame_caps[i];
            }

            if !register_tracked_region(
                client,
                target_vaddr,
                mapped,
                target_flags,
                REGION_SPAWN,
                tracked_caps,
                mapped,
            ) {
                for i in 0..mapped {
                    invoke::vspace_unmap(target_vspace_cap, target_vaddr + i as u64 * 4096);
                    invoke::vspace_unmap(caller_vspace_cap, window_vaddr + i as u64 * 4096);
                    let frame = *tracked_caps.add(i);
                    if frame != 0 {
                        invoke::cnode_delete(super::CAP_SELF_CSPACE, frame);
                    }
                }
                invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        invoke::cnode_delete(super::CAP_SELF_CSPACE, caller_vspace_cap);

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = mapped as u64;
    }
}

/// MM_UNMAP_WINDOW: procmgr removes write window from caller's VSpace.
///   MR0 = window vaddr in caller
///   MR1 = num_pages
///   + cap transfer: caller's VSpace cap
///   Reply: label = SALTY_OK
///
/// Frame caps stay in mmsrv's CSpace; target mapping persists after
/// window removal.
pub(crate) unsafe fn handle_mm_unmap_window(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
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

        (*reply).label = SALTY_OK;
    }
}

/// MM_FORK_REGIONS: procmgr clones parent's region state to child.
///   MR0 = parent client badge
///   MR1 = child client badge
///
/// Copies parent's heap_base, heap_current, and mmap_next to the child
/// client entry (which must already exist via MM_REGISTER).
pub(crate) unsafe fn handle_mm_fork_regions(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let parent_badge = (*msg).regs[0];
        let child_badge = (*msg).regs[1];

        let parent = find_client_by_badge(parent_badge);
        if parent.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let child = find_client_by_badge(child_badge);
        if child.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        // Clone parent's memory layout
        (*child).heap_base = (*parent).heap_base;
        (*child).heap_current = (*parent).heap_current;
        (*child).mmap_next = (*parent).mmap_next;

        // Deep-copy parent's region list (without frame caps -- COW-managed)
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
                for ri in 0..parent_rc {
                    let pr = parent_regions.add(ri);
                    let mut cr = MmRegion::zeroed();
                    cr.base = (*pr).base;
                    cr.length = (*pr).length;
                    cr.prot = (*pr).prot;
                    cr.region_type = (*pr).region_type;
                    cr.active = (*pr).active;
                    // frame_caps left null -- inherited via kernel COW

                    // Allocate COW bitmap for active child regions.
                    // After fork, ALL pages in the region are COW-shared:
                    // the kernel has already downgraded parent PTEs and
                    // cloned them read-only into the child.
                    if cr.active && cr.length > 0 {
                        let page_count = (cr.length / 4096) as usize;
                        let (bm_ptr, bm_words) = alloc_cow_bitmap(page_count);
                        if !bm_ptr.is_null() {
                            cr.cow_bitmap = bm_ptr;
                            cr.cow_bitmap_words = bm_words;
                            // Mark all pages as COW
                            for pi in 0..page_count {
                                let word_idx = pi / 64;
                                let bit_idx = pi % 64;
                                // SAFETY: word_idx < bm_words guaranteed by alloc_cow_bitmap sizing.
                                *bm_ptr.add(word_idx) |= 1u64 << bit_idx;
                            }
                        }

                        // Allocate/resize COW bitmap for the parent's region
                        // so the parent knows its frame_caps[i] are stale
                        // after a COW write fault.
                        //
                        // On re-fork: the bitmap may be too small if the
                        // region grew, and ALL bits must be re-set since fork
                        // downgrades all parent PTEs to read-only.
                        {
                            let need_words = ((page_count + 63) / 64) as u16;
                            if (*pr).cow_bitmap.is_null() || (*pr).cow_bitmap_words < need_words {
                                let (pbm_ptr, pbm_words) = alloc_cow_bitmap(page_count);
                                if !pbm_ptr.is_null() {
                                    // Old bitmap leaked (no munmap for self_mmap).
                                    // Bounded: at most 1 page per region lifetime.
                                    (*pr).cow_bitmap = pbm_ptr;
                                    (*pr).cow_bitmap_words = pbm_words;
                                }
                            }
                            // Re-mark ALL pages as COW — fork downgrades all
                            // parent PTEs to read-only.
                            if !(*pr).cow_bitmap.is_null() {
                                for pi in 0..page_count {
                                    let word_idx = pi / 64;
                                    let bit_idx = pi % 64;
                                    if (word_idx as u16) < (*pr).cow_bitmap_words {
                                        // SAFETY: word_idx is bounds-checked above.
                                        *(*pr).cow_bitmap.add(word_idx) |= 1u64 << bit_idx;
                                    }
                                }
                            }
                        }
                    }

                    *child_regions.add(ri) = cr;
                }
                (*child).regions = child_regions;
                (*child).region_count = parent_rc;
                (*child).region_cap = child_region_cap;
            }
        }

        // Set up COW frame pools for fast-path resolution (Phase 2).
        // Non-fatal: if pool setup fails, COW still works via mmsrv IPC.
        crate::pool::init_pool(child);
        crate::pool::init_pool(parent);

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] fork-regions parent=");
            lb.hex(parent_badge);
            lb.str(b" child=");
            lb.hex(child_badge);
            lb.str(b" heap=");
            lb.hex((*parent).heap_current);
            lb.str(b" mmap=");
            lb.hex((*parent).mmap_next);
            lb.str(b"\n");
            lb.flush();
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_ALLOC_THREAD_OBJECTS: allocate TCB + SchedContext + IPC buffer Frame.
///
/// The client sends 3 destination CNode slots in MR0, MR1, MR2 where
/// the resulting caps should be placed. mmsrv retypes the objects into
/// temporary slots, then transfers them back via IPC cap transfer.
///
/// Reply: label = SALTY_OK with 3 caps transferred, or error.
pub(crate) unsafe fn handle_mm_alloc_thread_objects(
    _msg: *const SaltyMsg,
    _caller_badge: u64,
    reply: *mut SaltyMsg,
) {
    unsafe {
        // Allocate 3 temp slots for the new objects
        let tcb_slot = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => { (*reply).label = SALTY_OUT_OF_MEMORY; return; }
        };
        let sc_slot = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => { (*reply).label = SALTY_OUT_OF_MEMORY; return; }
        };
        let frame_slot = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => { (*reply).label = SALTY_OUT_OF_MEMORY; return; }
        };

        // Retype: TCB (0 size_bits = default)
        let err = super::retype_any(OBJ_TCB, 0, tcb_slot);
        if err != 0 {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Retype: SchedContext (0 size_bits = default)
        let err = super::retype_any(OBJ_SCHED_CONTEXT, 0, sc_slot);
        if err != 0 {
            // Clean up TCB
            invoke::cnode_delete(super::CAP_SELF_CSPACE, tcb_slot);
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Retype: Frame (12 size_bits = 4K page for IPC buffer)
        let err = super::retype_any(OBJ_FRAME, 12, frame_slot);
        if err != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, tcb_slot);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, sc_slot);
            (*reply).label = SALTY_OUT_OF_MEMORY;
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

        (*reply).label = SALTY_OK;
        (*reply).length = 0;
    }
}

/// MM_ALLOC_OBJECT: allocate a single kernel object of any type.
///
/// Request: MR0 = obj_type, MR1 = size_bits, length = 2
/// Reply: label = SALTY_OK with 1 cap transferred, or SALTY_OUT_OF_MEMORY.
pub(crate) unsafe fn handle_mm_alloc_object(
    msg: *const SaltyMsg,
    _caller_badge: u64,
    reply: *mut SaltyMsg,
) {
    unsafe {
        let obj_type = (*msg).regs[0];
        let size_bits = (*msg).regs[1];

        let slot = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => { (*reply).label = SALTY_OUT_OF_MEMORY; return; }
        };

        let err = super::retype_any(obj_type, size_bits, slot);
        if err != 0 {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, slot);

        *(&raw mut super::PENDING_CLEANUP_SLOTS) = [slot, 0, 0, 0];
        *(&raw mut super::PENDING_CLEANUP_COUNT) = 1;

        (*reply).label = SALTY_OK;
        (*reply).length = 0;
    }
}

/// MM_MAP_BATCH: procmgr batch-maps N frames for spawn.
///   MR0 = target client badge
///   MR1 = start vaddr
///   MR2 = num_pages
///   MR3 = vspace flags
///   Reply: MR0 = pages_mapped
pub(crate) unsafe fn handle_mm_map_batch(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let start_vaddr = (*msg).regs[1];
        let num_pages = (*msg).regs[2] as usize;
        let flags = (*msg).regs[3];

        let client = find_client_by_badge(target_badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let vspace_cap = (*client).vspace_cap;
        let mut mapped: usize = 0;

        if num_pages == 0 {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let tracked_caps = super::alloc_frame_cap_array(num_pages);
        if tracked_caps.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for i in 0..num_pages {
            *tracked_caps.add(i) = 0;
        }

        for i in 0..num_pages {
            let frame_slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => break,
            };

            let err = super::retype_any(OBJ_FRAME, 0, frame_slot);
            if err != 0 {
                break;
            }

            let err = invoke::vspace_map(
                vspace_cap,
                frame_slot,
                start_vaddr + i as u64 * 4096,
                flags,
            );
            if err != 0 {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, frame_slot);
                break;
            }
            *tracked_caps.add(i) = frame_slot;
            mapped += 1;
        }

        if mapped > 0 {
            if !register_tracked_region(
                client,
                start_vaddr,
                mapped,
                flags,
                REGION_SPAWN,
                tracked_caps,
                mapped,
            ) {
                for i in 0..mapped {
                    invoke::vspace_unmap(vspace_cap, start_vaddr + i as u64 * 4096);
                    let frame = *tracked_caps.add(i);
                    if frame != 0 {
                        invoke::cnode_delete(super::CAP_SELF_CSPACE, frame);
                        *tracked_caps.add(i) = 0;
                    }
                }
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = mapped as u64;
    }
}
