use crate::types::*;
use salty::consts::*;
use salty::invoke;
use salty::serial::LineBuf;
use salty::types::*;

pub(crate) unsafe fn find_client_by_badge(badge: u64) -> *mut MmClient {
    unsafe {
        let ptr = *(&raw const super::CLIENTS_PTR);
        let cap = *(&raw const super::CLIENTS_CAP);
        for i in 0..cap {
            let c = ptr.add(i);
            if (*c).active && (*c).badge == badge {
                return c;
            }
        }
        core::ptr::null_mut()
    }
}

/// Find or grow a free client slot. Returns pointer to free slot or null.
pub(crate) unsafe fn find_free_client_slot() -> *mut MmClient {
    unsafe {
        let ptr = *(&raw const super::CLIENTS_PTR);
        let cap = *(&raw const super::CLIENTS_CAP);
        for i in 0..cap {
            let c = ptr.add(i);
            if !(*c).active {
                return c;
            }
        }
        // Grow: double capacity
        let new_cap = cap * 2;
        let new_bytes = new_cap * core::mem::size_of::<MmClient>();
        let new_pages = (new_bytes + 4095) / 4096;
        let new_ptr = super::self_mmap(new_pages);
        if new_ptr.is_null() {
            return core::ptr::null_mut();
        }
        let new_ptr = new_ptr as *mut MmClient;
        // Copy old entries
        for i in 0..cap {
            *new_ptr.add(i) = *ptr.add(i);
        }
        // First free slot is at old cap
        let free = new_ptr.add(cap);
        *(&raw mut super::CLIENTS_PTR) = new_ptr;
        *(&raw mut super::CLIENTS_CAP) = new_cap;
        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] clients grown to ");
            lb.hex(new_cap as u64);
            lb.str(b"\n");
            lb.flush();
        }
        free
    }
}

/// Add a region to a client. Returns pointer to the new region or null.
pub(crate) unsafe fn client_add_region(client: *mut MmClient) -> *mut MmRegion {
    unsafe {
        let count = (*client).region_count;
        let cap = (*client).region_cap;

        if count >= cap {
            // Grow regions array
            let new_cap = if cap == 0 { REGION_INITIAL_CAP } else { cap * 2 };
            let new_bytes = new_cap * core::mem::size_of::<MmRegion>();
            let new_pages = (new_bytes + 4095) / 4096;
            let new_pages = if new_pages == 0 { 1 } else { new_pages };
            let new_ptr = super::self_mmap(new_pages);
            if new_ptr.is_null() {
                return core::ptr::null_mut();
            }
            let new_ptr = new_ptr as *mut MmRegion;
            // Copy old regions
            let old_ptr = (*client).regions;
            if !old_ptr.is_null() {
                for i in 0..count {
                    *new_ptr.add(i) = *old_ptr.add(i);
                }
            }
            (*client).regions = new_ptr;
            (*client).region_cap = new_cap;
        }

        let region = (*client).regions.add(count);
        *region = MmRegion::zeroed();
        (*client).region_count = count + 1;
        region
    }
}

/// Find the region containing `addr` in a client's region list.
pub(crate) unsafe fn find_region_by_addr(client: *mut MmClient, addr: u64) -> *mut MmRegion {
    unsafe {
        let count = (*client).region_count;
        let regions = (*client).regions;
        if regions.is_null() {
            return core::ptr::null_mut();
        }
        for i in 0..count {
            let r = regions.add(i);
            if (*r).active && addr >= (*r).base && addr < (*r).base + (*r).length {
                return r;
            }
        }
        core::ptr::null_mut()
    }
}

/// Check whether a specific page in a region is COW-inherited.
pub(crate) fn is_cow_page(region: *const MmRegion, page_idx: usize) -> bool {
    // SAFETY: region is a valid pointer from the client's region array.
    unsafe {
        let r = &*region;
        if r.cow_bitmap.is_null() {
            return false;
        }
        let word_idx = page_idx / 64;
        let bit_idx = page_idx % 64;
        if word_idx >= r.cow_bitmap_words as usize {
            return false;
        }
        // SAFETY: word_idx is bounds-checked above.
        (*r.cow_bitmap.add(word_idx) >> bit_idx) & 1 != 0
    }
}

/// Mark a page as COW-inherited in the region's bitmap.
pub(crate) fn set_cow_bit(region: *mut MmRegion, page_idx: usize) {
    // SAFETY: region is a valid mutable pointer from the client's region array.
    unsafe {
        let r = &mut *region;
        if r.cow_bitmap.is_null() {
            return;
        }
        let word_idx = page_idx / 64;
        let bit_idx = page_idx % 64;
        if word_idx >= r.cow_bitmap_words as usize {
            return;
        }
        // SAFETY: word_idx is bounds-checked above.
        *r.cow_bitmap.add(word_idx) |= 1u64 << bit_idx;
    }
}

/// Clear the COW bit for a page (after COW resolution or unmap).
pub(crate) fn clear_cow_bit(region: *mut MmRegion, page_idx: usize) {
    // SAFETY: region is a valid mutable pointer from the client's region array.
    unsafe {
        let r = &mut *region;
        if r.cow_bitmap.is_null() {
            return;
        }
        let word_idx = page_idx / 64;
        let bit_idx = page_idx % 64;
        if word_idx >= r.cow_bitmap_words as usize {
            return;
        }
        // SAFETY: word_idx is bounds-checked above.
        *r.cow_bitmap.add(word_idx) &= !(1u64 << bit_idx);
    }
}

/// Allocate a COW bitmap for `page_count` pages.
/// Returns (pointer, word_count) or (null, 0) on failure.
pub(crate) fn alloc_cow_bitmap(page_count: usize) -> (*mut u64, u16) {
    let word_count = (page_count + 63) / 64;
    let byte_count = word_count * 8;
    // Round up to page boundary for self_mmap
    let alloc_pages = (byte_count + 4095) / 4096;
    let alloc_pages = if alloc_pages == 0 { 1 } else { alloc_pages };

    // SAFETY: self_mmap returns zero-initialized memory.
    let ptr = unsafe { super::self_mmap(alloc_pages) };
    if ptr.is_null() {
        return (core::ptr::null_mut(), 0);
    }
    (ptr as *mut u64, word_count as u16)
}

/// Free a COW bitmap from a region (null the pointer).
pub(crate) fn free_cow_bitmap(region: *mut MmRegion) {
    // SAFETY: region is a valid mutable pointer.
    unsafe {
        let r = &mut *region;
        if !r.cow_bitmap.is_null() {
            // In this no_std environment without munmap for self_mmap,
            // we just null the pointer. The memory is effectively leaked
            // but bounded (one bitmap per region lifetime).
            r.cow_bitmap = core::ptr::null_mut();
            r.cow_bitmap_words = 0;
        }
    }
}

/// MM_REGISTER: init/procmgr registers a new client.
///   MR0 = client badge
///   MR1 = heap_base
///   MR2 = mmap_base
///   MR3 = pid
///   + cap transfer: client's VSpace cap
pub(crate) unsafe fn handle_mm_register(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let heap_base = (*msg).regs[1];
        let mmap_base = (*msg).regs[2];
        let pid = (*msg).regs[3] as u32;

        if client_badge == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Check for duplicate
        if !find_client_by_badge(client_badge).is_null() {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] REGISTER: duplicate badge=");
            lb.hex(client_badge);
            lb.str(b"\n");
            lb.flush();
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        // Find free slot in client table (grows if needed)
        let slot = find_free_client_slot();
        if slot.is_null() {
            super::puts(b"[MMSRV] REGISTER: client table full, grow failed\n");
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // The VSpace cap was transferred into the current receive slot.
        let vspace_cap = *(&raw const super::CURRENT_RECV_SLOT);

        *slot = MmClient {
            badge: client_badge,
            pid,
            active: true,
            vspace_cap,
            heap_base,
            heap_current: heap_base,
            mmap_next: mmap_base,
            regions: core::ptr::null_mut(),
            region_count: 0,
            region_cap: 0,
        };
        *(&raw mut super::CLIENT_COUNT) += 1;

        // This handler permanently keeps the VSpace cap
        super::mark_recv_slot_kept();

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] registered client badge=");
            lb.hex(client_badge);
            lb.str(b" pid=");
            lb.hex(pid as u64);
            lb.str(b" heap=");
            lb.hex(heap_base);
            lb.str(b" mmap=");
            lb.hex(mmap_base);
            lb.str(b"\n");
            lb.flush();
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_DEREGISTER: procmgr removes a client on exit.
///   MR0 = client badge
pub(crate) unsafe fn handle_mm_deregister(msg: *const SaltyMsg, _caller_badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let pid = (*client).pid;
        let vspace_cap = (*client).vspace_cap;

        // Clean up all frame caps tracked in client regions
        let region_count = (*client).region_count;
        let regions = (*client).regions;
        if !regions.is_null() {
            for ri in 0..region_count {
                let r = regions.add(ri);
                if (*r).active {
                    let fcaps = (*r).frame_caps;
                    if !fcaps.is_null() {
                        for fi in 0..(*r).frame_count as usize {
                            let fc = *fcaps.add(fi);
                            if fc != 0 {
                                invoke::cnode_delete(super::CAP_SELF_CSPACE, fc);
                            }
                        }
                    }
                    free_cow_bitmap(r);
                    (*r).active = false;
                }
            }
        }

        // Tear down COW pool before deleting the VSpace cap
        if vspace_cap != 0 {
            crate::pool::teardown_pool(vspace_cap);
        }

        // Clean up the VSpace cap we hold
        if vspace_cap != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, vspace_cap);
        }

        (*client).active = false;
        (*client).badge = 0;
        *(&raw mut super::CLIENT_COUNT) -= 1;

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] deregistered client badge=");
            lb.hex(client_badge);
            lb.str(b" pid=");
            lb.hex(pid as u64);
            lb.str(b"\n");
            lb.flush();
        }

        (*reply).label = SALTY_OK;
    }
}

/// MM_GET_CLIENT_STATS: return memory stats for a client identified by PID.
/// Request: regs[0] = pid
/// Reply: regs[0]=heap_base, regs[1]=heap_current, regs[2]=region_count, regs[3]=total_pages
pub(crate) unsafe fn handle_mm_get_client_stats(msg: *const SaltyMsg, _badge: u64, reply: *mut SaltyMsg) {
    unsafe {
        let pid = (*msg).regs[0] as u32;
        let ptr = *(&raw const super::CLIENTS_PTR);
        let cap = *(&raw const super::CLIENTS_CAP);
        let mut found = false;
        for i in 0..cap {
            let c = ptr.add(i);
            if (*c).active && (*c).pid == pid {
                (*reply).regs[0] = (*c).heap_base;
                (*reply).regs[1] = (*c).heap_current;
                (*reply).regs[2] = (*c).region_count as u64;
                let mut total_pages: u64 = 0;
                for r in 0..(*c).region_count {
                    let region = (*c).regions.add(r);
                    if (*region).active {
                        total_pages += (*region).frame_count as u64;
                    }
                }
                (*reply).regs[3] = total_pages;
                (*reply).label = SALTY_OK;
                (*reply).length = 4;
                found = true;
                break;
            }
        }
        if !found {
            (*reply).label = SALTY_NOT_FOUND;
        }
    }
}
