use crate::types::*;
use besalt::consts::*;
use besalt::serial::LineBuf;
use besalt::types::*;

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

/// MM_REGISTER: init/procmgr registers a new client.
///   MR0 = client badge
///   MR1 = heap_base
///   MR2 = mmap_base
///   MR3 = pid
///   + cap transfer: client's VSpace cap
pub(crate) unsafe fn handle_mm_register(msg: *const BesaltMsg, _caller_badge: u64, reply: *mut BesaltMsg) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let heap_base = (*msg).regs[1];
        let mmap_base = (*msg).regs[2];
        let pid = (*msg).regs[3] as u32;

        if client_badge == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        // Check for duplicate
        if !find_client_by_badge(client_badge).is_null() {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] REGISTER: duplicate badge=");
            lb.hex(client_badge);
            lb.str(b"\n");
            lb.flush();
            (*reply).label = BESALT_ALREADY_EXISTS;
            return;
        }

        // Find free slot in client table (grows if needed)
        let slot = find_free_client_slot();
        if slot.is_null() {
            super::puts(b"[MMSRV] REGISTER: client table full, grow failed\n");
            (*reply).label = BESALT_OUT_OF_MEMORY;
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

        (*reply).label = BESALT_OK;
    }
}

/// MM_DEREGISTER: procmgr removes a client on exit.
///   MR0 = client badge
pub(crate) unsafe fn handle_mm_deregister(msg: *const BesaltMsg, _caller_badge: u64, reply: *mut BesaltMsg) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }

        let pid = (*client).pid;
        let vspace_cap = (*client).vspace_cap;

        // Clean up MO caps in client regions
        let region_count = (*client).region_count;
        let regions = (*client).regions;
        if !regions.is_null() {
            for ri in 0..region_count {
                let r = regions.add(ri);
                if (*r).active {
                    if (*r).mo_cap != 0 {
                        super::recycled_cnode_delete((*r).mo_cap);
                    }
                    (*r).active = false;
                }
            }
        }

        // Clean up the VSpace cap we hold
        if vspace_cap != 0 {
            super::recycled_cnode_delete(vspace_cap);
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

        (*reply).label = BESALT_OK;
    }
}

/// MM_GET_CLIENT_STATS: return memory stats for a client identified by PID.
/// Request: regs[0] = pid
/// Reply: regs[0]=heap_base, regs[1]=heap_current, regs[2]=region_count, regs[3]=total_pages
pub(crate) unsafe fn handle_mm_get_client_stats(msg: *const BesaltMsg, _badge: u64, reply: *mut BesaltMsg) {
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
                        total_pages += (*region).length / 4096;
                    }
                }
                (*reply).regs[3] = total_pages;
                (*reply).label = BESALT_OK;
                (*reply).length = 4;
                found = true;
                break;
            }
        }
        if !found {
            (*reply).label = BESALT_NOT_FOUND;
        }
    }
}
