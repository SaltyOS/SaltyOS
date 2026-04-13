use crate::types::*;
use trona::consts::kernel::*;
use trona::types::core::*;

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
        let new_buf = super::tracked_alloc_pages(new_pages);
        if new_buf.ptr.is_null() {
            return core::ptr::null_mut();
        }
        let new_ptr = new_buf.ptr as *mut MmClient;
        // Copy old entries
        for i in 0..cap {
            *new_ptr.add(i) = *ptr.add(i);
        }
        // First free slot is at old cap
        let free = new_ptr.add(cap);
        let old_buf = *(&raw const super::CLIENTS_BUF);
        *(&raw mut super::CLIENTS_BUF) = new_buf;
        *(&raw mut super::CLIENTS_PTR) = new_ptr;
        *(&raw mut super::CLIENTS_CAP) = new_cap;
        super::tracked_free_pages(old_buf);
        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] clients grown to ");
            _lb.hex(new_cap as u64);
            _lb.str(b"\n");
        });
        free
    }
}

/// Add a region to a client. Returns pointer to the new region or null.
pub(crate) unsafe fn client_reserve_regions(client: *mut MmClient, additional: usize) -> bool {
    unsafe {
        let count = (*client).region_count;
        let required = match count.checked_add(additional) {
            Some(v) => v,
            None => return false,
        };
        let cap = (*client).region_cap;

        if required <= cap {
            return true;
        }

        let mut new_cap = if cap == 0 { REGION_INITIAL_CAP } else { cap };
        while new_cap < required {
            new_cap = match new_cap.checked_mul(2) {
                Some(v) => v,
                None => return false,
            };
        }

        let new_bytes = match new_cap.checked_mul(core::mem::size_of::<MmRegion>()) {
            Some(v) => v,
            None => return false,
        };
        let new_pages = (new_bytes + 4095) / 4096;
        let new_pages = if new_pages == 0 { 1 } else { new_pages };
        let new_buf = super::tracked_alloc_pages(new_pages);
        if new_buf.ptr.is_null() {
            return false;
        }
        let new_ptr = new_buf.ptr as *mut MmRegion;

        let old_ptr = (*client).regions;
        if !old_ptr.is_null() {
            for i in 0..count {
                *new_ptr.add(i) = *old_ptr.add(i);
            }
        }

        let old_buf = (*client).regions_buf;
        (*client).regions = new_ptr;
        (*client).region_cap = new_cap;
        (*client).regions_buf = new_buf;
        super::tracked_free_pages(old_buf);
        true
    }
}

pub(crate) unsafe fn client_add_region(client: *mut MmClient) -> *mut MmRegion {
    unsafe {
        let count = (*client).region_count;
        if !client_reserve_regions(client, 1) {
            return core::ptr::null_mut();
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
pub(crate) unsafe fn handle_mm_register(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let heap_base = (*msg).regs[1];
        let mmap_base = (*msg).regs[2];
        let pid = (*msg).regs[3] as u32;

        if client_badge == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Check for duplicate
        if !find_client_by_badge(client_badge).is_null() {
            trona::uwarn!(|_lb| {
                _lb.str(b"[MMSRV] REGISTER: duplicate badge=");
                _lb.hex(client_badge);
                _lb.str(b"\n");
            });
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        // Find free slot in client table (grows if needed)
        let slot = find_free_client_slot();
        if slot.is_null() {
            trona::uerror!(|_lb| {
                _lb.str(b"[MMSRV] REGISTER: client table full, grow failed\n");
            });
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // The VSpace cap was transferred into the current receive slot.
        let vspace_cap = *(&raw const super::CURRENT_RECV_SLOT);

        *slot = MmClient {
            badge: client_badge,
            pid,
            active: true,
            deregistering: false,
            vspace_cap,
            heap_base,
            heap_current: heap_base,
            mmap_next: mmap_base,
            regions: core::ptr::null_mut(),
            region_count: 0,
            region_cap: 0,
            regions_buf: TrackedBuffer::zeroed(),
        };
        *(&raw mut super::CLIENT_COUNT) += 1;

        // This handler permanently keeps the VSpace cap
        super::mark_recv_slot_kept();

        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] registered client badge=");
            _lb.hex(client_badge);
            _lb.str(b" pid=");
            _lb.hex(pid as u64);
            _lb.str(b" heap=");
            _lb.hex(heap_base);
            _lb.str(b" mmap=");
            _lb.hex(mmap_base);
            _lb.str(b"\n");
        });
        super::debug_log_state(b"[MMSRV] register state", slot);

        (*reply).label = TRONA_OK;
    }
}

/// MM_DEREGISTER: procmgr removes a client on exit.
///   MR0 = client badge
pub(crate) unsafe fn handle_mm_deregister(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        if (*client).deregistering {
            (*reply).label = TRONA_OK;
            return;
        }

        (*client).deregistering = true;

        let pid = (*client).pid;
        let vspace_cap = (*client).vspace_cap;
        let released_region_count = (*client).region_count;
        let released_region_cap = (*client).region_cap;
        let released_region_pages = (*client).regions_buf.pages;

        // Tear down tracked mappings before releasing MO/VSpace caps.
        // Exec reuses the same VSpace object, so dropping only the metadata
        // leaves stale VmArea state behind in the kernel and can misattribute
        // later COW faults to the wrong backing MO.
        let region_count = (*client).region_count;
        let regions = (*client).regions;
        if !regions.is_null() {
            for ri in 0..region_count {
                let r = regions.add(ri);
                if (*r).active {
                    crate::mmap::flush_writeback_region(r, (*r).base, (*r).length);
                    if vspace_cap != 0 && (*r).length != 0 {
                        let page_count = (*r).length / 4096;
                        let mut unmap_err = 0i32;
                        let mut unmap_addr = 0u64;
                        for page in 0..page_count {
                            let page_addr = (*r).base + page * 4096;
                            let err = trona::invoke::vspace_unmap(vspace_cap, page_addr);
                            if err as u64 == TRONA_NOT_FOUND {
                                continue;
                            }
                            if err != 0 && unmap_err == 0 {
                                unmap_err = err;
                                unmap_addr = page_addr;
                            }
                        }
                        if unmap_err != 0 {
                            trona::uerror!(|_lb| {
                                _lb.str(b"[MMSRV] DEREGISTER: unmap failed badge=");
                                _lb.hex(client_badge);
                                _lb.str(b" addr=");
                                _lb.hex(unmap_addr);
                                _lb.str(b" err=");
                                _lb.hex(unmap_err as u64);
                                _lb.str(b"\n");
                            });
                        }
                    }
                    crate::mmap::retire_region(client, r);
                }
            }
        }

        // Clean up the VSpace cap we hold
        if vspace_cap != 0 {
            super::recycled_cnode_delete(vspace_cap);
        }

        (*client).active = false;
        (*client).deregistering = false;
        (*client).badge = 0;
        (*client).pid = 0;
        (*client).vspace_cap = 0;
        (*client).heap_base = 0;
        (*client).heap_current = 0;
        (*client).mmap_next = 0;
        (*client).regions = core::ptr::null_mut();
        (*client).region_count = 0;
        (*client).region_cap = 0;
        let old_regions_buf = (*client).regions_buf;
        (*client).regions_buf = TrackedBuffer::zeroed();
        super::tracked_free_pages(old_regions_buf);
        *(&raw mut super::CLIENT_COUNT) -= 1;

        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] deregistered client badge=");
            _lb.hex(client_badge);
            _lb.str(b" pid=");
            _lb.hex(pid as u64);
            _lb.str(b" released_regions=");
            _lb.hex(released_region_count as u64);
            _lb.str(b" released_cap=");
            _lb.hex(released_region_cap as u64);
            _lb.str(b" released_pages=");
            _lb.hex(released_region_pages as u64);
            _lb.str(b"\n");
        });
        super::debug_log_state(b"[MMSRV] deregister state", core::ptr::null());

        (*reply).label = TRONA_OK;
    }
}

/// MM_GET_CLIENT_STATS: return memory stats for a client identified by PID.
/// Request: regs[0] = pid
/// Reply: regs[0]=heap_base, regs[1]=heap_current, regs[2]=region_count, regs[3]=total_pages
pub(crate) unsafe fn handle_mm_get_client_stats(
    msg: *const TronaMsg,
    _badge: u64,
    reply: *mut TronaMsg,
) {
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
                        total_pages += ((*region).length + 4095) / 4096;
                    }
                }
                (*reply).regs[3] = total_pages;
                (*reply).label = TRONA_OK;
                (*reply).length = 4;
                found = true;
                break;
            }
        }
        if !found {
            (*reply).label = TRONA_NOT_FOUND;
        }
    }
}
