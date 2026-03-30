use crate::types::*;
use trona::consts::*;
use trona::types::*;

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
        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] clients grown to ");
            _lb.hex(new_cap as u64);
            _lb.str(b"\n");
        });
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
pub(crate) unsafe fn handle_mm_register(msg: *const TronaMsg, _caller_badge: u64, reply: *mut TronaMsg) {
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

        (*reply).label = TRONA_OK;
    }
}

/// MM_DEREGISTER: procmgr removes a client on exit.
///   MR0 = client badge
pub(crate) unsafe fn handle_mm_deregister(msg: *const TronaMsg, _caller_badge: u64, reply: *mut TronaMsg) {
    unsafe {
        let client_badge = (*msg).regs[0];
        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let pid = (*client).pid;
        let vspace_cap = (*client).vspace_cap;

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
                        if (*r).mo_cap != 0 {
                            let page_count = (*r).length / 4096;
                            if page_count != 0 {
                                let err = trona::invoke::vspace_unmap_mo(
                                    vspace_cap,
                                    (*r).base,
                                    page_count,
                                );
                                if err != 0 {
                                    trona::uerror!(|_lb| {
                                        _lb.str(b"[MMSRV] DEREGISTER: unmap_mo failed badge=");
                                        _lb.hex(client_badge);
                                        _lb.str(b" base=");
                                        _lb.hex((*r).base);
                                        _lb.str(b" pages=");
                                        _lb.hex(page_count);
                                        _lb.str(b" err=");
                                        _lb.hex(err as u64);
                                        _lb.str(b"\n");
                                    });
                                }
                            }
                        } else {
                            let page_count = (*r).length / 4096;
                            for page in 0..page_count {
                                let _ = trona::invoke::vspace_unmap(
                                    vspace_cap,
                                    (*r).base + page * 4096,
                                );
                            }
                        }
                    }
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

        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] deregistered client badge=");
            _lb.hex(client_badge);
            _lb.str(b" pid=");
            _lb.hex(pid as u64);
            _lb.str(b"\n");
        });

        (*reply).label = TRONA_OK;
    }
}

/// MM_GET_CLIENT_STATS: return memory stats for a client identified by PID.
/// Request: regs[0] = pid
/// Reply: regs[0]=heap_base, regs[1]=heap_current, regs[2]=region_count, regs[3]=total_pages
pub(crate) unsafe fn handle_mm_get_client_stats(msg: *const TronaMsg, _badge: u64, reply: *mut TronaMsg) {
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
