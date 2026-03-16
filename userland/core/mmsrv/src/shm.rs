use crate::types::*;
use crate::client::find_client_by_badge;
use besalt::consts::*;
use besalt::invoke;
use besalt::serial::LineBuf;
use besalt::types::*;

pub(crate) unsafe fn find_shm_by_id(id: u64) -> *mut ShmObject {
    unsafe {
        let ptr = *(&raw const super::SHM_PTR);
        let cap = *(&raw const super::SHM_CAP);
        for i in 0..cap {
            let obj = ptr.add(i);
            if (*obj).active && (*obj).id == id {
                return obj;
            }
        }
        core::ptr::null_mut()
    }
}

/// MM_SHM_CREATE: allocate frames for a SHM object.
///   MR0 = shm_id
///   MR1 = num_pages
///   Reply: label = BESALT_OK or error
pub(crate) unsafe fn handle_mm_shm_create(msg: *const BesaltMsg, _caller_badge: u64, reply: *mut BesaltMsg) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let num_pages = (*msg).regs[1] as usize;

        if num_pages == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            return;
        }

        // Check for duplicate
        if !find_shm_by_id(shm_id).is_null() {
            (*reply).label = BESALT_ALREADY_EXISTS;
            return;
        }

        // Find free slot in SHM table (grow if needed)
        let mut shm_ptr = *(&raw const super::SHM_PTR);
        let mut shm_cap = *(&raw const super::SHM_CAP);
        let mut free_slot: *mut ShmObject = core::ptr::null_mut();
        for i in 0..shm_cap {
            let obj = shm_ptr.add(i);
            if !(*obj).active {
                free_slot = obj;
                break;
            }
        }
        if free_slot.is_null() {
            // Grow
            let new_cap = shm_cap * 2;
            let new_bytes = new_cap * core::mem::size_of::<ShmObject>();
            let new_pages = (new_bytes + 4095) / 4096;
            let new_pages = if new_pages == 0 { 1 } else { new_pages };
            let new_ptr = super::self_mmap(new_pages);
            if new_ptr.is_null() {
                (*reply).label = BESALT_OUT_OF_MEMORY;
                return;
            }
            let new_ptr = new_ptr as *mut ShmObject;
            for i in 0..shm_cap {
                *new_ptr.add(i) = *shm_ptr.add(i);
            }
            free_slot = new_ptr.add(shm_cap);
            *(&raw mut super::SHM_PTR) = new_ptr;
            *(&raw mut super::SHM_CAP) = new_cap;
        }

        // Allocate frame_caps array
        let fcaps = super::alloc_frame_cap_array(num_pages);
        if fcaps.is_null() {
            (*reply).label = BESALT_OUT_OF_MEMORY;
            return;
        }

        // Allocate frames
        for i in 0..num_pages {
            let frame_slot = match super::alloc_frame() {
                Some(s) => s,
                None => {
                    for j in 0..i {
                        super::frame_pool_push(*fcaps.add(j));
                    }
                    (*reply).label = BESALT_OUT_OF_MEMORY;
                    return;
                }
            };
            *fcaps.add(i) = frame_slot;
        }

        *free_slot = ShmObject {
            id: shm_id,
            active: true,
            page_count: num_pages as u16,
            frame_caps: fcaps,
            frame_cap_capacity: num_pages as u16,
        };

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] SHM create id=");
            lb.hex(shm_id);
            lb.str(b" pages=");
            lb.hex(num_pages as u64);
            lb.str(b"\n");
            lb.flush();
        }

        (*reply).label = BESALT_OK;
    }
}

/// MM_SHM_MAP: map SHM frames into a client's VSpace.
///   MR0 = shm_id
///   MR1 = client badge
///   MR2 = vaddr
///   MR3 = prot (vspace flags)
///   Reply: label = BESALT_OK, MR0 = mapped_base
pub(crate) unsafe fn handle_mm_shm_map(msg: *const BesaltMsg, caller_badge: u64, reply: *mut BesaltMsg) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_badge = if (*msg).regs[1] == 0 { caller_badge } else { (*msg).regs[1] };
        let requested_vaddr = (*msg).regs[2];
        let flags = (*msg).regs[3];

        let shm = find_shm_by_id(shm_id);
        if shm.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }

        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }

        // Auto-pick vaddr from client's mmap region when caller passes 0
        let actual_vaddr = if requested_vaddr == 0 {
            (*client).mmap_next
        } else {
            requested_vaddr
        };

        let vspace_cap = (*client).vspace_cap;
        let page_count = (*shm).page_count as usize;

        for i in 0..page_count {
            let err = invoke::vspace_map(
                vspace_cap,
                *(*shm).frame_caps.add(i),
                actual_vaddr + i as u64 * 4096,
                flags,
            );
            if err != 0 {
                // Rollback mapped pages
                for j in 0..i {
                    invoke::vspace_unmap(vspace_cap, actual_vaddr + j as u64 * 4096);
                }
                (*reply).label = BESALT_BAD_ADDRESS;
                return;
            }
        }

        // Advance mmap_next if auto-placed
        if requested_vaddr == 0 {
            (*client).mmap_next = actual_vaddr + page_count as u64 * 4096;
        }

        (*reply).label = BESALT_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual_vaddr;
    }
}

/// MM_SHM_UNMAP: unmap SHM frames from a client's VSpace.
///   MR0 = shm_id
///   MR1 = client badge
///   MR2 = vaddr (base address of the mapping)
///   Reply: label = BESALT_OK
pub(crate) unsafe fn handle_mm_shm_unmap(msg: *const BesaltMsg, caller_badge: u64, reply: *mut BesaltMsg) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_badge = if (*msg).regs[1] == 0 { caller_badge } else { (*msg).regs[1] };
        let vaddr = (*msg).regs[2];

        let shm = find_shm_by_id(shm_id);
        if shm.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }

        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = BESALT_NOT_FOUND;
            return;
        }

        // Unmap each SHM page from the client's VSpace
        if vaddr != 0 {
            let vspace_cap = (*client).vspace_cap;
            for i in 0..(*shm).page_count as usize {
                invoke::vspace_unmap(vspace_cap, vaddr + i as u64 * 4096);
            }
        }

        (*reply).label = BESALT_OK;
    }
}
