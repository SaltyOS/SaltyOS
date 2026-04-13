use crate::client::find_client_by_badge;
use crate::types::*;
use trona::consts::kernel::*;
use trona::consts::server::MMAP_BACKING_SHM;
use trona::invoke;
use trona::types::core::*;

unsafe fn destroy_shm_object(shm: *mut ShmObject) {
    unsafe {
        if shm.is_null() || !(*shm).active {
            return;
        }

        for i in 0..(*shm).page_count as usize {
            let frame_cap = *(*shm).frame_caps.add(i);
            if frame_cap != 0 {
                super::frame_pool_push(frame_cap);
                *(*shm).frame_caps.add(i) = 0;
            }
        }

        (*shm).id = 0;
        (*shm).active = false;
        (*shm).page_count = 0;
    }
}

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

pub(crate) unsafe fn map_shm_frames(
    vspace_cap: Cap,
    shm: *const ShmObject,
    page_offset: usize,
    base: u64,
    num_pages: usize,
    flags: u64,
) -> u64 {
    unsafe {
        if shm.is_null() || num_pages == 0 {
            return TRONA_INVALID_ARGUMENT;
        }

        let end_page = match page_offset.checked_add(num_pages) {
            Some(v) => v,
            None => return TRONA_INVALID_ARGUMENT,
        };
        if end_page > (*shm).page_count as usize {
            return TRONA_INVALID_ARGUMENT;
        }

        for i in 0..num_pages {
            let err = invoke::vspace_map(
                vspace_cap,
                *(*shm).frame_caps.add(page_offset + i),
                base + i as u64 * 4096,
                flags,
            );
            if err != 0 {
                for j in 0..i {
                    invoke::vspace_unmap(vspace_cap, base + j as u64 * 4096);
                }
                return TRONA_BAD_ADDRESS;
            }
        }

        TRONA_OK
    }
}

unsafe fn find_free_shm_slot() -> *mut ShmObject {
    unsafe {
        let mut shm_ptr = *(&raw const super::SHM_PTR);
        let old_cap = *(&raw const super::SHM_CAP);
        for i in 0..old_cap {
            let obj = shm_ptr.add(i);
            if !(*obj).active {
                return obj;
            }
        }

        let new_cap = if old_cap == 0 { 1 } else { old_cap * 2 };
        let new_bytes = new_cap * core::mem::size_of::<ShmObject>();
        let new_pages = core::cmp::max(1, (new_bytes + 4095) / 4096);
        let new_buf = super::tracked_alloc_pages(new_pages);
        if new_buf.ptr.is_null() {
            return core::ptr::null_mut();
        }
        let new_ptr = new_buf.ptr as *mut ShmObject;
        for i in 0..new_cap {
            *new_ptr.add(i) = ShmObject::zeroed();
        }
        for i in 0..old_cap {
            *new_ptr.add(i) = *shm_ptr.add(i);
        }
        shm_ptr = new_ptr;
        let old_buf = *(&raw const super::SHM_BUF);
        *(&raw mut super::SHM_BUF) = new_buf;
        *(&raw mut super::SHM_PTR) = shm_ptr;
        *(&raw mut super::SHM_CAP) = new_cap;
        super::tracked_free_pages(old_buf);
        shm_ptr.add(old_cap)
    }
}

unsafe fn ensure_shm_frame_capacity(shm: *mut ShmObject, required_pages: usize) -> bool {
    unsafe {
        if shm.is_null() {
            return false;
        }
        if (*shm).frame_cap_capacity as usize >= required_pages {
            return true;
        }

        let old_cap = (*shm).frame_cap_capacity as usize;
        let new_cap = core::cmp::max(required_pages, core::cmp::max(1, old_cap.saturating_mul(2)));
        let new_bytes = new_cap * core::mem::size_of::<Cap>();
        let new_pages = core::cmp::max(1, (new_bytes + 4095) / 4096);
        let new_buf = super::tracked_alloc_pages(new_pages);
        if new_buf.ptr.is_null() {
            return false;
        }
        let new_ptr = new_buf.ptr as *mut Cap;
        for i in 0..new_cap {
            *new_ptr.add(i) = 0;
        }
        for i in 0..(*shm).page_count as usize {
            *new_ptr.add(i) = *(*shm).frame_caps.add(i);
        }
        let old_buf = (*shm).frame_caps_buf;
        (*shm).frame_caps = new_ptr;
        (*shm).frame_cap_capacity = new_cap as u32;
        (*shm).frame_caps_buf = new_buf;
        super::tracked_free_pages(old_buf);
        true
    }
}

unsafe fn shm_shrink_conflicts(shm_id: u64, new_pages: usize) -> bool {
    unsafe {
        let Some(new_size) = (new_pages as u64).checked_mul(4096) else {
            return true;
        };
        let clients = *(&raw const super::CLIENTS_PTR);
        let client_cap = *(&raw const super::CLIENTS_CAP);
        for i in 0..client_cap {
            let client = clients.add(i);
            if !(*client).active {
                continue;
            }
            let regions = (*client).regions;
            if regions.is_null() {
                continue;
            }
            for ri in 0..(*client).region_count {
                let region = regions.add(ri);
                if !(*region).active
                    || (*region).backing_kind != MMAP_BACKING_SHM as u8
                    || (*region).backing_id0 != shm_id
                {
                    continue;
                }
                let Some(region_end) = (*region).backing_file_offset.checked_add((*region).length)
                else {
                    return true;
                };
                if region_end > new_size {
                    return true;
                }
            }
        }
        false
    }
}

unsafe fn resize_shm_object(shm: *mut ShmObject, new_pages: usize) -> u64 {
    unsafe {
        if shm.is_null() || !(*shm).active || new_pages == 0 {
            return TRONA_INVALID_ARGUMENT;
        }

        let current_pages = (*shm).page_count as usize;
        if current_pages == new_pages {
            return TRONA_OK;
        }

        if new_pages < current_pages {
            if shm_shrink_conflicts((*shm).id, new_pages) {
                return TRONA_INVALID_OPERATION;
            }
            for i in new_pages..current_pages {
                let frame_cap = *(*shm).frame_caps.add(i);
                if frame_cap != 0 {
                    super::frame_pool_push(frame_cap);
                    *(*shm).frame_caps.add(i) = 0;
                }
            }
            (*shm).page_count = new_pages as u32;
            return TRONA_OK;
        }

        if !ensure_shm_frame_capacity(shm, new_pages) {
            return TRONA_OUT_OF_MEMORY;
        }

        for i in current_pages..new_pages {
            let frame_slot = match super::alloc_frame() {
                Some(s) => s,
                None => {
                    for j in current_pages..i {
                        let cap = *(*shm).frame_caps.add(j);
                        if cap != 0 {
                            super::frame_pool_push(cap);
                            *(*shm).frame_caps.add(j) = 0;
                        }
                    }
                    return TRONA_OUT_OF_MEMORY;
                }
            };
            *(*shm).frame_caps.add(i) = frame_slot;
        }
        (*shm).page_count = new_pages as u32;
        TRONA_OK
    }
}

/// MM_SHM_CREATE: allocate frames for a SHM object.
///   MR0 = shm_id
///   MR1 = num_pages
///   Reply: label = TRONA_OK or error
pub(crate) unsafe fn handle_mm_shm_create(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let num_pages = (*msg).regs[1] as usize;
        if num_pages == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }
        if !find_shm_by_id(shm_id).is_null() {
            (*reply).label = TRONA_ALREADY_EXISTS;
            return;
        }

        let free_slot = find_free_shm_slot();
        if free_slot.is_null() || !ensure_shm_frame_capacity(free_slot, num_pages) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        for i in 0..num_pages {
            let frame_slot = match super::alloc_frame() {
                Some(s) => s,
                None => {
                    for j in 0..i {
                        let cap = *(*free_slot).frame_caps.add(j);
                        if cap != 0 {
                            super::frame_pool_push(cap);
                            *(*free_slot).frame_caps.add(j) = 0;
                        }
                    }
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
            *(*free_slot).frame_caps.add(i) = frame_slot;
        }

        (*free_slot).id = shm_id;
        (*free_slot).active = true;
        (*free_slot).page_count = num_pages as u32;

        trona::udebug!(|_lb| {
            _lb.str(b"[MMSRV] SHM create id=");
            _lb.hex(shm_id);
            _lb.str(b" pages=");
            _lb.hex(num_pages as u64);
            _lb.str(b"\n");
        });

        (*reply).label = TRONA_OK;
    }
}

/// MM_SHM_RESIZE: resize an existing SHM object's backing.
///   MR0 = shm_id
///   MR1 = num_pages
///   Reply: label = TRONA_OK or error
pub(crate) unsafe fn handle_mm_shm_resize(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let num_pages = (*msg).regs[1] as usize;
        let shm = find_shm_by_id(shm_id);
        if shm.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }
        (*reply).label = resize_shm_object(shm, num_pages);
    }
}

/// MM_SHM_DESTROY: release backing frames for a SHM object.
///   MR0 = shm_id
///   Reply: label = TRONA_OK
pub(crate) unsafe fn handle_mm_shm_destroy(
    msg: *const TronaMsg,
    _caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let shm = find_shm_by_id(shm_id);
        if !shm.is_null() {
            destroy_shm_object(shm);
        }
        (*reply).label = TRONA_OK;
    }
}

/// MM_SHM_MAP: map SHM frames into a client's VSpace.
///   MR0 = shm_id
///   MR1 = client badge
///   MR2 = vaddr
///   MR3 = prot (vspace flags)
///   Reply: label = TRONA_OK, MR0 = mapped_base
pub(crate) unsafe fn handle_mm_shm_map(
    msg: *const TronaMsg,
    caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_badge = if (*msg).regs[1] == 0 {
            caller_badge
        } else {
            (*msg).regs[1]
        };
        let requested_vaddr = (*msg).regs[2];
        let flags = (*msg).regs[3];

        let shm = find_shm_by_id(shm_id);
        if shm.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Auto-pick vaddr from client's mmap region when caller passes 0
        let actual_vaddr = if requested_vaddr == 0 {
            (*client).mmap_next
        } else {
            if (requested_vaddr & 0xFFF) != 0 {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
            requested_vaddr
        };

        let vspace_cap = (*client).vspace_cap;
        let page_count = (*shm).page_count as usize;
        let length = match (page_count as u64).checked_mul(4096) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        let mapping_end = match actual_vaddr.checked_add(length) {
            Some(v) => v,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        if requested_vaddr != 0 {
            let remove_err =
                crate::mmap::remove_client_range(client, actual_vaddr, length, true, 0);
            if remove_err != TRONA_OK {
                (*reply).label = remove_err;
                return;
            }
        }

        let map_err = map_shm_frames(vspace_cap, shm, 0, actual_vaddr, page_count, flags);
        if map_err != TRONA_OK {
            (*reply).label = map_err;
            return;
        }

        if mapping_end > (*client).mmap_next {
            (*client).mmap_next = mapping_end;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = actual_vaddr;
    }
}

/// MM_SHM_UNMAP: unmap SHM frames from a client's VSpace.
///   MR0 = shm_id
///   MR1 = client badge
///   MR2 = vaddr (base address of the mapping)
///   Reply: label = TRONA_OK
pub(crate) unsafe fn handle_mm_shm_unmap(
    msg: *const TronaMsg,
    caller_badge: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_badge = if (*msg).regs[1] == 0 {
            caller_badge
        } else {
            (*msg).regs[1]
        };
        let vaddr = (*msg).regs[2];

        let shm = find_shm_by_id(shm_id);
        if shm.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let client = find_client_by_badge(client_badge);
        if client.is_null() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        // Unmap each SHM page from the client's VSpace
        if vaddr != 0 {
            let vspace_cap = (*client).vspace_cap;
            for i in 0..(*shm).page_count as usize {
                invoke::vspace_unmap(vspace_cap, vaddr + i as u64 * 4096);
            }
        }

        (*reply).label = TRONA_OK;
    }
}
