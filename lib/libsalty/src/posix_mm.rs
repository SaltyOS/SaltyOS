//! POSIX memory management (brk, sbrk, mmap, munmap, mprotect)
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::invoke;
use crate::types::*;

static mut MM: PosixMmState = PosixMmState {
    untyped: 0,
    vspace: 0,
    cspace: 0,
    next_frame_slot: 0,
    max_frame_slot: 0,
    heap_base: 0,
    heap_current: 0,
    mmap_base: 0,
    mmap_next: 0,
    regions: {
        const ZERO: PosixMmRegion = PosixMmRegion::zeroed();
        [ZERO; MM_MAX_REGIONS]
    },
    heap_frame_slots: [0; MM_MAX_PAGES_PER_REGION],
    initialized: 0,
};

const MM_UT_SCAN_END_FALLBACK: Cap = 200;
static mut MM_NEXT_UT_HINT: Cap = CAP_UNTYPED_START;

fn untyped_scan_end() -> Cap {
    let mut end = MM_UT_SCAN_END_FALLBACK;
    let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
    if info.error == 0 {
        unsafe {
            let ctx = &raw const crate::__salty_ipc_ctx;
            if !(*ctx).ipc_buffer.is_null() {
                let num_slots = (*(*ctx).ipc_buffer).msg[3];
                if num_slots > CAP_UNTYPED_START && num_slots < end {
                    end = num_slots;
                }
            }
        }
    }

    if end <= CAP_UNTYPED_START {
        CAP_UNTYPED_START + 1
    } else {
        end
    }
}

unsafe fn try_retype_frame_any_untyped(frame_slot: Cap) -> i32 {
    unsafe {
        let mut err = invoke::untyped_retype(MM.untyped, OBJ_FRAME, 0, frame_slot);
        if err == 0 {
            MM_NEXT_UT_HINT = MM.untyped;
            return 0;
        }

        let start = CAP_UNTYPED_START;
        let end = untyped_scan_end();

        let mut first = MM_NEXT_UT_HINT;
        if first < start || first >= end {
            first = start;
        }

        let mut best_err = err;

        for ut in first..end {
            if ut == MM.untyped {
                continue;
            }
            err = invoke::untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
            if err == 0 {
                MM.untyped = ut;
                MM_NEXT_UT_HINT = ut;
                return 0;
            }
            if err != SALTY_INVALID_CAPABILITY as i32
                && err != SALTY_INVALID_OPERATION as i32
                && err != SALTY_NOT_FOUND as i32
            {
                best_err = err;
            }
        }

        for ut in start..first {
            if ut == MM.untyped {
                continue;
            }
            err = invoke::untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
            if err == 0 {
                MM.untyped = ut;
                MM_NEXT_UT_HINT = ut;
                return 0;
            }
            if err != SALTY_INVALID_CAPABILITY as i32
                && err != SALTY_INVALID_OPERATION as i32
                && err != SALTY_NOT_FOUND as i32
            {
                best_err = err;
            }
        }

        best_err
    }
}

pub unsafe fn posix_mm_init(
    untyped: Cap,
    vspace: Cap,
    cspace: Cap,
    first_frame_slot: Cap,
    heap_base: u64,
    mmap_base: u64,
) {
    unsafe {
        MM.untyped = untyped;
        MM.vspace = vspace;
        MM.cspace = cspace;
        MM.next_frame_slot = first_frame_slot;
        MM.max_frame_slot = first_frame_slot + MM_MAX_FRAME_SLOTS;
        MM_NEXT_UT_HINT = CAP_UNTYPED_START;
        MM.heap_base = heap_base;
        MM.heap_current = heap_base;
        MM.mmap_base = mmap_base;
        MM.mmap_next = mmap_base;
        for i in 0..MM_MAX_REGIONS {
            MM.regions[i].region_type = MM_REGION_FREE;
        }
        MM.initialized = 1;
    }
}

unsafe fn alloc_frame() -> Cap {
    unsafe {
        while MM.next_frame_slot < MM.max_frame_slot {
            let slot = MM.next_frame_slot;
            MM.next_frame_slot += 1;
            if slot == 0 {
                continue;
            }
            let err = try_retype_frame_any_untyped(slot);
            if err == 0 {
                return slot;
            }
        }
        u64::MAX
    }
}

unsafe fn prot_to_flags(prot: i32) -> u64 {
    let mut flags = VSPACE_FLAG_USER;
    if prot & PROT_WRITE != 0 {
        flags |= VSPACE_FLAG_WRITABLE;
    }
    if prot & PROT_EXEC != 0 {
        flags |= VSPACE_FLAG_EXECUTABLE;
    }
    flags
}

unsafe fn map_page(frame: Cap, vaddr: u64, prot: i32) -> i32 {
    unsafe { invoke::vspace_map(MM.vspace, frame, vaddr, prot_to_flags(prot)) }
}

unsafe fn alloc_region() -> *mut PosixMmRegion {
    unsafe {
        for i in 0..MM_MAX_REGIONS {
            if MM.regions[i].region_type == MM_REGION_FREE {
                return &raw mut MM.regions[i];
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn find_region(addr: u64) -> *mut PosixMmRegion {
    unsafe {
        for i in 0..MM_MAX_REGIONS {
            let r = &mut MM.regions[i];
            if r.region_type != MM_REGION_FREE && addr >= r.base && addr < r.base + r.length {
                return r as *mut PosixMmRegion;
            }
        }
        core::ptr::null_mut()
    }
}

pub unsafe fn posix_brk(addr: u64) -> i32 {
    unsafe {
        if MM.initialized == 0 {
            return -1;
        }
        if addr < MM.heap_base {
            return -1;
        }

        let old_page = (MM.heap_current + 4095) & !4095u64;
        let new_page = (addr + 4095) & !4095u64;

        if new_page > old_page {
            let mut va = old_page;
            while va < new_page {
                let frame = alloc_frame();
                if frame == u64::MAX {
                    return -1;
                }
                let err = map_page(frame, va, PROT_READ | PROT_WRITE);
                if err != 0 {
                    return -1;
                }
                let idx = ((va - MM.heap_base) / 4096) as usize;
                if idx < MM_MAX_PAGES_PER_REGION {
                    MM.heap_frame_slots[idx] = frame;
                }
                // Zero the page
                let p = va as *mut u8;
                for i in 0..4096usize {
                    core::ptr::write_volatile(p.add(i), 0);
                }
                va += 4096;
            }
        } else if new_page < old_page {
            let mut va = new_page;
            while va < old_page {
                invoke::vspace_unmap(MM.vspace, va);
                let idx = ((va - MM.heap_base) / 4096) as usize;
                if idx < MM_MAX_PAGES_PER_REGION && MM.heap_frame_slots[idx] != 0 {
                    invoke::cnode_delete(MM.cspace, MM.heap_frame_slots[idx]);
                    MM.heap_frame_slots[idx] = 0;
                }
                va += 4096;
            }
        }

        MM.heap_current = addr;
        0
    }
}

pub unsafe fn posix_sbrk(increment: i64) -> u64 {
    unsafe {
        if MM.initialized == 0 {
            return u64::MAX;
        }

        let old_break = MM.heap_current;
        if increment == 0 {
            return old_break;
        }

        let new_break = if increment > 0 {
            old_break + increment as u64
        } else {
            let dec = (-increment) as u64;
            if dec > old_break - MM.heap_base {
                return u64::MAX;
            }
            old_break - dec
        };

        if posix_brk(new_break) != 0 {
            return u64::MAX;
        }
        old_break
    }
}

/// fd-backed mmap: sends POSIX_VFS_MMAP to VFS, receives device untyped cap,
/// then maps it into our VSpace with WC flags.
unsafe fn posix_mmap_fd(
    _addr: *mut u8,
    length: u64,
    _prot: i32,
    _flags: i32,
    fd: i32,
    offset: i64,
) -> *mut u8 {
    unsafe {
        let len = (length + 4095) & !4095u64;
        let num_pages = len / 4096;

        // Allocate a free cap slot to receive the transferred capability
        let recv_slot = MM.next_frame_slot;
        if recv_slot >= MM.max_frame_slot {
            return usize::MAX as *mut u8;
        }
        MM.next_frame_slot += 1;

        // Prepare receive slot for IPC cap transfer
        crate::ipc::set_receive_slot_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_SELF_CSPACE,
            recv_slot,
            0,
        );

        // Send POSIX_VFS_MMAP to VFS
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_MMAP;
        msg.length = 5;
        msg.regs[0] = fd as u64;
        msg.regs[1] = offset as u64;
        msg.regs[2] = len;
        msg.regs[3] = _prot as u64;
        msg.regs[4] = _flags as u64;

        let err = crate::ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return usize::MAX as *mut u8;
        }

        // VFS returned: regs[0]=smem_len, regs[1]=pitch, regs[2]=flags_hint
        // Cap was transferred into recv_slot

        // Pick a mapping base address
        let base = MM.mmap_next;
        MM.mmap_next = base + len;

        // Map using batch device range syscall with WC flags
        let map_flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER | VSPACE_FLAG_WRITE_THROUGH;
        let (map_err, mapped) = invoke::vspace_map_device_range(
            MM.vspace,
            recv_slot,
            offset as u64,
            base,
            num_pages,
            map_flags,
        );
        if map_err != 0 || mapped != num_pages {
            return usize::MAX as *mut u8;
        }

        // Track in region table
        let region = alloc_region();
        if !region.is_null() {
            (*region).base = base;
            (*region).length = len;
            (*region).region_type = MM_REGION_MMAP;
            (*region).prot = _prot as u8;
            (*region).num_pages = num_pages as u16;
            // Store the device untyped cap slot for cleanup
            (*region).frame_slots[0] = recv_slot;
        }

        base as *mut u8
    }
}

pub unsafe fn posix_mmap(
    addr: *mut u8,
    length: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> *mut u8 {
    unsafe {
        if MM.initialized == 0 || length == 0 {
            return usize::MAX as *mut u8; // MAP_FAILED
        }

        // fd-backed mmap (e.g. /dev/fb0): delegate to VFS for cap transfer
        if fd >= 0 && (flags & MAP_ANONYMOUS) == 0 {
            return posix_mmap_fd(addr, length, prot, flags, fd, offset);
        }

        if (flags & MAP_ANONYMOUS) == 0 {
            return usize::MAX as *mut u8; // MAP_FAILED
        }

        let len = (length + 4095) & !4095u64;
        let num_pages = (len / 4096) as usize;

        if num_pages > MM_MAX_PAGES_PER_REGION {
            return usize::MAX as *mut u8;
        }

        let region = alloc_region();
        if region.is_null() {
            return usize::MAX as *mut u8;
        }

        let base = if (flags & MAP_FIXED) != 0 && !addr.is_null() {
            let fixed_base = (addr as u64) & !4095u64;
            let existing = find_region(fixed_base);
            if !existing.is_null() && (*existing).region_type == MM_REGION_MMAP {
                posix_munmap((*existing).base as *mut u8, (*existing).length);
            }
            fixed_base
        } else {
            let b = MM.mmap_next;
            MM.mmap_next = b + len;
            b
        };

        (*region).base = base;
        (*region).length = len;
        (*region).region_type = MM_REGION_MMAP;
        (*region).prot = prot as u8;
        (*region).num_pages = num_pages as u16;

        for i in 0..num_pages {
            let frame = alloc_frame();
            if frame == u64::MAX {
                for j in 0..i {
                    invoke::vspace_unmap(MM.vspace, base + j as u64 * 4096);
                }
                (*region).region_type = MM_REGION_FREE;
                return usize::MAX as *mut u8;
            }
            (*region).frame_slots[i] = frame;

            let err = map_page(frame, base + i as u64 * 4096, prot);
            if err != 0 {
                for j in 0..i {
                    invoke::vspace_unmap(MM.vspace, base + j as u64 * 4096);
                }
                (*region).region_type = MM_REGION_FREE;
                return usize::MAX as *mut u8;
            }

            // Zero the page
            let p = (base + i as u64 * 4096) as *mut u8;
            for k in 0..4096usize {
                core::ptr::write_volatile(p.add(k), 0);
            }
        }

        base as *mut u8
    }
}

pub unsafe fn posix_munmap(addr: *mut u8, _length: u64) -> i32 {
    unsafe {
        if MM.initialized == 0 {
            return -1;
        }

        let base = addr as u64;
        let region = find_region(base);
        if region.is_null() || (*region).region_type != MM_REGION_MMAP {
            return -1;
        }
        if base != (*region).base {
            return -1;
        }

        for i in 0..(*region).num_pages as usize {
            invoke::vspace_unmap(MM.vspace, (*region).base + i as u64 * 4096);
            if (*region).frame_slots[i] != 0 {
                invoke::cnode_delete(MM.cspace, (*region).frame_slots[i]);
                (*region).frame_slots[i] = 0;
            }
        }

        (*region).region_type = MM_REGION_FREE;
        0
    }
}

pub unsafe fn posix_mprotect(addr: *mut u8, _length: u64, prot: i32) -> i32 {
    unsafe {
        if MM.initialized == 0 {
            return -1;
        }

        let base = addr as u64;
        let region = find_region(base);
        if region.is_null() || (*region).region_type != MM_REGION_MMAP {
            return -1;
        }

        for i in 0..(*region).num_pages as usize {
            let va = (*region).base + i as u64 * 4096;
            invoke::vspace_unmap(MM.vspace, va);
            let err = map_page((*region).frame_slots[i], va, prot);
            if err != 0 {
                return -1;
            }
        }

        (*region).prot = prot as u8;
        0
    }
}
