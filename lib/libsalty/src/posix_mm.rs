//! POSIX memory management (brk, sbrk, mmap, munmap, mprotect)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Manages the user process heap and anonymous/fd-backed memory mappings.
//! The heap grows upward from `heap_base` via `brk`/`sbrk`; anonymous
//! `mmap` regions are allocated from `mmap_base` upward. Each region is
//! tracked in a fixed-size table (`MM_MAX_REGIONS`).
//!
//! All page allocation uses the per-process slot allocator (`slot_alloc`)
//! and kernel capability invocations (`untyped_retype`, `vspace_map`).
//! fd-backed mmap (e.g. framebuffer) delegates to VFS for device cap
//! transfer, then maps the device pages with write-combining flags.

use crate::consts::*;
use crate::invoke;
use crate::types::*;

/// Global memory management state. Initialized by `posix_mm_init`.
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

/// Initialize the memory manager with capability slots and VA layout.
///
/// `untyped` is the memory source for frame allocation, `vspace`/`cspace`
/// are the process's own root capabilities, `first_frame_slot` is the
/// starting CNode slot for new frame objects, and `heap_base`/`mmap_base`
/// set the virtual address origins for heap and mmap regions.
///
/// # Safety
/// Must be called exactly once during process startup.
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

/// Allocate a CNode slot and retype a frame into it from the slot allocator.
/// Returns the frame cap, or `u64::MAX` on failure.
unsafe fn alloc_frame() -> Cap {
    if !crate::slot_alloc::slot_alloc_is_initialized() {
        return u64::MAX;
    }
    match crate::slot_alloc::slot_alloc_frame() {
        Some(slot) => slot,
        None => u64::MAX,
    }
}

/// Convert POSIX protection flags (PROT_READ/WRITE/EXEC) to VSpace flags.
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

/// Map a frame at `vaddr` with POSIX protection flags.
unsafe fn map_page(frame: Cap, vaddr: u64, prot: i32) -> i32 {
    unsafe { invoke::vspace_map(MM.vspace, frame, vaddr, prot_to_flags(prot)) }
}

/// Find a free slot in the region table. Returns null if all slots are in use.
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

/// Find the region containing virtual address `addr`. Returns null if not found.
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

/// Roll back heap growth in [start_va, end_va) by unmapping pages and
/// deleting tracked frame caps.
unsafe fn rollback_heap_growth(start_va: u64, end_va: u64) {
    unsafe {
        let mut va = start_va;
        while va < end_va {
            invoke::vspace_unmap(MM.vspace, va);
            let idx = ((va - MM.heap_base) / 4096) as usize;
            if idx < MM_MAX_PAGES_PER_REGION {
                let frame = MM.heap_frame_slots[idx];
                if frame != 0 {
                    invoke::cnode_delete(MM.cspace, frame);
                    MM.heap_frame_slots[idx] = 0;
                }
            }
            va += 4096;
        }
    }
}

/// Roll back anonymous mmap pages already mapped in `region`.
unsafe fn rollback_mmap_pages(region: *mut PosixMmRegion, mapped_pages: usize) {
    unsafe {
        for i in 0..mapped_pages {
            let va = (*region).base + i as u64 * 4096;
            invoke::vspace_unmap(MM.vspace, va);
            let frame = (*region).frame_slots[i];
            if frame != 0 {
                invoke::cnode_delete(MM.cspace, frame);
                (*region).frame_slots[i] = 0;
            }
        }
    }
}

/// Find the first available mmap hole of `len` bytes (page-aligned).
unsafe fn find_mmap_hole(len: u64) -> Option<u64> {
    unsafe {
        let mut candidate = MM.mmap_base;
        loop {
            let candidate_end = candidate.checked_add(len)?;
            let mut overlap_end: u64 = 0;
            let mut overlapped = false;

            for i in 0..MM_MAX_REGIONS {
                let r = &MM.regions[i];
                if r.region_type != MM_REGION_MMAP {
                    continue;
                }
                let r_start = r.base;
                let r_end = r.base.checked_add(r.length)?;
                if candidate_end <= r_start || candidate >= r_end {
                    continue;
                }
                if !overlapped || r_end < overlap_end {
                    overlap_end = r_end;
                    overlapped = true;
                }
            }

            if !overlapped {
                return Some(candidate);
            }
            if overlap_end <= candidate {
                return None;
            }
            candidate = overlap_end;
        }
    }
}

/// Reserve an mmap base for `len` bytes using first-fit hole search.
/// Advances `mmap_next` only when the chosen range reaches past current top.
unsafe fn reserve_mmap_base(len: u64) -> Option<u64> {
    unsafe {
        let base = find_mmap_hole(len)?;
        let end = base.checked_add(len)?;
        if end > MM.mmap_next {
            MM.mmap_next = end;
        }
        Some(base)
    }
}

/// Set the program break (end of heap) to `addr`.
///
/// If `addr` is above the current break, allocates and maps new pages.
/// If below, unmaps and deletes the freed pages. New pages are zeroed.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_brk(addr: u64) -> i32 {
    unsafe {
        if MM.initialized == 0 {
            return -1;
        }
        if addr < MM.heap_base {
            return -1;
        }

        let old_page = match MM.heap_current.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => return -1,
        };
        let new_page = match addr.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => return -1,
        };
        let max_heap_end = match MM
            .heap_base
            .checked_add((MM_MAX_PAGES_PER_REGION as u64) * 4096)
        {
            Some(v) => v,
            None => return -1,
        };
        if new_page > max_heap_end {
            return -1;
        }

        if new_page > old_page {
            let mut va = old_page;
            while va < new_page {
                let frame = alloc_frame();
                if frame == u64::MAX {
                    rollback_heap_growth(old_page, va);
                    return -1;
                }
                let idx = ((va - MM.heap_base) / 4096) as usize;
                if idx >= MM_MAX_PAGES_PER_REGION || MM.heap_frame_slots[idx] != 0 {
                    invoke::cnode_delete(MM.cspace, frame);
                    rollback_heap_growth(old_page, va);
                    return -1;
                }
                let err = map_page(frame, va, PROT_READ | PROT_WRITE);
                if err != 0 {
                    invoke::cnode_delete(MM.cspace, frame);
                    rollback_heap_growth(old_page, va);
                    return -1;
                }
                MM.heap_frame_slots[idx] = frame;
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

/// Increment the program break by `increment` bytes.
///
/// Returns the previous break address on success, or `u64::MAX` on error.
/// `increment == 0` returns the current break without changing it.
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
        if offset < 0 {
            return usize::MAX as *mut u8;
        }

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => return usize::MAX as *mut u8,
        };
        let num_pages = len / 4096;
        if num_pages > u16::MAX as u64 {
            return usize::MAX as *mut u8;
        }

        // Region tracking must be available before mapping so failure paths can
        // clean up deterministically.
        let region = alloc_region();
        if region.is_null() {
            return usize::MAX as *mut u8;
        }

        // Allocate a free cap slot to receive the transferred capability
        let recv_slot = match crate::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => return usize::MAX as *mut u8,
        };

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
            // If transfer happened before error, drop any received cap.
            invoke::cnode_delete(MM.cspace, recv_slot);
            return usize::MAX as *mut u8;
        }

        // VFS returned: regs[0]=smem_len, regs[1]=pitch, regs[2]=flags_hint
        // Cap was transferred into recv_slot

        // Pick a mapping base address
        let old_mmap_next = MM.mmap_next;
        let base = match reserve_mmap_base(len) {
            Some(v) => v,
            None => {
                invoke::cnode_delete(MM.cspace, recv_slot);
                return usize::MAX as *mut u8;
            }
        };

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
            for i in 0..mapped {
                invoke::vspace_unmap(MM.vspace, base + i * 4096);
            }
            invoke::cnode_delete(MM.cspace, recv_slot);
            MM.mmap_next = old_mmap_next;
            return usize::MAX as *mut u8;
        }

        // Track in region table
        *region = PosixMmRegion::zeroed();
        (*region).base = base;
        (*region).length = len;
        (*region).region_type = MM_REGION_MMAP;
        (*region).prot = _prot as u8;
        (*region).num_pages = num_pages as u16;
        // Store the device untyped cap slot for cleanup
        (*region).frame_slots[0] = recv_slot;

        base as *mut u8
    }
}

/// Map pages into the process address space.
///
/// Supports two modes:
/// - **Anonymous** (`MAP_ANONYMOUS`): allocates fresh frames, zeroes them,
///   and maps at the next available mmap address (or at `addr` with `MAP_FIXED`).
/// - **fd-backed** (`fd >= 0`): delegates to `posix_mmap_fd` which requests
///   a device capability from VFS and maps it with write-combining flags.
///
/// Returns the mapped base address, or `MAP_FAILED` (usize::MAX) on error.
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

        let len = match length.checked_add(4095) {
            Some(v) => v & !4095u64,
            None => return usize::MAX as *mut u8,
        };
        let num_pages = (len / 4096) as usize;

        if num_pages > MM_MAX_PAGES_PER_REGION {
            return usize::MAX as *mut u8;
        }

        let region = alloc_region();
        if region.is_null() {
            return usize::MAX as *mut u8;
        }

        let mut restore_mmap_next_on_fail = false;
        let old_mmap_next = MM.mmap_next;
        let base = if (flags & MAP_FIXED) != 0 && !addr.is_null() {
            let fixed_base = (addr as u64) & !4095u64;
            let existing = find_region(fixed_base);
            if !existing.is_null() && (*existing).region_type == MM_REGION_MMAP {
                posix_munmap((*existing).base as *mut u8, (*existing).length);
            }
            fixed_base
        } else {
            match reserve_mmap_base(len) {
                Some(v) => {
                    restore_mmap_next_on_fail = true;
                    v
                }
                None => return usize::MAX as *mut u8,
            }
        };

        *region = PosixMmRegion::zeroed();
        (*region).base = base;
        (*region).length = len;
        (*region).region_type = MM_REGION_MMAP;
        (*region).prot = prot as u8;
        (*region).num_pages = num_pages as u16;

        for i in 0..num_pages {
            let frame = alloc_frame();
            if frame == u64::MAX {
                rollback_mmap_pages(region, i);
                (*region).region_type = MM_REGION_FREE;
                if restore_mmap_next_on_fail {
                    MM.mmap_next = old_mmap_next;
                }
                return usize::MAX as *mut u8;
            }
            (*region).frame_slots[i] = frame;

            let err = map_page(frame, base + i as u64 * 4096, prot);
            if err != 0 {
                invoke::cnode_delete(MM.cspace, frame);
                (*region).frame_slots[i] = 0;
                rollback_mmap_pages(region, i);
                (*region).region_type = MM_REGION_FREE;
                if restore_mmap_next_on_fail {
                    MM.mmap_next = old_mmap_next;
                }
                return usize::MAX as *mut u8;
            }
        }

        base as *mut u8
    }
}

/// Unmap a previously mmap'd region at `addr`.
///
/// Unmaps all pages in the region, deletes frame capabilities, and frees
/// the region table entry. Returns 0 on success, -1 on error.
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

        let pages = (*region).num_pages as usize;
        for i in 0..pages {
            invoke::vspace_unmap(MM.vspace, (*region).base + i as u64 * 4096);
        }

        if pages > MM_MAX_PAGES_PER_REGION {
            // Device-backed mmap can span more than frame_slots[] capacity.
            // For that case we store only the transferred device cap in slot 0.
            if (*region).frame_slots[0] != 0 {
                invoke::cnode_delete(MM.cspace, (*region).frame_slots[0]);
                (*region).frame_slots[0] = 0;
            }
        } else {
            for i in 0..pages {
                if (*region).frame_slots[i] != 0 {
                    invoke::cnode_delete(MM.cspace, (*region).frame_slots[i]);
                    (*region).frame_slots[i] = 0;
                }
            }
        }

        (*region).region_type = MM_REGION_FREE;
        (*region).num_pages = 0;
        0
    }
}

/// Change protection flags on an mmap'd region.
///
/// Unmaps and remaps each page with the new `prot` flags.
/// Returns 0 on success, -1 on error.
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
        if (*region).num_pages as usize > MM_MAX_PAGES_PER_REGION {
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
