//! Userspace ELF64 loader
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Loads ELF64 executables into a child process's VSpace using a
//! scratch-map strategy: each page is temporarily mapped into the
//! loader's own address space (at `scratch_vaddr`), populated with
//! segment data, then remapped into the child's VSpace with the
//! correct permissions.
//!
//! Supports both ET_EXEC (fixed address) and ET_DYN (PIE, relocated to
//! `load_base`). R_X86_64_RELATIVE relocations are applied in-place
//! via the scratch page technique.
//!
//! Frame allocation uses a pluggable strategy: callers can provide an
//! `alloc_frame_slot` callback, or fall back to internal scanning of
//! untyped capabilities.

use crate::consts::*;
use crate::invoke;
use crate::serial;
use crate::types::*;

// Standard child CSpace layout
const CAP_SELF_CSPACE: u64 = 2;
const CAP_UNTYPED_START: u64 = 16;

/// Round down to the nearest 4K page boundary.
fn page_align_down(v: u64) -> u64 {
    v & !(ELF_PAGE_SIZE - 1)
}

/// Round up to the next 4K page boundary.
fn page_align_up(v: u64) -> u64 {
    (v + ELF_PAGE_SIZE - 1) & !(ELF_PAGE_SIZE - 1)
}

/// Fallback upper bound for untyped cap scanning when CNode info is unavailable.
const ELF_UT_SCAN_END_FALLBACK: Cap = 200;
/// Hint for the last untyped that succeeded, to speed up scanning.
static mut NEXT_UT_HINT: Cap = CAP_UNTYPED_START;

/// Determine the upper bound for untyped cap scanning by querying the CNode.
fn untyped_scan_end() -> Cap {
    let mut end = ELF_UT_SCAN_END_FALLBACK;
    let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
    if info.error == 0 {
        unsafe {
            let ctx = crate::tls::current_ipc_ctx();
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

/// Try to retype a frame into `frame_slot` from any available untyped cap.
///
/// Tries the loader context's `untyped` first, then scans all untyped caps
/// starting from a cached hint. Updates `ctx.untyped` and `NEXT_UT_HINT`
/// on success to speed up future calls.
fn try_retype_frame_any_untyped(ctx: &mut ElfLoaderCtx, frame_slot: Cap) -> i32 {
    let mut err = invoke::untyped_retype(ctx.untyped, OBJ_FRAME, 0, frame_slot);
    if err == 0 {
        unsafe {
            NEXT_UT_HINT = ctx.untyped;
        }
        return 0;
    }

    let start = CAP_UNTYPED_START;
    let end = untyped_scan_end();

    let mut first = unsafe { NEXT_UT_HINT };
    if first < start || first >= end {
        first = start;
    }

    let mut best_err = err;

    for ut in first..end {
        if ut == ctx.untyped {
            continue;
        }
        err = invoke::untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
        if err == 0 {
            ctx.untyped = ut;
            unsafe {
                NEXT_UT_HINT = ut;
            }
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
        if ut == ctx.untyped {
            continue;
        }
        err = invoke::untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
        if err == 0 {
            ctx.untyped = ut;
            unsafe {
                NEXT_UT_HINT = ut;
            }
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

/// Get the next frame slot, using the callback if provided or bumping the counter.
fn next_frame_slot(ctx: &mut ElfLoaderCtx) -> Cap {
    if let Some(alloc) = ctx.alloc_frame_slot {
        unsafe { alloc(ctx.alloc_opaque) }
    } else {
        let slot = ctx.next_frame_slot;
        ctx.next_frame_slot += 1;
        slot
    }
}

/// Record a page mapping via the callback, if one is configured.
fn record_page_map(ctx: &ElfLoaderCtx, vaddr: u64, frame_cap: Cap, flags: u64) -> i32 {
    if let Some(record) = ctx.record_page {
        unsafe { record(ctx.record_opaque, vaddr, frame_cap, flags) }
    } else {
        0
    }
}

/// Convert ELF segment flags (PF_R/W/X) to VSpace mapping flags.
/// Enforces W^X: if both W and X are set, writable wins (executable is dropped).
fn phdr_to_flags(p_flags: u32) -> u64 {
    let mut flags = VSPACE_FLAG_USER;
    let w = p_flags & PF_W != 0;
    let x = p_flags & PF_X != 0;
    if w {
        flags |= VSPACE_FLAG_WRITABLE;
    } else if x {
        flags |= VSPACE_FLAG_EXECUTABLE;
    }
    flags
}

/// Convert a virtual address to its file offset using PT_LOAD segment info.
fn vaddr_to_file_offset(
    data: *const u8,
    data_len: usize,
    ehdr: &Elf64Ehdr,
    vaddr: u64,
) -> Option<usize> {
    let phdr_base = ehdr.e_phoff as usize;
    let phdr_count = ehdr.e_phnum as usize;
    let phdr_size = ehdr.e_phentsize as usize;

    for i in 0..phdr_count {
        let off = phdr_base + i * phdr_size;
        if off + core::mem::size_of::<Elf64Phdr>() > data_len {
            break;
        }
        let phdr = unsafe { &*(data.add(off) as *const Elf64Phdr) };
        if phdr.p_type != PT_LOAD {
            continue;
        }
        if vaddr < phdr.p_vaddr {
            continue;
        }
        let seg_off = vaddr - phdr.p_vaddr;
        if seg_off >= phdr.p_filesz {
            continue;
        }
        let file_off = phdr.p_offset + seg_off;
        if file_off as usize >= data_len {
            return None;
        }
        return Some(file_off as usize);
    }
    None
}

/// Apply R_X86_64_RELATIVE relocations for PIE binaries.
///
/// Reads the PT_DYNAMIC segment to find DT_RELA entries, then writes
/// each relocated value through the scratch page. Only RELATIVE relocs
/// are handled (sufficient for static PIE without symbol resolution).
unsafe fn apply_relocations(
    data: *const u8,
    data_len: usize,
    delta: u64,
    load_base: u64,
    pages: &[ElfPageEntry],
    ctx: &mut ElfLoaderCtx,
) -> i32 {
    unsafe {
        let ehdr = &*(data as *const Elf64Ehdr);
        let phdr_base = ehdr.e_phoff as usize;
        let phdr_count = ehdr.e_phnum as usize;
        let phdr_size = ehdr.e_phentsize as usize;

        let mut dyn_offset: u64 = 0;
        let mut dyn_size: u64 = 0;

        for i in 0..phdr_count {
            let off = phdr_base + i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > data_len {
                break;
            }
            let phdr = &*(data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_DYNAMIC {
                dyn_offset = phdr.p_offset;
                dyn_size = phdr.p_filesz;
                break;
            }
        }

        if dyn_offset == 0 {
            return 0;
        }

        let mut rela_vaddr: u64 = 0;
        let mut rela_size: u64 = 0;
        let mut rela_ent: u64 = 0;

        let mut pos = dyn_offset as usize;
        let dyn_end = pos + dyn_size as usize;

        while pos + core::mem::size_of::<Elf64Dyn>() <= dyn_end
            && pos + core::mem::size_of::<Elf64Dyn>() <= data_len
        {
            let d = &*(data.add(pos) as *const Elf64Dyn);
            if d.d_tag == DT_NULL {
                break;
            }
            if d.d_tag == DT_RELA {
                rela_vaddr = d.d_val;
            }
            if d.d_tag == DT_RELASZ {
                rela_size = d.d_val;
            }
            if d.d_tag == DT_RELAENT {
                rela_ent = d.d_val;
            }
            pos += core::mem::size_of::<Elf64Dyn>();
        }

        if rela_vaddr == 0 || rela_size == 0 || rela_ent == 0 {
            return 0;
        }

        if rela_ent < core::mem::size_of::<Elf64Rela>() as u64 {
            return ELF_RELOC_FAILED;
        }

        let rela_file_offset = match vaddr_to_file_offset(data, data_len, ehdr, rela_vaddr) {
            Some(off) => off,
            None => return ELF_RELOC_FAILED,
        };

        let rela_count = rela_size / rela_ent;

        for i in 0..rela_count {
            let entry_off = rela_file_offset + (i as usize) * (rela_ent as usize);
            if entry_off + core::mem::size_of::<Elf64Rela>() > data_len {
                return ELF_RELOC_FAILED;
            }

            let rela = &*(data.add(entry_off) as *const Elf64Rela);
            let reloc_type = (rela.r_info & 0xFFFF_FFFF) as u32;

            if reloc_type == R_X86_64_RELATIVE {
                let target_vaddr = rela.r_offset + delta;
                let value = load_base.wrapping_add(rela.r_addend as u64);

                let target_page = page_align_down(target_vaddr);
                let page_offset = (target_vaddr - target_page) as usize;

                let mut found = false;
                for p in pages {
                    if p.vaddr == target_page {
                        let err = write_to_page(ctx, p.frame_cap, page_offset, value);
                        if err != 0 {
                            return ELF_RELOC_FAILED;
                        }
                        found = true;
                        break;
                    }
                }
                if !found {
                    return ELF_RELOC_FAILED;
                }
            }
        }

        0
    }
}

/// Write a u64 value into a frame page at the given offset.
///
/// Temporarily maps the frame into the loader's scratch address, writes
/// the value, then unmaps.
unsafe fn write_to_page(
    ctx: &mut ElfLoaderCtx,
    frame_cap: Cap,
    page_offset: usize,
    value: u64,
) -> i32 {
    let err = invoke::vspace_map(
        ctx.self_vspace,
        frame_cap,
        ctx.scratch_vaddr,
        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
    );
    if err != 0 {
        return err;
    }

    unsafe {
        let ptr = (ctx.scratch_vaddr as *mut u8).add(page_offset) as *mut u64;
        core::ptr::write_volatile(ptr, value);
    }

    invoke::vspace_unmap(ctx.self_vspace, ctx.scratch_vaddr);
    0
}

/// Count the number of pages needed to load all PT_LOAD segments.
/// Overcounts slightly when segments share pages, but overcounting is safe.
///
/// # Safety
/// `data` must point to a valid ELF64 file of at least `data_len` bytes.
pub unsafe fn elf_count_load_pages(data: *const u8, data_len: usize) -> usize {
    if data_len < core::mem::size_of::<Elf64Ehdr>() {
        return 0;
    }
    unsafe {
        let ehdr = &*(data as *const Elf64Ehdr);
        if ehdr.e_ident[0] != 0x7F
            || ehdr.e_ident[1] != b'E'
            || ehdr.e_ident[2] != b'L'
            || ehdr.e_ident[3] != b'F'
        {
            return 0;
        }

        let phdr_base = ehdr.e_phoff as usize;
        let phdr_count = ehdr.e_phnum as usize;
        let phdr_size = ehdr.e_phentsize as usize;
        let mut total: usize = 0;

        for i in 0..phdr_count {
            let off = phdr_base + i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > data_len {
                break;
            }
            let phdr = &*(data.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD {
                continue;
            }
            let seg_start = page_align_down(phdr.p_vaddr);
            let seg_end = page_align_up(phdr.p_vaddr + phdr.p_memsz);
            if seg_end > seg_start {
                total += ((seg_end - seg_start) / ELF_PAGE_SIZE) as usize;
            }
        }
        total
    }
}

/// Compute the total VA span needed to load all PT_LOAD segments.
/// Returns `page_align_up(max_vaddr_end) - page_align_down(min_vaddr)`.
///
/// # Safety
/// `data` must point to a valid ELF64 file of at least `data_len` bytes.
pub unsafe fn elf_compute_load_span(data: *const u8, data_len: usize) -> u64 {
    if data_len < core::mem::size_of::<Elf64Ehdr>() {
        return 0;
    }
    unsafe {
        let ehdr = &*(data as *const Elf64Ehdr);
        if ehdr.e_ident[0] != 0x7F
            || ehdr.e_ident[1] != b'E'
            || ehdr.e_ident[2] != b'L'
            || ehdr.e_ident[3] != b'F'
        {
            return 0;
        }

        let phdr_base = ehdr.e_phoff as usize;
        let phdr_count = ehdr.e_phnum as usize;
        let phdr_size = ehdr.e_phentsize as usize;
        let mut min_vaddr: u64 = u64::MAX;
        let mut max_vaddr_end: u64 = 0;

        for i in 0..phdr_count {
            let off = phdr_base + i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > data_len {
                break;
            }
            let phdr = &*(data.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD {
                continue;
            }
            if phdr.p_vaddr < min_vaddr {
                min_vaddr = phdr.p_vaddr;
            }
            let end = phdr.p_vaddr + phdr.p_memsz;
            if end > max_vaddr_end {
                max_vaddr_end = end;
            }
        }

        if min_vaddr == u64::MAX || max_vaddr_end == 0 {
            return 0;
        }

        page_align_up(max_vaddr_end) - page_align_down(min_vaddr)
    }
}

/// Load an ELF64 binary into a child process's VSpace.
///
/// Iterates PT_LOAD segments, allocating frames, copying segment data
/// via scratch-map, and mapping pages into `ctx.child_vspace` with correct
/// permissions. For PIE (ET_DYN), applies RELATIVE relocations.
///
/// On success, populates `*result` with the entry point, load base, and
/// break address, and returns `ELF_OK`. On error, returns an ELF error code.
///
/// # Safety
/// `data` must point to a valid ELF64 file of at least `data_len` bytes.
/// `ctx` and `result` must be valid pointers.
pub unsafe fn elf_load(
    data: *const u8,
    data_len: usize,
    load_base: u64,
    ctx: &mut ElfLoaderCtx,
    result: *mut ElfLoadResult,
) -> i32 {
    if data_len < core::mem::size_of::<Elf64Ehdr>() {
        return ELF_TOO_SMALL;
    }

    unsafe {
        let ehdr = &*(data as *const Elf64Ehdr);

        if ehdr.e_ident[0] != 0x7F
            || ehdr.e_ident[1] != b'E'
            || ehdr.e_ident[2] != b'L'
            || ehdr.e_ident[3] != b'F'
        {
            return ELF_NOT_ELF;
        }

        if ehdr.e_ident[4] != ELFCLASS64 {
            return ELF_NOT_64BIT;
        }
        if ehdr.e_ident[5] != ELFDATA2LSB {
            return ELF_NOT_LE;
        }
        if ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN {
            return ELF_BAD_TYPE;
        }
        if ehdr.e_machine != EM_X86_64 {
            return ELF_BAD_ARCH;
        }

        let is_pie = ehdr.e_type == ET_DYN;

        let phdr_base = ehdr.e_phoff as usize;
        let phdr_count = ehdr.e_phnum as usize;
        let phdr_size = ehdr.e_phentsize as usize;

        // Find min vaddr
        let mut min_vaddr: u64 = u64::MAX;
        let mut has_load = false;

        for i in 0..phdr_count {
            let off = phdr_base + i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > data_len {
                break;
            }
            let phdr = &*(data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_LOAD {
                has_load = true;
                if phdr.p_vaddr < min_vaddr {
                    min_vaddr = phdr.p_vaddr;
                }
            }
        }

        if !has_load {
            return ELF_NO_LOAD;
        }

        let delta = if is_pie {
            load_base.wrapping_sub(min_vaddr)
        } else {
            0
        };

        // Compute page capacity
        let mut page_capacity: usize = 0;
        for i in 0..phdr_count {
            let off = phdr_base + i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > data_len {
                break;
            }
            let phdr = &*(data.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD {
                continue;
            }
            let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
            let seg_start = page_align_down(seg_vaddr);
            let seg_end = page_align_up(seg_vaddr + phdr.p_memsz);
            if seg_end > seg_start {
                page_capacity += ((seg_end - seg_start) / ELF_PAGE_SIZE) as usize;
            }
        }

        if page_capacity == 0 {
            return ELF_NO_LOAD;
        }

        // Use a fixed-size buffer (max 256 pages = 1MB per binary, sufficient for our ELFs)
        const MAX_PAGES: usize = 256;
        if page_capacity > MAX_PAGES {
            return ELF_OUT_OF_MEMORY;
        }
        let mut pages = [ElfPageEntry {
            vaddr: 0,
            frame_cap: 0,
            flags: 0,
        }; MAX_PAGES];
        let mut page_count: usize = 0;
        let mut brk: u64 = 0;

        // Load each PT_LOAD segment
        for i in 0..phdr_count {
            let off = phdr_base + i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > data_len {
                break;
            }
            let phdr = &*(data.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD {
                continue;
            }

            let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
            let seg_start = page_align_down(seg_vaddr);
            let seg_end = page_align_up(seg_vaddr + phdr.p_memsz);
            let flags = phdr_to_flags(phdr.p_flags);

            if seg_end > brk {
                brk = seg_end;
            }

            let mut page_vaddr = seg_start;
            while page_vaddr < seg_end {
                // Check if page already mapped
                let mut existing_idx = page_count;
                for j in 0..page_count {
                    if pages[j].vaddr == page_vaddr {
                        existing_idx = j;
                        break;
                    }
                }

                // Calculate file data overlap
                let file_start = seg_vaddr;
                let file_end = seg_vaddr + phdr.p_filesz;
                let copy_start = if page_vaddr > file_start {
                    page_vaddr
                } else {
                    file_start
                };
                let copy_end_bound = page_vaddr + ELF_PAGE_SIZE;
                let copy_end = if copy_end_bound < file_end {
                    copy_end_bound
                } else {
                    file_end
                };

                let mut src_offset: usize = 0;
                let mut dst_offset: usize = 0;
                let mut copy_len: usize = 0;

                if copy_start < copy_end {
                    src_offset =
                        (copy_start - delta - phdr.p_vaddr + phdr.p_offset) as usize;
                    dst_offset = (copy_start - page_vaddr) as usize;
                    copy_len = (copy_end - copy_start) as usize;
                }

                if existing_idx < page_count {
                    let existing = pages[existing_idx].frame_cap;
                    // Page exists; copy more data if needed
                    if copy_len > 0 && src_offset + copy_len <= data_len {
                        let err = invoke::vspace_map(
                            ctx.self_vspace,
                            existing,
                            ctx.scratch_vaddr,
                            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                        );
                        if err == 0 {
                            let scratch = ctx.scratch_vaddr as *mut u8;
                            for k in 0..copy_len {
                                core::ptr::write_volatile(
                                    scratch.add(dst_offset + k),
                                    *data.add(src_offset + k),
                                );
                            }
                            invoke::vspace_unmap(ctx.self_vspace, ctx.scratch_vaddr);
                        }
                    }

                    // Merge permissions, enforcing W^X: if merge would produce W+X, drop X
                    let mut merged_flags = pages[existing_idx].flags | flags;
                    if (merged_flags & VSPACE_FLAG_WRITABLE != 0) && (merged_flags & VSPACE_FLAG_EXECUTABLE != 0) {
                        merged_flags &= !VSPACE_FLAG_EXECUTABLE;
                    }
                    if merged_flags != pages[existing_idx].flags {
                        invoke::vspace_unmap(ctx.child_vspace, page_vaddr);
                        let remap_err = invoke::vspace_map(
                            ctx.child_vspace,
                            existing,
                            page_vaddr,
                            merged_flags,
                        );
                        if remap_err != 0 {
                            serial::serial_puts(b"[ELF] remap child failed\n");
                            return ELF_MAP_FAILED;
                        }
                        pages[existing_idx].flags = merged_flags;
                        if record_page_map(ctx, page_vaddr, existing, merged_flags) != 0 {
                            return ELF_OUT_OF_MEMORY;
                        }
                    }
                } else {
                    // New page
                    if page_count >= page_capacity {
                        return ELF_OUT_OF_MEMORY;
                    }

                    let frame_slot = next_frame_slot(ctx);
                    if frame_slot == u64::MAX || frame_slot == 0 {
                        return ELF_OUT_OF_MEMORY;
                    }

                    // Some callers provide a frame-allocation callback that already
                    // performs retype. In that mode, `untyped == 0` is used as a
                    // sentinel to skip internal retype here.
                    if ctx.untyped != 0 {
                        let err = try_retype_frame_any_untyped(ctx, frame_slot);
                        if err != 0 {
                            return ELF_OUT_OF_MEMORY;
                        }
                    }

                    let err = invoke::vspace_map(
                        ctx.self_vspace,
                        frame_slot,
                        ctx.scratch_vaddr,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    );
                    if err != 0 {
                        serial::serial_puts(b"[ELF] map scratch failed\n");
                        return ELF_MAP_FAILED;
                    }

                    // Zero the page
                    let scratch = ctx.scratch_vaddr as *mut u8;
                    for k in 0..ELF_PAGE_SIZE as usize {
                        core::ptr::write_volatile(scratch.add(k), 0);
                    }

                    // Copy file data
                    if copy_len > 0 && src_offset + copy_len <= data_len {
                        for k in 0..copy_len {
                            core::ptr::write_volatile(
                                scratch.add(dst_offset + k),
                                *data.add(src_offset + k),
                            );
                        }
                    }

                    invoke::vspace_unmap(ctx.self_vspace, ctx.scratch_vaddr);

                    let err =
                        invoke::vspace_map(ctx.child_vspace, frame_slot, page_vaddr, flags);
                    if err != 0 {
                        serial::serial_puts(b"[ELF] map child failed\n");
                        return ELF_MAP_FAILED;
                    }

                    pages[page_count].vaddr = page_vaddr;
                    pages[page_count].frame_cap = frame_slot;
                    pages[page_count].flags = flags;
                    page_count += 1;
                    if record_page_map(ctx, page_vaddr, frame_slot, flags) != 0 {
                        return ELF_OUT_OF_MEMORY;
                    }
                }

                page_vaddr += ELF_PAGE_SIZE;
            }
        }

        // Apply RELA relocations for PIE
        if is_pie {
            let err =
                apply_relocations(data, data_len, delta, load_base, &pages[..page_count], ctx);
            if err != 0 {
                return err;
            }
        }

        (*result).entry = ehdr.e_entry.wrapping_add(delta);
        (*result).base = load_base;
        (*result).brk = brk;
        ELF_OK
    }
}
