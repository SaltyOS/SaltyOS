//! Userspace ELF64 loader
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::invoke;
use crate::serial;
use crate::types::*;

fn page_align_down(v: u64) -> u64 {
    v & !(ELF_PAGE_SIZE - 1)
}

fn page_align_up(v: u64) -> u64 {
    (v + ELF_PAGE_SIZE - 1) & !(ELF_PAGE_SIZE - 1)
}

fn next_frame_slot(ctx: &mut ElfLoaderCtx) -> Cap {
    if let Some(alloc) = ctx.alloc_frame_slot {
        unsafe { alloc(ctx.alloc_opaque) }
    } else {
        let slot = ctx.next_frame_slot;
        ctx.next_frame_slot += 1;
        slot
    }
}

fn record_page_map(ctx: &ElfLoaderCtx, vaddr: u64, frame_cap: Cap, flags: u64) -> i32 {
    if let Some(record) = ctx.record_page {
        unsafe { record(ctx.record_opaque, vaddr, frame_cap, flags) }
    } else {
        0
    }
}

fn phdr_to_flags(p_flags: u32) -> u64 {
    let mut flags = VSPACE_FLAG_USER;
    if p_flags & PF_W != 0 {
        flags |= VSPACE_FLAG_WRITABLE;
    }
    if p_flags & PF_X != 0 {
        flags |= VSPACE_FLAG_EXECUTABLE;
    }
    flags
}

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

                    // Merge permissions
                    let merged_flags = pages[existing_idx].flags | flags;
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
                    if frame_slot == u64::MAX {
                        return ELF_OUT_OF_MEMORY;
                    }

                    let err =
                        invoke::untyped_retype(ctx.untyped, OBJ_FRAME, 0, frame_slot);
                    if err != 0 {
                        return ELF_OUT_OF_MEMORY;
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
