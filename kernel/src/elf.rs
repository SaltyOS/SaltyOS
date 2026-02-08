//! ELF64 Loader
//!
//! Loads PIE (ET_DYN) and static (ET_EXEC) ELF64 binaries into a user VSpace.
//! Supports R_X86_64_RELATIVE relocations for position-independent executables.
//!
//! Ported from boot/stage3/elf.c + elf.h, adapted for kernel-side page-at-a-time
//! VSpace mapping instead of flat memcpy.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::mm::vspace::{PageFlags, VSpace};
use crate::mm::{alloc_frame, phys_to_virt, PAGE_SIZE};

// ELF64 header
#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

// ELF64 program header
#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

// ELF64 dynamic entry
#[repr(C)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

// ELF64 RELA relocation entry
#[repr(C)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

// ELF constants
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const R_X86_64_RELATIVE: u32 = 8;

/// ELF load errors
#[derive(Debug)]
pub enum ElfError {
    NotElf,
    Not64Bit,
    NotLittleEndian,
    BadType,
    BadArch,
    NoLoadSegment,
    RelocFailed,
    OutOfMemory,
    TooSmall,
    MapFailed,
}

/// Result of loading an ELF binary
pub struct ElfLoadResult {
    /// Virtual entry point (relocated for PIE)
    pub entry: u64,
    /// Virtual base address
    pub base: u64,
    /// Highest mapped virtual address (for future heap)
    pub brk: u64,
}

/// Convert ELF program header flags to VSpace PageFlags
fn phdr_to_pageflags(p_flags: u32) -> PageFlags {
    let r = p_flags & PF_R != 0;
    let w = p_flags & PF_W != 0;
    let x = p_flags & PF_X != 0;

    match (r, w, x) {
        (true, false, true) => PageFlags::USER_RX,
        (true, true, false) => PageFlags::USER_RW,
        (true, true, true) => PageFlags::USER_RW, // W^X: RWX → RW
        (true, false, false) => PageFlags::USER_RO,
        _ => PageFlags::USER_RO,
    }
}

/// Align a value down to page boundary
fn page_align_down(v: u64) -> u64 {
    v & !(PAGE_SIZE as u64 - 1)
}

/// Align a value up to page boundary
fn page_align_up(v: u64) -> u64 {
    (v + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1)
}

/// Load an ELF64 binary into a user VSpace.
///
/// For ET_DYN (PIE): loads at `load_base`, applies RELA relocations.
/// For ET_EXEC: loads at fixed addresses from program headers.
///
/// Each page of each PT_LOAD segment gets:
///   1. alloc_frame()
///   2. copy data (or zero for BSS) into phys_to_virt(frame)
///   3. vspace.map(page_vaddr, frame, flags)
pub fn load_elf(
    data: &[u8],
    vspace: &mut VSpace,
    load_base: u64,
) -> Result<ElfLoadResult, ElfError> {
    // Validate minimum size
    let ehdr_size = core::mem::size_of::<Elf64Ehdr>();
    if data.len() < ehdr_size {
        return Err(ElfError::TooSmall);
    }

    // Parse ELF header
    let ehdr = unsafe { &*(data.as_ptr() as *const Elf64Ehdr) };

    // Validate magic
    if ehdr.e_ident[0] != 0x7F
        || ehdr.e_ident[1] != b'E'
        || ehdr.e_ident[2] != b'L'
        || ehdr.e_ident[3] != b'F'
    {
        return Err(ElfError::NotElf);
    }

    if ehdr.e_ident[4] != ELFCLASS64 {
        return Err(ElfError::Not64Bit);
    }
    if ehdr.e_ident[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    if ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN {
        return Err(ElfError::BadType);
    }
    if ehdr.e_machine != EM_X86_64 {
        return Err(ElfError::BadArch);
    }

    let is_pie = ehdr.e_type == ET_DYN;

    // Find min vaddr across all PT_LOAD segments
    let mut min_vaddr: u64 = u64::MAX;
    let mut has_load = false;

    let phdr_base = ehdr.e_phoff as usize;
    let phdr_count = ehdr.e_phnum as usize;
    let phdr_size = ehdr.e_phentsize as usize;

    for i in 0..phdr_count {
        let off = phdr_base + i * phdr_size;
        if off + core::mem::size_of::<Elf64Phdr>() > data.len() {
            break;
        }
        let phdr = unsafe { &*(data.as_ptr().add(off) as *const Elf64Phdr) };
        if phdr.p_type == PT_LOAD {
            has_load = true;
            if phdr.p_vaddr < min_vaddr {
                min_vaddr = phdr.p_vaddr;
            }
        }
    }

    if !has_load {
        return Err(ElfError::NoLoadSegment);
    }

    // Delta for PIE relocation
    let delta = if is_pie {
        load_base.wrapping_sub(min_vaddr)
    } else {
        0
    };

    let mut brk: u64 = 0;

    // Load each PT_LOAD segment
    for i in 0..phdr_count {
        let off = phdr_base + i * phdr_size;
        if off + core::mem::size_of::<Elf64Phdr>() > data.len() {
            break;
        }
        let phdr = unsafe { &*(data.as_ptr().add(off) as *const Elf64Phdr) };
        if phdr.p_type != PT_LOAD {
            continue;
        }

        let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
        let seg_start = page_align_down(seg_vaddr);
        let seg_end = page_align_up(seg_vaddr + phdr.p_memsz);
        let flags = phdr_to_pageflags(phdr.p_flags);

        if seg_end > brk {
            brk = seg_end;
        }

        let mut page_vaddr = seg_start;
        while page_vaddr < seg_end {
            // Check if this page was already mapped by a previous segment
            let frame_phys = if let Some(phys) = vspace.resolve_page(page_vaddr) {
                // Page already mapped — reuse existing frame (don't re-zero)
                phys
            } else {
                // Allocate new physical frame
                let phys = alloc_frame().ok_or(ElfError::OutOfMemory)?;
                let ptr = phys_to_virt(phys) as *mut u8;
                unsafe {
                    core::ptr::write_bytes(ptr, 0, PAGE_SIZE);
                }

                // Map page into VSpace
                vspace
                    .map(page_vaddr, phys, flags)
                    .map_err(|_| ElfError::MapFailed)?;

                phys
            };

            let frame_ptr = phys_to_virt(frame_phys) as *mut u8;

            // Copy file data that overlaps this page
            let file_region_start = seg_vaddr;
            let file_region_end = seg_vaddr + phdr.p_filesz;

            let copy_start = if page_vaddr > file_region_start {
                page_vaddr
            } else {
                file_region_start
            };
            let copy_end = if page_vaddr + PAGE_SIZE as u64 > file_region_end {
                file_region_end
            } else {
                page_vaddr + PAGE_SIZE as u64
            };

            if copy_start < copy_end {
                let src_offset =
                    (copy_start.wrapping_sub(delta).wrapping_sub(phdr.p_vaddr) + phdr.p_offset)
                        as usize;
                let dst_offset = (copy_start - page_vaddr) as usize;
                let len = (copy_end - copy_start) as usize;

                if src_offset + len <= data.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr().add(src_offset),
                            frame_ptr.add(dst_offset),
                            len,
                        );
                    }
                }
            }

            page_vaddr += PAGE_SIZE as u64;
        }
    }

    // Apply RELA relocations for PIE binaries
    if is_pie {
        apply_relocations(data, delta, vspace)?;
    }

    let entry = ehdr.e_entry.wrapping_add(delta);

    Ok(ElfLoadResult {
        entry,
        base: load_base,
        brk,
    })
}

/// Convert a virtual address (from DT_RELA etc.) to a file offset by scanning PT_LOAD segments.
fn vaddr_to_file_offset(
    data: &[u8],
    phdr_base: usize,
    phdr_count: usize,
    phdr_size: usize,
    vaddr: u64,
) -> Result<usize, ElfError> {
    for i in 0..phdr_count {
        let off = phdr_base + i * phdr_size;
        if off + core::mem::size_of::<Elf64Phdr>() > data.len() {
            break;
        }
        let phdr = unsafe { &*(data.as_ptr().add(off) as *const Elf64Phdr) };
        if phdr.p_type != PT_LOAD {
            continue;
        }
        if vaddr >= phdr.p_vaddr && vaddr - phdr.p_vaddr < phdr.p_filesz {
            return Ok((phdr.p_offset + (vaddr - phdr.p_vaddr)) as usize);
        }
    }
    Err(ElfError::RelocFailed)
}

/// Apply RELA relocations by finding PT_DYNAMIC → DT_RELA/DT_RELASZ/DT_RELAENT
fn apply_relocations(
    data: &[u8],
    delta: u64,
    vspace: &VSpace,
) -> Result<(), ElfError> {
    let ehdr = unsafe { &*(data.as_ptr() as *const Elf64Ehdr) };
    let phdr_base = ehdr.e_phoff as usize;
    let phdr_count = ehdr.e_phnum as usize;
    let phdr_size = ehdr.e_phentsize as usize;

    // Find PT_DYNAMIC segment
    let mut dyn_offset: u64 = 0;
    let mut dyn_size: u64 = 0;

    for i in 0..phdr_count {
        let off = phdr_base + i * phdr_size;
        if off + core::mem::size_of::<Elf64Phdr>() > data.len() {
            break;
        }
        let phdr = unsafe { &*(data.as_ptr().add(off) as *const Elf64Phdr) };
        if phdr.p_type == PT_DYNAMIC {
            dyn_offset = phdr.p_offset;
            dyn_size = phdr.p_filesz;
            break;
        }
    }

    if dyn_offset == 0 {
        // No dynamic section — nothing to relocate
        return Ok(());
    }

    // Parse .dynamic entries to find RELA table
    let mut rela_vaddr: u64 = 0;
    let mut rela_size: u64 = 0;
    let mut rela_ent: u64 = 0;

    let dyn_entry_size = core::mem::size_of::<Elf64Dyn>();
    let mut pos = dyn_offset as usize;
    let dyn_end = (dyn_offset + dyn_size) as usize;

    while pos + dyn_entry_size <= dyn_end && pos + dyn_entry_size <= data.len() {
        let dyn_entry = unsafe { &*(data.as_ptr().add(pos) as *const Elf64Dyn) };

        if dyn_entry.d_tag == DT_NULL {
            break;
        }

        match dyn_entry.d_tag {
            DT_RELA => rela_vaddr = dyn_entry.d_val,
            DT_RELASZ => rela_size = dyn_entry.d_val,
            DT_RELAENT => rela_ent = dyn_entry.d_val,
            _ => {}
        }

        pos += dyn_entry_size;
    }

    if rela_vaddr == 0 || rela_size == 0 || rela_ent == 0 {
        return Ok(());
    }

    // DT_RELA value is a virtual address, not a file offset.
    // Convert to file offset by scanning PT_LOAD segments.
    let rela_file_offset = vaddr_to_file_offset(data, phdr_base, phdr_count, phdr_size, rela_vaddr)?;
    let rela_count = rela_size / rela_ent;

    let rela_entry_size = core::mem::size_of::<Elf64Rela>();

    crate::serial_puts("[INIT] ELF: ");
    crate::serial_dec(rela_count);
    crate::serial_puts(" relocations\n");

    for i in 0..rela_count {
        let entry_off = rela_file_offset + (i as usize) * rela_entry_size;
        if entry_off + rela_entry_size > data.len() {
            return Err(ElfError::RelocFailed);
        }

        let rela = unsafe { &*(data.as_ptr().add(entry_off) as *const Elf64Rela) };
        let reloc_type = (rela.r_info & 0xFFFF_FFFF) as u32;

        if reloc_type == R_X86_64_RELATIVE {
            // R_X86_64_RELATIVE: *target = B + A, where B = delta (slide)
            let target_vaddr = rela.r_offset.wrapping_add(delta);
            let value = delta.wrapping_add(rela.r_addend as u64);

            // Find the physical page containing this virtual address
            let target_page = page_align_down(target_vaddr);
            let page_offset = (target_vaddr - target_page) as usize;

            let phys = vspace.resolve_page(target_page).ok_or(ElfError::RelocFailed)?;
            let ptr = phys_to_virt(phys) as *mut u8;
            if page_offset + 8 <= PAGE_SIZE {
                unsafe {
                    let target = ptr.add(page_offset) as *mut u64;
                    target.write(value);
                }
            }
        }
        // Ignore other relocation types (R_X86_64_NONE, etc.)
    }

    Ok(())
}
