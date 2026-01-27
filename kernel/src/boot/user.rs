//! Userspace ELF loader (minimal PT_LOAD only).

#![no_std]

use core::mem::size_of;

use saltyos_ska::{PAGE_SIZE, USER_CODE_BASE, USER_STACK_BASE, USER_STACK_PAGES, USER_STACK_SIZE};

use crate::mm::{allocate_frame, map_page, PageFlags, VirtAddr};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS_64: u8 = 2;
const EI_DATA_LE: u8 = 1;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;

#[repr(C)]
struct Elf64Header {
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

fn is_power_of_two(value: u64) -> bool {
    value != 0 && (value & (value - 1)) == 0
}

pub fn load_and_enter(data: &[u8]) -> Result<(u64, u64), &'static str> {
    if data.len() < size_of::<Elf64Header>() {
        return Err("ELF header too small");
    }

    let header = unsafe { &*(data.as_ptr() as *const Elf64Header) };
    if header.e_ident[0..4] != ELF_MAGIC {
        return Err("ELF magic mismatch");
    }
    if header.e_ident[4] != EI_CLASS_64 || header.e_ident[5] != EI_DATA_LE {
        return Err("ELF class/data mismatch");
    }
    if header.e_machine != EM_X86_64 {
        return Err("ELF machine mismatch");
    }

    let phoff = header.e_phoff as usize;
    let phentsize = header.e_phentsize as usize;
    let phnum = header.e_phnum as usize;
    let ph_end = phoff.checked_add(phentsize.checked_mul(phnum).ok_or("ph overflow")?)
        .ok_or("ph overflow")?;
    if ph_end > data.len() {
        return Err("ELF phdr out of bounds");
    }

    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        let ph = unsafe { &*(data.as_ptr().add(base) as *const Elf64Phdr) };
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_memsz == 0 {
            continue;
        }
        if ph.p_filesz > ph.p_memsz {
            return Err("ELF segment filesz > memsz");
        }
        if ph.p_align != 0 {
            if !is_power_of_two(ph.p_align) {
                return Err("ELF segment p_align not power-of-two");
            }
            if ph.p_filesz != 0 && (ph.p_vaddr % ph.p_align) != (ph.p_offset % ph.p_align) {
                return Err("ELF segment p_align mismatch");
            }
        }
        if ph.p_vaddr < min_vaddr {
            min_vaddr = ph.p_vaddr;
        }
        let end = ph.p_vaddr.saturating_add(ph.p_memsz);
        if end > max_vaddr {
            max_vaddr = end;
        }
    }
    if min_vaddr == u64::MAX {
        return Err("No PT_LOAD segments");
    }

    let image_size = (max_vaddr - min_vaddr) as usize;
    let image_pages = (image_size + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;
    let user_flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER_ACCESSIBLE;

    for i in 0..image_pages {
        let frame = allocate_frame().ok_or("Out of memory")?;
        unsafe {
            map_page(
                VirtAddr::new(USER_CODE_BASE + (i as u64 * PAGE_SIZE)),
                frame,
                user_flags,
            )?;
        }
    }

    for i in 0..phnum {
        let base = phoff + i * phentsize;
        let ph = unsafe { &*(data.as_ptr().add(base) as *const Elf64Phdr) };
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_memsz == 0 {
            continue;
        }
        if ph.p_vaddr < min_vaddr {
            return Err("ELF segment below base");
        }
        let file_end = ph.p_offset.saturating_add(ph.p_filesz) as usize;
        if file_end > data.len() {
            return Err("ELF segment out of bounds");
        }
        let seg_offset = ph.p_vaddr - min_vaddr;
        let seg_end = seg_offset.saturating_add(ph.p_memsz);
        if seg_end as usize > image_size {
            return Err("ELF segment exceeds image");
        }
        let src = unsafe { data.as_ptr().add(ph.p_offset as usize) };
        let dest = (USER_CODE_BASE + seg_offset) as *mut u8;

        unsafe {
            core::ptr::copy_nonoverlapping(src, dest, ph.p_filesz as usize);
            if ph.p_memsz > ph.p_filesz {
                core::ptr::write_bytes(
                    dest.add(ph.p_filesz as usize),
                    0,
                    (ph.p_memsz - ph.p_filesz) as usize,
                );
            }
        }
    }

    for i in 0..(USER_STACK_PAGES as usize) {
        let frame = allocate_frame().ok_or("Out of memory")?;
        unsafe {
            map_page(
                VirtAddr::new(USER_STACK_BASE + (i as u64 * PAGE_SIZE)),
                frame,
                user_flags,
            )?;
            core::ptr::write_bytes(
                (USER_STACK_BASE + (i as u64 * PAGE_SIZE)) as *mut u8,
                0,
                PAGE_SIZE as usize,
            );
        }
    }

    let entry = USER_CODE_BASE + (header.e_entry - min_vaddr);
    let stack_top = USER_STACK_BASE + USER_STACK_SIZE;
    Ok((entry, stack_top))
}
