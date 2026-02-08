//! ELF dynamic linking helpers
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::types::*;

pub unsafe fn elf_has_interp(elf_data: *const u8, elf_size: usize) -> bool {
    if elf_size < core::mem::size_of::<Elf64Ehdr>() {
        return false;
    }

    unsafe {
        let ehdr = &*(elf_data as *const Elf64Ehdr);
        let phoff = ehdr.e_phoff as usize;
        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;

        for i in 0..phnum {
            let off = phoff + i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > elf_size {
                break;
            }
            let phdr = &*(elf_data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_INTERP {
                return true;
            }
        }
        false
    }
}

pub unsafe fn elf_get_interp(elf_data: *const u8, elf_size: usize) -> *const u8 {
    if elf_size < core::mem::size_of::<Elf64Ehdr>() {
        return core::ptr::null();
    }

    unsafe {
        let ehdr = &*(elf_data as *const Elf64Ehdr);
        let phoff = ehdr.e_phoff as usize;
        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;

        for i in 0..phnum {
            let off = phoff + i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > elf_size {
                break;
            }
            let phdr = &*(elf_data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_INTERP {
                let interp_off = phdr.p_offset as usize;
                let interp_len = phdr.p_filesz as usize;
                if interp_off + interp_len > elf_size {
                    return core::ptr::null();
                }
                return elf_data.add(interp_off);
            }
        }
        core::ptr::null()
    }
}

pub unsafe fn elf_get_phdr_info(
    elf_data: *const u8,
    elf_size: usize,
    load_base: u64,
    phdr_vaddr: *mut u64,
    phent: *mut u64,
    phnum: *mut u64,
) -> i32 {
    if elf_size < core::mem::size_of::<Elf64Ehdr>() {
        return -1;
    }

    unsafe {
        let ehdr = &*(elf_data as *const Elf64Ehdr);
        *phdr_vaddr = load_base + ehdr.e_phoff;
        *phent = ehdr.e_phentsize as u64;
        *phnum = ehdr.e_phnum as u64;
    }
    0
}
