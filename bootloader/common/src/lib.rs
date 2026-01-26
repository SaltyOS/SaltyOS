//! Common bootloader functionality (ELF loader)

#![no_std]

use saltyos_ska::{BootInfo, BootFlags, PhysAddr, BOOTINFO_MAGIC, BOOTINFO_VERSION};

pub mod layout;

/// ELF64 header
#[repr(C)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// ELF64 program header
#[repr(C)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Program header types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;

/// Errors from ELF loading
#[derive(Debug)]
pub enum ElfError {
    InvalidMagic,
    UnsupportedElfClass,
    UnsupportedMachine,
    LoadFailed,
}

/// Parse and validate ELF header
pub fn parse_elf_header(data: &[u8]) -> Result<&Elf64Header, ElfError> {
    if data.len() < core::mem::size_of::<Elf64Header>() {
        return Err(ElfError::InvalidMagic);
    }

    let header = unsafe { &*(data.as_ptr() as *const Elf64Header) };

    // Check magic
    if header.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::InvalidMagic);
    }

    // Check 64-bit
    if header.e_ident[4] != 2 {
        return Err(ElfError::UnsupportedElfClass);
    }

    // Check x86_64
    if header.e_machine != 62 {
        return Err(ElfError::UnsupportedMachine);
    }

    Ok(header)
}

/// Get program headers from ELF data
pub fn get_program_headers<'a>(data: &[u8], header: &'a Elf64Header) -> &'a [Elf64Phdr] {
    unsafe {
        let phdrs_ptr = (data.as_ptr() as usize + header.e_phoff as usize) as *const Elf64Phdr;
        core::slice::from_raw_parts(phdrs_ptr, header.e_phnum as usize)
    }
}

/// Find the min/max virtual address range among PT_LOAD segments.
pub fn find_load_vaddr_range(phdrs: &[Elf64Phdr]) -> Option<(u64, u64)> {
    let mut min = u64::MAX;
    let mut max = 0u64;

    for phdr in phdrs {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        if phdr.p_vaddr < min {
            min = phdr.p_vaddr;
        }
        let end = phdr.p_vaddr.saturating_add(phdr.p_memsz);
        if end > max {
            max = end;
        }
    }

    if min == u64::MAX {
        None
    } else {
        Some((min, max))
    }
}

/// Find the PT_DYNAMIC segment (vaddr, memsz) if present.
pub fn find_dynamic_segment(phdrs: &[Elf64Phdr]) -> Option<(u64, u64)> {
    for phdr in phdrs {
        if phdr.p_type == PT_DYNAMIC {
            return Some((phdr.p_vaddr, phdr.p_memsz));
        }
    }
    None
}

/// Initialize BootInfo structure with defaults
pub fn init_bootinfo() -> BootInfo {
    BootInfo {
        magic: *BOOTINFO_MAGIC,
        version: BOOTINFO_VERSION,
        flags: BootFlags::empty(),
        memory_map: PhysAddr::new(0),
        memory_map_entries: 0,
        framebuffer: None,
        initrd: None,
        cmdline: PhysAddr::new(0),
        cmdline_len: 0,
        rsdp: None,
    }
}
