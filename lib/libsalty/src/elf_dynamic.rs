//! ELF dynamic linking helpers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Utilities for inspecting ELF files before loading: detecting the
//! presence of a PT_INTERP segment (runtime linker), extracting its
//! path, listing DT_NEEDED shared library dependencies, and reading
//! program header info for the auxiliary vector.

use crate::consts::*;
use crate::types::*;

/// Check whether an ELF file has a PT_INTERP segment (i.e. needs a runtime linker).
///
/// # Safety
/// `elf_data` must point to a valid ELF file of at least `elf_size` bytes.
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

/// Return a pointer to the PT_INTERP string (runtime linker path) within the
/// ELF data, or null if no PT_INTERP segment exists.
///
/// # Safety
/// `elf_data` must point to a valid ELF file of at least `elf_size` bytes.
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

// ---- DT_NEEDED extraction ----

/// Maximum number of DT_NEEDED shared library dependencies tracked.
pub const MAX_NEEDED_LIBS: usize = 4;
/// Maximum length of a DT_NEEDED library name (bytes).
pub const MAX_NEEDED_NAME: usize = 24;

/// Collection of DT_NEEDED library names extracted from an ELF binary.
pub struct NeededLibs {
    pub count: usize,
    pub names: [[u8; MAX_NEEDED_NAME]; MAX_NEEDED_LIBS],
    pub name_lens: [usize; MAX_NEEDED_LIBS],
}

impl NeededLibs {
    pub const fn new() -> Self {
        NeededLibs {
            count: 0,
            names: [[0u8; MAX_NEEDED_NAME]; MAX_NEEDED_LIBS],
            name_lens: [0; MAX_NEEDED_LIBS],
        }
    }

    /// Check if a library name is in the needed list.
    pub fn contains(&self, name: &[u8]) -> bool {
        for i in 0..self.count {
            if self.name_lens[i] == name.len() {
                let mut eq = true;
                for j in 0..name.len() {
                    if self.names[i][j] != name[j] {
                        eq = false;
                        break;
                    }
                }
                if eq {
                    return true;
                }
            }
        }
        false
    }
}

/// Convert a virtual address to a file offset using PT_LOAD segments.
unsafe fn elf_va_to_file_offset(elf_data: *const u8, elf_size: usize, va: u64) -> Option<usize> {
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
            if phdr.p_type == PT_LOAD {
                if va >= phdr.p_vaddr && va < phdr.p_vaddr + phdr.p_filesz {
                    let offset = (va - phdr.p_vaddr + phdr.p_offset) as usize;
                    if offset < elf_size {
                        return Some(offset);
                    }
                }
            }
        }
        None
    }
}

/// Extract DT_NEEDED library names from a raw (on-disk) ELF file.
///
/// # Safety
/// `elf_data` must point to a valid ELF file of at least `elf_size` bytes.
pub unsafe fn elf_get_needed(elf_data: *const u8, elf_size: usize) -> NeededLibs {
    let mut result = NeededLibs::new();

    unsafe {
        if elf_size < core::mem::size_of::<Elf64Ehdr>() {
            return result;
        }

        let ehdr = &*(elf_data as *const Elf64Ehdr);
        let phoff = ehdr.e_phoff as usize;
        let phnum = ehdr.e_phnum as usize;
        let phentsz = ehdr.e_phentsize as usize;

        // Find PT_DYNAMIC
        let mut dyn_offset: usize = 0;
        let mut dyn_size: usize = 0;
        for i in 0..phnum {
            let off = phoff + i * phentsz;
            if off + core::mem::size_of::<Elf64Phdr>() > elf_size {
                break;
            }
            let phdr = &*(elf_data.add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_DYNAMIC {
                dyn_offset = phdr.p_offset as usize;
                dyn_size = phdr.p_filesz as usize;
                break;
            }
        }
        if dyn_offset == 0 || dyn_offset + dyn_size > elf_size {
            return result;
        }

        let dyn_ptr = elf_data.add(dyn_offset) as *const Elf64Dyn;
        let dyn_count = dyn_size / core::mem::size_of::<Elf64Dyn>();

        // First pass: find DT_STRTAB virtual address
        let mut strtab_va: u64 = 0;
        for i in 0..dyn_count {
            let d = &*dyn_ptr.add(i);
            if d.d_tag == DT_NULL {
                break;
            }
            if d.d_tag == DT_STRTAB {
                strtab_va = d.d_val;
                break;
            }
        }
        if strtab_va == 0 {
            return result;
        }

        // Convert strtab VA to file offset
        let strtab_file_off = match elf_va_to_file_offset(elf_data, elf_size, strtab_va) {
            Some(off) => off,
            None => return result,
        };

        // Second pass: extract DT_NEEDED names
        for i in 0..dyn_count {
            let d = &*dyn_ptr.add(i);
            if d.d_tag == DT_NULL {
                break;
            }
            if d.d_tag == DT_NEEDED {
                let name_off = strtab_file_off + d.d_val as usize;
                if name_off >= elf_size {
                    continue;
                }

                // Read null-terminated name
                let name_ptr = elf_data.add(name_off);
                let mut len = 0usize;
                while name_off + len < elf_size && *name_ptr.add(len) != 0 {
                    len += 1;
                }

                if len > 0 && result.count < MAX_NEEDED_LIBS {
                    let copy_len = if len > MAX_NEEDED_NAME { MAX_NEEDED_NAME } else { len };
                    for j in 0..copy_len {
                        result.names[result.count][j] = *name_ptr.add(j);
                    }
                    result.name_lens[result.count] = copy_len;
                    result.count += 1;
                }
            }
        }
    }

    result
}

/// Extract program header table location for the auxiliary vector.
///
/// Writes the PHDR virtual address (relative to `load_base`), entry size,
/// and count into the output pointers. Returns 0 on success, -1 on error.
///
/// # Safety
/// `elf_data` must point to a valid ELF file of at least `elf_size` bytes.
/// Output pointers must be valid and non-null.
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
