pub(crate) mod elf_load;
pub(crate) mod mem_util;
pub(crate) mod pe_load;
pub(crate) mod stack_build;
pub(crate) mod vfs_load;

pub(crate) const MAX_NEEDED_LIBS: usize = 16;
pub(crate) const MAX_NEEDED_NAME: usize = 64;

#[derive(Clone, Copy)]
pub(crate) struct NeededLibs {
    pub count: usize,
    pub names: [[u8; MAX_NEEDED_NAME]; MAX_NEEDED_LIBS],
    pub name_lens: [usize; MAX_NEEDED_LIBS],
}

impl NeededLibs {
    pub const fn new() -> Self {
        Self {
            count: 0,
            names: [[0u8; MAX_NEEDED_NAME]; MAX_NEEDED_LIBS],
            name_lens: [0; MAX_NEEDED_LIBS],
        }
    }
}

/// Build `NeededLibs` from ELF dynamic DT_NEEDED entries.
///
/// # Safety
/// `data` must point to `len` readable bytes of a valid ELF image.
pub(crate) unsafe fn elf_get_needed(data: *const u8, len: usize) -> NeededLibs {
    let mut libs = NeededLibs::new();
    unsafe {
        use trona_loader::common::elf::dynamic::{NeededIter, parse_dynamic, strtab_entry};
        use trona_loader::common::elf::header::{find_dynamic_phdr, phdr_slice, validate_ehdr};

        let ehdr = match validate_ehdr(data, len) {
            Ok(e) => e,
            Err(_) => return libs,
        };
        let phdrs = match phdr_slice(data, len, ehdr) {
            Ok(p) => p,
            Err(_) => return libs,
        };
        let dyn_phdr = match find_dynamic_phdr(phdrs) {
            Some(d) => d,
            None => return libs,
        };
        let dyn_ptr = data.add(dyn_phdr.p_offset as usize)
            as *const trona_loader::common::elf::types::Elf64Dyn;
        let info = parse_dynamic(dyn_ptr);
        if info.strtab == 0 || info.strsz == 0 {
            return libs;
        }
        let strtab = data.add(info.strtab as usize);
        let strsz = info.strsz as usize;
        let iter = NeededIter::new(dyn_ptr);
        for val in iter {
            let name = match strtab_entry(strtab, strsz, val) {
                Some(n) => n,
                None => continue,
            };
            if libs.count >= MAX_NEEDED_LIBS {
                break;
            }
            let copy_len = if name.len() < MAX_NEEDED_NAME {
                name.len()
            } else {
                MAX_NEEDED_NAME
            };
            let mut i = 0;
            while i < copy_len {
                libs.names[libs.count][i] = name[i];
                i += 1;
            }
            libs.name_lens[libs.count] = copy_len;
            libs.count += 1;
        }
    }
    libs
}

/// Compute load span from ELF program headers.
///
/// # Safety
/// `data` must point to `len` readable bytes.
pub(crate) unsafe fn elf_compute_load_span(data: *const u8, len: usize) -> u64 {
    unsafe {
        use trona_loader::common::elf::header::{load_span, phdr_slice, validate_ehdr};
        let ehdr = match validate_ehdr(data, len) {
            Ok(e) => e,
            Err(_) => return 0,
        };
        let phdrs = match phdr_slice(data, len, ehdr) {
            Ok(p) => p,
            Err(_) => return 0,
        };
        let Some((lo, hi)) = load_span(phdrs) else {
            return 0;
        };
        hi - lo
    }
}

/// Compute pages needed for a set of needed libraries + their transitive deps.
///
/// # Safety
/// `callback` must be safe to call.
pub(crate) unsafe fn compute_needed_window_pages(
    needed: &NeededLibs,
    callback: impl Fn(&[u8]) -> u64,
) -> usize {
    let mut total = 0usize;
    let mut i = 0;
    while i < needed.count {
        let name = &needed.names[i][..needed.name_lens[i]];
        let span = callback(name);
        total += ((span + 4095) / 4096) as usize;
        i += 1;
    }
    total
}

/// Resolve interpreter path to the exact CPIO key used in initrd.
/// If `interp` is empty, writes the default RTLD name `/lib/ldtrona-elf.so`.
/// Returns the number of bytes written to `out`.
pub(crate) fn resolve_interp_to_cpio_path(interp: &[u8], out: &mut [u8]) -> usize {
    if interp.is_empty() {
        let default = b"/lib/ldtrona-elf.so";
        if default.len() > out.len() {
            return 0;
        }
        let mut i = 0;
        while i < default.len() {
            out[i] = default[i];
            i += 1;
        }
        return default.len();
    }
    if interp.is_empty() || interp.len() > out.len() {
        return 0;
    }
    let mut i = 0;
    while i < interp.len() {
        out[i] = interp[i];
        i += 1;
    }
    interp.len()
}
