//! Core types for SaltyOS userland
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All types are #[repr(C)] for C ABI compatibility with rtld and libc.

pub type Cap = u64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyResult {
    pub error: u64,
    pub value: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyMsg {
    pub label: u64,
    pub length: u64,
    pub regs: [u64; 20],
}

impl SaltyMsg {
    pub const fn zeroed() -> Self {
        SaltyMsg {
            label: 0,
            length: 0,
            regs: [0; 20],
        }
    }
}

#[repr(C)]
pub struct IpcBuffer {
    pub msg: [u64; 22],
    pub badge: u64,
    pub caps: [u64; 4],
    pub receive_cnode: u64,
    pub receive_index: u64,
    pub receive_depth: u64,
    pub reserved: [u64; 478],
}

#[repr(C)]
pub struct IpcContext {
    pub ipc_buffer: *mut IpcBuffer,
    pub send_cap_count: i32,
}

unsafe impl Sync for IpcContext {}
unsafe impl Send for IpcContext {}

impl IpcContext {
    pub const fn new() -> Self {
        IpcContext {
            ipc_buffer: core::ptr::null_mut(),
            send_cap_count: 0,
        }
    }
}

// ELF types
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Ehdr {
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

#[repr(C)]
#[derive(Clone, Copy)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfLoadResult {
    pub entry: u64,
    pub base: u64,
    pub brk: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfPageEntry {
    pub vaddr: u64,
    pub frame_cap: Cap,
    pub flags: u64,
}

#[repr(C)]
pub struct ElfLoaderCtx {
    pub untyped: Cap,
    pub self_vspace: Cap,
    pub child_vspace: Cap,
    pub scratch_vaddr: u64,
    pub next_frame_slot: Cap,
    pub alloc_frame_slot: Option<unsafe extern "C" fn(*mut u8) -> Cap>,
    pub alloc_opaque: *mut u8,
    pub record_page: Option<unsafe extern "C" fn(*mut u8, u64, Cap, u64) -> i32>,
    pub record_opaque: *mut u8,
}

// CPIO types
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpioEntry {
    pub name: *const u8,
    pub name_len: usize,
    pub data: *const u8,
    pub data_len: usize,
}

impl CpioEntry {
    pub const fn zeroed() -> Self {
        CpioEntry {
            name: core::ptr::null(),
            name_len: 0,
            data: core::ptr::null(),
            data_len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpioEntryExt {
    pub name: *const u8,
    pub name_len: usize,
    pub data: *const u8,
    pub data_len: usize,
    pub mode: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub ino: u32,
}

impl CpioEntryExt {
    pub const fn zeroed() -> Self {
        CpioEntryExt {
            name: core::ptr::null(),
            name_len: 0,
            data: core::ptr::null(),
            data_len: 0,
            mode: 0,
            nlink: 0,
            mtime: 0,
            ino: 0,
        }
    }
}

// POSIX stat structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyStat {
    pub st_ino: u64,
    pub st_mode: u64,
    pub st_nlink: u64,
    pub st_size: u64,
    pub st_uid: u64,
    pub st_gid: u64,
    pub st_mtime: u64,
    pub st_type: u64,
}

impl SaltyStat {
    pub const fn zeroed() -> Self {
        SaltyStat {
            st_ino: 0,
            st_mode: 0,
            st_nlink: 0,
            st_size: 0,
            st_uid: 0,
            st_gid: 0,
            st_mtime: 0,
            st_type: 0,
        }
    }
}

// POSIX directory entry
#[repr(C)]
pub struct SaltyDirent {
    pub d_ino: u64,
    pub d_type: u8,
    pub d_namlen: u8,
    pub d_name: [u8; 62],
}

impl SaltyDirent {
    pub const fn zeroed() -> Self {
        SaltyDirent {
            d_ino: 0,
            d_type: 0,
            d_namlen: 0,
            d_name: [0; 62],
        }
    }
}

// POSIX memory management types
#[repr(C)]
pub struct PosixMmRegion {
    pub base: u64,
    pub length: u64,
    pub region_type: u8,
    pub prot: u8,
    pub num_pages: u16,
    pub frame_slots: [Cap; crate::consts::MM_MAX_PAGES_PER_REGION],
}

impl PosixMmRegion {
    pub const fn zeroed() -> Self {
        PosixMmRegion {
            base: 0,
            length: 0,
            region_type: MM_REGION_FREE,
            prot: 0,
            num_pages: 0,
            frame_slots: [0; crate::consts::MM_MAX_PAGES_PER_REGION],
        }
    }
}

pub const MM_REGION_FREE: u8 = 0;
pub const MM_REGION_HEAP: u8 = 1;
pub const MM_REGION_MMAP: u8 = 2;

#[repr(C)]
pub struct PosixMmState {
    pub untyped: Cap,
    pub vspace: Cap,
    pub cspace: Cap,
    pub next_frame_slot: Cap,
    pub max_frame_slot: Cap,
    pub heap_base: u64,
    pub heap_current: u64,
    pub mmap_base: u64,
    pub mmap_next: u64,
    pub regions: [PosixMmRegion; crate::consts::MM_MAX_REGIONS],
    pub heap_frame_slots: [Cap; crate::consts::MM_MAX_PAGES_PER_REGION],
    pub initialized: i32,
}

// Wait status helpers (match POSIX encoding: low 7 bits = signal, bits 15:8 = exit code)
pub fn wifexited(s: i32) -> bool {
    (s & 0x7f) == 0
}
pub fn wexitstatus(s: i32) -> i32 {
    (s >> 8) & 0xff
}
pub fn wifsignaled(s: i32) -> bool {
    (s & 0x7f) != 0 && (s & 0x7f) != 0x7f
}
pub fn wtermsig(s: i32) -> i32 {
    s & 0x7f
}
pub fn wifstopped(s: i32) -> bool {
    (s & 0xff) == 0x7f
}
pub fn wstopsig(s: i32) -> i32 {
    (s >> 8) & 0xff
}

// Signal handler type
pub type SigHandlerT = Option<unsafe extern "C" fn(i32)>;

// Special handler values encoded as usize
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
