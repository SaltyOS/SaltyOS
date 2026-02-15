//! Core types for SaltyOS userland
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All types are `#[repr(C)]` for C ABI compatibility with `rtld` and `saltyc`.
//! Structures here are shared across the Rust/C boundary and must remain
//! layout-stable.

/// Capability slot index. Caps are 64-bit integers that name a slot in the
/// thread's CNode; the kernel resolves the slot to a fat capability object.
pub type Cap = u64;

/// Result of a raw syscall: `error` is 0 on success, otherwise an error code
/// from `consts::SALTY_*`. `value` carries the return payload (e.g. badge,
/// notification bits, clock value).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyResult {
    pub error: u64,
    pub value: u64,
}

/// IPC message buffer passed between userland and the kernel.
///
/// `label` identifies the operation (invoke label or POSIX protocol label).
/// `length` is the number of valid message registers (0..20).
/// `regs[0..3]` travel in CPU registers; `regs[4..19]` overflow via the
/// IPC buffer page.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SaltyMsg {
    pub label: u64,
    pub length: u64,
    pub regs: [u64; 20],
}

impl SaltyMsg {
    /// Return a zero-initialized message (label=0, length=0, all regs=0).
    pub const fn zeroed() -> Self {
        SaltyMsg {
            label: 0,
            length: 0,
            regs: [0; 20],
        }
    }
}

/// Kernel-shared IPC buffer page (4096 bytes).
///
/// Mapped at a fixed virtual address per thread. The kernel reads/writes
/// this page during IPC to transfer overflow message registers (MR4+),
/// capability transfer slots, and receive-slot configuration.
///
/// - `msg[0..5]`: mirrors SaltyMsg header (label, length, regs[0..3])
/// - `msg[6..21]`: overflow message registers (regs[4..19])
/// - `badge`: sender badge written by kernel on receive
/// - `caps[0..3]`: CNode slots of capabilities to transfer on send
/// - `receive_cnode/index/depth`: destination for received capabilities
/// - `reserved[0..1]`: reserved for future ABI extensions
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

/// Per-thread IPC context: a pointer to the IPC buffer page and the
/// number of capability slots staged for the next send operation.
#[repr(C)]
pub struct IpcContext {
    /// Pointer to the kernel-shared IPC buffer page.
    pub ipc_buffer: *mut IpcBuffer,
    /// Number of caps staged in `ipc_buffer.caps[]` for the next send.
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

/// ELF64 file header. Matches the System V ABI ELF specification.
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

/// ELF64 program header. Describes a segment (PT_LOAD, PT_INTERP, etc.).
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

/// ELF64 dynamic section entry (tag + value pair from PT_DYNAMIC).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

/// ELF64 relocation entry with explicit addend (used for R_X86_64_RELATIVE).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

/// Result of loading an ELF binary: entry point, load base address, and
/// the end of the loaded BSS (program break).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfLoadResult {
    pub entry: u64,
    pub base: u64,
    pub brk: u64,
}

/// Tracks a single mapped page during ELF loading: its virtual address,
/// the frame capability slot, and VSpace mapping flags.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfPageEntry {
    pub vaddr: u64,
    pub frame_cap: Cap,
    pub flags: u64,
}

/// Context for the userspace ELF loader.
///
/// The loader uses a "scratch-map" strategy: each page is temporarily mapped
/// into the loader's own VSpace at `scratch_vaddr` for writing, then unmapped
/// and remapped into the child's VSpace. This allows loading into a foreign
/// address space without switching page tables.
#[repr(C)]
pub struct ElfLoaderCtx {
    /// Untyped cap to retype frames from (0 = skip internal retype).
    pub untyped: Cap,
    /// Loader's own VSpace cap (for scratch mapping).
    pub self_vspace: Cap,
    /// Target child's VSpace cap.
    pub child_vspace: Cap,
    /// Virtual address in the loader's VSpace used as a scratch page.
    pub scratch_vaddr: u64,
    /// Next CNode slot to use for frame allocation (bump allocator).
    pub next_frame_slot: Cap,
    /// Optional callback to allocate a frame slot (overrides bump allocator).
    pub alloc_frame_slot: Option<unsafe extern "C" fn(*mut u8) -> Cap>,
    /// Opaque pointer passed to `alloc_frame_slot`.
    pub alloc_opaque: *mut u8,
    /// Optional callback to record each (vaddr, frame_cap, flags) mapping.
    pub record_page: Option<unsafe extern "C" fn(*mut u8, u64, Cap, u64) -> i32>,
    /// Opaque pointer passed to `record_page`.
    pub record_opaque: *mut u8,
}

/// CPIO archive entry (basic): name pointer/length and data pointer/length.
/// Returned by `cpio_find_file` and `cpio_next`. Pointers reference data
/// within the mapped archive (no copies).
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

/// Extended CPIO archive entry: includes inode, mode, nlink, and mtime
/// parsed from the CPIO newc header fields. Used by VFS to populate
/// directory entries with proper metadata.
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

/// POSIX-compatible stat structure returned by `posix_stat` / `posix_fstat`.
/// Fields are packed into IPC message registers by the VFS server.
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

/// POSIX-compatible directory entry returned by `posix_readdir`.
/// `d_name` is null-terminated, max 61 chars + NUL.
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

/// A tracked virtual memory region in the per-process memory manager.
/// Each region records its base, length, type (heap/mmap/shm/free),
/// protection bits, and the frame capability slots backing its pages.
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

/// Global per-process memory management state for brk/mmap/munmap.
///
/// Tracks the heap (contiguous, grown via `brk`/`sbrk`) and mmap regions
/// (non-contiguous, each with its own frame caps). The heap grows upward
/// from `heap_base`; mmap regions are bump-allocated from `mmap_base`.
#[repr(C)]
pub struct PosixMmState {
    /// Untyped cap to allocate frames from.
    pub untyped: Cap,
    /// This process's VSpace cap for mapping.
    pub vspace: Cap,
    /// This process's CSpace cap for slot management.
    pub cspace: Cap,
    /// Next CNode slot for frame allocation.
    pub next_frame_slot: Cap,
    /// Upper bound on frame slot allocation.
    pub max_frame_slot: Cap,
    /// Fixed base address of the heap region.
    pub heap_base: u64,
    /// Current program break (end of allocated heap).
    pub heap_current: u64,
    /// Base address for mmap allocations.
    pub mmap_base: u64,
    /// Next available mmap address (bump allocator).
    pub mmap_next: u64,
    /// Region table tracking mmap/shm allocations.
    pub regions: [PosixMmRegion; crate::consts::MM_MAX_REGIONS],
    /// Frame cap slots backing heap pages (indexed by page offset from base).
    pub heap_frame_slots: [Cap; crate::consts::MM_MAX_PAGES_PER_REGION],
    /// 1 if initialized, 0 otherwise.
    pub initialized: i32,
}

/// Returns true if the child terminated normally (exit, not signal).
/// POSIX encoding: low 7 bits = termination signal (0 = normal exit).
pub fn wifexited(s: i32) -> bool {
    (s & 0x7f) == 0
}
/// Extract the exit code from a wait status (bits 15:8).
pub fn wexitstatus(s: i32) -> i32 {
    (s >> 8) & 0xff
}
/// Returns true if the child was terminated by a signal.
pub fn wifsignaled(s: i32) -> bool {
    (s & 0x7f) != 0 && (s & 0x7f) != 0x7f
}
/// Extract the signal number that caused termination.
pub fn wtermsig(s: i32) -> i32 {
    s & 0x7f
}
/// Returns true if the child is currently stopped.
pub fn wifstopped(s: i32) -> bool {
    (s & 0xff) == 0x7f
}
/// Extract the signal number that caused the child to stop.
pub fn wstopsig(s: i32) -> i32 {
    (s >> 8) & 0xff
}

// Signal handler type
pub type SigHandlerT = Option<unsafe extern "C" fn(i32)>;

// Special handler values encoded as usize
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

// SHM memory region type
pub const MM_REGION_SHM: u8 = 3;

/// Unix domain socket address. `sun_family` is `AF_UNIX` (1).
/// `sun_path` holds the null-terminated filesystem path (max 64 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; 64],
}

impl SockAddrUn {
    pub const fn zeroed() -> Self {
        SockAddrUn {
            sun_family: 0,
            sun_path: [0; 64],
        }
    }
}

/// POSIX poll file descriptor: `fd` to monitor, requested `events`
/// (POLLIN/POLLOUT), and returned `revents` filled by the kernel/VFS.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

impl PollFd {
    pub const fn zeroed() -> Self {
        PollFd {
            fd: -1,
            events: 0,
            revents: 0,
        }
    }
}

/// POSIX timespec: seconds + nanoseconds (used by clock_gettime, nanosleep).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec {
    pub tv_sec: u64,
    pub tv_nsec: u64,
}

impl Timespec {
    pub const fn zeroed() -> Self {
        Timespec { tv_sec: 0, tv_nsec: 0 }
    }
}

/// POSIX timeval: seconds + microseconds (used by gettimeofday).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    pub tv_sec: u64,
    pub tv_usec: u64,
}

impl Timeval {
    pub const fn zeroed() -> Self {
        Timeval { tv_sec: 0, tv_usec: 0 }
    }
}

/// POSIX termios structure for terminal I/O control. Layout matches `saltyc`.
/// Packed into IPC messages for `tcgetattr`/`tcsetattr` VFS calls.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Termios {
    pub const fn zeroed() -> Self {
        Termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; 32],
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }
}

/// Epoll event structure: `events` is a bitmask (EPOLLIN, EPOLLOUT, etc.),
/// `data` is an opaque user value associated with the fd.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

impl EpollEvent {
    pub const fn zeroed() -> Self {
        EpollEvent {
            events: 0,
            data: 0,
        }
    }
}
