//! Transactional spawn pipeline
//!
//! Uses the centralized allocator for slot management and rollback-safe
//! object creation. Replaces the stride-based handle_spawn.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;
use trona::types::pe::*;
use trona_posix::consts::*;

use crate::alloc::Allocator;
use crate::proc_table;

/// Zero `len` bytes at `ptr` using u64-wide volatile writes for bulk throughput,
/// with byte-granular head/tail for alignment.
///
/// # Safety
/// `ptr..ptr+len` must be valid, writable, and non-overlapping with any live reference.
pub(crate) unsafe fn volatile_zero(ptr: *mut u8, len: usize) {
    unsafe {
        let align_off = ptr.align_offset(8).min(len);
        for i in 0..align_off {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
        let remaining = len - align_off;
        let qwords = remaining / 8;
        let p64 = ptr.add(align_off) as *mut u64;
        for i in 0..qwords {
            core::ptr::write_volatile(p64.add(i), 0u64);
        }
        let tail_start = align_off + qwords * 8;
        for i in tail_start..len {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
}

/// Copy `len` bytes from `src` to `dst` using u64-wide volatile writes,
/// with byte-granular head/tail for alignment.
///
/// # Safety
/// `dst..dst+len` and `src..src+len` must be valid and non-overlapping.
unsafe fn volatile_copy(dst: *mut u8, src: *const u8, len: usize) {
    unsafe {
        let align_off = dst.align_offset(8).min(len);
        for i in 0..align_off {
            core::ptr::write_volatile(dst.add(i), *src.add(i));
        }
        let remaining = len - align_off;
        let qwords = remaining / 8;
        if qwords > 0 {
            let d64 = dst.add(align_off) as *mut u64;
            let s8 = src.add(align_off);
            for i in 0..qwords {
                let val = core::ptr::read_unaligned(s8.add(i * 8) as *const u64);
                core::ptr::write_volatile(d64.add(i), val);
            }
        }
        let tail_start = align_off + qwords * 8;
        for i in tail_start..len {
            core::ptr::write_volatile(dst.add(i), *src.add(i));
        }
    }
}

pub(crate) unsafe fn alloc_staging_buffer(num_pages: usize) -> *mut u8 {
    unsafe {
        let len = match (num_pages as u64).checked_mul(4096) {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        let ptr = trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr as usize == usize::MAX {
            core::ptr::null_mut()
        } else {
            ptr
        }
    }
}

pub(crate) unsafe fn free_staging_buffer(ptr: *mut u8, num_pages: usize) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        let len = match (num_pages as u64).checked_mul(4096) {
            Some(v) => v,
            None => return,
        };
        trona_posix::mm::posix_munmap(ptr, len);
    }
}

/// Pre-provision mmsrv with untyped memory if capacity is low.
/// Eliminates the Procmgr↔MMSRV deadlock cycle: instead of mmsrv
/// calling back to procmgr when out of memory (pull), procmgr
/// pushes untyped proactively before spawning (push).
///
/// Returns true if mmsrv has sufficient capacity (or was replenished).
pub(crate) unsafe fn ensure_mmsrv_capacity(alloc: &mut crate::alloc::Allocator) -> bool {
    unsafe {
        // Query mmsrv capacity
        let mut qmsg = TronaMsg::zeroed();
        let mut qreply = TronaMsg::zeroed();
        qmsg.label = trona::protocol::MM_QUERY_CAPACITY;
        qmsg.length = 0;
        let err = trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const qmsg,
            &raw mut qreply,
        );
        if err != 0 || qreply.label != trona::TRONA_OK {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] MM_QUERY_CAPACITY failed, proceeding anyway\n");
            });
            return true; // proceed optimistically
        }

        let capacity = qreply.regs[0];
        // Threshold: if fewer than 2 active UT sources, pre-provision
        if capacity >= 2 {
            return true;
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] mmsrv capacity low (");
            _lb.dec(capacity);
            _lb.str(b"), provisioning untyped\n");
        });

        provision_untyped_to_mmsrv(alloc)
    }
}

/// Provision a sub-untyped to mmsrv via MM_PROVISION_UNTYPED.
unsafe fn provision_untyped_to_mmsrv(alloc: &mut crate::alloc::Allocator) -> bool {
    unsafe {
        // Allocate a slot and retype a 256 MB sub-untyped
        let slot = match alloc.alloc_single_slot() {
            Some(s) => s,
            None => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] no slot for untyped provision\n");
                });
                return false;
            }
        };

        let err = alloc.retype_any(trona::OBJ_UNTYPED, 28, slot);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] retype sub-untyped failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            alloc.free_single_slot(slot);
            return false;
        }

        // Send the sub-untyped cap to mmsrv
        trona::ipc::set_send_cap_ctx(super::ipc_ctx(), 0, slot);
        let mut pmsg = TronaMsg::zeroed();
        let mut preply = TronaMsg::zeroed();
        pmsg.label = trona::protocol::MM_PROVISION_UNTYPED;
        pmsg.length = 1;
        pmsg.regs[0] = 28; // size_bits
        let err = trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const pmsg,
            &raw mut preply,
        );
        if err != 0 || preply.label != trona::TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] MM_PROVISION_UNTYPED failed\n");
            });
            return false;
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] provisioned 256MB untyped to mmsrv\n");
        });
        true
    }
}

/// Convert ELF `p_flags` to VSpace flags, enforcing W^X for a single segment.
fn elf_segment_vspace_flags(p_flags: u32) -> u64 {
    let mut flags = VSPACE_FLAG_USER;
    if p_flags & PF_W != 0 {
        flags |= VSPACE_FLAG_WRITABLE;
    } else if p_flags & PF_X != 0 {
        flags |= VSPACE_FLAG_EXECUTABLE;
    }
    flags
}

/// Apply final page protections for all PT_LOAD pages in an ELF image.
///
/// This merges permissions page-wise across overlapping PT_LOAD segments so a
/// trailing RW segment cannot accidentally strip execute permission from a page
/// that also contains code.
unsafe fn protect_load_pages(
    child_vspace: Cap,
    phdr_ptr: *const u8,
    phdr_count: usize,
    phdr_size: usize,
    phdr_bytes_len: usize,
    delta: u64,
) {
    unsafe {
        let mut min_page = u64::MAX;
        let mut max_page_end = 0u64;

        for i in 0..phdr_count {
            let off = i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                break;
            }
            let phdr = &*(phdr_ptr.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD || phdr.p_memsz == 0 {
                continue;
            }

            let seg_start_page = phdr.p_vaddr.wrapping_add(delta) & !0xFFFu64;
            let seg_end_page = (phdr.p_vaddr.wrapping_add(delta).wrapping_add(phdr.p_memsz) + 0xFFF) & !0xFFFu64;
            if seg_start_page < min_page {
                min_page = seg_start_page;
            }
            if seg_end_page > max_page_end {
                max_page_end = seg_end_page;
            }
        }

        if min_page == u64::MAX || max_page_end <= min_page {
            return;
        }

        let mut page = min_page;
        while page < max_page_end {
            let mut flags = VSPACE_FLAG_USER;
            let mut covered = false;

            for i in 0..phdr_count {
                let off = i * phdr_size;
                if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                    break;
                }
                let phdr = &*(phdr_ptr.add(off) as *const Elf64Phdr);
                if phdr.p_type != PT_LOAD || phdr.p_memsz == 0 {
                    continue;
                }

                let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
                let seg_start_page = seg_vaddr & !0xFFFu64;
                let seg_end_page = (seg_vaddr.wrapping_add(phdr.p_memsz) + 0xFFF) & !0xFFFu64;
                if page < seg_start_page || page >= seg_end_page {
                    continue;
                }

                covered = true;
                flags |= elf_segment_vspace_flags(phdr.p_flags);
            }

            if covered {
                if (flags & VSPACE_FLAG_WRITABLE != 0) && (flags & VSPACE_FLAG_EXECUTABLE != 0) {
                    flags &= !VSPACE_FLAG_EXECUTABLE;
                }
                let _ = trona::invoke::vspace_protect_range(child_vspace, page, 1, flags);
            }

            page = page.wrapping_add(4096);
        }
    }
}

// ---- Layout offsets within a reservation ----
// These are sequential offsets, NOT absolute cap slots.
const OFF_TCB: usize = 0;
const OFF_VSPACE: usize = 1;
const OFF_CNODE: usize = 2;
const OFF_SC: usize = 3;
const OFF_STACK_FR: usize = 4;
const OFF_IPC_FR: usize = 5;
const OFF_SIGNAL_NTFN: usize = 6;
const OFF_READY_NTFN: usize = 7;
pub(crate) const OFF_FIXED_END: usize = 8;
// Offsets >= OFF_FIXED_END are reserved but currently unused — all frame
// allocation is handled by mmsrv.

// ---- Re-exports from parent ----
const OBJ_TCB: u64 = trona::OBJ_TCB;
const OBJ_VSPACE: u64 = trona::OBJ_VSPACE;
const OBJ_CNODE: u64 = trona::OBJ_CNODE;
const OBJ_SCHED_CONTEXT: u64 = trona::OBJ_SCHED_CONTEXT;
const OBJ_FRAME: u64 = trona::OBJ_FRAME;
const OBJ_NOTIFICATION: u64 = trona::OBJ_NOTIFICATION;
const TRONA_OK: u64 = trona::TRONA_OK;
const TRONA_OUT_OF_MEMORY: u64 = trona::TRONA_OUT_OF_MEMORY;
const TRONA_NOT_FOUND: u64 = trona::TRONA_NOT_FOUND;
const TRONA_BUSY: u64 = trona::TRONA_BUSY;
const TRONA_OUT_OF_RANGE: u64 = trona::TRONA_OUT_OF_RANGE;
const TRONA_INVALID_ARGUMENT: u64 = trona::TRONA_INVALID_ARGUMENT;
const VSPACE_FLAG_WRITABLE: u64 = trona::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = trona::VSPACE_FLAG_USER;
const VSPACE_FLAG_EXECUTABLE: u64 = trona::VSPACE_FLAG_EXECUTABLE;
const PF_W: u32 = trona::PF_W;
const PF_X: u32 = trona::PF_X;
const PT_LOAD: u32 = trona::PT_LOAD;
const CAP_RIGHTS_ALL: u64 = trona::CAP_RIGHTS_ALL;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3);

use trona::layout::{self, VmLayoutPlan};

const CHILD_RTLD_FRAME_SLOT_START: u64 = super::CHILD_RTLD_FRAME_SLOT_START;
const PROCMGR_SCRATCH_VADDR: u64 = super::PROCMGR_SCRATCH_VADDR;

const CHILD_CAP_TCB: u64 = super::CHILD_CAP_TCB;
const CHILD_CAP_VSPACE: u64 = super::CHILD_CAP_VSPACE;
const CHILD_CAP_CSPACE: u64 = super::CHILD_CAP_CSPACE;
const CHILD_CAP_EP: u64 = super::CHILD_CAP_EP;
const CHILD_CAP_VFS: u64 = super::CHILD_CAP_VFS;
const CHILD_CAP_NAMESRV: u64 = super::CHILD_CAP_NAMESRV;
const CHILD_CAP_SIGNAL_NTFN: u64 = super::CHILD_CAP_SIGNAL_NTFN;
const CHILD_CAP_MMSRV_EP: u64 = super::CHILD_CAP_MMSRV_EP;
const CHILD_CAP_SC: u64 = super::CHILD_CAP_SC;
const CHILD_CAP_READINESS_NTFN: u64 = super::CHILD_CAP_READINESS_NTFN;
const CHILD_CAP_CSPACE_NTFN: u64 = super::CHILD_CAP_CSPACE_NTFN;
const CHILD_CAP_SERVICE_EP: u64 = super::CHILD_CAP_SERVICE_EP;
const CHILD_CAP_WIN32SRV_EP: u64 = super::CHILD_CAP_WIN32SRV_EP;

const CAP_SELF_CSPACE: Cap = super::CAP_SELF_CSPACE;
const CAP_SELF_VSPACE: Cap = super::CAP_SELF_VSPACE;
const CAP_SERVER_EP: Cap = super::CAP_SERVER_EP;
const CAP_RECV_SCRATCH: Cap = super::CAP_RECV_SCRATCH;
const CAP_REPLY_TEMP: Cap = super::CAP_REPLY_TEMP;
const CAP_NAMESRV_EP: Cap = super::CAP_NAMESRV_EP;
const CAP_VFS_EP: Cap = super::CAP_VFS_EP;
const CAP_FB_UNTYPED: Cap = super::CAP_FB_UNTYPED;
const CAP_INITRD_UNTYPED: Cap = super::CAP_INITRD_UNTYPED;
const CAP_MMSRV_EP: Cap = super::CAP_MMSRV_EP;
const CAP_MMSRV_EP_UNBADGED: Cap = super::CAP_MMSRV_EP_UNBADGED;

const AT_NULL: u64 = super::AT_NULL;
const AT_PHDR: u64 = super::AT_PHDR;
const AT_PHENT: u64 = super::AT_PHENT;
const AT_PHNUM: u64 = super::AT_PHNUM;
const AT_PAGESZ: u64 = super::AT_PAGESZ;
const AT_BASE: u64 = super::AT_BASE;
const AT_ENTRY: u64 = super::AT_ENTRY;
const AT_TRONA_VSPACE: u64 = super::AT_TRONA_VSPACE;
const AT_TRONA_SCRATCH: u64 = super::AT_TRONA_SCRATCH;
const AT_TRONA_INITRD: u64 = super::AT_TRONA_INITRD;
const AT_TRONA_INITRD_SZ: u64 = super::AT_TRONA_INITRD_SZ;
const AT_TRONA_FRAME_SLOT: u64 = super::AT_TRONA_FRAME_SLOT;
const AT_TRONA_SHARED_LIB_BASE: u64 = super::AT_TRONA_SHARED_LIB_BASE;
const AT_TRONA_SLOT_BASE: u64 = super::AT_TRONA_SLOT_BASE;
const AT_TRONA_SLOT_COUNT: u64 = super::AT_TRONA_SLOT_COUNT;
const AT_TRONA_CSPACE_NTFN: u64 = super::AT_TRONA_CSPACE_NTFN;
const AT_TRONA_MM_EP: u64 = super::AT_TRONA_MM_EP;
const AT_TRONA_IPC_BUFFER: u64 = super::AT_TRONA_IPC_BUFFER;
const AT_TRONA_SC_CAP: u64 = super::AT_TRONA_SC_CAP;
const AT_SALTYOS_PE_BASE: u64 = super::AT_SALTYOS_PE_BASE;
const AT_SALTYOS_PE_SIZE: u64 = super::AT_SALTYOS_PE_SIZE;
const AT_SALTYOS_WIN32SRV: u64 = super::AT_SALTYOS_WIN32SRV;
const AT_SALTYOS_KERNEL32_BASE: u64 = super::AT_SALTYOS_KERNEL32_BASE;
const AT_SALTYOS_KERNEL32_SIZE: u64 = super::AT_SALTYOS_KERNEL32_SIZE;
const CSPACE_EXPAND_BASE: u64 = super::CSPACE_EXPAND_BASE;
const READY_TIMEOUT_NS_DEFAULT: u64 = super::READY_TIMEOUT_NS_DEFAULT;
const SPAWN_FLAG_USE_PRE_EP: u64 = trona::SPAWN_FLAG_USE_PRE_EP;

#[cfg(target_arch = "aarch64")]
const STACK_ENTRY_BIAS: usize = 0;
#[cfg(target_arch = "x86_64")]
const STACK_ENTRY_BIAS: usize = 8;

const MAX_STACK_STRINGS: usize = 128;

#[derive(Clone, Copy)]
pub(crate) enum StackBuildError {
    OutOfMemory,
    InvalidArgument,
    TooLarge,
}
const SPAWN_FLAG_RESPAWN: u64 = trona::SPAWN_FLAG_RESPAWN;
const SPAWN_FLAG_START_SUSPENDED: u64 = trona::SPAWN_FLAG_START_SUSPENDED;

// ===========================================================================
// Shared library physical frame cache
// ===========================================================================

const MAX_SHARED_LIB_PAGES: usize = 1152;
const MAX_CACHED_LIBS: usize = 4;
const MAX_LIB_NAME: usize = 24;

/// Well-known CNode slots where init copies shared lib frame caps.
const CAP_SHARED_LIB_CACHE_BASE: u64 = 0x80;

#[derive(Clone, Copy)]
struct SharedPage {
    /// Offset relative to the library's own min_vaddr (NOT cumulative).
    vaddr_offset: u64,
    frame_cap: Cap,
    flags: u64,
}

const MAX_RW_SEGS: usize = 4;
const MAX_RO_SEGS: usize = 4;

/// Per-segment mapping info for RO segments within a shared lib MO.
/// MO pages are packed contiguously; `mo_page_start` gives the offset
/// within the MO for each segment.
#[derive(Clone, Copy)]
struct RoSegInfo {
    /// Offset from library min_vaddr (page-aligned down).
    vaddr_offset: u64,
    /// Starting page index within the MO.
    mo_page_start: u16,
    /// Number of pages in this segment.
    page_count: u16,
    /// VSpace flags for this RO segment (USER | optional EXECUTABLE).
    flags: u64,
}

impl RoSegInfo {
    const fn zeroed() -> Self {
        RoSegInfo { vaddr_offset: 0, mo_page_start: 0, page_count: 0, flags: 0 }
    }
}

#[derive(Clone, Copy)]
struct RwSegInfo {
    /// Offset from library min_vaddr (page-aligned down).
    vaddr_offset: u64,
    /// ELF p_offset for file data.
    file_offset: u64,
    /// p_filesz (bytes to copy from file; rest is BSS → zero).
    file_size: u64,
    /// Raw p_vaddr (for sub-page offset calculation).
    seg_vaddr: u64,
    /// p_memsz.
    memsz: u64,
    /// VSpace flags (WRITABLE | USER).
    flags: u64,
}

impl RwSegInfo {
    const fn zeroed() -> Self {
        RwSegInfo {
            vaddr_offset: 0,
            file_offset: 0,
            file_size: 0,
            seg_vaddr: 0,
            memsz: 0,
            flags: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct CachedLib {
    name: [u8; MAX_LIB_NAME],
    name_len: u8,
    page_start: u16,
    page_count: u16,
    /// Full VA span of the library (including RW segments), page-aligned.
    lib_span: u64,
    rw_segs: [RwSegInfo; MAX_RW_SEGS],
    rw_seg_count: u8,
    /// MO cap backing the RO pages (if non-zero, vspace_map_mo is used
    /// instead of per-page vspace_map during spawn, and mmsrv tracks the
    /// MO for fork/COW).
    ro_mo_cap: Cap,
    /// VSpace flags for the RO pages (e.g. USER | EXECUTABLE).
    ro_flags: u64,
    /// Offset of the first RO page relative to the library's min_vaddr.
    ro_base_offset: u64,
    /// Per-segment RO mapping info (for per-segment vspace_map_mo).
    ro_segs: [RoSegInfo; MAX_RO_SEGS],
    ro_seg_count: u8,
}

impl CachedLib {
    const fn zeroed() -> Self {
        CachedLib {
            name: [0u8; MAX_LIB_NAME],
            name_len: 0,
            page_start: 0,
            page_count: 0,
            lib_span: 0,
            rw_segs: [RwSegInfo::zeroed(); MAX_RW_SEGS],
            rw_seg_count: 0,
            ro_mo_cap: 0,
            ro_flags: 0,
            ro_base_offset: 0,
            ro_segs: [RoSegInfo::zeroed(); MAX_RO_SEGS],
            ro_seg_count: 0,
        }
    }
}

struct SharedLibCache {
    initialized: bool,
    page_count: usize,
    lib_count: usize,
    libs: [CachedLib; MAX_CACHED_LIBS],
    pages: [SharedPage; MAX_SHARED_LIB_PAGES],
}

impl SharedLibCache {
    const fn new() -> Self {
        SharedLibCache {
            initialized: false,
            page_count: 0,
            lib_count: 0,
            libs: [CachedLib::zeroed(); MAX_CACHED_LIBS],
            pages: [SharedPage {
                vaddr_offset: 0,
                frame_cap: 0,
                flags: 0,
            }; MAX_SHARED_LIB_PAGES],
        }
    }
}

static mut SHARED_LIB_CACHE: SharedLibCache = SharedLibCache::new();

// ===========================================================================
// Spawn plan
// ===========================================================================

struct SpawnPlan {
    is_dynamic: bool,
    readiness_mode: u64,
    ready_timeout_ns: u64,
    total_slots: usize,
    is_display: bool,
    lib_window_pages: usize,
    layout: VmLayoutPlan,
}

/// Compute total slots needed for a spawn.
///
/// All frame allocation (ELF, RTLD, stack, initrd, boot info) is handled
/// by mmsrv. Procmgr only needs slots for the fixed kernel objects.
fn compute_slot_budget() -> usize {
    OFF_FIXED_END + 6 // 8 fixed slots + margin
}

/// Count RTLD VA span for use from exec path.
///
/// # Safety
/// All pointers must be valid for their declared lengths.
pub(crate) unsafe fn count_rtld_span_for_exec(
    elf_data: *const u8,
    elf_data_len: usize,
    initrd: *const u8,
    initrd_size: usize,
) -> u64 {
    unsafe { count_rtld_span(elf_data, elf_data_len, initrd, initrd_size) }
}

/// Count RTLD VA span by looking up the interpreter in the initrd.
///
/// # Safety
/// All pointers must be valid for their declared lengths.
unsafe fn count_rtld_span(
    elf_data: *const u8,
    elf_data_len: usize,
    initrd: *const u8,
    initrd_size: usize,
) -> u64 {
    unsafe {
        const DEFAULT_RTLD: &[u8] = b"ld-trona.so";
        let mut rtld_name = DEFAULT_RTLD.as_ptr();
        let mut rtld_name_len = DEFAULT_RTLD.len();

        let interp = trona_loader::elf_dynamic::elf_get_interp(elf_data, elf_data_len);
        if !interp.is_null() && *interp != 0 {
            let mut last = interp;
            let mut p = interp;
            while *p != 0 {
                if *p == b'/' {
                    last = p.add(1);
                }
                p = p.add(1);
            }
            if *last != 0 {
                rtld_name = last;
                rtld_name_len = strlen(last);
            }
        }

        let mut rtld_entry = CpioEntry::zeroed();
        if trona_loader::cpio::cpio_find_file(
            initrd,
            initrd_size,
            rtld_name,
            rtld_name_len,
            &raw mut rtld_entry,
        ) == 0
        {
            return 5 * 4096; // fallback estimate
        }

        let span = trona_loader::elf_loader::elf_compute_load_span(rtld_entry.data, rtld_entry.data_len);
        if span == 0 {
            5 * 4096
        } else {
            span
        }
    }
}

pub(crate) unsafe fn count_rtld_span_by_name(
    rtld_name: *const u8,
    rtld_name_len: usize,
    initrd: *const u8,
    initrd_size: usize,
) -> u64 {
    unsafe {
        let mut rtld_entry = CpioEntry::zeroed();
        if trona_loader::cpio::cpio_find_file(
            initrd,
            initrd_size,
            rtld_name,
            rtld_name_len,
            &raw mut rtld_entry,
        ) == 0
        {
            return 5 * 4096;
        }

        let span = trona_loader::elf_loader::elf_compute_load_span(rtld_entry.data, rtld_entry.data_len);
        if span == 0 {
            5 * 4096
        } else {
            span
        }
    }
}

/// Return the total VA pages needed for the specified DT_NEEDED libraries.
/// Accounts for full library spans (including RW segments) plus inter-lib gaps.
pub(crate) fn shared_lib_va_pages_for_needed(needed: &trona_loader::elf_dynamic::NeededLibs) -> usize {
    unsafe {
        let cache = &*(&raw const SHARED_LIB_CACHE);
        if !cache.initialized || needed.count == 0 {
            return 0;
        }
        let mut total_bytes: u64 = 0;
        for ni in 0..needed.count {
            let name = &needed.names[ni][..needed.name_lens[ni]];
            for li in 0..cache.lib_count {
                let cl = &cache.libs[li];
                let cl_name = &cl.name[..cl.name_len as usize];
                if cl_name.len() == name.len() {
                    let mut eq = true;
                    for k in 0..name.len() {
                        if cl_name[k] != name[k] {
                            eq = false;
                            break;
                        }
                    }
                    if eq {
                        total_bytes += cl.lib_span + 4096; // span + gap
                        break;
                    }
                }
            }
        }
        ((total_bytes + 0xFFF) / 0x1000) as usize
    }
}

fn compute_ready_timeout_ns(
    configured_timeout_ns: u64,
    is_dynamic: bool,
    elf_size_bytes: usize,
    lib_window_pages: usize,
) -> u64 {
    if configured_timeout_ns != 0 {
        return configured_timeout_ns;
    }

    let mut timeout_ns = READY_TIMEOUT_NS_DEFAULT;
    if is_dynamic {
        timeout_ns = timeout_ns.saturating_add(3_000_000_000);
    }

    let elf_chunks = ((elf_size_bytes as u64).saturating_add(128 * 1024 - 1)) / (128 * 1024);
    let elf_bonus_ms = core::cmp::min(elf_chunks.saturating_mul(150), 4_000);
    timeout_ns = timeout_ns.saturating_add(elf_bonus_ms.saturating_mul(1_000_000));

    let lib_bonus_ms = core::cmp::min(lib_window_pages as u64 * 8, 3_000);
    timeout_ns.saturating_add(lib_bonus_ms.saturating_mul(1_000_000))
}

// ===========================================================================
// Library window computation for selective initrd mapping
// ===========================================================================

/// Scan CPIO for shared library entries (.so) and return the page-aligned
/// end offset of the last library. Libraries are packed first in the CPIO
/// (ensured by meson.build ordering), so this gives the minimal mapping
/// window for the runtime linker.
pub(crate) unsafe fn compute_lib_window_pages(initrd: *const u8, initrd_size: usize) -> usize {
    unsafe {
        let mut offset: usize = 0;
        let mut max_data_end: usize = 0;

        loop {
            let mut entry = CpioEntry::zeroed();
            if trona_loader::cpio::cpio_next(initrd, initrd_size, &raw mut offset, &raw mut entry) == 0 {
                break;
            }
            // Check if name ends with ".so"
            if entry.name_len >= 3 {
                let n = core::slice::from_raw_parts(entry.name, entry.name_len);
                if n[entry.name_len - 3] == b'.'
                    && n[entry.name_len - 2] == b's'
                    && n[entry.name_len - 1] == b'o'
                {
                    // data pointer relative to archive start
                    let data_offset = entry.data as usize - initrd as usize;
                    let end = data_offset + entry.data_len;
                    if end > max_data_end {
                        max_data_end = end;
                    }
                }
            }
        }

        if max_data_end == 0 {
            // No libraries found — map full initrd
            return (initrd_size + 4095) / 4096;
        }

        (max_data_end + 4095) / 4096
    }
}

// ===========================================================================
// Shared library frame cache: init and map
// ===========================================================================

/// Pre-load shared library RO segments into a permanent frame cache.
/// First checks for inherited frame caps from init (at CAP_SHARED_LIB_CACHE_BASE).
/// If inherited caps exist, uses them directly (zero frame allocation).
/// Otherwise falls back to self-allocation from the allocator.
pub(crate) unsafe fn init_shared_lib_cache(alloc: &mut Allocator) {
    unsafe {
        let cache = &mut *(&raw mut SHARED_LIB_CACHE);

        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::read_boot_info_initrd_size();

        // Check if init passed us inherited frame caps.
        // Probe the first slot — if it contains a valid cap, init pre-loaded the cache.
        // Try to inherit metadata (RW segment info, names) from init's
        // pre-loaded cache.  RO pages are always backed by MOs built from
        // the initrd below, so inherited Frame caps are unused.
        let _ = try_inherit_shared_lib_cache(cache, initrd, initrd_size, alloc);

        // Build MO-backed shared library cache from initrd.
        // For each library: parse ELF, create MO, populate RO pages
        // from the initrd, record RW segment metadata.
        let libs: [&[u8]; 3] = [b"libtrona.so", b"libc.so", b"libc++.so"];

        for lib_name in &libs {
            if cache.lib_count >= MAX_CACHED_LIBS {
                break;
            }

            // Skip libraries that already have MO. If an inherited entry
            // exists without MO, record its index so the MO rebuild updates
            // it in-place instead of appending a duplicate.
            let mut already_has_mo = false;
            let mut inherited_idx: usize = usize::MAX;
            for ei in 0..cache.lib_count {
                let el = &cache.libs[ei];
                let el_name = &el.name[..el.name_len as usize];
                if el_name.len() == lib_name.len() {
                    let mut eq = true;
                    for k in 0..lib_name.len() {
                        if el_name[k] != lib_name[k] { eq = false; break; }
                    }
                    if eq {
                        if el.ro_mo_cap != 0 {
                            already_has_mo = true;
                            break;
                        }
                        inherited_idx = ei;
                    }
                }
            }
            if already_has_mo { continue; }

            let mut entry = CpioEntry::zeroed();
            if trona_loader::cpio::cpio_find_file(
                initrd, initrd_size,
                lib_name.as_ptr(), lib_name.len(),
                &raw mut entry,
            ) == 0 { continue; }

            if entry.data_len < core::mem::size_of::<Elf64Ehdr>() { continue; }
            let ehdr = &*(entry.data as *const Elf64Ehdr);
            if ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != b'E'
                || ehdr.e_ident[2] != b'L' || ehdr.e_ident[3] != b'F'
            { continue; }
            if ehdr.e_type != trona::ET_DYN { continue; }

            let phdrs = entry.data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;
            let mut min_vaddr: u64 = u64::MAX;
            let mut max_seg_end: u64 = 0;
            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type == trona::PT_LOAD {
                    if ph.p_vaddr < min_vaddr { min_vaddr = ph.p_vaddr; }
                    let se = (ph.p_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;
                    if se > max_seg_end { max_seg_end = se; }
                }
            }
            if min_vaddr == u64::MAX { continue; }
            let lib_span = max_seg_end - (min_vaddr & !0xFFFu64);

            // --- Pass 1: count RO pages (compact) and record RW/RO segment metadata ---
            // MO pages are packed contiguously (no gaps). Each RO segment
            // records its vaddr_offset and mo_page_start so map_shared_libs
            // can issue per-segment vspace_map_mo calls at correct VAs.
            let mut ro_page_count: usize = 0;
            let mut ro_base_offset: u64 = u64::MAX;
            let mut ro_flags: u64 = VSPACE_FLAG_USER;
            let min_vaddr_aligned = min_vaddr & !0xFFFu64;

            // Update inherited entry in-place or append new entry
            let li = if inherited_idx != usize::MAX { inherited_idx } else { cache.lib_count };
            let mut lib_entry = if inherited_idx != usize::MAX {
                cache.libs[inherited_idx]
            } else {
                CachedLib::zeroed()
            };
            let copy_len = if lib_name.len() > MAX_LIB_NAME { MAX_LIB_NAME } else { lib_name.len() };
            for j in 0..copy_len { lib_entry.name[j] = lib_name[j]; }
            lib_entry.name_len = copy_len as u8;
            lib_entry.lib_span = lib_span;
            lib_entry.ro_seg_count = 0;

            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type != trona::PT_LOAD { continue; }

                if (ph.p_flags & trona::PF_W) != 0 {
                    if (lib_entry.rw_seg_count as usize) < MAX_RW_SEGS {
                        let idx = lib_entry.rw_seg_count as usize;
                        let flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
                        lib_entry.rw_segs[idx] = RwSegInfo {
                            vaddr_offset: (ph.p_vaddr & !0xFFFu64) - min_vaddr_aligned,
                            file_offset: ph.p_offset,
                            file_size: ph.p_filesz,
                            seg_vaddr: ph.p_vaddr,
                            memsz: ph.p_memsz,
                            flags,
                        };
                        lib_entry.rw_seg_count += 1;
                    }
                    continue;
                }

                // RO segment — pack contiguously in MO, record per-segment info
                let seg_start = ph.p_vaddr & !0xFFFu64;
                let seg_end = (ph.p_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;
                let seg_pages = ((seg_end - seg_start) / 4096) as usize;
                let vaddr_offset = seg_start - min_vaddr_aligned;
                let seg_flags = if (ph.p_flags & trona::PF_X) != 0 {
                    VSPACE_FLAG_USER | VSPACE_FLAG_EXECUTABLE
                } else {
                    VSPACE_FLAG_USER
                };
                if vaddr_offset < ro_base_offset { ro_base_offset = vaddr_offset; }

                if (lib_entry.ro_seg_count as usize) < MAX_RO_SEGS {
                    let si = lib_entry.ro_seg_count as usize;
                    lib_entry.ro_segs[si] = RoSegInfo {
                        vaddr_offset,
                        mo_page_start: ro_page_count as u16,
                        page_count: seg_pages as u16,
                        flags: seg_flags,
                    };
                    lib_entry.ro_seg_count += 1;
                }

                ro_page_count += seg_pages;

                if (ph.p_flags & trona::PF_X) != 0 {
                    ro_flags |= VSPACE_FLAG_EXECUTABLE;
                }
            }

            // --- Pass 1.5: detect and resolve RO/RW boundary page overlaps ---
            for ri in 0..lib_entry.ro_seg_count as usize {
                let ro_end = lib_entry.ro_segs[ri].vaddr_offset
                    + (lib_entry.ro_segs[ri].page_count as u64) * 4096;
                for wi in 0..lib_entry.rw_seg_count as usize {
                    let rw_start = lib_entry.rw_segs[wi].vaddr_offset;
                    if ro_end > rw_start
                        && lib_entry.ro_segs[ri].vaddr_offset < rw_start
                    {
                        let overlap = ((ro_end - rw_start) / 4096) as u16;
                        if overlap > 0 && overlap <= lib_entry.ro_segs[ri].page_count {
                            lib_entry.ro_segs[ri].page_count -= overlap;
                            ro_page_count -= overlap as usize;
                        }
                    }
                }
            }

            if ro_page_count == 0 {
                cache.libs[li] = lib_entry;
                if inherited_idx == usize::MAX {
                    cache.lib_count += 1;
                }
                continue;
            }
            if ro_base_offset == u64::MAX { ro_base_offset = 0; }

            // --- Pass 2: allocate MO and populate from initrd ---
            let mut sb: u64 = 0;
            while (1u64 << sb) < ro_page_count as u64 { sb += 1; }

            // Allocate MO via mmsrv
            let mo_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => continue,
            };
            {
                let mut msg = TronaMsg::zeroed();
                let mut rpl = TronaMsg::zeroed();
                msg.label = trona::protocol::MM_ALLOC_OBJECT;
                msg.length = 2;
                msg.regs[0] = trona::OBJ_MEMORY_OBJECT;
                msg.regs[1] = sb;
                trona::ipc::set_receive_slot_ctx(
                    super::ipc_ctx(), super::CAP_SELF_CSPACE, mo_slot, 0,
                );
                let err = trona::ipc::call_ctx(
                    super::ipc_ctx(), super::CAP_MMSRV_EP,
                    &raw const msg, &raw mut rpl,
                );
                if err != 0 || rpl.label != trona::TRONA_OK {
                    alloc.free_single_slot(mo_slot);
                    continue;
                }
            }

            // Commit all RO pages (try untyped sources, then PMM fallback)
            let (err, committed) = alloc.commit_mo_pages(mo_slot, 0, ro_page_count as u64);
            if err != 0 || committed != ro_page_count as u64 {
                alloc.free_single_slot(mo_slot);
                continue;
            }

            // Copy content from initrd into MO pages (packed contiguously).
            let scratch = PROCMGR_SCRATCH_VADDR;
            let mut mo_pi: u64 = 0;
            let mut populate_ok = true;

            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type != trona::PT_LOAD || (ph.p_flags & trona::PF_W) != 0 {
                    continue;
                }

                let seg_vaddr = ph.p_vaddr;
                let seg_start = seg_vaddr & !0xFFFu64;
                let seg_end = (seg_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;

                let mut page = seg_start;
                while page < seg_end {
                    // Map this MO page to scratch (writable)
                    let cf = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
                    let err = trona::invoke::vspace_map_mo(
                        CAP_SELF_VSPACE, mo_slot, scratch, mo_pi, cf,
                    );
                    if err != 0 {
                        populate_ok = false;
                        break;
                    }

                    let dst = scratch as *mut u8;
                    volatile_zero(dst, 4096);

                    // Copy file content
                    let file_start = seg_vaddr;
                    let file_end = seg_vaddr + ph.p_filesz;
                    let copy_start = if page > file_start { page } else { file_start };
                    let copy_end = if page + 4096 < file_end { page + 4096 } else { file_end };

                    if copy_start < copy_end {
                        let data_offset = (copy_start - seg_vaddr + ph.p_offset) as usize;
                        let page_offset = (copy_start - page) as usize;
                        let copy_len = (copy_end - copy_start) as usize;
                        if data_offset + copy_len <= entry.data_len {
                            let src = entry.data.add(data_offset);
                            volatile_copy(dst.add(page_offset), src, copy_len);
                        }
                    }

                    trona::invoke::vspace_unmap(CAP_SELF_VSPACE, scratch);
                    mo_pi += 1;
                    page += 4096;
                }
                if !populate_ok { break; }
            }

            if !populate_ok {
                alloc.free_single_slot(mo_slot);
                continue;
            }

            lib_entry.page_count = ro_page_count as u16;
            lib_entry.ro_mo_cap = mo_slot;
            lib_entry.ro_flags = ro_flags;
            lib_entry.ro_base_offset = ro_base_offset;
            cache.libs[li] = lib_entry;
            if inherited_idx == usize::MAX {
                cache.lib_count += 1;
            }
            cache.page_count += ro_page_count;
        }

        if cache.page_count > 0 {
            let mut valid = true;
            for i in 0..cache.lib_count {
                let cl = &cache.libs[i];
                if cl.page_count > 0 && cl.ro_mo_cap == 0 {
                    valid = false;
                    break;
                }
            }
            if valid {
                cache.initialized = true;
            } else {
                *cache = SharedLibCache::new();
            }
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] shared lib cache: ");
            _lb.hex(cache.page_count as u64);
            _lb.str(b" RO pages (MO-backed)\n");
        });
    }
}

/// Try to inherit pre-loaded shared library frame caps from init.
/// Init copies frame caps to slots CAP_SHARED_LIB_CACHE_BASE..+N.
/// We re-parse the same ELF headers to reconstruct the metadata
/// (vaddr_offset, flags) and pair them with the inherited caps.
/// Returns true if inheritance succeeded.
unsafe fn try_inherit_shared_lib_cache(
    cache: &mut SharedLibCache,
    initrd: *const u8,
    initrd_size: usize,
    alloc: &mut Allocator,
) -> bool {
    unsafe {
        // Probe the first inherited slot to check if init passed us caps.
        // Use vspace_map as a probe — if the cap exists and is a frame,
        // this will succeed (we immediately unmap).
        let probe_slot = CAP_SHARED_LIB_CACHE_BASE;
        let probe_err = trona::invoke::vspace_map(
            CAP_SELF_VSPACE,
            probe_slot,
            PROCMGR_SCRATCH_VADDR,
            VSPACE_FLAG_USER,
        );
        if probe_err != 0 {
            return false;
        }
        trona::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

        trona::uinfo!(|_lb| { _lb.str(b"[PROCMGR] inherited shared lib caps from init\n"); });

        // Reserve the entire inherited shared-lib slot namespace in allocator
        // so transactional reservations never overlap these pre-existing caps.
        for i in 0..MAX_SHARED_LIB_PAGES {
            let cap_slot = CAP_SHARED_LIB_CACHE_BASE + i as u64;
            alloc.mark_slot_used(cap_slot);
        }

        // Walk both libraries in the same order as init's cache builder.
        let libs: [&[u8]; 3] = [b"libtrona.so", b"libc.so", b"libc++.so"];
        let mut inherited_idx: usize = 0;

        for lib_name in &libs {
            if cache.lib_count >= MAX_CACHED_LIBS {
                break;
            }

            let mut entry = CpioEntry::zeroed();
            if trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                lib_name.as_ptr(),
                lib_name.len(),
                &raw mut entry,
            ) == 0
            {
                continue;
            }

            if entry.data_len < core::mem::size_of::<Elf64Ehdr>() {
                continue;
            }
            let ehdr = &*(entry.data as *const Elf64Ehdr);
            if ehdr.e_ident[0] != 0x7F
                || ehdr.e_ident[1] != b'E'
                || ehdr.e_ident[2] != b'L'
                || ehdr.e_ident[3] != b'F'
            {
                continue;
            }
            if ehdr.e_type != trona::ET_DYN {
                continue;
            }

            let phdrs = entry.data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;
            let mut min_vaddr: u64 = u64::MAX;
            let mut max_seg_end: u64 = 0;
            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type == trona::PT_LOAD {
                    if ph.p_vaddr < min_vaddr {
                        min_vaddr = ph.p_vaddr;
                    }
                    let se = (ph.p_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;
                    if se > max_seg_end {
                        max_seg_end = se;
                    }
                }
            }
            if min_vaddr == u64::MAX {
                continue;
            }
            let lib_span = max_seg_end - (min_vaddr & !0xFFFu64);

            let li = cache.lib_count;
            let page_start = cache.page_count as u16;
            let mut lib_entry = CachedLib::zeroed();
            let copy_len = if lib_name.len() > MAX_LIB_NAME {
                MAX_LIB_NAME
            } else {
                lib_name.len()
            };
            for j in 0..copy_len {
                lib_entry.name[j] = lib_name[j];
            }
            lib_entry.name_len = copy_len as u8;
            lib_entry.lib_span = lib_span;

            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type != trona::PT_LOAD {
                    continue;
                }

                // Record RW segments as metadata (mapped per-child later)
                if (ph.p_flags & trona::PF_W) != 0 {
                    if (lib_entry.rw_seg_count as usize) < MAX_RW_SEGS {
                        let idx = lib_entry.rw_seg_count as usize;
                        // W^X: writable segments never get executable permission
                        let flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
                        lib_entry.rw_segs[idx] = RwSegInfo {
                            vaddr_offset: (ph.p_vaddr & !0xFFFu64) - (min_vaddr & !0xFFFu64),
                            file_offset: ph.p_offset,
                            file_size: ph.p_filesz,
                            seg_vaddr: ph.p_vaddr,
                            memsz: ph.p_memsz,
                            flags,
                        };
                        lib_entry.rw_seg_count += 1;
                    }
                    continue;
                }

                let seg_vaddr = ph.p_vaddr;
                let seg_start = seg_vaddr & !0xFFFu64;
                let seg_end = (seg_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;

                let mut flags = VSPACE_FLAG_USER;
                if (ph.p_flags & trona::PF_X) != 0 {
                    flags |= VSPACE_FLAG_EXECUTABLE;
                }

                let mut page = seg_start;
                while page < seg_end {
                    if cache.page_count >= MAX_SHARED_LIB_PAGES {
                        break;
                    }
                    if inherited_idx >= MAX_SHARED_LIB_PAGES {
                        break;
                    }

                    let cap_slot = CAP_SHARED_LIB_CACHE_BASE + inherited_idx as u64;

                    cache.pages[cache.page_count] = SharedPage {
                        vaddr_offset: page - min_vaddr,
                        frame_cap: cap_slot,
                        flags,
                    };
                    cache.page_count += 1;
                    inherited_idx += 1;
                    page += 4096;
                }
            }

            lib_entry.page_start = page_start;
            lib_entry.page_count = (cache.page_count as u16) - page_start;
            cache.libs[li] = lib_entry;
            cache.lib_count += 1;
        }

        if cache.page_count > 0 {
            cache.initialized = true;
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] shared lib cache: ");
                _lb.hex(cache.page_count as u64);
                _lb.str(b" RO pages (inherited)\n");
            });
            return true;
        }

        false
    }
}

/// Map cached shared library frames into a child VSpace, mapping only
/// libraries listed in `needed` in their DT_NEEDED order.
/// RO pages are mapped from the shared frame cache (shared across processes).
/// RW pages are allocated per-child via mmsrv copy transactions and populated
/// from a staged image built from the initrd; BSS is zeroed.
/// `shared_lib_base_vaddr` is the layout-computed VA where libs start.
/// Returns (lib_load_addr, ProcLibMap) on success, (0, empty) on failure.
pub(crate) unsafe fn map_shared_lib_to_vspace(
    child_vs: Cap,
    shared_lib_base_vaddr: u64,
    needed: &trona_loader::elf_dynamic::NeededLibs,
    pid: u32,
) -> (u64, proc_table::ProcLibMap) {
    let empty = proc_table::ProcLibMap::zeroed();
    unsafe {
        let cache = &*(&raw const SHARED_LIB_CACHE);
        if !cache.initialized || cache.page_count == 0 || shared_lib_base_vaddr == 0 {
            return (0, empty);
        }
        if needed.count == 0 {
            return (0, empty);
        }

        let mut lib_map = proc_table::ProcLibMap::zeroed();
        let mut running_base = shared_lib_base_vaddr;

        // Map libraries in DT_NEEDED order
        for ni in 0..needed.count {
            let name = &needed.names[ni][..needed.name_lens[ni]];

            // Find this library in the cache
            let mut found = false;
            for li in 0..cache.lib_count {
                let cl = &cache.libs[li];
                let cl_name = &cl.name[..cl.name_len as usize];
                if cl_name.len() != name.len() {
                    continue;
                }
                let mut eq = true;
                for k in 0..name.len() {
                    if cl_name[k] != name[k] {
                        eq = false;
                        break;
                    }
                }
                if !eq {
                    continue;
                }

                // Record in ProcLibMap
                if (lib_map.count as usize) < proc_table::MAX_PROC_MAPPED_LIBS {
                    lib_map.lib_idx[lib_map.count as usize] = li as u8;
                    lib_map.base[lib_map.count as usize] = running_base;
                    lib_map.count += 1;
                }

                // Map this library's RO pages at running_base
                let ps = cl.page_start as usize;
                let pc = cl.page_count as usize;

                if cl.ro_mo_cap != 0 {
                    // MO-backed: map each RO segment separately using its
                    // mo_page_start offset. This handles gaps between segments
                    // without wasting physical pages on zero-filled gap pages.
                    for si in 0..cl.ro_seg_count as usize {
                        let seg = &cl.ro_segs[si];
                        let seg_vaddr = running_base + seg.vaddr_offset;
                        let count_and_flags =
                            ((seg.page_count as u64) << 32) | seg.flags;
                        let (err, mapped) = trona::invoke::vspace_map_mo_with_count(
                            child_vs,
                            cl.ro_mo_cap,
                            seg_vaddr,
                            seg.mo_page_start as u64,
                            count_and_flags,
                        );
                        if err != 0 || mapped != seg.page_count as u64 {
                            trona::uerror!(|_lb| {
                                _lb.str(b"[PROCMGR] shared lib MO map failed seg=");
                                _lb.hex(si as u64);
                                _lb.str(b" err=");
                                _lb.hex(err as u64);
                                _lb.str(b"\n");
                            });
                            return (0, empty);
                        }
                    }
                } else {
                    // Fallback: per-page Frame cap mapping
                    for pi in 0..pc {
                        let page = &cache.pages[ps + pi];
                        let vaddr = running_base + page.vaddr_offset;
                        let err =
                            trona::invoke::vspace_map(child_vs, page.frame_cap, vaddr, page.flags);
                        if err != 0 {
                            trona::uerror!(|_lb| {
                                _lb.str(b"[PROCMGR] shared lib map failed at ");
                                _lb.hex(vaddr);
                                _lb.str(b" err=");
                                _lb.hex(err as u64);
                                _lb.str(b"\n");
                            });
                            return (0, empty);
                        }
                    }
                }

                // Map RW segments (per-child private copies via mmsrv)
                if !map_rw_segments(cl, running_base, pid) {
                    return (0, empty);
                }

                // Register each RO segment with mmsrv as a separate region.
                // Each call transfers a copy of the MO cap so every segment's
                // region in mmsrv has its own cap reference.
                for si in 0..cl.ro_seg_count as usize {
                    let seg = &cl.ro_segs[si];
                    let mut sr_msg = TronaMsg::zeroed();
                    let mut sr_reply = TronaMsg::zeroed();
                    sr_msg.label = trona::protocol::MM_REGISTER_SHARED_REGION;
                    sr_msg.length = 6;
                    sr_msg.regs[0] = pid as u64;
                    sr_msg.regs[1] = running_base + seg.vaddr_offset;
                    sr_msg.regs[2] = seg.page_count as u64;
                    sr_msg.regs[3] = if cl.ro_mo_cap != 0 { 1 } else { 0 };
                    sr_msg.regs[4] = seg.mo_page_start as u64; // mo_offset
                    sr_msg.regs[5] = seg.flags;

                    if cl.ro_mo_cap != 0 {
                        // Transfer MO cap on every segment call.
                        // The cap is shared (not moved) — IPC cap transfer
                        // copies the cap, so the original stays valid.
                        trona::ipc::set_send_cap_ctx(
                            super::ipc_ctx(),
                            0,
                            cl.ro_mo_cap,
                        );
                    }
                    let _ = trona::ipc::call_ctx(
                        super::ipc_ctx(),
                        CAP_MMSRV_EP,
                        &raw const sr_msg,
                        &raw mut sr_reply,
                    );
                }

                running_base += cl.lib_span + 4096; // advance past this lib + gap
                found = true;
                break;
            }

            if !found {
                trona::udebug!(|_lb| {
                    _lb.str(b"[PROCMGR] shared lib cache miss: ");
                    _lb.bytes(name);
                    _lb.str(b"\n");
                });
            }
        }

        if lib_map.count > 0 {
            (shared_lib_base_vaddr, lib_map)
        } else {
            (0, empty)
        }
    }
}

/// Allocate and populate RW segment pages for a shared library in a child process.
/// Uses a local staging buffer plus mmsrv copy transactions so procmgr does not
/// need a direct writable mapping of the child region.
///
/// lld-20 RELRO split can produce multiple RW PT_LOAD segments whose page-aligned
/// ranges overlap (e.g. seg4 vaddr=0x43000, seg5 vaddr=0x43F20 both page-align to
/// 0x43000). To avoid overlapping child-region allocation, we merge all RW
/// segments into a single contiguous page range and populate it in one staged
/// copy transaction.
/// Returns true on success.
unsafe fn map_rw_segments(cl: &CachedLib, running_base: u64, pid: u32) -> bool {
    unsafe {
        if cl.rw_seg_count == 0 {
            return true;
        }

        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::read_boot_info_initrd_size();

        // Find this library in the initrd to get file data for .data copy
        let mut entry = CpioEntry::zeroed();
        let lib_name = &cl.name[..cl.name_len as usize];
        if trona_loader::cpio::cpio_find_file(
            initrd,
            initrd_size,
            lib_name.as_ptr(),
            lib_name.len(),
            &raw mut entry,
        ) == 0
        {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] RW map: lib not found in initrd\n"); });
            return false;
        }

        // Compute the merged page range across all RW segments to handle
        // overlapping pages from lld-20's RELRO split.
        let mut merged_start = u64::MAX;
        let mut merged_end: u64 = 0;
        let mut merged_flags: u64 = 0;
        for si in 0..cl.rw_seg_count as usize {
            let rw = &cl.rw_segs[si];
            let seg_start = running_base + rw.vaddr_offset;
            let seg_end =
                (running_base + rw.vaddr_offset + (rw.seg_vaddr & 0xFFF) + rw.memsz + 0xFFF)
                    & !0xFFFu64;
            if seg_start < merged_start {
                merged_start = seg_start;
            }
            if seg_end > merged_end {
                merged_end = seg_end;
            }
            merged_flags |= rw.flags;
        }
        if merged_start >= merged_end {
            return true;
        }
        let merged_pages = ((merged_end - merged_start) / 4096) as usize;
        if merged_pages == 0 {
            return true;
        }

        let stage = alloc_staging_buffer(merged_pages);
        if stage.is_null() {
            return false;
        }

        let status = (|| -> bool {
            volatile_zero(stage, merged_pages * 4096);

            // Copy file data from each segment at its correct offset.
            for si in 0..cl.rw_seg_count as usize {
                let rw = &cl.rw_segs[si];
                if rw.file_size == 0 {
                    continue;
                }
                let seg_start = running_base + rw.vaddr_offset;
                let sub_page_off = (rw.seg_vaddr & 0xFFF) as usize;
                let file_off = rw.file_offset as usize;
                let copy_len = rw.file_size as usize;
                let window_off = (seg_start - merged_start) as usize + sub_page_off;

                if file_off + copy_len <= entry.data_len {
                    let src = entry.data.add(file_off);
                    let dst = stage.add(window_off);
                    volatile_copy(dst, src, copy_len);
                }
            }

            // Copy RO tail data for boundary pages trimmed from the RO MO.
            if entry.data_len >= core::mem::size_of::<Elf64Ehdr>() {
                let ehdr = &*(entry.data as *const Elf64Ehdr);
                let elf_phdrs = entry.data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;
                let merged_vaddr_start = merged_start - running_base;
                let merged_vaddr_end = merged_vaddr_start + (merged_pages as u64) * 4096;
                for pi in 0..ehdr.e_phnum as usize {
                    let ph = &*elf_phdrs.add(pi);
                    if ph.p_type != trona::PT_LOAD || (ph.p_flags & trona::PF_W) != 0 {
                        continue;
                    }
                    let seg_file_end = ph.p_vaddr + ph.p_filesz;
                    if seg_file_end <= merged_vaddr_start || (ph.p_vaddr & !0xFFFu64) >= merged_vaddr_end {
                        continue;
                    }
                    let overlap_start = if ph.p_vaddr > merged_vaddr_start { ph.p_vaddr } else { merged_vaddr_start };
                    let overlap_end = if seg_file_end < merged_vaddr_end { seg_file_end } else { merged_vaddr_end };
                    if overlap_start >= overlap_end {
                        continue;
                    }
                    let file_off = (overlap_start - ph.p_vaddr + ph.p_offset) as usize;
                    let window_off = (overlap_start - merged_vaddr_start) as usize;
                    let copy_len = (overlap_end - overlap_start) as usize;
                    if file_off + copy_len <= entry.data_len {
                        let src = entry.data.add(file_off);
                        let dst = stage.add(window_off);
                        volatile_copy(dst, src, copy_len);
                    }
                }
            }

            let region_base = match alloc_private_copy_from_client_region_to_mmsrv(
                pid,
                merged_start,
                merged_pages as u64,
                merged_start,
                stage as u64,
                merged_pages as u64,
                merged_flags,
            ) {
                Ok(v) => v,
                Err((err, label, mapped)) => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] RW MM_ALLOC_PRIVATE_COPY failed err=");
                        _lb.hex(err as u64);
                        _lb.str(b" label=");
                        _lb.hex(label);
                        _lb.str(b" mapped=");
                        _lb.hex(mapped);
                        _lb.str(b"\n");
                    });
                    return false;
                }
            };
            if region_base != merged_start {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] RW MM_ALLOC_PRIVATE_COPY base mismatch\n");
                });
                return false;
            }

            true
        })();

        free_staging_buffer(stage, merged_pages);
        status
    }
}

// ===========================================================================
// Shared helpers: write_dynamic_stack and strlen
// ===========================================================================

unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

/// Build the auxv/dynamic stack for a dynamically-linked child.
/// `initrd_window_size` is the size of the initrd window visible to the child
/// (may be less than full archive if using selective mapping).
/// `shared_lib_base` is the load address of pre-mapped shared library RO pages
/// (0 if not using shared lib cache).
/// `argc`/`envc`/`str_data`/`str_len`: serialized argv+envp strings (null-terminated,
/// packed contiguously). When argc==0 and str_len==0, the stack gets argc=0 with
/// no argv/envp pointers (backward-compatible spawn path).
pub(crate) unsafe fn write_dynamic_stack(
    phdr_vaddr: u64,
    phent: u64,
    phnum: u64,
    stk_frame: Cap,
    elf_result: &ElfLoadResult,
    rtld_result: &ElfLoadResult,
    initrd_window_size: usize,
    shared_lib_base: u64,
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    scratch_vaddr: u64,
    initrd_vaddr: u64,
    stack_top: u64,
    _cnode_bits: u64,
    slot_pool_floor: u64,
    page_base: *mut u8,
    pre_mapped: bool,
) -> Result<u64, StackBuildError> {
    unsafe {
        let page_base = if pre_mapped {
            page_base
        } else {
            PROCMGR_SCRATCH_VADDR as *mut u8
        };

        if !pre_mapped {
            let err = trona::invoke::vspace_map(
                CAP_SELF_VSPACE,
                stk_frame,
                PROCMGR_SCRATCH_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] dynamic stack scratch map failed\n"); });
                return Err(StackBuildError::OutOfMemory);
            }
        }

        if phdr_vaddr == 0 || phent == 0 || phnum == 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] dynamic phdr info extraction failed\n"); });
            if !pre_mapped {
                trona::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
            }
            return Err(StackBuildError::InvalidArgument);
        }

        // +2 for AT_TRONA_SLOT_BASE/COUNT, +1 for AT_TRONA_CSPACE_NTFN, +1 for AT_TRONA_MM_EP,
        // +1 for AT_TRONA_SC_CAP
        let auxv_entries: u64 = if shared_lib_base != 0 { 18 } else { 17 };

        // Compute slot pool for child: from frame_slot_start to CSPACE_EXPAND_BASE.
        // Slots [CSPACE_EXPAND_BASE..CSPACE_EXPAND_BASE+8) are reserved for
        // CSpace expansion sub-CNodes.
        let slot_pool_base = if slot_pool_floor > CHILD_RTLD_FRAME_SLOT_START {
            slot_pool_floor
        } else {
            CHILD_RTLD_FRAME_SLOT_START
        };
        let slot_pool_count = CSPACE_EXPAND_BASE.saturating_sub(slot_pool_base);

        // Build the stack using the helper, which handles argv/envp layout
        let rsp = match write_stack_with_args(
            argc,
            envc,
            str_data,
            str_len,
            Some((
                auxv_entries,
                phdr_vaddr,
                phent,
                phnum,
                elf_result.entry,
                rtld_result.base,
                initrd_window_size as u64,
                shared_lib_base,
                slot_pool_base,
                slot_pool_count,
            )),
            page_base,
            scratch_vaddr,
            initrd_vaddr,
            stack_top,
        ) {
            Ok(rsp) => rsp,
            Err(err) => {
                if !pre_mapped {
                    trona::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
                }
                return Err(err);
            }
        };

        if !pre_mapped {
            trona::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
        }
        Ok(rsp)
    }
}

/// Build a stack for a statically-linked exec with argv/envp but no auxv.
pub(crate) unsafe fn write_static_stack(
    stk_frame: Cap,
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    scratch_vaddr: u64,
    initrd_vaddr: u64,
    stack_top: u64,
    page_base: *mut u8,
    pre_mapped: bool,
) -> Result<u64, StackBuildError> {
    unsafe {
        let page_base = if pre_mapped {
            page_base
        } else {
            PROCMGR_SCRATCH_VADDR as *mut u8
        };

        if !pre_mapped {
            let err = trona::invoke::vspace_map(
                CAP_SELF_VSPACE,
                stk_frame,
                PROCMGR_SCRATCH_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] static stack scratch map failed\n"); });
                return Err(StackBuildError::OutOfMemory);
            }
        }

        let rsp = match write_stack_with_args(
            argc,
            envc,
            str_data,
            str_len,
            None,
            page_base,
            scratch_vaddr,
            initrd_vaddr,
            stack_top,
        ) {
            Ok(rsp) => rsp,
            Err(err) => {
                if !pre_mapped {
                    trona::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
                }
                return Err(err);
            }
        };

        if !pre_mapped {
            trona::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
        }
        Ok(rsp)
    }
}

/// Common helper: write System V ABI initial stack into the scratch-mapped page.
///
/// Stack layout (high to low):
///   - string data (argv strings then envp strings, null-terminated)
///   - padding to 16-byte align
///   - auxv entries (if present) terminated by AT_NULL
///   - envp[envc] = NULL
///   - envp[0..envc-1] = pointers to envp strings
///   - argv[argc] = NULL
///   - argv[0..argc-1] = pointers to argv strings
///   - argc                <-- SP
///   - entry alignment: architecture-specific 16-byte ABI
///
/// `auxv_info` is Some(...) for dynamic executables, None for static.
unsafe fn write_stack_with_args(
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    auxv_info: Option<(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64)>,
    page_base: *mut u8,
    scratch_vaddr: u64,
    initrd_vaddr: u64,
    stack_top: u64,
) -> Result<u64, StackBuildError> {
    unsafe {
        if str_len > str_data.len() || str_len > 4096 {
            return Err(StackBuildError::TooLarge);
        }
        if argc as usize > MAX_STACK_STRINGS || envc as usize > MAX_STACK_STRINGS {
            return Err(StackBuildError::TooLarge);
        }

        // The child sees this page at the top of its stack
        let Some(child_page_base) = stack_top.checked_sub(4096) else {
            return Err(StackBuildError::InvalidArgument);
        };

        // 1. Copy string data to the top of the page
        let Some(str_area_start) = 4096usize.checked_sub(str_len) else {
            return Err(StackBuildError::TooLarge);
        };
        for i in 0..str_len {
            core::ptr::write_volatile(page_base.add(str_area_start + i), str_data[i]);
        }

        // 2. Build pointer arrays for argv and envp by scanning the string data
        // to find individual null-terminated strings.
        let mut argv_ptrs = [0u64; MAX_STACK_STRINGS];
        let mut envp_ptrs = [0u64; MAX_STACK_STRINGS];
        let mut arg_idx: u32 = 0;
        let mut env_idx: u32 = 0;
        let mut pos = 0usize;

        // Parse argv strings
        while arg_idx < argc {
            if pos >= str_len {
                return Err(StackBuildError::InvalidArgument);
            }
            let str_start = pos;
            while pos < str_len && str_data[pos] != 0 {
                pos += 1;
            }
            if pos >= str_len {
                return Err(StackBuildError::InvalidArgument);
            }
            let str_child_addr = child_page_base + str_area_start as u64 + str_start as u64;
            argv_ptrs[arg_idx as usize] = str_child_addr;
            arg_idx += 1;
            pos += 1; // skip null terminator
        }

        // Parse envp strings
        while env_idx < envc {
            if pos >= str_len {
                return Err(StackBuildError::InvalidArgument);
            }
            let str_start = pos;
            while pos < str_len && str_data[pos] != 0 {
                pos += 1;
            }
            if pos >= str_len {
                return Err(StackBuildError::InvalidArgument);
            }
            let str_child_addr = child_page_base + str_area_start as u64 + str_start as u64;
            envp_ptrs[env_idx as usize] = str_child_addr;
            env_idx += 1;
            pos += 1;
        }

        // 3. Calculate the metadata size (argc + argv ptrs + NULL + envp ptrs + NULL + auxv)
        let auxv_u64s: usize = match auxv_info {
            Some((entries, ..)) => entries as usize * 2, // entries includes AT_NULL
            None => 2,                                   // AT_NULL entry only
        };
        let metadata_u64s = 1 // argc
            + arg_idx as usize + 1 // argv + NULL
            + env_idx as usize + 1 // envp + NULL
            + auxv_u64s;

        let metadata_bytes = metadata_u64s * 8;
        // argc lives at [SP], but the entry alignment differs by arch:
        // x86_64 uses SP % 16 == 8 at function entry, while AArch64 requires
        // SP % 16 == 0 at public call boundaries.
        let metadata_end = str_area_start;
        let Some(metadata_floor) = metadata_end.checked_sub(metadata_bytes) else {
            return Err(StackBuildError::TooLarge);
        };
        let Some(metadata_start) = (metadata_floor & !0xF).checked_sub(STACK_ENTRY_BIAS) else {
            return Err(StackBuildError::TooLarge);
        };

        let stack_u64 = page_base.add(metadata_start) as *mut u64;
        let mut wi: usize = 0;
        let mut w = |v: u64| {
            core::ptr::write_volatile(stack_u64.add(wi), v);
            wi += 1;
        };

        // argc
        w(arg_idx as u64);

        // argv pointers
        for i in 0..arg_idx as usize {
            w(argv_ptrs[i]);
        }
        w(0); // argv NULL terminator

        // envp pointers
        for i in 0..env_idx as usize {
            w(envp_ptrs[i]);
        }
        w(0); // envp NULL terminator

        // auxv
        match auxv_info {
            Some((
                _,
                phdr,
                phent,
                phnum,
                entry,
                base,
                initrd_sz,
                shared_lib,
                slot_base,
                slot_count,
            )) => {
                w(AT_PHDR);
                w(phdr);
                w(AT_PHENT);
                w(phent);
                w(AT_PHNUM);
                w(phnum);
                w(AT_ENTRY);
                w(entry);
                w(AT_BASE);
                w(base);
                w(AT_PAGESZ);
                w(4096);
                w(AT_TRONA_VSPACE);
                w(CHILD_CAP_VSPACE);
                w(AT_TRONA_SCRATCH);
                w(scratch_vaddr);
                w(AT_TRONA_INITRD);
                w(initrd_vaddr);
                w(AT_TRONA_INITRD_SZ);
                w(initrd_sz);
                w(AT_TRONA_FRAME_SLOT);
                w(slot_base);
                w(AT_TRONA_SLOT_BASE);
                w(slot_base);
                w(AT_TRONA_SLOT_COUNT);
                w(slot_count);
                w(AT_TRONA_CSPACE_NTFN);
                w(CHILD_CAP_CSPACE_NTFN);
                w(AT_TRONA_MM_EP);
                w(CHILD_CAP_MMSRV_EP);
                w(AT_TRONA_SC_CAP);
                w(CHILD_CAP_SC);
                if shared_lib != 0 {
                    w(AT_TRONA_SHARED_LIB_BASE);
                    w(shared_lib);
                }
            }
            None => {}
        }
        w(AT_NULL);
        w(0);

        // RSP in child address space
        Ok(child_page_base + metadata_start as u64)
    }
}

// ===========================================================================
// mmsrv exec helpers
// ===========================================================================

/// Load an ELF64 binary into a child's VSpace using mmsrv for frame allocation.
///
/// Materializes one anonymous private region in mmsrv, then copies chunked
/// staged page images from procmgr's own anonymous buffer into the child MO.
///
/// Returns 0 on success, nonzero on error. Populates `*result` with entry,
/// base, and brk on success.
///
/// # Safety
/// `data` must point to a valid ELF64 file of at least `data_len` bytes.
pub(crate) unsafe fn exec_load_elf_mmsrv(
    data: *const u8,
    data_len: usize,
    load_base: u64,
    pid: u32,
    child_vspace: Cap,
    result: *mut ElfLoadResult,
) -> i32 {
    unsafe {
        use trona::consts::{
            ELFCLASS64, ELFDATA2LSB, ELF_BAD_ARCH, ELF_BAD_TYPE, ELF_MAP_FAILED, ELF_NOT_64BIT,
            ELF_NOT_ELF, ELF_NOT_LE, ELF_NO_LOAD, ELF_OUT_OF_MEMORY, ELF_TOO_SMALL,
            EM_AARCH64, EM_X86_64, ET_DYN, ET_EXEC, PF_W, PF_X, PT_LOAD,
        };

        if data_len < core::mem::size_of::<Elf64Ehdr>() {
            return ELF_TOO_SMALL;
        }

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
        #[cfg(target_arch = "x86_64")]
        if ehdr.e_machine != EM_X86_64 {
            return ELF_BAD_ARCH;
        }
        #[cfg(target_arch = "aarch64")]
        if ehdr.e_machine != EM_AARCH64 {
            return ELF_BAD_ARCH;
        }

        let is_pie = ehdr.e_type == ET_DYN;

        let phdr_base = ehdr.e_phoff as usize;
        let phdr_count = ehdr.e_phnum as usize;
        let phdr_size = ehdr.e_phentsize as usize;

        // Find min/max vaddr across all PT_LOAD segments
        let mut min_vaddr: u64 = u64::MAX;
        let mut max_vaddr_end: u64 = 0;
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
                let end = phdr.p_vaddr + phdr.p_memsz;
                if end > max_vaddr_end {
                    max_vaddr_end = end;
                }
            }
        }

        if !has_load || min_vaddr == u64::MAX {
            return ELF_NO_LOAD;
        }

        let delta = if is_pie {
            load_base.wrapping_sub(min_vaddr)
        } else {
            0
        };

        let span_start = (min_vaddr.wrapping_add(delta)) & !0xFFFu64;
        let span_end = ((max_vaddr_end.wrapping_add(delta)) + 0xFFF) & !0xFFFu64;
        let total_span_pages = ((span_end - span_start) / 4096) as usize;

        if total_span_pages == 0 {
            return ELF_OUT_OF_MEMORY;
        }

        const CHUNK_PAGES: usize = 512;
        let stage = alloc_staging_buffer(CHUNK_PAGES);
        if stage.is_null() {
            return ELF_OUT_OF_MEMORY;
        }

        let load_status = (|| -> i32 {
            let mut chunk_off: usize = 0;
            while chunk_off < total_span_pages {
                let chunk_count = if total_span_pages - chunk_off > CHUNK_PAGES {
                    CHUNK_PAGES
                } else {
                    total_span_pages - chunk_off
                };
                let chunk_vaddr = span_start + (chunk_off as u64) * 4096;
                let chunk_size = (chunk_count as u64) * 4096;

                volatile_zero(stage, chunk_count * 4096);

                for seg_i in 0..phdr_count {
                    let off = phdr_base + seg_i * phdr_size;
                    if off + core::mem::size_of::<Elf64Phdr>() > data_len {
                        break;
                    }
                    let phdr = &*(data.add(off) as *const Elf64Phdr);
                    if phdr.p_type != PT_LOAD {
                        continue;
                    }

                    let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
                    let seg_file_end = seg_vaddr + phdr.p_filesz;
                    let chunk_end = chunk_vaddr + chunk_size;
                    if seg_vaddr >= chunk_end || seg_file_end <= chunk_vaddr {
                        continue;
                    }

                    let copy_start = if seg_vaddr > chunk_vaddr { seg_vaddr } else { chunk_vaddr };
                    let copy_end = if seg_file_end < chunk_end { seg_file_end } else { chunk_end };
                    let file_off = phdr.p_offset as usize + (copy_start - seg_vaddr) as usize;
                    let win_off = (copy_start - chunk_vaddr) as usize;
                    let copy_len = (copy_end - copy_start) as usize;

                    if copy_len > 0 && file_off + copy_len <= data_len {
                        volatile_copy(stage.add(win_off), data.add(file_off), copy_len);
                    }
                }

                if is_pie {
                    exec_apply_relocs_chunk(
                        data,
                        data_len,
                        ehdr,
                        delta,
                        load_base,
                        stage,
                        chunk_vaddr,
                        chunk_size,
                    );
                }

                if chunk_off == 0 {
                    let region_base = match alloc_private_copy_from_client_region_to_mmsrv(
                        pid,
                        span_start,
                        total_span_pages as u64,
                        chunk_vaddr,
                        stage as u64,
                        chunk_count as u64,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    ) {
                        Ok(v) => v,
                        Err((err, label, value)) => {
                            trona::uerror!(|_lb| {
                                _lb.str(b"[PROCMGR] exec ELF MM_ALLOC_PRIVATE_COPY failed err=");
                                _lb.hex(err as u64);
                                _lb.str(b" label=");
                                _lb.hex(label);
                                _lb.str(b" value=");
                                _lb.hex(value);
                                _lb.str(b"\n");
                            });
                            return ELF_MAP_FAILED;
                        }
                    };
                    if region_base != span_start {
                        return ELF_MAP_FAILED;
                    }
                } else {
                    let copied = match copy_from_client_region_to_mmsrv(
                        pid,
                        chunk_vaddr,
                        stage as u64,
                        chunk_count as u64,
                    ) {
                        Ok(v) => v,
                        Err((err, label, value)) => {
                            trona::uerror!(|_lb| {
                                _lb.str(b"[PROCMGR] exec ELF MM_COPY_FROM_CLIENT_REGION failed err=");
                                _lb.hex(err as u64);
                                _lb.str(b" label=");
                                _lb.hex(label);
                                _lb.str(b" value=");
                                _lb.hex(value);
                                _lb.str(b"\n");
                            });
                            return ELF_MAP_FAILED;
                        }
                    };
                    if copied != chunk_count as u64 {
                        return ELF_MAP_FAILED;
                    }
                }

                chunk_off += chunk_count;
            }

            protect_load_pages(
                child_vspace,
                data.add(phdr_base),
                phdr_count,
                phdr_size,
                data_len - phdr_base,
                delta,
            );

            (*result).entry = if is_pie {
                ehdr.e_entry.wrapping_add(delta)
            } else {
                ehdr.e_entry
            };
            (*result).base = load_base;
            (*result).brk = span_end;

            0
        })();

        free_staging_buffer(stage, CHUNK_PAGES);
        load_status
    }
}

/// Apply RELATIVE relocations into a staged chunk buffer.
///
/// Only applies relocations whose target address falls within
/// `[chunk_vaddr, chunk_vaddr + chunk_size)`.
///
/// # Safety
/// `scratch` must point to a writable chunk buffer covering the chunk.
unsafe fn exec_apply_relocs_chunk(
    data: *const u8,
    data_len: usize,
    ehdr: &Elf64Ehdr,
    delta: u64,
    load_base: u64,
    scratch: *mut u8,
    chunk_vaddr: u64,
    chunk_size: u64,
) {
    unsafe {
        use trona::consts::{
            DT_NULL, DT_RELA, DT_RELAENT, DT_RELASZ, PT_DYNAMIC, PT_LOAD,
            R_AARCH64_RELATIVE, R_X86_64_RELATIVE,
        };

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
            return;
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
            return;
        }

        if rela_ent < core::mem::size_of::<Elf64Rela>() as u64 {
            return;
        }

        // Find the file offset corresponding to rela_vaddr
        let mut rela_file_offset: usize = 0;
        let mut found = false;
        for i in 0..phdr_count {
            let off = phdr_base + i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > data_len {
                break;
            }
            let phdr = &*(data.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD {
                continue;
            }
            if rela_vaddr >= phdr.p_vaddr && rela_vaddr < phdr.p_vaddr + phdr.p_filesz {
                rela_file_offset = (phdr.p_offset + (rela_vaddr - phdr.p_vaddr)) as usize;
                found = true;
                break;
            }
        }
        if !found {
            return;
        }

        let rela_count = rela_size / rela_ent;
        for i in 0..rela_count {
            let entry_off = rela_file_offset + (i as usize) * (rela_ent as usize);
            if entry_off + core::mem::size_of::<Elf64Rela>() > data_len {
                break;
            }
            let rela = &*(data.add(entry_off) as *const Elf64Rela);
            let reloc_type = (rela.r_info & 0xFFFF_FFFF) as u32;

            #[cfg(target_arch = "x86_64")]
            let is_relative = reloc_type == R_X86_64_RELATIVE;
            #[cfg(target_arch = "aarch64")]
            let is_relative = reloc_type == R_AARCH64_RELATIVE;
            if is_relative {
                let target_vaddr = rela.r_offset + delta;
                let value = load_base.wrapping_add(rela.r_addend as u64);

                if target_vaddr >= chunk_vaddr && target_vaddr + 8 <= chunk_vaddr + chunk_size {
                    let window_off = (target_vaddr - chunk_vaddr) as usize;
                    let ptr = scratch.add(window_off) as *mut u64;
                    core::ptr::write_volatile(ptr, value);
                }
            }
        }
    }
}

unsafe fn exec_apply_relocs_chunk_cached(
    rela_data: *const u8,
    rela_len: usize,
    rela_ent: usize,
    delta: u64,
    load_base: u64,
    scratch: *mut u8,
    chunk_vaddr: u64,
    chunk_size: u64,
) {
    unsafe {
        if rela_data.is_null() || rela_len == 0 || rela_ent < core::mem::size_of::<Elf64Rela>() {
            return;
        }

        let rela_count = rela_len / rela_ent;
        for i in 0..rela_count {
            let entry_off = i * rela_ent;
            if entry_off + core::mem::size_of::<Elf64Rela>() > rela_len {
                break;
            }
            let rela = &*(rela_data.add(entry_off) as *const Elf64Rela);
            let reloc_type = (rela.r_info & 0xFFFF_FFFF) as u32;
            #[cfg(target_arch = "x86_64")]
            let skip = reloc_type != trona::R_X86_64_RELATIVE;
            #[cfg(target_arch = "aarch64")]
            let skip = reloc_type != trona::R_AARCH64_RELATIVE;
            if skip {
                continue;
            }

            let target_vaddr = rela.r_offset + delta;
            if target_vaddr < chunk_vaddr || target_vaddr + 8 > chunk_vaddr + chunk_size {
                continue;
            }

            let value = load_base.wrapping_add(rela.r_addend as u64);
            let window_off = (target_vaddr - chunk_vaddr) as usize;
            let ptr = scratch.add(window_off) as *mut u64;
            core::ptr::write_volatile(ptr, value);
        }
    }
}

pub(crate) unsafe fn exec_load_elf_vfs_mmsrv(
    vfs: &super::vfs_load::VfsStreamExec,
    load_base: u64,
    pid: u32,
    child_vspace: Cap,
    result: *mut ElfLoadResult,
) -> i32 {
    unsafe {
        use trona::consts::{
            ELFCLASS64, ELFDATA2LSB, ELF_BAD_ARCH, ELF_BAD_TYPE, ELF_MAP_FAILED, ELF_NOT_64BIT,
            ELF_NOT_ELF, ELF_NOT_LE, ELF_NO_LOAD, ELF_OUT_OF_MEMORY, ELF_TOO_SMALL,
            EM_AARCH64, EM_X86_64, ET_DYN, ET_EXEC, PF_W, PF_X, PT_LOAD,
        };

        let fd = vfs.fd;
        let data_len = vfs.file_size;
        if data_len < core::mem::size_of::<Elf64Ehdr>() {
            return ELF_TOO_SMALL;
        }

        let mut ehdr = core::mem::MaybeUninit::<Elf64Ehdr>::uninit();
        if !super::vfs_load::vfs_read_exact_at(
            fd,
            ehdr.as_mut_ptr() as *mut u8,
            core::mem::size_of::<Elf64Ehdr>(),
            0,
        ) {
            return ELF_TOO_SMALL;
        }
        let ehdr = ehdr.assume_init();

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
        #[cfg(target_arch = "x86_64")]
        if ehdr.e_machine != EM_X86_64 {
            return ELF_BAD_ARCH;
        }
        #[cfg(target_arch = "aarch64")]
        if ehdr.e_machine != EM_AARCH64 {
            return ELF_BAD_ARCH;
        }

        let phdr_count = ehdr.e_phnum as usize;
        let phdr_size = ehdr.e_phentsize as usize;
        let phdr_bytes_len = phdr_count.saturating_mul(phdr_size);
        if phdr_count == 0 || phdr_bytes_len == 0 || phdr_bytes_len > 4096 {
            return ELF_NO_LOAD;
        }

        let mut phdr_bytes = [0u8; 4096];
        if !super::vfs_load::vfs_read_exact_at(fd, phdr_bytes.as_mut_ptr(), phdr_bytes_len, ehdr.e_phoff as usize) {
            return ELF_NO_LOAD;
        }

        let is_pie = ehdr.e_type == ET_DYN;
        let mut min_vaddr: u64 = u64::MAX;
        let mut max_vaddr_end: u64 = 0;
        let mut has_load = false;

        for i in 0..phdr_count {
            let off = i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                break;
            }
            let phdr = &*(phdr_bytes.as_ptr().add(off) as *const Elf64Phdr);
            if phdr.p_type == PT_LOAD {
                has_load = true;
                if phdr.p_vaddr < min_vaddr {
                    min_vaddr = phdr.p_vaddr;
                }
                let end = phdr.p_vaddr + phdr.p_memsz;
                if end > max_vaddr_end {
                    max_vaddr_end = end;
                }
            }
        }

        if !has_load || min_vaddr == u64::MAX {
            return ELF_NO_LOAD;
        }

        let delta = if is_pie {
            load_base.wrapping_sub(min_vaddr)
        } else {
            0
        };
        let span_start = (min_vaddr.wrapping_add(delta)) & !0xFFFu64;
        let span_end = ((max_vaddr_end.wrapping_add(delta)) + 0xFFF) & !0xFFFu64;
        let total_span_pages = ((span_end - span_start) / 4096) as usize;
        if total_span_pages == 0 {
            return ELF_OUT_OF_MEMORY;
        }

        const CHUNK_PAGES: usize = 512;
        let stage = alloc_staging_buffer(CHUNK_PAGES);
        if stage.is_null() {
            return ELF_OUT_OF_MEMORY;
        }

        let load_status = (|| -> i32 {
            let mut chunk_off = 0usize;
            while chunk_off < total_span_pages {
                let chunk_count = core::cmp::min(total_span_pages - chunk_off, CHUNK_PAGES);
                let chunk_vaddr = span_start + (chunk_off as u64) * 4096;
                let chunk_size = (chunk_count as u64) * 4096;

                volatile_zero(stage, chunk_count * 4096);

                for seg_i in 0..phdr_count {
                    let off = seg_i * phdr_size;
                    if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                        break;
                    }
                    let phdr = &*(phdr_bytes.as_ptr().add(off) as *const Elf64Phdr);
                    if phdr.p_type != PT_LOAD {
                        continue;
                    }

                    let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
                    let seg_file_end = seg_vaddr + phdr.p_filesz;
                    let chunk_end = chunk_vaddr + chunk_size;
                    if seg_vaddr >= chunk_end || seg_file_end <= chunk_vaddr {
                        continue;
                    }

                    let copy_start = if seg_vaddr > chunk_vaddr { seg_vaddr } else { chunk_vaddr };
                    let copy_end = if seg_file_end < chunk_end { seg_file_end } else { chunk_end };
                    let file_off = phdr.p_offset as usize + (copy_start - seg_vaddr) as usize;
                    let win_off = (copy_start - chunk_vaddr) as usize;
                    let copy_len = (copy_end - copy_start) as usize;

                    if copy_len > 0 && file_off + copy_len <= data_len {
                        if !super::vfs_load::vfs_read_exact_at(fd, stage.add(win_off), copy_len, file_off) {
                            return ELF_MAP_FAILED;
                        }
                    }
                }

                if is_pie {
                    exec_apply_relocs_chunk_cached(
                        vfs.rela_data,
                        vfs.rela_len,
                        vfs.rela_ent,
                        delta,
                        load_base,
                        stage,
                        chunk_vaddr,
                        chunk_size,
                    );
                }

                if chunk_off == 0 {
                    let region_base = match alloc_private_copy_from_client_region_to_mmsrv(
                        pid,
                        span_start,
                        total_span_pages as u64,
                        chunk_vaddr,
                        stage as u64,
                        chunk_count as u64,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    ) {
                        Ok(v) => v,
                        Err(_) => return ELF_MAP_FAILED,
                    };
                    if region_base != span_start {
                        return ELF_MAP_FAILED;
                    }
                } else {
                    let copied = match copy_from_client_region_to_mmsrv(
                        pid,
                        chunk_vaddr,
                        stage as u64,
                        chunk_count as u64,
                    ) {
                        Ok(v) => v,
                        Err(_) => return ELF_MAP_FAILED,
                    };
                    if copied != chunk_count as u64 {
                        return ELF_MAP_FAILED;
                    }
                }

                chunk_off += chunk_count;
            }

            protect_load_pages(
                child_vspace,
                phdr_bytes.as_ptr(),
                phdr_count,
                phdr_size,
                phdr_bytes_len,
                delta,
            );

            (*result).entry = if is_pie {
                ehdr.e_entry.wrapping_add(delta)
            } else {
                ehdr.e_entry
            };
            (*result).base = load_base;
            (*result).brk = span_end;
            0
        })();

        free_staging_buffer(stage, CHUNK_PAGES);
        load_status
    }
}

/// Load the RTLD (dynamic linker) into a child's VSpace using mmsrv.
///
/// Finds the interpreter ELF in the initrd, loads it via exec_load_elf_mmsrv.
///
/// # Safety
/// All pointers must be valid for their declared lengths.
pub(crate) unsafe fn exec_load_rtld_mmsrv(
    elf_data: *const u8,
    elf_data_len: usize,
    initrd: *const u8,
    initrd_size: usize,
    rtld_load_base: u64,
    pid: u32,
    child_vspace: Cap,
) -> Option<ElfLoadResult> {
    unsafe {
        const DEFAULT_RTLD: &[u8] = b"ld-trona.so";
        let mut rtld_name = DEFAULT_RTLD.as_ptr();
        let mut rtld_name_len = DEFAULT_RTLD.len();

        let interp = trona_loader::elf_dynamic::elf_get_interp(elf_data, elf_data_len);
        if !interp.is_null() && *interp != 0 {
            let mut last = interp;
            let mut p = interp;
            while *p != 0 {
                if *p == b'/' {
                    last = p.add(1);
                }
                p = p.add(1);
            }
            if *last != 0 {
                rtld_name = last;
                rtld_name_len = strlen(last);
            }
        }

        exec_load_rtld_mmsrv_by_name(
            rtld_name,
            rtld_name_len,
            initrd,
            initrd_size,
            rtld_load_base,
            pid,
            child_vspace,
        )
    }
}

pub(crate) unsafe fn exec_load_rtld_mmsrv_by_name(
    rtld_name: *const u8,
    rtld_name_len: usize,
    initrd: *const u8,
    initrd_size: usize,
    rtld_load_base: u64,
    pid: u32,
    child_vspace: Cap,
) -> Option<ElfLoadResult> {
    unsafe {
        let mut rtld_entry = CpioEntry::zeroed();
        if trona_loader::cpio::cpio_find_file(
            initrd,
            initrd_size,
            rtld_name,
            rtld_name_len,
            &raw mut rtld_entry,
        ) == 0
        {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] exec: rtld not found in initrd\n"); });
            return None;
        }

        let mut rtld_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let err = exec_load_elf_mmsrv(
            rtld_entry.data,
            rtld_entry.data_len,
            rtld_load_base,
            pid,
            child_vspace,
            &raw mut rtld_result,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] exec: rtld load failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return None;
        }
        Some(rtld_result)
    }
}

pub(crate) unsafe fn exec_load_pe_mmsrv_by_name(
    pe_name: *const u8,
    pe_name_len: usize,
    initrd: *const u8,
    initrd_size: usize,
    pe_load_base: u64,
    pid: u32,
    child_vspace: Cap,
) -> Option<PeLoadResult> {
    unsafe {
        let mut pe_entry = CpioEntry::zeroed();
        if trona_loader::cpio::cpio_find_file(
            initrd,
            initrd_size,
            pe_name,
            pe_name_len,
            &raw mut pe_entry,
        ) == 0
        {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] exec: PE image not found in initrd\n"); });
            return None;
        }

        match exec_load_pe_mmsrv(
            pe_entry.data,
            pe_entry.data_len,
            pe_load_base,
            pid,
            child_vspace,
        ) {
            Ok(result) => Some(result),
            Err(err) => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] exec: PE image load failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                None
            }
        }
    }
}

/// Load a PE image into a child's VSpace using mmsrv for frame allocation.
///
/// Maps the PE image into the child's VSpace at `load_base`. The PE data is
/// copied section-by-section through a staged chunk buffer, then transferred
/// into the child region via mmsrv copy transactions.
///
/// Returns a `PeLoadResult` on success (entry VA, base VA, image end VA).
///
/// # Safety
/// `data` must point to a valid PE32+ file of at least `data_len` bytes.
pub(crate) unsafe fn exec_load_pe_mmsrv(
    data: *const u8,
    data_len: usize,
    load_base: u64,
    pid: u32,
    child_vspace: Cap,
) -> Result<PeLoadResult, i32> {
    unsafe {
        let mut info = trona_loader::pe_loader::PeInfo::zeroed();
        let err = trona_loader::pe_loader::pe_validate(data, data_len, &raw mut info);
        if err != 0 {
            return Err(err);
        }

        let image_size = info.size_of_image as u64;
        let total_pages = ((image_size + 4095) / 4096) as usize;
        if total_pages == 0 {
            return Err(-1);
        }

        const MAX_CHUNK: usize = 16;
        let stage = alloc_staging_buffer(MAX_CHUNK);
        if stage.is_null() {
            return Err(-1);
        }

        let load_status = (|| -> Result<(), i32> {
            let mut page_off: usize = 0;
            while page_off < total_pages {
                let chunk_count = core::cmp::min(MAX_CHUNK, total_pages - page_off);
                let chunk_vaddr = load_base + (page_off as u64 * 4096);
                let chunk_rva = page_off * 4096;
                let chunk_len = chunk_count * 4096;

                volatile_zero(stage, chunk_len);

                let header_bytes = core::cmp::min(info.size_of_headers as usize, data_len);
                let header_copy_start = chunk_rva;
                let header_copy_end = core::cmp::min(chunk_rva + chunk_len, header_bytes);
                if header_copy_start < header_copy_end {
                    volatile_copy(
                        stage,
                        data.add(header_copy_start),
                        header_copy_end - header_copy_start,
                    );
                }

                for sec_idx in 0..info.number_of_sections as usize {
                    let sec_off = info.section_headers_offset
                        + sec_idx * core::mem::size_of::<SectionHeader>();
                    let sec = core::ptr::read_unaligned(data.add(sec_off) as *const SectionHeader);
                    let sec_rva = sec.virtual_address as usize;
                    let sec_raw_off = sec.pointer_to_raw_data as usize;
                    let sec_raw_size = sec.size_of_raw_data as usize;

                    if sec_raw_size == 0 || sec_raw_off >= data_len {
                        continue;
                    }

                    let sec_copy_start = core::cmp::max(chunk_rva, sec_rva);
                    let sec_copy_end = core::cmp::min(chunk_rva + chunk_len, sec_rva + sec_raw_size);
                    if sec_copy_start >= sec_copy_end {
                        continue;
                    }

                    let file_start = sec_raw_off + (sec_copy_start - sec_rva);
                    if file_start >= data_len {
                        continue;
                    }

                    let max_copy = data_len - file_start;
                    let copy_len = core::cmp::min(sec_copy_end - sec_copy_start, max_copy);
                    if copy_len == 0 {
                        continue;
                    }

                    volatile_copy(
                        stage.add(sec_copy_start - chunk_rva),
                        data.add(file_start),
                        copy_len,
                    );
                }

                if page_off == 0 {
                    let region_base = alloc_private_copy_from_client_region_to_mmsrv(
                        pid,
                        load_base,
                        total_pages as u64,
                        chunk_vaddr,
                        stage as u64,
                        chunk_count as u64,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    )
                    .map_err(|_| -2)?;
                    if region_base != load_base {
                        return Err(-2);
                    }
                } else {
                    let copied = copy_from_client_region_to_mmsrv(
                        pid,
                        chunk_vaddr,
                        stage as u64,
                        chunk_count as u64,
                    )
                    .map_err(|_| -2)?;
                    if copied != chunk_count as u64 {
                        return Err(-2);
                    }
                }

                page_off += chunk_count;
            }

            Ok(())
        })();

        free_staging_buffer(stage, MAX_CHUNK);
        load_status?;

        // NOTE: Section permissions are NOT set here for PE images.
        // The PE rtld writes to the IAT (in .rdata) during import resolution,
        // then applies final protections through mmsrv MM_MPROTECT so region
        // metadata and live PTE permissions stay in sync.

        let entry_va = load_base + info.entry_point_rva as u64;
        Ok(PeLoadResult {
            entry: entry_va,
            base: load_base,
            image_end: load_base + image_size,
        })
    }
}

/// Write a PE-specific initial stack with PE auxv entries.
///
/// Stack layout for PE processes (same SysV ABI format as ELF):
///   - string data (argv/envp)
///   - auxv entries (PE-specific: PE_BASE, PE_SIZE, WIN32SRV, plus common)
///   - envp array + NULL
///   - argv array + NULL
///   - argc   <-- SP
///
/// # Safety
/// `page_base` must point to a writable 4K stack page image buffer.
pub(crate) unsafe fn write_pe_stack(
    pe_result: &PeLoadResult,
    rtld_result: &ElfLoadResult,
    kernel32_result: &PeLoadResult,
    page_base: *mut u8,
    scratch_vaddr: u64,
    ipc_buffer_vaddr: u64,
    win32srv_ep: u64,
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    stack_top: u64,
    slot_pool_base: u64,
    slot_pool_count: u64,
) -> Result<u64, StackBuildError> {
    unsafe {
        if str_len > str_data.len() || str_len > 4096 {
            return Err(StackBuildError::TooLarge);
        }
        if argc as usize > MAX_STACK_STRINGS || envc as usize > MAX_STACK_STRINGS {
            return Err(StackBuildError::TooLarge);
        }

        let Some(child_page_base) = stack_top.checked_sub(4096) else {
            return Err(StackBuildError::InvalidArgument);
        };

        // 1. Copy string data to the top of the page
        let Some(str_area_start) = 4096usize.checked_sub(str_len) else {
            return Err(StackBuildError::TooLarge);
        };
        for i in 0..str_len {
            core::ptr::write_volatile(page_base.add(str_area_start + i), str_data[i]);
        }

        // 2. Build pointer arrays
        let mut argv_ptrs = [0u64; MAX_STACK_STRINGS];
        let mut envp_ptrs = [0u64; MAX_STACK_STRINGS];
        let mut arg_idx: u32 = 0;
        let mut env_idx: u32 = 0;
        let mut pos = 0usize;

        while arg_idx < argc {
            if pos >= str_len {
                return Err(StackBuildError::InvalidArgument);
            }
            let str_start = pos;
            while pos < str_len && str_data[pos] != 0 {
                pos += 1;
            }
            if pos >= str_len {
                return Err(StackBuildError::InvalidArgument);
            }
            argv_ptrs[arg_idx as usize] = child_page_base + str_area_start as u64 + str_start as u64;
            arg_idx += 1;
            pos += 1;
        }

        while env_idx < envc {
            if pos >= str_len {
                return Err(StackBuildError::InvalidArgument);
            }
            let str_start = pos;
            while pos < str_len && str_data[pos] != 0 {
                pos += 1;
            }
            if pos >= str_len {
                return Err(StackBuildError::InvalidArgument);
            }
            envp_ptrs[env_idx as usize] = child_page_base + str_area_start as u64 + str_start as u64;
            env_idx += 1;
            pos += 1;
        }

        // 3. PE auxv: 17 entries (including AT_NULL)
        let auxv_entries: usize = 17;
        let auxv_u64s = auxv_entries * 2;
        let metadata_u64s = 1 // argc
            + arg_idx as usize + 1 // argv + NULL
            + env_idx as usize + 1 // envp + NULL
            + auxv_u64s;
        let metadata_bytes = metadata_u64s * 8;
        let metadata_end = str_area_start;
        let Some(metadata_floor) = metadata_end.checked_sub(metadata_bytes) else {
            return Err(StackBuildError::TooLarge);
        };
        let Some(metadata_start) = (metadata_floor & !0xF).checked_sub(STACK_ENTRY_BIAS) else {
            return Err(StackBuildError::TooLarge);
        };

        let stack_u64 = page_base.add(metadata_start) as *mut u64;
        let mut wi: usize = 0;
        let mut w = |v: u64| {
            core::ptr::write_volatile(stack_u64.add(wi), v);
            wi += 1;
        };

        w(arg_idx as u64);
        for i in 0..arg_idx as usize {
            w(argv_ptrs[i]);
        }
        w(0);
        for i in 0..env_idx as usize {
            w(envp_ptrs[i]);
        }
        w(0);

        // PE-specific auxv
        w(AT_SALTYOS_PE_BASE); w(pe_result.base);
        w(AT_SALTYOS_PE_SIZE); w(pe_result.image_end - pe_result.base);
        w(AT_SALTYOS_WIN32SRV); w(win32srv_ep);
        w(AT_SALTYOS_KERNEL32_BASE); w(kernel32_result.base);
        w(AT_SALTYOS_KERNEL32_SIZE); w(kernel32_result.image_end - kernel32_result.base);
        w(AT_BASE); w(rtld_result.base);
        w(AT_ENTRY); w(pe_result.entry);
        w(AT_PAGESZ); w(4096);
        w(AT_TRONA_VSPACE); w(CHILD_CAP_VSPACE);
        w(AT_TRONA_SCRATCH); w(scratch_vaddr);
        w(AT_TRONA_IPC_BUFFER); w(ipc_buffer_vaddr);
        w(AT_TRONA_SLOT_BASE); w(slot_pool_base);
        w(AT_TRONA_SLOT_COUNT); w(slot_pool_count);
        w(AT_TRONA_CSPACE_NTFN); w(CHILD_CAP_CSPACE_NTFN);
        w(AT_TRONA_MM_EP); w(CHILD_CAP_MMSRV_EP);
        w(AT_TRONA_SC_CAP); w(CHILD_CAP_SC);
        w(AT_NULL); w(0);

        Ok(child_page_base + metadata_start as u64)
    }
}

/// Map initrd pages into a child's VSpace for exec.
///
/// Tries device-mapping first. Falls back to mmsrv initrd copy transactions.
///
/// # Safety
/// `initrd` must point to the initrd data, `initrd_size` must be valid.
pub(crate) unsafe fn exec_map_initrd_mmsrv(
    proc_vs: Cap,
    initrd: *const u8,
    initrd_size: usize,
    pid: u32,
    initrd_base: u64,
) -> i32 {
    unsafe {
        let initrd_pages = (initrd_size + 4095) / 4096;
        let mut mapped_device = true;

        for pg in 0..initrd_pages {
            let err = trona::invoke::vspace_map_device(
                proc_vs,
                CAP_INITRD_UNTYPED,
                (pg as u64) * 4096,
                initrd_base + pg as u64 * 4096,
                VSPACE_FLAG_USER,
            );
            if err != 0 {
                for mapped_pg in 0..pg {
                    trona::invoke::vspace_unmap(proc_vs, initrd_base + mapped_pg as u64 * 4096);
                }
                mapped_device = false;
                break;
            }
        }

        if mapped_device {
            return 0;
        }

        let _ = initrd;
        if alloc_initrd_copy_from_mmsrv(
            pid,
            initrd_base,
            initrd_pages as u64,
            initrd_size as u64,
            VSPACE_FLAG_USER,
        )
        .is_err()
        {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] exec: initrd MM_ALLOC_INITRD_COPY failed\n"); });
            return -1;
        }

        0
    }
}

/// Map boot info page into child VSpace for exec via mmsrv.
///
/// Returns 0 on success.
pub(crate) unsafe fn exec_map_bootinfo_mmsrv(pid: u32) -> i32 {
    unsafe {
        if alloc_bootinfo_copy_from_mmsrv(
            pid,
            super::BOOTINFO_VADDR,
            VSPACE_FLAG_USER,
        )
        .is_err()
        {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] exec: bootinfo MM_ALLOC_BOOTINFO_COPY failed\n"); });
            return -1;
        }

        0
    }
}

/// Map IPC buffer page into child VSpace for exec via mmsrv.
///
/// Returns 0 on success.
pub(crate) unsafe fn exec_map_ipc_buf_mmsrv(pid: u32, ipc_buf_vaddr: u64) -> i32 {
    unsafe {
        let mut mm_msg = TronaMsg::zeroed();
        let mut mm_reply = TronaMsg::zeroed();
        mm_msg.label = trona::protocol::MM_MAP_BATCH;
        mm_msg.length = 4;
        mm_msg.regs[0] = pid as u64;
        mm_msg.regs[1] = ipc_buf_vaddr;
        mm_msg.regs[2] = 1;
        mm_msg.regs[3] = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let err = trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const mm_msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK || mm_reply.regs[0] != 1 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] exec: IPC buf MM_MAP_BATCH failed\n"); });
            return -1;
        }
        0
    }
}

// ===========================================================================
// mmsrv rollback helpers
// ===========================================================================

/// Register a process with mmsrv.
///
/// `heap_base` is the page-aligned end of the ELF load span (brk).
/// `mmap_base` is derived from the process layout.
pub(crate) fn register_with_mmsrv(pid: u32, vspace_cap: Cap, heap_base: u64, mmap_base: u64) {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_REGISTER;
    msg.length = 4;
    msg.regs[0] = pid as u64; // client badge
    msg.regs[1] = heap_base;
    msg.regs[2] = mmap_base;
    msg.regs[3] = pid as u64; // pid
    unsafe {
        trona::ipc::set_send_cap_ctx(super::ipc_ctx(), 0, vspace_cap);
        let err = trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_with_mmsrv failed pid=");
                _lb.hex(pid as u64);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
        }
    }
}

pub(crate) fn clear_fault_handler(tcb_cap: Cap, pid: u32) {
    if tcb_cap == 0 {
        return;
    }

    let err = trona::invoke::tcb_set_fault_handler(tcb_cap, 0);
    if err != 0 {
        trona::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] WARN: clear fault handler failed pid=");
            _lb.hex(pid as u64);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
    }
}

/// Deregister a process from mmsrv on spawn failure.
pub(crate) fn deregister_from_mmsrv(pid: u32) {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_DEREGISTER;
    msg.length = 1;
    msg.regs[0] = pid as u64;
    let _ = unsafe {
        trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut mm_reply,
        )
    };
}

pub(crate) fn alloc_initrd_copy_from_mmsrv(
    pid: u32,
    region_base: u64,
    region_pages: u64,
    copy_len: u64,
    flags: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_ALLOC_INITRD_COPY;
    msg.length = 5;
    msg.regs[0] = pid as u64;
    msg.regs[1] = region_base;
    msg.regs[2] = region_pages;
    msg.regs[3] = copy_len;
    msg.regs[4] = flags;
    unsafe {
        let err = trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

pub(crate) fn alloc_bootinfo_copy_from_mmsrv(
    pid: u32,
    region_base: u64,
    flags: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_ALLOC_BOOTINFO_COPY;
    msg.length = 3;
    msg.regs[0] = pid as u64;
    msg.regs[1] = region_base;
    msg.regs[2] = flags;
    unsafe {
        let err = trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

pub(crate) fn copy_from_client_region_to_mmsrv(
    pid: u32,
    target_vaddr: u64,
    source_vaddr: u64,
    page_count: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_COPY_FROM_CLIENT_REGION;
    msg.length = 4;
    msg.regs[0] = pid as u64;
    msg.regs[1] = target_vaddr;
    msg.regs[2] = source_vaddr;
    msg.regs[3] = page_count;
    unsafe {
        let err = trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

pub(crate) fn alloc_private_copy_from_client_region_to_mmsrv(
    pid: u32,
    region_base: u64,
    region_pages: u64,
    target_vaddr: u64,
    source_vaddr: u64,
    page_count: u64,
    flags: u64,
) -> Result<u64, (i32, u64, u64)> {
    let mut msg = TronaMsg::zeroed();
    let mut mm_reply = TronaMsg::zeroed();
    msg.label = trona::protocol::MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION;
    msg.length = 7;
    msg.regs[0] = pid as u64;
    msg.regs[1] = region_base;
    msg.regs[2] = region_pages;
    msg.regs[3] = target_vaddr;
    msg.regs[4] = source_vaddr;
    msg.regs[5] = page_count;
    msg.regs[6] = flags;
    unsafe {
        let err = trona::ipc::call_ctx(
            super::ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK {
            Err((err, mm_reply.label, mm_reply.regs[0]))
        } else {
            Ok(mm_reply.regs[0])
        }
    }
}

// ===========================================================================
// Transactional spawn
// ===========================================================================

/// Transactional spawn: preflight → reserve → realize → commit.
/// On any failure, rolls back all allocated objects and slots.
pub unsafe fn handle_spawn_tx(
    msg: &TronaMsg,
    reply: &mut TronaMsg,
    badge: u64,
    alloc: &mut Allocator,
) -> bool {
    unsafe {
        // Parse message — new wire format:
        //   regs[0] = name_len
        //   regs[1] = spawn_policy bitfield
        //   regs[2] = timeout_ns
        //   regs[3] = spawn_flags
        //   regs[4] = spawn_args_len (NUL-separated args bytes)
        //   regs[5..] = name bytes, then spawn args bytes
        let name_reg_idx = 5usize;
        let spawn_policy = msg.regs[1];
        let requested_timeout_ns = msg.regs[2];
        let spawn_flags = msg.regs[3];
        let spawn_args_len = msg.regs[4] as usize;
        let name_len_wire = msg.regs[0] as usize;
        let name_words = (name_len_wire + 7) / 8;
        let args_reg_idx = name_reg_idx + name_words;
        let use_pre_ep = (spawn_flags & SPAWN_FLAG_USE_PRE_EP) != 0;
        let start_suspended = (spawn_flags & SPAWN_FLAG_START_SUSPENDED) != 0;
        let readiness_mode = trona::spawn_policy_readiness(spawn_policy);
        let policy_map_initrd = trona::spawn_policy_map_initrd(spawn_policy);
        let policy_is_display = trona::spawn_policy_is_display(spawn_policy);
        let policy_cnode_bits = trona::spawn_policy_cnode_bits(spawn_policy);
        let (name, name_len) = super::extract_name(msg, name_reg_idx);
        let mut exec_path = [0u8; proc_table::MAX_EXE_PATH_LEN];
        let exec_path_len = super::vfs_load::derive_exec_path_for_badge(
            &name,
            name_len,
            badge,
            &mut exec_path,
        );
        let is_display = policy_is_display || super::bytes_eq(&name[..name_len], b"dispdrv");

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] SPAWN: '");
            _lb.bytes(&name[..name_len]);
            _lb.str(b"'\n");
        });

        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::read_boot_info_initrd_size();

        // Find ELF in initrd
        let mut elf_entry = CpioEntry::zeroed();
        let mut found = trona_loader::cpio::cpio_find_file(
            initrd,
            initrd_size,
            name.as_ptr(),
            name_len,
            &raw mut elf_entry,
        ) != 0;
        if !found && name_len + 4 <= proc_table::MAX_NAME_LEN {
            let mut legacy = [0u8; proc_table::MAX_NAME_LEN + 5];
            for i in 0..name_len {
                legacy[i] = name[i];
            }
            legacy[name_len] = b'.';
            legacy[name_len + 1] = b'e';
            legacy[name_len + 2] = b'l';
            legacy[name_len + 3] = b'f';
            found = trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                legacy.as_ptr(),
                name_len + 4,
                &raw mut elf_entry,
            ) != 0;
        }
        // VFS fallback: stream large ELFs instead of buffering the whole file.
        let mut vfs_source = super::vfs_load::VfsExecSource::none();
        if !found {
            if let Some(source) =
                super::vfs_load::try_open_exec_source_from_vfs_for_badge(&name, name_len, badge)
            {
                if let Some((data, data_len)) = source.buffered_data() {
                    elf_entry.data = data;
                    elf_entry.data_len = data_len;
                }
                found = true;
                vfs_source = source;
            }
        }
        if !found {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] binary not found in initrd or VFS\n"); });
            reply.label = TRONA_NOT_FOUND;
            return false;
        }

        // ---- PE detection: check for MZ magic ----
        let is_pe = vfs_source.streamed().is_none()
            && elf_entry.data_len >= 2
            && trona_loader::pe_loader::pe_is_pe(elf_entry.data, elf_entry.data_len);
        let subsystem_id = if is_pe {
            proc_table::SUBSYS_WIN32
        } else {
            proc_table::SUBSYS_POSIX
        };

        if is_pe {
            // Delegate to PE-specific spawn path
            return handle_pe_spawn_inner(
                msg,
                reply,
                badge,
                alloc,
                elf_entry.data,
                elf_entry.data_len,
                &name,
                name_len,
                &exec_path,
                exec_path_len,
                subsystem_id,
                readiness_mode,
                requested_timeout_ns,
                spawn_flags,
                spawn_args_len,
                args_reg_idx,
                use_pre_ep,
                start_suspended,
                policy_map_initrd,
                policy_is_display,
                policy_cnode_bits,
                is_display,
            );
        }

        let vfs_stream = vfs_source.streamed();
        let is_dynamic = if let Some(vfs) = vfs_stream {
            vfs.is_dynamic
        } else {
            trona_loader::elf_dynamic::elf_has_interp(elf_entry.data, elf_entry.data_len)
        };
        // ---- PREFLIGHT: Build SpawnPlan ----
        let do_map_initrd = is_dynamic || policy_map_initrd;

        let lib_window_pages = if is_dynamic {
            compute_lib_window_pages(initrd, initrd_size)
        } else {
            0
        };

        let effective_timeout_ns = if readiness_mode == trona::SPAWN_READY_NOTIFY {
            compute_ready_timeout_ns(
                requested_timeout_ns,
                is_dynamic,
                if let Some(vfs) = vfs_stream { vfs.file_size } else { elf_entry.data_len },
                lib_window_pages,
            )
        } else {
            0 // IMMEDIATE mode: no timeout needed
        };

        // Compute spans for VM layout
        let elf_span = if let Some(vfs) = vfs_stream {
            vfs.elf_span
        } else {
            trona_loader::elf_loader::elf_compute_load_span(elf_entry.data, elf_entry.data_len)
        };
        let rtld_span = if is_dynamic {
            if let Some(vfs) = vfs_stream {
                count_rtld_span_by_name(
                    vfs.interp_name.as_ptr(),
                    vfs.interp_name_len,
                    initrd,
                    initrd_size,
                )
            } else {
                count_rtld_span(elf_entry.data, elf_entry.data_len, initrd, initrd_size)
            }
        } else {
            0
        };

        // Parse DT_NEEDED to determine which shared libs this ELF needs
        let needed_owned = if is_dynamic && vfs_stream.is_none() {
            trona_loader::elf_dynamic::elf_get_needed(elf_entry.data, elf_entry.data_len)
        } else {
            trona_loader::elf_dynamic::NeededLibs::new()
        };
        let needed = if let Some(vfs) = vfs_stream {
            &vfs.needed
        } else {
            &needed_owned
        };

        let shared_lib_cache_pages = shared_lib_va_pages_for_needed(needed);

        let layout = layout::compute_vm_layout_randomized(
            elf_span,
            rtld_span,
            shared_lib_cache_pages,
            do_map_initrd,
            lib_window_pages * 4096,
            || trona::syscall::sys_getrandom(),
        );

        if layout.stack_top == 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] ELF too large for VA layout\n"); });
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let plan = SpawnPlan {
            is_dynamic,
            readiness_mode,
            ready_timeout_ns: effective_timeout_ns,
            total_slots: compute_slot_budget(),
            is_display,
            lib_window_pages,
            layout,
        };

        // Auto-register caller if unknown
        let caller_idx = proc_table::find_by_badge(badge);
        if caller_idx.is_none() && badge != 0 {
            if let Some(ci) = proc_table::alloc_proc() {
                proc_table::proctab(ci).set_posix_personality();
                proc_table::proctab(ci).pid = badge as u32;
                proc_table::proctab(ci).ppid = 0;
                proc_table::proctab(ci).state = proc_table::PROC_RUNNING;
                proc_table::proctab(ci).badge = badge;
            }
        }

        let Some(slot_idx) = proc_table::alloc_proc() else {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] process table full\n"); });
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        let pid = proc_table::NEXT_PID;
        proc_table::NEXT_PID += 1;

        // ---- PRE-PROVISION mmsrv untyped (breaks Procmgr↔MMSRV cycle) ----
        ensure_mmsrv_capacity(alloc);

        // ---- RESERVE ----
        if !alloc.reserve(plan.total_slots) {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] slot reservation failed\n"); });
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // ---- REALIZE fixed objects via mmsrv ----
        // All kernel objects are allocated by mmsrv (centralized untyped owner)
        // and received via IPC cap transfer into procmgr's reservation slots.
        macro_rules! realize_mm {
            ($ty:expr, $sz:expr, $off:expr, $what:expr) => {
                match alloc.realize_via_mmsrv(CAP_MMSRV_EP, $ty, $sz, $off) {
                    Ok(s) => s,
                    Err(e) => {
                        trona::uerror!(|_lb| {
                            _lb.str(b"[PROCMGR] alloc ");
                            _lb.bytes($what);
                            _lb.str(b" failed err=");
                            _lb.hex(e as u64);
                            _lb.str(b"\n");
                        });
                        super::vfs_load::cleanup_exec_source(&mut vfs_source);
                        alloc.rollback();
                        reply.label = TRONA_OUT_OF_MEMORY;
                        return false;
                    }
                }
            };
        }

        let child_tcb = realize_mm!(OBJ_TCB, 0, OFF_TCB, b"TCB");
        let child_vs = realize_mm!(OBJ_VSPACE, 0, OFF_VSPACE, b"VSpace");
        let cn_size_bits = if policy_cnode_bits > 0 {
            policy_cnode_bits as u64
        } else {
            0
        };
        let child_cn = realize_mm!(OBJ_CNODE, cn_size_bits, OFF_CNODE, b"CNode");
        let child_sc = realize_mm!(OBJ_SCHED_CONTEXT, 0, OFF_SC, b"SC");
        // OFF_STACK_FR and OFF_IPC_FR slots left unused — frames allocated by mmsrv
        let child_sig_ntfn = realize_mm!(OBJ_NOTIFICATION, 0, OFF_SIGNAL_NTFN, b"signal ntfn");

        let child_ready_ntfn;
        if plan.readiness_mode == trona::SPAWN_READY_NOTIFY {
            child_ready_ntfn = realize_mm!(OBJ_NOTIFICATION, 0, OFF_READY_NTFN, b"ready ntfn");
        } else {
            child_ready_ntfn = 0;
        }

        // ---- Mint mmsrv EP into child CNode slot 7 (badged with child pid) ----
        let err = trona::invoke::cnode_mint(
            CAP_SELF_CSPACE,
            CAP_MMSRV_EP_UNBADGED,
            child_cn,
            CHILD_CAP_MMSRV_EP,
            pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] mint mmsrv EP into child failed\n"); });
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // ---- Copy caps into child CNode ----
        let err = copy_child_caps_tx(
            child_tcb,
            child_vs,
            child_cn,
            child_sc,
            child_sig_ntfn,
            child_ready_ntfn,
            plan.readiness_mode == trona::SPAWN_READY_NOTIFY,
            plan.is_display,
            pid,
            if use_pre_ep { CAP_RECV_SCRATCH } else { 0 },
        );
        if err != 0 {
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // ---- Mint CSpace expansion notification into child CNode ----
        let pm_ntfn = *(&raw const super::PM_BOUND_NTFN);
        if pm_ntfn != 0 {
            let cs_badge = 1u64 << (16 + slot_idx);
            let err = trona::invoke::cnode_mint(
                CAP_SELF_CSPACE,
                pm_ntfn,
                child_cn,
                CHILD_CAP_CSPACE_NTFN,
                cs_badge,
            );
            if err != 0 {
                trona::uwarn!(|_lb| { _lb.str(b"[PROCMGR] WARN: mint cspace ntfn cap failed\n"); });
            }
        }

        // ---- Configure TCB ----
        let err = trona::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] TCB set_space failed\n"); });
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // ---- Set fault handler: badged mmsrv EP so VMFaults route to mmsrv ----
        {
            let temp_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] SPAWN: fault EP slot alloc failed\n"); });
                    super::vfs_load::cleanup_exec_source(&mut vfs_source);
                    alloc.rollback();
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return false;
                }
            };
            let err = trona::invoke::cnode_mint(
                CAP_SELF_CSPACE,
                CAP_MMSRV_EP_UNBADGED,
                CAP_SELF_CSPACE,
                temp_slot,
                pid as u64,
            );
            if err != 0 {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[PROCMGR] WARN: fault EP mint failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
            } else {
                let err2 = trona::invoke::tcb_set_fault_handler(child_tcb, temp_slot);
                if err2 != 0 {
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[PROCMGR] WARN: tcb_set_fault_handler failed err=");
                        _lb.hex(err2 as u64);
                        _lb.str(b"\n");
                    });
                }
            }
            trona::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
            alloc.free_single_slot(temp_slot);
        }

        // ---- Register with mmsrv (before ELF loading — mmsrv needs client registered) ----
        let heap_base = plan.layout.heap_base();
        let mmap_base = trona::layout::compute_mmap_base(&plan.layout, heap_base);
        {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_REGISTER;
            mm_msg.length = 4;
            mm_msg.regs[0] = pid as u64; // client badge
            mm_msg.regs[1] = heap_base;
            mm_msg.regs[2] = mmap_base;
            mm_msg.regs[3] = pid as u64; // pid
            trona::ipc::set_send_cap_ctx(super::ipc_ctx(), 0, child_vs);
            let err = trona::ipc::call_ctx(
                super::ipc_ctx(),
                CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != TRONA_OK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] SPAWN: mmsrv register failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                super::vfs_load::cleanup_exec_source(&mut vfs_source);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // ---- Load ELF via mmsrv ----
        let mut elf_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let err = if let Some(vfs) = vfs_stream {
            exec_load_elf_vfs_mmsrv(
                vfs,
                plan.layout.elf_code.base,
                pid,
                child_vs,
                &raw mut elf_result,
            )
        } else {
            exec_load_elf_mmsrv(
                elf_entry.data,
                elf_entry.data_len,
                plan.layout.elf_code.base,
                pid,
                child_vs,
                &raw mut elf_result,
            )
        };
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] SPAWN: ELF load failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        // ---- Load RTLD via mmsrv if dynamic ----
        let mut rtld_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        if plan.is_dynamic {
            let rtld_load = if let Some(vfs) = vfs_stream {
                exec_load_rtld_mmsrv_by_name(
                    vfs.interp_name.as_ptr(),
                    vfs.interp_name_len,
                    initrd,
                    initrd_size,
                    plan.layout.rtld.base,
                    pid,
                    child_vs,
                )
            } else {
                exec_load_rtld_mmsrv(
                    elf_entry.data,
                    elf_entry.data_len,
                    initrd,
                    initrd_size,
                    plan.layout.rtld.base,
                    pid,
                    child_vs,
                )
            };
            match rtld_load {
                Some(r) => rtld_result = r,
                None => {
                    super::vfs_load::cleanup_exec_source(&mut vfs_source);
                    deregister_from_mmsrv(pid);
                    alloc.rollback();
                    reply.label = TRONA_NOT_FOUND;
                    return false;
                }
            }
        }
        // ---- Map shared library frames if available ----
        let (shared_lib_base, shared_lib_map) = if plan.is_dynamic {
            map_shared_lib_to_vspace(child_vs, plan.layout.shared_libs.base, needed, pid)
        } else {
            (0, proc_table::ProcLibMap::zeroed())
        };

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] layout pid=");
            _lb.hex(pid as u64);
            _lb.str(b" elf=[");
            _lb.hex(plan.layout.elf_code.base);
            _lb.str(b",");
            _lb.hex(plan.layout.elf_code.end());
            _lb.str(b") rtld=[");
            _lb.hex(plan.layout.rtld.base);
            _lb.str(b",");
            _lb.hex(plan.layout.rtld.end());
            _lb.str(b") shlib=[");
            _lb.hex(plan.layout.shared_libs.base);
            _lb.str(b",");
            _lb.hex(plan.layout.shared_libs.end());
            _lb.str(b") elf_entry=");
            _lb.hex(elf_result.entry);
            _lb.str(b" rtld_entry=");
            _lb.hex(rtld_result.entry);
            _lb.str(b" rtld_base=");
            _lb.hex(rtld_result.base);
            _lb.str(b" shlib_base=");
            _lb.hex(shared_lib_base);
            _lb.str(b"\n");
        });

        // ---- Schedule ----
        let err = trona::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] SC configure failed\n"); });
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        let err = trona::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] SC bind failed\n"); });
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // ---- Map initrd and boot info for dynamic executables ----
        if plan.is_dynamic {
            if map_initrd_to_child_tx(
                child_vs,
                initrd,
                initrd_size,
                pid,
                plan.lib_window_pages,
                plan.layout.initrd.base,
            ) != 0
            {
                super::vfs_load::cleanup_exec_source(&mut vfs_source);
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
            if map_boot_info_to_child_tx(child_vs, pid) != 0 {
                super::vfs_load::cleanup_exec_source(&mut vfs_source);
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // ---- Materialize stack via mmsrv from a local staged top-page image ----
        let stack_pages = plan.layout.stack.page_count();
        let stack_stage = alloc_staging_buffer(1);
        if stack_stage.is_null() {
            super::vfs_load::cleanup_exec_source(&mut vfs_source);
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        volatile_zero(stack_stage, 4096);

        // ---- Write stack data into the staged top page ----
        let mut child_entry_rip = elf_result.entry;
        let mut child_rsp = plan.layout.stack_top;
        let (phdr_vaddr, phent, phnum) = if let Some(vfs) = vfs_stream {
            (
                plan.layout.elf_code.base + vfs.phdr_vaddr,
                vfs.phent,
                vfs.phnum,
            )
        } else {
            let mut phdr_vaddr = 0u64;
            let mut phent = 0u64;
            let mut phnum = 0u64;
            if trona_loader::elf_dynamic::elf_get_phdr_info(
                elf_entry.data,
                elf_entry.data_len,
                plan.layout.elf_code.base,
                &raw mut phdr_vaddr,
                &raw mut phent,
                &raw mut phnum,
            ) != 0
            {
                super::vfs_load::cleanup_exec_source(&mut vfs_source);
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_INVALID_ARGUMENT;
                return false;
            }
            (phdr_vaddr, phent, phnum)
        };

        if plan.is_dynamic {
            // Pass library window size for AT_TRONA_INITRD_SZ
            let initrd_window_size = plan.lib_window_pages * 4096;

            // Build argv/envp for the child process.
            let mut str_buf = [0u8; 256];
            let mut str_pos = 0usize;

            // argv[0]: resolved executable path captured at spawn time.
            let argv0 = if exec_path_len != 0 {
                &exec_path[..exec_path_len]
            } else {
                &name[..name_len]
            };
            for &b in argv0 {
                if str_pos < str_buf.len() {
                    str_buf[str_pos] = b;
                    str_pos += 1;
                }
            }
            if str_pos < str_buf.len() {
                str_buf[str_pos] = 0;
                str_pos += 1;
            } // NUL

            let mut argc: u32 = 1;
            if spawn_args_len > 0 && msg.length as usize > args_reg_idx && str_pos < str_buf.len() {
                let src = &msg.regs[args_reg_idx] as *const u64 as *const u8;
                let copy_len = core::cmp::min(spawn_args_len, str_buf.len() - str_pos);
                let mut saw_nonzero = false;
                let mut in_arg = false;
                for i in 0..copy_len {
                    let b = *src.add(i);
                    str_buf[str_pos] = b;
                    str_pos += 1;
                    if b != 0 {
                        saw_nonzero = true;
                        if !in_arg {
                            in_arg = true;
                            argc += 1;
                        }
                    } else {
                        in_arg = false;
                    }
                }
                if saw_nonzero && in_arg && str_pos < str_buf.len() {
                    str_buf[str_pos] = 0;
                    str_pos += 1;
                }
            }

            // envp strings
            let mut path_env = [0u8; 48];
            let prefix = b"PATH=";
            let mut pi = 0usize;
            while pi < prefix.len() {
                path_env[pi] = prefix[pi];
                pi += 1;
            }
            let dp = trona::consts::posix::DEFAULT_PATH;
            let mut di = 0usize;
            while di < dp.len() && pi < path_env.len() {
                path_env[pi] = dp[di];
                pi += 1;
                di += 1;
            }

            let env_strs: [&[u8]; 4] = [
                &path_env[..pi],
                b"HOME=/",
                b"TERM=vt100",
                b"SHELL=/bin/sh",
            ];
            for env in &env_strs {
                for &b in *env {
                    if str_pos < str_buf.len() {
                        str_buf[str_pos] = b;
                        str_pos += 1;
                    }
                }
                if str_pos < str_buf.len() {
                    str_buf[str_pos] = 0;
                    str_pos += 1;
                } // NUL
            }

            match write_dynamic_stack(
                phdr_vaddr,
                phent,
                phnum,
                0, // stk_frame unused in pre_mapped mode
                &elf_result,
                &rtld_result,
                initrd_window_size,
                shared_lib_base,
                argc,
                4,
                &str_buf,
                str_pos,
                plan.layout.scratch.base,
                plan.layout.initrd.base,
                plan.layout.stack_top,
                cn_size_bits,
                if use_pre_ep {
                    CHILD_CAP_SERVICE_EP + 1
                } else {
                    CHILD_RTLD_FRAME_SLOT_START
                },
                stack_stage,
                true, // pre_mapped: stack top page already at PROCMGR_SCRATCH_VADDR
            ) {
                Ok(rsp) => {
                    child_rsp = rsp;
                    child_entry_rip = rtld_result.entry;
                }
                Err(err) => {
                    free_staging_buffer(stack_stage, 1);
                    super::vfs_load::cleanup_exec_source(&mut vfs_source);
                    deregister_from_mmsrv(pid);
                    alloc.rollback();
                    reply.label = match err {
                        StackBuildError::OutOfMemory => TRONA_OUT_OF_MEMORY,
                        StackBuildError::InvalidArgument => TRONA_INVALID_ARGUMENT,
                        StackBuildError::TooLarge => TRONA_OUT_OF_RANGE,
                    };
                    return false;
                }
            }
        }

        match alloc_private_copy_from_client_region_to_mmsrv(
            pid,
            plan.layout.stack.base,
            stack_pages as u64,
            plan.layout.stack_top - 4096,
            stack_stage as u64,
            1,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        ) {
            Ok(base) if base == plan.layout.stack.base => {}
            _ => {
                free_staging_buffer(stack_stage, 1);
                super::vfs_load::cleanup_exec_source(&mut vfs_source);
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }
        free_staging_buffer(stack_stage, 1);

        // ELF scratch buffer no longer needed (all elf_entry.data users complete).
        super::vfs_load::cleanup_exec_source(&mut vfs_source);

        // ---- Map IPC buffer via mmsrv (child only, zero-filled) ----
        {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_MAP_BATCH;
            mm_msg.length = 4;
            mm_msg.regs[0] = pid as u64;
            mm_msg.regs[1] = plan.layout.ipc_buf.base;
            mm_msg.regs[2] = 1; // 1 page
            mm_msg.regs[3] = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
            let err = trona::ipc::call_ctx(
                super::ipc_ctx(),
                CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != TRONA_OK || mm_reply.regs[0] != 1 {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] SPAWN: MM_MAP_BATCH ipc failed\n"); });
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // ---- Configure TCB with entry point and stack pointer ----
        let err = trona::invoke::tcb_configure(child_tcb, child_entry_rip, child_rsp, 0);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] TCB configure failed\n"); });
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        let err = trona::invoke::tcb_set_ipc_buffer(child_tcb, plan.layout.ipc_buf.base);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] set child IPC buffer failed\n"); });
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // Pre-populate minimal PROCTAB fields so that CSpace expansion
        // handlers (serviced by the main loop's bound-ntfn poll) can
        // identify and serve this child during async readiness wait.
        {
            let p = proc_table::proctab(slot_idx);
            p.set_personality_from_subsystem_id(subsystem_id);
            p.state = if start_suspended {
                proc_table::PROC_STOPPED
            } else {
                proc_table::PROC_RUNNING
            };
            p.tcb_cap = child_tcb;
            p.vspace_cap = child_vs;
            p.cnode_cap = child_cn;
            p.sc_cap = child_sc;
            p.pid = pid;
            p.badge = pid as u64;
            p.has_service_ep = use_pre_ep;
            p.mmsrv_registered = true;
        }

        // ---- Start ----
        if !start_suspended {
            let err = trona::invoke::tcb_resume(child_tcb);
            if err != 0 {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] TCB resume failed\n"); });
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // ---- COMMIT ----
        let (slot_base, slot_count) = alloc.commit();

        // Record in process table
        let caller_idx = proc_table::find_by_badge(badge);
        let p = proc_table::proctab(slot_idx);
        p.set_personality_from_subsystem_id(subsystem_id);
        p.pid = pid;
        p.ppid = if let Some(ci) = caller_idx {
            proc_table::proctab(ci).pid
        } else {
            0
        };
        p.state = if start_suspended {
            proc_table::PROC_STOPPED
        } else {
            proc_table::PROC_RUNNING
        };
        p.exit_code = 0;
        p.badge = pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.slot_base = slot_base;
        p.slot_count = slot_count;
        p.shared_lib_base = shared_lib_base;
        p.lib_map = shared_lib_map;
        p.layout = plan.layout;
        p.has_service_ep = use_pre_ep;
        p.mmsrv_registered = true;
        let is_notify = plan.readiness_mode == trona::SPAWN_READY_NOTIFY;
        p.ready_ntfn = if is_notify { child_ready_ntfn } else { 0 };
        p.wait_ready_on_resume = start_suspended && is_notify;
        p.ready_timeout_ns = if is_notify { plan.ready_timeout_ns } else { 0 };
        if p.is_posix() {
            let posix = p.posix_mut();
            posix.sid = if let Some(ci) = caller_idx {
                proc_table::proctab(ci).posix().sid
            } else {
                pid
            };
            posix.waiter_reply = 0;
            posix.waiter_pid = 0;
            posix.signal_ntfn = child_sig_ntfn;
            posix.pgid = if let Some(ci) = caller_idx {
                proc_table::proctab(ci).posix().pgid
            } else {
                pid
            };
            for i in 0..proc_table::NSIG {
                posix.sig_disposition[i] = proc_table::SIG_DISP_DFL;
            }
        }

        // Set process name (up to 31 chars + NUL)
        {
            let name_copy = if name_len > 31 { 31 } else { name_len };
            for i in 0..name_copy {
                p.name[i] = name[i];
            }
            for i in name_copy..32 {
                p.name[i] = 0;
            }
            let exe_copy = if exec_path_len >= proc_table::MAX_EXE_PATH_LEN {
                proc_table::MAX_EXE_PATH_LEN - 1
            } else {
                exec_path_len
            };
            if p.is_posix() {
                let posix = p.posix_mut();
                for i in 0..exe_copy {
                    posix.exe_path[i] = exec_path[i];
                }
                for i in exe_copy..proc_table::MAX_EXE_PATH_LEN {
                    posix.exe_path[i] = 0;
                }
            }
        }

        // SPAWN_FLAG_RESPAWN: mark process for automatic restart on exit
        if (spawn_flags & SPAWN_FLAG_RESPAWN) != 0 {
            p.respawn = true;
            let copy_len = if name_len > proc_table::MAX_NAME_LEN {
                proc_table::MAX_NAME_LEN
            } else {
                name_len
            };
            for i in 0..copy_len {
                p.respawn_binary[i] = name[i];
            }
            for i in copy_len..proc_table::MAX_NAME_LEN {
                p.respawn_binary[i] = 0;
            }
        }

        // Defer readiness wait: save caller reply and return to main loop
        if !start_suspended && is_notify {
            if super::readiness::defer_readiness(slot_idx) {
                return true;
            }
            // Defer failed (OOM) — graceful degradation: clear readiness fields
            // and reply immediately. The child is already running.
            p.ready_ntfn = 0;
            p.ready_timeout_ns = 0;
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] Process started PID=");
            _lb.hex(pid as u64);
            _lb.str(b"\n");
        });
        reply.label = TRONA_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
        return false;
    }
}

// ===========================================================================
// PE spawn inner — handles PE/COFF binary loading
// ===========================================================================

/// Inner PE spawn path: validates PE, loads image + pe_rtld, builds stack,
/// starts the child process.
///
/// # Safety
/// All pointers must be valid. `data` must point to a valid PE32+ file.
#[allow(clippy::too_many_arguments)]
unsafe fn handle_pe_spawn_inner(
    msg: &TronaMsg,
    reply: &mut TronaMsg,
    badge: u64,
    alloc: &mut Allocator,
    data: *const u8,
    data_len: usize,
    name: &[u8],
    name_len: usize,
    exec_path: &[u8],
    exec_path_len: usize,
    subsystem_id: u8,
    readiness_mode: u64,
    requested_timeout_ns: u64,
    spawn_flags: u64,
    spawn_args_len: usize,
    args_reg_idx: usize,
    use_pre_ep: bool,
    start_suspended: bool,
    _policy_map_initrd: bool,
    policy_is_display: bool,
    policy_cnode_bits: u8,
    is_display: bool,
) -> bool {
    unsafe {
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] PE spawn: '");
            _lb.bytes(&name[..name_len]);
            _lb.str(b"'\n");
        });

        // Validate PE and get image span
        let mut pe_info = trona_loader::pe_loader::PeInfo::zeroed();
        let err = trona_loader::pe_loader::pe_validate(data, data_len, &raw mut pe_info);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] PE validation failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let pe_span = trona_loader::pe_loader::pe_compute_load_span(data, data_len);
        if pe_span == 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] PE span is zero\n"); });
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        // Find ld-trona-pe.so in initrd
        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::read_boot_info_initrd_size();

        let pe_rtld_name = b"ld-trona-pe.so";
        let pe_rtld_span = {
            let mut pe_rtld_entry = CpioEntry::zeroed();
            if trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                pe_rtld_name.as_ptr(),
                pe_rtld_name.len(),
                &raw mut pe_rtld_entry,
            ) == 0
            {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] ld-trona-pe.so not found in initrd\n"); });
                reply.label = TRONA_NOT_FOUND;
                return false;
            }
            trona_loader::elf_loader::elf_compute_load_span(
                pe_rtld_entry.data,
                pe_rtld_entry.data_len,
            )
        };

        // Find kernel32.dll in initrd to compute its VA span for layout planning
        let kernel32_name = b"kernel32.dll";
        let kernel32_span = {
            let mut k32_entry = CpioEntry::zeroed();
            if trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                kernel32_name.as_ptr(),
                kernel32_name.len(),
                &raw mut k32_entry,
            ) != 0
            {
                trona_loader::pe_loader::pe_compute_load_span(k32_entry.data, k32_entry.data_len)
            } else {
                0
            }
        };
        let kernel32_pages = ((kernel32_span + 0xFFF) / 0x1000) as usize;

        // Compute VM layout: PE image + pe_rtld + kernel32 + stack
        // Reuse ELF layout with PE span in the elf_code slot, pe_rtld in rtld,
        // and kernel32 in shared_libs.
        let layout = layout::compute_vm_layout_randomized(
            pe_span,
            pe_rtld_span,
            kernel32_pages,
            false, // no initrd mapping needed
            0,
            || trona::syscall::sys_getrandom(),
        );

        if layout.stack_top == 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] PE too large for VA layout\n"); });
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let effective_timeout_ns = if readiness_mode == trona::SPAWN_READY_NOTIFY {
            compute_ready_timeout_ns(requested_timeout_ns, true, data_len, 0)
        } else {
            0
        };

        let plan = SpawnPlan {
            is_dynamic: true, // PE always uses pe_rtld
            readiness_mode,
            ready_timeout_ns: effective_timeout_ns,
            total_slots: compute_slot_budget(),
            is_display,
            lib_window_pages: 0,
            layout,
        };

        // Auto-register caller if unknown
        let caller_idx = proc_table::find_by_badge(badge);
        if caller_idx.is_none() && badge != 0 {
            if let Some(ci) = proc_table::alloc_proc() {
                proc_table::proctab(ci).set_posix_personality();
                proc_table::proctab(ci).pid = badge as u32;
                proc_table::proctab(ci).ppid = 0;
                proc_table::proctab(ci).state = proc_table::PROC_RUNNING;
                proc_table::proctab(ci).badge = badge;
            }
        }

        let Some(slot_idx) = proc_table::alloc_proc() else {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] process table full\n"); });
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        let pid = proc_table::NEXT_PID;
        proc_table::NEXT_PID += 1;

        // ---- PRE-PROVISION mmsrv untyped (breaks Procmgr↔MMSRV cycle) ----
        ensure_mmsrv_capacity(alloc);

        // ---- RESERVE ----
        if !alloc.reserve(plan.total_slots) {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] slot reservation failed\n"); });
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // ---- REALIZE fixed objects via mmsrv ----
        macro_rules! realize_mm {
            ($ty:expr, $sz:expr, $off:expr, $what:expr) => {
                match alloc.realize_via_mmsrv(CAP_MMSRV_EP, $ty, $sz, $off) {
                    Ok(s) => s,
                    Err(e) => {
                        trona::uerror!(|_lb| {
                            _lb.str(b"[PROCMGR] PE alloc ");
                            _lb.bytes($what);
                            _lb.str(b" failed err=");
                            _lb.hex(e as u64);
                            _lb.str(b"\n");
                        });
                        alloc.rollback();
                        reply.label = TRONA_OUT_OF_MEMORY;
                        return false;
                    }
                }
            };
        }

        let child_tcb = realize_mm!(OBJ_TCB, 0, OFF_TCB, b"TCB");
        let child_vs = realize_mm!(OBJ_VSPACE, 0, OFF_VSPACE, b"VSpace");
        let cn_size_bits = if policy_cnode_bits > 0 {
            policy_cnode_bits as u64
        } else {
            0
        };
        let child_cn = realize_mm!(OBJ_CNODE, cn_size_bits, OFF_CNODE, b"CNode");
        let child_sc = realize_mm!(OBJ_SCHED_CONTEXT, 0, OFF_SC, b"SC");
        let child_sig_ntfn = realize_mm!(OBJ_NOTIFICATION, 0, OFF_SIGNAL_NTFN, b"signal ntfn");

        let child_ready_ntfn = if plan.readiness_mode == trona::SPAWN_READY_NOTIFY {
            realize_mm!(OBJ_NOTIFICATION, 0, OFF_READY_NTFN, b"ready ntfn")
        } else {
            0
        };

        // Mint mmsrv EP into child CNode slot 7
        let err = trona::invoke::cnode_mint(
            CAP_SELF_CSPACE,
            CAP_MMSRV_EP_UNBADGED,
            child_cn,
            CHILD_CAP_MMSRV_EP,
            pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] PE mint mmsrv EP failed\n"); });
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // Copy standard caps into child CNode
        let err = copy_child_caps_tx(
            child_tcb,
            child_vs,
            child_cn,
            child_sc,
            child_sig_ntfn,
            child_ready_ntfn,
            plan.readiness_mode == trona::SPAWN_READY_NOTIFY,
            plan.is_display,
            pid,
            if use_pre_ep { CAP_RECV_SCRATCH } else { 0 },
        );
        if err != 0 {
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // Mint CSpace expansion notification
        let pm_ntfn = *(&raw const super::PM_BOUND_NTFN);
        if pm_ntfn != 0 {
            let cs_badge = 1u64 << (16 + slot_idx);
            let _ = trona::invoke::cnode_mint(
                CAP_SELF_CSPACE,
                pm_ntfn,
                child_cn,
                CHILD_CAP_CSPACE_NTFN,
                cs_badge,
            );
        }

        // Configure TCB
        let err = trona::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] PE TCB set_space failed\n"); });
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // Set fault handler
        {
            let temp_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    alloc.rollback();
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return false;
                }
            };
            let err = trona::invoke::cnode_mint(
                CAP_SELF_CSPACE,
                CAP_MMSRV_EP_UNBADGED,
                CAP_SELF_CSPACE,
                temp_slot,
                pid as u64,
            );
            if err == 0 {
                let _ = trona::invoke::tcb_set_fault_handler(child_tcb, temp_slot);
            }
            trona::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
            alloc.free_single_slot(temp_slot);
        }

        // Register with mmsrv
        let heap_base = plan.layout.heap_base();
        let mmap_base = trona::layout::compute_mmap_base(&plan.layout, heap_base);
        {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_REGISTER;
            mm_msg.length = 4;
            mm_msg.regs[0] = pid as u64;
            mm_msg.regs[1] = heap_base;
            mm_msg.regs[2] = mmap_base;
            mm_msg.regs[3] = pid as u64;
            trona::ipc::set_send_cap_ctx(super::ipc_ctx(), 0, child_vs);
            let err = trona::ipc::call_ctx(
                super::ipc_ctx(),
                CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != TRONA_OK {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] PE mmsrv register failed\n"); });
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }
        // ---- Load PE image via mmsrv ----
        let pe_result = match exec_load_pe_mmsrv(
            data,
            data_len,
            plan.layout.elf_code.base, // PE image goes in the "elf_code" layout region
            pid,
            child_vs,
        ) {
            Ok(r) => r,
            Err(e) => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] PE load failed err=");
                    _lb.hex(e as u64);
                    _lb.str(b"\n");
                });
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        // ---- Load ld-trona-pe.so (PE runtime loader, ELF format) via mmsrv ----
        let rtld_result = match exec_load_rtld_mmsrv_by_name(
            pe_rtld_name.as_ptr(),
            pe_rtld_name.len(),
            initrd,
            initrd_size,
            plan.layout.rtld.base,
            pid,
            child_vs,
        ) {
            Some(r) => r,
            None => {
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_NOT_FOUND;
                return false;
            }
        };

        let kernel32_result = match exec_load_pe_mmsrv_by_name(
            kernel32_name.as_ptr(),
            kernel32_name.len(),
            initrd,
            initrd_size,
            plan.layout.shared_libs.base,
            pid,
            child_vs,
        ) {
            Some(r) => r,
            None => {
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_NOT_FOUND;
                return false;
            }
        };

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] PE layout pid=");
            _lb.hex(pid as u64);
            _lb.str(b" pe=[");
            _lb.hex(pe_result.base);
            _lb.str(b",");
            _lb.hex(pe_result.image_end);
            _lb.str(b") rtld=[");
            _lb.hex(rtld_result.base);
            _lb.str(b",");
            _lb.hex(rtld_result.base + rtld_result.brk);
            _lb.str(b") kernel32=[");
            _lb.hex(kernel32_result.base);
            _lb.str(b",");
            _lb.hex(kernel32_result.image_end);
            _lb.str(b") pe_entry=");
            _lb.hex(pe_result.entry);
            _lb.str(b" rtld_entry=");
            _lb.hex(rtld_result.entry);
            _lb.str(b"\n");
        });

        // ---- Schedule ----
        let err = trona::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 {
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        let err = trona::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 {
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // ---- Materialize stack via mmsrv from a local staged top-page image ----
        let stack_pages = plan.layout.stack.page_count();
        let stack_stage = alloc_staging_buffer(1);
        if stack_stage.is_null() {
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        volatile_zero(stack_stage, 4096);

        // ---- Write PE stack with PE-specific auxv ----
        let slot_pool_floor = if use_pre_ep {
            CHILD_CAP_WIN32SRV_EP + 1
        } else if CHILD_CAP_WIN32SRV_EP + 1 > CHILD_RTLD_FRAME_SLOT_START {
            CHILD_CAP_WIN32SRV_EP + 1
        } else {
            CHILD_RTLD_FRAME_SLOT_START
        };
        let slot_pool_base = if slot_pool_floor > CHILD_RTLD_FRAME_SLOT_START {
            slot_pool_floor
        } else {
            CHILD_RTLD_FRAME_SLOT_START
        };
        let slot_pool_count = CSPACE_EXPAND_BASE.saturating_sub(slot_pool_base);

        // Build minimal argv
        let mut str_buf = [0u8; 256];
        let mut str_pos = 0usize;
        let argv0 = if exec_path_len != 0 {
            &exec_path[..exec_path_len]
        } else {
            &name[..name_len]
        };
        for &b in argv0 {
            if str_pos < str_buf.len() {
                str_buf[str_pos] = b;
                str_pos += 1;
            }
        }
        if str_pos < str_buf.len() {
            str_buf[str_pos] = 0;
            str_pos += 1;
        }

        let mut argc: u32 = 1;
        if spawn_args_len > 0 && msg.length as usize > args_reg_idx && str_pos < str_buf.len() {
            let src = &msg.regs[args_reg_idx] as *const u64 as *const u8;
            let copy_len = core::cmp::min(spawn_args_len, str_buf.len() - str_pos);
            let mut in_arg = false;
            for i in 0..copy_len {
                let b = *src.add(i);
                str_buf[str_pos] = b;
                str_pos += 1;
                if b != 0 {
                    if !in_arg {
                        in_arg = true;
                        argc += 1;
                    }
                } else {
                    in_arg = false;
                }
            }
            if in_arg && str_pos < str_buf.len() {
                str_buf[str_pos] = 0;
                str_pos += 1;
            }
        }

        let envc: u32 = 0;
        let win32srv_ep: u64 = CHILD_CAP_WIN32SRV_EP;

        let child_entry_rip;
        let child_rsp;
        match write_pe_stack(
            &pe_result,
            &rtld_result,
            &kernel32_result,
            stack_stage,
            plan.layout.scratch.base,
            plan.layout.ipc_buf.base,
            win32srv_ep,
            argc,
            envc,
            &str_buf,
            str_pos,
            plan.layout.stack_top,
            slot_pool_base,
            slot_pool_count,
        ) {
            Ok(rsp) => {
                child_rsp = rsp;
                child_entry_rip = rtld_result.entry; // Start at pe_rtld, not PE entry
            }
            Err(_) => {
                free_staging_buffer(stack_stage, 1);
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        match alloc_private_copy_from_client_region_to_mmsrv(
            pid,
            plan.layout.stack.base,
            stack_pages as u64,
            plan.layout.stack_top - 4096,
            stack_stage as u64,
            1,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        ) {
            Ok(base) if base == plan.layout.stack.base => {}
            _ => {
                free_staging_buffer(stack_stage, 1);
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }
        free_staging_buffer(stack_stage, 1);

        // Map IPC buffer
        {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_MAP_BATCH;
            mm_msg.length = 4;
            mm_msg.regs[0] = pid as u64;
            mm_msg.regs[1] = plan.layout.ipc_buf.base;
            mm_msg.regs[2] = 1;
            mm_msg.regs[3] = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
            let err = trona::ipc::call_ctx(
                super::ipc_ctx(),
                CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != TRONA_OK || mm_reply.regs[0] != 1 {
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // Configure TCB with entry point and stack
        let err = trona::invoke::tcb_configure(child_tcb, child_entry_rip, child_rsp, 0);
        if err != 0 {
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        let err = trona::invoke::tcb_set_ipc_buffer(child_tcb, plan.layout.ipc_buf.base);
        if err != 0 {
            deregister_from_mmsrv(pid);
            alloc.rollback();
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        // Pre-populate PROCTAB before the child runs so early procmgr IPC
        // sees the correct Win32 subsystem/personality rather than the
        // default zeroed POSIX state.
        {
            let p = proc_table::proctab(slot_idx);
            p.set_win32_personality();
            p.state = if start_suspended {
                proc_table::PROC_STOPPED
            } else {
                proc_table::PROC_RUNNING
            };
            p.tcb_cap = child_tcb;
            p.vspace_cap = child_vs;
            p.cnode_cap = child_cn;
            p.sc_cap = child_sc;
            p.pid = pid;
            p.badge = pid as u64;
            p.shared_lib_base = kernel32_result.base;
            p.layout = plan.layout;
            p.has_service_ep = use_pre_ep;
            p.mmsrv_registered = true;
            p.ready_ntfn = if start_suspended { child_ready_ntfn } else { 0 };
            p.wait_ready_on_resume =
                start_suspended && plan.readiness_mode == trona::SPAWN_READY_NOTIFY;
            p.ready_timeout_ns = if start_suspended {
                plan.ready_timeout_ns
            } else {
                0
            };
            let name_copy = if name_len > 31 { 31 } else { name_len };
            for i in 0..name_copy {
                p.name[i] = name[i];
            }
            for i in name_copy..32 {
                p.name[i] = 0;
            }
        }

        // Start
        if !start_suspended {
            let err = trona::invoke::tcb_resume(child_tcb);
            if err != 0 {
                deregister_from_mmsrv(pid);
                alloc.rollback();
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // ---- COMMIT ----
        let (slot_base, slot_count) = alloc.commit();

        let caller_idx = proc_table::find_by_badge(badge);
        let p = proc_table::proctab(slot_idx);
        p.set_win32_personality();
        p.pid = pid;
        p.ppid = if let Some(ci) = caller_idx {
            proc_table::proctab(ci).pid
        } else {
            0
        };
        p.state = if start_suspended {
            proc_table::PROC_STOPPED
        } else {
            proc_table::PROC_RUNNING
        };
        p.exit_code = 0;
        p.badge = pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.slot_base = slot_base;
        p.slot_count = slot_count;
        p.shared_lib_base = kernel32_result.base;
        p.lib_map = proc_table::ProcLibMap::zeroed();
        p.layout = plan.layout;
        p.has_service_ep = use_pre_ep;
        p.mmsrv_registered = true;
        let is_notify = plan.readiness_mode == trona::SPAWN_READY_NOTIFY;
        p.ready_ntfn = if is_notify { child_ready_ntfn } else { 0 };
        p.wait_ready_on_resume = start_suspended && is_notify;
        p.ready_timeout_ns = if is_notify { plan.ready_timeout_ns } else { 0 };

        // Set process name
        {
            let name_copy = if name_len > 31 { 31 } else { name_len };
            for i in 0..name_copy {
                p.name[i] = name[i];
            }
            for i in name_copy..32 {
                p.name[i] = 0;
            }
        }

        if (spawn_flags & SPAWN_FLAG_RESPAWN) != 0 {
            p.respawn = true;
            let copy_len = if name_len > proc_table::MAX_NAME_LEN {
                proc_table::MAX_NAME_LEN
            } else {
                name_len
            };
            for i in 0..copy_len {
                p.respawn_binary[i] = name[i];
            }
            for i in copy_len..proc_table::MAX_NAME_LEN {
                p.respawn_binary[i] = 0;
            }
        }

        // Defer readiness wait: save caller reply and return to main loop
        if !start_suspended && is_notify {
            if super::readiness::defer_readiness(slot_idx) {
                return true;
            }
            // Defer failed (OOM) — graceful degradation
            p.ready_ntfn = 0;
            p.ready_timeout_ns = 0;
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] PE process started PID=");
            _lb.hex(pid as u64);
            _lb.str(b"\n");
        });
        reply.label = TRONA_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
        return false;
    }
}

// ===========================================================================
// Helper: map initrd via device-map with selective library window
// ===========================================================================

unsafe fn map_initrd_to_child_tx(
    child_vs: Cap,
    _initrd: *const u8,
    initrd_size: usize,
    pid: u32,
    lib_window_pages: usize,
    initrd_base_vaddr: u64,
) -> i32 {
    unsafe {
        // Use library window if available, otherwise full initrd
        let map_pages = if lib_window_pages > 0 {
            lib_window_pages
        } else {
            (initrd_size + 4095) / 4096
        };

        let mut mapped_with_device = true;

        for pg in 0..map_pages {
            let err = trona::invoke::vspace_map_device(
                child_vs,
                CAP_INITRD_UNTYPED,
                (pg as u64) * 4096,
                initrd_base_vaddr + pg as u64 * 4096,
                VSPACE_FLAG_USER,
            );
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] initrd device map failed pg=");
                    _lb.hex(pg as u64);
                    _lb.str(b" err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                for mapped_pg in 0..pg {
                    trona::invoke::vspace_unmap(
                        child_vs,
                        initrd_base_vaddr + mapped_pg as u64 * 4096,
                    );
                }
                mapped_with_device = false;
                break;
            }
        }

        if mapped_with_device {
            return 0;
        }

        let _ = _initrd;
        let copy_size = map_pages * 4096;
        if alloc_initrd_copy_from_mmsrv(
            pid,
            initrd_base_vaddr,
            map_pages as u64,
            copy_size as u64,
            VSPACE_FLAG_USER,
        )
        .is_err()
        {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] initrd MM_ALLOC_INITRD_COPY failed\n"); });
            return -1;
        }
        0
    }
}

/// Map boot info page into child VSpace via mmsrv.
///
/// The child must already be registered with mmsrv (MM_REGISTER done).
unsafe fn map_boot_info_to_child_tx(child_vs: Cap, pid: u32) -> i32 {
    unsafe {
        let _ = child_vs;
        if alloc_bootinfo_copy_from_mmsrv(
            pid,
            super::BOOTINFO_VADDR,
            VSPACE_FLAG_USER,
        )
        .is_err()
        {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] bootinfo MM_ALLOC_BOOTINFO_COPY failed\n"); });
            return -1;
        }

        0
    }
}

/// Copy standard caps into child CNode.
fn copy_child_caps_tx(
    child_tcb: Cap,
    child_vs: Cap,
    child_cn: Cap,
    child_sc: Cap,
    child_sig_ntfn: Cap,
    child_ready_ntfn: Cap,
    with_ready_ntfn: bool,
    with_fb_untyped: bool,
    pid: u32,
    pre_service_ep: Cap,
) -> i32 {
    let mut err;
    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_tcb,
        child_cn,
        CHILD_CAP_TCB,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] copy TCB cap failed\n"); });
        return err;
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_vs,
        child_cn,
        CHILD_CAP_VSPACE,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] copy VSpace cap failed\n"); });
        return err;
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_cn,
        child_cn,
        CHILD_CAP_CSPACE,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] copy CNode cap failed\n"); });
        return err;
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_sc,
        child_cn,
        CHILD_CAP_SC,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] copy SC cap failed\n"); });
        return err;
    }

    err = trona::invoke::cnode_mint(
        CAP_SELF_CSPACE,
        CAP_SERVER_EP,
        child_cn,
        CHILD_CAP_EP,
        pid as u64,
    );
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] mint EP cap failed err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return err;
    }

    if pre_service_ep != 0 {
        err = trona::invoke::cnode_move(
            child_cn,
            CHILD_CAP_SERVICE_EP,
            CAP_SELF_CSPACE,
            pre_service_ep,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] copy pre-service EP failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return err;
        }
    }

    err = trona::invoke::cnode_mint(
        CAP_SELF_CSPACE,
        CAP_VFS_EP,
        child_cn,
        CHILD_CAP_VFS,
        pid as u64,
    );
    if err != 0 {
        trona::uwarn!(|_lb| { _lb.str(b"[PROCMGR] WARN: mint VFS EP failed, trying unbadged copy\n"); });
        err = trona::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            CAP_VFS_EP,
            child_cn,
            CHILD_CAP_VFS,
            CAP_RIGHTS_ALL,
        );
        if err != 0 {
            trona::uwarn!(|_lb| { _lb.str(b"[PROCMGR] WARN: copy VFS EP cap failed\n"); });
        }
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        CAP_NAMESRV_EP,
        child_cn,
        CHILD_CAP_NAMESRV,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uwarn!(|_lb| { _lb.str(b"[PROCMGR] WARN: copy Nameserv EP cap failed\n"); });
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_sig_ntfn,
        child_cn,
        CHILD_CAP_SIGNAL_NTFN,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uwarn!(|_lb| { _lb.str(b"[PROCMGR] WARN: copy signal ntfn cap failed\n"); });
    }

    if with_ready_ntfn {
        err = trona::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            child_ready_ntfn,
            child_cn,
            CHILD_CAP_READINESS_NTFN,
            CAP_RIGHTS_ALL,
        );
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] copy readiness ntfn cap failed\n"); });
            return err;
        }
    }

    if with_fb_untyped {
        err = trona::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            CAP_FB_UNTYPED,
            child_cn,
            13, // Child's CAP_FB_UNTYPED slot
            CAP_RIGHTS_ALL,
        );
        if err != 0 {
            trona::uwarn!(|_lb| { _lb.str(b"[PROCMGR] WARN: copy framebuffer untyped cap failed\n"); });
        }
    }

    // Provide initrd device-untyped
    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        CAP_INITRD_UNTYPED,
        child_cn,
        CAP_INITRD_UNTYPED,
        INITRD_COPY_RIGHTS,
    );
    if err != 0 {
        trona::uwarn!(|_lb| { _lb.str(b"[PROCMGR] WARN: copy initrd untyped cap failed\n"); });
    }

    // Note: root untypeds are no longer mirrored to children.
    // Child-private regions are materialized by mmsrv and populated via
    // staged copy transactions from procmgr.

    0
}
