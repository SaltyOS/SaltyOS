//! Transactional spawn pipeline
//!
//! Uses the centralized allocator for slot management and rollback-safe
//! object creation. Replaces the stride-based handle_spawn.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use salty::serial::LineBuf;
use salty::types::*;

use crate::alloc::Allocator;
use crate::proc_table;

fn puts(s: &[u8]) {
    salty::serial::serial_puts(s);
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
const OFF_CHILD_UT: usize = 7;
const OFF_READY_NTFN: usize = 8;
pub(crate) const OFF_FIXED_END: usize = 9;
// Offsets >= OFF_FIXED_END are used for ELF/rtld pages, extra stack frames,
// boot info frame, etc.

const CHILD_UT_BITS_MIN: u8 = 12;

// ---- Re-exports from parent ----
const OBJ_TCB: u64 = salty::OBJ_TCB;
const OBJ_VSPACE: u64 = salty::OBJ_VSPACE;
const OBJ_CNODE: u64 = salty::OBJ_CNODE;
const OBJ_SCHED_CONTEXT: u64 = salty::OBJ_SCHED_CONTEXT;
const OBJ_FRAME: u64 = salty::OBJ_FRAME;
const OBJ_NOTIFICATION: u64 = salty::OBJ_NOTIFICATION;
const OBJ_UNTYPED: u64 = salty::OBJ_UNTYPED;
const SALTY_OK: u64 = salty::SALTY_OK;
const SALTY_OUT_OF_MEMORY: u64 = salty::SALTY_OUT_OF_MEMORY;
const SALTY_NOT_FOUND: u64 = salty::SALTY_NOT_FOUND;
const SALTY_BUSY: u64 = salty::SALTY_BUSY;
const SALTY_INVALID_ARGUMENT: u64 = salty::SALTY_INVALID_ARGUMENT;
const VSPACE_FLAG_WRITABLE: u64 = salty::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = salty::VSPACE_FLAG_USER;
const VSPACE_FLAG_EXECUTABLE: u64 = salty::VSPACE_FLAG_EXECUTABLE;
const CAP_RIGHTS_ALL: u64 = salty::CAP_RIGHTS_ALL;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3);

// Re-use parent module's layout constants
const CHILD_CODE_VADDR: u64 = super::CHILD_CODE_VADDR;
const CHILD_STACK_VADDR: u64 = super::CHILD_STACK_VADDR;
const CHILD_STACK_PAGES: usize = super::CHILD_STACK_PAGES;
const CHILD_STACK_TOP: u64 = super::CHILD_STACK_TOP;
const CHILD_IPC_BUF_VADDR: u64 = super::CHILD_IPC_BUF_VADDR;
const CHILD_RTLD_VADDR: u64 = super::CHILD_RTLD_VADDR;
const CHILD_INITRD_VADDR: u64 = super::CHILD_INITRD_VADDR;
const CHILD_SCRATCH_VADDR: u64 = super::CHILD_SCRATCH_VADDR;
const CHILD_RTLD_FRAME_SLOT_START: u64 = super::CHILD_RTLD_FRAME_SLOT_START;
const PROCMGR_SCRATCH_VADDR: u64 = super::PROCMGR_SCRATCH_VADDR;

const CHILD_CAP_TCB: u64 = super::CHILD_CAP_TCB;
const CHILD_CAP_VSPACE: u64 = super::CHILD_CAP_VSPACE;
const CHILD_CAP_CSPACE: u64 = super::CHILD_CAP_CSPACE;
const CHILD_CAP_EP: u64 = super::CHILD_CAP_EP;
const CHILD_CAP_VFS: u64 = super::CHILD_CAP_VFS;
const CHILD_CAP_NAMESERV: u64 = super::CHILD_CAP_NAMESERV;
const CHILD_CAP_SIGNAL_NTFN: u64 = super::CHILD_CAP_SIGNAL_NTFN;
const CHILD_CAP_UNTYPED: u64 = super::CHILD_CAP_UNTYPED;
const CHILD_CAP_READINESS_NTFN: u64 = super::CHILD_CAP_READINESS_NTFN;

const CAP_SELF_CSPACE: Cap = super::CAP_SELF_CSPACE;
const CAP_SELF_VSPACE: Cap = super::CAP_SELF_VSPACE;
const CAP_SERVER_EP: Cap = super::CAP_SERVER_EP;
const CAP_NAMESERV_EP: Cap = super::CAP_NAMESERV_EP;
const CAP_VFS_EP: Cap = super::CAP_VFS_EP;
const CAP_INITRD_UNTYPED: Cap = super::CAP_INITRD_UNTYPED;
const CAP_UNTYPED_START: Cap = super::CAP_UNTYPED_START;

const AT_NULL: u64 = super::AT_NULL;
const AT_PHDR: u64 = super::AT_PHDR;
const AT_PHENT: u64 = super::AT_PHENT;
const AT_PHNUM: u64 = super::AT_PHNUM;
const AT_PAGESZ: u64 = super::AT_PAGESZ;
const AT_BASE: u64 = super::AT_BASE;
const AT_ENTRY: u64 = super::AT_ENTRY;
const AT_SALTY_UNTYPED: u64 = super::AT_SALTY_UNTYPED;
const AT_SALTY_VSPACE: u64 = super::AT_SALTY_VSPACE;
const AT_SALTY_SCRATCH: u64 = super::AT_SALTY_SCRATCH;
const AT_SALTY_INITRD: u64 = super::AT_SALTY_INITRD;
const AT_SALTY_INITRD_SZ: u64 = super::AT_SALTY_INITRD_SZ;
const AT_SALTY_FRAME_SLOT: u64 = super::AT_SALTY_FRAME_SLOT;
const AT_SALTY_SHARED_LIB_BASE: u64 = super::AT_SALTY_SHARED_LIB_BASE;
const UT_MIRROR_COUNT: Cap = super::UT_MIRROR_COUNT;
const CHILD_UT_BITS_DEFAULT: u8 = super::CHILD_UT_BITS_DEFAULT;
const READY_TIMEOUT_NS_DEFAULT: u64 = super::READY_TIMEOUT_NS_DEFAULT;

const PM_SPAWN_FLAG_WAIT_READY: u64 = super::PM_SPAWN_FLAG_WAIT_READY;

// ===========================================================================
// Shared library physical frame cache
// ===========================================================================

const MAX_SHARED_LIB_PAGES: usize = 192;

/// Well-known CNode slots where init copies shared lib frame caps.
const CAP_SHARED_LIB_CACHE_BASE: u64 = 0x80;

#[derive(Clone, Copy)]
struct SharedPage {
    vaddr_offset: u64,
    frame_cap: Cap,
    flags: u64,
}

struct SharedLibCache {
    initialized: bool,
    page_count: usize,
    pages: [SharedPage; MAX_SHARED_LIB_PAGES],
}

impl SharedLibCache {
    const fn new() -> Self {
        SharedLibCache {
            initialized: false,
            page_count: 0,
            pages: [SharedPage { vaddr_offset: 0, frame_cap: 0, flags: 0 }; MAX_SHARED_LIB_PAGES],
        }
    }
}

static mut SHARED_LIB_CACHE: SharedLibCache = SharedLibCache::new();

/// Check if a virtual address falls within the shared library cache's RO pages
/// and return the cached frame cap + flags if so.
///
/// # Safety
/// Caller must ensure `SHARED_LIB_CACHE` is not being concurrently modified.
pub(crate) unsafe fn lookup_shared_lib_page(vaddr: u64, lib_base: u64) -> Option<(Cap, u64)> {
    unsafe {
        let cache = &*(&raw const SHARED_LIB_CACHE);
        if !cache.initialized || cache.page_count == 0 || lib_base == 0 {
            return None;
        }
        if vaddr < lib_base {
            return None;
        }
        let offset = vaddr - lib_base;
        for i in 0..cache.page_count {
            if cache.pages[i].vaddr_offset == offset {
                return Some((cache.pages[i].frame_cap, cache.pages[i].flags));
            }
        }
        None
    }
}

// ===========================================================================
// Spawn plan
// ===========================================================================

struct SpawnPlan {
    is_dynamic: bool,
    wait_ready: bool,
    ready_timeout_ns: u64,
    child_ut_bits: u8,
    total_slots: usize,
    is_display: bool,
    lib_window_pages: usize,
}

/// Estimate total slots needed for a spawn.
fn estimate_slots(is_dynamic: bool) -> usize {
    // Fixed objects: TCB, VSpace, CNode, SC, stack_frame, ipc_frame,
    //   signal_ntfn, child_ut, ready_ntfn
    let mut count = OFF_FIXED_END;

    // Extra stack frames (4 pages total, 1 is at OFF_STACK_FR)
    count += CHILD_STACK_PAGES - 1;

    // ELF pages (estimate: ~10 for main binary)
    count += 10;

    if is_dynamic {
        // rtld pages (~5)
        count += 5;
        // Boot info frame
        count += 1;
        // Initrd mapping: usually device-map (0 frames),
        // but reserve a few for copy fallback
        count += 4;
    }

    // Margin for alignment/extras
    count += 4;

    count
}

// ===========================================================================
// Frame allocation callback for ELF loader
// ===========================================================================

struct FrameAllocCtx {
    alloc: *mut Allocator,
    error: i32,
}

unsafe extern "C" fn spawn_alloc_frame(opaque: *mut u8) -> Cap {
    unsafe {
        let ctx = &mut *(opaque as *mut FrameAllocCtx);
        let alloc = &mut *ctx.alloc;
        match alloc.realize_object(OBJ_FRAME, 0) {
            Ok(slot) => slot,
            Err(e) => {
                ctx.error = e;
                0
            }
        }
    }
}

// ===========================================================================
// Service profile lookup
// ===========================================================================

fn ascii_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { b + 32 } else { b }
}

fn bytes_eq_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if ascii_lower(a[i]) != ascii_lower(b[i]) {
            return false;
        }
    }
    true
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while !s.is_empty() && (s[0] == b' ' || s[0] == b'\t' || s[0] == b'\r') {
        s = &s[1..];
    }
    while !s.is_empty() {
        let c = s[s.len() - 1];
        if c == b' ' || c == b'\t' || c == b'\r' {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

fn parse_decimal_u64(data: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in data {
        if b >= b'0' && b <= b'9' {
            val = val.wrapping_mul(10).wrapping_add((b - b'0') as u64);
        } else {
            break;
        }
    }
    val
}

fn parse_duration_ns(data: &[u8]) -> u64 {
    let v = trim_ascii(data);
    if v.is_empty() {
        return 0;
    }
    if bytes_eq_ci(v, b"infinity") {
        return 0;
    }

    let mut num_end = 0usize;
    while num_end < v.len() && v[num_end] >= b'0' && v[num_end] <= b'9' {
        num_end += 1;
    }
    if num_end == 0 {
        return 0;
    }

    let n = parse_decimal_u64(&v[..num_end]);
    let unit = trim_ascii(&v[num_end..]);
    let scale = if unit.is_empty()
        || bytes_eq_ci(unit, b"s")
        || bytes_eq_ci(unit, b"sec")
        || bytes_eq_ci(unit, b"secs")
        || bytes_eq_ci(unit, b"second")
        || bytes_eq_ci(unit, b"seconds")
    {
        1_000_000_000u64
    } else if bytes_eq_ci(unit, b"ms")
        || bytes_eq_ci(unit, b"msec")
        || bytes_eq_ci(unit, b"msecs")
    {
        1_000_000u64
    } else if bytes_eq_ci(unit, b"us")
        || bytes_eq_ci(unit, b"usec")
        || bytes_eq_ci(unit, b"usecs")
    {
        1_000u64
    } else if bytes_eq_ci(unit, b"m")
        || bytes_eq_ci(unit, b"min")
        || bytes_eq_ci(unit, b"mins")
        || bytes_eq_ci(unit, b"minute")
        || bytes_eq_ci(unit, b"minutes")
    {
        60 * 1_000_000_000u64
    } else if bytes_eq_ci(unit, b"h")
        || bytes_eq_ci(unit, b"hr")
        || bytes_eq_ci(unit, b"hrs")
        || bytes_eq_ci(unit, b"hour")
        || bytes_eq_ci(unit, b"hours")
    {
        60 * 60 * 1_000_000_000u64
    } else {
        1_000_000_000u64
    };

    n.saturating_mul(scale)
}

/// Look up startup profile values from a `.service` file in the initrd.
/// Returns `(memory_kb, timeout_start_ns)`; each value is 0 when unspecified.
unsafe fn lookup_service_profile(
    initrd: *const u8,
    initrd_size: usize,
    elf_name: &[u8],
    elf_name_len: usize,
) -> (u16, u64) {
    unsafe {
        // Convert "foo.elf" → "services/foo.service"
        let mut svc_path = [0u8; 64];
        let prefix = b"services/";
        let mut pos = 0usize;
        for &b in prefix { svc_path[pos] = b; pos += 1; }

        // Copy base name without .elf extension
        let base_len = if elf_name_len > 4 { elf_name_len - 4 } else { elf_name_len };
        for i in 0..base_len {
            if pos >= 60 { return (0, 0); }
            svc_path[pos] = elf_name[i];
            pos += 1;
        }
        let suffix = b".service";
        for &b in suffix { svc_path[pos] = b; pos += 1; }
        svc_path[pos] = 0;

        let mut entry = CpioEntry::zeroed();
        if salty::cpio::cpio_find_file(initrd, initrd_size, svc_path.as_ptr(), pos, &raw mut entry) == 0 {
            return (0, 0);
        }

        let data = core::slice::from_raw_parts(entry.data, entry.data_len);
        let mut memory_kb: u16 = 0;
        let mut timeout_start_ns: u64 = 0;

        let mut line_start = 0usize;
        while line_start < data.len() {
            let mut line_end = line_start;
            while line_end < data.len() && data[line_end] != b'\n' {
                line_end += 1;
            }
            let line = trim_ascii(&data[line_start..line_end]);

            if !line.is_empty() && line[0] != b'#' && line[0] != b';' {
                let mut eq = 0usize;
                let mut found_eq = false;
                while eq < line.len() {
                    if line[eq] == b'=' {
                        found_eq = true;
                        break;
                    }
                    eq += 1;
                }
                if found_eq {
                    let key = trim_ascii(&line[..eq]);
                    let value = trim_ascii(&line[eq + 1..]);
                    if bytes_eq_ci(key, b"MemoryKB") {
                        let parsed = parse_decimal_u64(value);
                        memory_kb = if parsed > u16::MAX as u64 { u16::MAX } else { parsed as u16 };
                    } else if bytes_eq_ci(key, b"TimeoutStartSec")
                        || bytes_eq_ci(key, b"TimeoutSec")
                    {
                        timeout_start_ns = parse_duration_ns(value);
                    }
                }
            }

            line_start = line_end + 1;
        }

        (memory_kb, timeout_start_ns)
    }
}

/// Convert MemoryKB to untyped size_bits: smallest power-of-2 >= kb*1024.
fn memory_kb_to_ut_bits(kb: u16) -> u8 {
    if kb == 0 { return CHILD_UT_BITS_DEFAULT; }
    let bytes = (kb as u32) * 1024;
    let mut bits: u8 = 12;
    while (1u32 << bits) < bytes && bits < 28 { bits += 1; }
    bits
}

fn compute_ready_timeout_ns(
    configured_timeout_ns: u64,
    is_dynamic: bool,
    elf_size_bytes: usize,
    lib_window_pages: usize,
    child_ut_bits: u8,
) -> u64 {
    if configured_timeout_ns != 0 {
        return configured_timeout_ns;
    }

    let mut timeout_ns = READY_TIMEOUT_NS_DEFAULT;
    if is_dynamic {
        timeout_ns = timeout_ns.saturating_add(3_000_000_000);
    }
    if child_ut_bits >= 18 {
        timeout_ns = timeout_ns.saturating_add(1_000_000_000);
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
unsafe fn compute_lib_window_pages(
    initrd: *const u8,
    initrd_size: usize,
) -> usize {
    unsafe {
        let mut offset: usize = 0;
        let mut max_data_end: usize = 0;

        loop {
            let mut entry = CpioEntry::zeroed();
            if salty::cpio::cpio_next(initrd, initrd_size, &raw mut offset, &raw mut entry) == 0 {
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
                    if end > max_data_end { max_data_end = end; }
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
        let has_inherited = try_inherit_shared_lib_cache(cache, initrd, initrd_size);
        if has_inherited {
            return;
        }

        // Fallback: build cache ourselves by parsing ELF and allocating frames
        let libs: [&[u8]; 2] = [b"libsalty.so", b"libc.so"];
        let mut cumulative_base: u64 = 0;

        for lib_name in &libs {
            let mut entry = CpioEntry::zeroed();
            if salty::cpio::cpio_find_file(
                initrd, initrd_size, lib_name.as_ptr(), lib_name.len(), &raw mut entry,
            ) == 0
            {
                continue;
            }

            if entry.data_len < core::mem::size_of::<Elf64Ehdr>() {
                continue;
            }
            let ehdr = &*(entry.data as *const Elf64Ehdr);
            if ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != b'E'
                || ehdr.e_ident[2] != b'L' || ehdr.e_ident[3] != b'F'
            {
                continue;
            }
            if ehdr.e_type != salty::ET_DYN {
                continue;
            }

            let phdrs = entry.data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;
            let mut min_vaddr: u64 = u64::MAX;
            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type == salty::PT_LOAD && ph.p_vaddr < min_vaddr {
                    min_vaddr = ph.p_vaddr;
                }
            }
            if min_vaddr == u64::MAX {
                continue;
            }

            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type != salty::PT_LOAD {
                    continue;
                }
                if (ph.p_flags & salty::PF_W) != 0 {
                    continue;
                }

                let seg_vaddr = ph.p_vaddr;
                let seg_start = seg_vaddr & !0xFFFu64;
                let seg_end = (seg_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;

                let mut flags = VSPACE_FLAG_USER;
                if (ph.p_flags & salty::PF_X) != 0 {
                    flags |= VSPACE_FLAG_EXECUTABLE;
                }

                let mut page = seg_start;
                while page < seg_end {
                    if cache.page_count >= MAX_SHARED_LIB_PAGES {
                        break;
                    }

                    let slot = match alloc.alloc_single_slot() {
                        Some(s) => s,
                        None => return,
                    };

                    let err = alloc.retype_any(OBJ_FRAME, 0, slot);
                    if err != 0 {
                        alloc.free_single_slot(slot);
                        // Partial cache is still usable
                        break;
                    }

                    let err = salty::invoke::vspace_map(
                        CAP_SELF_VSPACE, slot, PROCMGR_SCRATCH_VADDR,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    );
                    if err != 0 {
                        break;
                    }

                    let scratch = PROCMGR_SCRATCH_VADDR as *mut u8;
                    for j in 0..4096usize {
                        core::ptr::write_volatile(scratch.add(j), 0);
                    }

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
                            let dst = scratch.add(page_offset);
                            for j in 0..copy_len {
                                core::ptr::write_volatile(dst.add(j), *src.add(j));
                            }
                        }
                    }

                    salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

                    cache.pages[cache.page_count] = SharedPage {
                        vaddr_offset: cumulative_base + (page - min_vaddr),
                        frame_cap: slot,
                        flags,
                    };
                    cache.page_count += 1;
                    page += 4096;
                }
            }
            cumulative_base += 0x80000;
        }

        if cache.page_count > 0 {
            cache.initialized = true;
        }

        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] shared lib cache: ");
        lb.hex(cache.page_count as u64);
        lb.str(b" RO pages cached (self-allocated)\n");
        lb.flush();
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
) -> bool {
    unsafe {
        // Probe the first inherited slot to check if init passed us caps.
        // Use vspace_map as a probe — if the cap exists and is a frame,
        // this will succeed (we immediately unmap).
        let probe_slot = CAP_SHARED_LIB_CACHE_BASE;
        let probe_err = salty::invoke::vspace_map(
            CAP_SELF_VSPACE, probe_slot, PROCMGR_SCRATCH_VADDR,
            VSPACE_FLAG_USER,
        );
        if probe_err != 0 {
            return false;
        }
        salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

        puts(b"[PROCMGR] inherited shared lib caps from init\n");

        // Walk both libraries in the same order as init's cache builder.
        let libs: [&[u8]; 2] = [b"libsalty.so", b"libc.so"];
        let mut inherited_idx: usize = 0;
        let mut cumulative_base: u64 = 0;

        for lib_name in &libs {
            let mut entry = CpioEntry::zeroed();
            if salty::cpio::cpio_find_file(
                initrd, initrd_size, lib_name.as_ptr(), lib_name.len(), &raw mut entry,
            ) == 0
            {
                continue;
            }

            if entry.data_len < core::mem::size_of::<Elf64Ehdr>() {
                continue;
            }
            let ehdr = &*(entry.data as *const Elf64Ehdr);
            if ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != b'E'
                || ehdr.e_ident[2] != b'L' || ehdr.e_ident[3] != b'F'
            {
                continue;
            }
            if ehdr.e_type != salty::ET_DYN {
                continue;
            }

            let phdrs = entry.data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;
            let mut min_vaddr: u64 = u64::MAX;
            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type == salty::PT_LOAD && ph.p_vaddr < min_vaddr {
                    min_vaddr = ph.p_vaddr;
                }
            }
            if min_vaddr == u64::MAX {
                continue;
            }

            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type != salty::PT_LOAD || (ph.p_flags & salty::PF_W) != 0 {
                    continue;
                }

                let seg_vaddr = ph.p_vaddr;
                let seg_start = seg_vaddr & !0xFFFu64;
                let seg_end = (seg_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;

                let mut flags = VSPACE_FLAG_USER;
                if (ph.p_flags & salty::PF_X) != 0 {
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
                        vaddr_offset: cumulative_base + (page - min_vaddr),
                        frame_cap: cap_slot,
                        flags,
                    };
                    cache.page_count += 1;
                    inherited_idx += 1;
                    page += 4096;
                }
            }
            cumulative_base += 0x80000;
        }

        if cache.page_count > 0 {
            cache.initialized = true;
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] shared lib cache: ");
            lb.hex(cache.page_count as u64);
            lb.str(b" RO pages (inherited)\n");
            lb.flush();
            return true;
        }

        false
    }
}

/// Map cached shared library RO frames into a child VSpace.
/// Returns (lib_load_addr, ro_page_count) on success, (0, 0) on failure.
pub(crate) unsafe fn map_shared_lib_to_vspace(
    child_vs: Cap,
    rtld_base: u64,
) -> (u64, u64) {
    unsafe {
        let cache = &*(&raw const SHARED_LIB_CACHE);
        if !cache.initialized || cache.page_count == 0 {
            return (0, 0);
        }

        let lib_load_addr = rtld_base + 0x80000;

        for i in 0..cache.page_count {
            let page = &cache.pages[i];
            let vaddr = lib_load_addr + page.vaddr_offset;
            let err = salty::invoke::vspace_map(
                child_vs, page.frame_cap, vaddr, page.flags,
            );
            if err != 0 {
                // Rollback already-mapped pages
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] shared lib map failed at ");
                lb.hex(vaddr);
                lb.str(b" err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                for j in 0..i {
                    let prev_vaddr = lib_load_addr + cache.pages[j].vaddr_offset;
                    salty::invoke::vspace_unmap(child_vs, prev_vaddr);
                }
                return (0, 0);
            }
        }

        (lib_load_addr, cache.page_count as u64)
    }
}

// ===========================================================================
// Shared helpers: load_rtld and write_dynamic_stack
// ===========================================================================

unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    unsafe { while *s.add(len) != 0 { len += 1; } }
    len
}

/// Load the runtime dynamic linker and return its load result.
pub(crate) unsafe fn load_rtld(
    elf_data: *const u8,
    elf_data_len: usize,
    initrd: *const u8,
    initrd_size: usize,
    loader_ctx: &mut ElfLoaderCtx,
) -> Option<ElfLoadResult> {
    unsafe {
        let mut rtld_name = b"ld-salty.so".as_ptr();
        let mut rtld_name_len = 10usize;

        let interp = salty::elf_dynamic::elf_get_interp(elf_data, elf_data_len);
        if !interp.is_null() && *interp != 0 {
            let mut last = interp;
            let mut p = interp;
            while *p != 0 {
                if *p == b'/' { last = p.add(1); }
                p = p.add(1);
            }
            if *last != 0 {
                rtld_name = last;
                rtld_name_len = strlen(last);
            }
        }

        let mut rtld_entry = CpioEntry::zeroed();
        if salty::cpio::cpio_find_file(initrd, initrd_size, rtld_name, rtld_name_len, &raw mut rtld_entry) == 0 {
            puts(b"[PROCMGR] rtld not found in initrd\n");
            return None;
        }

        let mut rtld_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        let err = salty::elf_loader::elf_load(
            rtld_entry.data, rtld_entry.data_len,
            CHILD_RTLD_VADDR, loader_ctx, &raw mut rtld_result,
        );
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] rtld load failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
            return None;
        }
        Some(rtld_result)
    }
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
    elf_data: *const u8,
    elf_data_len: usize,
    stk_frame: Cap,
    elf_result: &ElfLoadResult,
    rtld_result: &ElfLoadResult,
    initrd_window_size: usize,
    shared_lib_base: u64,
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
) -> Result<u64, ()> {
    unsafe {
        let err = salty::invoke::vspace_map(
            CAP_SELF_VSPACE, stk_frame, PROCMGR_SCRATCH_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] dynamic stack scratch map failed\n");
            return Err(());
        }

        let mut phdr_vaddr: u64 = 0;
        let mut phent: u64 = 0;
        let mut phnum: u64 = 0;
        if salty::elf_dynamic::elf_get_phdr_info(
            elf_data, elf_data_len, CHILD_CODE_VADDR,
            &raw mut phdr_vaddr, &raw mut phent, &raw mut phnum,
        ) != 0 {
            puts(b"[PROCMGR] dynamic phdr info extraction failed\n");
            salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
            return Err(());
        }

        let auxv_entries: u64 = if shared_lib_base != 0 { 14 } else { 13 };

        // Build the stack using the helper, which handles argv/envp layout
        let rsp = write_stack_with_args(
            argc, envc, str_data, str_len,
            Some((auxv_entries, phdr_vaddr, phent, phnum,
                  elf_result.entry, rtld_result.base,
                  initrd_window_size as u64, shared_lib_base)),
        );

        salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
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
) -> Result<u64, ()> {
    unsafe {
        let err = salty::invoke::vspace_map(
            CAP_SELF_VSPACE, stk_frame, PROCMGR_SCRATCH_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] static stack scratch map failed\n");
            return Err(());
        }

        let rsp = write_stack_with_args(argc, envc, str_data, str_len, None);

        salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
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
///   - argc                <-- RSP
///
/// `auxv_info` is Some(...) for dynamic executables, None for static.
unsafe fn write_stack_with_args(
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    auxv_info: Option<(u64, u64, u64, u64, u64, u64, u64, u64)>,
) -> u64 {
    unsafe {
        let page_base = PROCMGR_SCRATCH_VADDR as *mut u8;
        // The child sees this page at the top of its stack
        let child_page_base = CHILD_STACK_TOP - 4096;

        // 1. Copy string data to the top of the page
        let str_area_start = 4096 - str_len;
        for i in 0..str_len {
            core::ptr::write_volatile(page_base.add(str_area_start + i), str_data[i]);
        }

        // 2. Build pointer arrays for argv and envp by scanning the string data
        // to find individual null-terminated strings.
        let mut argv_ptrs = [0u64; 64];
        let mut envp_ptrs = [0u64; 64];
        let mut arg_idx: u32 = 0;
        let mut env_idx: u32 = 0;
        let mut pos = 0usize;

        // Parse argv strings
        while arg_idx < argc && pos < str_len {
            let str_child_addr = child_page_base + str_area_start as u64 + pos as u64;
            argv_ptrs[arg_idx as usize] = str_child_addr;
            arg_idx += 1;
            // Skip to end of this null-terminated string
            while pos < str_len && str_data[pos] != 0 {
                pos += 1;
            }
            if pos < str_len {
                pos += 1; // skip null terminator
            }
        }

        // Parse envp strings
        while env_idx < envc && pos < str_len {
            let str_child_addr = child_page_base + str_area_start as u64 + pos as u64;
            envp_ptrs[env_idx as usize] = str_child_addr;
            env_idx += 1;
            while pos < str_len && str_data[pos] != 0 {
                pos += 1;
            }
            if pos < str_len {
                pos += 1;
            }
        }

        // 3. Calculate the metadata size (argc + argv ptrs + NULL + envp ptrs + NULL + auxv)
        let auxv_u64s: usize = match auxv_info {
            Some((entries, ..)) => entries as usize * 2, // entries includes AT_NULL
            None => 2, // AT_NULL entry only
        };
        let metadata_u64s = 1 // argc
            + arg_idx as usize + 1 // argv + NULL
            + env_idx as usize + 1 // envp + NULL
            + auxv_u64s;

        let metadata_bytes = metadata_u64s * 8;
        // Align down from str_area_start to make room for metadata, 16-byte aligned
        let metadata_end = str_area_start;
        let metadata_start = (metadata_end - metadata_bytes) & !0xF;

        let stack_u64 = (PROCMGR_SCRATCH_VADDR + metadata_start as u64) as *mut u64;
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
            Some((_, phdr, phent, phnum, entry, base, initrd_sz, shared_lib)) => {
                w(AT_PHDR);     w(phdr);
                w(AT_PHENT);    w(phent);
                w(AT_PHNUM);    w(phnum);
                w(AT_ENTRY);    w(entry);
                w(AT_BASE);     w(base);
                w(AT_PAGESZ);   w(4096);
                w(AT_SALTY_UNTYPED);    w(CHILD_CAP_UNTYPED);
                w(AT_SALTY_VSPACE);     w(CHILD_CAP_VSPACE);
                w(AT_SALTY_SCRATCH);    w(CHILD_SCRATCH_VADDR);
                w(AT_SALTY_INITRD);     w(CHILD_INITRD_VADDR);
                w(AT_SALTY_INITRD_SZ);  w(initrd_sz);
                w(AT_SALTY_FRAME_SLOT); w(CHILD_RTLD_FRAME_SLOT_START);
                if shared_lib != 0 {
                    w(AT_SALTY_SHARED_LIB_BASE); w(shared_lib);
                }
            }
            None => {}
        }
        w(AT_NULL); w(0);

        // RSP in child address space
        child_page_base + metadata_start as u64
    }
}

// ===========================================================================
// Transactional spawn
// ===========================================================================

/// Transactional spawn: preflight → reserve → realize → commit.
/// On any failure, rolls back all allocated objects and slots.
pub unsafe fn handle_spawn_tx(
    msg: &SaltyMsg,
    reply: &mut SaltyMsg,
    badge: u64,
    alloc: &mut Allocator,
) {
    unsafe {
        // Parse message
        let mut name_reg_idx = 1usize;
        let mut spawn_flags: u64 = 0;
        let mut requested_timeout_ns: u64 = 0;
        let packed_name_words = (msg.regs[0] + 7) / 8;
        if msg.length >= 3 + packed_name_words {
            spawn_flags = msg.regs[1];
            requested_timeout_ns = msg.regs[2];
            name_reg_idx = 3;
        } else if msg.length >= 2 + packed_name_words {
            // Backward-compatible path: flags present, no timeout field.
            spawn_flags = msg.regs[1];
            name_reg_idx = 2;
        }
        let wait_ready = (spawn_flags & PM_SPAWN_FLAG_WAIT_READY) != 0;
        let (name, name_len) = super::extract_name(msg, name_reg_idx);
        let is_display = super::bytes_eq(&name[..name_len], b"display.elf");

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] SPAWN: '");
            lb.bytes(&name[..name_len]);
            lb.str(b"'\n");
            lb.flush();
        }

        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::read_boot_info_initrd_size();

        // Find ELF in initrd
        let mut elf_entry = CpioEntry::zeroed();
        if salty::cpio::cpio_find_file(
            initrd, initrd_size, name.as_ptr(), name_len, &raw mut elf_entry,
        ) == 0
        {
            puts(b"[PROCMGR] ELF not found in initrd\n");
            reply.label = SALTY_NOT_FOUND;
            return;
        }

        let is_dynamic =
            salty::elf_dynamic::elf_has_interp(elf_entry.data, elf_entry.data_len);
        if is_dynamic {
            puts(b"[PROCMGR] ELF is dynamically linked\n");
        }

        // ---- PREFLIGHT: Build SpawnPlan ----
        let (service_kb, service_timeout_ns) =
            lookup_service_profile(initrd, initrd_size, &name, name_len);
        let child_ut_bits = memory_kb_to_ut_bits(service_kb);

        let lib_window_pages = if is_dynamic {
            compute_lib_window_pages(initrd, initrd_size)
        } else {
            0
        };

        let effective_timeout_ns = compute_ready_timeout_ns(
            if requested_timeout_ns != 0 {
                requested_timeout_ns
            } else {
                service_timeout_ns
            },
            is_dynamic,
            elf_entry.data_len,
            lib_window_pages,
            child_ut_bits,
        );

        let plan = SpawnPlan {
            is_dynamic,
            wait_ready,
            ready_timeout_ns: effective_timeout_ns,
            child_ut_bits,
            total_slots: estimate_slots(is_dynamic),
            is_display,
            lib_window_pages,
        };

        if service_kb > 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] service profile: MemoryKB=");
            lb.hex(service_kb as u64);
            lb.str(b" ut_bits=");
            lb.hex(plan.child_ut_bits as u64);
            lb.str(b"\n");
            lb.flush();
        }

        // Auto-register caller if unknown
        let caller_idx = proc_table::find_by_badge(badge);
        if caller_idx.is_none() && badge != 0 {
            if let Some(ci) = proc_table::alloc_proc() {
                proc_table::PROCTAB[ci].pid = badge as u32;
                proc_table::PROCTAB[ci].ppid = 0;
                proc_table::PROCTAB[ci].state = proc_table::PROC_RUNNING;
                proc_table::PROCTAB[ci].badge = badge;
            }
        }

        let Some(slot_idx) = proc_table::alloc_proc() else {
            puts(b"[PROCMGR] process table full\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        };

        let pid = proc_table::NEXT_PID;
        proc_table::NEXT_PID += 1;

        // ---- RESERVE ----
        if !alloc.reserve(plan.total_slots) {
            puts(b"[PROCMGR] slot reservation failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // ---- REALIZE fixed objects ----
        macro_rules! realize {
            ($ty:expr, $sz:expr, $off:expr, $what:expr) => {
                match alloc.realize_object_at($ty, $sz, $off) {
                    Ok(s) => s,
                    Err(e) => {
                        let mut lb = LineBuf::new();
                        lb.str(b"[PROCMGR] retype ");
                        lb.bytes($what);
                        lb.str(b" failed err=");
                        lb.hex(e as u64);
                        lb.str(b"\n");
                        lb.flush();
                        alloc.rollback();
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                }
            };
        }

        let child_tcb = realize!(OBJ_TCB, 0, OFF_TCB, b"TCB");
        let child_vs = realize!(OBJ_VSPACE, 0, OFF_VSPACE, b"VSpace");
        let child_cn = realize!(OBJ_CNODE, 0, OFF_CNODE, b"CNode");
        let child_sc = realize!(OBJ_SCHED_CONTEXT, 0, OFF_SC, b"SC");
        let child_stk_fr = realize!(OBJ_FRAME, 0, OFF_STACK_FR, b"stack frame");
        let child_ipc_fr = realize!(OBJ_FRAME, 0, OFF_IPC_FR, b"IPC frame");
        let child_sig_ntfn = realize!(OBJ_NOTIFICATION, 0, OFF_SIGNAL_NTFN, b"signal ntfn");

        // Sub-untyped for child — use profile-derived bits with downshift
        {
            let mut granted = false;
            let mut bits = plan.child_ut_bits;
            while bits >= CHILD_UT_BITS_MIN {
                match alloc.realize_object_at(OBJ_UNTYPED, bits as u64, OFF_CHILD_UT) {
                    Ok(_) => {
                        if bits != plan.child_ut_bits {
                            let mut lb = LineBuf::new();
                            lb.str(b"[PROCMGR] child untyped downshifted to 2^");
                            lb.hex(bits as u64);
                            lb.str(b"\n");
                            lb.flush();
                        }
                        granted = true;
                        break;
                    }
                    Err(_) => {
                        if bits == CHILD_UT_BITS_MIN {
                            break;
                        }
                        bits -= 1;
                    }
                }
            }
            if !granted {
                puts(b"[PROCMGR] child untyped unavailable\n");
                alloc.rollback();
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }
        let child_ut_slot = alloc.reservation_slot(OFF_CHILD_UT);

        let child_ready_ntfn;
        if plan.wait_ready {
            child_ready_ntfn = realize!(OBJ_NOTIFICATION, 0, OFF_READY_NTFN, b"ready ntfn");
        } else {
            child_ready_ntfn = 0;
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] Objects retyped for PID ");
            lb.hex(pid as u64);
            lb.str(b"\n");
            lb.flush();
        }

        // ---- REALIZE ELF pages ----
        let mut frame_alloc_ctx = FrameAllocCtx {
            alloc: alloc as *mut Allocator,
            error: 0,
        };

        let mut loader_ctx = ElfLoaderCtx {
            untyped: 0, // unused — alloc_frame_slot callback does retype
            self_vspace: CAP_SELF_VSPACE,
            child_vspace: child_vs,
            scratch_vaddr: PROCMGR_SCRATCH_VADDR,
            next_frame_slot: 0, // unused
            alloc_frame_slot: Some(spawn_alloc_frame),
            alloc_opaque: &raw mut frame_alloc_ctx as *mut u8,
            record_page: None,
            record_opaque: core::ptr::null_mut(),
        };

        let mut elf_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let err = salty::elf_loader::elf_load(
            elf_entry.data,
            elf_entry.data_len,
            CHILD_CODE_VADDR,
            &mut loader_ctx,
            &raw mut elf_result,
        );
        if err != 0 || frame_alloc_ctx.error != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] ELF load failed err=");
            lb.hex(if err != 0 {
                err as u64
            } else {
                frame_alloc_ctx.error as u64
            });
            lb.str(b"\n");
            lb.flush();
            alloc.rollback();
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] ELF loaded: entry=");
            lb.hex(elf_result.entry);
            lb.str(b"\n");
            lb.flush();
        }

        // ---- Load rtld if dynamic ----
        let mut rtld_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        if plan.is_dynamic {
            match load_rtld(
                elf_entry.data,
                elf_entry.data_len,
                initrd,
                initrd_size,
                &mut loader_ctx,
            ) {
                Some(r) => rtld_result = r,
                None => {
                    alloc.rollback();
                    reply.label = SALTY_NOT_FOUND;
                    return;
                }
            }
            if frame_alloc_ctx.error != 0 {
                alloc.rollback();
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // ---- Map stack pages ----
        for pg in 0..CHILD_STACK_PAGES {
            let page_vaddr = CHILD_STACK_VADDR + pg as u64 * 4096;
            let frame_slot;
            if pg == CHILD_STACK_PAGES - 1 {
                frame_slot = child_stk_fr;
            } else {
                match alloc.realize_object(OBJ_FRAME, 0) {
                    Ok(s) => frame_slot = s,
                    Err(_) => {
                        puts(b"[PROCMGR] stack frame retype failed\n");
                        alloc.rollback();
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                }
            }
            let err = salty::invoke::vspace_map(
                child_vs,
                frame_slot,
                page_vaddr,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] stack map failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                alloc.rollback();
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // ---- Map IPC buffer ----
        let err = salty::invoke::vspace_map(
            child_vs,
            child_ipc_fr,
            CHILD_IPC_BUF_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] IPC buf map failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // ---- Map initrd and boot info for dynamic executables ----
        // Use selective library window mapping
        if plan.is_dynamic {
            if map_initrd_to_child_tx(child_vs, initrd, initrd_size, alloc, plan.lib_window_pages) != 0 {
                alloc.rollback();
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
            if map_boot_info_to_child_tx(child_vs, alloc) != 0 {
                alloc.rollback();
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // ---- Provision child untyped into child CNode ----
        let cerr = salty::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            child_ut_slot,
            child_cn,
            CHILD_CAP_UNTYPED,
            CAP_RIGHTS_ALL,
        );
        if cerr != 0 {
            puts(b"[PROCMGR] copy child Untyped cap failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // ---- Copy caps into child CNode ----
        let err = copy_child_caps_tx(
            child_tcb,
            child_vs,
            child_cn,
            child_sig_ntfn,
            child_ready_ntfn,
            plan.wait_ready,
            plan.is_display,
            pid,
        );
        if err != 0 {
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // ---- Configure TCB ----
        let err = salty::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            puts(b"[PROCMGR] TCB set_space failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // ---- Map shared library RO frames if available ----
        let (shared_lib_base, _shared_lib_ro_pages) = if plan.is_dynamic {
            map_shared_lib_to_vspace(child_vs, rtld_result.base)
        } else {
            (0, 0)
        };

        let mut child_entry_rip = elf_result.entry;
        let mut child_rsp = CHILD_STACK_TOP;

        if plan.is_dynamic {
            // Pass library window size for AT_SALTY_INITRD_SZ
            let initrd_window_size = plan.lib_window_pages * 4096;
            match write_dynamic_stack(
                elf_entry.data,
                elf_entry.data_len,
                child_stk_fr,
                &elf_result,
                &rtld_result,
                initrd_window_size,
                shared_lib_base,
                0, 0, &[], 0,
            ) {
                Ok(rsp) => {
                    child_rsp = rsp;
                    child_entry_rip = rtld_result.entry;
                }
                Err(()) => {
                    alloc.rollback();
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        }

        let err =
            salty::invoke::tcb_configure(child_tcb, child_entry_rip, child_rsp, 0);
        if err != 0 {
            puts(b"[PROCMGR] TCB configure failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let err =
            salty::invoke::tcb_set_ipc_buffer(child_tcb, CHILD_IPC_BUF_VADDR);
        if err != 0 {
            puts(b"[PROCMGR] set child IPC buffer failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // ---- Schedule ----
        let err = salty::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 {
            puts(b"[PROCMGR] SC configure failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 {
            puts(b"[PROCMGR] SC bind failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // ---- Start ----
        let err = salty::invoke::tcb_resume(child_tcb);
        if err != 0 {
            puts(b"[PROCMGR] TCB resume failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        if plan.wait_ready {
            if super::wait_for_child_ready(
                child_tcb,
                child_ready_ntfn,
                &name[..name_len],
                plan.ready_timeout_ns,
            ) != 0
            {
                alloc.rollback();
                reply.label = SALTY_BUSY;
                return;
            }
        }

        // ---- COMMIT ----
        let (slot_base, slot_count) = alloc.commit();

        // Record in process table
        let caller_idx = proc_table::find_by_badge(badge);
        let p = &mut proc_table::PROCTAB[slot_idx];
        p.pid = pid;
        p.ppid = if let Some(ci) = caller_idx {
            proc_table::PROCTAB[ci].pid
        } else {
            0
        };
        p.state = proc_table::PROC_RUNNING;
        p.exit_code = 0;
        p.badge = pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.waiter_reply = 0;
        p.waiter_pid = 0;
        p.signal_ntfn = child_sig_ntfn;
        p.pgid = pid;
        p.slot_base = slot_base;
        p.slot_count = slot_count;
        p.shared_lib_base = shared_lib_base;
        for i in 0..proc_table::NSIG {
            p.sig_disposition[i] = proc_table::SIG_DISP_DFL;
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] Process started PID=");
            lb.hex(pid as u64);
            lb.str(b"\n");
            lb.flush();
        }
        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
    }
}

// ===========================================================================
// Helper: map initrd via device-map with selective library window
// ===========================================================================

unsafe fn map_initrd_to_child_tx(
    child_vs: Cap,
    _initrd: *const u8,
    initrd_size: usize,
    alloc: &mut Allocator,
    lib_window_pages: usize,
) -> i32 {
    unsafe {
        // Use library window if available, otherwise full initrd
        let map_pages = if lib_window_pages > 0 {
            lib_window_pages
        } else {
            (initrd_size + 4095) / 4096
        };

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] initrd mapping: ");
            lb.hex(map_pages as u64);
            lb.str(b" pages (lib window)\n");
            lb.flush();
        }

        let mut mapped_with_device = true;

        for pg in 0..map_pages {
            let err = salty::invoke::vspace_map_device(
                child_vs,
                CAP_INITRD_UNTYPED,
                (pg as u64) * 4096,
                CHILD_INITRD_VADDR + pg as u64 * 4096,
                VSPACE_FLAG_USER,
            );
            if err != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] initrd device map failed pg=");
                lb.hex(pg as u64);
                lb.str(b" err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                for mapped_pg in 0..pg {
                    salty::invoke::vspace_unmap(
                        child_vs,
                        CHILD_INITRD_VADDR + mapped_pg as u64 * 4096,
                    );
                }
                mapped_with_device = false;
                break;
            }
        }

        if mapped_with_device {
            return 0;
        }

        // Copy fallback: allocate frames from allocator
        let initrd = _initrd;
        let copy_size = map_pages * 4096;
        for pg in 0..map_pages {
            let fr_slot = match alloc.realize_object(OBJ_FRAME, 0) {
                Ok(s) => s,
                Err(_) => {
                    puts(b"[PROCMGR] initrd frame retype failed\n");
                    return -1;
                }
            };

            let err = salty::invoke::vspace_map(
                CAP_SELF_VSPACE,
                fr_slot,
                PROCMGR_SCRATCH_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[PROCMGR] initrd scratch map failed\n");
                return -1;
            }

            let scratch = PROCMGR_SCRATCH_VADDR as *mut u8;
            let src = initrd.add(pg * 4096);
            let mut copy_len = 4096usize;
            let byte_offset = pg * 4096;
            if byte_offset + copy_len > copy_size {
                copy_len = if copy_size > byte_offset { copy_size - byte_offset } else { 0 };
            }
            for i in 0..copy_len {
                core::ptr::write_volatile(scratch.add(i), *src.add(i));
            }
            for i in copy_len..4096 {
                core::ptr::write_volatile(scratch.add(i), 0);
            }

            salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

            let err = salty::invoke::vspace_map(
                child_vs,
                fr_slot,
                CHILD_INITRD_VADDR + pg as u64 * 4096,
                VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[PROCMGR] initrd child map failed\n");
                return -1;
            }
        }
        0
    }
}

/// Map boot info page into child VSpace.
unsafe fn map_boot_info_to_child_tx(child_vs: Cap, alloc: &mut Allocator) -> i32 {
    unsafe {
        let bi_fr = match alloc.realize_object(OBJ_FRAME, 0) {
            Ok(s) => s,
            Err(_) => {
                puts(b"[PROCMGR] bootinfo frame retype failed\n");
                return -1;
            }
        };

        let err = salty::invoke::vspace_map(
            CAP_SELF_VSPACE,
            bi_fr,
            PROCMGR_SCRATCH_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] bootinfo scratch map failed\n");
            return -1;
        }

        let bi_src = super::BOOTINFO_VADDR as *const u8;
        let scratch = PROCMGR_SCRATCH_VADDR as *mut u8;
        for i in 0..4096usize {
            core::ptr::write_volatile(
                scratch.add(i),
                core::ptr::read_volatile(bi_src.add(i)),
            );
        }

        salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

        let err = salty::invoke::vspace_map(
            child_vs,
            bi_fr,
            super::BOOTINFO_VADDR,
            VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] bootinfo child map failed\n");
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
    child_sig_ntfn: Cap,
    child_ready_ntfn: Cap,
    with_ready_ntfn: bool,
    with_fb_untyped: bool,
    pid: u32,
) -> i32 {
    let mut err;
    err = salty::invoke::cnode_copy(
        CAP_SELF_CSPACE, child_tcb, child_cn, CHILD_CAP_TCB, CAP_RIGHTS_ALL,
    );
    if err != 0 {
        puts(b"[PROCMGR] copy TCB cap failed\n");
        return err;
    }

    err = salty::invoke::cnode_copy(
        CAP_SELF_CSPACE, child_vs, child_cn, CHILD_CAP_VSPACE, CAP_RIGHTS_ALL,
    );
    if err != 0 {
        puts(b"[PROCMGR] copy VSpace cap failed\n");
        return err;
    }

    err = salty::invoke::cnode_copy(
        CAP_SELF_CSPACE, child_cn, child_cn, CHILD_CAP_CSPACE, CAP_RIGHTS_ALL,
    );
    if err != 0 {
        puts(b"[PROCMGR] copy CNode cap failed\n");
        return err;
    }

    err = salty::invoke::cnode_mint(
        CAP_SELF_CSPACE, CAP_SERVER_EP, child_cn, CHILD_CAP_EP, pid as u64,
    );
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] mint EP cap failed err=");
        lb.hex(err as u64);
        lb.str(b"\n");
        lb.flush();
        return err;
    }

    err = salty::invoke::cnode_mint(
        CAP_SELF_CSPACE, CAP_VFS_EP, child_cn, CHILD_CAP_VFS, pid as u64,
    );
    if err != 0 {
        puts(b"[PROCMGR] WARN: mint VFS EP failed, trying unbadged copy\n");
        err = salty::invoke::cnode_copy(
            CAP_SELF_CSPACE, CAP_VFS_EP, child_cn, CHILD_CAP_VFS, CAP_RIGHTS_ALL,
        );
        if err != 0 {
            puts(b"[PROCMGR] WARN: copy VFS EP cap failed\n");
        }
    }

    err = salty::invoke::cnode_copy(
        CAP_SELF_CSPACE, CAP_NAMESERV_EP, child_cn, CHILD_CAP_NAMESERV, CAP_RIGHTS_ALL,
    );
    if err != 0 {
        puts(b"[PROCMGR] WARN: copy Nameserv EP cap failed\n");
    }

    err = salty::invoke::cnode_copy(
        CAP_SELF_CSPACE, child_sig_ntfn, child_cn, CHILD_CAP_SIGNAL_NTFN, CAP_RIGHTS_ALL,
    );
    if err != 0 {
        puts(b"[PROCMGR] WARN: copy signal ntfn cap failed\n");
    }

    if with_ready_ntfn {
        err = salty::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            child_ready_ntfn,
            child_cn,
            CHILD_CAP_READINESS_NTFN,
            CAP_RIGHTS_ALL,
        );
        if err != 0 {
            puts(b"[PROCMGR] copy readiness ntfn cap failed\n");
            return err;
        }
    }

    if with_fb_untyped {
        err = salty::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            salty::CAP_FB_UNTYPED,
            child_cn,
            salty::CAP_FB_UNTYPED,
            CAP_RIGHTS_ALL,
        );
        if err != 0 {
            puts(b"[PROCMGR] WARN: copy framebuffer untyped cap failed\n");
        }
    }

    // Provide initrd device-untyped
    err = salty::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        CAP_INITRD_UNTYPED,
        child_cn,
        CAP_INITRD_UNTYPED,
        INITRD_COPY_RIGHTS,
    );
    if err != 0 {
        puts(b"[PROCMGR] WARN: copy initrd untyped cap failed\n");
    }

    // Mirror root untypeds
    for ut_slot in CAP_UNTYPED_START..(CAP_UNTYPED_START + UT_MIRROR_COUNT) {
        let _ = salty::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            ut_slot,
            child_cn,
            ut_slot,
            CAP_RIGHTS_ALL,
        );
    }

    0
}
