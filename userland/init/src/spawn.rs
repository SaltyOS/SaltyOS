//! Process spawning helpers
//! SPDX-License-Identifier: GPL-2.0-only

use salty::consts::*;
use salty::cpio;
use salty::elf_dynamic;
use salty::elf_loader;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::syscall;
use salty::types::*;

#[derive(Clone, Copy)]
pub struct ExtraCapCopy {
    pub src: Cap,
    pub dst: u64,
}

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

const INIT_UT_SCAN_END_FALLBACK: Cap = 200;
const CHILD_UT_BITS_MIN: u8 = 12;
const UT_MIRROR_COUNT: Cap = 8;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3); // READ|EXECUTE|GRANT
const READY_SIGNAL_BITS: u64 = 1;
const READY_TIMEOUT_NS: u64 = 10_000_000_000; // 10s default
const READY_WAIT_YIELDS_FALLBACK: usize = 200_000;
static mut NEXT_UT_HINT: Cap = CAP_UNTYPED_START;

// ===========================================================================
// Shared library physical frame cache
// ===========================================================================

const MAX_SHARED_LIB_PAGES: usize = 192;
const MAX_CACHED_LIBS: usize = 4;
const MAX_LIB_NAME: usize = 24;

/// Well-known CNode slot range where cached frame caps are copied into
/// procmgr's CSpace, enabling zero-allocation library sharing.
const CAP_SHARED_LIB_CACHE_BASE: u64 = 0x80;

#[derive(Clone, Copy)]
struct SharedPage {
    /// Offset relative to the library's own min_vaddr (NOT cumulative).
    vaddr_offset: u64,
    frame_cap: Cap,
    flags: u64,
}

#[derive(Clone, Copy)]
struct CachedLib {
    name: [u8; MAX_LIB_NAME],
    name_len: u8,
    page_start: u16,
    page_count: u16,
    /// Full VA span of the library (including RW segments), page-aligned.
    lib_span: u64,
}

impl CachedLib {
    const fn zeroed() -> Self {
        CachedLib {
            name: [0u8; MAX_LIB_NAME],
            name_len: 0,
            page_start: 0,
            page_count: 0,
            lib_span: 0,
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
            pages: [SharedPage { vaddr_offset: 0, frame_cap: 0, flags: 0 }; MAX_SHARED_LIB_PAGES],
        }
    }
}

static mut SHARED_LIB_CACHE: SharedLibCache = SharedLibCache::new();

// ===========================================================================
// Spawn memory budget
// ===========================================================================

#[derive(Clone, Copy)]
struct SpawnMemoryBudget {
    boot_load_bits: u8,
    runtime_bits: u8,
    runtime_mirror_slots: Cap,
}

fn clamp_ut_bits(bits: u8) -> u8 {
    let mut out = bits;
    if out < CHILD_UT_BITS_MIN {
        out = CHILD_UT_BITS_MIN;
    }
    if out > 28 {
        out = 28;
    }
    out
}

fn compute_spawn_memory_budget(is_dynamic: bool, requested_bits: u8) -> SpawnMemoryBudget {
    let runtime_bits = clamp_ut_bits(requested_bits);

    if !is_dynamic {
        return SpawnMemoryBudget {
            boot_load_bits: runtime_bits,
            runtime_bits,
            runtime_mirror_slots: 0,
        };
    }

    // Dynamic services get a bounded dedicated boot/load pool so main ELF load
    // does not over-reserve under lowmem. Runtime growth comes from mirrored
    // parent untyped caps as fallback.
    let mut boot_load_bits = runtime_bits;
    if boot_load_bits > 17 {
        boot_load_bits = 17;
    }
    if boot_load_bits < 15 {
        boot_load_bits = 15;
    }

    let runtime_mirror_slots = if runtime_bits >= 20 {
        8
    } else if runtime_bits >= 18 {
        8
    } else if runtime_bits >= 16 {
        6
    } else {
        5
    };

    SpawnMemoryBudget {
        boot_load_bits,
        runtime_bits,
        runtime_mirror_slots,
    }
}

fn compute_ready_timeout_ns(
    configured_timeout_ns: u64,
    is_dynamic: bool,
    elf_size_bytes: usize,
    map_initrd: bool,
    runtime_bits: u8,
) -> u64 {
    if configured_timeout_ns != 0 {
        return configured_timeout_ns;
    }

    let mut timeout_ns = READY_TIMEOUT_NS;
    if is_dynamic {
        timeout_ns = timeout_ns.saturating_add(3_000_000_000);
    }
    if map_initrd {
        timeout_ns = timeout_ns.saturating_add(1_000_000_000);
    }
    if runtime_bits >= 18 {
        timeout_ns = timeout_ns.saturating_add(1_000_000_000);
    }

    let elf_chunks = ((elf_size_bytes as u64).saturating_add(128 * 1024 - 1)) / (128 * 1024);
    let elf_bonus_ms = core::cmp::min(elf_chunks.saturating_mul(150), 4_000);
    timeout_ns.saturating_add(elf_bonus_ms.saturating_mul(1_000_000))
}

unsafe fn wait_for_child_ready(
    child_tcb: Cap,
    ready_ntfn: Cap,
    label: &[u8],
    timeout_ns: u64,
) -> i32 {
    let start_ns = {
        let now = syscall::syscall(SYS_CLOCK_GETTIME, 1, 0, 0, 0, 0, 0);
        if now.error == 0 { Some(now.value) } else { None }
    };
    let mut yields: usize = 0;

    loop {
        let poll = syscall::syscall(SYS_POLL, ready_ntfn, 0, 0, 0, 0, 0);
        if poll.error == 0 {
            if (poll.value & READY_SIGNAL_BITS) != 0 {
                return 0;
            }
        } else if poll.error != SALTY_WOULD_BLOCK {
            let mut lb = LineBuf::new();
            lb.str(b"[INIT] ready poll failed err=");
            lb.hex(poll.error);
            lb.str(b"\n");
            lb.flush();
            let _ = invoke::tcb_suspend(child_tcb);
            return -1;
        }

        let timed_out = if let Some(start) = start_ns {
            let now = syscall::syscall(SYS_CLOCK_GETTIME, 1, 0, 0, 0, 0, 0);
            if now.error == 0 {
                now.value.saturating_sub(start) >= timeout_ns
            } else {
                yields >= READY_WAIT_YIELDS_FALLBACK
            }
        } else {
            yields >= READY_WAIT_YIELDS_FALLBACK
        };
        if timed_out {
            break;
        }

        let _ = syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        yields += 1;
    }

    let mut lb = LineBuf::new();
    lb.str(b"[INIT] ");
    lb.bytes(label);
    lb.str(b" ready timeout\n");
    lb.flush();
    let _ = invoke::tcb_suspend(child_tcb);
    -1
}

unsafe fn init_untyped_scan_end() -> Cap {
    let mut end = INIT_UT_SCAN_END_FALLBACK;
    let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
    if info.error == 0 {
        let ctx = unsafe { &*super::ipc_ctx() };
        if !ctx.ipc_buffer.is_null() {
            let num_slots = unsafe { (*ctx.ipc_buffer).msg[3] };
            if num_slots > CAP_UNTYPED_START && num_slots < end {
                end = num_slots;
            }
        }
    }
    if end <= CAP_UNTYPED_START {
        CAP_UNTYPED_START + 1
    } else {
        end
    }
}

unsafe fn retype_from_any_untyped(new_type: u64, size_bits: u64, dest_slot: Cap) -> i32 {
    unsafe { retype_from_any_untyped_with_source(new_type, size_bits, dest_slot, core::ptr::null_mut()) }
}

unsafe fn retype_from_any_untyped_with_source(
    new_type: u64,
    size_bits: u64,
    dest_slot: Cap,
    src_ut_out: *mut Cap,
) -> i32 {
    let start = CAP_UNTYPED_START;
    let end = unsafe { init_untyped_scan_end() };

    let mut first = unsafe { NEXT_UT_HINT };
    if first < start || first >= end {
        first = start;
    }

    let mut best_err = SALTY_OUT_OF_MEMORY as i32;

    for ut in first..end {
        let err = invoke::untyped_retype(ut, new_type, size_bits, dest_slot);
        if err == 0 {
            unsafe { NEXT_UT_HINT = ut; }
            if !src_ut_out.is_null() {
                unsafe { *src_ut_out = ut; }
            }
            return 0;
        }
        if err != SALTY_INVALID_CAPABILITY as i32
            && err != SALTY_INVALID_OPERATION as i32
            && err != SALTY_NOT_FOUND as i32
        {
            best_err = err;
        }
    }
    for ut in start..first {
        let err = invoke::untyped_retype(ut, new_type, size_bits, dest_slot);
        if err == 0 {
            unsafe { NEXT_UT_HINT = ut; }
            if !src_ut_out.is_null() {
                unsafe { *src_ut_out = ut; }
            }
            return 0;
        }
        if err != SALTY_INVALID_CAPABILITY as i32
            && err != SALTY_INVALID_OPERATION as i32
            && err != SALTY_NOT_FOUND as i32
        {
            best_err = err;
        }
    }

    best_err
}

unsafe fn retype_from_any_untyped_excluding(
    new_type: u64,
    size_bits: u64,
    dest_slot: Cap,
    exclude_ut: Cap,
    src_ut_out: *mut Cap,
) -> i32 {
    let start = CAP_UNTYPED_START;
    let end = unsafe { init_untyped_scan_end() };

    let mut first = unsafe { NEXT_UT_HINT };
    if first < start || first >= end {
        first = start;
    }

    let mut best_err = SALTY_OUT_OF_MEMORY as i32;

    for ut in first..end {
        if ut == exclude_ut {
            continue;
        }
        let err = invoke::untyped_retype(ut, new_type, size_bits, dest_slot);
        if err == 0 {
            unsafe { NEXT_UT_HINT = ut; }
            if !src_ut_out.is_null() {
                unsafe { *src_ut_out = ut; }
            }
            return 0;
        }
        if err != SALTY_INVALID_CAPABILITY as i32
            && err != SALTY_INVALID_OPERATION as i32
            && err != SALTY_NOT_FOUND as i32
        {
            best_err = err;
        }
    }
    for ut in start..first {
        if ut == exclude_ut {
            continue;
        }
        let err = invoke::untyped_retype(ut, new_type, size_bits, dest_slot);
        if err == 0 {
            unsafe { NEXT_UT_HINT = ut; }
            if !src_ut_out.is_null() {
                unsafe { *src_ut_out = ut; }
            }
            return 0;
        }
        if err != SALTY_INVALID_CAPABILITY as i32
            && err != SALTY_INVALID_OPERATION as i32
            && err != SALTY_NOT_FOUND as i32
        {
            best_err = err;
        }
    }

    best_err
}

unsafe fn allocate_child_untyped_budget(
    dest_slot: Cap,
    preferred_bits: u8,
    exclude_ut: Cap,
    src_ut_out: *mut Cap,
) -> Result<u8, i32> {
    let mut bits = clamp_ut_bits(preferred_bits);
    let mut last_err = SALTY_OUT_OF_MEMORY as i32;

    while bits >= CHILD_UT_BITS_MIN {
        let mut err = unsafe {
            retype_from_any_untyped_excluding(
                OBJ_UNTYPED,
                bits as u64,
                dest_slot,
                exclude_ut,
                src_ut_out,
            )
        };
        if err != 0 {
            err = unsafe {
                retype_from_any_untyped_with_source(
                    OBJ_UNTYPED,
                    bits as u64,
                    dest_slot,
                    src_ut_out,
                )
            };
        }
        if err == 0 {
            return Ok(bits);
        }
        last_err = err;
        if bits == CHILD_UT_BITS_MIN {
            break;
        }
        bits -= 1;
    }

    Err(last_err)
}

// ===========================================================================
// Shared library cache: init + map
// ===========================================================================

/// Pre-load shared library RO segments into permanent frame caps.
/// Called once at init startup. Processes both libsalty.so and libc.so.
/// On failure, cache stays uninitialized and all spawns fall through
/// to per-process RTLD allocation.
pub unsafe fn init_shared_lib_cache(root_ut: Cap) {
    unsafe {
        let cache = &mut *(&raw mut SHARED_LIB_CACHE);
        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::INITRD_SIZE;

        let libs: [&[u8]; 2] = [b"libsalty.so", b"libc.so"];

        for lib_name in &libs {
            if cache.lib_count >= MAX_CACHED_LIBS {
                break;
            }

            let mut entry = CpioEntry::zeroed();
            if salty::cpio::cpio_find_file(
                initrd, initrd_size, lib_name.as_ptr(), lib_name.len(), &raw mut entry,
            ) == 0
            {
                let mut lb = LineBuf::new();
                lb.str(b"[INIT] shared lib cache: ");
                lb.bytes(lib_name);
                lb.str(b" not found, skipping\n");
                lb.flush();
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

            // Find min_vaddr and max_seg_end across PT_LOAD segments
            let phdrs = entry.data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;
            let mut min_vaddr: u64 = u64::MAX;
            let mut max_seg_end: u64 = 0;
            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type == salty::PT_LOAD {
                    if ph.p_vaddr < min_vaddr { min_vaddr = ph.p_vaddr; }
                    let se = (ph.p_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;
                    if se > max_seg_end { max_seg_end = se; }
                }
            }
            if min_vaddr == u64::MAX {
                continue;
            }
            let lib_span = max_seg_end - (min_vaddr & !0xFFFu64);

            // Start a new CachedLib entry
            let li = cache.lib_count;
            let page_start = cache.page_count as u16;
            let mut lib_entry = CachedLib::zeroed();
            let copy_len = if lib_name.len() > MAX_LIB_NAME { MAX_LIB_NAME } else { lib_name.len() };
            for j in 0..copy_len {
                lib_entry.name[j] = lib_name[j];
            }
            lib_entry.name_len = copy_len as u8;
            lib_entry.lib_span = lib_span;

            // Cache each page of each read-only PT_LOAD segment
            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type != salty::PT_LOAD {
                    continue;
                }
                // Skip writable segments — those are per-process
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
                        puts(b"[INIT] shared lib cache: too many pages\n");
                        break;
                    }

                    // Allocate a permanent frame cap slot
                    let frame_slot = super::init_alloc_frame_slot(core::ptr::null_mut());

                    // Retype frame from any available untyped
                    let mut err = invoke::untyped_retype(root_ut, OBJ_FRAME, 0, frame_slot);
                    if err != 0 {
                        err = retype_from_any_untyped(OBJ_FRAME, 0, frame_slot);
                    }
                    if err != 0 {
                        let mut lb = LineBuf::new();
                        lb.str(b"[INIT] shared lib cache: frame retype failed err=");
                        lb.hex(err as u64);
                        lb.str(b"\n");
                        lb.flush();
                        break;
                    }

                    // Scratch-map to fill frame contents
                    let err = invoke::vspace_map(
                        CAP_SELF_VSPACE, frame_slot, SCRATCH_VADDR,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    );
                    if err != 0 {
                        puts(b"[INIT] shared lib cache: scratch map failed\n");
                        break;
                    }

                    // Zero the page
                    let scratch = SCRATCH_VADDR as *mut u8;
                    for j in 0..4096usize {
                        core::ptr::write_volatile(scratch.add(j), 0);
                    }

                    // Copy file data for this page
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

                    // Unmap scratch
                    invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

                    // Store in cache with offset relative to library's own min_vaddr.
                    cache.pages[cache.page_count] = SharedPage {
                        vaddr_offset: page - min_vaddr,
                        frame_cap: frame_slot,
                        flags,
                    };
                    cache.page_count += 1;
                    page += 4096;
                }
            }

            // Finalize CachedLib entry
            lib_entry.page_start = page_start;
            lib_entry.page_count = (cache.page_count as u16) - page_start;
            cache.libs[li] = lib_entry;
            cache.lib_count += 1;
        }

        if cache.page_count > 0 {
            cache.initialized = true;
            let mut lb = LineBuf::new();
            lb.str(b"[INIT] shared lib cache: ");
            lb.hex(cache.page_count as u64);
            lb.str(b" RO pages cached\n");
            lb.flush();
        }
    }
}

/// Map cached shared library RO frames into a child VSpace, mapping only
/// libraries listed in `needed` in their DT_NEEDED order.
/// `shared_lib_base_vaddr` is the layout-computed VA where libs start.
/// Returns the shared_lib_base address on success, 0 on failure.
unsafe fn map_shared_lib_to_child(
    child_vs: Cap,
    _child_cn: Cap,
    shared_lib_base_vaddr: u64,
    needed: &salty::elf_dynamic::NeededLibs,
) -> u64 {
    unsafe {
        let cache = &*(&raw const SHARED_LIB_CACHE);
        if !cache.initialized || cache.page_count == 0 || shared_lib_base_vaddr == 0 {
            return 0;
        }
        if needed.count == 0 {
            return 0;
        }

        let mut running_base = shared_lib_base_vaddr;
        let mut total_mapped = 0usize;

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

                // Map this library's RO pages at running_base
                let ps = cl.page_start as usize;
                let pc = cl.page_count as usize;
                for pi in 0..pc {
                    let page = &cache.pages[ps + pi];
                    let vaddr = running_base + page.vaddr_offset;
                    let err = invoke::vspace_map(child_vs, page.frame_cap, vaddr, page.flags);
                    if err != 0 {
                        let mut lb = LineBuf::new();
                        lb.str(b"[INIT] shared lib map failed at ");
                        lb.hex(vaddr);
                        lb.str(b" err=");
                        lb.hex(err as u64);
                        lb.str(b"\n");
                        lb.flush();
                        return 0;
                    }
                    total_mapped += 1;
                }

                running_base += cl.lib_span + 4096; // advance past this lib + gap
                found = true;
                break;
            }

            if !found {
                // Library not in cache — RTLD will load it from initrd
                let mut lb = LineBuf::new();
                lb.str(b"[INIT] shared lib cache miss: ");
                lb.bytes(name);
                lb.str(b"\n");
                lb.flush();
            }
        }

        if total_mapped > 0 {
            shared_lib_base_vaddr
        } else {
            0
        }
    }
}

/// Return the total VA pages needed for the specified DT_NEEDED libraries.
/// This accounts for full library spans (including RW segments) plus inter-lib gaps.
pub fn shared_lib_va_pages_for_needed(needed: &salty::elf_dynamic::NeededLibs) -> usize {
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
                        if cl_name[k] != name[k] { eq = false; break; }
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

/// Copy all cached shared library frame caps into a child CNode
/// at slots CAP_SHARED_LIB_CACHE_BASE..CAP_SHARED_LIB_CACHE_BASE+count.
unsafe fn copy_shared_lib_caps_to_child(child_cn: Cap) {
    unsafe {
        let cache = &*(&raw const SHARED_LIB_CACHE);
        if !cache.initialized || cache.page_count == 0 {
            return;
        }

        for i in 0..cache.page_count {
            let dst_slot = CAP_SHARED_LIB_CACHE_BASE + i as u64;
            let _ = invoke::cnode_copy(
                CAP_SELF_CSPACE,
                cache.pages[i].frame_cap,
                child_cn,
                dst_slot,
                CAP_RIGHTS_ALL,
            );
        }
    }
}

// ===========================================================================
// Spawn server
// ===========================================================================

pub unsafe fn spawn_server(
    root_ut: Cap,
    cap_base: Cap,
    elf_name: &[u8],
    label: &[u8],
    extras: &[ExtraCapCopy],
    map_initrd: bool,
    cnode_size_bits: u64,
    child_ut_bits: u8,
    copy_shared_lib_caps: bool,
    ready_timeout_ns: u64,
    pre_ep: Cap,
    procmgr_ep: Cap,
    spawn_badge: u64,
) -> i32 {
    { let mut lb = LineBuf::new(); lb.str(b"[INIT] Spawning "); lb.bytes(label); lb.str(b" ("); lb.bytes(elf_name); lb.str(b")\n"); lb.flush(); }

    unsafe {
        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::INITRD_SIZE;

        let mut entry = CpioEntry::zeroed();
        let mut found = cpio::cpio_find_file(
            initrd, initrd_size, elf_name.as_ptr(), elf_name.len(), &raw mut entry,
        ) != 0;
        if !found && elf_name.len() + 4 <= 96 {
            let mut legacy = [0u8; 96];
            for i in 0..elf_name.len() {
                legacy[i] = elf_name[i];
            }
            legacy[elf_name.len()] = b'.';
            legacy[elf_name.len() + 1] = b'e';
            legacy[elf_name.len() + 2] = b'l';
            legacy[elf_name.len() + 3] = b'f';
            found = cpio::cpio_find_file(
                initrd,
                initrd_size,
                legacy.as_ptr(),
                elf_name.len() + 4,
                &raw mut entry,
            ) != 0;
        }
        if !found {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] "); lb.bytes(elf_name); lb.str(b" not found in initrd\n"); lb.flush(); }
            return -1;
        }

        let is_dynamic = elf_dynamic::elf_has_interp(entry.data, entry.data_len);

        // Pre-compute ELF and RTLD spans for layout computation
        let elf_span = elf_loader::elf_compute_load_span(entry.data, entry.data_len);
        let mut rtld_entry = CpioEntry::zeroed();
        let rtld_span = if is_dynamic {
            let rtld_name = b"ld-salty.so";
            if cpio::cpio_find_file(initrd, initrd_size, rtld_name.as_ptr(), rtld_name.len(), &raw mut rtld_entry) == 0 {
                puts(b"[INIT] rtld not found in initrd\n");
                return -1;
            }
            elf_loader::elf_compute_load_span(rtld_entry.data, rtld_entry.data_len)
        } else {
            0
        };

        // Parse DT_NEEDED to determine which shared libs this ELF needs
        let needed = if is_dynamic {
            elf_dynamic::elf_get_needed(entry.data, entry.data_len)
        } else {
            salty::elf_dynamic::NeededLibs::new()
        };

        let shared_lib_pages = shared_lib_va_pages_for_needed(&needed);
        let layout = salty::layout::compute_vm_layout(
            elf_span,
            rtld_span,
            shared_lib_pages,
            map_initrd || is_dynamic,
            initrd_size,
        );
        if layout.stack_top == 0 {
            puts(b"[INIT] ELF too large for VA layout\n");
            return -1;
        }

        let budget = compute_spawn_memory_budget(is_dynamic, child_ut_bits);
        let effective_ready_timeout_ns = compute_ready_timeout_ns(
            ready_timeout_ns,
            is_dynamic,
            entry.data_len,
            map_initrd,
            budget.runtime_bits,
        );

        let child_tcb = cap_base + super::COFF_TCB;
        let child_vs = cap_base + super::COFF_VSPACE;
        let child_cn = cap_base + super::COFF_CNODE;
        let child_sc = cap_base + super::COFF_SC;
        let child_stk_fr = cap_base + super::COFF_STACK_FR;
        let child_ipc_fr = cap_base + super::COFF_IPC_FR;
        let child_ep = cap_base + super::COFF_EP;
        let child_ready_ntfn = cap_base + super::COFF_READY_NTFN;
        let sub_ut_slot = cap_base + super::CAP_CHILD_UNTYPED_OFFSET;
        let mut sub_ut_parent: Cap = CAP_UNTYPED_START;
        // Allocate spawn-time objects from the init/root untyped pool.
        // Reserve a dedicated boot/load untyped from a bounded budget, while
        // runtime growth is supplied by mirrored untyped fallbacks.
        let loader_ut = root_ut;

        // Large CNodes (e.g. procmgr) must be created before small-object churn,
        // otherwise monotonic untyped allocation can make the large retype fail.
        // Prefer parent/root untyped for this so the child's dedicated untyped
        // remains mostly available for runtime allocations.
        if cnode_size_bits > 0 {
            let mut err = retype_from_any_untyped(OBJ_CNODE, cnode_size_bits, child_cn);
            if err != 0 {
                err = invoke::untyped_retype(loader_ut, OBJ_CNODE, cnode_size_bits, child_cn);
            }
            if err != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[INIT] retype CNode (large) failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                return -1;
            }
        }

        macro_rules! retype {
            ($obj:expr, $slot:expr, $name:expr) => {
                let mut err = invoke::untyped_retype(loader_ut, $obj, 0, $slot);
                if err != 0 {
                    err = retype_from_any_untyped($obj, 0, $slot);
                }
                if err != 0 {
                    let mut lb = LineBuf::new();
                    lb.str(b"[INIT] retype ");
                    lb.bytes($name);
                    lb.str(b" failed err=");
                    lb.hex(err as u64);
                    lb.str(b"\n");
                    lb.flush();
                    return -1;
                }
            };
        }

        retype!(OBJ_TCB, child_tcb, b"TCB");
        retype!(OBJ_VSPACE, child_vs, b"VSpace");
        if cnode_size_bits == 0 {
            retype!(OBJ_CNODE, child_cn, b"CNode");
        }
        retype!(OBJ_SCHED_CONTEXT, child_sc, b"SC");
        retype!(OBJ_FRAME, child_stk_fr, b"stack frame");
        retype!(OBJ_FRAME, child_ipc_fr, b"IPC frame");
        if pre_ep != 0 {
            let err = invoke::cnode_copy(
                super::CAP_SELF_CSPACE, pre_ep,
                super::CAP_SELF_CSPACE, child_ep,
                CAP_RIGHTS_ALL,
            );
            if err != 0 {
                puts(b"[INIT] copy pre-EP failed\n");
                return -1;
            }
        } else {
            retype!(OBJ_ENDPOINT, child_ep, b"EP");
        }
        retype!(OBJ_NOTIFICATION, child_ready_ntfn, b"ready ntfn");

        let granted_bits = match allocate_child_untyped_budget(
            sub_ut_slot,
            budget.boot_load_bits,
            loader_ut,
            &raw mut sub_ut_parent,
        ) {
            Ok(bits) => bits,
            Err(err) => {
                let mut lb = LineBuf::new();
                lb.str(b"[INIT] sub-untyped retype failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                return -1;
            }
        };
        if granted_bits != budget.boot_load_bits {
            let mut lb = LineBuf::new();
            lb.str(b"[INIT] sub-untyped downshifted to 2^");
            lb.hex(granted_bits as u64);
            lb.str(b"\n");
            lb.flush();
        }

        let mut loader_ctx = ElfLoaderCtx {
            untyped: sub_ut_slot,
            self_vspace: CAP_SELF_VSPACE,
            child_vspace: child_vs,
            scratch_vaddr: SCRATCH_VADDR,
            next_frame_slot: cap_base + super::COFF_FRAME_START,
            alloc_frame_slot: Some(super::init_alloc_frame_slot),
            alloc_opaque: core::ptr::null_mut(),
            record_page: None,
            record_opaque: core::ptr::null_mut(),
        };

        let mut elf_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        let err = elf_loader::elf_load(
            entry.data,
            entry.data_len,
            layout.elf_code.base,
            &mut loader_ctx,
            &raw mut elf_result,
        );
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] ELF load failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            return -1;
        }


        let mut rtld_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };

        if is_dynamic {
            let err = elf_loader::elf_load(
                rtld_entry.data,
                rtld_entry.data_len,
                layout.rtld.base,
                &mut loader_ctx,
                &raw mut rtld_result,
            );
            if err != 0 {
                puts(b"[INIT] rtld ELF load failed\n");
                return -1;
            }

        }

        // Map stack pages
        let stack_pages = layout.stack.page_count();
        for pg in 0..stack_pages {
            let page_vaddr = layout.stack.base + pg as u64 * 4096;
            let frame_slot;

            if pg == stack_pages - 1 {
                frame_slot = child_stk_fr;
            } else {
                frame_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
                let mut err = invoke::untyped_retype(loader_ut, OBJ_FRAME, 0, frame_slot);
                if err != 0 {
                    err = retype_from_any_untyped(OBJ_FRAME, 0, frame_slot);
                }
                if err != 0 {
                    puts(b"[INIT] stack frame retype failed\n");
                    return -1;
                }
            }

            let err = invoke::vspace_map(
                child_vs,
                frame_slot,
                page_vaddr,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[INIT] stack map failed\n");
                return -1;
            }
        }

        // Map IPC buffer
        let err = invoke::vspace_map(
            child_vs,
            child_ipc_fr,
            layout.ipc_buf.base,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[INIT] IPC buf map failed\n");
            return -1;
        }

        // Map initrd if needed
        if map_initrd || is_dynamic {
            let initrd_pages = (initrd_size + 4095) / 4096;
            let mut mapped_with_device = true;

            for pg in 0..initrd_pages {
                let err = invoke::vspace_map_device(
                    child_vs,
                    CAP_INITRD_UNTYPED,
                    (pg as u64) * 4096,
                    layout.initrd.base + pg as u64 * 4096,
                    VSPACE_FLAG_USER,
                );
                if err != 0 {
                    let mut lb = LineBuf::new();
                    lb.str(b"[INIT] initrd device map failed pg=");
                    lb.hex(pg as u64);
                    lb.str(b" err=");
                    lb.hex(err as u64);
                    lb.str(b"\n");
                    lb.flush();
                    for mapped_pg in 0..pg {
                        invoke::vspace_unmap(
                            child_vs,
                            layout.initrd.base + mapped_pg as u64 * 4096,
                        );
                    }
                    mapped_with_device = false;
                    break;
                }
            }

            if !mapped_with_device {
                for pg in 0..initrd_pages {
                    let fr_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
                    let mut err = invoke::untyped_retype(loader_ut, OBJ_FRAME, 0, fr_slot);
                    if err != 0 {
                        err = retype_from_any_untyped(OBJ_FRAME, 0, fr_slot);
                    }
                    if err != 0 {
                        puts(b"[INIT] initrd frame retype failed\n");
                        return -1;
                    }

                    let err = invoke::vspace_map(
                        CAP_SELF_VSPACE,
                        fr_slot,
                        SCRATCH_VADDR,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    );
                    if err != 0 {
                        puts(b"[INIT] initrd scratch map failed\n");
                        return -1;
                    }

                    let scratch = SCRATCH_VADDR as *mut u8;
                    let isrc = initrd.add(pg * 4096);
                    let mut copy_len = 4096;
                    if pg * 4096 + copy_len > initrd_size {
                        copy_len = initrd_size - pg * 4096;
                    }
                    for i in 0..copy_len {
                        core::ptr::write_volatile(scratch.add(i), *isrc.add(i));
                    }
                    for i in copy_len..4096 {
                        core::ptr::write_volatile(scratch.add(i), 0);
                    }

                    invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

                    let err = invoke::vspace_map(
                        child_vs,
                        fr_slot,
                        layout.initrd.base + pg as u64 * 4096,
                        VSPACE_FLAG_USER,
                    );
                    if err != 0 {
                        puts(b"[INIT] initrd child map failed\n");
                        return -1;
                    }
                }
            }
            // Map init's persistent bootinfo snapshot page into child.
            let err = invoke::vspace_map(
                child_vs,
                super::CAP_BOOTINFO_SNAPSHOT_FRAME,
                BOOTINFO_VADDR,
                VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[INIT] bootinfo child map failed\n");
                return -1;
            }
        }

        // Copy standard caps
        macro_rules! copy_cap {
            ($src:expr, $dst:expr) => {
                invoke::cnode_copy(CAP_SELF_CSPACE, $src, child_cn, $dst, CAP_RIGHTS_ALL)
            };
        }

        if copy_cap!(child_tcb, 0) != 0 { puts(b"[INIT] copy TCB failed\n"); return -1; }
        if copy_cap!(child_vs, 1) != 0 { puts(b"[INIT] copy VSpace failed\n"); return -1; }
        if copy_cap!(child_cn, 2) != 0 { puts(b"[INIT] copy CNode failed\n"); return -1; }
        if copy_cap!(child_ep, 3) != 0 { puts(b"[INIT] copy EP failed\n"); return -1; }
        if copy_cap!(child_ready_ntfn, CAP_READINESS_NTFN) != 0 {
            puts(b"[INIT] copy ready ntfn failed\n");
            return -1;
        }
        if is_dynamic {
            let derr = invoke::cnode_copy(
                CAP_SELF_CSPACE,
                CAP_INITRD_UNTYPED,
                child_cn,
                CAP_INITRD_UNTYPED,
                INITRD_COPY_RIGHTS,
            );
            if derr != 0 {
                puts(b"[INIT] WARN: copy initrd untyped failed\n");
            }
        }

        let err = copy_cap!(sub_ut_slot, 7);
        if err != 0 {
            puts(b"[INIT] copy child Untyped failed\n");
            return -1;
        }

        if is_dynamic {
            // Mirror a few parent root-untyped caps into the child so rtld can
            // fall back when the dedicated child untyped is exhausted.
            let mirror_slots = if budget.runtime_mirror_slots > UT_MIRROR_COUNT {
                UT_MIRROR_COUNT
            } else {
                budget.runtime_mirror_slots
            };
            let mirror_end = CAP_UNTYPED_START + mirror_slots;
            let mut mirrored: u64 = 0;
            for ut_slot in CAP_UNTYPED_START..mirror_end {
                if ut_slot == CAP_INITRD_UNTYPED {
                    continue;
                }
                let cerr = invoke::cnode_copy(
                    CAP_SELF_CSPACE,
                    ut_slot,
                    child_cn,
                    ut_slot,
                    CAP_RIGHTS_ALL,
                );
                if cerr == 0 {
                    mirrored += 1;
                }
            }
            if mirrored == 0 {
                puts(b"[INIT] WARN: no untyped mirrors copied for rtld fallback\n");
            } else if mirrored < mirror_slots {
                let mut lb = LineBuf::new();
                lb.str(b"[INIT] rtld untyped mirrors copied=");
                lb.hex(mirrored);
                lb.str(b"\n");
                lb.flush();
            }
        }

        for extra in extras {
            if extra.src == 0 && extra.dst == 0 {
                continue;
            }
            if is_dynamic && extra.dst == CAP_INITRD_UNTYPED {
                continue;
            }
            let err = copy_cap!(extra.src, extra.dst);
            if err != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[INIT] ERROR: cap copy failed src=");
                lb.hex(extra.src);
                lb.str(b" dst=");
                lb.hex(extra.dst);
                lb.str(b" err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                return -1;
            }
        }

        // Auto-mint badged procmgr EP at child slot CAP_EXPAND_EP (9)
        if procmgr_ep != 0 {
            let err = invoke::cnode_mint(
                CAP_SELF_CSPACE, procmgr_ep,
                child_cn, super::CAP_EXPAND_EP,
                spawn_badge,
            );
            if err != 0 {
                puts(b"[INIT] WARN: mint expand EP failed\n");
            }
        }

        if copy_shared_lib_caps {
            copy_shared_lib_caps_to_child(child_cn);
        }

        // Configure TCB
        let err = invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 { puts(b"[INIT] TCB set_space failed\n"); return -1; }

        // Map shared library RO frames into child VSpace
        // Shared libs start after RTLD's actual extent + 1-page gap
        let shared_lib_base = if is_dynamic && layout.shared_libs.size > 0 {
            map_shared_lib_to_child(child_vs, child_cn, layout.shared_libs.base, &needed)
        } else {
            0
        };

        let mut child_entry = elf_result.entry;
        let mut child_rsp = layout.stack_top;

        if is_dynamic {
            let err = invoke::vspace_map(
                CAP_SELF_VSPACE,
                child_stk_fr,
                SCRATCH_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[INIT] dynamic stack scratch map failed\n");
                return -1;
            }

            let mut phdr_vaddr: u64 = 0;
            let mut phent: u64 = 0;
            let mut phnum: u64 = 0;
            if elf_dynamic::elf_get_phdr_info(
                entry.data,
                entry.data_len,
                layout.elf_code.base,
                &raw mut phdr_vaddr,
                &raw mut phent,
                &raw mut phnum,
            ) != 0 {
                puts(b"[INIT] dynamic phdr info extraction failed\n");
                invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);
                return -1;
            }

            // +2 for AT_SALTY_SLOT_BASE/COUNT, +1 for AT_SALTY_EXPAND_EP if procmgr available
            let has_expand_ep = procmgr_ep != 0;
            let base_count: u64 = if shared_lib_base != 0 { 16 } else { 15 };
            let auxv_count: u64 = if has_expand_ep { base_count + 1 } else { base_count };
            let srv_stack_frame_size: u64 = 3 * 8 + auxv_count * 2 * 8 + 8;
            let stack_base = (SCRATCH_VADDR + 4096 - srv_stack_frame_size) as *mut u64;

            let mut idx: usize = 0;
            macro_rules! w {
                ($v:expr) => {
                    core::ptr::write_volatile(stack_base.add(idx), $v);
                    idx += 1;
                };
            }
            w!(0); // argc
            w!(0); // argv terminator
            w!(0); // envp terminator

            w!(super::AT_PHDR); w!(phdr_vaddr);
            w!(super::AT_PHENT); w!(phent);
            w!(super::AT_PHNUM); w!(phnum);
            w!(super::AT_ENTRY); w!(elf_result.entry);
            w!(super::AT_BASE); w!(rtld_result.base);
            w!(super::AT_PAGESZ); w!(4096);
            w!(super::AT_SALTY_UNTYPED); w!(super::CAP_CHILD_UNTYPED_OFFSET);
            w!(super::AT_SALTY_VSPACE); w!(1);
            w!(super::AT_SALTY_SCRATCH); w!(layout.scratch.base);
            w!(super::AT_SALTY_INITRD); w!(layout.initrd.base);
            w!(super::AT_SALTY_INITRD_SZ); w!(initrd_size as u64);
            // Compute first free child CNode slot past extras and shared lib cache
            let frame_slot_start = {
                let mut s = super::CHILD_RTLD_FRAME_SLOT_START;
                for extra in extras {
                    if (extra.src != 0 || extra.dst != 0) && extra.dst + 1 > s {
                        s = extra.dst + 1;
                    }
                }
                let cache = &*(&raw const SHARED_LIB_CACHE);
                if cache.initialized && cache.page_count > 0 {
                    let cache_end = CAP_SHARED_LIB_CACHE_BASE + cache.page_count as u64;
                    if cache_end > s {
                        s = cache_end;
                    }
                }
                s
            };
            w!(super::AT_SALTY_FRAME_SLOT); w!(frame_slot_start);
            // Slot pool: from frame_slot_start to CNode end
            let effective_cnode_bits: u64 = if cnode_size_bits > 0 { cnode_size_bits } else { 10 };
            let cnode_total_slots: u64 = 1u64 << effective_cnode_bits;
            let slot_pool_count = cnode_total_slots.saturating_sub(frame_slot_start);
            w!(super::AT_SALTY_SLOT_BASE); w!(frame_slot_start);
            w!(super::AT_SALTY_SLOT_COUNT); w!(slot_pool_count);
            if has_expand_ep {
                w!(super::AT_SALTY_EXPAND_EP); w!(super::CAP_EXPAND_EP);
            }
            if shared_lib_base != 0 {
                w!(super::AT_SALTY_SHARED_LIB_BASE); w!(shared_lib_base);
            }
            w!(super::AT_NULL); w!(0);
            w!(0); // padding

            invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

            child_rsp = layout.stack_top - srv_stack_frame_size;
            child_entry = rtld_result.entry;
        }

        let err = invoke::tcb_configure(child_tcb, child_entry, child_rsp, 0);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[INIT] TCB configure failed err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            return -1;
        }

        invoke::tcb_set_ipc_buffer(child_tcb, layout.ipc_buf.base);

        let err = invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 { puts(b"[INIT] SC configure failed\n"); return -1; }

        let err = invoke::sc_bind(child_sc, child_tcb);
        if err != 0 { puts(b"[INIT] SC bind failed\n"); return -1; }

        let err = invoke::tcb_resume(child_tcb);
        if err != 0 { puts(b"[INIT] TCB resume failed\n"); return -1; }

        // Register init-spawned service with procmgr (badge + CNode)
        if procmgr_ep != 0 {
            let mut reg_msg = SaltyMsg::zeroed();
            let mut reg_reply = SaltyMsg::zeroed();
            reg_msg.label = POSIX_PM_REGISTER;
            reg_msg.length = 2;
            reg_msg.regs[0] = spawn_badge;
            // Transfer child CNode cap so procmgr can access child's untyped
            ipc::set_send_cap_ctx(super::ipc_ctx(), 0, child_cn);
            let reg_err = ipc::call_ctx(
                super::ipc_ctx(), procmgr_ep,
                &raw const reg_msg, &raw mut reg_reply,
            );
            if reg_err != 0 || reg_reply.label != SALTY_OK {
                let mut lb = LineBuf::new();
                lb.str(b"[INIT] WARN: PM_REGISTER ");
                lb.bytes(label);
                lb.str(b" failed err=");
                lb.hex(reg_err as u64);
                lb.str(b" label=");
                lb.hex(reg_reply.label);
                lb.str(b"\n");
                lb.flush();
            }
        }

        if wait_for_child_ready(
            child_tcb,
            child_ready_ntfn,
            label,
            effective_ready_timeout_ns,
        ) != 0 {
            return -1;
        }

        { let mut lb = LineBuf::new(); lb.str(b"[INIT] "); lb.bytes(label); lb.str(b" ready\n"); lb.flush(); }
        0
    }
}

/// Spawn via procmgr IPC (for post-procmgr services).
///
/// Uses the new spawn wire format:
///   regs[0] = name_len
///   regs[1] = spawn_policy bitfield
///   regs[2] = timeout_ns (only for NOTIFY mode, 0=auto)
///   regs[3] = spawn_flags
///   regs[4] = spawn_args_len (NUL-separated args bytes)
///   regs[5..] = name bytes packed into u64 words, then spawn_args bytes
pub unsafe fn pm_spawn(
    pm_ep: Cap,
    prog: &[u8],
    def: &super::ini::ServiceDef,
    pre_ep: Cap,
) -> i32 {
    unsafe {
        let len = prog.len();

        let readiness = match def.svc_type {
            super::ini::ServiceType::Notify => SPAWN_READY_NOTIFY,
            super::ini::ServiceType::Simple => SPAWN_READY_IMMEDIATE,
        };
        let policy = spawn_policy_build(
            readiness,
            def.map_initrd,
            false, // service class is determined by procmgr from binary name
            def.cnode_bits,
            def.memory_kb,
        );
        let timeout_ns = if readiness == SPAWN_READY_NOTIFY {
            def.timeout_start_ns
        } else {
            0
        };

        let mut spawn_flags: u64 = 0;
        if pre_ep != 0 {
            spawn_flags |= SPAWN_FLAG_USE_PRE_EP;
            ipc::set_send_cap_ctx(super::ipc_ctx(), 0, pre_ep);
        }
        if matches!(def.restart, super::ini::RestartPolicy::Always) {
            spawn_flags |= SPAWN_FLAG_RESPAWN;
        }

        let mut spawn_msg = SaltyMsg::zeroed();
        spawn_msg.label = POSIX_PM_SPAWN;
        let packed_name_words = ((len as u64) + 7) / 8;
        let args_len = def.spawn_args_len as u64;
        let packed_args_words = (args_len + 7) / 8;
        spawn_msg.length = 5 + packed_name_words + packed_args_words;
        spawn_msg.regs[0] = len as u64;
        spawn_msg.regs[1] = policy;
        spawn_msg.regs[2] = timeout_ns;
        spawn_msg.regs[3] = spawn_flags;
        spawn_msg.regs[4] = args_len;
        let dst = &raw mut spawn_msg.regs[5] as *mut u8;
        for i in 0..len {
            *dst.add(i) = prog[i];
        }
        let args_dst = dst.add(packed_name_words as usize * 8);
        for i in 0..(def.spawn_args_len as usize) {
            *args_dst.add(i) = def.spawn_args[i];
        }

        let mut spawn_reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(super::ipc_ctx(), pm_ep, &raw const spawn_msg, &raw mut spawn_reply);
        if err != 0 || spawn_reply.label != SALTY_OK {
            return -1;
        }

        spawn_reply.regs[0] as i32
    }
}

/// Inject a capability into a procmgr-managed child's CSpace.
/// Uses PM_INJECT_CAP IPC to have procmgr copy the cap into the child.
pub unsafe fn pm_inject_cap(pm_ep: Cap, pid: u32, dst_slot: u64, cap: Cap) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        msg.label = POSIX_PM_INJECT_CAP;
        msg.length = 2;
        msg.regs[0] = pid as u64;
        msg.regs[1] = dst_slot;
        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, cap);

        let mut reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(super::ipc_ctx(), pm_ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            -1
        } else {
            0
        }
    }
}
