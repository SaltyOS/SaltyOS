//! Process spawning helpers
//! SPDX-License-Identifier: GPL-2.0-only

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::syscall;
use trona::types::core::*;
use trona_loader::cpio;
use trona_loader::elf_dynamic;
use trona_loader::elf_loader;

#[derive(Clone, Copy)]
pub struct ExtraCapCopy {
    pub src: Cap,
    pub dst: u64,
    /// Optional badge to apply when copying endpoint capabilities.
    /// 0 means plain cnode_copy; non-zero uses cnode_mint.
    pub badge: u64,
    /// Optional `ROLE_*` identifier. When non-zero, `spawn_server` also
    /// emits a `cap_table` entry pointing at `dst`, so the child can
    /// reach the cap via `trona::caps::<name>()`. Callers set this via
    /// `ini::system_role_for_bare_name(provider_name)` when the `NeedEP=`
    /// provider is a known system role.
    pub role_id: u32,
    /// `CAP_TBL_FLAG_*` bits to emit alongside `role_id`. Paired with
    /// `role_id`; ignored when `role_id == 0`.
    pub role_flags: u32,
}

// Import from parent module
use super::child_layout::{
    ChildCapLayout, ChildSlotAlloc, COFF_CNODE, COFF_EP, COFF_FRAME_START, COFF_IPC_FR,
    COFF_READY_NTFN, COFF_SC, COFF_STACK_FR, COFF_TCB, COFF_VSPACE,
};
use super::{CAP_SELF_CSPACE, CAP_SELF_VSPACE, CAP_UNTYPED_START};

/// Init-side CSpace slot where the kernel bootstrap seeds the initrd untyped
/// cap. Init inherits this slot from `kernite/src/init.rs` and uses the cap as
/// the source of initrd device mappings and initrd untyped copies minted into
/// child CSpaces.
const CAP_INIT_INITRD_UNTYPED: Cap = 12;

/// Child-side starting offset for the range of untyped capabilities that
/// init mints into a service CSpace. This is a range start, not a single
/// slot, so it is not drawn from the `ChildSlotAlloc` cursor — keep it as a
/// spawner-private constant. `ld-trona.so` reads it from `AT_TRONA_UNTYPED`
/// and, on miss, falls back to scanning `CAP_UNTYPED_START..CAP_UNTYPED_END`.
const CAP_CHILD_UNTYPED_OFFSET: u64 = 7;

const INIT_UT_SCAN_END_FALLBACK: Cap = 200;
const UT_MIRROR_COUNT: Cap = 16;
const INIT_WORK_UNTYPED_RESERVE: Cap = 1;

/// Badge value used by init when calling rsrcsrv. rsrcsrv recognizes this
/// badge as init and accepts privileged operations from it
/// (RES_QUOTA_FLAG_PROMOTE_PRIVILEGED, RES_ADOPT_UNTYPED).
pub const INIT_BADGE: u64 = 1;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3); // READ|EXECUTE|GRANT
const READY_SIGNAL_BITS: u64 = 1;
const READY_TIMEOUT_NS: u64 = 10_000_000_000; // 10s default
const READY_WAIT_YIELDS_FALLBACK: usize = 200_000;
static mut NEXT_UT_HINT: Cap = CAP_UNTYPED_START;

#[cfg(target_arch = "aarch64")]
const STACK_ENTRY_BIAS: u64 = 0;
#[cfg(target_arch = "x86_64")]
const STACK_ENTRY_BIAS: u64 = 8;

// ===========================================================================
// Shared library physical frame cache
// ===========================================================================

const MAX_SHARED_LIB_PAGES: usize = 1152;
const MAX_CACHED_LIBS: usize = 4;
const MAX_LIB_NAME: usize = 24;
const MAX_RW_SEGS: usize = 4;

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
    rw_segs: [RwSegInfo; MAX_RW_SEGS],
    rw_seg_count: u8,
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
// Spawn role
// ===========================================================================

/// Spawn dispatch classification.
///
/// - `Authority`: init's bootstrap-allocator path. init allocates the child's
///   kernel objects directly via untyped retype, then transfers ownership of
///   all of init's root untypeds to the child via `cnode_move` at the end of
///   spawn. The system has exactly one such service: rsrcsrv. This is the
///   final init-side use of direct untyped retype — every spawn after this
///   one is a Service- or Pager-class spawn that calls rsrcsrv via IPC.
///
/// - `Pager`: a normal Service-class spawn (rsrcsrv RPC for kernel objects),
///   but init also captures the resulting endpoint and uses it as the VM
///   fault handler / MM_REGISTER target for every subsequent PreProcmgr
///   service. The system has exactly one Pager: mmsrv. The Pager service's
///   own CSpace gets the dedicated receive-slot range so it can absorb the
///   cap_transfers that come with cross-VSpace operations.
///
/// - `Service`: every other userspace server. init acts as an rsrcsrv client
///   and uses `RES_ALLOC_BATCH` to obtain TCB / VSpace / CNode / SC /
///   Notification / Frame caps for the child. No untyped is exposed to the
///   child.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnRole {
    Authority,
    Pager,
    Service,
}

fn compute_ready_timeout_ns(
    configured_timeout_ns: u64,
    is_dynamic: bool,
    elf_size_bytes: usize,
    map_initrd: bool,
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
        if now.error == 0 {
            Some(now.value)
        } else {
            None
        }
    };
    let mut yields: usize = 0;

    loop {
        let poll = syscall::syscall(SYS_POLL, ready_ntfn, 0, 0, 0, 0, 0);
        if poll.error == 0 {
            if (poll.value & READY_SIGNAL_BITS) != 0 {
                return 0;
            }
        } else if poll.error != TRONA_WOULD_BLOCK {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] ready poll failed err=");
                _lb.hex(poll.error);
                _lb.str(b"\n");
            });
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

    trona::uerror!(|_lb| {
        _lb.str(b"[INIT] ");
        _lb.bytes(label);
        _lb.str(b" ready timeout\n");
    });
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
    unsafe {
        retype_from_any_untyped_with_source(new_type, size_bits, dest_slot, core::ptr::null_mut())
    }
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

    let mut best_err = TRONA_OUT_OF_MEMORY as i32;

    for ut in first..end {
        let err = invoke::untyped_retype(ut, new_type, size_bits, dest_slot);
        if err == 0 {
            unsafe {
                NEXT_UT_HINT = ut;
            }
            if !src_ut_out.is_null() {
                unsafe {
                    *src_ut_out = ut;
                }
            }
            return 0;
        }
        if err != TRONA_INVALID_CAPABILITY as i32
            && err != TRONA_INVALID_OPERATION as i32
            && err != TRONA_NOT_FOUND as i32
        {
            best_err = err;
        }
    }
    for ut in start..first {
        let err = invoke::untyped_retype(ut, new_type, size_bits, dest_slot);
        if err == 0 {
            unsafe {
                NEXT_UT_HINT = ut;
            }
            if !src_ut_out.is_null() {
                unsafe {
                    *src_ut_out = ut;
                }
            }
            return 0;
        }
        if err != TRONA_INVALID_CAPABILITY as i32
            && err != TRONA_INVALID_OPERATION as i32
            && err != TRONA_NOT_FOUND as i32
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

    let mut best_err = TRONA_OUT_OF_MEMORY as i32;

    for ut in first..end {
        if ut == exclude_ut {
            continue;
        }
        let err = invoke::untyped_retype(ut, new_type, size_bits, dest_slot);
        if err == 0 {
            unsafe {
                NEXT_UT_HINT = ut;
            }
            if !src_ut_out.is_null() {
                unsafe {
                    *src_ut_out = ut;
                }
            }
            return 0;
        }
        if err != TRONA_INVALID_CAPABILITY as i32
            && err != TRONA_INVALID_OPERATION as i32
            && err != TRONA_NOT_FOUND as i32
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
            unsafe {
                NEXT_UT_HINT = ut;
            }
            if !src_ut_out.is_null() {
                unsafe {
                    *src_ut_out = ut;
                }
            }
            return 0;
        }
        if err != TRONA_INVALID_CAPABILITY as i32
            && err != TRONA_INVALID_OPERATION as i32
            && err != TRONA_NOT_FOUND as i32
        {
            best_err = err;
        }
    }

    best_err
}

// ===========================================================================
// Shared library cache: init + map
// ===========================================================================

/// Pre-load shared library RO segments into permanent frame caps.
/// Called once at init startup. Processes both libtrona.so and libc.so.
/// On failure, cache stays uninitialized and all spawns fall through
/// to per-process RTLD allocation.
pub unsafe fn init_shared_lib_cache(root_ut: Cap) {
    unsafe {
        let cache = &mut *(&raw mut SHARED_LIB_CACHE);
        *cache = SharedLibCache::new();
        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::INITRD_SIZE;

        let libs: [&[u8]; 3] = [b"lib/libtrona.so", b"lib/libc.so", b"lib/libc++.so"];

        let mut cache_ok = true;
        for lib_name in &libs {
            if cache.lib_count >= MAX_CACHED_LIBS {
                break;
            }

            let mut lib_failed = false;

            let mut entry = CpioEntry::zeroed();
            if trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                lib_name.as_ptr(),
                lib_name.len(),
                &raw mut entry,
            ) == 0
            {
                trona::udebug!(|_lb| {
                    _lb.str(b"[INIT] shared lib cache: ");
                    _lb.bytes(lib_name);
                    _lb.str(b" not found, skipping\n");
                });
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

            // Find min_vaddr and max_seg_end across PT_LOAD segments
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

            // Start a new CachedLib entry
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

            // Cache each page of each read-only PT_LOAD segment
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
                        let rw_flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
                        lib_entry.rw_segs[idx] = RwSegInfo {
                            vaddr_offset: (ph.p_vaddr & !0xFFFu64) - (min_vaddr & !0xFFFu64),
                            file_offset: ph.p_offset,
                            file_size: ph.p_filesz,
                            seg_vaddr: ph.p_vaddr,
                            memsz: ph.p_memsz,
                            flags: rw_flags,
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
                        lib_failed = true;
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
                        lib_failed = true;
                        break;
                    }

                    // Scratch-map to fill frame contents
                    let err = invoke::vspace_map(
                        CAP_SELF_VSPACE,
                        frame_slot,
                        SCRATCH_VADDR,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    );
                    if err != 0 {
                        lib_failed = true;
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
                    let copy_end = if page + 4096 < file_end {
                        page + 4096
                    } else {
                        file_end
                    };

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

                if lib_failed {
                    break;
                }
            }

            if lib_failed {
                cache_ok = false;
                break;
            }

            // Finalize CachedLib entry
            lib_entry.page_start = page_start;
            lib_entry.page_count = (cache.page_count as u16) - page_start;
            cache.libs[li] = lib_entry;
            cache.lib_count += 1;
        }

        if !cache_ok {
            trona::uerror!(|_lb| {
                _lb.str(
                    b"[INIT] shared lib cache disabled: capacity or frame allocation failure\n",
                );
            });
            *cache = SharedLibCache::new();
            return;
        }

        if cache.page_count > 0 {
            cache.initialized = true;
            trona::uinfo!(|_lb| {
                _lb.str(b"[INIT] shared lib cache: ");
                _lb.hex(cache.page_count as u64);
                _lb.str(b" RO pages cached\n");
            });
        }
    }
}

/// Map cached shared library RO frames into a child VSpace, mapping only
/// libraries listed in `needed` in their DT_NEEDED order.
/// `shared_lib_base_vaddr` is the layout-computed VA where libs start.
/// `loader_ut` is the untyped used for per-spawn RW page allocation:
/// init's root untyped for Authority spawns, the rsrcsrv scratch untyped
/// for Pager/Service spawns (init's root untypeds have already been
/// `cnode_move`d into rsrcsrv by the time any non-Authority spawn runs).
/// Returns the shared_lib_base address on success, 0 on failure.
unsafe fn map_shared_lib_to_child(
    child_vs: Cap,
    _child_cn: Cap,
    shared_lib_base_vaddr: u64,
    needed: &trona_loader::elf_dynamic::NeededLibs,
    loader_ut: Cap,
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

            // Find this library in the cache.
            // Cache stores CPIO paths ("lib/libtrona.so") but DT_NEEDED
            // gives bare sonames ("libtrona.so").  Strip the "lib/" prefix
            // from cache names before comparing.
            let mut found = false;
            for li in 0..cache.lib_count {
                let cl = &cache.libs[li];
                let cl_full = &cl.name[..cl.name_len as usize];
                let cl_name = if cl_full.len() > 4
                    && cl_full[0] == b'l'
                    && cl_full[1] == b'i'
                    && cl_full[2] == b'b'
                    && cl_full[3] == b'/'
                {
                    &cl_full[4..]
                } else {
                    cl_full
                };
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
                        trona::uerror!(|_lb| {
                            _lb.str(b"[INIT] shared lib map failed at ");
                            _lb.hex(vaddr);
                            _lb.str(b" err=");
                            _lb.hex(err as u64);
                            _lb.str(b"\n");
                        });
                        return 0;
                    }
                    total_mapped += 1;
                }

                // Map RW segments (per-child private copies)
                if cl.rw_seg_count > 0 {
                    // Find library in initrd to get file data for .data copy
                    let initrd = super::INITRD_VADDR as *const u8;
                    let initrd_size = super::INITRD_SIZE;
                    let mut lib_entry = CpioEntry::zeroed();
                    // cl.name stores the full CPIO path (e.g. "lib/libtrona.so")
                    let lib_cpio_name = &cl.name[..cl.name_len as usize];
                    let lib_found = trona_loader::cpio::cpio_find_file(
                        initrd,
                        initrd_size,
                        lib_cpio_name.as_ptr(),
                        lib_cpio_name.len(),
                        &raw mut lib_entry,
                    ) != 0;

                    // Track RW pages mapped so far for this library to
                    // handle overlapping PT_LOAD segments (lld-20 RELRO
                    // split produces two RW segments whose page-aligned
                    // starts can land on the same page).
                    const MAX_RW_TRACK: usize = 16;
                    let mut rw_track_vaddr: [u64; MAX_RW_TRACK] = [0; MAX_RW_TRACK];
                    let mut rw_track_cap: [Cap; MAX_RW_TRACK] = [0; MAX_RW_TRACK];
                    let mut rw_track_count: usize = 0;

                    for si in 0..cl.rw_seg_count as usize {
                        let rw = &cl.rw_segs[si];
                        let seg_start = running_base + rw.vaddr_offset;
                        let seg_end = (running_base
                            + rw.vaddr_offset
                            + (rw.seg_vaddr & 0xFFF)
                            + rw.memsz
                            + 0xFFF)
                            & !0xFFFu64;

                        let mut page = seg_start;
                        while page < seg_end {
                            // Check if this page was already mapped by a
                            // previous RW segment (overlap case).
                            let mut existing_cap: Cap = 0;
                            for j in 0..rw_track_count {
                                if rw_track_vaddr[j] == page {
                                    existing_cap = rw_track_cap[j];
                                    break;
                                }
                            }

                            if existing_cap != 0 {
                                // Overlap: scratch-map existing frame, patch
                                // this segment's data without zeroing, then
                                // skip the child VSpace map (already mapped).
                                if lib_found && rw.file_size > 0 {
                                    let err = invoke::vspace_map(
                                        CAP_SELF_VSPACE,
                                        existing_cap,
                                        SCRATCH_VADDR,
                                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                                    );
                                    if err != 0 {
                                        trona::uerror!(|_lb| {
                                            _lb.str(b"[INIT] RW overlap scratch map failed\n");
                                        });
                                        return 0;
                                    }

                                    let scratch = SCRATCH_VADDR as *mut u8;
                                    let sub_page_off = (rw.seg_vaddr & 0xFFF) as usize;
                                    let file_off = rw.file_offset as usize;
                                    let data_len = rw.file_size as usize;
                                    let page_rel = (page - seg_start) as usize;
                                    let file_region_start = sub_page_off;
                                    let file_region_end = sub_page_off + data_len;
                                    let page_byte_start = page_rel;
                                    let page_byte_end = page_rel + 4096;
                                    let copy_start = if page_byte_start > file_region_start {
                                        page_byte_start
                                    } else {
                                        file_region_start
                                    };
                                    let copy_end = if page_byte_end < file_region_end {
                                        page_byte_end
                                    } else {
                                        file_region_end
                                    };
                                    if copy_start < copy_end {
                                        let src_off = file_off + (copy_start - sub_page_off);
                                        let dst_off = copy_start - page_rel;
                                        let len = copy_end - copy_start;
                                        if src_off + len <= lib_entry.data_len {
                                            let src = lib_entry.data.add(src_off);
                                            let dst = scratch.add(dst_off);
                                            for j in 0..len {
                                                core::ptr::write_volatile(dst.add(j), *src.add(j));
                                            }
                                        }
                                    }

                                    invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);
                                }
                                page += 4096;
                                continue;
                            }

                            // New page: allocate frame, zero, copy, map.
                            let frame_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
                            let mut err =
                                invoke::untyped_retype(loader_ut, OBJ_FRAME, 0, frame_slot);
                            if err != 0 {
                                err = retype_from_any_untyped(OBJ_FRAME, 0, frame_slot);
                            }
                            if err != 0 {
                                trona::uerror!(|_lb| {
                                    _lb.str(b"[INIT] RW frame retype failed err=");
                                    _lb.hex(err as u64);
                                    _lb.str(b"\n");
                                });
                                return 0;
                            }

                            let err = invoke::vspace_map(
                                CAP_SELF_VSPACE,
                                frame_slot,
                                SCRATCH_VADDR,
                                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                            );
                            if err != 0 {
                                trona::uerror!(|_lb| {
                                    _lb.str(b"[INIT] RW scratch map failed\n");
                                });
                                return 0;
                            }

                            // Zero the page
                            let scratch = SCRATCH_VADDR as *mut u8;
                            for j in 0..4096usize {
                                core::ptr::write_volatile(scratch.add(j), 0);
                            }

                            // Copy file data if available
                            if lib_found && rw.file_size > 0 {
                                let sub_page_off = (rw.seg_vaddr & 0xFFF) as usize;
                                let file_off = rw.file_offset as usize;
                                let data_len = rw.file_size as usize;
                                // page_rel: offset of this page relative to seg_start
                                let page_rel = (page - seg_start) as usize;
                                // file data starts at sub_page_off bytes into the first page
                                let file_region_start = sub_page_off;
                                let file_region_end = sub_page_off + data_len;
                                // range of bytes covered by this page within the segment
                                let page_byte_start = page_rel;
                                let page_byte_end = page_rel + 4096;
                                let copy_start = if page_byte_start > file_region_start {
                                    page_byte_start
                                } else {
                                    file_region_start
                                };
                                let copy_end = if page_byte_end < file_region_end {
                                    page_byte_end
                                } else {
                                    file_region_end
                                };
                                if copy_start < copy_end {
                                    let src_off = file_off + (copy_start - sub_page_off);
                                    let dst_off = copy_start - page_rel;
                                    let len = copy_end - copy_start;
                                    if src_off + len <= lib_entry.data_len {
                                        let src = lib_entry.data.add(src_off);
                                        let dst = scratch.add(dst_off);
                                        for j in 0..len {
                                            core::ptr::write_volatile(dst.add(j), *src.add(j));
                                        }
                                    }
                                }
                            }

                            invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

                            let err = invoke::vspace_map(child_vs, frame_slot, page, rw.flags);
                            if err != 0 {
                                trona::uerror!(|_lb| {
                                    _lb.str(b"[INIT] RW child map failed at ");
                                    _lb.hex(page);
                                    _lb.str(b" err=");
                                    _lb.hex(err as u64);
                                    _lb.str(b"\n");
                                });
                                return 0;
                            }

                            // Record this page for overlap detection
                            if rw_track_count < MAX_RW_TRACK {
                                rw_track_vaddr[rw_track_count] = page;
                                rw_track_cap[rw_track_count] = frame_slot;
                                rw_track_count += 1;
                            }

                            total_mapped += 1;
                            page += 4096;
                        }
                    }
                }

                running_base += cl.lib_span + 4096; // advance past this lib + gap
                found = true;
                break;
            }

            if !found {
                // Library not in cache — RTLD will load it from initrd
                trona::udebug!(|_lb| {
                    _lb.str(b"[INIT] shared lib cache miss: ");
                    _lb.bytes(name);
                    _lb.str(b"\n");
                });
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
pub fn shared_lib_va_pages_for_needed(needed: &trona_loader::elf_dynamic::NeededLibs) -> usize {
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
                let cl_full = &cl.name[..cl.name_len as usize];
                // Strip "lib/" prefix for DT_NEEDED comparison
                let cl_name = if cl_full.len() > 4
                    && cl_full[0] == b'l'
                    && cl_full[1] == b'i'
                    && cl_full[2] == b'b'
                    && cl_full[3] == b'/'
                {
                    &cl_full[4..]
                } else {
                    cl_full
                };
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
    copy_shared_lib_caps: bool,
    ready_timeout_ns: u64,
    pre_ep: Cap,
    mmsrv_ep: Cap,
    procmgr_ep: Cap,
    bootstrap_authority_call_ep: Cap,
    bootstrap_authority_raw_ep: Cap,
    spawn_badge: u64,
    spawn_role: SpawnRole,
    pager_child_slot: u64,
    registered_pid_out: *mut u32,
) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[INIT] Spawning ");
        _lb.bytes(label);
        _lb.str(b" (");
        _lb.bytes(elf_name);
        _lb.str(b")\n");
    });

    unsafe {
        if !registered_pid_out.is_null() {
            *registered_pid_out = 0;
        }
        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::INITRD_SIZE;

        let mut entry = CpioEntry::zeroed();
        // Strip leading '/' for CPIO lookup — archive entries use "bin/foo", not "/bin/foo"
        let cpio_name = if !elf_name.is_empty() && elf_name[0] == b'/' {
            &elf_name[1..]
        } else {
            elf_name
        };
        let mut found = cpio::cpio_find_file(
            initrd,
            initrd_size,
            cpio_name.as_ptr(),
            cpio_name.len(),
            &raw mut entry,
        ) != 0;
        if !found && cpio_name.len() + 4 <= 96 {
            let mut legacy = [0u8; 96];
            for i in 0..cpio_name.len() {
                legacy[i] = cpio_name[i];
            }
            legacy[cpio_name.len()] = b'.';
            legacy[cpio_name.len() + 1] = b'e';
            legacy[cpio_name.len() + 2] = b'l';
            legacy[cpio_name.len() + 3] = b'f';
            found = cpio::cpio_find_file(
                initrd,
                initrd_size,
                legacy.as_ptr(),
                cpio_name.len() + 4,
                &raw mut entry,
            ) != 0;
        }
        if !found {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] ");
                _lb.bytes(elf_name);
                _lb.str(b" not found in initrd\n");
            });
            return -1;
        }

        let is_dynamic = elf_dynamic::elf_has_interp(entry.data, entry.data_len);

        // Pre-compute ELF and RTLD spans for layout computation
        let elf_span = elf_loader::elf_compute_load_span(entry.data, entry.data_len);
        let mut rtld_entry = CpioEntry::zeroed();
        let rtld_span = if is_dynamic {
            let rtld_name = b"lib/ld-trona.so";
            if cpio::cpio_find_file(
                initrd,
                initrd_size,
                rtld_name.as_ptr(),
                rtld_name.len(),
                &raw mut rtld_entry,
            ) == 0
            {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] rtld not found in initrd\n");
                });
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
            trona_loader::elf_dynamic::NeededLibs::new()
        };

        let shared_lib_pages = shared_lib_va_pages_for_needed(&needed);
        let layout = trona::layout::compute_vm_layout_randomized(
            elf_span,
            rtld_span,
            shared_lib_pages,
            map_initrd || is_dynamic,
            initrd_size,
            || trona::syscall::sys_getrandom(),
        );
        if layout.stack_top == 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] ELF too large for VA layout\n");
            });
            return -1;
        }

        let effective_ready_timeout_ns =
            compute_ready_timeout_ns(ready_timeout_ns, is_dynamic, entry.data_len, map_initrd);

        let child_tcb = cap_base + COFF_TCB;
        let child_vs = cap_base + COFF_VSPACE;
        let child_cn = cap_base + COFF_CNODE;
        let child_sc = cap_base + COFF_SC;
        let child_stk_fr = cap_base + COFF_STACK_FR;
        let child_ipc_fr = cap_base + COFF_IPC_FR;
        let child_ep = cap_base + COFF_EP;
        let child_ready_ntfn = cap_base + COFF_READY_NTFN;

        // Build the child's CSpace slot layout using a sequential cursor.
        // Starting the cursor at slot 0 naturally pins SELF_TCB/VSPACE/CSPACE
        // to the kernel ABI positions 0/1/2 before the rest of the well-known
        // caps are drawn. The cursor is bounded by the child CNode capacity so
        // that we fail loudly if a service requests a CNode too small for the
        // well-known cap set.
        let child_cnode_capacity: u64 = if cnode_size_bits > 0 {
            1u64 << cnode_size_bits
        } else {
            1u64 << 10
        };
        let mut child_slot_alloc = ChildSlotAlloc::new(0, child_cnode_capacity);
        let cap_layout = match ChildCapLayout::from_alloc(&mut child_slot_alloc) {
            Some(l) => l,
            None => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] child CNode too small for well-known layout\n");
                });
                return -1;
            }
        };

        // Resolve the bootstrap untyped that this spawn will retype its kernel
        // objects (and ELF / RTLD pages) from.
        //
        // - SpawnRole::Authority (rsrcsrv): use init's own root untyped. After
        //   rsrcsrv is up and running, the rest of init's untypeds are handed
        //   to it via cnode_move at the end of this function.
        //
        // - SpawnRole::Pager / SpawnRole::Service: init has no usable untypeds
        //   of its own at this point. Ask rsrcsrv for a per-spawn scratch
        //   untyped (2^24 bytes = 16 MiB) which is large enough for any single
        //   child's ELF + RTLD load + initial frames. The scratch cap lands in
        //   `scratch_slot` via cap_transfer and is used as the loader untyped
        //   for the rest of this function. It can be reclaimed by
        //   RES_FREE_HANDLE later if needed; for now it stays on init's CSpace
        //   as one cap per spawned child.
        let loader_ut = match spawn_role {
            SpawnRole::Authority => root_ut,
            SpawnRole::Pager | SpawnRole::Service => {
                let scratch_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
                ipc::set_receive_slot_ctx(super::ipc_ctx(), CAP_SELF_CSPACE, scratch_slot, 0);
                let mut req = TronaMsg::zeroed();
                req.label = RES_ALLOC_OBJECT;
                req.length = 4;
                req.regs[0] = spawn_badge; // owner_id
                req.regs[1] = OBJ_UNTYPED;
                req.regs[2] = 24; // 16 MiB
                req.regs[3] = 0; // flags
                let mut resp = TronaMsg::zeroed();
                let err = ipc::call_ctx(
                    super::ipc_ctx(),
                    bootstrap_authority_call_ep,
                    &raw const req,
                    &raw mut resp,
                );
                if err != 0 || resp.label != TRONA_OK {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[INIT] rsrcsrv scratch untyped alloc failed err=");
                        _lb.hex(err as u64);
                        _lb.str(b" label=");
                        _lb.hex(resp.label);
                        _lb.str(b"\n");
                    });
                    return -1;
                }
                scratch_slot
            }
        };

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
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] retype CNode (large) failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
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
                    trona::uerror!(|_lb| {
                        _lb.str(b"[INIT] retype ");
                        _lb.bytes($name);
                        _lb.str(b" failed err=");
                        _lb.hex(err as u64);
                        _lb.str(b"\n");
                    });
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
                super::CAP_SELF_CSPACE,
                pre_ep,
                super::CAP_SELF_CSPACE,
                child_ep,
                CAP_RIGHTS_ALL,
            );
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] copy pre-EP failed\n");
                });
                return -1;
            }
        } else {
            retype!(OBJ_ENDPOINT, child_ep, b"EP");
        }
        retype!(OBJ_NOTIFICATION, child_ready_ntfn, b"ready ntfn");

        let mut loader_ctx = ElfLoaderCtx {
            untyped: loader_ut,
            self_vspace: CAP_SELF_VSPACE,
            child_vspace: child_vs,
            scratch_vaddr: SCRATCH_VADDR,
            next_frame_slot: cap_base + COFF_FRAME_START,
            alloc_frame_slot: Some(super::init_alloc_frame_slot),
            alloc_opaque: core::ptr::null_mut(),
            record_page: None,
            record_opaque: core::ptr::null_mut(),
        };

        let mut elf_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let err = elf_loader::elf_load(
            entry.data,
            entry.data_len,
            layout.elf_code.base,
            &mut loader_ctx,
            &raw mut elf_result,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] ELF load failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return -1;
        }

        let mut rtld_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };

        if is_dynamic {
            let err = elf_loader::elf_load(
                rtld_entry.data,
                rtld_entry.data_len,
                layout.rtld.base,
                &mut loader_ctx,
                &raw mut rtld_result,
            );
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] rtld ELF load failed\n");
                });
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
                    trona::uerror!(|_lb| {
                        _lb.str(b"[INIT] stack frame retype failed\n");
                    });
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
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] stack map failed\n");
                });
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
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] IPC buf map failed\n");
            });
            return -1;
        }

        // Map initrd if needed
        if map_initrd || is_dynamic {
            let initrd_pages = (initrd_size + 4095) / 4096;
            let mut mapped_with_device = true;

            for pg in 0..initrd_pages {
                let err = invoke::vspace_map_device(
                    child_vs,
                    CAP_INIT_INITRD_UNTYPED,
                    (pg as u64) * 4096,
                    layout.initrd.base + pg as u64 * 4096,
                    VSPACE_FLAG_USER,
                );
                if err != 0 {
                    trona::udebug!(|_lb| {
                        _lb.str(b"[INIT] initrd device map failed pg=");
                        _lb.hex(pg as u64);
                        _lb.str(b" err=");
                        _lb.hex(err as u64);
                        _lb.str(b"\n");
                    });
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

            if mapped_with_device {
                trona::udebug!(|_lb| {
                    _lb.str(b"[INIT] initrd device-mapped: ");
                    _lb.dec(initrd_pages as u64);
                    _lb.str(b" pages at ");
                    _lb.hex(layout.initrd.base);
                    _lb.str(b"\n");
                });
            }

            if !mapped_with_device {
                for pg in 0..initrd_pages {
                    let fr_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
                    let mut err = invoke::untyped_retype(loader_ut, OBJ_FRAME, 0, fr_slot);
                    if err != 0 {
                        err = retype_from_any_untyped(OBJ_FRAME, 0, fr_slot);
                    }
                    if err != 0 {
                        trona::uerror!(|_lb| {
                            _lb.str(b"[INIT] initrd frame retype failed\n");
                        });
                        return -1;
                    }

                    let err = invoke::vspace_map(
                        CAP_SELF_VSPACE,
                        fr_slot,
                        SCRATCH_VADDR,
                        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    );
                    if err != 0 {
                        trona::uerror!(|_lb| {
                            _lb.str(b"[INIT] initrd scratch map failed\n");
                        });
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
                        trona::uerror!(|_lb| {
                            _lb.str(b"[INIT] initrd child map failed\n");
                        });
                        return -1;
                    }
                }
                trona::udebug!(|_lb| {
                    _lb.str(b"[INIT] initrd copy-mapped: ");
                    _lb.dec(initrd_pages as u64);
                    _lb.str(b" pages at ");
                    _lb.hex(layout.initrd.base);
                    _lb.str(b"\n");
                });
            }
            // Map init's persistent bootinfo snapshot page into child.
            let err = invoke::vspace_map(
                child_vs,
                super::CAP_BOOTINFO_SNAPSHOT_FRAME,
                BOOTINFO_VADDR,
                VSPACE_FLAG_USER,
            );
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] bootinfo child map failed\n");
                });
                return -1;
            }
        }

        // Copy standard caps
        macro_rules! copy_cap {
            ($src:expr, $dst:expr) => {
                invoke::cnode_copy(CAP_SELF_CSPACE, $src, child_cn, $dst, CAP_RIGHTS_ALL)
            };
        }

        if copy_cap!(child_tcb, cap_layout.self_tcb) != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] copy TCB failed\n");
            });
            return -1;
        }
        if copy_cap!(child_vs, cap_layout.self_vspace) != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] copy VSpace failed\n");
            });
            return -1;
        }
        if copy_cap!(child_cn, cap_layout.self_cspace) != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] copy CNode failed\n");
            });
            return -1;
        }
        if copy_cap!(child_ep, cap_layout.service_ep) != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] copy EP failed\n");
            });
            return -1;
        }
        if copy_cap!(child_ready_ntfn, cap_layout.ready_ntfn) != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] copy ready ntfn failed\n");
            });
            return -1;
        }
        if copy_cap!(child_sc, cap_layout.sc) != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] copy SC failed\n");
            });
            return -1;
        }
        if is_dynamic {
            let derr = invoke::cnode_copy(
                CAP_SELF_CSPACE,
                CAP_INIT_INITRD_UNTYPED,
                child_cn,
                cap_layout.initrd_untyped,
                INITRD_COPY_RIGHTS,
            );
            if derr != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] WARN: copy initrd untyped failed\n");
                });
            }
        }

        // No per-child boot-load untyped or mirror slots are installed:
        // Authority-class spawns transfer init's root untypeds via cnode_move
        // at the end of spawn (handled below); Service-class spawns receive
        // their kernel objects via rsrcsrv RPC and never see untyped at all.

        for extra in extras {
            if extra.src == 0 && extra.dst == 0 {
                continue;
            }
            if extra.src == 0 {
                // Late-bound NeedEP entries reserve the child slot / cap_table role
                // up front, but the provider cap is injected later by init.
                continue;
            }
            if is_dynamic && extra.dst == cap_layout.initrd_untyped {
                continue;
            }
            let err = if extra.badge != 0 {
                invoke::cnode_mint(CAP_SELF_CSPACE, extra.src, child_cn, extra.dst, extra.badge)
            } else {
                copy_cap!(extra.src, extra.dst)
            };
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] ERROR: cap copy failed src=");
                    _lb.hex(extra.src);
                    _lb.str(b" dst=");
                    _lb.hex(extra.dst);
                    _lb.str(b" err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                return -1;
            }
        }

        // Auto-mint badged procmgr EP at the child slot the cursor picked
        // for the bootstrap procmgr-control endpoint. Pre-procmgr children
        // use this single badged slot both for bootstrap RPC and, when
        // present, as the only expansion path exposed to libtrona.
        if procmgr_ep != 0 {
            let err = invoke::cnode_mint(
                CAP_SELF_CSPACE,
                procmgr_ep,
                child_cn,
                cap_layout.procmgr_ep,
                spawn_badge,
            );
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] WARN: mint procmgr control EP failed\n");
                });
            }
        }

        // Auto-mint a badged bootstrap-authority EP at the child slot the
        // cursor picked for the rsrcsrv endpoint. Each child gets a unique
        // badge (= spawn_badge) so the authority can distinguish callers in
        // its owner table. The raw cap is 0 while the authority itself is
        // being spawned, so it gets skipped automatically.
        if bootstrap_authority_raw_ep != 0 {
            let err = invoke::cnode_mint(
                CAP_SELF_CSPACE,
                bootstrap_authority_raw_ep,
                child_cn,
                cap_layout.rsrcsrv_ep,
                spawn_badge,
            );
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] WARN: mint bootstrap-authority EP failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
            }
        }

        if copy_shared_lib_caps {
            copy_shared_lib_caps_to_child(child_cn);
        }

        // Configure TCB
        let err = invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] TCB set_space failed\n");
            });
            return -1;
        }

        // Set fault handler so VMFaults route to mmsrv for demand paging
        if mmsrv_ep != 0 {
            let fault_ep_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
            let err = invoke::cnode_mint(
                CAP_SELF_CSPACE,
                mmsrv_ep,
                CAP_SELF_CSPACE,
                fault_ep_slot,
                spawn_badge,
            );
            if err == 0 {
                let err2 = invoke::tcb_set_fault_handler(child_tcb, fault_ep_slot);
                if err2 != 0 {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[INIT] WARN: tcb_set_fault_handler failed err=");
                        _lb.hex(err2 as u64);
                        _lb.str(b"\n");
                    });
                }
            } else {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] WARN: fault EP mint failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
            }
        }

        // Map shared library RO frames into child VSpace
        // Shared libs start after RTLD's actual extent + 1-page gap
        let shared_lib_base = if is_dynamic && layout.shared_libs.size > 0 {
            map_shared_lib_to_child(
                child_vs,
                child_cn,
                layout.shared_libs.base,
                &needed,
                loader_ut,
            )
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
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] dynamic stack scratch map failed\n");
                });
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
            ) != 0
            {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] dynamic phdr info extraction failed\n");
                });
                invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);
                return -1;
            }

            let has_procmgr_ep = procmgr_ep != 0;
            let has_mm_ep = mmsrv_ep != 0 && pager_child_slot != 0;
            let has_rsrcsrv_ep = bootstrap_authority_raw_ep != 0;
            let has_initrd_untyped = is_dynamic;
            // Unlike procmgr, init does not own a bound notification that can
            // drive async CSpace expansion for children. Pre-procmgr services
            // therefore rely on the blocking procmgr EP path when available,
            // and we omit AT_TRONA_CSPACE_NTFN entirely until a real source
            // for CHILD_CAP_CSPACE_NTFN exists.
            let child_cspace_ntfn_slot: Option<u64> = None;
            // Always-on auxv pairs (15):
            //   AT_PHDR, AT_PHENT, AT_PHNUM, AT_ENTRY, AT_BASE, AT_PAGESZ,
            //   AT_TRONA_UNTYPED, AT_TRONA_VSPACE, AT_TRONA_SCRATCH,
            //   AT_TRONA_INITRD, AT_TRONA_INITRD_SZ, AT_TRONA_CSPACE_LAYOUT,
            //   AT_TRONA_CAP_TABLE, AT_TRONA_IPC_BUFFER, AT_TRONA_SC_CAP
            //
            // All role-bearing caps flow exclusively through the cap_table
            // built below. Only the AT_TRONA_CSPACE_NTFN structural tag and
            // AT_TRONA_SHARED_LIB_BASE are still conditional.
            let base_count: u64 = 15;
            // Conditional pairs: CSPACE_NTFN, SHARED_LIB_BASE.
            let auxv_count: u64 = base_count
                + if child_cspace_ntfn_slot.is_some() {
                    1
                } else {
                    0
                }
                + if shared_lib_base != 0 { 1 } else { 0 };
            let cspace_layout_size = core::mem::size_of::<trona::TronaCspaceLayoutV1>() as u64;

            // Build the startup capability table ahead of the stack layout
            // computation so its exact byte length is known. The table sits
            // immediately below the cspace layout in the scratch page. All
            // role-bearing caps are installed into the child's libtrona weak
            // symbols by the substrate cap_table walker on the child side.
            //
            // `seen_roles` is a first-write-wins guard: each system role may
            // appear in the child's cap_table at most once. When a role is
            // delivered both via the hardcoded always-on path and a
            // `NeedEP=` / `CopyCap=` extra — or via two separate `NeedEP=`
            // entries for the same provider (e.g. procmgr's
            // `NeedEP=mmsrv:67:badge mmsrv:68` pair, where `:67` is the
            // badged client cap and `:68` is the unbadged raw authority —
            // only the first push wins. This keeps
            // `trona::caps::<name>()` resolving to the client variant even
            // when procmgr-private raw-authority duplicates are present.
            let mut cap_tbl_builder = trona::cap_table::CapTableBuilder::new();
            let mut seen_roles: [u32; 32] = [0; 32];
            let mut seen_roles_count: usize = 0;
            let mut push_role = |builder: &mut trona::cap_table::CapTableBuilder,
                                 seen: &mut [u32; 32],
                                 seen_count: &mut usize,
                                 role_id: u32,
                                 slot: u64,
                                 rights: u32,
                                 flags: u32| {
                if role_id == 0 || slot == 0 {
                    return;
                }
                for i in 0..*seen_count {
                    if seen[i] == role_id {
                        return;
                    }
                }
                if *seen_count < seen.len() {
                    seen[*seen_count] = role_id;
                    *seen_count += 1;
                }
                let _ = builder.push(role_id, slot, rights, flags);
            };
            {
                use trona::consts::kernel::{
                    CAP_TBL_FLAG_BADGED, CAP_TBL_FLAG_DEVICE_UT, CAP_TBL_FLAG_NOTIFICATION,
                    CAP_TBL_FLAG_UNTYPED, ROLE_CSPACE_NTFN, ROLE_INITRD_UNTYPED, ROLE_MMSRV_CLIENT,
                    ROLE_PROCMGR_CONTROL, ROLE_READINESS_NTFN, ROLE_RSRCSRV_CLIENT, ROLE_SC_CAP,
                    ROLE_SERVICE_EP,
                };
                // Always-on system roles.
                push_role(
                    &mut cap_tbl_builder,
                    &mut seen_roles,
                    &mut seen_roles_count,
                    ROLE_SERVICE_EP,
                    cap_layout.service_ep,
                    0,
                    0,
                );
                push_role(
                    &mut cap_tbl_builder,
                    &mut seen_roles,
                    &mut seen_roles_count,
                    ROLE_SC_CAP,
                    cap_layout.sc,
                    0,
                    0,
                );
                push_role(
                    &mut cap_tbl_builder,
                    &mut seen_roles,
                    &mut seen_roles_count,
                    ROLE_READINESS_NTFN,
                    cap_layout.ready_ntfn,
                    0,
                    CAP_TBL_FLAG_NOTIFICATION,
                );
                if has_initrd_untyped {
                    push_role(
                        &mut cap_tbl_builder,
                        &mut seen_roles,
                        &mut seen_roles_count,
                        ROLE_INITRD_UNTYPED,
                        cap_layout.initrd_untyped,
                        0,
                        CAP_TBL_FLAG_UNTYPED | CAP_TBL_FLAG_DEVICE_UT,
                    );
                }
                if has_procmgr_ep {
                    // init's bootstrap procmgr-control slot is the child's
                    // only well-known route back to procmgr before the full
                    // post-procmgr spawn model exists.
                    push_role(
                        &mut cap_tbl_builder,
                        &mut seen_roles,
                        &mut seen_roles_count,
                        ROLE_PROCMGR_CONTROL,
                        cap_layout.procmgr_ep,
                        0,
                        CAP_TBL_FLAG_BADGED,
                    );
                }
                if has_mm_ep {
                    push_role(
                        &mut cap_tbl_builder,
                        &mut seen_roles,
                        &mut seen_roles_count,
                        ROLE_MMSRV_CLIENT,
                        pager_child_slot,
                        0,
                        CAP_TBL_FLAG_BADGED,
                    );
                }
                if has_rsrcsrv_ep {
                    push_role(
                        &mut cap_tbl_builder,
                        &mut seen_roles,
                        &mut seen_roles_count,
                        ROLE_RSRCSRV_CLIENT,
                        cap_layout.rsrcsrv_ep,
                        0,
                        CAP_TBL_FLAG_BADGED,
                    );
                }
                if let Some(ntfn_slot) = child_cspace_ntfn_slot {
                    push_role(
                        &mut cap_tbl_builder,
                        &mut seen_roles,
                        &mut seen_roles_count,
                        ROLE_CSPACE_NTFN,
                        ntfn_slot,
                        0,
                        CAP_TBL_FLAG_NOTIFICATION,
                    );
                }
                // Extra `ExtraCapCopy` entries carry an optional `role_id`
                // set by the caller (see `ini::system_role_for_bare_name`
                // and `init_slot_to_role`). Pushed here so pre-procmgr
                // services can reach their `NeedEP=` / `CopyCap=` caps via
                // `trona::caps::<name>()` getters.
                for extra in extras {
                    push_role(
                        &mut cap_tbl_builder,
                        &mut seen_roles,
                        &mut seen_roles_count,
                        extra.role_id,
                        extra.dst,
                        0,
                        extra.role_flags,
                    );
                }
            }
            let cap_tbl_size = cap_tbl_builder.byte_len() as u64;

            // Reserved stack contents:
            // - argc, argv NULL, envp NULL: 3 u64s
            // - auxv payload: auxv_count pairs
            // - AT_NULL terminator pair
            // - one trailing u64 padding slot
            let stack_words: u64 = 3 + auxv_count * 2 + 2 + 1;
            let srv_stack_frame_size: u64 = stack_words * 8 + cspace_layout_size + cap_tbl_size;
            // argc lives at [SP], but the required entry bias differs by arch.
            let stack_rsp_bias: u64 = STACK_ENTRY_BIAS;
            let stack_base =
                (SCRATCH_VADDR + 4096 - srv_stack_frame_size - stack_rsp_bias) as *mut u64;

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

            w!(super::AT_PHDR);
            w!(phdr_vaddr);
            w!(super::AT_PHENT);
            w!(phent);
            w!(super::AT_PHNUM);
            w!(phnum);
            w!(super::AT_ENTRY);
            w!(elf_result.entry);
            w!(super::AT_BASE);
            w!(rtld_result.base);
            w!(super::AT_PAGESZ);
            w!(4096);
            w!(super::AT_TRONA_UNTYPED);
            w!(CAP_CHILD_UNTYPED_OFFSET);
            w!(super::AT_TRONA_VSPACE);
            w!(cap_layout.self_vspace);
            w!(super::AT_TRONA_SCRATCH);
            w!(layout.scratch.base);
            w!(super::AT_TRONA_INITRD);
            w!(layout.initrd.base);
            w!(super::AT_TRONA_INITRD_SZ);
            w!(initrd_size as u64);
            // Compute first free child CNode slot past extras and shared lib cache
            let frame_slot_start = {
                let mut s = cap_layout.frame_slot_start;
                for extra in extras {
                    if (extra.src != 0 || extra.dst != 0) && extra.dst + 1 > s {
                        s = extra.dst + 1;
                    }
                }
                let cache = &*(&raw const SHARED_LIB_CACHE);
                if copy_shared_lib_caps && cache.initialized && cache.page_count > 0 {
                    let cache_end = CAP_SHARED_LIB_CACHE_BASE + cache.page_count as u64;
                    if cache_end > s {
                        s = cache_end;
                    }
                }
                s
            };
            let effective_cnode_bits: u64 = if cnode_size_bits > 0 {
                cnode_size_bits
            } else {
                10
            };
            let cspace_layout = trona::layout::compute_cspace_layout(
                effective_cnode_bits,
                frame_slot_start,
                match spawn_role {
                    SpawnRole::Authority => trona::layout::CspaceLayoutProfile::BootstrapAuthority,
                    SpawnRole::Pager => trona::layout::CspaceLayoutProfile::Pager,
                    SpawnRole::Service => trona::layout::CspaceLayoutProfile::DefaultService,
                },
                has_procmgr_ep,
            );
            let cspace_layout_addr =
                (SCRATCH_VADDR + 4096 - cspace_layout_size) as *mut trona::TronaCspaceLayoutV1;
            let cspace_layout_child_addr = layout.stack_top - cspace_layout_size;
            core::ptr::write(cspace_layout_addr, cspace_layout);

            // Cap table sits immediately below the cspace layout in both
            // the scratch page and the child's stack view. Stamp the
            // builder's bytes into the scratch page and record the child
            // VA for the auxv writer below.
            let cap_tbl_scratch_addr =
                (SCRATCH_VADDR + 4096 - cspace_layout_size - cap_tbl_size) as *mut u8;
            let cap_tbl_child_addr = layout.stack_top - cspace_layout_size - cap_tbl_size;
            let _ = cap_tbl_builder.write_at(cap_tbl_scratch_addr);

            w!(super::AT_TRONA_CSPACE_LAYOUT);
            w!(cspace_layout_child_addr);
            w!(super::AT_TRONA_CAP_TABLE);
            w!(cap_tbl_child_addr);
            // Init's single child slot that doubles as the CSpace-expand
            // endpoint and the procmgr RPC endpoint is communicated to the
            // child through the cap_table as ROLE_PROCMGR_CONTROL — no
            // dedicated auxv tag needed.
            if let Some(cspace_ntfn_slot) = child_cspace_ntfn_slot {
                w!(super::AT_TRONA_CSPACE_NTFN);
                w!(cspace_ntfn_slot);
            }
            // All other role-bearing caps (MMSRV_CLIENT, RSRCSRV_CLIENT,
            // INITRD_UNTYPED, READINESS_NTFN, ...) now flow exclusively
            // through the cap_table — no legacy AT_TRONA_* emit needed.
            w!(super::AT_TRONA_IPC_BUFFER);
            w!(layout.ipc_buf.base);
            w!(super::AT_TRONA_SC_CAP);
            w!(cap_layout.sc);
            if shared_lib_base != 0 {
                w!(super::AT_TRONA_SHARED_LIB_BASE);
                w!(shared_lib_base);
            }
            w!(super::AT_NULL);
            w!(0);
            w!(0); // padding
            let _ = idx;

            invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

            child_rsp = layout.stack_top - srv_stack_frame_size - stack_rsp_bias;
            child_entry = rtld_result.entry;
        }

        #[cfg(target_arch = "aarch64")]
        trona::udebug!(|_lb| {
            _lb.str(b"[INIT] child layout ");
            _lb.bytes(label);
            _lb.str(b" entry=");
            _lb.hex(child_entry);
            _lb.str(b" stack=");
            _lb.hex(layout.stack.base);
            _lb.str(b"..");
            _lb.hex(layout.stack.base + layout.stack.page_count() as u64 * 4096);
            _lb.str(b" rsp=");
            _lb.hex(child_rsp);
            _lb.str(b" ipc=");
            _lb.hex(layout.ipc_buf.base);
            if shared_lib_base != 0 {
                _lb.str(b" shared=");
                _lb.hex(shared_lib_base);
            }
            _lb.str(b"\n");
        });

        let err = invoke::tcb_configure(child_tcb, child_entry, child_rsp, 0);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] TCB configure failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return -1;
        }

        invoke::tcb_set_ipc_buffer(child_tcb, layout.ipc_buf.base);

        let err = invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] SC configure failed\n");
            });
            return -1;
        }

        let err = invoke::sc_bind(child_sc, child_tcb);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] SC bind failed\n");
            });
            return -1;
        }

        // Register pre-procmgr child with mmsrv before first user instruction.
        // This guarantees posix_mmap()/brk() works immediately on service start.
        if mmsrv_ep != 0 {
            let heap_base = layout.elf_code.end();
            let mmap_base = trona::layout::compute_mmap_base(&layout, heap_base);
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = MM_REGISTER;
            mm_msg.length = 4;
            mm_msg.regs[0] = spawn_badge;
            mm_msg.regs[1] = heap_base;
            mm_msg.regs[2] = mmap_base;
            mm_msg.regs[3] = 0; // PID not assigned yet in init-spawn path
            ipc::set_send_cap_ctx(super::ipc_ctx(), 0, child_vs);
            let mm_err = ipc::call_ctx(
                super::ipc_ctx(),
                mmsrv_ep,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if mm_err != 0 || (mm_reply.label != TRONA_OK && mm_reply.label != TRONA_ALREADY_EXISTS)
            {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] WARN: MM_REGISTER ");
                    _lb.bytes(label);
                    _lb.str(b" failed err=");
                    _lb.hex(mm_err as u64);
                    _lb.str(b" label=");
                    _lb.hex(mm_reply.label);
                    _lb.str(b"\n");
                });
                return -1;
            }
        }

        let err = invoke::tcb_resume(child_tcb);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] TCB resume failed\n");
            });
            return -1;
        }

        // Register init-spawned service with procmgr (badge + CNode)
        let mut assigned_pid: u32 = 0;
        if procmgr_ep != 0 {
            let mut reg_msg = TronaMsg::zeroed();
            let mut reg_reply = TronaMsg::zeroed();
            reg_msg.label = PM_REGISTER;
            reg_msg.length = 3;
            reg_msg.regs[0] = spawn_badge;
            reg_msg.regs[1] = INIT_BADGE;
            // Init does not mint a bound CSpace-expansion notification into
            // its children (see child_cspace_ntfn_slot = None above); 0 tells
            // procmgr to skip installing a bound ntfn for this service.
            reg_msg.regs[2] = 0;
            // Transfer child CNode cap so procmgr can access child's untyped
            ipc::set_send_cap_ctx(super::ipc_ctx(), 0, child_cn);
            let reg_err = ipc::call_ctx(
                super::ipc_ctx(),
                procmgr_ep,
                &raw const reg_msg,
                &raw mut reg_reply,
            );
            if reg_err != 0 || reg_reply.label != TRONA_OK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] WARN: PM_REGISTER ");
                    _lb.bytes(label);
                    _lb.str(b" failed err=");
                    _lb.hex(reg_err as u64);
                    _lb.str(b" label=");
                    _lb.hex(reg_reply.label);
                    _lb.str(b"\n");
                });
                return -1;
            }
            assigned_pid = reg_reply.regs[0] as u32;
            if !registered_pid_out.is_null() {
                *registered_pid_out = assigned_pid;
            }
        }

        if wait_for_child_ready(
            child_tcb,
            child_ready_ntfn,
            label,
            effective_ready_timeout_ns,
        ) != 0
        {
            return -1;
        }

        // Authority spawns are init's last direct retype path. After the
        // child (rsrcsrv) has signalled ready, transfer ownership of all of
        // init's root untypeds to it via cnode_move. The kernel resolves
        // each cap by slot at retype time, so rsrcsrv's static
        // init_untyped_pool — which registers slots 16..31 as active sources
        // — only needs the caps to be present at the time it actually
        // services its first RES_ALLOC_OBJECT request.
        if spawn_role == SpawnRole::Authority {
            let mut moved: u64 = 0;
            let transfer_end = CAP_UNTYPED_START + UT_MIRROR_COUNT - INIT_WORK_UNTYPED_RESERVE;
            for ut_slot in CAP_UNTYPED_START..transfer_end {
                if ut_slot == CAP_INIT_INITRD_UNTYPED {
                    continue;
                }
                let merr = invoke::cnode_move(child_cn, ut_slot, CAP_SELF_CSPACE, ut_slot);
                if merr == 0 {
                    moved += 1;
                }
            }
            trona::uinfo!(|_lb| {
                _lb.str(b"[INIT] transferred ");
                _lb.dec(moved);
                _lb.str(b" root untypeds to rsrcsrv\n");
            });
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[INIT] ");
            _lb.bytes(label);
            _lb.str(b" ready\n");
        });
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
    start_suspended: bool,
) -> i32 {
    unsafe {
        let len = prog.len();

        let readiness = match def.svc_type {
            super::ini::ServiceType::Notify => SPAWN_READY_NOTIFY,
            super::ini::ServiceType::Simple => SPAWN_READY_IMMEDIATE,
            // Target units are bootstrap milestones and are filtered out by init
            // before they reach the process spawn path.
            super::ini::ServiceType::Target => SPAWN_READY_IMMEDIATE,
        };
        let mut is_display = false;
        for i in 0..def.require_count as usize {
            let req = def.requires[i];
            if req.role_id == trona::consts::kernel::ROLE_FB_UNTYPED {
                is_display = true;
                break;
            }
        }
        let policy = spawn_policy_build(
            readiness,
            def.map_initrd,
            is_display,
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
        if start_suspended {
            spawn_flags |= SPAWN_FLAG_START_SUSPENDED;
        }
        let mut spawn_msg = TronaMsg::zeroed();
        spawn_msg.label = PM_SPAWN;
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

        let mut spawn_reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            super::ipc_ctx(),
            pm_ep,
            &raw const spawn_msg,
            &raw mut spawn_reply,
        );
        if err != 0 || spawn_reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] pm_spawn IPC failed err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(spawn_reply.label);
                _lb.str(b"\n");
            });
            if err != 0 {
                return -((err & 0x7fff_ffff) + 1);
            }
            return -((spawn_reply.label as i32 & 0x7fff_ffff) + 1);
        }

        spawn_reply.regs[0] as i32
    }
}

/// Ship the parsed post-procmgr service definitions to procmgr in one shot
/// (option 5 — boot-time registry transfer).
///
/// Init has already parsed every `.service` file in the initrd into
/// `mgr.services[..]`. Pre-procmgr services it spawns directly. Post-procmgr
/// services need their `Require=` entries resolved by procmgr at spawn time;
/// rather than re-parsing on procmgr's side, init narrows each parsed
/// `RequireDef` to the wire shape `TronaProcmgrRequireV1` (drops `alias`),
/// packs them into a single 4 KiB frame, and transfers the frame cap via
/// `PM_REGISTER_SERVICE_DEFS`.
///
/// Returns 0 on success, negative on failure. Must be called exactly once,
/// after procmgr is up and before the first `pm_spawn` for a post-procmgr
/// service.
pub unsafe fn pm_register_service_defs(
    pm_ep: Cap,
    bootstrap_authority_ep: Cap,
    mgr: &super::svc_mgr::ServiceManager,
) -> i32 {
    unsafe {
        if pm_ep == 0 {
            return -1;
        }

        // Allocate a fresh frame slot. Once rsrcsrv is up, ask it for the
        // backing frame so init does not depend on retaining spare root
        // untypeds for this one-shot metadata transfer.
        let frame_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
        let retype_err = if bootstrap_authority_ep != 0 {
            ipc::set_receive_slot_ctx(super::ipc_ctx(), CAP_SELF_CSPACE, frame_slot, 0);
            let mut req = TronaMsg::zeroed();
            req.label = RES_ALLOC_OBJECT;
            req.length = 4;
            req.regs[0] = INIT_BADGE;
            req.regs[1] = OBJ_FRAME;
            req.regs[2] = 0;
            req.regs[3] = 0;
            let mut resp = TronaMsg::zeroed();
            let call_err = ipc::call_ctx(
                super::ipc_ctx(),
                bootstrap_authority_ep,
                &raw const req,
                &raw mut resp,
            );
            if call_err != 0 {
                call_err
            } else {
                resp.label as i32
            }
        } else {
            retype_from_any_untyped(OBJ_FRAME, 0, frame_slot)
        };
        if retype_err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] pm_register_service_defs: frame retype err=");
                _lb.hex(retype_err as u64);
                _lb.str(b"\n");
            });
            return -2;
        }

        // Map the frame at SCRATCH_VADDR for serialization. SCRATCH_VADDR is
        // owned by init and reused across one-shot scratch operations; the
        // unmap below releases it again.
        let map_err = invoke::vspace_map(
            CAP_SELF_VSPACE,
            frame_slot,
            SCRATCH_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if map_err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] pm_register_service_defs: scratch map err=");
                _lb.hex(map_err as u64);
                _lb.str(b"\n");
            });
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);
            return -3;
        }

        let scratch = SCRATCH_VADDR as *mut u8;
        for i in 0..4096usize {
            core::ptr::write_volatile(scratch.add(i), 0u8);
        }

        let header = scratch as *mut TronaProcmgrServiceDefsV1;
        core::ptr::write_volatile(&raw mut (*header).magic, TRONA_PROCMGR_DEFS_MAGIC);
        core::ptr::write_volatile(&raw mut (*header).version, TRONA_PROCMGR_DEFS_VERSION);
        core::ptr::write_volatile(&raw mut (*header).reserved, 0u32);

        let header_size = core::mem::size_of::<TronaProcmgrServiceDefsV1>();
        let entry_size = core::mem::size_of::<TronaProcmgrServiceDefV1>();
        let entries_dst = scratch.add(header_size) as *mut TronaProcmgrServiceDefV1;

        let mut count: u32 = 0;
        for i in 0..mgr.count {
            let def = &mgr.services[i].def;
            // Pre-procmgr services are spawned by init itself; procmgr never
            // sees them in `pm_spawn` so the registry can skip them.
            if def.pre_procmgr {
                continue;
            }
            // Targets are bootstrap milestones, not real spawnable services.
            if def.svc_type == super::ini::ServiceType::Target {
                continue;
            }
            // Defensive: never ship procmgr's own def, even if the manifest
            // forgets `PreProcmgr=yes`.
            if def.name_bytes() == b"procmgr" {
                continue;
            }

            if (count as usize) >= MAX_PROCMGR_SERVICE_DEFS {
                trona::uerror!(|_lb| {
                    _lb.str(
                        b"[INIT] pm_register_service_defs: too many post-procmgr services (max ",
                    );
                    _lb.dec(MAX_PROCMGR_SERVICE_DEFS as u64);
                    _lb.str(b")\n");
                });
                let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);
                let _ = invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);
                return -4;
            }
            if (def.require_count as usize) > MAX_PROCMGR_REQUIRES {
                trona::uerror!(|_lb| {
                    _lb.str(b"[INIT] pm_register_service_defs: ");
                    _lb.bytes(def.name_bytes());
                    _lb.str(b" has ");
                    _lb.dec(def.require_count as u64);
                    _lb.str(b" Require= entries, exceeds wire max ");
                    _lb.dec(MAX_PROCMGR_REQUIRES as u64);
                    _lb.str(b"\n");
                });
                let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);
                let _ = invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);
                return -5;
            }

            let mut entry = TronaProcmgrServiceDefV1::zeroed();
            let name = def.name_bytes();
            let name_n = name.len().min(MAX_REQUIRE_PROVIDER);
            for j in 0..name_n {
                entry.name[j] = name[j];
            }
            entry.name_len = name_n as u8;
            entry.bootstrap_privileged = if def.bootstrap_privileged { 1 } else { 0 };
            entry.require_count = def.require_count;

            // Narrow each parsed RequireDef to the wire shape — drop `alias`,
            // keep everything procmgr needs to look the cap up later.
            for r in 0..(def.require_count as usize) {
                let src = &def.requires[r];
                let dst = &mut entry.requires[r];
                let plen = (src.provider_len as usize).min(MAX_REQUIRE_PROVIDER);
                for j in 0..plen {
                    dst.provider[j] = src.provider[j];
                }
                dst.provider_len = plen as u8;
                dst.kind = src.kind;
                dst.badged = src.badged;
                dst.raw = src.raw;
                dst.role_id = src.role_id;
            }

            core::ptr::write_volatile(entries_dst.add(count as usize), entry);
            count += 1;
        }

        core::ptr::write_volatile(&raw mut (*header).count, count);

        let payload_bytes = header_size + (count as usize) * entry_size;

        // Unmap from init's vspace before transferring; the receiver will map
        // its own copy at procmgr's scratch VA.
        let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

        // Stage the frame cap for transfer in caps[0].
        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, frame_slot);

        let mut req = TronaMsg::zeroed();
        req.label = PM_REGISTER_SERVICE_DEFS;
        req.length = 1;
        req.regs[0] = payload_bytes as u64;

        let mut reply = TronaMsg::zeroed();
        let perr = ipc::call_ctx(super::ipc_ctx(), pm_ep, &raw const req, &raw mut reply);

        // Procmgr receives a copy of the cap (kernel cnode_copy semantics).
        // Init's slot still holds the original; delete it now so the slot is
        // free. The frame's backing memory is leaked into procmgr's untyped
        // pool — acceptable for a one-shot 4 KiB transfer at boot.
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, frame_slot);

        if perr != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] pm_register_service_defs: PM ack err=");
                _lb.hex(perr as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return -6;
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[INIT] pm_register_service_defs: ");
            _lb.dec(count as u64);
            _lb.str(b" defs transferred (");
            _lb.dec(payload_bytes as u64);
            _lb.str(b" B)\n");
        });
        0
    }
}

/// Register a single pre-procmgr provider with procmgr via
/// `PM_REGISTER_PROVIDER`. The cap is transferred to procmgr (procmgr
/// makes its own copy at a permanent slot); init's slot is unaffected.
///
/// `name` is the provider service name (e.g. `b"console"`); init does not
/// filter by what procmgr already has — procmgr's handler is idempotent.
/// Returns 0 on success or success-equivalent (already registered).
pub unsafe fn pm_register_provider(pm_ep: Cap, name: &[u8], cap: Cap) -> i32 {
    unsafe {
        if pm_ep == 0 || cap == 0 || name.is_empty() || name.len() > MAX_REQUIRE_PROVIDER {
            return -1;
        }

        let mut req = TronaMsg::zeroed();
        req.label = PM_REGISTER_PROVIDER;
        req.regs[0] = name.len() as u64;
        let name_words = (name.len() + 7) / 8;
        req.length = 1 + name_words as u64;
        let dst = &raw mut req.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }

        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, cap);

        let mut reply = TronaMsg::zeroed();
        let perr = ipc::call_ctx(super::ipc_ctx(), pm_ep, &raw const req, &raw mut reply);
        if perr != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| {
                _lb.str(b"[INIT] pm_register_provider: ");
                _lb.bytes(name);
                _lb.str(b" failed err=");
                _lb.hex(perr as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return -2;
        }
        0
    }
}

/// Register every pre-procmgr service that has a non-zero `pre_ep` (i.e.
/// init created and currently holds the listener EP for it). Procmgr's
/// `PM_REGISTER_PROVIDER` handler is idempotent — services that procmgr
/// already has via its own `NeedEP=` (namesrv/vfs/mmsrv/rsrcsrv) are
/// silently ignored on the procmgr side, so init does not need to filter.
///
/// Procmgr itself is skipped — it is not its own provider.
///
/// Returns the number of provider entries successfully registered (0 on
/// total failure but no hard error — boot continues so non-essential
/// providers do not gate the system).
pub unsafe fn pm_register_pre_procmgr_providers(
    pm_ep: Cap,
    mgr: &super::svc_mgr::ServiceManager,
) -> u32 {
    unsafe {
        if pm_ep == 0 {
            return 0;
        }
        let mut count: u32 = 0;
        for i in 0..mgr.count {
            let svc = &mgr.services[i];
            let def = &svc.def;
            if !def.pre_procmgr {
                continue;
            }
            if def.svc_type == super::ini::ServiceType::Target {
                continue;
            }
            if svc.pre_ep == 0 {
                continue;
            }
            let name = def.name_bytes();
            if name == b"procmgr" {
                continue;
            }
            if super::ini::system_role_for_needep(name, false).is_some()
                || super::ini::system_role_for_needep(name, true).is_some()
            {
                // procmgr already has bootstrap system-role providers via its own
                // NeedEP slots; only register non-system pre-procmgr services here.
                continue;
            }
            let r = pm_register_provider(pm_ep, name, svc.pre_ep);
            if r == 0 {
                count += 1;
            }
        }
        trona::uinfo!(|_lb| {
            _lb.str(b"[INIT] pm_register_pre_procmgr_providers: ");
            _lb.dec(count as u64);
            _lb.str(b" providers registered\n");
        });
        count
    }
}

/// Resume a procmgr-managed child that was spawned with START_SUSPENDED.
/// Uses PM_RESUME so boot sequencing is not coupled to signal semantics.
pub unsafe fn pm_resume_child(pm_ep: Cap, pid: u32) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        msg.label = PM_RESUME;
        msg.length = 1;
        msg.regs[0] = pid as u64;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(super::ipc_ctx(), pm_ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            -1
        } else {
            0
        }
    }
}

/// Inject a capability into a procmgr-managed child's CSpace.
/// Uses PM_INJECT_CAP IPC to have procmgr copy the cap into the child.
pub unsafe fn pm_inject_cap(pm_ep: Cap, pid: u32, dst_slot: u64, cap: Cap, badge: u64) -> i32 {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        msg.label = PM_INJECT_CAP;
        msg.length = 3;
        msg.regs[0] = pid as u64;
        msg.regs[1] = dst_slot;
        msg.regs[2] = badge;
        ipc::set_send_cap_ctx(super::ipc_ctx(), 0, cap);

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(super::ipc_ctx(), pm_ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            -1
        } else {
            0
        }
    }
}
