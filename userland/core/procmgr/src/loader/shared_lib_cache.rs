//! Shared library physical frame cache
//!
//! Pre-loads shared library RO segments into permanent MO-backed storage and
//! maps them (plus per-child RW copies) into child VSpaces at spawn time.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;

use crate::base::alloc::Allocator;
use crate::base::proc_table;

const VSPACE_FLAG_WRITABLE: u64 = trona::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = trona::VSPACE_FLAG_USER;
const VSPACE_FLAG_EXECUTABLE: u64 = trona::VSPACE_FLAG_EXECUTABLE;
const CAP_SELF_VSPACE: Cap = crate::CAP_SELF_VSPACE;
const PROCMGR_SCRATCH_VADDR: u64 = crate::PROCMGR_SCRATCH_VADDR;

const MAX_SHARED_LIB_PAGES: usize = 2048;
pub(crate) const MAX_CACHED_LIBS: usize = 8;
const MAX_LIB_NAME: usize = 24;

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
        RoSegInfo {
            vaddr_offset: 0,
            mo_page_start: 0,
            page_count: 0,
            flags: 0,
        }
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
    /// For VFS-loaded libraries: persistent mmap'd file data used by
    /// `map_rw_segments` on every spawn. NULL for CPIO-backed libs
    /// (those read directly from the initrd).
    vfs_file_data: *const u8,
    vfs_file_data_len: usize,
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
            vfs_file_data: core::ptr::null(),
            vfs_file_data_len: 0,
        }
    }
}

pub(crate) struct SharedLibCache {
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

pub(crate) static mut SHARED_LIB_CACHE: SharedLibCache = SharedLibCache::new();

/// Return the total VA pages needed for the specified DT_NEEDED libraries.
/// Accounts for full library spans (including RW segments) plus inter-lib gaps.
/// Libraries not yet in the cache (potential VFS loads) get a conservative
/// default reservation of 512 KiB each.
pub(crate) fn shared_lib_va_pages_for_needed(
    needed: &trona_loader::elf_dynamic::NeededLibs,
) -> usize {
    unsafe {
        let cache = &*(&raw const SHARED_LIB_CACHE);
        if needed.count == 0 {
            return 0;
        }
        // Even if the cache is uninitialized, reserve space for VFS libs.
        let mut total_bytes: u64 = 0;
        for ni in 0..needed.count {
            let name = &needed.names[ni][..needed.name_lens[ni]];
            let mut found = false;
            if cache.initialized {
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
                            total_bytes += cl.lib_span + 4096;
                            found = true;
                            break;
                        }
                    }
                }
            }
            if !found {
                // Conservative estimate for VFS-loaded libraries
                total_bytes += (512 * 1024) + 4096;
            }
        }
        ((total_bytes + 0xFFF) / 0x1000) as usize
    }
}

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
            if trona_loader::cpio::cpio_next(initrd, initrd_size, &raw mut offset, &raw mut entry)
                == 0
            {
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

/// Pre-load shared library RO segments into a permanent MO-backed cache.
/// Parses each library's ELF, creates MOs for RO segments, and records metadata.
pub(crate) unsafe fn init_shared_lib_cache(alloc: &mut Allocator) {
    unsafe {
        let cache = &mut *(&raw mut SHARED_LIB_CACHE);

        let initrd = crate::INITRD_VADDR as *const u8;
        let initrd_size = crate::read_boot_info_initrd_size();

        // Build MO-backed shared library cache from initrd.
        // For each library: parse ELF, create MO, populate RO pages
        // from the initrd, record RW segment metadata.
        // Names are bare sonames — the "lib/" prefix is added only for CPIO lookup.
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
                        if el_name[k] != lib_name[k] {
                            eq = false;
                            break;
                        }
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
            if already_has_mo {
                continue;
            }

            // Build CPIO path: "lib/" + soname
            let mut cpio_path = [0u8; 64];
            let cpio_path_len =
                trona_loader::elf_dynamic::build_initrd_lib_path(lib_name, &mut cpio_path);
            if cpio_path_len == 0 {
                continue;
            }

            let mut entry = CpioEntry::zeroed();
            if trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                cpio_path.as_ptr(),
                cpio_path_len,
                &raw mut entry,
            ) == 0
            {
                continue;
            }

            let Some(lib_info) =
                trona_loader::elf_dynamic::elf_compute_lib_info(entry.data, entry.data_len)
            else {
                continue;
            };
            let min_vaddr = lib_info.min_vaddr;
            let lib_span = lib_info.lib_span;
            let ehdr = &*(entry.data as *const Elf64Ehdr);
            let phdrs = entry.data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;

            // --- Pass 1: count RO pages (compact) and record RW/RO segment metadata ---
            // MO pages are packed contiguously (no gaps). Each RO segment
            // records its vaddr_offset and mo_page_start so map_shared_libs
            // can issue per-segment vspace_map_mo calls at correct VAs.
            let mut ro_page_count: usize = 0;
            let mut ro_base_offset: u64 = u64::MAX;
            let mut ro_flags: u64 = VSPACE_FLAG_USER;
            let min_vaddr_aligned = min_vaddr & !0xFFFu64;

            // Update inherited entry in-place or append new entry
            let li = if inherited_idx != usize::MAX {
                inherited_idx
            } else {
                cache.lib_count
            };
            let mut lib_entry = if inherited_idx != usize::MAX {
                cache.libs[inherited_idx]
            } else {
                CachedLib::zeroed()
            };
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
            lib_entry.ro_seg_count = 0;

            for i in 0..ehdr.e_phnum as usize {
                let ph = &*phdrs.add(i);
                if ph.p_type != trona::PT_LOAD {
                    continue;
                }

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
                if vaddr_offset < ro_base_offset {
                    ro_base_offset = vaddr_offset;
                }

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
                    if ro_end > rw_start && lib_entry.ro_segs[ri].vaddr_offset < rw_start {
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
            if ro_base_offset == u64::MAX {
                ro_base_offset = 0;
            }

            // --- Pass 2: allocate MO and populate from initrd ---
            let mut sb: u64 = 0;
            while (1u64 << sb) < ro_page_count as u64 {
                sb += 1;
            }

            // Allocate MO via rsrcsrv. owner_id=0 means rsrcsrv treats the
            // caller (procmgr) as the owner.
            let (mo_slot, mo_handle) = match crate::base::alloc::alloc_single(
                trona::caps::rsrcsrv_ep(),
                0,
                trona::OBJ_MEMORY_OBJECT,
                sb,
            ) {
                Ok(t) => t,
                Err(_) => continue,
            };

            // Commit all RO pages via the kernel PMM path (ut_cap=0). The
            // shared-library cache is initialised before mmsrv is up, so we
            // can't ask mmsrv to back the frames; the kernel PMM is the
            // canonical fallback the design relies on for this case.
            let (err, committed) = trona::invoke::mo_commit(mo_slot, 0, ro_page_count as u64, 0);
            if err != 0 || committed != ro_page_count as u64 {
                let _ = crate::base::alloc::free_handle(trona::caps::rsrcsrv_ep(), 0, mo_handle);
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
                    let err =
                        trona::invoke::vspace_map_mo(CAP_SELF_VSPACE, mo_slot, scratch, mo_pi, cf);
                    if err != 0 {
                        populate_ok = false;
                        break;
                    }

                    let dst = scratch as *mut u8;
                    crate::loader::mem_util::volatile_zero(dst, 4096);

                    // Copy file content
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
                            crate::loader::mem_util::volatile_copy(dst.add(page_offset), src, copy_len);
                        }
                    }

                    trona::invoke::vspace_unmap(CAP_SELF_VSPACE, scratch);
                    mo_pi += 1;
                    page += 4096;
                }
                if !populate_ok {
                    break;
                }
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

/// Map a single cached library (at index `li`) into a child VSpace.
/// Handles RO segment mapping (MO or per-page), RW segment mapping
/// (per-child private copy via mmsrv), and mmsrv shared-region registration.
/// Records the mapping in `lib_map`. Returns false on fatal error.
unsafe fn map_cached_lib_to_child(
    cache: &SharedLibCache,
    li: usize,
    child_vs: Cap,
    running_base: u64,
    pid: u32,
    lib_map: &mut proc_table::ProcLibMap,
) -> bool {
    unsafe {
        let cl = &cache.libs[li];

        // Record in ProcLibMap
        if (lib_map.count as usize) < proc_table::MAX_PROC_MAPPED_LIBS {
            lib_map.lib_idx[lib_map.count as usize] = li as u8;
            lib_map.base[lib_map.count as usize] = running_base;
            lib_map.count += 1;
        }

        // Map RO pages
        let ps = cl.page_start as usize;
        let pc = cl.page_count as usize;

        if cl.ro_mo_cap != 0 {
            for si in 0..cl.ro_seg_count as usize {
                let seg = &cl.ro_segs[si];
                let seg_vaddr = running_base + seg.vaddr_offset;
                let count_and_flags = ((seg.page_count as u64) << 32) | seg.flags;
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
                    return false;
                }
            }
        } else {
            for pi in 0..pc {
                let page = &cache.pages[ps + pi];
                let vaddr = running_base + page.vaddr_offset;
                let err = trona::invoke::vspace_map(child_vs, page.frame_cap, vaddr, page.flags);
                if err != 0 {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] shared lib map failed at ");
                        _lb.hex(vaddr);
                        _lb.str(b" err=");
                        _lb.hex(err as u64);
                        _lb.str(b"\n");
                    });
                    return false;
                }
            }
        }

        // Map RW segments (per-child private copies via mmsrv)
        if !map_rw_segments(cl, running_base, pid) {
            return false;
        }

        // Register each RO segment with mmsrv
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
            sr_msg.regs[4] = seg.mo_page_start as u64;
            sr_msg.regs[5] = seg.flags;

            if cl.ro_mo_cap != 0 {
                trona::ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, cl.ro_mo_cap);
            }
            let _ = trona::ipc::call_ctx(
                crate::ipc_ctx(),
                trona::caps::mmsrv_ep(),
                &raw const sr_msg,
                &raw mut sr_reply,
            );
        }

        true
    }
}

/// Try to load a shared library from VFS (/lib/<name>, /usr/lib/<name>),
/// parse its ELF structure, create an MO for RO segments, populate it,
/// and add the result to SHARED_LIB_CACHE. Returns the cache index on success.
unsafe fn try_load_and_cache_vfs_lib(name: &[u8]) -> Option<usize> {
    unsafe {
        let cache = &mut *(&raw mut SHARED_LIB_CACHE);
        if cache.lib_count >= MAX_CACHED_LIBS {
            return None;
        }

        // Build search paths and try to load
        let name_len = name.len();
        if name_len == 0 || name_len > 64 {
            return None;
        }

        let prefixes: [&[u8]; 2] = [b"/lib/", b"/usr/lib/"];
        let mut vfs_result: Option<crate::loader::vfs_load::VfsLoadResult> = None;

        for prefix in &prefixes {
            let mut path_buf = [0u8; 128];
            let path_len = prefix.len() + name_len;
            if path_len >= path_buf.len() {
                continue;
            }
            for i in 0..prefix.len() {
                path_buf[i] = prefix[i];
            }
            for i in 0..name_len {
                path_buf[prefix.len() + i] = name[i];
            }
            // try_load_from_vfs expects the path to start with '/',
            // which our constructed paths do.
            if let Some(result) = crate::loader::vfs_load::try_load_from_vfs(&path_buf, path_len) {
                vfs_result = Some(result);
                break;
            }
        }

        let vfs_buf = vfs_result?;

        // Validate ELF and compute VA layout
        let Some(lib_info) =
            trona_loader::elf_dynamic::elf_compute_lib_info(vfs_buf.data, vfs_buf.data_len)
        else {
            crate::loader::vfs_load::cleanup_vfs_load(vfs_buf.data, vfs_buf.alloc_size);
            return None;
        };
        let min_vaddr = lib_info.min_vaddr;
        let min_vaddr_aligned = min_vaddr & !0xFFFu64;
        let lib_span = lib_info.lib_span;
        let ehdr = &*(vfs_buf.data as *const Elf64Ehdr);
        let phdrs = vfs_buf.data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;

        // Build CachedLib metadata
        let li = cache.lib_count;
        let mut lib_entry = CachedLib::zeroed();
        let copy_len = if name_len > MAX_LIB_NAME {
            MAX_LIB_NAME
        } else {
            name_len
        };
        for j in 0..copy_len {
            lib_entry.name[j] = name[j];
        }
        lib_entry.name_len = copy_len as u8;
        lib_entry.lib_span = lib_span;

        let mut ro_page_count: usize = 0;
        let mut ro_base_offset: u64 = u64::MAX;
        let mut ro_flags: u64 = VSPACE_FLAG_USER;

        for i in 0..ehdr.e_phnum as usize {
            let ph = &*phdrs.add(i);
            if ph.p_type != trona::PT_LOAD {
                continue;
            }

            if (ph.p_flags & trona::PF_W) != 0 {
                if (lib_entry.rw_seg_count as usize) < MAX_RW_SEGS {
                    let idx = lib_entry.rw_seg_count as usize;
                    lib_entry.rw_segs[idx] = RwSegInfo {
                        vaddr_offset: (ph.p_vaddr & !0xFFFu64) - min_vaddr_aligned,
                        file_offset: ph.p_offset,
                        file_size: ph.p_filesz,
                        seg_vaddr: ph.p_vaddr,
                        memsz: ph.p_memsz,
                        flags: VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                    };
                    lib_entry.rw_seg_count += 1;
                }
                continue;
            }

            // RO segment
            let seg_start = ph.p_vaddr & !0xFFFu64;
            let seg_end = (ph.p_vaddr + ph.p_memsz + 0xFFF) & !0xFFFu64;
            let seg_pages = ((seg_end - seg_start) / 4096) as usize;
            let vaddr_offset = seg_start - min_vaddr_aligned;
            let seg_flags = if (ph.p_flags & trona::PF_X) != 0 {
                VSPACE_FLAG_USER | VSPACE_FLAG_EXECUTABLE
            } else {
                VSPACE_FLAG_USER
            };
            if vaddr_offset < ro_base_offset {
                ro_base_offset = vaddr_offset;
            }

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

        // Resolve RO/RW boundary page overlaps
        for ri in 0..lib_entry.ro_seg_count as usize {
            let ro_end = lib_entry.ro_segs[ri].vaddr_offset
                + (lib_entry.ro_segs[ri].page_count as u64) * 4096;
            for wi in 0..lib_entry.rw_seg_count as usize {
                let rw_start = lib_entry.rw_segs[wi].vaddr_offset;
                if ro_end > rw_start && lib_entry.ro_segs[ri].vaddr_offset < rw_start {
                    let overlap = ((ro_end - rw_start) / 4096) as u16;
                    if overlap > 0 && overlap <= lib_entry.ro_segs[ri].page_count {
                        lib_entry.ro_segs[ri].page_count -= overlap;
                        ro_page_count -= overlap as usize;
                    }
                }
            }
        }

        if ro_base_offset == u64::MAX {
            ro_base_offset = 0;
        }

        // Create MO and populate RO pages from VFS file data
        if ro_page_count > 0 {
            let alloc = &mut *(&raw mut crate::ALLOCATOR);
            let mut sb: u64 = 0;
            while (1u64 << sb) < ro_page_count as u64 {
                sb += 1;
            }

            // Allocate MO via rsrcsrv. owner_id=0 → procmgr's own badge.
            let (mo_slot, mo_handle) = match crate::base::alloc::alloc_single(
                trona::caps::rsrcsrv_ep(),
                0,
                trona::OBJ_MEMORY_OBJECT,
                sb,
            ) {
                Ok(t) => t,
                Err(_) => {
                    crate::loader::vfs_load::cleanup_vfs_load(vfs_buf.data, vfs_buf.alloc_size);
                    return None;
                }
            };

            // Commit all RO pages via the kernel PMM path (ut_cap=0).
            let (err, committed) = trona::invoke::mo_commit(mo_slot, 0, ro_page_count as u64, 0);
            if err != 0 || committed != ro_page_count as u64 {
                let _ = crate::base::alloc::free_handle(trona::caps::rsrcsrv_ep(), 0, mo_handle);
                crate::loader::vfs_load::cleanup_vfs_load(vfs_buf.data, vfs_buf.alloc_size);
                return None;
            }

            // Copy content from VFS buffer into MO pages
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
                    let cf = (1u64 << 32) | VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
                    let merr =
                        trona::invoke::vspace_map_mo(CAP_SELF_VSPACE, mo_slot, scratch, mo_pi, cf);
                    if merr != 0 {
                        populate_ok = false;
                        break;
                    }

                    let dst = scratch as *mut u8;
                    crate::loader::mem_util::volatile_zero(dst, 4096);

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
                        let clen = (copy_end - copy_start) as usize;
                        if data_offset + clen <= vfs_buf.data_len {
                            let src = vfs_buf.data.add(data_offset);
                            crate::loader::mem_util::volatile_copy(dst.add(page_offset), src, clen);
                        }
                    }

                    trona::invoke::vspace_unmap(CAP_SELF_VSPACE, scratch);
                    mo_pi += 1;
                    page += 4096;
                }
                if !populate_ok {
                    break;
                }
            }

            if !populate_ok {
                alloc.free_single_slot(mo_slot);
                crate::loader::vfs_load::cleanup_vfs_load(vfs_buf.data, vfs_buf.alloc_size);
                return None;
            }

            lib_entry.page_count = ro_page_count as u16;
            lib_entry.ro_mo_cap = mo_slot;
            lib_entry.ro_flags = ro_flags;
            lib_entry.ro_base_offset = ro_base_offset;
        }

        // Store VFS file data permanently for RW segment population on future spawns.
        // The mmap'd buffer is NOT freed — it stays alive for the lifetime of procmgr.
        lib_entry.vfs_file_data = vfs_buf.data;
        lib_entry.vfs_file_data_len = vfs_buf.data_len;

        cache.libs[li] = lib_entry;
        cache.lib_count += 1;
        cache.page_count += ro_page_count;
        cache.initialized = true;

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] VFS lib cached: ");
            _lb.bytes(name);
            _lb.str(b" RO=");
            _lb.hex(ro_page_count as u64);
            _lb.str(b" span=");
            _lb.hex(lib_span);
            _lb.str(b"\n");
        });

        Some(li)
    }
}

/// Map cached shared library frames into a child VSpace, mapping only
/// libraries listed in `needed` in their DT_NEEDED order.
/// RO pages are mapped from the shared frame cache (shared across processes).
/// RW pages are allocated per-child via mmsrv copy transactions and populated
/// from the initrd or VFS file data; BSS is zeroed.
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
        if shared_lib_base_vaddr == 0 {
            return (0, empty);
        }
        if needed.count == 0 {
            return (0, empty);
        }

        let mut lib_map = proc_table::ProcLibMap::zeroed();
        let mut running_base = shared_lib_base_vaddr;

        // BFS queue: start with the executable's direct DT_NEEDED,
        // then append transitive dependencies from loaded libraries.
        let mut queue = *needed; // copy — we will extend it
        let mut qi: usize = 0;

        while qi < queue.count {
            let name = &queue.names[qi][..queue.name_lens[qi]];
            qi += 1;

            // Find this library in the cache
            let cache = &*(&raw const SHARED_LIB_CACHE);
            let mut cache_idx: Option<usize> = None;
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
                        cache_idx = Some(li);
                        break;
                    }
                }
            }

            // VFS fallback: load from filesystem and add to cache
            if cache_idx.is_none() {
                cache_idx = try_load_and_cache_vfs_lib(name);
            }

            let Some(li) = cache_idx else {
                trona::udebug!(|_lb| {
                    _lb.str(b"[PROCMGR] shared lib not found (cache or VFS): ");
                    _lb.bytes(name);
                    _lb.str(b"\n");
                });
                continue;
            };

            // Map the cached library into the child
            let cache = &*(&raw const SHARED_LIB_CACHE);
            if !map_cached_lib_to_child(cache, li, child_vs, running_base, pid, &mut lib_map) {
                return (0, empty);
            }
            running_base += cache.libs[li].lib_span + 4096;

            // Parse the loaded library's DT_NEEDED for transitive deps.
            // Use the cached file data (VFS buffer or CPIO) to read the
            // ELF .dynamic section and enqueue any new dependencies.
            let cl = &cache.libs[li];
            let elf_data: *const u8;
            let elf_data_len: usize;
            if !cl.vfs_file_data.is_null() && cl.vfs_file_data_len > 0 {
                elf_data = cl.vfs_file_data;
                elf_data_len = cl.vfs_file_data_len;
            } else {
                // CPIO-backed: re-lookup in initrd.
                // cl.name is a bare soname — prepend "lib/" for CPIO lookup.
                let initrd = crate::INITRD_VADDR as *const u8;
                let initrd_size = crate::read_boot_info_initrd_size();
                let lib_soname = &cl.name[..cl.name_len as usize];
                let mut cpio_lib_path = [0u8; 64];
                let cpio_lib_path_len = trona_loader::elf_dynamic::build_initrd_lib_path(
                    lib_soname,
                    &mut cpio_lib_path,
                );
                let mut cpio_entry = CpioEntry::zeroed();
                if cpio_lib_path_len != 0
                    && trona_loader::cpio::cpio_find_file(
                        initrd,
                        initrd_size,
                        cpio_lib_path.as_ptr(),
                        cpio_lib_path_len,
                        &raw mut cpio_entry,
                    ) != 0
                {
                    elf_data = cpio_entry.data;
                    elf_data_len = cpio_entry.data_len;
                } else {
                    // No file data available — skip transitive dep scan
                    continue;
                }
            }

            if elf_data_len >= core::mem::size_of::<Elf64Ehdr>() {
                let dep_ehdr = &*(elf_data as *const Elf64Ehdr);
                if dep_ehdr.e_ident[0] == 0x7F
                    && dep_ehdr.e_ident[1] == b'E'
                    && dep_ehdr.e_ident[2] == b'L'
                    && dep_ehdr.e_ident[3] == b'F'
                {
                    let dep_needed =
                        trona_loader::elf_dynamic::elf_get_needed(elf_data, elf_data_len);
                    for dni in 0..dep_needed.count {
                        let dep_name = &dep_needed.names[dni][..dep_needed.name_lens[dni]];
                        // Skip if already in the queue
                        if !queue.contains(dep_name) {
                            queue.add(dep_name);
                        }
                    }
                }
            }
        }

        if lib_map.count > 0 || running_base > shared_lib_base_vaddr {
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

        // Resolve ELF file data: VFS-backed libs have persistent file data;
        // CPIO-backed libs read from the initrd.
        let elf_data: *const u8;
        let elf_data_len: usize;
        let mut cpio_entry = CpioEntry::zeroed();

        if !cl.vfs_file_data.is_null() && cl.vfs_file_data_len > 0 {
            elf_data = cl.vfs_file_data;
            elf_data_len = cl.vfs_file_data_len;
        } else {
            let initrd = crate::INITRD_VADDR as *const u8;
            let initrd_size = crate::read_boot_info_initrd_size();
            // cl.name is a bare soname — prepend "lib/" for CPIO lookup
            let lib_soname = &cl.name[..cl.name_len as usize];
            let mut rw_cpio_path = [0u8; 64];
            let rw_cpio_len =
                trona_loader::elf_dynamic::build_initrd_lib_path(lib_soname, &mut rw_cpio_path);
            if rw_cpio_len == 0
                || trona_loader::cpio::cpio_find_file(
                    initrd,
                    initrd_size,
                    rw_cpio_path.as_ptr(),
                    rw_cpio_len,
                    &raw mut cpio_entry,
                ) == 0
            {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] RW map: lib not found\n");
                });
                return false;
            }
            elf_data = cpio_entry.data;
            elf_data_len = cpio_entry.data_len;
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

        let stage = crate::loader::mem_util::alloc_staging_buffer(merged_pages);
        if stage.is_null() {
            return false;
        }

        let status = (|| -> bool {
            crate::loader::mem_util::volatile_zero(stage, merged_pages * 4096);

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

                if file_off + copy_len <= elf_data_len {
                    let src = elf_data.add(file_off);
                    let dst = stage.add(window_off);
                    crate::loader::mem_util::volatile_copy(dst, src, copy_len);
                }
            }

            // Copy RO tail data for boundary pages trimmed from the RO MO.
            if elf_data_len >= core::mem::size_of::<Elf64Ehdr>() {
                let ehdr = &*(elf_data as *const Elf64Ehdr);
                let elf_phdrs = elf_data.add(ehdr.e_phoff as usize) as *const Elf64Phdr;
                let merged_vaddr_start = merged_start - running_base;
                let merged_vaddr_end = merged_vaddr_start + (merged_pages as u64) * 4096;
                for pi in 0..ehdr.e_phnum as usize {
                    let ph = &*elf_phdrs.add(pi);
                    if ph.p_type != trona::PT_LOAD || (ph.p_flags & trona::PF_W) != 0 {
                        continue;
                    }
                    let seg_file_end = ph.p_vaddr + ph.p_filesz;
                    if seg_file_end <= merged_vaddr_start
                        || (ph.p_vaddr & !0xFFFu64) >= merged_vaddr_end
                    {
                        continue;
                    }
                    let overlap_start = if ph.p_vaddr > merged_vaddr_start {
                        ph.p_vaddr
                    } else {
                        merged_vaddr_start
                    };
                    let overlap_end = if seg_file_end < merged_vaddr_end {
                        seg_file_end
                    } else {
                        merged_vaddr_end
                    };
                    if overlap_start >= overlap_end {
                        continue;
                    }
                    let file_off = (overlap_start - ph.p_vaddr + ph.p_offset) as usize;
                    let window_off = (overlap_start - merged_vaddr_start) as usize;
                    let copy_len = (overlap_end - overlap_start) as usize;
                    if file_off + copy_len <= elf_data_len {
                        let src = elf_data.add(file_off);
                        let dst = stage.add(window_off);
                        crate::loader::mem_util::volatile_copy(dst, src, copy_len);
                    }
                }
            }

            let region_base = match crate::base::mmsrv_ipc::alloc_private_copy_from_client_region_to_mmsrv(
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

        crate::loader::mem_util::free_staging_buffer(stage, merged_pages);
        status
    }
}
