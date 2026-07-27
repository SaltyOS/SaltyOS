// SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::*;

use crate::base::mmsrv_ipc;
use crate::base::proc_table;

const VSPACE_FLAG_WRITABLE: u64 = uapi::KERNITE_PAGE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = uapi::KERNITE_PAGE_FLAG_USER;
const VSPACE_FLAG_EXECUTABLE: u64 = uapi::KERNITE_PAGE_FLAG_EXECUTABLE;
const PF_W: u32 = uapi::KERNITE_PF_W;
const PF_X: u32 = uapi::KERNITE_PF_X;
const PT_LOAD: u32 = uapi::KERNITE_PT_LOAD;
const CHUNK_PAGES: usize = 512;
const MAX_IMAGE_RO_SEGS: usize = 8;
const MAX_IMAGE_RW_RANGES: usize = 8;
const MAX_IMAGE_RW_RUNS: usize = 8;
const REGION_TYPE_SPAWN: u64 = 2;
const REGION_TYPE_IMAGE_RO: u64 = 6;
const REGION_TYPE_IMAGE_TEXT: u64 = 8;
const REGION_TYPE_IMAGE_DATA: u64 = 9;
#[allow(dead_code)]
const REGION_TYPE_IMAGE_BSS: u64 = 10;

pub(crate) struct ElfRuntimePlan {
    pub is_dynamic: bool,
    pub lib_window_pages: usize,
    pub needed: super::NeededLibs,
    pub layout: trona_runtime::spawn::layout::VmLayoutPlan,
}

pub(crate) struct ElfRuntimeLoadResult {
    pub elf_result: ElfLoadResult,
    pub rtld_result: ElfLoadResult,
    pub shared_lib_base: u64,
    pub shared_lib_map: proc_table::ProcLibMap,
    pub mapped_image_count: usize,
    pub mapped_images: [trona_protocol::win32::SaltyOSMappedImageV1;
        trona_protocol::win32::SALTYOS_STARTUP_MAX_MAPPED_IMAGES],
}

unsafe fn inspect_shared_lib_for_layout(
    initrd: *const u8,
    initrd_size: usize,
    soname: &[u8],
) -> Option<(u64, super::NeededLibs)> {
    unsafe {
        const LIB_PREFIX: &[u8] = b"/lib/";
        let mut cpio_name = [0u8; 64];
        if soname.len() + LIB_PREFIX.len() <= cpio_name.len() {
            let mut i = 0usize;
            while i < LIB_PREFIX.len() {
                cpio_name[i] = LIB_PREFIX[i];
                i += 1;
            }
            i = 0;
            while i < soname.len() {
                cpio_name[LIB_PREFIX.len() + i] = soname[i];
                i += 1;
            }

            if let Some(entry) = trona_loader::common::cpio::cpio_find_file(
                initrd,
                initrd_size,
                &cpio_name[..soname.len() + LIB_PREFIX.len()],
            ) {
                return Some((
                    super::elf_compute_load_span(entry.data, entry.data_len),
                    super::elf_get_needed(entry.data, entry.data_len),
                ));
            }
        }

        let mut vfs_path = [0u8; 160];
        if soname.len() + LIB_PREFIX.len() <= vfs_path.len() {
            let mut i = 0usize;
            while i < LIB_PREFIX.len() {
                vfs_path[i] = LIB_PREFIX[i];
                i += 1;
            }
            let mut j = 0usize;
            while j < soname.len() {
                vfs_path[LIB_PREFIX.len() + j] = soname[j];
                j += 1;
            }
            if let Some(info) = crate::loader::vfs_load::inspect_shared_object_from_vfs(
                &vfs_path,
                LIB_PREFIX.len() + soname.len(),
            ) {
                return Some(info);
            }
        }

        const USR_LIB_PREFIX: &[u8] = b"/usr/lib/";
        if soname.len() + USR_LIB_PREFIX.len() <= vfs_path.len() {
            let mut i = 0usize;
            while i < USR_LIB_PREFIX.len() {
                vfs_path[i] = USR_LIB_PREFIX[i];
                i += 1;
            }
            let mut j = 0usize;
            while j < soname.len() {
                vfs_path[USR_LIB_PREFIX.len() + j] = soname[j];
                j += 1;
            }
            return crate::loader::vfs_load::inspect_shared_object_from_vfs(
                &vfs_path,
                USR_LIB_PREFIX.len() + soname.len(),
            );
        }

        None
    }
}

fn page_align_up_u64(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFFu64
}

fn push_needed_unique(libs: &mut super::NeededLibs, name: &[u8]) -> bool {
    let mut i = 0usize;
    while i < libs.count {
        if libs.name_lens[i] == name.len() {
            let mut j = 0usize;
            let mut same = true;
            while j < name.len() {
                if libs.names[i][j] != name[j] {
                    same = false;
                    break;
                }
                j += 1;
            }
            if same {
                return true;
            }
        }
        i += 1;
    }

    if libs.count >= super::MAX_NEEDED_LIBS {
        return false;
    }
    let copy_len = core::cmp::min(name.len(), super::MAX_NEEDED_NAME);
    let mut j = 0usize;
    while j < copy_len {
        libs.names[libs.count][j] = name[j];
        j += 1;
    }
    libs.name_lens[libs.count] = copy_len;
    libs.count += 1;
    true
}

unsafe fn collect_bootstrap_closure(
    seeds: &super::NeededLibs,
    initrd: *const u8,
    initrd_size: usize,
) -> Option<super::NeededLibs> {
    unsafe {
        let mut closure = super::NeededLibs::new();
        let mut i = 0usize;
        while i < seeds.count {
            let name = &seeds.names[i][..seeds.name_lens[i]];
            if !push_needed_unique(&mut closure, name) {
                return None;
            }
            i += 1;
        }

        let mut cursor = 0usize;
        while cursor < closure.count {
            let name = &closure.names[cursor][..closure.name_lens[cursor]];
            let (_, needed) = inspect_shared_lib_for_layout(initrd, initrd_size, name)?;
            let mut dep_idx = 0usize;
            while dep_idx < needed.count {
                let dep = &needed.names[dep_idx][..needed.name_lens[dep_idx]];
                if !push_needed_unique(&mut closure, dep) {
                    return None;
                }
                dep_idx += 1;
            }
            cursor += 1;
        }

        Some(closure)
    }
}

fn prefixed_path(prefix: &[u8], name: &[u8], out: &mut [u8]) -> Option<usize> {
    if prefix.len().saturating_add(name.len()) > out.len() {
        return None;
    }
    let mut i = 0usize;
    while i < prefix.len() {
        out[i] = prefix[i];
        i += 1;
    }
    let mut j = 0usize;
    while j < name.len() {
        out[prefix.len() + j] = name[j];
        j += 1;
    }
    Some(prefix.len() + name.len())
}

unsafe fn load_bootstrap_shared_object(
    soname: &[u8],
    initrd: *const u8,
    initrd_size: usize,
    load_base: u64,
    pid: u32,
    child_vspace: Cap,
) -> Option<ElfLoadResult> {
    unsafe {
        const LIB_PREFIX: &[u8] = b"/lib/";
        const USR_LIB_PREFIX: &[u8] = b"/usr/lib/";

        let mut path = [0u8; 160];
        if let Some(path_len) = prefixed_path(LIB_PREFIX, soname, &mut path) {
            if let Some(entry) =
                trona_loader::common::cpio::cpio_find_file(initrd, initrd_size, &path[..path_len])
            {
                let mut result = ElfLoadResult {
                    entry: 0,
                    base: 0,
                    brk: 0,
                };
                let err = exec_load_elf_mmsrv(
                    entry.data,
                    entry.data_len,
                    load_base,
                    pid,
                    child_vspace,
                    &raw mut result,
                );
                if err == 0 {
                    return Some(result);
                }
                return None;
            }
            if let Some(result) =
                exec_load_elf_from_vfs(&path[..path_len], load_base, pid, child_vspace)
            {
                return Some(result);
            }
        }

        if let Some(path_len) = prefixed_path(USR_LIB_PREFIX, soname, &mut path) {
            if let Some(result) =
                exec_load_elf_from_vfs(&path[..path_len], load_base, pid, child_vspace)
            {
                return Some(result);
            }
        }

        None
    }
}

fn elf_segment_vspace_flags(p_flags: u32) -> u64 {
    let mut flags = VSPACE_FLAG_USER;
    if p_flags & PF_W != 0 {
        flags |= VSPACE_FLAG_WRITABLE;
    } else if p_flags & PF_X != 0 {
        flags |= VSPACE_FLAG_EXECUTABLE;
    }
    flags
}

#[derive(Clone, Copy)]
struct ImageRoSeg {
    base: u64,
    page_count: u32,
    flags: u64,
}

impl ImageRoSeg {
    const fn zeroed() -> Self {
        Self {
            base: 0,
            page_count: 0,
            flags: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct ImageRange {
    base: u64,
    end: u64,
}

impl ImageRange {
    const fn zeroed() -> Self {
        Self { base: 0, end: 0 }
    }
}

struct ImageLoadPlan {
    ro_segs: [ImageRoSeg; MAX_IMAGE_RO_SEGS],
    ro_seg_count: usize,
    rw_runs: [ImageRange; MAX_IMAGE_RW_RUNS],
    rw_run_count: usize,
}

impl ImageLoadPlan {
    const fn zeroed() -> Self {
        const RO: ImageRoSeg = ImageRoSeg::zeroed();
        const RANGE: ImageRange = ImageRange::zeroed();
        Self {
            ro_segs: [RO; MAX_IMAGE_RO_SEGS],
            ro_seg_count: 0,
            rw_runs: [RANGE; MAX_IMAGE_RW_RUNS],
            rw_run_count: 0,
        }
    }
}

fn insert_sorted_range(ranges: &mut [ImageRange], count: &mut usize, base: u64, end: u64) -> bool {
    if *count >= ranges.len() {
        return false;
    }

    let mut idx = *count;
    while idx > 0 && base < ranges[idx - 1].base {
        ranges[idx] = ranges[idx - 1];
        idx -= 1;
    }
    ranges[idx] = ImageRange { base, end };
    *count += 1;
    true
}

unsafe fn build_segmented_load_plan(
    phdr_ptr: *const u8,
    phdr_count: usize,
    phdr_size: usize,
    phdr_bytes_len: usize,
    delta: u64,
    image_base: u64,
    header_prefix_len: u64,
) -> Option<ImageLoadPlan> {
    unsafe {
        let mut plan = ImageLoadPlan::zeroed();
        let mut rw_ranges = [ImageRange::zeroed(); MAX_IMAGE_RW_RANGES];
        let mut rw_range_count = 0usize;

        for i in 0..phdr_count {
            let off = i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                break;
            }
            let phdr = &*(phdr_ptr.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD || phdr.p_memsz == 0 || (phdr.p_flags & PF_W) == 0 {
                continue;
            }

            let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
            let seg_base = seg_vaddr & !0xFFFu64;
            let seg_end = (seg_vaddr.wrapping_add(phdr.p_memsz) + 0xFFF) & !0xFFFu64;
            if seg_end <= seg_base {
                continue;
            }

            if !insert_sorted_range(&mut rw_ranges, &mut rw_range_count, seg_base, seg_end) {
                return None;
            }
        }

        for i in 0..rw_range_count {
            let seg = rw_ranges[i];
            if plan.rw_run_count == 0 {
                plan.rw_runs[0] = seg;
                plan.rw_run_count = 1;
                continue;
            }

            let last = &mut plan.rw_runs[plan.rw_run_count - 1];
            if seg.base <= last.end {
                if seg.end > last.end {
                    last.end = seg.end;
                }
            } else {
                if plan.rw_run_count >= MAX_IMAGE_RW_RUNS {
                    return None;
                }
                plan.rw_runs[plan.rw_run_count] = seg;
                plan.rw_run_count += 1;
            }
        }

        let mut min_ro_page = u64::MAX;
        let mut max_ro_end = 0u64;
        for i in 0..phdr_count {
            let off = i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                break;
            }
            let phdr = &*(phdr_ptr.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD || phdr.p_memsz == 0 || (phdr.p_flags & PF_W) != 0 {
                continue;
            }

            let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
            let seg_base = seg_vaddr & !0xFFFu64;
            let seg_end = (seg_vaddr.wrapping_add(phdr.p_memsz) + 0xFFF) & !0xFFFu64;
            if seg_base < min_ro_page {
                min_ro_page = seg_base;
            }
            if seg_end > max_ro_end {
                max_ro_end = seg_end;
            }
        }

        if header_prefix_len != 0 {
            if image_base < min_ro_page {
                min_ro_page = image_base;
            }
            let header_end = image_base.wrapping_add(header_prefix_len);
            if header_end > max_ro_end {
                max_ro_end = header_end;
            }
        }

        if min_ro_page != u64::MAX && max_ro_end > min_ro_page {
            let mut page = min_ro_page;
            while page < max_ro_end {
                let mut skip_page = false;
                for wi in 0..rw_range_count {
                    if page >= rw_ranges[wi].base && page < rw_ranges[wi].end {
                        skip_page = true;
                        break;
                    }
                }

                let mut flags = 0u64;
                if !skip_page {
                    if header_prefix_len != 0
                        && page >= image_base
                        && page < image_base.wrapping_add(header_prefix_len)
                    {
                        flags |= VSPACE_FLAG_USER;
                    }
                    for i in 0..phdr_count {
                        let off = i * phdr_size;
                        if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                            break;
                        }
                        let phdr = &*(phdr_ptr.add(off) as *const Elf64Phdr);
                        if phdr.p_type != PT_LOAD || phdr.p_memsz == 0 || (phdr.p_flags & PF_W) != 0
                        {
                            continue;
                        }

                        let seg_vaddr = phdr.p_vaddr.wrapping_add(delta);
                        let seg_base = seg_vaddr & !0xFFFu64;
                        let seg_end = (seg_vaddr.wrapping_add(phdr.p_memsz) + 0xFFF) & !0xFFFu64;
                        if page >= seg_base && page < seg_end {
                            flags |= elf_segment_vspace_flags(phdr.p_flags);
                        }
                    }
                }

                if flags != 0 {
                    if plan.ro_seg_count > 0 {
                        let last = &mut plan.ro_segs[plan.ro_seg_count - 1];
                        let last_end = last.base + (last.page_count as u64) * 4096;
                        if last_end == page && last.flags == flags {
                            last.page_count += 1;
                        } else {
                            if plan.ro_seg_count >= MAX_IMAGE_RO_SEGS {
                                return None;
                            }
                            plan.ro_segs[plan.ro_seg_count] = ImageRoSeg {
                                base: page,
                                page_count: 1,
                                flags,
                            };
                            plan.ro_seg_count += 1;
                        }
                    } else {
                        plan.ro_segs[0] = ImageRoSeg {
                            base: page,
                            page_count: 1,
                            flags,
                        };
                        plan.ro_seg_count = 1;
                    }
                }

                page = page.wrapping_add(4096);
            }
        }

        Some(plan)
    }
}

unsafe fn copy_file_bytes_into_chunk<FRead>(
    stage: *mut u8,
    chunk_vaddr: u64,
    chunk_size: u64,
    seg_vaddr: u64,
    file_offset: u64,
    file_size: u64,
    read_at: &mut FRead,
) -> bool
where
    FRead: FnMut(*mut u8, usize, usize) -> bool,
{
    unsafe {
        if file_size == 0 {
            return true;
        }

        let seg_file_end = seg_vaddr.wrapping_add(file_size);
        let chunk_end = chunk_vaddr.wrapping_add(chunk_size);
        if seg_vaddr >= chunk_end || seg_file_end <= chunk_vaddr {
            return true;
        }

        let copy_start = if seg_vaddr > chunk_vaddr {
            seg_vaddr
        } else {
            chunk_vaddr
        };
        let copy_end = if seg_file_end < chunk_end {
            seg_file_end
        } else {
            chunk_end
        };
        if copy_start >= copy_end {
            return true;
        }

        let file_off = (file_offset + (copy_start - seg_vaddr)) as usize;
        let win_off = (copy_start - chunk_vaddr) as usize;
        let copy_len = (copy_end - copy_start) as usize;
        read_at(stage.add(win_off), copy_len, file_off)
    }
}

unsafe fn fill_rw_chunk<FRead>(
    stage: *mut u8,
    chunk_vaddr: u64,
    chunk_size: u64,
    phdr_ptr: *const u8,
    phdr_count: usize,
    phdr_size: usize,
    phdr_bytes_len: usize,
    delta: u64,
    read_at: &mut FRead,
) -> bool
where
    FRead: FnMut(*mut u8, usize, usize) -> bool,
{
    unsafe {
        for pass in 0..2 {
            for i in 0..phdr_count {
                let off = i * phdr_size;
                if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                    break;
                }
                let phdr = &*(phdr_ptr.add(off) as *const Elf64Phdr);
                if phdr.p_type != PT_LOAD || phdr.p_filesz == 0 {
                    continue;
                }

                let writable = (phdr.p_flags & PF_W) != 0;
                if (pass == 0 && !writable) || (pass == 1 && writable) {
                    continue;
                }

                if !copy_file_bytes_into_chunk(
                    stage,
                    chunk_vaddr,
                    chunk_size,
                    phdr.p_vaddr.wrapping_add(delta),
                    phdr.p_offset,
                    phdr.p_filesz,
                    read_at,
                ) {
                    return false;
                }
            }
        }

        true
    }
}

unsafe fn fill_ro_chunk<FRead>(
    stage: *mut u8,
    chunk_vaddr: u64,
    chunk_size: u64,
    image_base: u64,
    header_prefix_len: u64,
    phdr_ptr: *const u8,
    phdr_count: usize,
    phdr_size: usize,
    phdr_bytes_len: usize,
    delta: u64,
    read_at: &mut FRead,
) -> bool
where
    FRead: FnMut(*mut u8, usize, usize) -> bool,
{
    unsafe {
        if header_prefix_len != 0 {
            let header_end = image_base.wrapping_add(header_prefix_len);
            let chunk_end = chunk_vaddr.wrapping_add(chunk_size);
            if chunk_vaddr < header_end && chunk_end > image_base {
                let copy_start = if chunk_vaddr > image_base {
                    chunk_vaddr
                } else {
                    image_base
                };
                let copy_end = if chunk_end < header_end {
                    chunk_end
                } else {
                    header_end
                };
                if copy_start < copy_end {
                    let file_off = (copy_start - image_base) as usize;
                    let win_off = (copy_start - chunk_vaddr) as usize;
                    let copy_len = (copy_end - copy_start) as usize;
                    if !read_at(stage.add(win_off), copy_len, file_off) {
                        return false;
                    }
                }
            }
        }

        for i in 0..phdr_count {
            let off = i * phdr_size;
            if off + core::mem::size_of::<Elf64Phdr>() > phdr_bytes_len {
                break;
            }
            let phdr = &*(phdr_ptr.add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD || phdr.p_filesz == 0 || (phdr.p_flags & PF_W) != 0 {
                continue;
            }

            if !copy_file_bytes_into_chunk(
                stage,
                chunk_vaddr,
                chunk_size,
                phdr.p_vaddr.wrapping_add(delta),
                phdr.p_offset,
                phdr.p_filesz,
                read_at,
            ) {
                return false;
            }
        }

        true
    }
}

unsafe fn load_segmented_image<FRead>(
    phdr_ptr: *const u8,
    phdr_count: usize,
    phdr_size: usize,
    phdr_bytes_len: usize,
    is_pie: bool,
    entry_vaddr: u64,
    image_base: u64,
    header_prefix_len: u64,
    min_vaddr: u64,
    max_vaddr_end: u64,
    load_base: u64,
    pid: u32,
    result: *mut ElfLoadResult,
    mut read_at: FRead,
) -> i32
where
    FRead: FnMut(*mut u8, usize, usize) -> bool,
{
    use uapi::{ELF_MAP_FAILED, ELF_OUT_OF_MEMORY};

    unsafe {
        let delta = if is_pie {
            load_base.wrapping_sub(min_vaddr)
        } else {
            0
        };
        let span_end = ((max_vaddr_end.wrapping_add(delta)) + 0xFFF) & !0xFFFu64;
        let Some(plan) = build_segmented_load_plan(
            phdr_ptr,
            phdr_count,
            phdr_size,
            phdr_bytes_len,
            delta,
            image_base,
            header_prefix_len,
        ) else {
            return ELF_MAP_FAILED;
        };

        let stage = crate::loader::mem_util::alloc_staging_buffer(CHUNK_PAGES);
        if stage.is_null() {
            return ELF_OUT_OF_MEMORY;
        }

        let load_status = (|| -> i32 {
            for si in 0..plan.ro_seg_count {
                let seg = plan.ro_segs[si];
                let total_pages = seg.page_count as usize;
                let mut chunk_off = 0usize;
                while chunk_off < total_pages {
                    let chunk_count = core::cmp::min(total_pages - chunk_off, CHUNK_PAGES);
                    let chunk_vaddr = seg.base + (chunk_off as u64) * 4096;
                    let chunk_size = (chunk_count as u64) * 4096;

                    crate::loader::mem_util::volatile_zero(stage, chunk_count * 4096);
                    if !fill_ro_chunk(
                        stage,
                        chunk_vaddr,
                        chunk_size,
                        image_base,
                        header_prefix_len,
                        phdr_ptr,
                        phdr_count,
                        phdr_size,
                        phdr_bytes_len,
                        delta,
                        &mut read_at,
                    ) {
                        return ELF_MAP_FAILED;
                    }
                    if chunk_off == 0 {
                        let region_base =
                            match mmsrv_ipc::alloc_typed_copy_from_client_region_to_mmsrv(
                                pid,
                                seg.base,
                                total_pages as u64,
                                chunk_vaddr,
                                stage as u64,
                                chunk_count as u64,
                                seg.flags,
                                // Executable RO runs are the main
                                // program's `.text` (→ VmExe). Non-exec
                                // RO runs are `.rodata` — classified
                                // under `IMAGE_RO` so procfs lumps
                                // them with shared-lib read-only pages
                                // (VmLib).
                                if seg.flags & VSPACE_FLAG_EXECUTABLE != 0 {
                                    REGION_TYPE_IMAGE_TEXT
                                } else {
                                    REGION_TYPE_IMAGE_RO
                                },
                            ) {
                                Ok(v) => v,
                                Err((err, label, value)) => {
                                    trona_runtime::uerror!(|_lb| {
                                        _lb.str(
                                            b"[PROCMGR] exec ELF RO MM_ALLOC_TYPED_COPY failed err=",
                                        );
                                        _lb.hex(err as u64);
                                        _lb.str(b" label=");
                                        _lb.hex(label);
                                        _lb.str(b" value=");
                                        _lb.hex(value);
                                        _lb.str(b" base=");
                                        _lb.hex(seg.base);
                                        _lb.str(b"\n");
                                    });
                                    return ELF_MAP_FAILED;
                                }
                            };
                        if region_base != seg.base {
                            return ELF_MAP_FAILED;
                        }
                    } else {
                        let copied = match mmsrv_ipc::copy_from_client_region_to_mmsrv(
                            pid,
                            chunk_vaddr,
                            stage as u64,
                            chunk_count as u64,
                        ) {
                            Ok(v) => v,
                            Err((err, label, value)) => {
                                trona_runtime::uerror!(|_lb| {
                                    _lb.str(
                                        b"[PROCMGR] exec ELF RO MM_COPY_FROM_CLIENT_REGION failed err=",
                                    );
                                    _lb.hex(err as u64);
                                    _lb.str(b" label=");
                                    _lb.hex(label);
                                    _lb.str(b" value=");
                                    _lb.hex(value);
                                    _lb.str(b" addr=");
                                    _lb.hex(chunk_vaddr);
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
            }

            for ri in 0..plan.rw_run_count {
                let run = plan.rw_runs[ri];
                let total_pages = ((run.end - run.base) / 4096) as usize;
                let mut chunk_off = 0usize;
                while chunk_off < total_pages {
                    let chunk_count = core::cmp::min(total_pages - chunk_off, CHUNK_PAGES);
                    let chunk_vaddr = run.base + (chunk_off as u64) * 4096;
                    let chunk_size = (chunk_count as u64) * 4096;

                    crate::loader::mem_util::volatile_zero(stage, chunk_count * 4096);
                    if !fill_rw_chunk(
                        stage,
                        chunk_vaddr,
                        chunk_size,
                        phdr_ptr,
                        phdr_count,
                        phdr_size,
                        phdr_bytes_len,
                        delta,
                        &mut read_at,
                    ) {
                        return ELF_MAP_FAILED;
                    }
                    if chunk_off == 0 {
                        let region_base =
                            match mmsrv_ipc::alloc_typed_copy_from_client_region_to_mmsrv(
                                pid,
                                run.base,
                                total_pages as u64,
                                chunk_vaddr,
                                stage as u64,
                                chunk_count as u64,
                                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                                // Writable runs are `.data` / `.bss`
                                // of the main program (→ VmData).
                                REGION_TYPE_IMAGE_DATA,
                            ) {
                                Ok(v) => v,
                                Err((err, label, value)) => {
                                    trona_runtime::uerror!(|_lb| {
                                        _lb.str(
                                            b"[PROCMGR] exec ELF RW MM_ALLOC_TYPED_COPY failed err=",
                                        );
                                        _lb.hex(err as u64);
                                        _lb.str(b" label=");
                                        _lb.hex(label);
                                        _lb.str(b" value=");
                                        _lb.hex(value);
                                        _lb.str(b" base=");
                                        _lb.hex(run.base);
                                        _lb.str(b"\n");
                                    });
                                    return ELF_MAP_FAILED;
                                }
                            };
                        if region_base != run.base {
                            return ELF_MAP_FAILED;
                        }
                    } else {
                        let copied = match mmsrv_ipc::copy_from_client_region_to_mmsrv(
                            pid,
                            chunk_vaddr,
                            stage as u64,
                            chunk_count as u64,
                        ) {
                            Ok(v) => v,
                            Err((err, label, value)) => {
                                trona_runtime::uerror!(|_lb| {
                                    _lb.str(
                                        b"[PROCMGR] exec ELF RW MM_COPY_FROM_CLIENT_REGION failed err=",
                                    );
                                    _lb.hex(err as u64);
                                    _lb.str(b" label=");
                                    _lb.hex(label);
                                    _lb.str(b" value=");
                                    _lb.hex(value);
                                    _lb.str(b" addr=");
                                    _lb.hex(chunk_vaddr);
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
            }

            (*result).entry = if is_pie {
                entry_vaddr.wrapping_add(delta)
            } else {
                entry_vaddr
            };
            (*result).base = load_base;
            (*result).brk = span_end;
            0
        })();

        crate::loader::mem_util::free_staging_buffer(stage, CHUNK_PAGES);
        load_status
    }
}

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
        let mut rtld_cpio_path = [0u8; 64];
        let rtld_cpio_len = {
            use trona_loader::common::elf::header::{get_interp, phdr_slice, validate_ehdr};
            let interp_opt = validate_ehdr(elf_data, elf_data_len)
                .ok()
                .and_then(|ehdr| phdr_slice(elf_data, elf_data_len, ehdr).ok())
                .and_then(|phdrs| get_interp(elf_data, phdrs));
            match interp_opt {
                Some(interp) => {
                    if interp.is_empty() || interp.len() > rtld_cpio_path.len() {
                        0
                    } else {
                        let mut i = 0;
                        while i < interp.len() {
                            rtld_cpio_path[i] = interp[i];
                            i += 1;
                        }
                        interp.len()
                    }
                }
                None => 0,
            }
        };
        if rtld_cpio_len == 0 {
            return 5 * 4096;
        }

        let rtld_entry = match trona_loader::common::cpio::cpio_find_file(
            initrd,
            initrd_size,
            &rtld_cpio_path[..rtld_cpio_len],
        ) {
            Some(e) => e,
            None => return 5 * 4096,
        };

        let span = super::elf_compute_load_span(rtld_entry.data, rtld_entry.data_len);
        if span == 0 { 5 * 4096 } else { span }
    }
}

pub(crate) unsafe fn count_rtld_span_by_name(
    rtld_name: *const u8,
    rtld_name_len: usize,
    initrd: *const u8,
    initrd_size: usize,
) -> u64 {
    unsafe {
        let rtld_entry = match trona_loader::common::cpio::cpio_find_file(
            initrd,
            initrd_size,
            core::slice::from_raw_parts(rtld_name, rtld_name_len),
        ) {
            Some(e) => e,
            None => return 5 * 4096,
        };

        let span = super::elf_compute_load_span(rtld_entry.data, rtld_entry.data_len);
        if span == 0 { 5 * 4096 } else { span }
    }
}

pub(crate) unsafe fn plan_elf_runtime(
    elf_data: *const u8,
    elf_data_len: usize,
    vfs_stream: Option<&crate::loader::vfs_load::VfsStreamExec>,
    initrd: *const u8,
    initrd_size: usize,
    map_initrd: bool,
) -> Option<ElfRuntimePlan> {
    unsafe {
        let is_dynamic = if let Some(vfs) = vfs_stream {
            vfs.is_dynamic
        } else {
            use trona_loader::common::elf::header::{has_interp, phdr_slice, validate_ehdr};
            validate_ehdr(elf_data, elf_data_len)
                .and_then(|ehdr| phdr_slice(elf_data, elf_data_len, ehdr))
                .map(|phdrs| has_interp(phdrs))
                .unwrap_or(false)
        };

        let elf_span = if let Some(vfs) = vfs_stream {
            vfs.elf_span
        } else {
            super::elf_compute_load_span(elf_data, elf_data_len)
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
                count_rtld_span(elf_data, elf_data_len, initrd, initrd_size)
            }
        } else {
            0
        };

        let direct_needed = if is_dynamic && vfs_stream.is_none() {
            super::elf_get_needed(elf_data, elf_data_len)
        } else if let Some(vfs) = vfs_stream {
            vfs.needed
        } else {
            super::NeededLibs::new()
        };

        let needed = if is_dynamic {
            collect_bootstrap_closure(&direct_needed, initrd, initrd_size)?
        } else {
            super::NeededLibs::new()
        };

        let lib_window_pages = super::compute_needed_window_pages(&needed, |soname| {
            unsafe { inspect_shared_lib_for_layout(initrd, initrd_size, soname) }
                .map(|(span, _)| span)
                .unwrap_or(0)
        });

        // The spawner preloads the bootstrap DSO closure into the reserved
        // shared-library window before first entry, and RTLD reuses that
        // window metadata to seed its object graph.
        let initrd_window_size = if map_initrd { initrd_size } else { 0 };
        let layout = trona_runtime::spawn::layout::compute_vm_layout_randomized(
            elf_span,
            rtld_span,
            lib_window_pages,
            map_initrd,
            initrd_window_size,
            trona_runtime::spawn::stack_plan::StackLayoutSpec::default_service(),
            || trona_kernel::syscall::sys_getrandom(),
        );
        if layout.stack_top == 0 {
            return None;
        }

        Some(ElfRuntimePlan {
            is_dynamic,
            lib_window_pages,
            needed,
            layout,
        })
    }
}

pub(crate) unsafe fn load_elf_runtime(
    elf_data: *const u8,
    elf_data_len: usize,
    vfs_stream: Option<&crate::loader::vfs_load::VfsStreamExec>,
    runtime: &ElfRuntimePlan,
    initrd: *const u8,
    initrd_size: usize,
    pid: u32,
    child_vspace: Cap,
) -> Option<ElfRuntimeLoadResult> {
    unsafe {
        let mut elf_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let err = if let Some(vfs) = vfs_stream {
            exec_load_elf_vfs_mmsrv(
                vfs,
                runtime.layout.elf_code.base,
                pid,
                child_vspace,
                &raw mut elf_result,
            )
        } else {
            exec_load_elf_mmsrv(
                elf_data,
                elf_data_len,
                runtime.layout.elf_code.base,
                pid,
                child_vspace,
                &raw mut elf_result,
            )
        };
        if err != 0 {
            return None;
        }

        let mut rtld_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let mut mapped_image_count = 0usize;
        let mut mapped_images = [trona_protocol::win32::SaltyOSMappedImageV1::zeroed();
            trona_protocol::win32::SALTYOS_STARTUP_MAX_MAPPED_IMAGES];
        if runtime.is_dynamic {
            rtld_result = if let Some(vfs) = vfs_stream {
                exec_load_rtld_mmsrv_by_name(
                    vfs.interp_name.as_ptr(),
                    vfs.interp_name_len,
                    initrd,
                    initrd_size,
                    runtime.layout.rtld.base,
                    pid,
                    child_vspace,
                )?
            } else {
                exec_load_rtld_mmsrv(
                    elf_data,
                    elf_data_len,
                    initrd,
                    initrd_size,
                    runtime.layout.rtld.base,
                    pid,
                    child_vspace,
                )?
            };

            let mut next_base = runtime.layout.shared_libs.base;
            let mut i = 0usize;
            while i < runtime.needed.count {
                let name = &runtime.needed.names[i][..runtime.needed.name_lens[i]];
                let load = load_bootstrap_shared_object(
                    name,
                    initrd,
                    initrd_size,
                    next_base,
                    pid,
                    child_vspace,
                )?;
                if mapped_image_count >= mapped_images.len() {
                    return None;
                }
                let mut mapped = trona_protocol::win32::SaltyOSMappedImageV1::zeroed();
                mapped.image = trona_protocol::win32::SaltyOSImageInfoV1::new(
                    trona_protocol::win32::SALTYOS_IMAGE_KIND_ELF,
                    0,
                    load.base,
                    load.brk.saturating_sub(load.base),
                    0,
                );
                mapped.set_name(name);
                mapped_images[mapped_image_count] = mapped;
                mapped_image_count += 1;
                next_base = page_align_up_u64(load.brk);
                i += 1;
            }
        }

        let shared_lib_base: u64 = if mapped_image_count != 0 {
            runtime.layout.shared_libs.base
        } else {
            0
        };
        let shared_lib_map = proc_table::ProcLibMap::zeroed();

        Some(ElfRuntimeLoadResult {
            elf_result,
            rtld_result,
            shared_lib_base,
            shared_lib_map,
            mapped_image_count,
            mapped_images,
        })
    }
}

/// Load an ELF64 binary into a child's VSpace using mmsrv for frame allocation.
///
/// Materializes segment-aware image regions in mmsrv, preserving PT_LOAD
/// boundaries instead of flattening the full span into one anonymous region.
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
    _child_vspace: Cap,
    result: *mut ElfLoadResult,
) -> i32 {
    unsafe {
        use uapi::{
            ELF_BAD_ARCH, ELF_BAD_TYPE, ELF_NO_LOAD, ELF_NOT_64BIT, ELF_NOT_ELF, ELF_NOT_LE,
            ELF_OUT_OF_MEMORY, ELF_TOO_SMALL, ELFCLASS64, ELFDATA2LSB, EM_X86_64, ET_DYN, ET_EXEC,
            PT_LOAD,
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
        if ehdr.e_machine != trona_runtime::core::server_consts::EM_AARCH64 {
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
        let header_prefix_len = ((phdr_base + phdr_count * phdr_size) as u64 + 0xFFF) & !0xFFFu64;

        if total_span_pages == 0 {
            return ELF_OUT_OF_MEMORY;
        }
        load_segmented_image(
            data.add(phdr_base),
            phdr_count,
            phdr_size,
            data_len - phdr_base,
            is_pie,
            ehdr.e_entry,
            span_start,
            header_prefix_len,
            min_vaddr,
            max_vaddr_end,
            load_base,
            pid,
            result,
            |dst, len, file_off| {
                if file_off + len > data_len {
                    return false;
                }
                crate::loader::mem_util::volatile_copy(dst, data.add(file_off), len);
                true
            },
        )
    }
}

pub(crate) unsafe fn exec_load_elf_vfs_mmsrv(
    vfs: &crate::loader::vfs_load::VfsStreamExec,
    load_base: u64,
    pid: u32,
    _child_vspace: Cap,
    result: *mut ElfLoadResult,
) -> i32 {
    unsafe {
        use uapi::{
            ELF_BAD_ARCH, ELF_BAD_TYPE, ELF_NO_LOAD, ELF_NOT_64BIT, ELF_NOT_ELF, ELF_NOT_LE,
            ELF_OUT_OF_MEMORY, ELF_TOO_SMALL, ELFCLASS64, ELFDATA2LSB, EM_X86_64, ET_DYN, ET_EXEC,
            PT_LOAD,
        };

        let fd = vfs.fd;
        let data_len = vfs.file_size;
        if data_len < core::mem::size_of::<Elf64Ehdr>() {
            return ELF_TOO_SMALL;
        }

        let mut ehdr = core::mem::MaybeUninit::<Elf64Ehdr>::uninit();
        if !crate::loader::vfs_load::vfs_read_exact_at(
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
        if ehdr.e_machine != trona_runtime::core::server_consts::EM_AARCH64 {
            return ELF_BAD_ARCH;
        }

        let phdr_count = ehdr.e_phnum as usize;
        let phdr_size = ehdr.e_phentsize as usize;
        let phdr_bytes_len = phdr_count.saturating_mul(phdr_size);
        if phdr_count == 0 || phdr_bytes_len == 0 || phdr_bytes_len > 4096 {
            return ELF_NO_LOAD;
        }

        let mut phdr_bytes = [0u8; 4096];
        if !crate::loader::vfs_load::vfs_read_exact_at(
            fd,
            phdr_bytes.as_mut_ptr(),
            phdr_bytes_len,
            ehdr.e_phoff as usize,
        ) {
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
        let header_prefix_len =
            ((ehdr.e_phoff as usize + phdr_bytes_len) as u64 + 0xFFF) & !0xFFFu64;
        if total_span_pages == 0 {
            return ELF_OUT_OF_MEMORY;
        }
        load_segmented_image(
            phdr_bytes.as_ptr(),
            phdr_count,
            phdr_size,
            phdr_bytes_len,
            is_pie,
            ehdr.e_entry,
            span_start,
            header_prefix_len,
            min_vaddr,
            max_vaddr_end,
            load_base,
            pid,
            result,
            |dst, len, file_off| crate::loader::vfs_load::vfs_read_exact_at(fd, dst, len, file_off),
        )
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
        let mut rtld_cpio_path = [0u8; 64];
        let rtld_cpio_len = {
            use trona_loader::common::elf::header::{get_interp, phdr_slice, validate_ehdr};
            let interp_opt = validate_ehdr(elf_data, elf_data_len)
                .ok()
                .and_then(|ehdr| phdr_slice(elf_data, elf_data_len, ehdr).ok())
                .and_then(|phdrs| get_interp(elf_data, phdrs));
            match interp_opt {
                Some(interp) => super::resolve_interp_to_cpio_path(interp, &mut rtld_cpio_path),
                None => 0,
            }
        };
        if rtld_cpio_len == 0 {
            return None;
        }

        exec_load_rtld_mmsrv_by_name(
            rtld_cpio_path.as_ptr(),
            rtld_cpio_len,
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
        let rtld_entry = match trona_loader::common::cpio::cpio_find_file(
            initrd,
            initrd_size,
            core::slice::from_raw_parts(rtld_name, rtld_name_len),
        ) {
            Some(e) => e,
            None => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] exec: rtld not found in initrd\n");
                });
                return None;
            }
        };

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
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] exec: rtld load failed err=");
                _lb.hex(err as u64);
                _lb.str(b" pid=");
                _lb.hex(pid as u64);
                _lb.str(b" base=");
                _lb.hex(rtld_load_base);
                _lb.str(b"\n");
            });
            return None;
        }
        Some(rtld_result)
    }
}

/// Load an ELF from VFS into a child's VSpace via mmsrv.
///
/// # Safety
/// Caller must ensure `child_vspace` is a valid VSpace cap for `pid`.
pub(crate) unsafe fn exec_load_elf_from_vfs(
    path: &[u8],
    load_base: u64,
    pid: u32,
    child_vspace: Cap,
) -> Option<ElfLoadResult> {
    unsafe {
        let vfs_buf = crate::loader::vfs_load::try_load_from_vfs(path, path.len())?;
        let mut result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let err = exec_load_elf_mmsrv(
            vfs_buf.data,
            vfs_buf.data_len,
            load_base,
            pid,
            child_vspace,
            &raw mut result,
        );
        crate::loader::vfs_load::cleanup_vfs_load(vfs_buf.data, vfs_buf.alloc_size);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] exec: VFS ELF load failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return None;
        }
        Some(result)
    }
}
