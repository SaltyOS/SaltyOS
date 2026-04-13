// SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;
use trona::types::pe::*;

use trona::layout::VmLayoutPlan;

use crate::base::mmsrv_ipc;
use crate::loader::mem_util::{
    alloc_staging_buffer, free_staging_buffer, volatile_copy, volatile_zero,
};
use crate::loader::elf_load::{
    exec_load_elf_from_vfs, exec_load_rtld_mmsrv_by_name,
};

pub(crate) struct PeRuntimeSupportPlan {
    pub pe_rtld_cpio_path: [u8; 64],
    pub pe_rtld_cpio_len: usize,
    pub pe_rtld_from_vfs: bool,
    pub pe_rtld_span: u64,
    pub kernel32_cpio_path: [u8; 64],
    pub kernel32_cpio_len: usize,
    pub kernel32_from_vfs: bool,
    pub kernel32_pages: usize,
}

pub(crate) struct PeRuntimeLoadResult {
    pub pe_result: PeLoadResult,
    pub rtld_result: ElfLoadResult,
    pub kernel32_result: PeLoadResult,
}

pub(crate) unsafe fn plan_pe_runtime_support(
    initrd: *const u8,
    initrd_size: usize,
) -> Option<PeRuntimeSupportPlan> {
    unsafe {
        let pe_rtld_soname = b"ld-trona-pe.so";
        let mut pe_rtld_cpio_path = [0u8; 64];
        let pe_rtld_cpio_len = trona_loader::elf_dynamic::build_initrd_lib_path(
            pe_rtld_soname,
            &mut pe_rtld_cpio_path,
        );
        let pe_rtld_vfs_path = b"/lib/ld-trona-pe.so";
        let mut pe_rtld_from_vfs = false;
        let pe_rtld_span = 'rtld_span: {
            if let Some(vfs_result) =
                crate::loader::vfs_load::try_load_from_vfs(pe_rtld_vfs_path, pe_rtld_vfs_path.len())
            {
                let span = trona_loader::elf_loader::elf_compute_load_span(
                    vfs_result.data,
                    vfs_result.data_len,
                );
                crate::loader::vfs_load::cleanup_vfs_load(vfs_result.data, vfs_result.alloc_size);
                if span != 0 {
                    pe_rtld_from_vfs = true;
                    break 'rtld_span span;
                }
            }

            let mut pe_rtld_entry = CpioEntry::zeroed();
            if pe_rtld_cpio_len == 0
                || trona_loader::cpio::cpio_find_file(
                    initrd,
                    initrd_size,
                    pe_rtld_cpio_path.as_ptr(),
                    pe_rtld_cpio_len,
                    &raw mut pe_rtld_entry,
                ) == 0
            {
                return None;
            }

            trona_loader::elf_loader::elf_compute_load_span(
                pe_rtld_entry.data,
                pe_rtld_entry.data_len,
            )
        };

        let kernel32_soname = b"kernel32.dll";
        let mut kernel32_cpio_path = [0u8; 64];
        let kernel32_cpio_len = trona_loader::elf_dynamic::build_initrd_lib_path(
            kernel32_soname,
            &mut kernel32_cpio_path,
        );
        let kernel32_vfs_path = b"/lib/kernel32.dll";
        let mut kernel32_from_vfs = false;
        let kernel32_span = 'k32_span: {
            if let Some(vfs_result) =
                crate::loader::vfs_load::try_load_from_vfs(kernel32_vfs_path, kernel32_vfs_path.len())
            {
                let span = trona_loader::pe_loader::pe_compute_load_span(
                    vfs_result.data,
                    vfs_result.data_len,
                );
                crate::loader::vfs_load::cleanup_vfs_load(vfs_result.data, vfs_result.alloc_size);
                if span != 0 {
                    kernel32_from_vfs = true;
                    break 'k32_span span;
                }
            }

            let mut k32_entry = CpioEntry::zeroed();
            if kernel32_cpio_len != 0
                && trona_loader::cpio::cpio_find_file(
                    initrd,
                    initrd_size,
                    kernel32_cpio_path.as_ptr(),
                    kernel32_cpio_len,
                    &raw mut k32_entry,
                ) != 0
            {
                trona_loader::pe_loader::pe_compute_load_span(k32_entry.data, k32_entry.data_len)
            } else {
                0
            }
        };

        Some(PeRuntimeSupportPlan {
            pe_rtld_cpio_path,
            pe_rtld_cpio_len,
            pe_rtld_from_vfs,
            pe_rtld_span,
            kernel32_cpio_path,
            kernel32_cpio_len,
            kernel32_from_vfs,
            kernel32_pages: ((kernel32_span + 0xFFF) / 0x1000) as usize,
        })
    }
}

pub(crate) unsafe fn load_pe_runtime_support(
    support: &PeRuntimeSupportPlan,
    data: *const u8,
    data_len: usize,
    layout: &VmLayoutPlan,
    initrd: *const u8,
    initrd_size: usize,
    pid: u32,
    child_vspace: Cap,
) -> Option<PeRuntimeLoadResult> {
    unsafe {
        let pe_result =
            exec_load_pe_mmsrv(data, data_len, layout.elf_code.base, pid, child_vspace).ok()?;

        let pe_rtld_vfs_path = b"/lib/ld-trona-pe.so";
        let rtld_result = if support.pe_rtld_from_vfs {
            exec_load_elf_from_vfs(pe_rtld_vfs_path, layout.rtld.base, pid, child_vspace)?
        } else {
            exec_load_rtld_mmsrv_by_name(
                support.pe_rtld_cpio_path.as_ptr(),
                support.pe_rtld_cpio_len,
                initrd,
                initrd_size,
                layout.rtld.base,
                pid,
                child_vspace,
            )?
        };

        let kernel32_vfs_path = b"/lib/kernel32.dll";
        let kernel32_result = if support.kernel32_from_vfs {
            exec_load_pe_from_vfs(
                kernel32_vfs_path,
                layout.shared_libs.base,
                pid,
                child_vspace,
            )?
        } else {
            exec_load_pe_mmsrv_by_name(
                support.kernel32_cpio_path.as_ptr(),
                support.kernel32_cpio_len,
                initrd,
                initrd_size,
                layout.shared_libs.base,
                pid,
                child_vspace,
            )?
        };

        Some(PeRuntimeLoadResult {
            pe_result,
            rtld_result,
            kernel32_result,
        })
    }
}

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
                    let sec_copy_end =
                        core::cmp::min(chunk_rva + chunk_len, sec_rva + sec_raw_size);
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
                    let region_base = mmsrv_ipc::alloc_private_copy_from_client_region_to_mmsrv(
                        pid,
                        load_base,
                        total_pages as u64,
                        chunk_vaddr,
                        stage as u64,
                        chunk_count as u64,
                        trona::VSPACE_FLAG_WRITABLE | trona::VSPACE_FLAG_USER,
                    )
                    .map_err(|_| -2)?;
                    if region_base != load_base {
                        return Err(-2);
                    }
                } else {
                    let copied = mmsrv_ipc::copy_from_client_region_to_mmsrv(
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

        let entry_va = load_base + info.entry_point_rva as u64;
        Ok(PeLoadResult {
            entry: entry_va,
            base: load_base,
            image_end: load_base + image_size,
        })
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
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] exec: PE image not found in initrd\n");
            });
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

pub(crate) unsafe fn exec_load_pe_from_vfs(
    path: &[u8],
    load_base: u64,
    pid: u32,
    child_vspace: Cap,
) -> Option<PeLoadResult> {
    unsafe {
        let vfs_buf = crate::loader::vfs_load::try_load_from_vfs(path, path.len())?;
        let load_result =
            exec_load_pe_mmsrv(vfs_buf.data, vfs_buf.data_len, load_base, pid, child_vspace);
        crate::loader::vfs_load::cleanup_vfs_load(vfs_buf.data, vfs_buf.alloc_size);
        match load_result {
            Ok(r) => Some(r),
            Err(err) => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] exec: VFS PE load failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                None
            }
        }
    }
}
