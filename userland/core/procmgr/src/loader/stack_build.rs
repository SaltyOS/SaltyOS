// SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;
use trona::types::pe::*;

use crate::base::alloc::Allocator;
use crate::base::child_layout::ChildCapLayout;
#[derive(Clone, Copy)]
pub(crate) enum StackBuildError {
    OutOfMemory,
    InvalidArgument,
    TooLarge,
}

#[cfg(target_arch = "aarch64")]
const STACK_ENTRY_BIAS: usize = 0;
#[cfg(target_arch = "x86_64")]
const STACK_ENTRY_BIAS: usize = 8;

const MAX_STACK_STRINGS: usize = 128;

const VSPACE_FLAG_WRITABLE: u64 = trona::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = trona::VSPACE_FLAG_USER;
const TRONA_OUT_OF_MEMORY: u64 = trona::TRONA_OUT_OF_MEMORY;
const PROCMGR_SCRATCH_VADDR: u64 = crate::PROCMGR_SCRATCH_VADDR;
const CAP_SELF_VSPACE: Cap = crate::CAP_SELF_VSPACE;

const AT_NULL: u64 = crate::AT_NULL;
const AT_PHDR: u64 = crate::AT_PHDR;
const AT_PHENT: u64 = crate::AT_PHENT;
const AT_PHNUM: u64 = crate::AT_PHNUM;
const AT_PAGESZ: u64 = crate::AT_PAGESZ;
const AT_BASE: u64 = crate::AT_BASE;
const AT_ENTRY: u64 = crate::AT_ENTRY;
const AT_TRONA_VSPACE: u64 = crate::AT_TRONA_VSPACE;
const AT_TRONA_SCRATCH: u64 = crate::AT_TRONA_SCRATCH;
const AT_TRONA_INITRD: u64 = crate::AT_TRONA_INITRD;
const AT_TRONA_INITRD_SZ: u64 = crate::AT_TRONA_INITRD_SZ;
const AT_TRONA_SHARED_LIB_BASE: u64 = crate::AT_TRONA_SHARED_LIB_BASE;
const AT_TRONA_CSPACE_LAYOUT: u64 = crate::AT_TRONA_CSPACE_LAYOUT;
const AT_TRONA_CAP_TABLE: u64 = crate::AT_TRONA_CAP_TABLE;
const AT_TRONA_CSPACE_NTFN: u64 = crate::AT_TRONA_CSPACE_NTFN;
const AT_TRONA_IPC_BUFFER: u64 = crate::AT_TRONA_IPC_BUFFER;
const AT_TRONA_SC_CAP: u64 = crate::AT_TRONA_SC_CAP;
const AT_SALTYOS_PE_BASE: u64 = crate::AT_SALTYOS_PE_BASE;
const AT_SALTYOS_PE_SIZE: u64 = crate::AT_SALTYOS_PE_SIZE;
const AT_SALTYOS_WIN32SRV: u64 = crate::AT_SALTYOS_WIN32SRV;
const AT_SALTYOS_KERNEL32_BASE: u64 = crate::AT_SALTYOS_KERNEL32_BASE;
const AT_SALTYOS_KERNEL32_SIZE: u64 = crate::AT_SALTYOS_KERNEL32_SIZE;

pub(crate) unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

pub(crate) fn append_nul_terminated_bytes(buf: &mut [u8], pos: &mut usize, bytes: &[u8]) {
    for &b in bytes {
        if *pos < buf.len() {
            buf[*pos] = b;
            *pos += 1;
        }
    }
    if *pos < buf.len() {
        buf[*pos] = 0;
        *pos += 1;
    }
}

pub(crate) unsafe fn pack_spawn_argv_strings(
    msg: &TronaMsg,
    args_reg_idx: usize,
    spawn_args_len: usize,
    name: &[u8],
    name_len: usize,
    exec_path: &[u8],
    exec_path_len: usize,
    buf: &mut [u8],
    ensure_trailing_nul: bool,
) -> (u32, usize) {
    let mut pos = 0usize;
    let argv0 = if exec_path_len != 0 {
        &exec_path[..exec_path_len]
    } else {
        &name[..name_len]
    };
    append_nul_terminated_bytes(buf, &mut pos, argv0);

    let mut argc: u32 = 1;
    if spawn_args_len > 0 && msg.length as usize > args_reg_idx && pos < buf.len() {
        let src = &msg.regs[args_reg_idx] as *const u64 as *const u8;
        let copy_len = core::cmp::min(spawn_args_len, buf.len() - pos);
        let mut saw_nonzero = false;
        let mut in_arg = false;
        for i in 0..copy_len {
            let b = unsafe { *src.add(i) };
            buf[pos] = b;
            pos += 1;
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
        if ensure_trailing_nul && saw_nonzero && in_arg && pos < buf.len() {
            buf[pos] = 0;
            pos += 1;
        }
    }

    (argc, pos)
}

pub(crate) unsafe fn alloc_zeroed_staged_stack_page(
    alloc: &mut Allocator,
    reply: &mut TronaMsg,
    pid: u32,
) -> Option<*mut u8> {
    unsafe {
        let stack_stage = crate::loader::mem_util::alloc_staging_buffer(1);
        if stack_stage.is_null() {
            crate::base::mmsrv_ipc::deregister_from_mmsrv(pid);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return None;
        }
        crate::loader::mem_util::volatile_zero(stack_stage, 4096);
        Some(stack_stage)
    }
}

pub(crate) unsafe fn alloc_zeroed_exec_stack_page() -> Option<*mut u8> {
    unsafe {
        let stack_stage = crate::loader::mem_util::alloc_staging_buffer(1);
        if stack_stage.is_null() {
            None
        } else {
            crate::loader::mem_util::volatile_zero(stack_stage, 4096);
            Some(stack_stage)
        }
    }
}

pub(crate) unsafe fn commit_staged_top_stack_page(
    alloc: &mut Allocator,
    reply: &mut TronaMsg,
    pid: u32,
    stack_base: u64,
    stack_top: u64,
    stack_pages: usize,
    stack_stage: *mut u8,
) -> bool {
    unsafe {
        match crate::base::mmsrv_ipc::alloc_private_copy_from_client_region_to_mmsrv(
            pid,
            stack_base,
            stack_pages as u64,
            stack_top - 4096,
            stack_stage as u64,
            1,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        ) {
            Ok(base) if base == stack_base => true,
            _ => {
                crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
                crate::base::mmsrv_ipc::deregister_from_mmsrv(pid);
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = TRONA_OUT_OF_MEMORY;
                false
            }
        }
    }
}

pub(crate) unsafe fn commit_exec_stack_page(
    pid: u32,
    stack_base: u64,
    stack_top: u64,
    stack_pages: usize,
    stack_stage: *mut u8,
) -> bool {
    unsafe {
        match crate::base::mmsrv_ipc::alloc_private_copy_from_client_region_to_mmsrv(
            pid,
            stack_base,
            stack_pages as u64,
            stack_top - 4096,
            stack_stage as u64,
            1,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        ) {
            Ok(base) if base == stack_base => true,
            _ => {
                crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
                false
            }
        }
    }
}

unsafe fn write_runtime_stack_with_aux_entries(
    stk_frame: Cap,
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    aux_entries: &mut [(u64, u64)],
    cspace_layout: trona::TronaCspaceLayoutV1,
    cap_table_builder: Option<&trona::cap_table::CapTableBuilder>,
    stack_top: u64,
    page_base: *mut u8,
    pre_mapped: bool,
    scratch_map_error: &[u8],
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
                trona::uerror!(|_lb| {
                    _lb.bytes(scratch_map_error);
                });
                return Err(StackBuildError::OutOfMemory);
            }
        }

        let cap_tbl_size = cap_table_builder.map_or(0, |b| b.byte_len());
        let prepared = match prepare_stack_page_layout(
            argc,
            envc,
            str_data,
            str_len,
            page_base,
            stack_top,
            cap_tbl_size,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                if !pre_mapped {
                    trona::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
                }
                return Err(err);
            }
        };

        for aux in aux_entries.iter_mut() {
            if aux.0 == AT_TRONA_CSPACE_LAYOUT && aux.1 == 0 {
                aux.1 = prepared.desc_child_addr;
            }
            if aux.0 == AT_TRONA_CAP_TABLE && aux.1 == 0 {
                aux.1 = prepared.cap_tbl_child_addr;
            }
        }

        let rsp = match write_prepared_stack_metadata(
            &prepared,
            aux_entries,
            Some(cspace_layout),
            cap_table_builder,
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
    cspace_layout: trona::TronaCspaceLayoutV1,
    cap_layout: &ChildCapLayout,
    page_base: *mut u8,
    pre_mapped: bool,
    // service_name: name for `Require=` lookup, or empty for fork/exec paths
    //               where no fresh resolve is needed.
    // pid:          consumer pid - used to badge minted local-role caps.
    // child_cn:     target child CSpace cap, into which local-role caps are minted.
    service_name: &[u8],
    pid: u32,
    child_cn: Cap,
) -> Result<u64, StackBuildError> {
    unsafe {
        if phdr_vaddr == 0 || phent == 0 || phnum == 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] dynamic phdr info extraction failed\n");
            });
            return Err(StackBuildError::InvalidArgument);
        }

        let mut aux_entries = [(0u64, 0u64); 32];
        let mut aux_count = 0usize;
        let mut push_aux = |tag: u64, value: u64| {
            aux_entries[aux_count] = (tag, value);
            aux_count += 1;
        };

        push_aux(AT_PHDR, phdr_vaddr);
        push_aux(AT_PHENT, phent);
        push_aux(AT_PHNUM, phnum);
        push_aux(AT_ENTRY, elf_result.entry);
        push_aux(AT_BASE, rtld_result.base);
        push_aux(AT_PAGESZ, 4096);
        push_aux(AT_TRONA_VSPACE, cap_layout.self_vspace);
        push_aux(AT_TRONA_SCRATCH, scratch_vaddr);
        push_aux(AT_TRONA_INITRD, initrd_vaddr);
        push_aux(AT_TRONA_INITRD_SZ, initrd_window_size as u64);
        push_aux(AT_TRONA_CSPACE_LAYOUT, 0);
        push_aux(AT_TRONA_CAP_TABLE, 0);
        push_aux(AT_TRONA_CSPACE_NTFN, cap_layout.cspace_ntfn);
        push_aux(AT_TRONA_IPC_BUFFER, trona::layout::IPC_BUF_BASE);
        push_aux(AT_TRONA_SC_CAP, cap_layout.sc);
        // All role-bearing caps (PROCMGR_CONTROL, VFS_CLIENT, NAMESRV_CLIENT,
        // SIGNAL_NTFN, MMSRV_CLIENT, READINESS_NTFN, SERVICE_EP,
        // INITRD_UNTYPED, FB_UNTYPED) now flow exclusively through the
        // cap_table populated below — no legacy AT_TRONA_*_EP emit.
        if shared_lib_base != 0 {
            push_aux(AT_TRONA_SHARED_LIB_BASE, shared_lib_base);
        }

        let mut cap_tbl_builder = trona::cap_table::CapTableBuilder::new();
        let _ = cap_layout.populate_cap_table(&mut cap_tbl_builder);
        // Resolve service-local Require= entries (drawn from procmgr's
        // SERVICE_REGISTRY) and mint the corresponding caps into the
        // child's [extras_base, frame_slot_start) cspace window. A
        // failure here means the consumer would start with an
        // incomplete cap_table — fail the spawn rather than letting the
        // child fault on its first use of the missing cap.
        if !service_name.is_empty() {
            if crate::service::registry::resolve_local_requires(
                service_name,
                pid,
                child_cn,
                cap_layout,
                &mut cap_tbl_builder,
            )
            .is_err()
            {
                return Err(StackBuildError::InvalidArgument);
            }
        }

        write_runtime_stack_with_aux_entries(
            stk_frame,
            argc,
            envc,
            str_data,
            str_len,
            &mut aux_entries[..aux_count],
            cspace_layout,
            Some(&cap_tbl_builder),
            stack_top,
            page_base,
            pre_mapped,
            b"[PROCMGR] dynamic stack scratch map failed\n",
        )
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
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] static stack scratch map failed\n");
                });
                return Err(StackBuildError::OutOfMemory);
            }
        }

        let rsp = match write_stack_with_args(
            argc,
            envc,
            str_data,
            str_len,
            None,
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
struct PreparedStackPage {
    page_base: *mut u8,
    child_page_base: u64,
    desc_start: usize,
    desc_child_addr: u64,
    /// Offset inside the page where the `TronaCapTableV1` header begins.
    /// Zero (together with `cap_tbl_child_addr == 0`) means this spawn
    /// carries no cap_table (e.g. a static exec).
    cap_tbl_start: usize,
    /// Child VA of the cap_table, or 0 when absent.
    cap_tbl_child_addr: u64,
    arg_count: usize,
    env_count: usize,
    argv_ptrs: [u64; MAX_STACK_STRINGS],
    envp_ptrs: [u64; MAX_STACK_STRINGS],
}

unsafe fn prepare_stack_page_layout(
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    page_base: *mut u8,
    stack_top: u64,
    cap_tbl_size: usize,
) -> Result<PreparedStackPage, StackBuildError> {
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

        let Some(str_area_start) = 4096usize.checked_sub(str_len) else {
            return Err(StackBuildError::TooLarge);
        };
        for i in 0..str_len {
            core::ptr::write_volatile(page_base.add(str_area_start + i), str_data[i]);
        }

        let mut prepared = PreparedStackPage {
            page_base,
            child_page_base,
            desc_start: 0,
            desc_child_addr: 0,
            cap_tbl_start: 0,
            cap_tbl_child_addr: 0,
            arg_count: 0,
            env_count: 0,
            argv_ptrs: [0; MAX_STACK_STRINGS],
            envp_ptrs: [0; MAX_STACK_STRINGS],
        };

        let mut pos = 0usize;
        while prepared.arg_count < argc as usize {
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
            prepared.argv_ptrs[prepared.arg_count] =
                child_page_base + str_area_start as u64 + str_start as u64;
            prepared.arg_count += 1;
            pos += 1;
        }

        while prepared.env_count < envc as usize {
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
            prepared.envp_ptrs[prepared.env_count] =
                child_page_base + str_area_start as u64 + str_start as u64;
            prepared.env_count += 1;
            pos += 1;
        }

        let cspace_layout_size = core::mem::size_of::<trona::TronaCspaceLayoutV1>();
        let desc_end = str_area_start;
        let Some(desc_floor) = desc_end.checked_sub(cspace_layout_size) else {
            return Err(StackBuildError::TooLarge);
        };
        prepared.desc_start = desc_floor & !0x7;
        prepared.desc_child_addr = child_page_base + prepared.desc_start as u64;

        // Reserve the cap_table region immediately below the cspace layout
        // (growing toward the metadata area). When `cap_tbl_size == 0` the
        // caller has no table and both fields stay zero.
        if cap_tbl_size > 0 {
            let Some(cap_tbl_floor) = prepared.desc_start.checked_sub(cap_tbl_size) else {
                return Err(StackBuildError::TooLarge);
            };
            prepared.cap_tbl_start = cap_tbl_floor & !0x7;
            prepared.cap_tbl_child_addr = child_page_base + prepared.cap_tbl_start as u64;
        }

        Ok(prepared)
    }
}

unsafe fn write_prepared_stack_metadata(
    prepared: &PreparedStackPage,
    aux_entries: &[(u64, u64)],
    cspace_layout: Option<trona::TronaCspaceLayoutV1>,
    cap_table: Option<&trona::cap_table::CapTableBuilder>,
) -> Result<u64, StackBuildError> {
    unsafe {
        let auxv_u64s = (aux_entries.len() + 1) * 2;
        let metadata_u64s = 1 + prepared.arg_count + 1 + prepared.env_count + 1 + auxv_u64s;
        let metadata_bytes = metadata_u64s * 8;
        // Metadata grows upward from the bottom of the cap_table region (if
        // present) or the cspace layout otherwise.
        let metadata_end = if prepared.cap_tbl_child_addr != 0 {
            prepared.cap_tbl_start
        } else {
            prepared.desc_start
        };
        let Some(metadata_floor) = metadata_end.checked_sub(metadata_bytes) else {
            return Err(StackBuildError::TooLarge);
        };
        let Some(metadata_start) = (metadata_floor & !0xF).checked_sub(STACK_ENTRY_BIAS) else {
            return Err(StackBuildError::TooLarge);
        };

        let stack_u64 = prepared.page_base.add(metadata_start) as *mut u64;
        let mut wi: usize = 0;
        let mut w = |v: u64| {
            core::ptr::write_volatile(stack_u64.add(wi), v);
            wi += 1;
        };

        w(prepared.arg_count as u64);
        for i in 0..prepared.arg_count {
            w(prepared.argv_ptrs[i]);
        }
        w(0);
        for i in 0..prepared.env_count {
            w(prepared.envp_ptrs[i]);
        }
        w(0);

        if let Some(cspace_layout) = cspace_layout {
            core::ptr::write(
                prepared.page_base.add(prepared.desc_start) as *mut trona::TronaCspaceLayoutV1,
                cspace_layout,
            );
        }

        if let Some(cap_table) = cap_table {
            if prepared.cap_tbl_child_addr != 0 {
                let cap_tbl_addr = prepared.page_base.add(prepared.cap_tbl_start);
                let _ = cap_table.write_at(cap_tbl_addr);
            }
        }

        for &(tag, value) in aux_entries {
            w(tag);
            w(value);
        }
        w(AT_NULL);
        w(0);

        Ok(prepared.child_page_base + metadata_start as u64)
    }
}

unsafe fn write_stack_with_args(
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    auxv_info: Option<(
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        trona::TronaCspaceLayoutV1,
    )>,
    cap_layout: Option<&ChildCapLayout>,
    page_base: *mut u8,
    scratch_vaddr: u64,
    initrd_vaddr: u64,
    stack_top: u64,
) -> Result<u64, StackBuildError> {
    unsafe {
        match auxv_info {
            Some((
                _entries,
                phdr,
                phent,
                phnum,
                entry,
                base,
                initrd_sz,
                shared_lib,
                cspace_layout,
            )) => {
                // If auxv_info is Some, cap_layout must also be Some — they
                // always travel together along the dynamic-exec path.
                let cap_layout = cap_layout.expect("auxv_info without cap_layout");

                let mut cap_tbl_builder = trona::cap_table::CapTableBuilder::new();
                let _ = cap_layout.populate_cap_table(&mut cap_tbl_builder);
                let cap_tbl_size = cap_tbl_builder.byte_len();

                let prepared = prepare_stack_page_layout(
                    argc,
                    envc,
                    str_data,
                    str_len,
                    page_base,
                    stack_top,
                    cap_tbl_size,
                )?;

                let mut aux_entries = [(0u64, 0u64); 32];
                let mut aux_count = 0usize;
                let mut push_aux = |tag: u64, value: u64| {
                    aux_entries[aux_count] = (tag, value);
                    aux_count += 1;
                };

                push_aux(AT_PHDR, phdr);
                push_aux(AT_PHENT, phent);
                push_aux(AT_PHNUM, phnum);
                push_aux(AT_ENTRY, entry);
                push_aux(AT_BASE, base);
                push_aux(AT_PAGESZ, 4096);
                push_aux(AT_TRONA_VSPACE, cap_layout.self_vspace);
                push_aux(AT_TRONA_SCRATCH, scratch_vaddr);
                push_aux(AT_TRONA_INITRD, initrd_vaddr);
                push_aux(AT_TRONA_INITRD_SZ, initrd_sz);
                push_aux(AT_TRONA_CSPACE_LAYOUT, prepared.desc_child_addr);
                push_aux(AT_TRONA_CAP_TABLE, prepared.cap_tbl_child_addr);
                push_aux(AT_TRONA_CSPACE_NTFN, cap_layout.cspace_ntfn);
                push_aux(AT_TRONA_IPC_BUFFER, trona::layout::IPC_BUF_BASE);
                push_aux(AT_TRONA_SC_CAP, cap_layout.sc);
                // Role-bearing caps (PROCMGR_CONTROL, VFS_CLIENT,
                // NAMESRV_CLIENT, SIGNAL_NTFN, MMSRV_CLIENT, READINESS_NTFN,
                // SERVICE_EP, INITRD_UNTYPED, FB_UNTYPED) flow exclusively
                // through the cap_table populated below.
                if shared_lib != 0 {
                    push_aux(AT_TRONA_SHARED_LIB_BASE, shared_lib);
                }

                write_prepared_stack_metadata(
                    &prepared,
                    &aux_entries[..aux_count],
                    Some(cspace_layout),
                    Some(&cap_tbl_builder),
                )
            }
            None => {
                let prepared = prepare_stack_page_layout(
                    argc, envc, str_data, str_len, page_base, stack_top, 0,
                )?;
                write_prepared_stack_metadata(&prepared, &[], None, None)
            }
        }
    }
}

/// Build the PE-specific stack with Win32 auxv entries.
///
/// Stack layout is the same as the ELF dynamic stack but with PE-specific
/// aux entries (AT_SALTYOS_PE_BASE, AT_SALTYOS_WIN32SRV, etc.).
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
    cspace_layout: trona::TronaCspaceLayoutV1,
    cap_layout: &ChildCapLayout,
    // service_name: name for `Require=` lookup, or empty for fork/exec paths
    //               where no fresh resolve is needed.
    // pid:          consumer pid - used to badge minted local-role caps.
    // child_cn:     target child CSpace cap, into which local-role caps are minted.
    service_name: &[u8],
    pid: u32,
    child_cn: Cap,
) -> Result<u64, StackBuildError> {
    unsafe {
        let mut aux_entries = [(0u64, 0u64); 32];
        let mut aux_count = 0usize;
        let mut push_aux = |tag: u64, value: u64| {
            aux_entries[aux_count] = (tag, value);
            aux_count += 1;
        };

        push_aux(AT_SALTYOS_PE_BASE, pe_result.base);
        push_aux(AT_SALTYOS_PE_SIZE, pe_result.image_end - pe_result.base);
        push_aux(AT_SALTYOS_WIN32SRV, win32srv_ep);
        push_aux(AT_SALTYOS_KERNEL32_BASE, kernel32_result.base);
        push_aux(
            AT_SALTYOS_KERNEL32_SIZE,
            kernel32_result.image_end - kernel32_result.base,
        );
        push_aux(AT_BASE, rtld_result.base);
        push_aux(AT_ENTRY, pe_result.entry);
        push_aux(AT_PAGESZ, 4096);
        push_aux(AT_TRONA_VSPACE, cap_layout.self_vspace);
        push_aux(AT_TRONA_SCRATCH, scratch_vaddr);
        push_aux(AT_TRONA_IPC_BUFFER, ipc_buffer_vaddr);
        push_aux(AT_TRONA_CSPACE_LAYOUT, 0);
        push_aux(AT_TRONA_CAP_TABLE, 0);
        push_aux(AT_TRONA_CSPACE_NTFN, cap_layout.cspace_ntfn);
        push_aux(AT_TRONA_SC_CAP, cap_layout.sc);
        // Role-bearing caps (PROCMGR_CONTROL, VFS_CLIENT, NAMESRV_CLIENT,
        // SIGNAL_NTFN, MMSRV_CLIENT, READINESS_NTFN, SERVICE_EP,
        // INITRD_UNTYPED, FB_UNTYPED) flow exclusively through the
        // cap_table populated below.

        let mut cap_tbl_builder = trona::cap_table::CapTableBuilder::new();
        let _ = cap_layout.populate_cap_table(&mut cap_tbl_builder);
        // Same `Require=` resolution as the ELF dynamic stack — empty
        // `service_name` short-circuits, otherwise resolve failures abort
        // the spawn rather than ship a partial cap_table.
        if !service_name.is_empty() {
            if crate::service::registry::resolve_local_requires(
                service_name,
                pid,
                child_cn,
                cap_layout,
                &mut cap_tbl_builder,
            )
            .is_err()
            {
                return Err(StackBuildError::InvalidArgument);
            }
        }

        write_runtime_stack_with_aux_entries(
            0,
            argc,
            envc,
            str_data,
            str_len,
            &mut aux_entries[..aux_count],
            cspace_layout,
            Some(&cap_tbl_builder),
            stack_top,
            page_base,
            true,
            b"[PROCMGR] PE stack scratch map failed\n",
        )
    }
}
