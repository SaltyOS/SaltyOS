// SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::pe::*;
use trona_kernel::core_types::*;

use trona_runtime::spawn::layout::ChildCapLayout;
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

const VSPACE_FLAG_WRITABLE: u64 = uapi::KERNITE_PAGE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = uapi::KERNITE_PAGE_FLAG_USER;
const TRONA_OUT_OF_MEMORY: u64 = trona_protocol::posix::TRONA_OUT_OF_MEMORY;
const PROCMGR_SCRATCH_VADDR: u64 = crate::PROCMGR_SCRATCH_VADDR;
const CAP_SELF_VSPACE: Cap = crate::CAP_SELF_VSPACE;

const AT_NULL: u64 = crate::AT_NULL;
const AT_PHDR: u64 = crate::AT_PHDR;
const AT_PHENT: u64 = crate::AT_PHENT;
const AT_PHNUM: u64 = crate::AT_PHNUM;
const AT_PAGESZ: u64 = crate::AT_PAGESZ;
const AT_BASE: u64 = crate::AT_BASE;
const AT_ENTRY: u64 = crate::AT_ENTRY;
const AT_SALTYOS_STARTUP: u64 = trona_kernel::core_types::AT_SALTYOS_STARTUP;

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
    reply: &mut TronaMsg,
    slot_idx: usize,
) -> Option<*mut u8> {
    unsafe {
        let stack_stage = crate::loader::mem_util::alloc_staging_buffer(1);
        if stack_stage.is_null() {
            crate::lifecycle::exit::abort_spawning_process(slot_idx);
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
    reply: &mut TronaMsg,
    slot_idx: usize,
    stack_top: u64,
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
    stack_stage: *mut u8,
    child_tcb: Cap,
) -> bool {
    unsafe {
        let pid = crate::base::proc_table::proctab(slot_idx).pid;
        match commit_stack_region_impl(pid, stack_top, stack_spec, stack_stage, child_tcb) {
            Ok(()) => true,
            Err(label) => {
                crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
                crate::lifecycle::exit::abort_spawning_process(slot_idx);
                reply.label = if label != 0 {
                    label
                } else {
                    TRONA_OUT_OF_MEMORY
                };
                false
            }
        }
    }
}

pub(crate) unsafe fn commit_exec_stack_page(
    pid: u32,
    stack_top: u64,
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
    stack_stage: *mut u8,
    child_tcb: Cap,
) -> bool {
    unsafe {
        match commit_stack_region_impl(pid, stack_top, stack_spec, stack_stage, child_tcb) {
            Ok(()) => true,
            Err(_) => {
                crate::loader::mem_util::free_staging_buffer(stack_stage, 1);
                false
            }
        }
    }
}

/// Shared implementation: allocate the full stack region via mmsrv
/// (MM_ALLOC_STACK_REGION — full-span reserve + prefault commit +
/// DEMAND PTE + unmapped guard) and publish the authoritative bounds
/// to the child TCB via TCB_SET_STACK_BOUNDS.
unsafe fn commit_stack_region_impl(
    pid: u32,
    stack_top: u64,
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
    stack_stage: *mut u8,
    child_tcb: Cap,
) -> Result<(), u64> {
    let mat = trona_runtime::spawn::stack_plan::plan_stack_materialization(stack_spec, stack_top)
        .ok_or(trona_protocol::posix::TRONA_INVALID_ARGUMENT)?;
    let reserve_base = match crate::base::mmsrv_ipc::alloc_stack_region_in_mmsrv(
        pid,
        stack_top,
        mat.mo_pages as u64,
        mat.commit_count_pages as u64,
        stack_spec.guard_pages as u64,
        VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        stack_stage as u64,
        1,
    ) {
        Ok(base) if base == mat.reserve_base => base,
        Ok(base) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] commit_stack_region_impl: stack base mismatch pid=");
                _lb.hex(pid as u64);
                _lb.str(b" expected=");
                _lb.hex(mat.reserve_base);
                _lb.str(b" got=");
                _lb.hex(base);
                _lb.str(b"\n");
            });
            return Err(trona_protocol::posix::TRONA_BAD_ADDRESS);
        }
        Err((ipc_err, reply_label)) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] commit_stack_region_impl: alloc_stack_region failed pid=");
                _lb.hex(pid as u64);
                _lb.str(b" top=");
                _lb.hex(stack_top);
                _lb.str(b" reserve_pages=");
                _lb.hex(mat.mo_pages as u64);
                _lb.str(b" prefault_pages=");
                _lb.hex(mat.commit_count_pages as u64);
                _lb.str(b" guard_pages=");
                _lb.hex(stack_spec.guard_pages as u64);
                _lb.str(b" ipc=");
                _lb.hex(ipc_err as u64);
                _lb.str(b" label=");
                _lb.hex(reply_label);
                _lb.str(b"\n");
            });
            return Err(if reply_label != 0 {
                reply_label
            } else {
                TRONA_OUT_OF_MEMORY
            });
        }
    };

    // If bounds publication fails, we need to tear down the stack
    // region in mmsrv so the child VSpace does not leak a half-built
    // REGION_STACK mapping whose TCB cache never got the matching
    // bounds (memory-model-audit I21).
    let err = trona_kernel::invoke::tcb_set_stack_bounds(
        child_tcb,
        mat.stack_top,
        mat.reserve_base,
        mat.guard_bottom,
    );
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] commit_stack_region_impl: tcb_set_stack_bounds failed pid=");
            _lb.hex(pid as u64);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        if let Err((ipc_err, reply_label)) =
            crate::base::mmsrv_ipc::free_stack_region_in_mmsrv(pid, reserve_base)
        {
            trona_runtime::uerror!(|_lb| {
                _lb.str(
                    b"[PROCMGR] commit_stack_region_impl: rollback free_stack_region failed ipc=",
                );
                _lb.hex(ipc_err as u64);
                _lb.str(b" label=");
                _lb.hex(reply_label);
                _lb.str(b"\n");
            });
        }
        return Err(err as u64);
    }
    Ok(())
}

unsafe fn write_runtime_stack_with_aux_entries(
    stk_frame: Cap,
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    aux_entries: &mut [(u64, u64)],
    mut startup: Option<trona_kernel::core_types::SaltyOSStartupLayoutV1>,
    cspace_layout: trona_kernel::core_types::SaltyOSCspaceLayoutV1,
    cap_table_builder: Option<&trona_runtime::spawn::cap_table::CapTableBuilder>,
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
            let err = trona_kernel::invoke::vspace_map(
                CAP_SELF_VSPACE,
                stk_frame,
                PROCMGR_SCRATCH_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.bytes(scratch_map_error);
                });
                return Err(StackBuildError::OutOfMemory);
            }
        }

        let startup_size = startup
            .as_ref()
            .map(|_| core::mem::size_of::<trona_kernel::core_types::SaltyOSStartupLayoutV1>())
            .unwrap_or(0);
        let cap_tbl_size = cap_table_builder.map_or(0, |b| b.byte_len());
        let prepared = match prepare_stack_page_layout(
            argc,
            envc,
            str_data,
            str_len,
            page_base,
            stack_top,
            startup_size,
            cap_tbl_size,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                if !pre_mapped {
                    trona_kernel::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
                }
                return Err(err);
            }
        };

        for aux in aux_entries.iter_mut() {
            if aux.0 == AT_SALTYOS_STARTUP && aux.1 == 0 {
                aux.1 = prepared.startup_child_addr;
            }
        }
        if let Some(ref mut startup) = startup {
            if startup.cspace_layout_ptr == 0 {
                startup.cspace_layout_ptr = prepared.desc_child_addr;
            }
            if startup.cap_table_ptr == 0 {
                startup.cap_table_ptr = prepared.cap_tbl_child_addr;
            }
        }

        let rsp = match write_prepared_stack_metadata(
            &prepared,
            aux_entries,
            startup,
            Some(cspace_layout),
            cap_table_builder,
        ) {
            Ok(rsp) => rsp,
            Err(err) => {
                if !pre_mapped {
                    trona_kernel::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
                }
                return Err(err);
            }
        };

        if !pre_mapped {
            trona_kernel::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
        }
        Ok(rsp)
    }
}

/// Build the auxv/dynamic stack for a dynamically-linked child.
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
    mapped_images: &[trona_protocol::win32::SaltyOSMappedImageV1],
    dso_window_base: u64,
    dso_window_size: u64,
    argc: u32,
    envc: u32,
    str_data: &[u8],
    str_len: usize,
    scratch_vaddr: u64,
    stack_top: u64,
    cspace_layout: trona_kernel::core_types::SaltyOSCspaceLayoutV1,
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
    // Word 0 of the startup block's `preinstalled_slot_bitmap` — the CRT
    // uses this to skip lazy stdio binds for slots whose bit is set. The
    // spawner computes this from stdio_mode (PTY handoff success → 0b111,
    // CONSOLE/INHERIT → 0) and passes it through unchanged.
    preinstalled_stdio_bits: u64,
) -> Result<u64, StackBuildError> {
    unsafe {
        if phdr_vaddr == 0 || phent == 0 || phnum == 0 {
            trona_runtime::uerror!(|_lb| {
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
        push_aux(AT_SALTYOS_STARTUP, 0);

        let mut cap_tbl_builder = trona_runtime::spawn::cap_table::CapTableBuilder::new();
        let _ = cap_layout.populate_cap_table(&mut cap_tbl_builder);
        // Resolve registry-described attachment entries (drawn from
        // procmgr's SERVICE_REGISTRY) and materialize the supported
        // non-system ones into the child's
        // [extras_base, frame_slot_start) cspace window. A failure here
        // means the consumer would start with an incomplete cap_table —
        // fail the spawn rather than letting the child fault on its
        // first use of the missing cap.
        if !service_name.is_empty() {
            if crate::service::registry::resolve_registry_attachments(
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

        let mut startup = trona_kernel::core_types::SaltyOSStartupLayoutV1::new(
            trona_runtime::spawn::layout::IPC_BUF_BASE,
            scratch_vaddr,
            dso_window_base,
            dso_window_size,
            0,
            0,
        );
        startup.set_main_image(trona_protocol::win32::SaltyOSImageInfoV1::new(
            trona_protocol::win32::SALTYOS_IMAGE_KIND_ELF,
            0,
            elf_result.base,
            elf_result.brk.saturating_sub(elf_result.base),
            elf_result.entry,
        ));
        for mapped in mapped_images {
            let _ = startup.push_mapped_image(mapped.image, mapped.name_bytes());
        }
        startup.preinstalled_slot_bitmap[0] = preinstalled_stdio_bits;

        write_runtime_stack_with_aux_entries(
            stk_frame,
            argc,
            envc,
            str_data,
            str_len,
            &mut aux_entries[..aux_count],
            Some(startup),
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
            let err = trona_kernel::invoke::vspace_map(
                CAP_SELF_VSPACE,
                stk_frame,
                PROCMGR_SCRATCH_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                trona_runtime::uerror!(|_lb| {
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
            stack_top,
        ) {
            Ok(rsp) => rsp,
            Err(err) => {
                if !pre_mapped {
                    trona_kernel::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
                }
                return Err(err);
            }
        };

        if !pre_mapped {
            trona_kernel::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
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
    startup_start: usize,
    startup_child_addr: u64,
    /// Offset inside the page where the `SaltyOSCapTableV1` header begins.
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
    startup_size: usize,
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
            startup_start: 0,
            startup_child_addr: 0,
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

        let cspace_layout_size =
            core::mem::size_of::<trona_kernel::core_types::SaltyOSCspaceLayoutV1>();
        let desc_end = str_area_start;
        let Some(desc_floor) = desc_end.checked_sub(cspace_layout_size) else {
            return Err(StackBuildError::TooLarge);
        };
        prepared.desc_start = desc_floor & !0x7;
        prepared.desc_child_addr = child_page_base + prepared.desc_start as u64;

        // Reserve the cap_table and startup block immediately below the
        // cspace layout (growing toward the metadata area).
        if cap_tbl_size > 0 {
            let Some(cap_tbl_floor) = prepared.desc_start.checked_sub(cap_tbl_size) else {
                return Err(StackBuildError::TooLarge);
            };
            prepared.cap_tbl_start = cap_tbl_floor & !0x7;
            prepared.cap_tbl_child_addr = child_page_base + prepared.cap_tbl_start as u64;
        }
        if startup_size > 0 {
            let startup_end = if prepared.cap_tbl_child_addr != 0 {
                prepared.cap_tbl_start
            } else {
                prepared.desc_start
            };
            let Some(startup_floor) = startup_end.checked_sub(startup_size) else {
                return Err(StackBuildError::TooLarge);
            };
            prepared.startup_start = startup_floor & !0x7;
            prepared.startup_child_addr = child_page_base + prepared.startup_start as u64;
        }

        Ok(prepared)
    }
}

unsafe fn write_prepared_stack_metadata(
    prepared: &PreparedStackPage,
    aux_entries: &[(u64, u64)],
    startup: Option<trona_kernel::core_types::SaltyOSStartupLayoutV1>,
    cspace_layout: Option<trona_kernel::core_types::SaltyOSCspaceLayoutV1>,
    cap_table: Option<&trona_runtime::spawn::cap_table::CapTableBuilder>,
) -> Result<u64, StackBuildError> {
    unsafe {
        let auxv_u64s = (aux_entries.len() + 1) * 2;
        let metadata_u64s = 1 + prepared.arg_count + 1 + prepared.env_count + 1 + auxv_u64s;
        let metadata_bytes = metadata_u64s * 8;
        // Metadata grows upward from the bottom of the startup block, then the
        // cap_table, then the cspace layout.
        let metadata_end = if prepared.startup_child_addr != 0 {
            prepared.startup_start
        } else if prepared.cap_tbl_child_addr != 0 {
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
                prepared.page_base.add(prepared.desc_start)
                    as *mut trona_kernel::core_types::SaltyOSCspaceLayoutV1,
                cspace_layout,
            );
        }

        if let Some(cap_table) = cap_table {
            if prepared.cap_tbl_child_addr != 0 {
                let cap_tbl_addr = prepared.page_base.add(prepared.cap_tbl_start);
                let _ = cap_table.write_at(cap_tbl_addr);
            }
        }
        if let Some(startup) = startup {
            if prepared.startup_child_addr != 0 {
                core::ptr::write(
                    prepared.page_base.add(prepared.startup_start)
                        as *mut trona_kernel::core_types::SaltyOSStartupLayoutV1,
                    startup,
                );
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
        trona_kernel::core_types::SaltyOSCspaceLayoutV1,
    )>,
    cap_layout: Option<&ChildCapLayout>,
    page_base: *mut u8,
    scratch_vaddr: u64,
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
                _initrd_sz,
                shared_lib,
                cspace_layout,
            )) => {
                // If auxv_info is Some, cap_layout must also be Some — they
                // always travel together along the dynamic-exec path.
                let cap_layout = cap_layout.expect("auxv_info without cap_layout");

                let mut cap_tbl_builder = trona_runtime::spawn::cap_table::CapTableBuilder::new();
                let _ = cap_layout.populate_cap_table(&mut cap_tbl_builder);
                let cap_tbl_size = cap_tbl_builder.byte_len();

                let prepared = prepare_stack_page_layout(
                    argc,
                    envc,
                    str_data,
                    str_len,
                    page_base,
                    stack_top,
                    core::mem::size_of::<trona_kernel::core_types::SaltyOSStartupLayoutV1>(),
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
                push_aux(AT_SALTYOS_STARTUP, prepared.startup_child_addr);

                let mut startup = trona_kernel::core_types::SaltyOSStartupLayoutV1::new(
                    trona_runtime::spawn::layout::IPC_BUF_BASE,
                    scratch_vaddr,
                    shared_lib,
                    0,
                    prepared.cap_tbl_child_addr,
                    prepared.desc_child_addr,
                );
                startup.set_main_image(trona_protocol::win32::SaltyOSImageInfoV1::new(
                    trona_protocol::win32::SALTYOS_IMAGE_KIND_ELF,
                    0,
                    base,
                    0,
                    entry,
                ));
                // `write_static_stack` (the sole caller of
                // `write_stack_with_args` that reaches this branch) has
                // no spawner-side knowledge of stdio preinstall state;
                // leave `preinstalled_slot_bitmap` at its zeroed
                // default. Static execs today come from test paths
                // that do a lazy `/dev/console` bind anyway.

                write_prepared_stack_metadata(
                    &prepared,
                    &aux_entries[..aux_count],
                    Some(startup),
                    Some(cspace_layout),
                    Some(&cap_tbl_builder),
                )
            }
            None => {
                let prepared = prepare_stack_page_layout(
                    argc, envc, str_data, str_len, page_base, stack_top, 0, 0,
                )?;
                write_prepared_stack_metadata(&prepared, &[], None, None, None)
            }
        }
    }
}

/// Build the PE-specific stack with a startup block that fully describes the
/// main image and any already-mapped DLLs.
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
    cspace_layout: trona_kernel::core_types::SaltyOSCspaceLayoutV1,
    cap_layout: &ChildCapLayout,
    // service_name: name for `Require=` lookup, or empty for fork/exec paths
    //               where no fresh resolve is needed.
    // pid:          consumer pid - used to badge minted local-role caps.
    // child_cn:     target child CSpace cap, into which local-role caps are minted.
    service_name: &[u8],
    pid: u32,
    child_cn: Cap,
    // Word 0 of the startup block's `preinstalled_slot_bitmap` — see
    // `write_dynamic_stack` for the rationale.
    preinstalled_stdio_bits: u64,
) -> Result<u64, StackBuildError> {
    unsafe {
        let mut aux_entries = [(0u64, 0u64); 32];
        let mut aux_count = 0usize;
        let mut push_aux = |tag: u64, value: u64| {
            aux_entries[aux_count] = (tag, value);
            aux_count += 1;
        };

        push_aux(AT_BASE, rtld_result.base);
        push_aux(AT_ENTRY, pe_result.entry);
        push_aux(AT_PAGESZ, 4096);
        push_aux(AT_SALTYOS_STARTUP, 0);

        let mut cap_tbl_builder = trona_runtime::spawn::cap_table::CapTableBuilder::new();
        let _ = cap_layout.populate_cap_table(&mut cap_tbl_builder);
        // Same registry-attachment resolution as the ELF dynamic stack —
        // empty `service_name` short-circuits, otherwise resolve
        // failures abort the spawn rather than ship a partial cap_table.
        if !service_name.is_empty() {
            if crate::service::registry::resolve_registry_attachments(
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

        let mut startup = trona_kernel::core_types::SaltyOSStartupLayoutV1::new(
            ipc_buffer_vaddr,
            scratch_vaddr,
            0,
            0,
            0,
            0,
        );
        startup.set_main_image(trona_protocol::win32::SaltyOSImageInfoV1::new(
            trona_protocol::win32::SALTYOS_IMAGE_KIND_PE,
            0,
            pe_result.base,
            pe_result.image_end.saturating_sub(pe_result.base),
            pe_result.entry,
        ));
        startup.preinstalled_slot_bitmap[0] = preinstalled_stdio_bits;
        let _ = startup.push_mapped_image(
            trona_protocol::win32::SaltyOSImageInfoV1::new(
                trona_protocol::win32::SALTYOS_IMAGE_KIND_PE,
                0,
                kernel32_result.base,
                kernel32_result
                    .image_end
                    .saturating_sub(kernel32_result.base),
                0,
            ),
            b"kernel32.dll",
        );
        let _ = win32srv_ep;

        write_runtime_stack_with_aux_entries(
            0,
            argc,
            envc,
            str_data,
            str_len,
            &mut aux_entries[..aux_count],
            Some(startup),
            cspace_layout,
            Some(&cap_tbl_builder),
            stack_top,
            page_base,
            true,
            b"[PROCMGR] PE stack scratch map failed\n",
        )
    }
}
