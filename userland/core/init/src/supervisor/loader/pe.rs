// SPDX-License-Identifier: GPL-2.0-only
//
//! PE image staging for init's post-mmsrv service/exec path.
//!
//! The manifest no longer selects a "subsystem". Init classifies the
//! executable by its on-disk magic, then stages the matching runtime:
//! ELF images use the existing ELF/DSO closure path, while PE images
//! get a PE main image, the PE rtld (`ldtrona-pe.so`), and the
//! preloaded `kernel32.dll` image advertised through
//! `SaltyOSStartupLayoutV1`.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_loader::common::image::{
    Carve, ImageEnvelope, ImageId, PlacementSink, Run, RunPlan, RunSource, map_image,
};
use trona_loader::common::pe::run_plan::{build_carves, plan_pe};
use trona_runtime::spawn::layout::{VmLayoutPlan, compute_vm_layout};
use trona_runtime::spawn::stack_plan::StackLayoutSpec;
use uapi::KERNITE_PAGE_BYTES;

use crate::supervisor::SupervisorState;
use crate::supervisor::ldsrv_adopt::mint_borrowed;
use crate::supervisor::loader::code_mo;
use crate::supervisor::loader::elf;
use crate::supervisor::loader::{cpio, stack};
use crate::supervisor::mm_ipc::{
    image_kind_from_prot, mm_stage_image_region_exec_flags, mm_stage_image_region_provided_flags,
};
use trona_protocol::mm::{
    STAGE_FLAG_EXEC_MATERIALIZE, STAGE_FLAG_EXEC_MO_SRC, STAGE_FLAG_EXEC_TXN,
    STAGE_FLAG_TXN_ID_SHIFT,
};
use trona_runtime::core::slot_alloc::{OwnedCap, resolved_cap_ref};

pub const PE_RTLD_PATH: &[u8] = b"/lib/ldtrona-pe.so";
pub const KERNEL32_PATH: &[u8] = b"/lib/kernel32.dll";
const MAX_PE_RUNS: usize = 128;
const MAX_PE_CARVES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Elf,
    Pe,
}

#[derive(Clone, Copy)]
pub struct PeLoadedImage {
    pub base: u64,
    pub size: u64,
    pub entry: u64,
}

pub struct PeLoadedProgram {
    pub entry_pc: u64,
    pub main: PeLoadedImage,
    pub rtld_base: u64,
    pub kernel32: PeLoadedImage,
    pub scratch_vaddr: u64,
    /// Layout plan from `compute_vm_layout`; exposes the planned runtime
    /// DSO window to the stack composer.
    pub plan: VmLayoutPlan,
}

#[inline]
fn invalid_argument() -> i32 {
    uapi::KERNITE_ERR_INVALID_ARGUMENT as i32
}

#[inline]
fn page_align_up(value: u64) -> Result<u64, i32> {
    let page = KERNITE_PAGE_BYTES as u64;
    value
        .checked_add(page - 1)
        .map(|v| v & !(page - 1))
        .ok_or_else(invalid_argument)
}

/// Canonical PE magic check (`MZ`). Used by `lifecycle::compute_spawn_layout`
/// to dispatch into the PE branch, and by `ldsrv_adopt` to skip non-PE
/// files. The boot ExecAuthority path is the only consumer that needs
/// the full header walk; classification is just the leading two bytes.
#[inline]
pub fn is_pe_header(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z'
}

pub fn detect_format(bytes: &[u8]) -> Result<ImageFormat, i32> {
    if bytes.len() >= 4 && bytes[..4] == *b"\x7fELF" {
        return Ok(ImageFormat::Elf);
    }
    if is_pe_header(bytes) {
        return Ok(ImageFormat::Pe);
    }
    Err(invalid_argument())
}

fn pe_image_size(bytes: &[u8]) -> Result<u64, i32> {
    let headers =
        unsafe { trona_loader::common::pe::header::validate(bytes.as_ptr(), bytes.len()) }
            .map_err(|_| invalid_argument())?;
    let image_size = headers.opt.size_of_image as u64;
    if image_size == 0 || headers.opt.address_of_entry_point as u64 >= image_size {
        return Err(invalid_argument());
    }
    Ok(image_size)
}

/// Public view of [`pe_image_size`]: layout planner reads the size of a PE
/// image from its headers (already in `&[u8]` form) without staging it.
/// Returns 0 on parse failure — the caller treats 0 as a layout failure.
pub fn pe_image_size_or_zero(bytes: &[u8]) -> u64 {
    pe_image_size(bytes).unwrap_or(0)
}

/// Layout-planner helper: return the byte size of the initrd-resident
/// kernel32 PE image, or 0 if it is missing or unparseable. The planner
/// treats 0 as a layout failure (`MmapWindowEmpty` upstream).
pub fn kernel32_size_or_zero(state: &SupervisorState) -> u64 {
    let Some(bytes) = cpio::find_file(state, KERNEL32_PATH) else {
        return 0;
    };
    pe_image_size(bytes).unwrap_or(0)
}

pub fn elf_load_span(bytes: &[u8]) -> Result<u64, i32> {
    let image = elf::parse(bytes)?;
    let Some((lo, hi)) = trona_loader::common::elf::header::load_span(image.phdrs) else {
        return Err(invalid_argument());
    };
    Ok(hi.saturating_sub(lo))
}

/// Shared PE layout planner used by both service spawn
/// (`compute_spawn_layout_pe`) and `INIT_EXEC`
/// (`compute_exec_layout_pe`). Both call sites must produce the same
/// `VmClientLayout` for a given PE image: the loader stages the same main
/// image + `ldtrona-pe.so` interpreter + preloaded `kernel32.dll`, so the
/// planner must reserve the same windows. Drift here previously broke
/// PE exec: `compute_exec_layout_pe` omitted the rtld span, so mmsrv's
/// region table never got an `interpreter_*` window and `ldtrona-pe.so`
/// had nowhere to map.
pub fn compute_pe_layout(
    state: &SupervisorState,
    image_bytes: &[u8],
    stack_spec: trona_runtime::spawn::stack_plan::StackLayoutSpec,
) -> Result<trona_runtime::spawn::layout::VmClientLayout, i32> {
    use trona_runtime::spawn::layout::compute_vm_layout;
    let main_span = pe_image_size_or_zero(image_bytes);
    let rtld_bytes =
        cpio::find_file(state, PE_RTLD_PATH).ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
    let kernel32_bytes =
        cpio::find_file(state, KERNEL32_PATH).ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
    let rtld_span =
        elf_load_span(rtld_bytes).map_err(|_| uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    let kernel32_span = pe_image_size_or_zero(kernel32_bytes);
    let preloaded = [kernel32_span];
    let plan = compute_vm_layout(main_span, rtld_span, &preloaded, false, 0, stack_spec)
        .map_err(|e| e.wire_code() as i32)?;
    Ok(plan.client_layout())
}

fn current_ipc_buffer_base() -> Result<*mut u8, i32> {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() || unsafe { (*ctx).ipc_buffer.is_null() } {
        return Err(uapi::KERNITE_ERR_INVALID_OPERATION as i32);
    }
    Ok(unsafe { (*ctx).ipc_buffer as *mut u8 })
}

fn mo_read_bytes(mo: CapRef, mut offset: u64, mut out: &mut [u8]) -> Result<(), i32> {
    let ipc = current_ipc_buffer_base()?;
    let max = uapi::KERNITE_IPC_BUFFER_SIZE as usize;
    while !out.is_empty() {
        let n = core::cmp::min(out.len(), max);
        let (err, got) = invoke::mo_read(mo, offset, n as u64);
        if err != 0 {
            return Err(err);
        }
        if got != n as u64 {
            return Err(uapi::KERNITE_ERR_IO_ERROR as i32);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(ipc as *const u8, out.as_mut_ptr(), n);
        }
        offset = offset.checked_add(n as u64).ok_or_else(invalid_argument)?;
        let (_, rest) = out.split_at_mut(n);
        out = rest;
    }
    Ok(())
}

fn resolve_pe_file_code_mo(state: &mut SupervisorState, bytes: &[u8]) -> Result<OwnedCap, i32> {
    // ldsrv resolves PE file backings by relaying them into memory-image MOs
    // before conferring EXECUTE. Init then plans and stages from that code MO.
    let backing = mint_borrowed(state, state.caps.initrd_va, bytes, false)?;
    let control_ep = state
        .ldsrv_exec_control_send
        .as_ref()
        .map(|c| c.as_raw())
        .unwrap_or(0);
    let resolved = unsafe {
        trona_runtime::client::ldsrv::resolve_main(
            control_ep,
            backing.into_transfer(),
            bytes.len() as u64,
            0,
        )
    }
    .map_err(|e| e as i32)?;
    Ok(resolved.code_mo)
}

struct PeProvidedSink<'a> {
    state: &'a SupervisorState,
    dst_client_id: u32,
    code_mo: CapRef,
    load_base: u64,
    txn_flags: u64,
}

impl PlacementSink for PeProvidedSink<'_> {
    type CodeMo = ();
    type Error = i32;

    fn begin_image(
        &mut self,
        _code_mo: (),
        _envelope: ImageEnvelope,
        _carves: &[Carve],
    ) -> Result<ImageId, i32> {
        Ok(ImageId::NONE)
    }

    fn place_run(&mut self, _image: ImageId, run: &Run) -> Result<(), i32> {
        let mem_size = run.bytes;
        let file_off = run.va.wrapping_sub(self.load_base);
        let (file_size, src_flags) = match run.source {
            RunSource::CleanFromCodeMo { .. } => (mem_size, 0),
            RunSource::PrivateFromCodeMo { file_bytes, .. } => {
                (file_bytes, STAGE_FLAG_EXEC_MATERIALIZE)
            }
            RunSource::ZeroFill => (0, STAGE_FLAG_EXEC_MATERIALIZE),
        };
        let prot = run.prot.0 as u64;
        mm_stage_image_region_provided_flags(
            self.state,
            self.dst_client_id,
            self.code_mo,
            run.va,
            file_off,
            file_size,
            mem_size,
            prot,
            image_kind_from_prot(prot),
            src_flags | self.txn_flags,
        )
    }
}

struct PeExecMoSink<'a> {
    state: &'a SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    txn_id: u64,
    load_base: u64,
}

impl PlacementSink for PeExecMoSink<'_> {
    type CodeMo = ();
    type Error = i32;

    fn begin_image(
        &mut self,
        _code_mo: (),
        _envelope: ImageEnvelope,
        _carves: &[Carve],
    ) -> Result<ImageId, i32> {
        Ok(ImageId::NONE)
    }

    fn place_run(&mut self, _image: ImageId, run: &Run) -> Result<(), i32> {
        let mem_size = run.bytes;
        let file_off = run.va.wrapping_sub(self.load_base);
        let (file_size, extra_flags) = match run.source {
            RunSource::CleanFromCodeMo { .. } => (mem_size, STAGE_FLAG_EXEC_MO_SRC),
            RunSource::PrivateFromCodeMo { file_bytes, .. } => (
                file_bytes,
                STAGE_FLAG_EXEC_MO_SRC | STAGE_FLAG_EXEC_MATERIALIZE,
            ),
            RunSource::ZeroFill => (0, STAGE_FLAG_EXEC_MO_SRC | STAGE_FLAG_EXEC_MATERIALIZE),
        };
        let prot = run.prot.0 as u64;
        mm_stage_image_region_exec_flags(
            self.state,
            self.src_client_id,
            0,
            self.dst_client_id,
            run.va,
            file_off,
            file_size,
            mem_size,
            prot,
            image_kind_from_prot(prot),
            self.txn_id,
            extra_flags,
        )
    }
}

fn build_plan_from_mo<'a>(
    header_bytes: &[u8],
    read_mo: CapRef,
    load_base: u64,
    runs: &'a mut [Run; MAX_PE_RUNS],
    carves: &'a mut [Carve; MAX_PE_CARVES],
) -> Result<(PeLoadedImage, RunPlan<'a>), i32> {
    let headers = unsafe {
        trona_loader::common::pe::header::validate(header_bytes.as_ptr(), header_bytes.len())
    }
    .map_err(|_| invalid_argument())?;
    let image_size = headers.opt.size_of_image as u64;
    if image_size == 0 || headers.opt.address_of_entry_point as u64 >= image_size {
        return Err(invalid_argument());
    }

    let mut read_at = |rva: u64, out: &mut [u8]| -> bool {
        let Some(end) = rva.checked_add(out.len() as u64) else {
            return false;
        };
        if end > image_size {
            return false;
        }
        mo_read_bytes(read_mo, rva, out).is_ok()
    };
    let carve_count = build_carves(&headers, header_bytes.as_ptr(), &mut read_at, carves)
        .map_err(|_| invalid_argument())?;
    let (envelope, run_count) = plan_pe(
        &headers,
        header_bytes.as_ptr(),
        load_base,
        &carves[..carve_count],
        runs,
    )
    .map_err(|_| invalid_argument())?;

    let entry = load_base
        .checked_add(headers.opt.address_of_entry_point as u64)
        .ok_or_else(invalid_argument)?;
    let loaded = PeLoadedImage {
        base: load_base,
        size: image_size,
        entry,
    };
    Ok((
        loaded,
        RunPlan {
            envelope,
            runs: &runs[..run_count],
            carves: &carves[..carve_count],
        },
    ))
}

fn stage_pe_image_from_exec_mo(
    state: &SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    header_bytes: &[u8],
    load_base: u64,
    exec_mo: CapRef,
    txn_id: u64,
) -> Result<PeLoadedImage, i32> {
    let mut runs = [Run::EMPTY; MAX_PE_RUNS];
    let mut carves = [Carve { rva: 0, bytes: 0 }; MAX_PE_CARVES];
    let (loaded, plan) =
        build_plan_from_mo(header_bytes, exec_mo, load_base, &mut runs, &mut carves)?;
    let mut sink = PeExecMoSink {
        state,
        src_client_id,
        dst_client_id,
        txn_id,
        load_base,
    };
    map_image(&mut sink, (), &plan).map(|_| loaded)
}

fn stage_pe_image_provided(
    state: &mut SupervisorState,
    dst_client_id: u32,
    bytes: &[u8],
    load_base: u64,
    txn_id: Option<u64>,
) -> Result<PeLoadedImage, i32> {
    let image_size = pe_image_size(bytes)?;
    let code_mo = resolve_pe_file_code_mo(state, bytes)?;

    let mut runs = [Run::EMPTY; MAX_PE_RUNS];
    let mut carves = [Carve { rva: 0, bytes: 0 }; MAX_PE_CARVES];
    let (loaded, plan) =
        match build_plan_from_mo(bytes, code_mo.borrow(), load_base, &mut runs, &mut carves) {
            Ok(plan) => plan,
            Err(e) => {
                drop(code_mo);
                return Err(e);
            }
        };
    if loaded.size != image_size {
        drop(code_mo);
        return Err(invalid_argument());
    }

    let txn_flags = match txn_id {
        Some(txn) => (txn << STAGE_FLAG_TXN_ID_SHIFT) | STAGE_FLAG_EXEC_TXN,
        None => 0,
    };
    let mut sink = PeProvidedSink {
        state: &*state,
        dst_client_id,
        code_mo: resolved_cap_ref(code_mo.as_raw()),
        load_base,
        txn_flags,
    };
    let result = map_image(&mut sink, (), &plan).map(|_| loaded);
    drop(code_mo);
    result
}

#[allow(clippy::too_many_arguments)]
pub fn load_pe_program_via_mmsrv(
    state: &mut SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    image_bytes: &[u8],
    exec_code_mo: Option<CapRef>,
    child_stack_top: u64,
    stack_spec: StackLayoutSpec,
    txn_id: Option<u64>,
) -> Result<PeLoadedProgram, i32> {
    let rtld_bytes =
        cpio::find_file(state, PE_RTLD_PATH).ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
    let kernel32_bytes =
        cpio::find_file(state, KERNEL32_PATH).ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;

    let main_span = pe_image_size(image_bytes)?;
    let rtld_span = elf_load_span(rtld_bytes)?;
    let kernel32_span = pe_image_size(kernel32_bytes)?;
    let _page_bytes = KERNITE_PAGE_BYTES as u64;

    // PE layout maps directly onto the new VmLayoutPlan fields: the PE
    // rtld (ldtrona-pe.so) is the interpreter, kernel32.dll is a
    // preloaded DSO. The planner places both at their natural bases.
    let layout = compute_vm_layout(main_span, rtld_span, &[kernel32_span], false, 0, stack_spec)
        .map_err(|e| e.wire_code() as i32)?;

    if layout.stack_top == 0
        || layout.stack_top != child_stack_top
        || layout.interpreter.base == 0
        || layout.preloaded_dsos.base == 0
        || layout.scratch.base == 0
    {
        return Err(invalid_argument());
    }

    let main = match txn_id {
        Some(txn) => stage_pe_image_from_exec_mo(
            state,
            src_client_id,
            dst_client_id,
            image_bytes,
            layout.elf_code.base,
            exec_code_mo.ok_or_else(invalid_argument)?,
            txn,
        )?,
        None => stage_pe_image_provided(
            state,
            dst_client_id,
            image_bytes,
            layout.elf_code.base,
            None,
        )?,
    };

    let rtld_image = elf::parse(rtld_bytes)?;
    elf::stage_image_provided(
        state,
        dst_client_id,
        &rtld_image,
        layout.interpreter.base,
        code_mo::CodeSource::Library {
            name: b"ldtrona-pe.so",
            bytes: rtld_bytes,
        },
        txn_id,
    )?;

    let kernel32 = stage_pe_image_provided(
        state,
        dst_client_id,
        kernel32_bytes,
        layout.preloaded_dsos.base,
        txn_id,
    )?;

    Ok(PeLoadedProgram {
        entry_pc: layout
            .interpreter
            .base
            .checked_add(rtld_image.ehdr.e_entry)
            .ok_or_else(invalid_argument)?,
        main,
        rtld_base: layout.interpreter.base,
        kernel32,
        scratch_vaddr: layout.scratch.base,
        plan: layout,
    })
}

impl From<&PeLoadedProgram> for stack::PeStartupImages {
    fn from(program: &PeLoadedProgram) -> Self {
        Self {
            main_base: program.main.base,
            main_size: program.main.size,
            main_entry: program.main.entry,
            rtld_base: program.rtld_base,
            kernel32_base: program.kernel32.base,
            kernel32_size: program.kernel32.size,
            scratch_vaddr: program.scratch_vaddr,
        }
    }
}
