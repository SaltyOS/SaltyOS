// SPDX-License-Identifier: GPL-2.0-only
//
//! ELF image parsing and mmsrv-backed staging into a child VSpace.

use trona_loader::common::elf::header::{phdr_slice, validate_ehdr};
use trona_loader::common::elf::run_plan::plan_elf;
use trona_loader::common::elf::types::{Elf64Ehdr, Elf64Phdr};
use trona_loader::common::image::{
    Carve, ImageEnvelope, ImageId, PlacementSink, Run, RunPlan, RunSource, map_image,
};

use super::code_mo::{CodeSource, get_code_mo};
use crate::supervisor::SupervisorState;
use crate::supervisor::mm_ipc::{
    image_kind_from_prot, mm_stage_image_region_exec_flags, mm_stage_image_region_provided_flags,
};
use trona_protocol::mm::{
    STAGE_FLAG_EXEC_MATERIALIZE, STAGE_FLAG_EXEC_MO_SRC, STAGE_FLAG_EXEC_TXN,
    STAGE_FLAG_TXN_ID_SHIFT,
};

#[inline]
pub(crate) fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

#[inline]
fn invalid_argument() -> i32 {
    uapi::KERNITE_ERR_INVALID_ARGUMENT as i32
}

/// Parsed ELF — the slice of bytes plus the validated header and the
/// program-header table.
pub struct ElfImage<'a> {
    pub bytes: &'a [u8],
    pub ehdr: &'a Elf64Ehdr,
    pub phdrs: &'a [Elf64Phdr],
}

/// Parse `bytes` as an ELF64 file. Returns the validated header and
/// program-header slice. Errors if the magic / class / encoding are
/// wrong, or if the program-header table extends past the buffer.
pub fn parse(bytes: &[u8]) -> Result<ElfImage<'_>, i32> {
    if bytes.len() < 4 || bytes[..4] != *b"\x7fELF" {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    let ehdr = unsafe { validate_ehdr(bytes.as_ptr(), bytes.len()) }
        .map_err(|_| uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    let phdrs = unsafe { phdr_slice(bytes.as_ptr(), bytes.len(), ehdr) }
        .map_err(|_| uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    Ok(ElfImage { bytes, ehdr, phdrs })
}

/// Drives mmsrv's per-region exec staging from a run plan: the init-side
/// adapter that turns each [`Run`] into an `MM_STAGE_IMAGE_REGION` call against a
/// client's pending exec VSpace. mmsrv holds the exec MemoryObject for the
/// transaction (named via `STAGE_FLAG_EXEC_MO_SRC`), so the sink's `CodeMo` is
/// the unit type and the transaction id is the teardown handle.
struct MmsrvSink<'a> {
    state: &'a SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    txn_id: u64,
    load_base: u64,
}

impl PlacementSink for MmsrvSink<'_> {
    type CodeMo = ();
    type Error = i32;

    fn begin_image(
        &mut self,
        _code_mo: (),
        _envelope: ImageEnvelope,
        _carves: &[Carve],
    ) -> Result<ImageId, i32> {
        // execve replaces the whole address space, so the main image needs no
        // per-image teardown handle; the returned id is unused by the caller.
        // (A dynamic linker that must `dlclose` a DSO reserves its own image via
        // MM_RESERVE_IMAGE and tears it down with MM_UNMAP_IMAGE.)
        Ok(ImageId::NONE)
    }

    fn place_run(&mut self, _image: ImageId, run: &Run) -> Result<(), i32> {
        let mem_size = run.bytes;
        // p_offset == p_vaddr (the producer enforces it), so the source offset in
        // the exec MO is the run's VA offset from the load base.
        let file_off = run.va.wrapping_sub(self.load_base);
        let (file_size, extra_flags) = match run.source {
            // Clean run: map the exec MO sub-range shared (zero-copy).
            RunSource::CleanFromCodeMo { .. } => (mem_size, STAGE_FLAG_EXEC_MO_SRC),
            // Private run: mmsrv clones the contiguous file extent and zero-fills
            // the tail beyond `file_bytes`.
            RunSource::PrivateFromCodeMo { file_bytes, .. } => (
                file_bytes,
                STAGE_FLAG_EXEC_MO_SRC | STAGE_FLAG_EXEC_MATERIALIZE,
            ),
            // Pure zero-fill: a private region with no file bytes.
            RunSource::ZeroFill => (0, STAGE_FLAG_EXEC_MO_SRC | STAGE_FLAG_EXEC_MATERIALIZE),
        };
        let prot = run.prot.0 as u64;
        mm_stage_image_region_exec_flags(
            self.state,
            self.src_client_id,
            // Source region unused: the EXEC_MO_SRC flag sources from the exec MO.
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

/// Largest number of runs one image plan can produce. A well-formed image has
/// a handful of `PT_LOAD` segments; the planner splits each BSS-only tail
/// beyond `p_filesz` into its own `ZeroFill` run, so the worst case is roughly
/// two runs per PT_LOAD (private file extent + trailing BSS), plus text and
/// rodata runs. 128 comfortably covers every plausible layout and matches
/// `MAX_PE_RUNS` in `pe.rs`.
const MAX_IMAGE_RUNS: usize = 128;

/// Stage the main executable from the exec MemoryObject mmsrv holds for the
/// transaction. The image is reduced to a run plan (shared zero-copy text /
/// rodata, private copy-on-write data, zero-fill BSS) by the shared producer,
/// which a [`MmsrvSink`] realizes through per-run `MM_STAGE_IMAGE_REGION` calls.
/// The interpreter and any DSOs are staged separately.
pub fn stage_main_from_exec_mo(
    state: &SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    image: &ElfImage<'_>,
    load_base: u64,
    txn_id: u64,
) -> Result<(), i32> {
    let mut runs = [Run::EMPTY; MAX_IMAGE_RUNS];
    let (envelope, count) = plan_elf(image.phdrs, load_base, image.ehdr.e_entry, &mut runs)
        .map_err(|_| invalid_argument())?;
    let plan = RunPlan {
        envelope,
        runs: &runs[..count],
        carves: &[],
    };
    let mut sink = MmsrvSink {
        state,
        src_client_id,
        dst_client_id,
        txn_id,
        load_base,
    };
    map_image(&mut sink, (), &plan).map(|_| ())
}

/// A [`PlacementSink`] that stages each run from a caller-provided code MO
/// (`mm_stage_image_region_provided_flags`) into a service-spawn's live VSpace,
/// or an execve interpreter's pending exec VSpace. Mirrors [`MmsrvSink`] but
/// sources from a `code_mo` transferred per run as `caps[0]` (mmsrv mints the
/// attenuated per-run alias), instead of the transaction's held exec MO.
/// `txn_flags` is `STAGE_FLAG_EXEC_TXN | txn_id << SHIFT` for an interpreter
/// staged inside a replace txn, else `0` for a service spawn's live VSpace.
struct MmsrvProvidedSink<'a> {
    state: &'a SupervisorState,
    dst_client_id: u32,
    code_mo: trona_kernel::core_types::CapRef,
    load_base: u64,
    txn_flags: u64,
}

impl PlacementSink for MmsrvProvidedSink<'_> {
    type CodeMo = ();
    type Error = i32;

    fn begin_image(
        &mut self,
        _code_mo: (),
        _envelope: ImageEnvelope,
        _carves: &[Carve],
    ) -> Result<ImageId, i32> {
        // The closure images need no per-image teardown handle here: a service
        // spawn maps for the process's life, and an execve interpreter is torn
        // down with the transaction. A dlclose-able DSO reserves its own image.
        Ok(ImageId::NONE)
    }

    fn place_run(&mut self, _image: ImageId, run: &Run) -> Result<(), i32> {
        let mem_size = run.bytes;
        // p_offset == p_vaddr (the producer enforces it), so the run's source
        // offset in the code MO is its VA offset from the load base.
        let file_off = run.va.wrapping_sub(self.load_base);
        let (file_size, src_flags) = match run.source {
            // Clean run: share the code MO sub-range zero-copy.
            RunSource::CleanFromCodeMo { .. } => (mem_size, 0),
            // Private run: mmsrv copies the file extent and zero-fills the tail.
            RunSource::PrivateFromCodeMo { file_bytes, .. } => {
                (file_bytes, STAGE_FLAG_EXEC_MATERIALIZE)
            }
            // Pure zero-fill (.bss): a private region with no file bytes.
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

/// Stage one image (a service-spawn main / interpreter / DSO, or an execve
/// interpreter / DSO) through mmsrv from a code MO acquired via [`get_code_mo`].
/// The image is reduced to a run plan and each run staged with
/// `STAGE_FLAG_PROVIDED_MO`; `txn_id` is `Some` when the image lands in a pending
/// exec VSpace (an execve interpreter) or `None` for a service spawn's live one.
pub fn stage_image_provided(
    state: &mut SupervisorState,
    dst_client_id: u32,
    image: &ElfImage<'_>,
    load_base: u64,
    source: CodeSource<'_>,
    txn_id: Option<u64>,
) -> Result<(), i32> {
    let code_mo = get_code_mo(state, source)?;

    let mut runs = [Run::EMPTY; MAX_IMAGE_RUNS];
    let (envelope, count) = plan_elf(image.phdrs, load_base, image.ehdr.e_entry, &mut runs)
        .map_err(|_| invalid_argument())?;
    let plan = RunPlan {
        envelope,
        runs: &runs[..count],
        carves: &[],
    };

    let txn_flags = match txn_id {
        Some(txn) => (txn << STAGE_FLAG_TXN_ID_SHIFT) | STAGE_FLAG_EXEC_TXN,
        None => 0,
    };
    let mut sink = MmsrvProvidedSink {
        state: &*state,
        dst_client_id,
        code_mo: trona_runtime::core::slot_alloc::resolved_cap_ref(code_mo.as_raw()),
        load_base,
        txn_flags,
    };
    let result = map_image(&mut sink, (), &plan).map(|_| ());
    // The code MO was retained only to feed staging; mmsrv holds its own
    // attenuated per-region dups, so drop it once every run is placed (the last
    // per-run transfer copy has already been consumed) or on failure.
    drop(code_mo);
    result
}
