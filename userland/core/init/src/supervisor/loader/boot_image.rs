// SPDX-License-Identifier: GPL-2.0-only
//
//! Stage-0 (pre-mmsrv) image loader under W^X.
//!
//! Early boot services (namesrv / rsrcsrv / mmsrv) are spawned before mmsrv is
//! alive, so init maps their images into the child VSpace with raw kernel ops.
//! `retype` mints no EXECUTE, so init cannot map a raw FRAME executable; instead
//! it backs a code MemoryObject with the immortal initrd frames at the binary's
//! page-aligned offset (`mo_populate_borrowed`), confers `R-X` on it with the
//! boot ExecAuthority (`mo_mark_executable`), and maps the shared producer's
//! runs into the child:
//!
//! * text shares the `R-X` code MO, rodata a no-execute (`R--`) alias of it,
//! * writable data / `.bss` are a fresh private Anon MO whose bytes init copies
//!   from the initrd image through its own scratch page (then maps `R-W`).
//!
//! No page is ever mapped writable-and-executable; the kernel's cap-derived
//! ceiling is the W^X boundary.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_loader::common::elf::header::{phdr_slice, validate_ehdr};
use trona_loader::common::elf::run_plan::plan_elf;
use trona_loader::common::image::{
    Carve, ImageEnvelope, ImageId, ImageRunKind, PlacementSink, Run, RunPlan, RunSource, map_image,
};
use trona_runtime::core::slot_alloc::{alloc_slot, resolved_cap_ref};
use uapi::{
    KERNITE_CAP_SELF_CSPACE, KERNITE_CAP_SELF_VSPACE, KERNITE_OBJ_MEMORY_OBJECT,
    KERNITE_PAGE_BYTES, KERNITE_PAGE_FLAG_EXECUTABLE, KERNITE_PAGE_FLAG_USER,
    KERNITE_PAGE_FLAG_WRITABLE, KERNITE_RIGHT_GRANT, KERNITE_RIGHT_READ, KERNITE_RIGHT_TRANSFER,
};

use crate::internal_slots::{SCRATCH_FRAME_VA, SLOT_EXEC_AUTHORITY, SLOT_INITRD_UNTYPED};
use crate::supervisor::loader::dso::DsoClosure;

const PAGE: u64 = KERNITE_PAGE_BYTES as u64;
/// Largest run buffer for one boot image plan. The planner splits each
/// BSS-only tail beyond `p_filesz` into its own `ZeroFill` run, so the worst
/// case is roughly two runs per PT_LOAD (private file extent + trailing BSS),
/// plus text and rodata runs. 128 comfortably covers every plausible layout
/// and matches `MAX_IMAGE_RUNS` in `elf.rs` / `MAX_PE_RUNS` in `pe.rs`.
const MAX_BOOT_RUNS: usize = 128;

#[inline]
fn invalid_argument() -> i32 {
    uapi::KERNITE_ERR_INVALID_ARGUMENT as i32
}

#[inline]
fn page_align_up(v: u64) -> u64 {
    (v + PAGE - 1) & !(PAGE - 1)
}

/// `size_bits` for a MemoryObject covering `pages` pages: `log2` of the next
/// power-of-two page count (matching `mo_registry::mo_size_bits_for_length`).
fn mo_size_bits(pages: u64) -> Option<u64> {
    if pages == 0 {
        return None;
    }
    let bits = pages.checked_next_power_of_two()?.trailing_zeros() as u64;
    if bits > 31 { None } else { Some(bits) }
}

/// Pack a `(page_count, page_flags)` pair for `VSPACE_MAP_MO` — count in the high
/// 32 bits, flags in the low 32.
#[inline]
fn count_and_flags(pages: u64, flags: u64) -> u64 {
    (pages << 32) | (flags & 0xFFFF_FFFF)
}

fn free_slot(slot: u64) {
    let _ = invoke::cnode_delete(CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64), slot);
}

fn map_mo_exact(
    vspace: CapRef,
    mo_cap: u64,
    vaddr: u64,
    mo_offset: u64,
    pages: u64,
    flags: u64,
) -> Result<(), i32> {
    let (err, mapped) = invoke::vspace_map_mo_with_count(
        vspace,
        mo_cap,
        vaddr,
        mo_offset,
        count_and_flags(pages, flags),
    );
    if err != 0 {
        return Err(err);
    }
    if mapped == pages {
        return Ok(());
    }
    for i in 0..mapped {
        let _ = invoke::vspace_unmap(vspace, vaddr + i * PAGE);
    }
    Err(uapi::KERNITE_ERR_INVALID_OPERATION as i32)
}

/// Realizes one image's runs into a child VSpace with raw kernel ops.
struct BootImageSink<'a> {
    child_vspace: u64,
    untyped: u64,
    /// Initrd image bytes (the file content), for copying writable data.
    image_bytes: &'a [u8],
    load_base: u64,
    /// `R-X` code MO (the conferred borrowed-frames object), set in begin_image.
    code_mo: CapRef,
    /// `R--` (no-execute) alias of the code MO for rodata runs.
    code_mo_ro: u64,
}

impl<'a> PlacementSink for BootImageSink<'a> {
    type CodeMo = CapRef;
    type Error = i32;

    fn begin_image(
        &mut self,
        code_mo: CapRef,
        _envelope: ImageEnvelope,
        _carves: &[Carve],
    ) -> Result<ImageId, i32> {
        self.code_mo = code_mo;
        Ok(ImageId::NONE) // boot images are pinned; no teardown handle.
    }

    fn place_run(&mut self, _image: ImageId, run: &Run) -> Result<(), i32> {
        let pages = run.bytes / PAGE;
        match run.source {
            RunSource::CleanFromCodeMo { mo_offset_pages } => {
                // Text shares the R-X code MO; rodata shares its no-execute alias
                // so a later mprotect(+X) on read-only data is refused.
                let (mo_cap, flags) = if matches!(run.kind, ImageRunKind::Text) {
                    (
                        self.code_mo.addr(),
                        (KERNITE_PAGE_FLAG_USER | KERNITE_PAGE_FLAG_EXECUTABLE) as u64,
                    )
                } else {
                    (self.code_mo_ro, KERNITE_PAGE_FLAG_USER as u64)
                };
                map_mo_exact(
                    resolved_cap_ref(self.child_vspace),
                    mo_cap,
                    run.va,
                    mo_offset_pages,
                    pages,
                    flags,
                )
            }
            RunSource::PrivateFromCodeMo {
                mo_offset_pages: _,
                file_bytes,
            } => unsafe { self.place_private(run, pages, file_bytes) },
            RunSource::ZeroFill => unsafe { self.place_private(run, pages, 0) },
        }
    }
}

impl<'a> BootImageSink<'a> {
    /// Map a writable run: retype a fresh Anon MO, fill each page from the initrd
    /// image (zeroing the tail) through init's scratch page, then map it `R-W`
    /// into the child.
    ///
    /// # Safety
    /// `SCRATCH_FRAME_VA` is init's private one-page staging window.
    unsafe fn place_private(&mut self, run: &Run, pages: u64, file_bytes: u64) -> Result<(), i32> {
        let size_bits = mo_size_bits(pages).ok_or_else(invalid_argument)?;
        let mo = alloc_slot().ok_or_else(invalid_argument)?;
        let mo_slot = mo.addr();
        let r = invoke::untyped_retype(
            resolved_cap_ref(self.untyped),
            KERNITE_OBJ_MEMORY_OBJECT as u64,
            size_bits,
            mo_slot,
        );
        if r != 0 {
            return Err(r);
        }
        let r = invoke::mo_commit(resolved_cap_ref(mo_slot), 0, pages, self.untyped);
        if r != 0 {
            free_slot(mo_slot);
            return Err(r);
        }

        let self_vspace = CapRef::flat(KERNITE_CAP_SELF_VSPACE as u64);
        let rw = (KERNITE_PAGE_FLAG_USER | KERNITE_PAGE_FLAG_WRITABLE) as u64;
        // The run's file offset equals its VA offset from the load base (ELF
        // PIEs satisfy p_offset == p_vaddr).
        let run_file_off = run.va.wrapping_sub(self.load_base);
        for i in 0..pages {
            let r = map_mo_exact(self_vspace, mo_slot, SCRATCH_FRAME_VA, i, 1, rw);
            if let Err(r) = r {
                free_slot(mo_slot);
                return Err(r);
            }
            // SAFETY: the scratch page is mapped R-W above.
            let dst = SCRATCH_FRAME_VA as *mut u8;
            unsafe { core::ptr::write_bytes(dst, 0, PAGE as usize) };
            let page_file_off = run_file_off + i * PAGE;
            let avail = file_bytes.saturating_sub(i * PAGE).min(PAGE) as usize;
            let src_lo = page_file_off as usize;
            let src_hi = src_lo.saturating_add(avail).min(self.image_bytes.len());
            if src_hi > src_lo {
                // SAFETY: dst is a full mapped page; copy is bounded by `avail`.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.image_bytes.as_ptr().add(src_lo),
                        dst,
                        src_hi - src_lo,
                    );
                }
            }
            let r = invoke::vspace_unmap(self_vspace, SCRATCH_FRAME_VA);
            if r != 0 {
                free_slot(mo_slot);
                return Err(r);
            }
        }

        let r = map_mo_exact(
            resolved_cap_ref(self.child_vspace),
            mo_slot,
            run.va,
            0,
            pages,
            rw,
        );
        // The child VmArea now holds the MO ref; drop init's cap regardless.
        free_slot(mo_slot);
        if let Err(r) = r {
            return Err(r);
        }
        Ok(())
    }
}

/// Map one ELF image (from the initrd) into `child_vspace` at `load_base` under
/// the W^X borrowed-frames model. `untyped` is the spawning stage's seed for
/// retyping the code MO + private data MOs.
///
/// # Safety
/// `image_bytes` is a live borrow of the initrd mapping; `child_vspace`,
/// `untyped`, and the boot caps name live capabilities.
pub unsafe fn map_one_image(
    initrd_va: u64,
    child_vspace: u64,
    untyped: u64,
    image_bytes: &[u8],
    load_base: u64,
) -> Result<(), i32> {
    let ehdr = unsafe { validate_ehdr(image_bytes.as_ptr(), image_bytes.len()) }
        .map_err(|_| invalid_argument())?;
    let phdrs = unsafe { phdr_slice(image_bytes.as_ptr(), image_bytes.len(), ehdr) }
        .map_err(|_| invalid_argument())?;

    // The code MO borrows the initrd frames at the image's page-aligned offset.
    let offset = (image_bytes.as_ptr() as u64).wrapping_sub(initrd_va);
    if offset % PAGE != 0 {
        return Err(invalid_argument());
    }
    let span_pages = page_align_up(image_bytes.len() as u64) / PAGE;
    let size_bits = mo_size_bits(span_pages).ok_or_else(invalid_argument)?;

    let code = alloc_slot().ok_or_else(invalid_argument)?;
    let code_slot = code.addr();
    let r = invoke::untyped_retype(
        resolved_cap_ref(untyped),
        KERNITE_OBJ_MEMORY_OBJECT as u64,
        size_bits,
        code_slot,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::mo_populate_borrowed(
        resolved_cap_ref(code_slot),
        resolved_cap_ref(SLOT_INITRD_UNTYPED),
        offset,
        span_pages,
    );
    if r != 0 {
        free_slot(code_slot);
        return Err(r);
    }
    // Confer R-X: the executable code MO is a CDT child of the borrowed-frames
    // object.
    let exec = alloc_slot().ok_or_else(invalid_argument)?;
    let exec_slot = exec.addr();
    let r = invoke::mo_mark_executable_ref(
        resolved_cap_ref(SLOT_EXEC_AUTHORITY),
        resolved_cap_ref(code_slot),
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        exec.borrow(),
    );
    // The borrowed-frames R-W cap is no longer needed: the R-X child keeps the MO
    // alive with no writable view (W^X).
    free_slot(code_slot);
    if r != 0 {
        free_slot(exec_slot);
        return Err(r);
    }
    // A no-execute alias of the code MO for rodata runs.
    let ro = alloc_slot().ok_or_else(invalid_argument)?;
    let ro_slot = ro.addr();
    let r = invoke::cnode_copy_ref(
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        resolved_cap_ref(exec_slot),
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        resolved_cap_ref(ro_slot),
        (KERNITE_RIGHT_READ | KERNITE_RIGHT_GRANT | KERNITE_RIGHT_TRANSFER) as u64,
    );
    if r != 0 {
        free_slot(exec_slot);
        free_slot(ro_slot);
        return Err(r);
    }

    let mut runs = [Run::EMPTY; MAX_BOOT_RUNS];
    let (envelope, count) =
        plan_elf(phdrs, load_base, ehdr.e_entry, &mut runs).map_err(|_| invalid_argument())?;
    let plan = RunPlan {
        envelope,
        runs: &runs[..count],
        carves: &[],
    };
    let mut sink = BootImageSink {
        child_vspace,
        untyped,
        image_bytes,
        load_base,
        code_mo: resolved_cap_ref(exec_slot),
        code_mo_ro: ro_slot,
    };
    let result = map_image(&mut sink, resolved_cap_ref(exec_slot), &plan).map(|_| ());

    // The child VmAreas hold their own MO refs; drop init's caps.
    free_slot(exec_slot);
    free_slot(ro_slot);
    result
}

/// Map a whole DSO closure (main image + interpreter + every DT_NEEDED DSO) into
/// `child_vspace` under the W^X borrowed-frames model.
///
/// # Safety
/// Each closure mapping's `bytes` is a live borrow of the initrd; the caps name
/// live capabilities.
pub unsafe fn map_closure_borrowed(
    initrd_va: u64,
    child_vspace: u64,
    untyped: u64,
    closure: &DsoClosure<'_>,
) -> Result<(), i32> {
    unsafe {
        map_one_image(
            initrd_va,
            child_vspace,
            untyped,
            closure.main.bytes,
            closure.main.load_base,
        )?;
        if let Some(interp) = &closure.interp {
            map_one_image(
                initrd_va,
                child_vspace,
                untyped,
                interp.bytes,
                interp.load_base,
            )?;
        }
        for i in 0..closure.needed_len {
            if let Some(dso) = &closure.needed[i] {
                map_one_image(initrd_va, child_vspace, untyped, dso.bytes, dso.load_base)?;
            }
        }
    }
    Ok(())
}
