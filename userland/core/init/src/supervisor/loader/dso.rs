// SPDX-License-Identifier: GPL-2.0-only
//
//! DSO closure resolution for dynamically-linked spawn paths.
//!
//! When a child binary's program-header table contains a `PT_INTERP`
//! entry, the kernel does NOT load the interpreter on its own —
//! init's spawner has to load the main executable, the interpreter
//! (`/lib/ldtrona-elf.so`), and the transitive `DT_NEEDED` DSO closure
//! required by both. The interpreter does not perform file-system DSO
//! loading during early core-service bootstrap; it validates that init
//! already mapped the dependency graph.
//!
//! The resolver returns just bytes and names; per-DSO load bases are
//! assigned later by [`assign_bases`] from a `VmLayoutPlan`. This keeps
//! the loader-policy (window placement) in the layout module while the
//! file-system / DT_NEEDED walk stays here.
//!
//! The resolver walks `DT_NEEDED` entries from the main executable,
//! the interpreter, and every newly discovered DSO. It de-duplicates
//! names, then looks each one up by a small set of canonical paths
//! (`/lib/<name>` first, then the initrd root).

use trona_loader::common::elf::dynamic::{NeededIter, parse_dynamic, strtab_entry};
use trona_loader::common::elf::header::{find_dynamic_phdr, get_interp, has_interp, load_span};
use trona_loader::common::elf::types::{ET_DYN, Elf64Dyn, PT_LOAD};
use trona_runtime::spawn::layout::{ELF_CODE_BASE, VmLayoutPlan};

use crate::supervisor::SupervisorState;
use crate::supervisor::loader::cpio;
use crate::supervisor::loader::elf::{ElfImage, align_up, parse};

/// Maximum number of distinct DSOs a service can pull in via transitive
/// `DT_NEEDED` before init refuses the spawn. The userland's typical
/// DSO footprint sits well under this limit (libtrona + libc + arch helpers).
pub const MAX_DSO_CLOSURE: usize = 16;

/// Load bias for PT_INTERP-backed ET_DYN main executables. This matches
/// the shared spawn VA layout's ELF code window and keeps PIE text/data
/// clear of the fixed startup IPC buffer page.
pub const MAIN_ET_DYN_LOAD_BASE: u64 = ELF_CODE_BASE;

/// One entry of the resolved DSO closure. The entire chain (main
/// executable + interpreter + DT_NEEDED DSOs) shares this shape.
///
/// `load_base` and `entry_pc` are filled by [`assign_bases`]; before
/// that runs they are `0`.
pub struct DsoMapping<'a> {
    /// Original image name/path as discovered from the caller, PT_INTERP, or
    /// DT_NEEDED. This is what startup metadata reports.
    pub name: &'a [u8],
    /// Name passed to `ldsrv.resolve_library`: always a soname, never a path.
    /// `PT_INTERP` is path-like (`/lib/ldtrona-elf.so`).
    pub resolve_name: &'a [u8],
    pub bytes: &'a [u8],
    /// Page-aligned `PT_LOAD` span (high_va - low_va). Set by the resolver
    /// from the parsed headers.
    pub span: u64,
    /// Set by [`assign_bases`].
    pub load_base: u64,
    /// Set by [`assign_bases`].
    pub entry_pc: u64,
}

/// Resolved closure ready for image staging. Empty when the main executable has
/// no `PT_INTERP` (e.g. the static-linked init itself).
pub struct DsoClosure<'a> {
    pub main: DsoMapping<'a>,
    pub interp: Option<DsoMapping<'a>>,
    pub needed: [Option<DsoMapping<'a>>; MAX_DSO_CLOSURE],
    pub needed_len: usize,
}

/// Resolve the full DSO closure for `main`. Looks up `PT_INTERP` to find
/// the interpreter, then resolves the transitive `DT_NEEDED` graph. Returns
/// the closure with each entry's span computed from its `PT_LOAD` headers.
/// Per-image `load_base` / `entry_pc` are 0; call [`assign_bases`] once the
/// layout plan is in hand.
pub fn resolve<'a>(
    state: &SupervisorState,
    main: &'a ElfImage<'a>,
    main_name: &'a [u8],
    interp_loads_dsos: bool,
) -> Result<DsoClosure<'a>, i32> {
    let main_span = span_of(main);
    let mut closure = DsoClosure {
        main: DsoMapping {
            name: main_name,
            resolve_name: main_name,
            bytes: main.bytes,
            span: main_span,
            load_base: 0,
            entry_pc: 0,
        },
        interp: None,
        needed: [const { None }; MAX_DSO_CLOSURE],
        needed_len: 0,
    };

    if !has_interp(main.phdrs) {
        return Ok(closure);
    }

    let interp_path = unsafe { get_interp(main.bytes.as_ptr(), main.phdrs) }
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    let interp_bytes = lookup_dso(state, interp_path)?;
    let interp = parse(interp_bytes)?;
    let interp_span = span_of(&interp);
    if interp_span == 0 {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }

    closure.interp = Some(DsoMapping {
        name: interp_path,
        resolve_name: soname_from_path(interp_path),
        bytes: interp_bytes,
        span: interp_span,
        load_base: 0,
        entry_pc: 0,
    });

    if !interp_loads_dsos {
        collect_needed_from_image(state, main, &mut closure)?;
        if let Some(interp) = &closure.interp {
            let interp_image = parse(interp.bytes)?;
            collect_needed_from_image(state, &interp_image, &mut closure)?;
        }
    }

    Ok(closure)
}

/// Resolve `name` to a byte slice in the initrd. Tries the canonical
/// `/lib/<name>` path first, falls back to the initrd-root file
/// matching `name`.
fn lookup_dso<'a>(state: &SupervisorState, name: &[u8]) -> Result<&'a [u8], i32> {
    let mut path = [0u8; 128];
    let prefix = b"/lib/";
    if prefix.len() + name.len() <= path.len() {
        path[..prefix.len()].copy_from_slice(prefix);
        path[prefix.len()..prefix.len() + name.len()].copy_from_slice(name);
        if let Some(b) = cpio::find_file(state, &path[..prefix.len() + name.len()]) {
            return Ok(b);
        }
    }
    cpio::find_file(state, name).ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)
}

fn collect_needed_from_image<'a>(
    state: &SupervisorState,
    image: &ElfImage<'a>,
    closure: &mut DsoClosure<'a>,
) -> Result<(), i32> {
    let Some(dyn_phdr) = find_dynamic_phdr(image.phdrs) else {
        return Ok(());
    };
    let dyn_ptr =
        unsafe { image.bytes.as_ptr().add(dyn_phdr.p_offset as usize) as *const Elf64Dyn };
    let dyn_info = unsafe { parse_dynamic(dyn_ptr) };
    if dyn_info.strtab == 0 || dyn_info.strsz == 0 {
        return Ok(());
    }

    let strtab_off = strtab_file_offset(image, dyn_info.strtab) as usize;
    let strsz = dyn_info.strsz as usize;
    if strtab_off >= image.bytes.len() || strsz > image.bytes.len() - strtab_off {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    let strtab_ptr = unsafe { image.bytes.as_ptr().add(strtab_off) };

    for needed_off in unsafe { NeededIter::new(dyn_ptr) } {
        let name = unsafe { strtab_entry(strtab_ptr, strsz, needed_off) }
            .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        if closure_contains_name(closure, name) {
            continue;
        }

        let bytes = lookup_dso(state, name)?;
        let dso_image = parse(bytes)?;
        let span = span_of(&dso_image);
        if span == 0 {
            return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
        }
        if closure.needed_len >= MAX_DSO_CLOSURE {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
        }
        closure.needed[closure.needed_len] = Some(DsoMapping {
            name,
            resolve_name: name,
            bytes,
            span,
            load_base: 0,
            entry_pc: 0,
        });
        closure.needed_len += 1;

        collect_needed_from_image(state, &dso_image, closure)?;
    }

    Ok(())
}

fn closure_contains_name(closure: &DsoClosure<'_>, name: &[u8]) -> bool {
    if closure.main.name == name || closure.main.resolve_name == name {
        return true;
    }
    if let Some(interp) = closure.interp.as_ref() {
        if interp.name == name || interp.resolve_name == name {
            return true;
        }
    }
    closure
        .needed
        .iter()
        .take(closure.needed_len)
        .flatten()
        .any(|mapping| mapping.name == name || mapping.resolve_name == name)
}

fn soname_from_path(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b'/') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

const KERNITE_PAGE_BYTES_AS_U64: u64 = uapi::KERNITE_PAGE_BYTES as u64;

/// Return the load span (high VA - low VA) of an ELF. Used by
/// `assign_bases` to lay out per-DSO load bases so they don't overlap.
fn span_of(image: &ElfImage<'_>) -> u64 {
    match load_span(image.phdrs) {
        Some((lo, hi)) => hi - lo,
        None => 0,
    }
}

/// Resolve a `DT_STRTAB` virtual address back to the file offset
/// inside `image`. For ET_DYN the strtab `d_val` is the in-memory VA
/// after relocation; we walk `PT_LOAD`s to find which segment owns
/// the VA and convert.
fn strtab_file_offset(image: &ElfImage<'_>, strtab_va: u64) -> u64 {
    for ph in image.phdrs {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if strtab_va >= ph.p_vaddr && strtab_va < ph.p_vaddr + ph.p_memsz {
            return ph.p_offset + (strtab_va - ph.p_vaddr);
        }
    }
    strtab_va
}

/// Stamp per-DSO `load_base` / `entry_pc` from the image-side windows in
/// `plan`. The plan fields (`elf_code`, `interpreter`, `preloaded_dsos`,
/// `runtime_dso_window`) are owned by the planner; this helper only reads
/// them and walks the per-DSO strides they already encode.
///
/// Window policy (DSO_LOAD_BASE_START / DSO_LOAD_BASE_STRIDE / per-window
/// ordering) lives entirely in the layout module. The resolver owns
/// dependency names and bytes; this function only maps closure entries
/// onto the planner's already-allocated windows.
///
/// The caller must have run `compute_vm_layout` with the same
/// `interp_span` and `preloaded_dso_spans` this closure resolves to —
/// per-DSO loads in `interpreter` / `preloaded_dsos` will not fit
/// otherwise.
pub fn assign_bases(plan: &VmLayoutPlan, closure: &mut DsoClosure<'_>) -> Result<(), i32> {
    closure.main.load_base = plan.elf_code.base;
    closure.main.entry_pc = plan.elf_code.base + ehdr_e_entry(closure.main.bytes);

    if let Some(interp) = closure.interp.as_mut() {
        // The planner places the interpreter at DSO_LOAD_BASE_START with the
        // size derived from `interp_span` — so a single DSO lands at the
        // window's base. Multi-image closures don't exist here: there is
        // exactly one interpreter.
        if plan.interpreter.size < page_align_up(interp.span) {
            return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
        }
        interp.load_base = plan.interpreter.base;
        interp.entry_pc = interp.load_base + ehdr_e_entry(interp.bytes);
    }

    if closure.needed_len > 0 && plan.preloaded_dsos.size > 0 {
        // The planner sizes `preloaded_dsos` as the sum of (span + stride)
        // for every needed DSO. Walk the same stride pattern to stamp each
        // `load_base` from the window's base.
        let stride = trona_runtime::spawn::layout::DSO_LOAD_BASE_STRIDE;
        let mut cursor = plan.preloaded_dsos.base;
        for i in 0..closure.needed_len {
            let Some(dso) = closure.needed[i].as_mut() else {
                return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
            };
            dso.load_base = cursor;
            dso.entry_pc = dso.load_base + ehdr_e_entry(dso.bytes);
            cursor = cursor
                .checked_add(page_align_up(dso.span))
                .and_then(|v| v.checked_add(stride))
                .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        }
        // The plan reserves one stride past the last DSO as a guard page
        // (mirrors the planner's accounting), so the next DSO can't overlap
        // a partially-rounded tail.
        let last_end = cursor.saturating_sub(stride);
        if last_end > plan.preloaded_dsos.end() {
            return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
        }
    }
    Ok(())
}

fn ehdr_e_entry(bytes: &[u8]) -> u64 {
    match parse(bytes) {
        Ok(image) => image.ehdr.e_entry,
        Err(_) => 0,
    }
}

fn page_align_up(v: u64) -> u64 {
    align_up(v, KERNITE_PAGE_BYTES_AS_U64)
}

/// Count the 4 KiB frames the direct loader will retype for this
/// closure without materialising pages, so the boot allocator can size
/// bootstrap untypeds before any service is spawned.
pub fn direct_map_frame_pages(closure: &DsoClosure<'_>) -> Result<u64, i32> {
    let main_image = parse(closure.main.bytes)?;
    let mut pages = mapped_pages_for_image(&main_image)?;

    if let Some(interp) = &closure.interp {
        let interp_image = parse(interp.bytes)?;
        pages = pages
            .checked_add(mapped_pages_for_image(&interp_image)?)
            .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    }

    for i in 0..closure.needed_len {
        if let Some(dso) = &closure.needed[i] {
            let dso_image = parse(dso.bytes)?;
            pages = pages
                .checked_add(mapped_pages_for_image(&dso_image)?)
                .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        }
    }

    Ok(pages)
}

fn mapped_pages_for_image(image: &ElfImage<'_>) -> Result<u64, i32> {
    let Some((span_lo, span_hi)) = load_span(image.phdrs) else {
        return Ok(0);
    };
    let mut page_va = span_lo;
    let mut pages = 0u64;
    while page_va < span_hi {
        let page_end = page_va
            .checked_add(KERNITE_PAGE_BYTES_AS_U64)
            .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        let mut has_mapping = false;

        for ph in image.phdrs {
            if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
                continue;
            }
            if ph.p_filesz > ph.p_memsz {
                return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
            }
            let seg_end = ph
                .p_vaddr
                .checked_add(ph.p_memsz)
                .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
            if seg_end > page_va && ph.p_vaddr < page_end {
                has_mapping = true;
                break;
            }
        }

        if has_mapping {
            pages = pages
                .checked_add(1)
                .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        }
        page_va = page_end;
    }
    Ok(pages)
}

/// Pick the entry PC the kernel jumps to. With an interpreter, that
/// is the interpreter's `_start` (it parses argc/argv/auxv, runs its
/// own self-relocation, then hands control to the main executable).
/// Without an interpreter, the kernel jumps directly to the main
/// executable's `e_entry`. Caller must have run [`assign_bases`].
pub fn closure_entry(closure: &DsoClosure<'_>) -> u64 {
    closure
        .interp
        .as_ref()
        .map(|i| i.entry_pc)
        .unwrap_or(closure.main.entry_pc)
}
