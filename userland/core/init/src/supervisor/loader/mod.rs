// SPDX-License-Identifier: GPL-2.0-only
//
//! Image loader pipeline — glues ELF/PE parsing, DSO closure resolution,
//! image staging, stack composition, and cap-table delivery. Early core
//! services use [`load_image_borrowed`]; regular service spawn and exec use
//! [`load_program_via_mmsrv`].

pub mod boot_image;
pub mod cap_table;
pub mod code_mo;
pub mod cpio;
pub mod dso;
pub mod elf;
pub mod pe;
pub mod stack;

use crate::supervisor::SupervisorState;
use crate::supervisor::manifest::{ServiceDef, UnitRef};
use trona_kernel::core_types::{CapRef, SaltyOSFramebufferInfoV1};
use trona_runtime::spawn::layout::{VmLayoutPlan, compute_vm_layout};
use trona_runtime::spawn::stack_plan::StackLayoutSpec;

/// The entry-state hand-off the spawn pipeline writes into the new
/// TCB's registers. `entry_pc` goes to RIP; `child_sp` to RSP. `plan`
/// is the post-assignment `VmLayoutPlan` whose `runtime_dso_window` is
/// stamped into the child startup block.
pub struct LoadedImage {
    pub entry_pc: u64,
    pub child_sp: u64,
    pub plan: VmLayoutPlan,
}

/// Extract the preloaded DSO spans from a closure for `compute_vm_layout`.
fn closure_preloaded_spans(closure: &dso::DsoClosure<'_>) -> [u64; dso::MAX_DSO_CLOSURE] {
    let mut spans = [0u64; dso::MAX_DSO_CLOSURE];
    for i in 0..closure.needed_len {
        if let Some(d) = closure.needed[i].as_ref() {
            spans[i] = d.span;
        }
    }
    spans
}

/// Run `compute_vm_layout` + `dso::assign_bases` for a closure. Returns the
/// plan and the (now-stamped) closure. The closure mutates so its
/// `load_base` / `entry_pc` fields are valid afterwards. The plan is the
/// single source of truth for image windows — `assign_bases` only reads
/// `plan.elf_code` / `plan.interpreter` / `plan.preloaded_dsos` to stamp
/// per-DSO bases.
fn plan_for_closure(
    stack_spec: StackLayoutSpec,
    closure: &mut dso::DsoClosure<'_>,
    map_initrd: bool,
    initrd_window_size: usize,
) -> Result<VmLayoutPlan, i32> {
    let spans = closure_preloaded_spans(closure);
    let needed_count = closure.needed_len;
    let interp_span = closure.interp.as_ref().map(|i| i.span).unwrap_or(0);
    let plan = compute_vm_layout(
        closure.main.span,
        interp_span,
        &spans[..needed_count],
        map_initrd,
        initrd_window_size,
        stack_spec,
    )
    .map_err(|e| e.wire_code() as i32)?;
    dso::assign_bases(&plan, closure)?;
    Ok(plan)
}

pub fn startup_framebuffer_for(
    state: &SupervisorState,
    def: &ServiceDef,
) -> SaltyOSFramebufferInfoV1 {
    for i in 0..def.unit_requires_len as usize {
        if let UnitRef::Cap(name) = def.unit_requires[i] {
            if name.as_bytes() == b"fb_untyped.cap" {
                return state.caps.framebuffer;
            }
        }
    }
    SaltyOSFramebufferInfoV1::zeroed()
}

/// Load an executable through the mmsrv-backed path after detecting
/// the image format from the file bytes. ELF uses the normal
/// ELF/DSO closure path; PE stages the PE main image with
/// `ldtrona-pe.so` and the preloaded `kernel32.dll` image.
#[allow(clippy::too_many_arguments)]
pub fn load_program_via_mmsrv(
    state: &mut SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    image_name: &[u8],
    image_bytes: &[u8],
    exec_code_mo: Option<CapRef>,
    argv: &[&[u8]],
    envp: &[&[u8]],
    child_stack_top: u64,
    stack_spec: StackLayoutSpec,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    alloc_slot_base: u64,
    startup_framebuffer: SaltyOSFramebufferInfoV1,
    txn_id: Option<u64>,
    interp_loads_dsos: bool,
) -> Result<LoadedImage, i32> {
    match pe::detect_format(image_bytes)? {
        pe::ImageFormat::Elf => load_image_via_mmsrv(
            state,
            src_client_id,
            dst_client_id,
            image_name,
            image_bytes,
            argv,
            envp,
            child_stack_top,
            stack_spec,
            cap_table_va,
            ipc_buffer_va,
            alloc_slot_base,
            startup_framebuffer,
            txn_id,
            interp_loads_dsos,
        ),
        pe::ImageFormat::Pe => {
            let loaded = pe::load_pe_program_via_mmsrv(
                state,
                src_client_id,
                dst_client_id,
                image_bytes,
                exec_code_mo,
                child_stack_top,
                stack_spec,
                txn_id,
            )?;
            let images = stack::PeStartupImages::from(&loaded);
            let composed = stack::compose_pe_via_mmsrv(
                state,
                src_client_id,
                dst_client_id,
                child_stack_top,
                stack_spec,
                argv,
                envp,
                &images,
                cap_table_va,
                ipc_buffer_va,
                alloc_slot_base,
                startup_framebuffer,
                loaded.plan.runtime_dso_window.base,
                loaded.plan.runtime_dso_window.size,
                txn_id,
            )?;
            Ok(LoadedImage {
                entry_pc: loaded.entry_pc,
                child_sp: composed.child_sp,
                plan: loaded.plan,
            })
        }
    }
}

/// Load `image_bytes` into `child_vspace` via the direct-untyped backend under
/// W^X: the DSO closure (main + interpreter + DT_NEEDED) is mapped run-by-run
/// from borrowed-frames code MemoryObjects conferred `R-X` with the boot
/// ExecAuthority (see [`boot_image`]), instead of retyping raw executable
/// frames. Used by the Stage C/D/E core spawns (namesrv / rsrcsrv / mmsrv)
/// before mmsrv is alive. `untyped` is the spawning stage's seed.
#[allow(clippy::too_many_arguments)]
pub fn load_image_borrowed(
    state: &SupervisorState,
    child_vspace: u64,
    untyped: u64,
    image_name: &[u8],
    image_bytes: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    stack_frame: u64,
    child_stack_top: u64,
    stack_spec: StackLayoutSpec,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    alloc_slot_base: u64,
) -> Result<LoadedImage, i32> {
    let main_image = elf::parse(image_bytes)?;
    let mut closure = dso::resolve(state, &main_image, image_name, false)?;
    let plan = plan_for_closure(stack_spec, &mut closure, false, 0)?;
    unsafe {
        boot_image::map_closure_borrowed(state.caps.initrd_va, child_vspace, untyped, &closure)?;
    }
    let composed = stack::compose(
        child_vspace,
        stack_frame,
        child_stack_top,
        argv,
        envp,
        &closure,
        cap_table_va,
        ipc_buffer_va,
        alloc_slot_base,
        plan.runtime_dso_window.base,
        plan.runtime_dso_window.size,
    )?;
    let entry_pc = dso::closure_entry(&closure);

    Ok(LoadedImage {
        entry_pc,
        child_sp: composed.child_sp,
        plan,
    })
}

/// Load an ELF `image_bytes` into `child_vspace` via the mmsrv-backed
/// backend. This is the ELF backend used by
/// [`load_program_via_mmsrv`] after byte-signature dispatch.
///
/// Stages every PT_LOAD run of the main image, the interpreter
/// (`/lib/ldtrona-elf.so` for dynamically-linked userland), and every
/// DT_NEEDED DSO through the provided-code-MO path, then composes the
/// SysV stack via `stack::compose_via_mmsrv` so every spawned region —
/// including the lower stack pages that demand-fault as the child pushes
/// — lives in mmsrv's `RegionTable`. Cap-table delivery is a separate
/// concern handled by [`cap_table::populate_via_mmsrv`]; callers pass
/// the same planned high-water slot as `alloc_slot_base` and can compare
/// it with the population result.
///
/// `txn_id == Some(_)` routes every staging call through the exec
/// transaction so the new image lands in mmsrv's pending VSpace
/// until `MM_COMMIT_EXEC_REPLACE` swaps it in.
#[allow(clippy::too_many_arguments)]
pub fn load_image_via_mmsrv(
    state: &mut SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    image_name: &[u8],
    image_bytes: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    child_stack_top: u64,
    stack_spec: StackLayoutSpec,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    alloc_slot_base: u64,
    startup_framebuffer: SaltyOSFramebufferInfoV1,
    txn_id: Option<u64>,
    interp_loads_dsos: bool,
) -> Result<LoadedImage, i32> {
    let main_image = elf::parse(image_bytes)?;
    let mut closure = dso::resolve(state, &main_image, image_name, interp_loads_dsos)?;
    let plan = plan_for_closure(stack_spec, &mut closure, false, 0)?;

    // The whole closure's executable text comes from code MemoryObjects, never
    // an anonymous copy: the main image either from the exec MO mmsrv holds for
    // an execve transaction or conferred via ldsrv for a service spawn, and the
    // interpreter / DSOs from ldsrv-resolved code MOs. The destination VSpace is
    // reached through `dst_client_id` (mmsrv resolves the cap from its client
    // table), so `child_vspace` is intentionally not used.
    match txn_id {
        // Exec: the main image stages directly from the exec MemoryObject mmsrv
        // holds for the transaction (zero-copy, by geometry from the headers);
        // the interpreter and DSOs from ldsrv-resolved code MOs, into the same
        // pending exec VSpace.
        Some(txn) => {
            elf::stage_main_from_exec_mo(
                state,
                src_client_id,
                dst_client_id,
                &main_image,
                closure.main.load_base,
                txn,
            )?;
            if let Some(interp) = &closure.interp {
                let interp_image = elf::parse(interp.bytes)?;
                elf::stage_image_provided(
                    state,
                    dst_client_id,
                    &interp_image,
                    interp.load_base,
                    code_mo::CodeSource::Library {
                        name: interp.resolve_name,
                        bytes: interp.bytes,
                    },
                    Some(txn),
                )?;
            }
            for i in 0..closure.needed_len {
                if let Some(dso) = &closure.needed[i] {
                    let dso_image = elf::parse(dso.bytes)?;
                    elf::stage_image_provided(
                        state,
                        dst_client_id,
                        &dso_image,
                        dso.load_base,
                        code_mo::CodeSource::Library {
                            name: dso.resolve_name,
                            bytes: dso.bytes,
                        },
                        Some(txn),
                    )?;
                }
            }
        }
        // Service spawn: the whole closure resolves through ldsrv into the live
        // VSpace — the main image conferred from its initrd bytes
        // (`resolve_main`), the interpreter and DSOs from ldsrv's cache by soname.
        None => {
            elf::stage_image_provided(
                state,
                dst_client_id,
                &main_image,
                closure.main.load_base,
                code_mo::CodeSource::Main {
                    bytes: closure.main.bytes,
                },
                None,
            )?;
            if let Some(interp) = &closure.interp {
                let interp_image = elf::parse(interp.bytes)?;
                elf::stage_image_provided(
                    state,
                    dst_client_id,
                    &interp_image,
                    interp.load_base,
                    code_mo::CodeSource::Library {
                        name: interp.resolve_name,
                        bytes: interp.bytes,
                    },
                    None,
                )?;
            }
            for i in 0..closure.needed_len {
                if let Some(dso) = &closure.needed[i] {
                    let dso_image = elf::parse(dso.bytes)?;
                    elf::stage_image_provided(
                        state,
                        dst_client_id,
                        &dso_image,
                        dso.load_base,
                        code_mo::CodeSource::Library {
                            name: dso.resolve_name,
                            bytes: dso.bytes,
                        },
                        None,
                    )?;
                }
            }
        }
    }

    let composed = stack::compose_via_mmsrv(
        state,
        src_client_id,
        dst_client_id,
        child_stack_top,
        stack_spec,
        argv,
        envp,
        &closure,
        cap_table_va,
        ipc_buffer_va,
        alloc_slot_base,
        startup_framebuffer,
        plan.runtime_dso_window.base,
        plan.runtime_dso_window.size,
        txn_id,
    )?;
    let entry_pc = dso::closure_entry(&closure);

    Ok(LoadedImage {
        entry_pc,
        child_sp: composed.child_sp,
        plan,
    })
}
