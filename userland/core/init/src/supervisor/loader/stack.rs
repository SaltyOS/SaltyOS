// SPDX-License-Identifier: GPL-2.0-only
//
//! SysV-ABI initial stack composer + auxv writer + startup block.
//!
//! When the child enters its `_start`, the System V x86_64 ABI says
//! the stack contains, in order from low to high address:
//!
//! ```text
//! argc            (1 word)
//! argv[0..argc]   (argc words)
//! NULL            (1 word)
//! envp[0..n]      (n words)
//! NULL            (1 word)
//! auxv[0..m]      (m × 2 words)
//! AT_NULL/0       (2 words)
//! string blob     (variable; argv/envp pointers point into here)
//! ```
//!
//! The kernel hands the child a stack with `RSP` pointing at `argc`.
//! Substrate's `crt_start.S` reads each section through `RSP` and
//! eventually calls `trona_runtime_set_auxv` with the auxv pointer.
//!
//! Init has no way to write directly into the child's stack VA, so
//! it stages the bytes into a frame mapped at `SCRATCH_FRAME_VA` in
//! init's own VSpace, then maps the same frame into the child at the
//! stack-top - PAGE_BYTES address. The SaltyOS startup block and
//! CSpace layout descriptor live at fixed offsets within the same page,
//! so the child's `_start` can compute the block VA from the auxv
//! `AT_SALTYOS_STARTUP` entry (which init stamps in the auxv vector).

use trona_kernel::core_types::{
    SaltyOSCspaceLayoutV1, SaltyOSFramebufferInfoV1, SaltyOSStartupLayoutV1,
};
use trona_kernel::invoke;
use trona_loader::common::elf::types::{
    AT_BASE, AT_ENTRY, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_SALTYOS_STARTUP,
    Elf64Auxv,
};
use trona_runtime::spawn::layout::CHILD_RTLD_FRAME_SLOT_START;
use trona_runtime::spawn::stack_plan::{StackLayoutSpec, plan_stack_materialization};
use uapi::{
    KERNITE_CAP_SELF_VSPACE, KERNITE_PAGE_BYTES, KERNITE_PAGE_FLAG_USER, KERNITE_PAGE_FLAG_WRITABLE,
};

use crate::internal_slots::SCRATCH_FRAME_VA;
use crate::supervisor::SupervisorState;
use crate::supervisor::loader::dso::DsoClosure;
use crate::supervisor::mm_ipc::{
    MMAP_KIND_ANON_STACK, PROT_READ, PROT_WRITE, STAGE_FLAG_STACK, STAGE_GUARD_PAGES_MASK,
    STAGE_GUARD_PAGES_SHIFT, STAGE_IMAGE_KIND_NONE, mm_mmap_self, mm_munmap_self,
    mm_prefault_self_exact, mm_stage_image_region, mm_stage_image_region_exec_flags,
};

const PAGE_FLAGS_RW_USER: u64 =
    (KERNITE_PAGE_FLAG_USER as u64) | (KERNITE_PAGE_FLAG_WRITABLE as u64);

/// Number of bytes reserved at the top of the child's stack page for
/// the `SaltyOSStartupLayoutV1` block.
pub const STARTUP_BLOCK_BYTES: usize = core::mem::size_of::<SaltyOSStartupLayoutV1>();

const CSPACE_LAYOUT_BYTES: usize = core::mem::size_of::<SaltyOSCspaceLayoutV1>();

/// Init retypes every child root CNode as a 12-bit CNode in both the
/// early boot-core path and the mmsrv-backed lifecycle path.
const CHILD_CNODE_BITS: u64 = 12;
const CHILD_CNODE_SLOTS: u64 = 1u64 << (CHILD_CNODE_BITS as usize);

/// Result of [`compose`] / [`compose_via_mmsrv`]. The caller passes
/// `child_sp` to the kernel as the new TCB's RSP via
/// `TCB_CONFIGURE`.
pub struct ComposedStack {
    /// Child VA the kernel writes into RSP. Points at `argc`.
    pub child_sp: u64,
}

#[derive(Clone, Copy)]
pub struct PeStartupImages {
    pub main_base: u64,
    pub main_size: u64,
    pub main_entry: u64,
    pub rtld_base: u64,
    pub kernel32_base: u64,
    pub kernel32_size: u64,
    pub scratch_vaddr: u64,
}

#[derive(Clone, Copy)]
enum StartupPayload<'a, 'img> {
    Elf(&'a DsoClosure<'img>),
    Pe(&'a PeStartupImages),
}

/// Write a fully-formed SysV initial stack into `scratch` at the
/// caller-chosen `top_page_offset`. The single page at
/// `scratch[top_page_offset..top_page_offset + PAGE_BYTES]` ends up
/// holding the `SaltyOSStartupLayoutV1` block, the CSpace layout
/// descriptor, the auxv array, the argv/envp pointer arrays, `argc`,
/// and the string blob — exactly what the SysV ABI demands at `RSP`.
///
/// `child_top_page_va` is the child VA of that single page once it
/// is published into the child VSpace. The function uses it to
/// translate scratch offsets into child VAs for the argv/envp/auxv
/// pointers it writes into the page.
///
/// `dso_window_base` / `dso_window_size` come from `plan.runtime_dso_window`
/// and seed the runtime DSO window in the startup block so rtld knows
/// where to map `MM_RESERVE_IMAGE` allocations.
///
/// Returns the child VA of `argc` (becomes `RSP`) and the child VA
/// of the startup block (stamped into auxv `AT_SALTYOS_STARTUP`).
fn write_sysv_layout(
    scratch: *mut u8,
    top_page_offset: usize,
    child_top_page_va: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    payload: StartupPayload<'_, '_>,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    alloc_slot_base: u64,
    framebuffer: SaltyOSFramebufferInfoV1,
    dso_window_base: u64,
    dso_window_size: u64,
) -> Result<ComposedStack, i32> {
    let page_bytes = KERNITE_PAGE_BYTES as usize;

    if argv.len() > 32 || envp.len() > 32 {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }

    // Keep ABI metadata at the top of the page. The string blob grows
    // downward below it; the auxv / envp / argv / argc array lives below
    // the strings.
    let startup_block_offset = top_page_offset + (page_bytes - STARTUP_BLOCK_BYTES);
    let startup_block_va = child_top_page_va + (startup_block_offset - top_page_offset) as u64;
    if startup_block_offset - top_page_offset < CSPACE_LAYOUT_BYTES {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let cspace_layout_offset = (startup_block_offset - CSPACE_LAYOUT_BYTES) & !0x7;
    if cspace_layout_offset < top_page_offset {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let cspace_layout_va = child_top_page_va + (cspace_layout_offset - top_page_offset) as u64;

    let mut blob_cursor = cspace_layout_offset;
    let mut argv_str_va: [u64; 32] = [0; 32];
    let mut envp_str_va: [u64; 32] = [0; 32];

    for (i, s) in argv.iter().enumerate() {
        let need = s.len() + 1;
        if need > blob_cursor - top_page_offset {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
        }
        blob_cursor -= need;
        unsafe {
            let dst = scratch.add(blob_cursor);
            core::ptr::copy_nonoverlapping(s.as_ptr(), dst, s.len());
            *dst.add(s.len()) = 0;
        }
        argv_str_va[i] = child_top_page_va + (blob_cursor - top_page_offset) as u64;
    }
    for (i, s) in envp.iter().enumerate() {
        let need = s.len() + 1;
        if need > blob_cursor - top_page_offset {
            return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
        }
        blob_cursor -= need;
        unsafe {
            let dst = scratch.add(blob_cursor);
            core::ptr::copy_nonoverlapping(s.as_ptr(), dst, s.len());
            *dst.add(s.len()) = 0;
        }
        envp_str_va[i] = child_top_page_va + (blob_cursor - top_page_offset) as u64;
    }

    let (auxv_entries, auxv_len) = build_auxv_entries(payload, startup_block_va);
    let num_words = 1                     // argc
        + argv.len() + 1                  // argv pointers + NULL
        + envp.len() + 1                  // envp pointers + NULL
        + 2 * auxv_len; // auxv (key, val) pairs
    let total_word_bytes = num_words * 8;
    if total_word_bytes > blob_cursor - top_page_offset {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let mut word_off = blob_cursor - total_word_bytes;
    word_off &= !0xF;
    let argc_off = word_off;

    unsafe {
        let dst = scratch.add(word_off) as *mut u64;
        *dst = argv.len() as u64;
    }
    word_off += 8;
    for i in 0..argv.len() {
        unsafe {
            let dst = scratch.add(word_off) as *mut u64;
            *dst = argv_str_va[i];
        }
        word_off += 8;
    }
    unsafe {
        *(scratch.add(word_off) as *mut u64) = 0;
    }
    word_off += 8;
    for i in 0..envp.len() {
        unsafe {
            let dst = scratch.add(word_off) as *mut u64;
            *dst = envp_str_va[i];
        }
        word_off += 8;
    }
    unsafe {
        *(scratch.add(word_off) as *mut u64) = 0;
    }
    word_off += 8;
    for &(key, val) in auxv_entries[..auxv_len].iter() {
        unsafe {
            *(scratch.add(word_off) as *mut u64) = key;
            *(scratch.add(word_off + 8) as *mut u64) = val;
        }
        word_off += 16;
    }

    let cspace_layout = build_cspace_layout(alloc_slot_base);
    let block = build_startup_block(
        payload,
        cap_table_va,
        ipc_buffer_va,
        cspace_layout_va,
        framebuffer,
        dso_window_base,
        dso_window_size,
    );
    unsafe {
        let layout_dst = scratch.add(cspace_layout_offset) as *mut SaltyOSCspaceLayoutV1;
        core::ptr::write(layout_dst, cspace_layout);
        let startup_dst = scratch.add(startup_block_offset) as *mut SaltyOSStartupLayoutV1;
        core::ptr::write(startup_dst, block);
    }

    Ok(ComposedStack {
        child_sp: child_top_page_va + (argc_off - top_page_offset) as u64,
    })
}

/// Compose the initial SysV stack on a freshly-retyped FRAME, then
/// map the FRAME into the child's VSpace at `child_stack_top -
/// PAGE_BYTES` (highest stack page) so the kernel sees the assembled
/// argc/argv/envp/auxv blob at the new TCB's RSP.
///
/// `child_vspace` is the VSpace cap (in init's CSpace) for the new
/// process. `stack_frame` is the FRAME cap init has reserved for
/// the highest stack page. `child_stack_top` is the stack bound the
/// new TCB receives after `TCB_CONFIGURE(rsp = child_sp)`.
///
/// `argv` / `envp` are slices of byte-string slices. `closure` lets
/// the auxv writer stamp `AT_PHDR` / `AT_PHENT` / `AT_PHNUM` /
/// `AT_ENTRY` / `AT_BASE` / `AT_PAGESZ` / `AT_SALTYOS_STARTUP`.
///
/// `cap_table_va` and `ipc_buffer_va` are the child VAs the cspace /
/// loader modules picked for the cap-table frame and the IPC buffer
/// frame; they go into the startup block so substrate doesn't have
/// to discover them.
#[allow(clippy::too_many_arguments)]
pub fn compose(
    child_vspace: u64,
    stack_frame: u64,
    child_stack_top: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    closure: &DsoClosure<'_>,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    alloc_slot_base: u64,
    dso_window_base: u64,
    dso_window_size: u64,
) -> Result<ComposedStack, i32> {
    let page_bytes_u64 = KERNITE_PAGE_BYTES as u64;
    let child_top_page_va = child_stack_top - page_bytes_u64;

    let r = invoke::vspace_map(
        trona_kernel::core_types::CapRef::flat(KERNITE_CAP_SELF_VSPACE as u64),
        trona_runtime::core::slot_alloc::resolved_cap_ref(stack_frame),
        SCRATCH_FRAME_VA,
        PAGE_FLAGS_RW_USER,
    );
    if r != 0 {
        return Err(r);
    }
    let scratch = SCRATCH_FRAME_VA as *mut u8;

    let layout_result = write_sysv_layout(
        scratch,
        0,
        child_top_page_va,
        argv,
        envp,
        StartupPayload::Elf(closure),
        cap_table_va,
        ipc_buffer_va,
        alloc_slot_base,
        SaltyOSFramebufferInfoV1::zeroed(),
        dso_window_base,
        dso_window_size,
    );

    let r = invoke::vspace_unmap(
        trona_kernel::core_types::CapRef::flat(KERNITE_CAP_SELF_VSPACE as u64),
        SCRATCH_FRAME_VA,
    );
    if r != 0 {
        return Err(r);
    }
    let composed = layout_result?;

    let r = invoke::vspace_map(
        trona_runtime::core::slot_alloc::resolved_cap_ref(child_vspace),
        trona_runtime::core::slot_alloc::resolved_cap_ref(stack_frame),
        child_top_page_va,
        PAGE_FLAGS_RW_USER,
    );
    if r != 0 {
        return Err(r);
    }

    Ok(composed)
}

/// Mmsrv-backed stack composer for the post-mmsrv spawn path.
///
/// Allocates the service's full stack reserve in init's VSpace via
/// `MM_MMAP`, writes the SysV initial stack content into the topmost
/// page (so the rest start as anon zero — exactly what a fresh stack
/// wants), then asks mmsrv to splice the same MO into the child
/// VSpace at the planner-computed stack reserve base. Init releases
/// its writable view before the function returns; the child sees the
/// full configured stack reserve with the topmost page already
/// populated for its `_start`. mmsrv's `RegionTable` now tracks the
/// mapping on both sides, so a child page-fault on lower stack pages
/// resolves as an anon page allocation rather than a "no region" kill.
///
/// `txn_id == Some(_)` routes the splice through an exec transaction
/// so the new stack lands in the pending VSpace until commit.
#[allow(clippy::too_many_arguments)]
pub fn compose_via_mmsrv(
    state: &SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    child_stack_top: u64,
    stack_spec: StackLayoutSpec,
    argv: &[&[u8]],
    envp: &[&[u8]],
    closure: &DsoClosure<'_>,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    alloc_slot_base: u64,
    startup_framebuffer: SaltyOSFramebufferInfoV1,
    dso_window_base: u64,
    dso_window_size: u64,
    txn_id: Option<u64>,
) -> Result<ComposedStack, i32> {
    compose_payload_via_mmsrv(
        state,
        src_client_id,
        dst_client_id,
        child_stack_top,
        stack_spec,
        argv,
        envp,
        StartupPayload::Elf(closure),
        cap_table_va,
        ipc_buffer_va,
        alloc_slot_base,
        startup_framebuffer,
        dso_window_base,
        dso_window_size,
        txn_id,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compose_pe_via_mmsrv(
    state: &SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    child_stack_top: u64,
    stack_spec: StackLayoutSpec,
    argv: &[&[u8]],
    envp: &[&[u8]],
    images: &PeStartupImages,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    alloc_slot_base: u64,
    startup_framebuffer: SaltyOSFramebufferInfoV1,
    dso_window_base: u64,
    dso_window_size: u64,
    txn_id: Option<u64>,
) -> Result<ComposedStack, i32> {
    compose_payload_via_mmsrv(
        state,
        src_client_id,
        dst_client_id,
        child_stack_top,
        stack_spec,
        argv,
        envp,
        StartupPayload::Pe(images),
        cap_table_va,
        ipc_buffer_va,
        alloc_slot_base,
        startup_framebuffer,
        dso_window_base,
        dso_window_size,
        txn_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn compose_payload_via_mmsrv(
    state: &SupervisorState,
    src_client_id: u32,
    dst_client_id: u32,
    child_stack_top: u64,
    stack_spec: StackLayoutSpec,
    argv: &[&[u8]],
    envp: &[&[u8]],
    payload: StartupPayload<'_, '_>,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    alloc_slot_base: u64,
    startup_framebuffer: SaltyOSFramebufferInfoV1,
    dso_window_base: u64,
    dso_window_size: u64,
    txn_id: Option<u64>,
) -> Result<ComposedStack, i32> {
    let page_bytes_u64 = KERNITE_PAGE_BYTES as u64;
    let materialization = plan_stack_materialization(stack_spec, child_stack_top)
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    let stack_size_bytes = materialization.reserve_bytes();
    let stack_bottom_va = materialization.reserve_base;
    let child_top_page_va = child_stack_top - page_bytes_u64;
    let top_page_offset = (stack_size_bytes - page_bytes_u64) as usize;

    let (scratch_va, src_region_packed) = mm_mmap_self(
        state,
        MMAP_KIND_ANON_STACK,
        0,
        stack_size_bytes,
        PROT_READ | PROT_WRITE,
        0,
    )?;

    let prefault_offset = (materialization.commit_offset_pages as u64) * page_bytes_u64;
    let prefault_bytes = (materialization.commit_count_pages as u64) * page_bytes_u64;
    let layout_result = match (scratch_va.checked_add(prefault_offset), prefault_bytes != 0) {
        (Some(prefault_va), true) => {
            match mm_prefault_self_exact(state, prefault_va, prefault_bytes, PROT_READ | PROT_WRITE)
            {
                Ok(()) => write_sysv_layout(
                    scratch_va as *mut u8,
                    top_page_offset,
                    child_top_page_va,
                    argv,
                    envp,
                    payload,
                    cap_table_va,
                    ipc_buffer_va,
                    alloc_slot_base,
                    startup_framebuffer,
                    dso_window_base,
                    dso_window_size,
                ),
                Err(e) => Err(e),
            }
        }
        _ => Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32),
    };

    // A staged stack reserves a guard band of the loader's planned width;
    // pack `guard_pages` into the flags word so mmsrv reserves that many
    // pages below the stack (not just the default one). 0 = no guard.
    let guard_flag =
        ((stack_spec.guard_pages as u64) & STAGE_GUARD_PAGES_MASK) << STAGE_GUARD_PAGES_SHIFT;
    let stage_result = match (layout_result.is_ok(), txn_id) {
        (true, Some(txn)) => mm_stage_image_region_exec_flags(
            state,
            src_client_id,
            src_region_packed,
            dst_client_id,
            stack_bottom_va,
            0,
            stack_size_bytes,
            stack_size_bytes,
            PROT_READ | PROT_WRITE,
            STAGE_IMAGE_KIND_NONE,
            txn,
            STAGE_FLAG_STACK | guard_flag,
        ),
        (true, None) => mm_stage_image_region(
            state,
            src_client_id,
            src_region_packed,
            dst_client_id,
            stack_bottom_va,
            0,
            stack_size_bytes,
            stack_size_bytes,
            PROT_READ | PROT_WRITE,
            STAGE_IMAGE_KIND_NONE,
            STAGE_FLAG_STACK | guard_flag,
        ),
        (false, _) => Ok(()),
    };

    mm_munmap_self(state, scratch_va, stack_size_bytes)?;

    let composed = layout_result?;
    stage_result?;
    Ok(composed)
}

/// Build the auxv vector substrate's `_start` expects. Order
/// matches glibc's `__libc_start_main` consumer order; substrate's
/// runtime-install path treats it as a flat dictionary so the order
/// is informational rather than load-bearing.
fn build_auxv_entries(
    payload: StartupPayload<'_, '_>,
    startup_block_va: u64,
) -> ([(u64, u64); 8], usize) {
    match payload {
        StartupPayload::Elf(closure) => {
            // `at_phdr` is the runtime VA of the program-header table within
            // the loaded image. `closure.main.load_base` carries either the
            // ET_DYN PIE bias or 0 for absolute ET_EXEC/direct images.
            let main_phdr_va = closure.main.load_base + closure.main.bytes_phoff();
            let main_phent = closure.main.bytes_phentsize();
            let main_phnum = closure.main.bytes_phnum();
            let main_entry = closure.main.entry_pc;
            let interp_base = closure.interp.as_ref().map(|i| i.load_base).unwrap_or(0);

            (
                [
                    (AT_PHDR, main_phdr_va),
                    (AT_PHENT, main_phent),
                    (AT_PHNUM, main_phnum),
                    (AT_ENTRY, main_entry),
                    (AT_BASE, interp_base),
                    (AT_PAGESZ, KERNITE_PAGE_BYTES),
                    (AT_SALTYOS_STARTUP, startup_block_va),
                    (AT_NULL, 0),
                ],
                8,
            )
        }
        StartupPayload::Pe(images) => (
            [
                (AT_BASE, images.rtld_base),
                (AT_ENTRY, images.main_entry),
                (AT_PAGESZ, KERNITE_PAGE_BYTES),
                (AT_SALTYOS_STARTUP, startup_block_va),
                (AT_NULL, 0),
                (0, 0),
                (0, 0),
                (0, 0),
            ],
            5,
        ),
    }
}

/// Compose the child CSpace descriptor advertised through
/// `SaltyOSStartupLayoutV1.cspace_layout_ptr`.
fn build_cspace_layout(alloc_slot_base: u64) -> SaltyOSCspaceLayoutV1 {
    // Do not advertise an RTLD untyped window here: init does not install
    // one into child CSpaces. The allocator range starts after bootstrap caps.
    let alloc_base = if alloc_slot_base > CHILD_RTLD_FRAME_SLOT_START {
        alloc_slot_base
    } else {
        CHILD_RTLD_FRAME_SLOT_START
    };
    SaltyOSCspaceLayoutV1 {
        version: SaltyOSCspaceLayoutV1::VERSION,
        flags: 0,
        cnode_bits: CHILD_CNODE_BITS,
        rtld_untyped_base: 0,
        rtld_untyped_count: 0,
        rtld_untyped_size_bits: 0,
        frame_slot_base: alloc_base,
        frame_slot_limit: CHILD_CNODE_SLOTS,
        alloc_base,
        alloc_limit: CHILD_CNODE_SLOTS,
        recv_base: 0,
        recv_limit: 0,
        expand_base: 0,
        expand_limit: 0,
    }
}

/// Compose the `SaltyOSStartupLayoutV1` block — the substrate-private
/// startup descriptor pointed at by auxv `AT_SALTYOS_STARTUP`.
///
/// `main_image` identifies the child executable for rtld dispatch. The
/// `mapped_images` array is narrower: rtld has already installed the
/// interpreter as object 0 and the main executable as object 1 before it
/// reads this list, so init must only advertise extra preloaded DSOs here.
/// Otherwise rtld tries to seed the main image again and may reject valid
/// main-executable metadata as an invalid preloaded DSO entry.
fn build_startup_block(
    payload: StartupPayload<'_, '_>,
    cap_table_va: u64,
    ipc_buffer_va: u64,
    cspace_layout_va: u64,
    framebuffer: SaltyOSFramebufferInfoV1,
    dso_window_base: u64,
    dso_window_size: u64,
) -> SaltyOSStartupLayoutV1 {
    use trona_kernel::core_types::{
        SALTYOS_IMAGE_KIND_ELF, SALTYOS_IMAGE_KIND_PE, SaltyOSImageInfoV1,
    };

    let scratch_vaddr = match payload {
        StartupPayload::Elf(_) => SCRATCH_FRAME_VA,
        StartupPayload::Pe(images) => images.scratch_vaddr,
    };
    let mut block = SaltyOSStartupLayoutV1::new(
        ipc_buffer_va,
        scratch_vaddr,
        dso_window_base,
        dso_window_size,
        cap_table_va,
        cspace_layout_va,
    );
    block.set_framebuffer(framebuffer);

    match payload {
        StartupPayload::Elf(closure) => {
            let main_size = closure.main.span_bytes();
            block.set_main_image(SaltyOSImageInfoV1::new(
                SALTYOS_IMAGE_KIND_ELF,
                0,
                closure.main.load_base,
                main_size,
                closure.main.entry_pc,
            ));

            for needed in closure.needed.iter().take(closure.needed_len).flatten() {
                let needed_size = needed.span_bytes();
                let _ = block.push_mapped_image(
                    SaltyOSImageInfoV1::new(
                        SALTYOS_IMAGE_KIND_ELF,
                        0,
                        needed.load_base,
                        needed_size,
                        needed.entry_pc,
                    ),
                    needed.name,
                );
            }
        }
        StartupPayload::Pe(images) => {
            block.set_main_image(SaltyOSImageInfoV1::new(
                SALTYOS_IMAGE_KIND_PE,
                0,
                images.main_base,
                images.main_size,
                images.main_entry,
            ));
            let _ = block.push_mapped_image(
                SaltyOSImageInfoV1::new(
                    SALTYOS_IMAGE_KIND_PE,
                    0,
                    images.kernel32_base,
                    images.kernel32_size,
                    0,
                ),
                b"kernel32.dll",
            );
        }
    }

    block
}

// `Elf64Auxv` is referenced for size assertions only; suppress the
// unused-import warning by binding it.
#[allow(dead_code)]
const _AUX_SIZE_CHECK: usize = core::mem::size_of::<Elf64Auxv>();

/// Helpers on `DsoMapping` that cache the main image's program-header
/// metadata for the auxv writer and the startup-block builder.
trait DsoMappingExt {
    fn bytes_phoff(&self) -> u64;
    fn bytes_phentsize(&self) -> u64;
    fn bytes_phnum(&self) -> u64;
    /// Total VA span of the image's PT_LOAD segments — used as the
    /// `size` field in the `mapped_images` startup-block entries so
    /// rtld knows how much of each DSO is mapped.
    fn span_bytes(&self) -> u64;
}

impl DsoMappingExt for crate::supervisor::loader::dso::DsoMapping<'_> {
    fn bytes_phoff(&self) -> u64 {
        // ELF64 ehdr: e_phoff at offset 32 (u64 LE).
        if self.bytes.len() < 40 {
            return 0;
        }
        u64::from_le_bytes(self.bytes[32..40].try_into().unwrap_or([0u8; 8]))
    }
    fn bytes_phentsize(&self) -> u64 {
        // ELF64 ehdr: e_phentsize at offset 54 (u16 LE).
        if self.bytes.len() < 56 {
            return 0;
        }
        u16::from_le_bytes(self.bytes[54..56].try_into().unwrap_or([0u8; 2])) as u64
    }
    fn bytes_phnum(&self) -> u64 {
        // ELF64 ehdr: e_phnum at offset 56 (u16 LE).
        if self.bytes.len() < 58 {
            return 0;
        }
        u16::from_le_bytes(self.bytes[56..58].try_into().unwrap_or([0u8; 2])) as u64
    }
    fn span_bytes(&self) -> u64 {
        // Re-parse the ELF to walk the program-header table — cheap
        // because the bytes are already in init's address space.
        // Returns 0 if the parse fails; rtld treats 0 as "size
        // unknown" and falls back to PT_LOAD scanning at startup.
        match crate::supervisor::loader::elf::parse(self.bytes) {
            Ok(image) => match trona_loader::common::elf::header::load_span(image.phdrs) {
                Some((lo, hi)) => hi.saturating_sub(lo),
                None => 0,
            },
            Err(_) => 0,
        }
    }
}
