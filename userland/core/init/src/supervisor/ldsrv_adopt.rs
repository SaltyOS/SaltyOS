// SPDX-License-Identifier: GPL-2.0-only
//
//! PID 1 → `ldsrv` boot-cache adoption — the handoff sender.
//!
//! Once `ldsrv` is up, init transfers the canonical initrd code-MemoryObject set
//! to it (each an executable code MO keyed by its content digest), then
//! **moves** the boot ExecAuthority so `ldsrv` becomes the single steady-state
//! EXECUTE origin, then seals. After the seal `ldsrv` serves `resolve_*` and
//! init relinquishes its bootstrap authority.
//!
//! Both ELF and PE objects are adopted. ELF adopts use a borrowed-frames
//! code MO over the initrd bytes (the file layout is the memory layout).
//! PE adopts relay the file into an anonymous memory-image MO so the R-X
//! child is the PE's `size_of_image` window in memory order, not the
//! file's section layout — the planner in `trona_loader::common::pe::memory_image`
//! drives both `ldsrv::resolve::relayout_pe` and this adopt path from a
//! shared invariant set.
//!
//! The code-MO objects are carved from init's own slab pool (`state.frames`) —
//! the same path mmsrv uses for MemoryObjects — and the borrowed frames come
//! from the immortal initrd device-untyped, so the objects are pinned for the
//! system lifetime and never released.

use trona_kernel::core_types::{CapRef, TronaMsg};
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_loader::common::cpio::CpioIter;
use trona_loader::common::elf::header::validate_ehdr;
use trona_loader::common::pe::memory_image::{MAX_COPIES, PeCopy, plan_memory_image};
use trona_protocol::common::TRONA_OK;
use trona_protocol::ldsrv::{
    ContentDigest, LDSRV_ADOPT_AUTHORITY, LDSRV_ADOPT_NAME_BASE, LDSRV_ADOPT_OBJECT,
    LDSRV_ADOPT_REG_ENTRY, LDSRV_ADOPT_REG_FORMAT, LDSRV_ADOPT_REG_IDENTITY_HI,
    LDSRV_ADOPT_REG_IDENTITY_LO, LDSRV_ADOPT_REG_MO_SIZE, LDSRV_ADOPT_REG_NAME_LEN,
    LDSRV_ADOPT_REG_PHNUM, LDSRV_ADOPT_REG_PHOFF, LDSRV_ADOPT_SEAL, LDSRV_FORMAT_ELF,
    LDSRV_FORMAT_PE,
};
use trona_runtime::core::slot_alloc::{OwnedCap, alloc_slot, dup_for_transfer, resolved_cap_ref};
use uapi::{KERNITE_CAP_SELF_CSPACE, KERNITE_OBJ_MEMORY_OBJECT, KERNITE_PAGE_BYTES};

use crate::internal_slots::{SLOT_EXEC_AUTHORITY, SLOT_INITRD_UNTYPED};
use crate::supervisor::SupervisorState;

const PAGE: u64 = KERNITE_PAGE_BYTES as u64;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

#[inline]
fn invalid_argument() -> i32 {
    uapi::KERNITE_ERR_INVALID_ARGUMENT as i32
}

#[inline]
fn page_align_up(v: u64) -> u64 {
    (v + PAGE - 1) & !(PAGE - 1)
}

/// `size_bits` for a MemoryObject covering `pages` pages (matches
/// `mo_registry::mo_size_bits_for_length`).
fn mo_size_bits(pages: u64) -> Option<u64> {
    if pages == 0 {
        return None;
    }
    let bits = pages.checked_next_power_of_two()?.trailing_zeros() as u64;
    if bits > 31 { None } else { Some(bits) }
}

/// Adopt the full initrd ELF code set into `ldsrv` over the private adopt MP
/// `adopt_send`, then move the boot ExecAuthority and seal.
pub fn send_adopt_set(state: &mut SupervisorState, adopt_send: u64) -> Result<(), i32> {
    let initrd_va = state.caps.initrd_va;
    let initrd_len = state.caps.initrd_len;
    if initrd_len == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }

    let mut adopted = 0u64;
    let mut iter = unsafe { CpioIter::new(initrd_va as *const u8, initrd_len) };
    while let Some(entry) = iter.next_entry() {
        let name = unsafe { core::slice::from_raw_parts(entry.name, entry.name_len) };
        if !is_adoptable(name) {
            continue;
        }
        let bytes = unsafe { core::slice::from_raw_parts(entry.data, entry.data_len) };
        // Branch by format: ELF adopts use a borrowed-frames code MO
        // over the initrd bytes; PE adopts relay the file into an
        // anonymous memory-image MO. Both are exec-MOs ready for the
        // ldsrv cache. Anything else (scripts, data) is not adopted.
        if crate::supervisor::loader::pe::is_pe_header(bytes) {
            adopt_object_pe(state, adopt_send, initrd_va, name, bytes)?;
            adopted += 1;
        } else if bytes.len() >= 4 && bytes[..4] == ELF_MAGIC {
            adopt_object_elf(state, adopt_send, initrd_va, name, bytes)?;
            adopted += 1;
        }
    }
    if adopted == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }

    move_authority(adopt_send)?;
    // The boot ExecAuthority now lives in ldsrv; init can no longer mint
    // executable code MOs and resolves them through ldsrv from here on.
    state.exec_authority_held = false;
    seal(adopt_send)?;
    Ok(())
}

/// Adoptable initrd code lives under `/bin/` (main images) or `/lib/` (DSOs).
fn is_adoptable(name: &[u8]) -> bool {
    name.starts_with(b"/bin/") || name.starts_with(b"/lib/")
}

/// The final path component, bound as the object's soname.
fn basename(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b'/') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// Pack `name` bytes contiguously from `LDSRV_ADOPT_NAME_BASE`, matching
/// `ldsrv`'s byte-contiguous `copy_name`. Returns the byte length.
fn pack_name(regs: &mut [u64; 32], name: &[u8]) -> usize {
    let dst = &raw mut regs[LDSRV_ADOPT_NAME_BASE] as *mut u8;
    let max = (regs.len() - LDSRV_ADOPT_NAME_BASE) * 8;
    let n = name.len().min(max);
    for i in 0..n {
        // SAFETY: `dst` points at `regs[NAME_BASE]`; `n <= max` keeps the write
        // inside the contiguous `[u64; 32]`.
        unsafe { *dst.add(i) = name[i] };
    }
    n
}

/// Mint a borrowed-frames code MO for `bytes` (over the initrd at its
/// page-aligned offset) and return the owning cap. The MO object is carved from
/// `state.frames`. With `executable`, the boot ExecAuthority confers an `R-X`
/// view and the writable parent cap is dropped so only the `R-X` view leaves
/// (W^X) — the adopt path and the pre-handoff `get_code_mo` branch use this.
/// Without it, the populated `READ` cap itself is returned (no EXECUTE, no
/// authority needed) — a `resolve_main` backing ldsrv reads to confer / dedup.
pub(crate) fn mint_borrowed(
    state: &mut SupervisorState,
    initrd_va: u64,
    bytes: &[u8],
    executable: bool,
) -> Result<OwnedCap, i32> {
    let offset = (bytes.as_ptr() as u64).wrapping_sub(initrd_va);
    if offset % PAGE != 0 {
        return Err(invalid_argument());
    }
    let span_pages = page_align_up(bytes.len() as u64) / PAGE;
    let size_bits = mo_size_bits(span_pages).ok_or_else(invalid_argument)?;

    let slot = alloc_slot().ok_or_else(invalid_argument)?;
    let dest = slot.addr();
    state
        .frames
        .retype_child(KERNITE_OBJ_MEMORY_OBJECT as u64, size_bits, dest)
        .ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
    let mo = slot.assume_filled();
    let r = invoke::mo_populate_borrowed(
        resolved_cap_ref(mo.as_raw()),
        resolved_cap_ref(SLOT_INITRD_UNTYPED),
        offset,
        span_pages,
    );
    if r != 0 {
        return Err(r);
    }

    if !executable {
        // READ-only borrowed-frames view: the populated cap (no EXECUTE) is the
        // deliverable — a backing ldsrv reads to confer EXECUTE itself.
        return Ok(mo);
    }

    let exec = alloc_slot().ok_or_else(invalid_argument)?;
    let r = invoke::mo_mark_executable_ref(
        resolved_cap_ref(SLOT_EXEC_AUTHORITY),
        resolved_cap_ref(mo.as_raw()),
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        exec.borrow(),
    );
    if r != 0 {
        return Err(r);
    }
    // The R-X child keeps the (frames-pinned) object alive with no writable
    // view; drop the R-W cap.
    drop(mo);
    Ok(exec.assume_filled())
}

/// Mint and adopt one ELF object.
fn adopt_object_elf(
    state: &mut SupervisorState,
    adopt_send: u64,
    initrd_va: u64,
    name: &[u8],
    bytes: &[u8],
) -> Result<(), i32> {
    let ehdr =
        unsafe { validate_ehdr(bytes.as_ptr(), bytes.len()) }.map_err(|_| invalid_argument())?;
    let exec = mint_borrowed(state, initrd_va, bytes, true)?;

    let mut digest = ContentDigest::new();
    digest.update(bytes);
    let (id_lo, id_hi) = digest.finish();

    let mut msg = TronaMsg::zeroed();
    msg.label = LDSRV_ADOPT_OBJECT;
    msg.regs[LDSRV_ADOPT_REG_IDENTITY_LO] = id_lo;
    msg.regs[LDSRV_ADOPT_REG_IDENTITY_HI] = id_hi;
    msg.regs[LDSRV_ADOPT_REG_MO_SIZE] = bytes.len() as u64;
    msg.regs[LDSRV_ADOPT_REG_FORMAT] = LDSRV_FORMAT_ELF;
    msg.regs[LDSRV_ADOPT_REG_ENTRY] = ehdr.e_entry;
    msg.regs[LDSRV_ADOPT_REG_PHOFF] = ehdr.e_phoff;
    msg.regs[LDSRV_ADOPT_REG_PHNUM] = ehdr.e_phnum as u64;
    let nlen = pack_name(&mut msg.regs, basename(name));
    msg.regs[LDSRV_ADOPT_REG_NAME_LEN] = nlen as u64;
    msg.length = LDSRV_ADOPT_NAME_BASE as u64 + nlen.div_ceil(8) as u64;

    let result = call_adopt(adopt_send, &msg, Some(exec.borrow()));
    // The init-side R-X cap is no longer needed: ldsrv holds the transferred
    // copy. Drop it whether or not the call succeeded.
    drop(exec);
    result
}

/// Adopt one PE object: relay the file into a memory-image MO and
/// ship the R-X child through the adopt channel. The original PE file
/// bytes are the **content-identity input** — they match what ldsrv's
/// `confer_and_cache` would hash on first resolve, so the adopt hits
/// cache before any exec. The PE plan (file_off → RVA copy list) is
/// shared with ldsrv's `resolve::relayout_pe` via
/// `trona_loader::common::pe::memory_image`.
///
/// Init does NOT use `trona_runtime::client::mm::{mo_create, mmap_mo,
/// munmap}` here — those resolve `mmsrv_ep()` from the runtime weak
/// symbol, which is 0 for init (init's mmsrv endpoint is its own
/// self-tier `state.caps.mmsrv_self_mp`). We go through
/// `mm_ipc::mm_mo_create_self` / `mm_mmap_mo_self` /
/// `mm_ipc::mm_munmap_self` instead.
fn adopt_object_pe(
    state: &mut SupervisorState,
    adopt_send: u64,
    _initrd_va: u64,
    name: &[u8],
    bytes: &[u8],
) -> Result<(), i32> {
    // Plan the copy list from the shared helper.
    let mut copies = [PeCopy::EMPTY; MAX_COPIES];
    let (image_size, _size_of_headers, entry_rva, copy_count) =
        plan_memory_image(bytes, &mut copies).map_err(|_| invalid_argument())?;

    // Allocate the anonymous memory-image MO against mmsrv on init's
    // self-tier MP, then mmap it R/W into init's VSpace.
    let map_len = page_align_up(image_size);
    let memimage = crate::supervisor::mm_ipc::mm_mo_create_self(state, map_len, 0)?;
    let mapped = crate::supervisor::mm_ipc::mm_mmap_mo_self(
        state,
        memimage.duplicate().ok_or_else(invalid_argument)?,
        map_len,
        (uapi::KERNITE_RIGHT_READ | uapi::KERNITE_RIGHT_WRITE) as u64,
        0,
        false,
    )? as usize;

    // Execute each copy from the initrd byte slice directly. The
    // CPIO-extracted `bytes` already points into the boot CPIO; we
    // copy into the mapped memory-image MO. Anonymous MO bytes that
    // fall outside any section (gap between sections, BSS) are left
    // zero by `MM_MO_CREATE` + the kernel's anon backing.
    let mut ok = true;
    for c in &copies[..copy_count] {
        let len = c.bytes as usize;
        let src_start = c.src_file_offset as usize;
        let dst_off = c.dst_rva as usize;
        let Some(src_end) = src_start.checked_add(len) else {
            ok = false;
            break;
        };
        if src_end > bytes.len() {
            ok = false;
            break;
        }
        let Some(dst_end) = mapped.checked_add(dst_off).and_then(|p| p.checked_add(len)) else {
            ok = false;
            break;
        };
        if dst_end > mapped + map_len as usize {
            ok = false;
            break;
        }
        unsafe {
            let dst_ptr = (mapped + dst_off) as *mut u8;
            core::ptr::copy_nonoverlapping(bytes.as_ptr().add(src_start), dst_ptr, len);
        }
    }
    let unmapped = crate::supervisor::mm_ipc::mm_munmap_self(state, mapped as u64, map_len).is_ok();
    if !ok || !unmapped {
        return Err(invalid_argument());
    }

    // Mint the R-X child via the boot ExecAuthority. The anonymous MO
    // holds the memory-image bytes; the writable parent cap is dropped
    // so only the R-X view leaves (W^X).
    let exec = alloc_slot().ok_or_else(invalid_argument)?;
    let r = invoke::mo_mark_executable_ref(
        resolved_cap_ref(SLOT_EXEC_AUTHORITY),
        resolved_cap_ref(memimage.as_raw()),
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        exec.borrow(),
    );
    drop(memimage);
    if r != 0 {
        return Err(r);
    }
    let exec = exec.assume_filled();

    let mut digest = ContentDigest::new();
    digest.update(bytes);
    let (id_lo, id_hi) = digest.finish();

    let mut msg = TronaMsg::zeroed();
    msg.label = LDSRV_ADOPT_OBJECT;
    msg.regs[LDSRV_ADOPT_REG_IDENTITY_LO] = id_lo;
    msg.regs[LDSRV_ADOPT_REG_IDENTITY_HI] = id_hi;
    msg.regs[LDSRV_ADOPT_REG_MO_SIZE] = image_size;
    msg.regs[LDSRV_ADOPT_REG_FORMAT] = LDSRV_FORMAT_PE;
    msg.regs[LDSRV_ADOPT_REG_ENTRY] = entry_rva;
    msg.regs[LDSRV_ADOPT_REG_PHOFF] = 0;
    msg.regs[LDSRV_ADOPT_REG_PHNUM] = 0;
    let nlen = pack_name(&mut msg.regs, basename(name));
    msg.regs[LDSRV_ADOPT_REG_NAME_LEN] = nlen as u64;
    msg.length = LDSRV_ADOPT_NAME_BASE as u64 + nlen.div_ceil(8) as u64;

    let result = call_adopt(adopt_send, &msg, Some(exec.borrow()));
    drop(exec);
    result
}

/// Move the boot ExecAuthority to `ldsrv`, then delete init's copy so EXECUTE
/// has a single origin.
fn move_authority(adopt_send: u64) -> Result<(), i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = LDSRV_ADOPT_AUTHORITY;
    msg.length = 0;
    call_adopt(
        adopt_send,
        &msg,
        Some(resolved_cap_ref(SLOT_EXEC_AUTHORITY)),
    )?;
    let _ = invoke::cnode_delete(
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        SLOT_EXEC_AUTHORITY,
    );
    Ok(())
}

/// Seal adoption — `ldsrv` begins serving resolutions and acks.
fn seal(adopt_send: u64) -> Result<(), i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = LDSRV_ADOPT_SEAL;
    msg.length = 0;
    call_adopt(adopt_send, &msg, None)
}

/// Issue one adopt request on `adopt_send`, optionally moving a copy of `cap` to
/// `ldsrv`. Mirrors the resolve client's send-cap discipline.
fn call_adopt(adopt_send: u64, msg: &TronaMsg, cap: Option<CapRef>) -> Result<(), i32> {
    let ctx = trona_runtime::current_ipc_ctx();
    unsafe { ipc::clear_send_caps_ctx(ctx) };
    let xfer = match cap {
        Some(c) => {
            let tc = dup_for_transfer(c).ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
            unsafe { ipc::set_send_cap_ctx(ctx, 0, tc.slot()) };
            Some(tc)
        }
        None => None,
    };

    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ctx,
            adopt_send,
            msg as *const TronaMsg,
            &raw mut reply,
            ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    drop(xfer);
    if err != 0 {
        return Err(err as i32);
    }
    if reply.label != TRONA_OK {
        return Err(reply.label as i32);
    }
    Ok(())
}
