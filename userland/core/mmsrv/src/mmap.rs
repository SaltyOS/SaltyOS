// SPDX-License-Identifier: GPL-2.0-only
//
//! Self-only tier handlers — MMAP, MUNMAP, MPROTECT, BRK, SBRK,
//! SHM_CREATE, SHM_MAP, FILE_MMAP, PREFAULT_RANGE, GET_SYSTEM_MEMINFO.
//!
//! Source identity for every handler is the per-client MP recv side
//! the message arrived on (resolved by the reactor before invoking
//! these); the wire carries no `target_badge` field.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::{TRONA_OK, TRONA_PERMISSION_DENIED};
use trona_protocol::mm::{
    MM_FLAG_FIXED as FLAG_FIXED, MM_FLAG_FIXED_NOREPLACE as FLAG_FIXED_NOREPLACE,
    MM_FLAG_GROWSDOWN as FLAG_GROWSDOWN, MM_FLAG_LAZY as FLAG_LAZY,
    MM_FLAG_PRIVATE as FLAG_PRIVATE, MM_MMAP_REQ_REG_FILE_BACKING_ID,
    MM_MMAP_REQ_REG_FILE_BACKING_LENGTH, MM_MMAP_REQ_REG_IMAGE_ID, MM_MMAP_REQ_REG_IMAGE_KIND,
    MMAP_KIND_SHM_MO, STAGE_IMAGE_KIND_BSS, STAGE_IMAGE_KIND_DATA, STAGE_IMAGE_KIND_NONE,
    STAGE_IMAGE_KIND_RODATA, STAGE_IMAGE_KIND_TEXT,
};
use trona_protocol::posix_abi::mm::{MS_ASYNC, MS_INVALIDATE, MS_SYNC};
use trona_protocol::vfs::public::{
    VFS_MSYNC_MO, VFS_PUBLIC_REPLY_AGAIN, VFS_PUBLIC_REPLY_BUSY, VFS_PUBLIC_REPLY_INVALID,
    VFS_PUBLIC_REPLY_IO_ERROR, VFS_PUBLIC_REPLY_NO_MEM, VFS_PUBLIC_REPLY_NOT_FOUND,
    VFS_PUBLIC_REPLY_NOT_SUPPORTED, VFS_PUBLIC_REPLY_OK, VFS_PUBLIC_REPLY_PERM,
    VFS_PUBLIC_REPLY_RANGE, VFS_PUBLIC_REPLY_RO_FS,
};
use uapi::{
    KERNITE_CAP_SELF_CSPACE, KERNITE_ERR_ALREADY_EXISTS, KERNITE_ERR_ALREADY_MAPPED,
    KERNITE_ERR_BUSY, KERNITE_ERR_INSUFFICIENT_RIGHTS, KERNITE_ERR_INVALID_ARGUMENT,
    KERNITE_ERR_INVALID_OPERATION, KERNITE_ERR_IO_ERROR, KERNITE_ERR_NOT_FOUND,
    KERNITE_ERR_NOT_SUPPORTED, KERNITE_ERR_OUT_OF_MEMORY, KERNITE_ERR_OUT_OF_RANGE,
    KERNITE_ERR_READONLY, KERNITE_INV_CNODE_DELETE, KERNITE_INV_CNODE_MOVE,
    KERNITE_INV_MO_ATTACH_PAGER, KERNITE_INV_MO_GET_SIZE, KERNITE_INV_MO_SNAPSHOT,
    KERNITE_INV_UNTYPED_RETYPE, KERNITE_INV_VSPACE_MAP_MO, KERNITE_INV_VSPACE_UNMAP,
    KERNITE_OBJ_VM_HIERARCHY_STATE, KERNITE_PAGE_BYTES as KERNITE_PAGE_BYTES_U32,
    KERNITE_PAGE_FLAG_EXECUTABLE, KERNITE_PAGE_FLAG_NOCACHE, KERNITE_PAGE_FLAG_USER,
    KERNITE_PAGE_FLAG_WRITABLE, KERNITE_RIGHT_ALL, KERNITE_RIGHT_EXECUTE, kernite_ipc_buffer,
};

use crate::caps::recv_user_slot;
use crate::client::{ClientState, ClientVm};
use crate::file_backed_registry::{FileBackedEntry, FileBackedRegistry};
use crate::main_loop::ServerState;
use crate::mo_registry::{MoKind, MoRegistry};
use crate::region::{
    BackingDescriptor, ForkPolicy, ImageKind, MappedRegion, MoHandle, REGION_HEAP,
    REGION_IMAGE_BSS, REGION_IMAGE_DATA, REGION_IMAGE_TEXT, REGION_MMAP, REGION_SHARED_LIB,
    REGION_STACK, RegionId, ReservationId, ReservationPurpose, ReservedRange,
    max_prot_for_region_type,
};
use crate::self_vm::SelfVm;
use crate::txn::{self, MappingPlan, STACK_GUARD_BYTES};
use crate::va_alloc;
use trona_protocol::init::{TronaProcMemSnapshot, TronaVSpaceMemStats, TronaVSpaceRangeStats};
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::frame_alloc::FrameAllocator;
use trona_server::slab::ReservationKind;
use trona_server::{ContHandle, MpReplyTarget};

const KERNITE_PAGE_BYTES: u64 = KERNITE_PAGE_BYTES_U32 as u64;
const VFS_WRITEBACK_OP_MUNMAP: u8 = 1;
const VFS_WRITEBACK_OP_MSYNC: u8 = 2;
const VFS_WRITEBACK_OP_MMAP_FIXED_REPLACE: u8 = 3;

#[derive(Clone, Copy)]
pub(crate) struct MmapFixedReplaceCtx {
    kind: u64,
    hint: u64,
    unmap_base: u64,
    unmap_size: u64,
    size: u64,
    prot: u64,
    flags: u64,
    mo_offset: u64,
    image_reservation: Option<ReservationId>,
    image_kind: Option<ImageKind>,
    file_backing_id: u64,
    file_backing_length: u64,
    stable_cap_slot: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum VfsWritebackContinuation {
    Munmap { vaddr: u64, size: u64 },
    Msync,
    MmapFixedReplace(MmapFixedReplaceCtx),
}

#[derive(Clone, Copy)]
pub(crate) struct PendingVfsWritebackGroup {
    pub token: u64,
    pub reply_target: MpReplyTarget,
    pub client_idx: u32,
    pub client_epoch: u64,
    pub continuation: VfsWritebackContinuation,
    pub remaining: u32,
    pub first_error: u64,
    pub started_tick: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct PendingVfsWritebackRequest {
    pub group_token: u64,
}

fn raw_received_cap_count(buf: *mut kernite_ipc_buffer) -> u64 {
    if buf.is_null() {
        return 0;
    }
    unsafe { trona_kernel::ipc_buffer::read_received_cap_count(buf as *const _) }
}

fn received_user_cap_count(buf: *mut kernite_ipc_buffer) -> u64 {
    raw_received_cap_count(buf)
}

fn delete_recv_user_caps(user_cap_count: u64) {
    let limit = core::cmp::min(user_cap_count, crate::caps::RECV_WINDOW_LEN);
    for idx in 0..limit {
        let _ = trona_kernel::syscall::invoke(
            KERNITE_CAP_SELF_CSPACE as u64,
            KERNITE_INV_CNODE_DELETE as u64,
            recv_user_slot(idx),
            0,
            0,
            0,
        );
    }
}

pub const MMAP_KIND_ANON: u64 = 0;
pub const MMAP_KIND_ANON_STACK: u64 = 1;
pub const MMAP_KIND_SHARED_ANON: u64 = 2;
pub const MMAP_KIND_DEVICE: u64 = 3;
/// Caller-supplied MO mapping. `caps[0] = mo_cap` (typically a
/// pager-attached MO returned by `VFS_GET_BACKING_MO`, or an SHM
/// MO from `MM_SHM_*`). `regs[5] = mo_offset` (page offset within
/// the MO). mmsrv `cnode_move`s the cap out of receive scratch into
/// a stable slot, invokes `KERNITE_INV_VSPACE_MAP_MO` against the
/// caller's vspace, and stores the cap on the `MappedRegion` so
/// `munmap` can revoke the mapping and release the cap copy.
pub const MMAP_KIND_MO: u64 = 4;

fn commit_mo_range(mo_cap: u64, offset_pages: u64, page_count: u64) -> Result<(), u64> {
    if page_count == 0 {
        return Ok(());
    }
    let commit_err = unsafe { crate::kernel_vm::commit_mo_pages(mo_cap, offset_pages, page_count) };
    if commit_err != 0 {
        return Err(commit_err as u64);
    }
    Ok(())
}

fn send_reply(buf: *mut kernite_ipc_buffer, label: u64, regs: &[u64], cap_count: u64) -> u64 {
    if buf.is_null() {
        return KERNITE_ERR_INVALID_ARGUMENT as u64;
    }
    let raw_caps = raw_received_cap_count(buf);
    let err = unsafe {
        trona_server::mp_write_reply_to(
            buf,
            crate::dispatch::current_reply_target(),
            label,
            regs,
            cap_count,
        )
    };
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] mp_write_reply failed label=");
            _lb.hex(label);
            _lb.str(b" err=");
            _lb.dec(err as u64);
            _lb.str(b" caps=");
            _lb.dec(cap_count);
            _lb.str(b" recv_caps=");
            _lb.dec(raw_caps);
            _lb.str(b" recv_base=");
            _lb.hex(crate::caps::main_recv_base_slot());
            _lb.putc(b'\n');
        });
    }
    err as u64
}

fn send_reply_to_target(
    buf: *mut kernite_ipc_buffer,
    target: MpReplyTarget,
    label: u64,
    regs: &[u64],
) -> u64 {
    if buf.is_null() {
        return KERNITE_ERR_INVALID_ARGUMENT as u64;
    }
    let err = unsafe { trona_server::mp_write_reply_to(buf, target, label, regs, 0) };
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] deferred reply failed label=");
            _lb.hex(label);
            _lb.str(b" err=");
            _lb.dec(err as u64);
            _lb.putc(b'\n');
        });
    }
    err as u64
}

fn copy_cap_for_reply(src_slot: u64, label: &'static [u8]) -> Result<u64, u64> {
    let Some(temp) = trona_runtime::core::slot_alloc::alloc_slot() else {
        let _ = label;
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    let err = crate::kernel_vm::cnode_copy_ref(
        KERNITE_CAP_SELF_CSPACE as u64,
        trona_runtime::core::slot_alloc::resolved_cap_ref(src_slot),
        KERNITE_CAP_SELF_CSPACE as u64,
        trona_runtime::core::slot_alloc::resolved_cap_ref(temp.addr()),
        // Client-facing MO caps never carry EXECUTE (see dispatch.rs).
        (KERNITE_RIGHT_ALL & !KERNITE_RIGHT_EXECUTE) as u64,
    );
    if err != 0 {
        // copy failed: `temp` (OwnedSlot) Drop frees the empty slot.
        return Err(err as u64);
    }
    Ok(temp.into_raw())
}

/// # Safety
/// `slot` is a transient cap slot the caller solely owns; torn down and its
/// index freed once here.
unsafe fn delete_and_free_temp_cap(slot: u64) {
    // SAFETY: exclusive ownership of `slot` per this fn's `# Safety`.
    unsafe { trona_runtime::core::slot_alloc::delete_and_free(slot) };
}

fn send_reply_with_cap_copy(
    buf: *mut kernite_ipc_buffer,
    src_slot: u64,
    label: u64,
    regs: &[u64],
    copy_label: &'static [u8],
) -> bool {
    let temp = match copy_cap_for_reply(src_slot, copy_label) {
        Ok(slot) => slot,
        Err(err) => {
            send_reply(buf, err, &[], 0);
            return false;
        }
    };
    unsafe {
        (*buf).caps[0] = temp;
    }
    let result = unsafe {
        trona_server::mp_write_reply_to_with_error_fallback(
            buf,
            crate::dispatch::current_reply_target(),
            label,
            regs,
            1,
        )
    };
    let err = result.primary_error as u64;
    if err != 0 {
        // SAFETY: the reply failed so `temp` (from copy_cap_for_reply) still
        // holds its cap and is solely owned here; tear down + free once.
        unsafe { delete_and_free_temp_cap(temp) };
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] cap reply primary failed label=");
            _lb.hex(label);
            _lb.str(b" primary=");
            _lb.dec(err);
            _lb.str(b" fallback=");
            _lb.dec(result.fallback_error as u64);
            _lb.putc(b'\n');
        });
        let _ = result.fallback_error;
        false
    } else {
        // The reply transfer moved the cap out of `temp`, leaving it empty.
        // SAFETY: `temp` came from copy_cap_for_reply and the successful reply
        // moved its cap out, so the slot is empty and is reclaimed once here.
        unsafe {
            trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(temp);
        }
        true
    }
}

/// Auto-placement: find a free `size`-byte VA gap in the client's mmap
/// window, preferring `hint` (or the client's running `mmap_hint` when
/// `hint` is 0). Routes through the reservation-aware allocator so
/// region *and* reservation occupancy are both honoured.
///
/// # Safety
/// Single-threaded server invariant.
unsafe fn place_va(vm: &ClientVm, client: &ClientState, hint: u64, size: u64) -> Option<u64> {
    let place_hint = if hint != 0 { hint } else { client.mmap_hint };
    unsafe {
        va_alloc::find_free_va_gap(
            vm,
            size,
            KERNITE_PAGE_BYTES,
            place_hint,
            client.layout.mmap_base..client.layout.mmap_limit,
            None,
        )
    }
}

/// Whether `[base, base + size)` is free of existing mappings — the
/// fixed-placement overlap check.
///
/// # Safety
/// Single-threaded server invariant.
unsafe fn range_is_free(
    vm: &ClientVm,
    base: u64,
    size: u64,
    except_reservation: Option<ReservationId>,
) -> bool {
    unsafe {
        va_alloc::range_overlaps_mapping(vm, base, size).is_none()
            && va_alloc::range_overlaps_reservation(vm, base, size, except_reservation).is_none()
    }
}

/// Validate an optional `regs[6]` image-reservation id for a fixed image-run
/// placement. `0` → `Ok(None)` (no image grouping). A non-zero value must name
/// an existing `Image`-purpose reservation owned by the caller that fully
/// contains `[va, va + size)`, and the mapping must be `MM_FLAG_FIXED` (image
/// runs are always placed at the producer's chosen VAs). Returns the validated
/// id, or a wire error code.
///
/// # Safety
/// Single-threaded server invariant.
unsafe fn resolve_image_reservation(
    vm: &ClientVm,
    client: &ClientState,
    image_id_raw: u64,
    va: u64,
    size: u64,
    is_fixed: bool,
) -> core::result::Result<Option<ReservationId>, u64> {
    if image_id_raw == 0 {
        return Ok(None);
    }
    if !is_fixed {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
    }
    let id = ReservationId::unpack(image_id_raw);
    let Some(r) = (unsafe { vm.reservation(id) }) else {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
    };
    if r.purpose != ReservationPurpose::Image || r.owner_badge != client.client_id as u64 {
        return Err(KERNITE_ERR_INSUFFICIENT_RIGHTS as u64);
    }
    let Some(end) = va.checked_add(size) else {
        return Err(KERNITE_ERR_OUT_OF_RANGE as u64);
    };
    if va < r.base || end > r.end() {
        return Err(KERNITE_ERR_OUT_OF_RANGE as u64);
    }
    Ok(Some(id))
}

fn image_kind_from_wire(raw: u64) -> core::result::Result<Option<ImageKind>, u64> {
    match raw {
        STAGE_IMAGE_KIND_NONE => Ok(None),
        STAGE_IMAGE_KIND_TEXT => Ok(Some(ImageKind::Text)),
        STAGE_IMAGE_KIND_DATA => Ok(Some(ImageKind::Data)),
        STAGE_IMAGE_KIND_RODATA => Ok(Some(ImageKind::RoData)),
        STAGE_IMAGE_KIND_BSS => Ok(Some(ImageKind::Bss)),
        _ => Err(KERNITE_ERR_INVALID_ARGUMENT as u64),
    }
}

fn image_region_type(kind: ImageKind) -> u8 {
    match kind {
        ImageKind::Text => REGION_IMAGE_TEXT,
        ImageKind::Data => REGION_IMAGE_DATA,
        ImageKind::RoData => REGION_SHARED_LIB,
        ImageKind::Bss => REGION_IMAGE_BSS,
    }
}

fn image_fork_policy(kind: ImageKind) -> ForkPolicy {
    match kind {
        ImageKind::Text | ImageKind::RoData => ForkPolicy::InheritShare,
        ImageKind::Data | ImageKind::Bss => ForkPolicy::InheritCow,
    }
}

/// Validate the paired runtime-image `MM_MMAP` fields:
/// `regs[6]` names the image reservation and `regs[7]` names the run kind.
///
/// # Safety
/// Single-threaded server invariant.
unsafe fn resolve_mmap_image(
    vm: &ClientVm,
    client: &ClientState,
    image_id_raw: u64,
    image_kind_raw: u64,
    va: u64,
    size: u64,
    is_fixed: bool,
) -> core::result::Result<(Option<ReservationId>, Option<ImageKind>), u64> {
    let image_res = unsafe {
        // SAFETY: caller upholds the mmsrv single-threaded server invariant.
        resolve_image_reservation(vm, client, image_id_raw, va, size, is_fixed)?
    };
    let image_kind = image_kind_from_wire(image_kind_raw)?;
    match (image_res, image_kind) {
        (Some(_), Some(_)) | (None, None) => Ok((image_res, image_kind)),
        _ => Err(KERNITE_ERR_INVALID_ARGUMENT as u64),
    }
}

#[derive(Clone, Copy)]
enum CapSlotCleanup {
    Receive,
    Allocated,
}

fn cleanup_cap_slot(slot: u64, cleanup: CapSlotCleanup) {
    match cleanup {
        CapSlotCleanup::Receive => delete_recv_cap(slot),
        CapSlotCleanup::Allocated => {
            // SAFETY: `slot` is a solely-owned allocator slot moved out of
            // receive scratch for a parked operation.
            unsafe { delete_and_free_temp_cap(slot) };
        }
    }
}

fn delete_preserved_cap(slot: u64) {
    if slot == 0 {
        return;
    }
    // SAFETY: preserved continuation caps are raw allocator slots owned by the
    // parked operation until an install helper consumes them.
    unsafe { delete_and_free_temp_cap(slot) };
}

fn move_recv_cap_to_stable(recv_slot: u64) -> Result<u64, u64> {
    let Some(stable_mo_slot) = trona_runtime::core::slot_alloc::alloc_slot() else {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    let mv = trona_kernel::syscall::invoke(
        KERNITE_CAP_SELF_CSPACE as u64,
        KERNITE_INV_CNODE_MOVE as u64,
        stable_mo_slot.addr(),
        KERNITE_CAP_SELF_CSPACE as u64,
        recv_slot,
        0,
    );
    if mv.error != 0 {
        return Err(mv.error);
    }
    Ok(stable_mo_slot.into_raw())
}

#[allow(clippy::too_many_arguments)]
fn install_anon(
    client: &mut ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
    kind: u64,
    va_base: u64,
    size: u64,
    prot: u64,
    flags: u64,
    image_res: Option<ReservationId>,
    image_kind: Option<ImageKind>,
) -> Result<RegionId, u64> {
    let grow_down = flags & FLAG_GROWSDOWN != 0;
    let is_stack = kind == MMAP_KIND_ANON_STACK || grow_down;
    let lazy = flags & FLAG_LAZY != 0 || is_stack;
    let region_type = image_kind.map(image_region_type).unwrap_or(if is_stack {
        REGION_STACK
    } else {
        REGION_MMAP
    });

    let Some(mo_idx) = mo_registry.alloc_slot() else {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    let kind_for_registry = match kind {
        MMAP_KIND_SHARED_ANON => MoKind::Shm { name_hash: 0 },
        _ => MoKind::Anon,
    };
    let Some(mo_cap) =
        mo_registry.install(mo_idx, size, client.client_id, kind_for_registry, frames)
    else {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };

    let guard_reservation_id = if is_stack {
        match unsafe {
            txn::reserve_stack_guard(
                vm,
                va_base,
                STACK_GUARD_BYTES,
                client.client_id as u64,
                self_vm,
            )
        } {
            Some(g) => Some(g),
            None => {
                mo_registry.vacate(mo_idx, frames);
                return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
            }
        }
    } else {
        None
    };

    let pages = size / KERNITE_PAGE_BYTES;
    let plan = MappingPlan {
        va_base,
        pages,
        prot: prot as u8,
        region_type,
        fork_policy: image_kind.map(image_fork_policy).unwrap_or(
            if kind == MMAP_KIND_SHARED_ANON {
                ForkPolicy::InheritShare
            } else {
                ForkPolicy::InheritCow
            },
        ),
        lazy,
        mo_cap,
        mo_offset_pages: 0,
        eager_commit: !lazy,
        backing: if let Some(kind) = image_kind {
            BackingDescriptor::Image {
                mo_handle: MoHandle(mo_idx as u32),
                mo_offset: 0,
                image_kind: kind,
            }
        } else {
            BackingDescriptor::Anon {
                mo_handle: MoHandle(mo_idx as u32),
                mo_offset: 0,
            }
        },
        reservation: image_res,
        stack_allocator_badge: 0,
        guard_reservation_id,
    };
    match unsafe { plan.apply(vm, client.vspace_cap.as_raw(), self_vm) } {
        Ok(region_id) => {
            if let Some(guard_id) = guard_reservation_id {
                if let Some(g) = unsafe { vm.reservation_mut(guard_id) } {
                    g.stack_region_id = Some(region_id);
                }
            }
            if let Some(next) = va_base.checked_add(size) {
                if next > client.mmap_hint {
                    client.mmap_hint = next;
                }
            }
            Ok(region_id)
        }
        Err(code) => {
            if let Some(guard_id) = guard_reservation_id {
                unsafe { vm.vacate_reservation(guard_id) };
            }
            mo_registry.vacate(mo_idx, frames);
            Err(code)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn install_mo_shared_from_stable(
    stable_mo_slot: u64,
    client: &mut ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    va_base: u64,
    size: u64,
    prot: u64,
    mo_offset: u64,
    image_res: Option<ReservationId>,
    image_kind: Option<ImageKind>,
    file_backing_id: u64,
    file_backing_length: u64,
) -> Result<RegionId, u64> {
    let pages = size / KERNITE_PAGE_BYTES;
    let mo_offset_pages = mo_offset / KERNITE_PAGE_BYTES;
    let region_type = image_kind.map(image_region_type).unwrap_or(REGION_MMAP);
    let plan = MappingPlan {
        va_base,
        pages,
        prot: prot as u8,
        region_type,
        lazy: false,
        mo_cap: stable_mo_slot,
        mo_offset_pages,
        eager_commit: false,
        fork_policy: image_kind
            .map(image_fork_policy)
            .unwrap_or(ForkPolicy::InheritShare),
        backing: BackingDescriptor::FileBacked {
            // SAFETY: `stable_mo_slot` holds the caller's moved-in MO cap and
            // this backing becomes its sole persistent owner.
            mo_cap: unsafe { OwnedCap::adopt_received(stable_mo_slot) },
            mo_offset: mo_offset_pages as u32,
            file_id0: file_backing_id,
            file_id1: 0,
            file_offset: 0,
            file_size: file_backing_length,
            backing_kind: 0,
            writeback: file_backing_id != 0,
        },
        reservation: image_res,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    let region_id = unsafe { plan.apply(vm, client.vspace_cap.as_raw(), self_vm) }?;
    if let Some(next) = va_base.checked_add(size) {
        if next > client.mmap_hint {
            client.mmap_hint = next;
        }
    }
    Ok(region_id)
}

pub fn handle_mmap(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client_idx: u32,
    state: &mut ServerState,
) {
    let kind = regs[0];
    let hint = regs[1];
    let size = regs[2];
    let prot = regs[3];
    let flags = regs[4];

    if size == 0 || size % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    if kind == MMAP_KIND_DEVICE {
        handle_mmap_device(buf, regs, client_idx, state);
        return;
    }
    if kind == MMAP_KIND_MO || kind == MMAP_KIND_SHM_MO {
        handle_mmap_mo(buf, regs, client_idx, state);
        return;
    }
    if !matches!(
        kind,
        MMAP_KIND_ANON | MMAP_KIND_ANON_STACK | MMAP_KIND_SHARED_ANON
    ) {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    let is_stack = kind == MMAP_KIND_ANON_STACK || flags & FLAG_GROWSDOWN != 0;
    let placement_size = if is_stack {
        match size.checked_add(STACK_GUARD_BYTES) {
            Some(s) => s,
            None => {
                send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
                return;
            }
        }
    } else {
        size
    };

    if flags & FLAG_FIXED != 0 {
        if hint % KERNITE_PAGE_BYTES != 0 {
            send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
            return;
        }
        let Some(span_base) = (if is_stack {
            hint.checked_sub(STACK_GUARD_BYTES)
        } else {
            Some(hint)
        }) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        };
        let Some(end) = hint.checked_add(size) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        };
        let idx = client_idx as usize;
        let (image_res, image_kind) = {
            let Some((client, vm)) = state.clients.entry_and_vm_mut(idx) else {
                send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                return;
            };
            let resolved = unsafe {
                resolve_mmap_image(
                    vm,
                    client,
                    regs[MM_MMAP_REQ_REG_IMAGE_ID],
                    regs[MM_MMAP_REQ_REG_IMAGE_KIND],
                    hint,
                    size,
                    true,
                )
            };
            let (image_res, image_kind) = match resolved {
                Ok(r) => r,
                Err(code) => {
                    send_reply(buf, code, &[], 0);
                    return;
                }
            };
            if image_kind.is_some() && (is_stack || kind == MMAP_KIND_SHARED_ANON) {
                send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
                return;
            }
            if matches!(image_kind, Some(ImageKind::Text | ImageKind::Data)) {
                send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
                return;
            }
            if image_res.is_none()
                && (hint < client.layout.mmap_base || end > client.layout.mmap_limit)
            {
                send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
                return;
            }
            if flags & FLAG_FIXED_NOREPLACE != 0
                && !unsafe { range_is_free(vm, span_base, placement_size, image_res) }
            {
                send_reply(buf, KERNITE_ERR_ALREADY_MAPPED as u64, &[], 0);
                return;
            }
            (image_res, image_kind)
        };

        if flags & FLAG_FIXED_NOREPLACE != 0 {
            let clients = &mut state.clients;
            let self_vm = &mut state.self_vm;
            let mo_registry = &mut state.mo_registry;
            let frames = &mut state.frames;
            let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
                send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                return;
            };
            match install_anon(
                client,
                vm,
                self_vm,
                mo_registry,
                frames,
                kind,
                hint,
                size,
                prot,
                flags,
                image_res,
                image_kind,
            ) {
                Ok(region_id) => send_reply(
                    buf,
                    TRONA_OK,
                    &[hint, region_id.idx() as u64, region_id.epoch() as u64],
                    0,
                ),
                Err(code) => send_reply(buf, code, &[], 0),
            };
            return;
        }

        let ctx = MmapFixedReplaceCtx {
            kind,
            hint,
            unmap_base: span_base,
            unmap_size: placement_size,
            size,
            prot,
            flags,
            mo_offset: 0,
            image_reservation: image_res,
            image_kind,
            file_backing_id: 0,
            file_backing_length: 0,
            stable_cap_slot: 0,
        };
        match park_vfs_writeback_group(
            buf,
            state,
            client_idx,
            span_base,
            placement_size,
            MS_SYNC as u64,
            VFS_WRITEBACK_OP_MMAP_FIXED_REPLACE,
            VfsWritebackContinuation::MmapFixedReplace(ctx),
        ) {
            Ok(true) => {}
            Ok(false) => {
                let clients = &mut state.clients;
                let self_vm = &mut state.self_vm;
                let mo_registry = &mut state.mo_registry;
                let frames = &mut state.frames;
                let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
                    send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                    return;
                };
                let pages = placement_size / KERNITE_PAGE_BYTES;
                if let Err(code) = unsafe {
                    txn::force_unmap_range(
                        vm,
                        span_base,
                        pages,
                        client.vspace_cap.as_raw(),
                        self_vm,
                        mo_registry,
                        frames,
                    )
                } {
                    send_reply(buf, code, &[], 0);
                    return;
                }
                match install_anon(
                    client,
                    vm,
                    self_vm,
                    mo_registry,
                    frames,
                    kind,
                    hint,
                    size,
                    prot,
                    flags,
                    image_res,
                    image_kind,
                ) {
                    Ok(region_id) => send_reply(
                        buf,
                        TRONA_OK,
                        &[hint, region_id.idx() as u64, region_id.epoch() as u64],
                        0,
                    ),
                    Err(code) => send_reply(buf, code, &[], 0),
                };
            }
            Err(code) => {
                send_reply(buf, code, &[], 0);
            }
        };
        return;
    }

    let idx = client_idx as usize;
    let clients = &mut state.clients;
    let self_vm = &mut state.self_vm;
    let mo_registry = &mut state.mo_registry;
    let frames = &mut state.frames;
    let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let (image_res, image_kind) = match unsafe {
        resolve_mmap_image(
            vm,
            client,
            regs[MM_MMAP_REQ_REG_IMAGE_ID],
            regs[MM_MMAP_REQ_REG_IMAGE_KIND],
            hint,
            size,
            false,
        )
    } {
        Ok(r) => r,
        Err(code) => {
            send_reply(buf, code, &[], 0);
            return;
        }
    };
    if image_kind.is_some() && (is_stack || kind == MMAP_KIND_SHARED_ANON) {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    if matches!(image_kind, Some(ImageKind::Text | ImageKind::Data)) {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let va_base = match unsafe { place_va(vm, client, hint, placement_size) } {
        Some(span_base) if is_stack => span_base + STACK_GUARD_BYTES,
        Some(span_base) => span_base,
        None => {
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        }
    };
    match install_anon(
        client,
        vm,
        self_vm,
        mo_registry,
        frames,
        kind,
        va_base,
        size,
        prot,
        flags,
        image_res,
        image_kind,
    ) {
        Ok(region_id) => send_reply(
            buf,
            TRONA_OK,
            &[va_base, region_id.idx() as u64, region_id.epoch() as u64],
            0,
        ),
        Err(code) => send_reply(buf, code, &[], 0),
    };
}

/// `MM_MMAP(kind=MMAP_KIND_MO | MMAP_KIND_SHM_MO, ...)` — caller-supplied MO
/// mapping. A shared mapping (no `MM_FLAG_PRIVATE`) lands the MO cap (deposited
/// in `recv_user_slot(0)` by the inbound IPC) into a stable cspace slot via
/// `cnode_move`, invokes `KERNITE_INV_VSPACE_MAP_MO` against the caller's
/// vspace, and stamps a `BackingDescriptor::FileBacked` region; the cap copy is
/// retained on the region so `handle_munmap` can revoke it. A private mapping
/// (`MM_FLAG_PRIVATE`) maps a copy-on-write child instead of the shared object.
#[allow(clippy::too_many_arguments)]
fn handle_mmap_mo(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client_idx: u32,
    state: &mut ServerState,
) {
    let kind = regs[0];
    let hint = regs[1];
    let size = regs[2];
    let prot = regs[3];
    let flags = regs[4];
    let mo_offset = regs[5];
    let recv_slot = recv_user_slot(0);

    if size == 0 || size % KERNITE_PAGE_BYTES != 0 || mo_offset % KERNITE_PAGE_BYTES != 0 {
        reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_INVALID_ARGUMENT as u64);
        return;
    }
    if recv_slot == 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    let idx = client_idx as usize;
    let fixed = flags & FLAG_FIXED != 0;
    let (va_base, image_res, image_kind) = if fixed {
        if hint % KERNITE_PAGE_BYTES != 0 {
            reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_INVALID_ARGUMENT as u64);
            return;
        }
        let Some(end) = hint.checked_add(size) else {
            reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_OUT_OF_RANGE as u64);
            return;
        };
        let (image_res, image_kind) = {
            let Some((client, vm)) = state.clients.entry_and_vm_mut(idx) else {
                reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_NOT_FOUND as u64);
                return;
            };
            let resolved = unsafe {
                resolve_mmap_image(
                    vm,
                    client,
                    regs[MM_MMAP_REQ_REG_IMAGE_ID],
                    regs[MM_MMAP_REQ_REG_IMAGE_KIND],
                    hint,
                    size,
                    true,
                )
            };
            let (image_res, image_kind) = match resolved {
                Ok(r) => r,
                Err(code) => {
                    reject_mmap_mo_recv(buf, recv_slot, code);
                    return;
                }
            };
            if image_res.is_none()
                && (hint < client.layout.mmap_base || end > client.layout.mmap_limit)
            {
                reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_OUT_OF_RANGE as u64);
                return;
            }
            if flags & FLAG_FIXED_NOREPLACE != 0
                && !unsafe { range_is_free(vm, hint, size, image_res) }
            {
                reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_ALREADY_MAPPED as u64);
                return;
            }
            (image_res, image_kind)
        };
        (hint, image_res, image_kind)
    } else {
        let Some((client, vm)) = state.clients.entry_and_vm_mut(idx) else {
            reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_NOT_FOUND as u64);
            return;
        };
        let (image_res, image_kind) = match unsafe {
            resolve_mmap_image(
                vm,
                client,
                regs[MM_MMAP_REQ_REG_IMAGE_ID],
                regs[MM_MMAP_REQ_REG_IMAGE_KIND],
                hint,
                size,
                false,
            )
        } {
            Ok(r) => r,
            Err(code) => {
                reject_mmap_mo_recv(buf, recv_slot, code);
                return;
            }
        };
        let va = match unsafe { place_va(vm, client, hint, size) } {
            Some(va) => va,
            None => {
                reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_OUT_OF_RANGE as u64);
                return;
            }
        };
        (va, image_res, image_kind)
    };

    if image_kind.is_some() && kind == MMAP_KIND_SHM_MO {
        reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_INVALID_ARGUMENT as u64);
        return;
    }
    if flags & FLAG_PRIVATE != 0 {
        if matches!(image_kind, Some(ImageKind::Text | ImageKind::Bss)) {
            reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_INVALID_ARGUMENT as u64);
            return;
        }
    } else if matches!(image_kind, Some(ImageKind::Data | ImageKind::Bss)) {
        reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_INVALID_ARGUMENT as u64);
        return;
    }

    let file_backing_id = if kind == MMAP_KIND_MO {
        regs[MM_MMAP_REQ_REG_FILE_BACKING_ID]
    } else {
        0
    };
    let file_backing_length = if kind == MMAP_KIND_MO {
        regs[MM_MMAP_REQ_REG_FILE_BACKING_LENGTH]
    } else {
        0
    };

    if fixed && flags & FLAG_FIXED_NOREPLACE == 0 {
        let stable_mo_slot = match move_recv_cap_to_stable(recv_slot) {
            Ok(slot) => slot,
            Err(code) => {
                reject_mmap_mo_recv(buf, recv_slot, code);
                return;
            }
        };
        let ctx = MmapFixedReplaceCtx {
            kind,
            hint: va_base,
            unmap_base: va_base,
            unmap_size: size,
            size,
            prot,
            flags,
            mo_offset,
            image_reservation: image_res,
            image_kind,
            file_backing_id,
            file_backing_length,
            stable_cap_slot: stable_mo_slot,
        };
        match park_vfs_writeback_group(
            buf,
            state,
            client_idx,
            va_base,
            size,
            MS_SYNC as u64,
            VFS_WRITEBACK_OP_MMAP_FIXED_REPLACE,
            VfsWritebackContinuation::MmapFixedReplace(ctx),
        ) {
            Ok(true) => {}
            Ok(false) => {
                let clients = &mut state.clients;
                let self_vm = &mut state.self_vm;
                let mo_registry = &mut state.mo_registry;
                let frames = &mut state.frames;
                let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
                    delete_preserved_cap(stable_mo_slot);
                    send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                    return;
                };
                let pages = size / KERNITE_PAGE_BYTES;
                if let Err(code) = unsafe {
                    txn::force_unmap_range(
                        vm,
                        va_base,
                        pages,
                        client.vspace_cap.as_raw(),
                        self_vm,
                        mo_registry,
                        frames,
                    )
                } {
                    delete_preserved_cap(stable_mo_slot);
                    send_reply(buf, code, &[], 0);
                    return;
                }
                let result = if flags & FLAG_PRIVATE != 0 {
                    install_mo_private_from_source(
                        stable_mo_slot,
                        CapSlotCleanup::Allocated,
                        kind,
                        va_base,
                        size,
                        prot,
                        mo_offset,
                        image_res,
                        image_kind,
                        client,
                        vm,
                        self_vm,
                        mo_registry,
                        frames,
                    )
                } else {
                    install_mo_shared_from_stable(
                        stable_mo_slot,
                        client,
                        vm,
                        self_vm,
                        va_base,
                        size,
                        prot,
                        mo_offset,
                        image_res,
                        image_kind,
                        file_backing_id,
                        file_backing_length,
                    )
                };
                match result {
                    Ok(region_id) => send_reply(
                        buf,
                        TRONA_OK,
                        &[va_base, region_id.idx() as u64, region_id.epoch() as u64],
                        0,
                    ),
                    Err(code) => send_reply(buf, code, &[], 0),
                };
            }
            Err(code) => {
                delete_preserved_cap(stable_mo_slot);
                send_reply(buf, code, &[], 0);
            }
        };
        return;
    }

    let clients = &mut state.clients;
    let self_vm = &mut state.self_vm;
    let mo_registry = &mut state.mo_registry;
    let frames = &mut state.frames;
    let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
        reject_mmap_mo_recv(buf, recv_slot, KERNITE_ERR_NOT_FOUND as u64);
        return;
    };

    // A private (MAP_PRIVATE) mapping does not map the shared object: it maps
    // a copy-on-write child seeded from it (shm freezes via MO_SNAPSHOT, file
    // clones via MO_CLONE).
    if flags & FLAG_PRIVATE != 0 {
        let result = install_mo_private_from_source(
            recv_slot,
            CapSlotCleanup::Receive,
            kind,
            va_base,
            size,
            prot,
            mo_offset,
            image_res,
            image_kind,
            client,
            vm,
            self_vm,
            mo_registry,
            frames,
        );
        match result {
            Ok(region_id) => send_reply(
                buf,
                TRONA_OK,
                &[va_base, region_id.idx() as u64, region_id.epoch() as u64],
                0,
            ),
            Err(code) => send_reply(buf, code, &[], 0),
        };
        return;
    }

    // Move the caller's MO cap out of receive scratch into a stable slot
    // the published region will own. CNODE_MOVE preserves the cap's rights:
    // a JIT client's exec-bearing MO (one it conferred R-X on itself via
    // mo_mark_executable, holding its own exec-authority) stays executable and
    // maps R-X. mmsrv mints no executable cap and holds no JIT flag — the
    // kernel's cap-derived ceiling refuses PROT_EXEC for any non-exec cap, so a
    // process without exec-authority can never get executable memory this way.
    // (Do not attenuate EXECUTE here; only caps mmsrv *returns* are stripped.)
    let stable_mo_slot = match move_recv_cap_to_stable(recv_slot) {
        Ok(slot) => slot,
        Err(code) => {
            reject_mmap_mo_recv(buf, recv_slot, code);
            return;
        }
    };
    match install_mo_shared_from_stable(
        stable_mo_slot,
        client,
        vm,
        self_vm,
        va_base,
        size,
        prot,
        mo_offset,
        image_res,
        image_kind,
        file_backing_id,
        file_backing_length,
    ) {
        Ok(region_id) => send_reply(
            buf,
            TRONA_OK,
            &[va_base, region_id.idx() as u64, region_id.epoch() as u64],
            0,
        ),
        Err(code) => send_reply(buf, code, &[], 0),
    };
}

/// Delete a cap sitting in mmsrv's receive scratch — either the transient source
/// MO copy a private mapping uses only to seed its COW child, or an inbound MO
/// cap rejected before the shared-mapping path can move it into a stable slot.
fn delete_recv_cap(slot: u64) {
    if slot == 0 {
        return;
    }
    let _ = trona_kernel::syscall::invoke(
        KERNITE_CAP_SELF_CSPACE as u64,
        KERNITE_INV_CNODE_DELETE as u64,
        slot,
        0,
        0,
        0,
    );
}

fn reject_mmap_mo_recv(buf: *mut kernite_ipc_buffer, recv_slot: u64, code: u64) {
    delete_recv_cap(recv_slot);
    send_reply(buf, code, &[], 0);
}

/// Provision the per-tree `VmHierarchyState` `S` the kernel requires to create a
/// COW tree (the standalone-source snapshot / clone / fork). Retypes
/// `OBJ_VM_HIERARCHY_STATE` out of mmsrv's own untyped pool — mirroring
/// `watch_pool::alloc_watch_into` — into a fresh allocator slot. The returned
/// [`OwnedCap`] deletes the cap (and frees the slot) on drop: after the bind
/// call the kernel holds its own per-MO refs on `S`, so dropping mmsrv's cap
/// leaves `S` alive for the tree on success and reaps it on failure.
pub(crate) fn alloc_vm_hierarchy_state(frames: &mut FrameAllocator) -> Option<OwnedCap> {
    let s_slot = trona_runtime::core::slot_alloc::alloc_slot()?;
    let chunk_count = frames.chunk_count();
    for idx in 0..chunk_count {
        let Some(chunk_cap) = frames.chunk_cap(idx) else {
            continue;
        };
        let r = trona_kernel::syscall::invoke(
            chunk_cap,
            KERNITE_INV_UNTYPED_RETYPE as u64,
            KERNITE_OBJ_VM_HIERARCHY_STATE as u64,
            0,
            s_slot.addr(),
            0,
        );
        if r.error == 0 {
            frames.note_typed_child(idx);
            return Some(s_slot.assume_filled());
        }
    }
    None
}

/// `MM_MMAP(kind=MMAP_KIND_MO | MMAP_KIND_SHM_MO, MM_FLAG_PRIVATE, ...)` —
/// private (copy-on-write) mapping of a caller-supplied MO.
///
/// Instead of mapping the shared object, mmsrv maps a fresh COW child `C`
/// seeded from it so the caller's writes stay private:
///
/// * `MMAP_KIND_SHM_MO` → strict snapshot. mmsrv retypes a hidden parent `H`
///   and child `C`, then `MO_SNAPSHOT` freezes the shm's committed pages into
///   `H` and reparents both the shm and `C` as COW children of `H`. `C` reads
///   the frozen pages and breaks privately on write; concurrent shared writers
///   break against `H` and reconverge. mmsrv drops its `H` cap immediately —
///   the kernel keeps `H` alive through the cow_parent refs until both children
///   are gone.
/// * `MMAP_KIND_MO` → lazy clone. mmsrv retypes `C` and `MO_CLONE`s it onto the
///   (pager-backed file) source; `C` resolves uncommitted pages through the
///   source's pager and breaks privately on write.
///
/// `C` is registry-owned. Ordinary private mappings publish it as `Anon`; image
/// private runs publish it as `Image` so region type, max-prot, and fork policy
/// match the rest of the image pipeline. The source cap is a transient copy
/// dropped once the COW link is established.
#[allow(clippy::too_many_arguments)]
fn install_mo_private_from_source(
    source_slot: u64,
    source_cleanup: CapSlotCleanup,
    kind: u64,
    va_base: u64,
    size: u64,
    prot: u64,
    mo_offset: u64,
    image_reservation: Option<ReservationId>,
    image_kind: Option<ImageKind>,
    client: &mut ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) -> Result<RegionId, u64> {
    let pages = size / KERNITE_PAGE_BYTES;
    let mo_offset_pages = mo_offset / KERNITE_PAGE_BYTES;

    // The COW child is a full-length view of the source, and the mapped
    // sub-range must lie within it. `MO_GET_SIZE` both sizes `C` / `H` and
    // validates the caller's MO cap.
    let sz = trona_kernel::syscall::invoke(source_slot, KERNITE_INV_MO_GET_SIZE as u64, 0, 0, 0, 0);
    if sz.error != 0 {
        cleanup_cap_slot(source_slot, source_cleanup);
        return Err(sz.error);
    }
    let source_pages = sz.value;
    let within = mo_offset_pages
        .checked_add(pages)
        .is_some_and(|end| end <= source_pages);
    if !within {
        cleanup_cap_slot(source_slot, source_cleanup);
        return Err(KERNITE_ERR_OUT_OF_RANGE as u64);
    }
    let full_size = source_pages * KERNITE_PAGE_BYTES;

    // Retype the private child `C`. The install size is the mapped sub-range
    // only: the kernel resets `child.page_count` to `child_page_count` on
    // `MO_CLONE_RANGE` / `MO_SNAPSHOT` (mo.rs:656), and the untyped-chunk
    // reservation is sized off `install.size_bytes`, so this keeps the
    // reservation tight. The SHM branch installs H at `full_size` below
    // because H is the frozen parent covering the whole source.
    let child_install_size = if kind == MMAP_KIND_SHM_MO {
        full_size
    } else {
        pages * KERNITE_PAGE_BYTES
    };
    let Some(c_idx) = mo_registry.alloc_slot() else {
        cleanup_cap_slot(source_slot, source_cleanup);
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    let Some(c_cap) = mo_registry.install(
        c_idx,
        child_install_size,
        client.client_id,
        MoKind::Anon,
        frames,
    ) else {
        cleanup_cap_slot(source_slot, source_cleanup);
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };

    if kind == MMAP_KIND_SHM_MO {
        // Strict snapshot also needs a hidden parent `H`.
        let Some(h_idx) = mo_registry.alloc_slot() else {
            mo_registry.vacate(c_idx, frames);
            cleanup_cap_slot(source_slot, source_cleanup);
            return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
        };
        let Some(h_cap) =
            mo_registry.install(h_idx, full_size, client.client_id, MoKind::Anon, frames)
        else {
            mo_registry.vacate(c_idx, frames);
            cleanup_cap_slot(source_slot, source_cleanup);
            return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
        };
        // The kernel now requires the per-tree state `S` to create the COW
        // tree; provision and pass it. (A chained snapshot of an already-bound
        // source ignores it; mmsrv's drop below reaps it either way.)
        let Some(s_cap) = alloc_vm_hierarchy_state(frames) else {
            mo_registry.vacate(h_idx, frames);
            mo_registry.vacate(c_idx, frames);
            cleanup_cap_slot(source_slot, source_cleanup);
            return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
        };
        let snap = trona_kernel::syscall::invoke(
            source_slot,
            KERNITE_INV_MO_SNAPSHOT as u64,
            h_cap,
            c_cap,
            s_cap.as_raw(),
            0,
        );
        // Drop mmsrv's S cap: on success the kernel holds per-MO refs that keep
        // S alive for the tree; on failure / chained-adopt this reaps it.
        drop(s_cap);
        // The snapshot adopts H / C as kernel COW objects. Either way mmsrv
        // stops tracking H: on success it survives through the source's and
        // C's cow_parent refs (vacate's `UNTYPED_RESET` no-ops under
        // HasChildren, leaving the chunk dirty); on failure vacate reclaims the
        // still-pristine H.
        mo_registry.vacate(h_idx, frames);
        if snap.error != 0 {
            mo_registry.vacate(c_idx, frames);
            cleanup_cap_slot(source_slot, source_cleanup);
            return Err(snap.error);
        }
    } else {
        // Lazy sub-range clone: `C` is a `MO_CLONE_RANGE` child covering only
        // the mapped sub-range of the (file) source, so its radix is sized to
        // the mapped extent, not the whole source. Pages fault in through the
        // source's pager and break privately on write. The kernel requires
        // the per-tree state `S` for a standalone source; a chained clone of
        // an already-bound source ignores `S` (reaped on drop).
        let Some(s_cap) = alloc_vm_hierarchy_state(frames) else {
            mo_registry.vacate(c_idx, frames);
            cleanup_cap_slot(source_slot, source_cleanup);
            return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
        };
        let clone = trona_kernel::syscall::invoke(
            source_slot,
            uapi::KERNITE_INV_MO_CLONE_RANGE as u64,
            c_cap,
            mo_offset_pages,
            pages,
            s_cap.as_raw(),
        );
        drop(s_cap);
        if clone.error != 0 {
            mo_registry.vacate(c_idx, frames);
            cleanup_cap_slot(source_slot, source_cleanup);
            return Err(clone.error);
        }
    }

    // The source cap only seeded the COW link; the kernel now holds `C`'s
    // cow_parent ref, so drop mmsrv's transient copy.
    cleanup_cap_slot(source_slot, source_cleanup);

    // Map `C` lazily — its pages fault in through the kernel COW chain (the
    // frozen hidden parent for shm, the pager-backed ancestor for file). Never
    // eager-commit: a committed `C` would own fresh zero pages instead of
    // reading the source's content through COW.
    let region_type = image_kind.map(image_region_type).unwrap_or(REGION_MMAP);
    let plan = MappingPlan {
        va_base,
        pages,
        prot: prot as u8,
        region_type,
        lazy: false,
        mo_cap: c_cap,
        mo_offset_pages: 0,
        eager_commit: false,
        fork_policy: image_kind
            .map(image_fork_policy)
            .unwrap_or(ForkPolicy::InheritCow),
        backing: if let Some(kind) = image_kind {
            BackingDescriptor::Image {
                mo_handle: MoHandle(c_idx as u32),
                mo_offset: 0,
                image_kind: kind,
            }
        } else {
            BackingDescriptor::Anon {
                mo_handle: MoHandle(c_idx as u32),
                mo_offset: 0,
            }
        },
        reservation: image_reservation,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    match unsafe { plan.apply(vm, client.vspace_cap.as_raw(), self_vm) } {
        Ok(region_id) => {
            if let Some(next) = va_base.checked_add(size) {
                if next > client.mmap_hint {
                    client.mmap_hint = next;
                }
            }
            Ok(region_id)
        }
        Err(code) => {
            mo_registry.vacate(c_idx, frames);
            Err(code)
        }
    }
}

/// `MM_MMAP(kind=MMAP_KIND_DEVICE, ...)` — caller-supplied device
/// untyped mapping. The incoming cap is consumed only for the map
/// operation; mmsrv does not retain it after `VSPACE_MAP_DEVICE_RANGE`
/// because unmap only needs the target vspace VA range.
#[allow(clippy::too_many_arguments)]
fn install_device_from_slot(
    cap_slot: u64,
    cap_cleanup: CapSlotCleanup,
    client: &mut ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    va_base: u64,
    size: u64,
    prot: u64,
    device_offset: u64,
) -> Result<RegionId, u64> {
    if !unsafe { vm.reserve_region_capacity(1, self_vm) } {
        cleanup_cap_slot(cap_slot, cap_cleanup);
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    }

    let pages = size / KERNITE_PAGE_BYTES;
    let offset_pages = device_offset / KERNITE_PAGE_BYTES;
    let map_flags = (KERNITE_PAGE_FLAG_USER as u64)
        | (KERNITE_PAGE_FLAG_NOCACHE as u64)
        | if prot & 0x2 != 0 {
            KERNITE_PAGE_FLAG_WRITABLE as u64
        } else {
            0
        };
    let (dev_err, dev_val) = crate::kernel_vm::vspace_map_device_range(
        client.vspace_cap.as_raw(),
        cap_slot,
        offset_pages,
        va_base,
        pages,
        map_flags,
    );
    cleanup_cap_slot(cap_slot, cap_cleanup);
    if dev_err != 0 || dev_val != pages {
        for p in 0..dev_val.min(pages) {
            let _ = crate::kernel_vm::vspace_unmap(
                client.vspace_cap.as_raw(),
                va_base + p * KERNITE_PAGE_BYTES,
            );
        }
        return Err(if dev_err != 0 {
            dev_err as u64
        } else {
            KERNITE_ERR_OUT_OF_MEMORY as u64
        });
    }

    let region = MappedRegion {
        base: va_base,
        length: size,
        prot: prot as u8,
        max_prot: max_prot_for_region_type(REGION_MMAP),
        region_type: REGION_MMAP,
        lazy: false,
        fork_policy: ForkPolicy::Exclude,
        backing: BackingDescriptor::Device {
            phys_addr: device_offset,
            length: size,
        },
        reservation: None,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    let region_id = match unsafe { vm.install_region(region, self_vm) } {
        Ok(id) => id,
        Err(e) => {
            let code = e.code();
            let _ = e.into_region();
            for p in 0..pages {
                let _ = trona_kernel::syscall::invoke(
                    client.vspace_cap.as_raw(),
                    KERNITE_INV_VSPACE_UNMAP as u64,
                    va_base + p * KERNITE_PAGE_BYTES,
                    0,
                    0,
                    0,
                );
            }
            return Err(code);
        }
    };
    if let Some(next) = va_base.checked_add(size) {
        if next > client.mmap_hint {
            client.mmap_hint = next;
        }
    }
    Ok(region_id)
}

fn handle_mmap_device(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client_idx: u32,
    state: &mut ServerState,
) {
    let hint = regs[1];
    let size = regs[2];
    let prot = regs[3];
    let flags = regs[4];
    let device_offset = regs[5];

    if size == 0 || size % KERNITE_PAGE_BYTES != 0 || device_offset % KERNITE_PAGE_BYTES != 0 {
        delete_recv_cap(recv_user_slot(0));
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let recv_slot = recv_user_slot(0);
    if recv_slot == 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    let idx = client_idx as usize;
    let va_base = if flags & FLAG_FIXED != 0 {
        if hint % KERNITE_PAGE_BYTES != 0 {
            delete_recv_cap(recv_slot);
            send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
            return;
        }
        let Some(end) = hint.checked_add(size) else {
            delete_recv_cap(recv_slot);
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        };
        {
            let Some((client, vm)) = state.clients.entry_and_vm_mut(idx) else {
                delete_recv_cap(recv_slot);
                send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                return;
            };
            if hint < client.layout.mmap_base || end > client.layout.mmap_limit {
                delete_recv_cap(recv_slot);
                send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
                return;
            }
            if flags & FLAG_FIXED_NOREPLACE != 0 && !unsafe { range_is_free(vm, hint, size, None) }
            {
                delete_recv_cap(recv_slot);
                send_reply(buf, KERNITE_ERR_ALREADY_MAPPED as u64, &[], 0);
                return;
            }
        }
        hint
    } else {
        let Some((client, vm)) = state.clients.entry_and_vm_mut(idx) else {
            delete_recv_cap(recv_slot);
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        };
        match unsafe { place_va(vm, client, hint, size) } {
            Some(va) => va,
            None => {
                delete_recv_cap(recv_slot);
                send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
                return;
            }
        }
    };

    if flags & FLAG_FIXED != 0 && flags & FLAG_FIXED_NOREPLACE == 0 {
        let stable_cap_slot = match move_recv_cap_to_stable(recv_slot) {
            Ok(slot) => slot,
            Err(code) => {
                delete_recv_cap(recv_slot);
                send_reply(buf, code, &[], 0);
                return;
            }
        };
        let ctx = MmapFixedReplaceCtx {
            kind: MMAP_KIND_DEVICE,
            hint: va_base,
            unmap_base: va_base,
            unmap_size: size,
            size,
            prot,
            flags,
            mo_offset: device_offset,
            image_reservation: None,
            image_kind: None,
            file_backing_id: 0,
            file_backing_length: 0,
            stable_cap_slot,
        };
        match park_vfs_writeback_group(
            buf,
            state,
            client_idx,
            va_base,
            size,
            MS_SYNC as u64,
            VFS_WRITEBACK_OP_MMAP_FIXED_REPLACE,
            VfsWritebackContinuation::MmapFixedReplace(ctx),
        ) {
            Ok(true) => {}
            Ok(false) => {
                let clients = &mut state.clients;
                let self_vm = &mut state.self_vm;
                let mo_registry = &mut state.mo_registry;
                let frames = &mut state.frames;
                let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
                    delete_preserved_cap(stable_cap_slot);
                    send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                    return;
                };
                let pages = size / KERNITE_PAGE_BYTES;
                if let Err(code) = unsafe {
                    txn::force_unmap_range(
                        vm,
                        va_base,
                        pages,
                        client.vspace_cap.as_raw(),
                        self_vm,
                        mo_registry,
                        frames,
                    )
                } {
                    delete_preserved_cap(stable_cap_slot);
                    send_reply(buf, code, &[], 0);
                    return;
                }
                match install_device_from_slot(
                    stable_cap_slot,
                    CapSlotCleanup::Allocated,
                    client,
                    vm,
                    self_vm,
                    va_base,
                    size,
                    prot,
                    device_offset,
                ) {
                    Ok(region_id) => send_reply(
                        buf,
                        TRONA_OK,
                        &[va_base, region_id.idx() as u64, region_id.epoch() as u64],
                        0,
                    ),
                    Err(code) => send_reply(buf, code, &[], 0),
                };
            }
            Err(code) => {
                delete_preserved_cap(stable_cap_slot);
                send_reply(buf, code, &[], 0);
            }
        };
        return;
    }

    let clients = &mut state.clients;
    let self_vm = &mut state.self_vm;
    let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
        delete_recv_cap(recv_slot);
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    match install_device_from_slot(
        recv_slot,
        CapSlotCleanup::Receive,
        client,
        vm,
        self_vm,
        va_base,
        size,
        prot,
        device_offset,
    ) {
        Ok(region_id) => send_reply(
            buf,
            TRONA_OK,
            &[va_base, region_id.idx() as u64, region_id.epoch() as u64],
            0,
        ),
        Err(code) => send_reply(buf, code, &[], 0),
    };
}

fn validate_msync_flags(flags: u64) -> bool {
    let known = (MS_ASYNC | MS_INVALIDATE | MS_SYNC) as u64;
    if flags & !known != 0 {
        return false;
    }
    let sync = flags & (MS_SYNC as u64) != 0;
    let async_ = flags & (MS_ASYNC as u64) != 0;
    !(sync && async_)
}

fn vfs_msync_reply_to_error(label: u64) -> u64 {
    match label {
        VFS_PUBLIC_REPLY_OK => TRONA_OK,
        VFS_PUBLIC_REPLY_INVALID => KERNITE_ERR_INVALID_ARGUMENT as u64,
        VFS_PUBLIC_REPLY_NOT_FOUND => KERNITE_ERR_NOT_FOUND as u64,
        VFS_PUBLIC_REPLY_BUSY | VFS_PUBLIC_REPLY_AGAIN => KERNITE_ERR_BUSY as u64,
        VFS_PUBLIC_REPLY_NO_MEM => KERNITE_ERR_OUT_OF_MEMORY as u64,
        VFS_PUBLIC_REPLY_RANGE => KERNITE_ERR_OUT_OF_RANGE as u64,
        VFS_PUBLIC_REPLY_NOT_SUPPORTED => KERNITE_ERR_NOT_SUPPORTED as u64,
        VFS_PUBLIC_REPLY_PERM => KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
        VFS_PUBLIC_REPLY_RO_FS => KERNITE_ERR_READONLY as u64,
        VFS_PUBLIC_REPLY_IO_ERROR => KERNITE_ERR_IO_ERROR as u64,
        _ => KERNITE_ERR_IO_ERROR as u64,
    }
}

#[derive(Clone, Copy)]
struct FileBackedFlushSegment {
    mo_id: u64,
    mo_offset: u64,
    length: u64,
}

unsafe fn send_vfs_msync_request(
    vfs_mp_send_slot: u64,
    request_token: u64,
    mo_id: u64,
    mo_offset: u64,
    length: u64,
    flags: u64,
) -> Result<(), u64> {
    if vfs_mp_send_slot == 0 {
        return Err(KERNITE_ERR_INVALID_OPERATION as u64);
    }
    if length == 0 {
        return Ok(());
    }

    let mut req = TronaMsg::zeroed();
    req.label = VFS_MSYNC_MO;
    req.length = 5;
    req.regs[0] = request_token;
    req.regs[1] = mo_id;
    req.regs[2] = mo_offset;
    req.regs[3] = length;
    req.regs[4] = flags;

    let err = unsafe {
        trona_kernel::ipc::mp_write_ctx(
            trona_posix::tls::current_ipc_ctx(),
            vfs_mp_send_slot,
            &raw const req,
        )
    };
    if err != 0 { Err(err as u64) } else { Ok(()) }
}

unsafe fn walk_file_backed_flush_segments<F>(
    vm: &ClientVm,
    vaddr: u64,
    size: u64,
    mut f: F,
) -> Result<u32, u64>
where
    F: FnMut(FileBackedFlushSegment) -> Result<(), u64>,
{
    if size == 0 {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
    }
    let end = vaddr
        .checked_add(size)
        .ok_or(KERNITE_ERR_OUT_OF_RANGE as u64)?;
    let mut cur = vaddr;
    let mut count = 0u32;

    while cur < end {
        let Some(region_id) = (unsafe { va_alloc::range_overlaps_mapping(vm, cur, end - cur) })
        else {
            return Ok(count);
        };
        let (region_base, region_end, flush_segment) = {
            let region = unsafe { vm.region(region_id) }.ok_or(KERNITE_ERR_NOT_FOUND as u64)?;
            let region_end = region
                .base
                .checked_add(region.length)
                .ok_or(KERNITE_ERR_OUT_OF_RANGE as u64)?;
            if region_end <= cur {
                return Err(KERNITE_ERR_OUT_OF_RANGE as u64);
            }
            let segment_start = core::cmp::max(cur, region.base);
            let segment_end = core::cmp::min(region_end, end);
            if segment_end <= segment_start {
                return Err(KERNITE_ERR_OUT_OF_RANGE as u64);
            }
            let flush_segment = if let BackingDescriptor::FileBacked {
                mo_offset,
                file_id0,
                file_size,
                writeback,
                ..
            } = &region.backing
            {
                if *writeback && *file_id0 != 0 {
                    let relative = segment_start - region.base;
                    let mo_byte_offset = (*mo_offset as u64)
                        .saturating_mul(KERNITE_PAGE_BYTES)
                        .saturating_add(relative);
                    let segment_len = segment_end - segment_start;
                    let flush_len = if *file_size == 0 {
                        segment_len
                    } else if mo_byte_offset >= *file_size {
                        0
                    } else {
                        core::cmp::min(segment_len, *file_size - mo_byte_offset)
                    };
                    if flush_len != 0 {
                        Some(FileBackedFlushSegment {
                            mo_id: *file_id0,
                            mo_offset: mo_byte_offset,
                            length: flush_len,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            (region.base, segment_end, flush_segment)
        };
        if region_end <= region_base {
            return Err(KERNITE_ERR_OUT_OF_RANGE as u64);
        }
        if let Some(segment) = flush_segment {
            f(segment)?;
            count = count.saturating_add(1);
        }
        cur = region_end;
    }

    Ok(count)
}

fn send_mmap_result_to_target(
    buf: *mut kernite_ipc_buffer,
    target: MpReplyTarget,
    va_base: u64,
    result: Result<RegionId, u64>,
) {
    match result {
        Ok(region_id) => {
            send_reply_to_target(
                buf,
                target,
                TRONA_OK,
                &[va_base, region_id.idx() as u64, region_id.epoch() as u64],
            );
        }
        Err(code) => {
            send_reply_to_target(buf, target, code, &[]);
        }
    }
}

fn cleanup_mmap_fixed_replace_ctx(ctx: MmapFixedReplaceCtx) {
    if ctx.stable_cap_slot != 0 {
        delete_preserved_cap(ctx.stable_cap_slot);
    }
}

fn finish_mmap_fixed_replace(
    buf: *mut kernite_ipc_buffer,
    state: &mut ServerState,
    group: PendingVfsWritebackGroup,
    ctx: MmapFixedReplaceCtx,
) {
    let idx = group.client_idx as usize;
    let Some(epoch) = state.clients.epoch_of(idx) else {
        cleanup_mmap_fixed_replace_ctx(ctx);
        send_reply_to_target(buf, group.reply_target, KERNITE_ERR_NOT_FOUND as u64, &[]);
        return;
    };
    if epoch != group.client_epoch {
        cleanup_mmap_fixed_replace_ctx(ctx);
        send_reply_to_target(
            buf,
            group.reply_target,
            KERNITE_ERR_INVALID_OPERATION as u64,
            &[],
        );
        return;
    }

    let pages = ctx.unmap_size / KERNITE_PAGE_BYTES;
    let clients = &mut state.clients;
    let self_vm = &mut state.self_vm;
    let mo_registry = &mut state.mo_registry;
    let frames = &mut state.frames;
    let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
        cleanup_mmap_fixed_replace_ctx(ctx);
        send_reply_to_target(buf, group.reply_target, KERNITE_ERR_NOT_FOUND as u64, &[]);
        return;
    };
    if let Err(code) = unsafe {
        txn::force_unmap_range(
            vm,
            ctx.unmap_base,
            pages,
            client.vspace_cap.as_raw(),
            self_vm,
            mo_registry,
            frames,
        )
    } {
        cleanup_mmap_fixed_replace_ctx(ctx);
        send_reply_to_target(buf, group.reply_target, code, &[]);
        return;
    }

    let result = match ctx.kind {
        MMAP_KIND_ANON | MMAP_KIND_ANON_STACK | MMAP_KIND_SHARED_ANON => install_anon(
            client,
            vm,
            self_vm,
            mo_registry,
            frames,
            ctx.kind,
            ctx.hint,
            ctx.size,
            ctx.prot,
            ctx.flags,
            ctx.image_reservation,
            ctx.image_kind,
        ),
        MMAP_KIND_MO | MMAP_KIND_SHM_MO => {
            if ctx.flags & FLAG_PRIVATE != 0 {
                install_mo_private_from_source(
                    ctx.stable_cap_slot,
                    CapSlotCleanup::Allocated,
                    ctx.kind,
                    ctx.hint,
                    ctx.size,
                    ctx.prot,
                    ctx.mo_offset,
                    ctx.image_reservation,
                    ctx.image_kind,
                    client,
                    vm,
                    self_vm,
                    mo_registry,
                    frames,
                )
            } else {
                install_mo_shared_from_stable(
                    ctx.stable_cap_slot,
                    client,
                    vm,
                    self_vm,
                    ctx.hint,
                    ctx.size,
                    ctx.prot,
                    ctx.mo_offset,
                    ctx.image_reservation,
                    ctx.image_kind,
                    ctx.file_backing_id,
                    ctx.file_backing_length,
                )
            }
        }
        MMAP_KIND_DEVICE => install_device_from_slot(
            ctx.stable_cap_slot,
            CapSlotCleanup::Allocated,
            client,
            vm,
            self_vm,
            ctx.hint,
            ctx.size,
            ctx.prot,
            ctx.mo_offset,
        ),
        _ => {
            cleanup_mmap_fixed_replace_ctx(ctx);
            Err(KERNITE_ERR_INVALID_ARGUMENT as u64)
        }
    };
    send_mmap_result_to_target(buf, group.reply_target, ctx.hint, result);
}

fn finish_vfs_writeback_group(
    buf: *mut kernite_ipc_buffer,
    state: &mut ServerState,
    group: PendingVfsWritebackGroup,
) {
    if group.first_error != TRONA_OK {
        if let VfsWritebackContinuation::MmapFixedReplace(ctx) = group.continuation {
            cleanup_mmap_fixed_replace_ctx(ctx);
        }
        send_reply_to_target(buf, group.reply_target, group.first_error, &[]);
        return;
    }

    match group.continuation {
        VfsWritebackContinuation::Munmap { vaddr, size } => {
            let idx = group.client_idx as usize;
            let Some(epoch) = state.clients.epoch_of(idx) else {
                send_reply_to_target(buf, group.reply_target, KERNITE_ERR_NOT_FOUND as u64, &[]);
                return;
            };
            if epoch != group.client_epoch {
                send_reply_to_target(
                    buf,
                    group.reply_target,
                    KERNITE_ERR_INVALID_OPERATION as u64,
                    &[],
                );
                return;
            }
            let pages = size / KERNITE_PAGE_BYTES;
            let clients = &mut state.clients;
            let self_vm = &mut state.self_vm;
            let mo_registry = &mut state.mo_registry;
            let frames = &mut state.frames;
            let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
                send_reply_to_target(buf, group.reply_target, KERNITE_ERR_NOT_FOUND as u64, &[]);
                return;
            };
            let result = unsafe {
                txn::force_unmap_range(
                    vm,
                    vaddr,
                    pages,
                    client.vspace_cap.as_raw(),
                    self_vm,
                    mo_registry,
                    frames,
                )
            };
            match result {
                Ok(()) => send_reply_to_target(buf, group.reply_target, TRONA_OK, &[]),
                Err(code) => send_reply_to_target(buf, group.reply_target, code, &[]),
            };
        }
        VfsWritebackContinuation::Msync => {
            send_reply_to_target(buf, group.reply_target, TRONA_OK, &[]);
        }
        VfsWritebackContinuation::MmapFixedReplace(ctx) => {
            finish_mmap_fixed_replace(buf, state, group, ctx);
        }
    };
}

fn complete_vfs_writeback_group_token(
    buf: *mut kernite_ipc_buffer,
    state: &mut ServerState,
    group_token: u64,
    code: u64,
) {
    let Some(handle) = state.pending_vfs_writeback_groups.lookup_token(group_token) else {
        return;
    };
    let mut finished = false;
    if let Some(group) = state.pending_vfs_writeback_groups.get_mut(handle) {
        if code != TRONA_OK && group.first_error == TRONA_OK {
            group.first_error = code;
        }
        group.remaining = group.remaining.saturating_sub(1);
        finished = group.remaining == 0;
    }
    if finished {
        if let Some(group) = state.pending_vfs_writeback_groups.take(handle) {
            finish_vfs_writeback_group(buf, state, group);
        }
    }
}

fn release_vfs_writeback_requests_for_group(state: &mut ServerState, group_token: u64) {
    const MAX_RELEASE_BATCH: usize = 16;

    loop {
        let mut handles = [ContHandle::INVALID; MAX_RELEASE_BATCH];
        let mut count = 0usize;
        state
            .pending_vfs_writeback_requests
            .for_each_active(|handle, request| {
                if request.group_token == group_token && count < MAX_RELEASE_BATCH {
                    handles[count] = handle;
                    count += 1;
                }
                count < MAX_RELEASE_BATCH
            });
        if count == 0 {
            break;
        }
        for handle in handles.iter().take(count) {
            let _ = state.pending_vfs_writeback_requests.release(*handle);
        }
        if count < MAX_RELEASE_BATCH {
            break;
        }
    }
}

fn force_complete_vfs_writeback_group_token(
    buf: *mut kernite_ipc_buffer,
    state: &mut ServerState,
    group_token: u64,
    code: u64,
) {
    let Some(handle) = state.pending_vfs_writeback_groups.lookup_token(group_token) else {
        return;
    };
    if let Some(group) = state.pending_vfs_writeback_groups.get_mut(handle) {
        group.remaining = 1;
        if group.first_error == TRONA_OK {
            group.first_error = code;
        }
    }
    complete_vfs_writeback_group_token(buf, state, group_token, code);
}

pub fn sweep_stale_vfs_writeback_groups(
    buf: *mut kernite_ipc_buffer,
    state: &mut ServerState,
) -> usize {
    const STALE_WRITEBACK_GROUP_TICKS: u64 = 4096;
    const MAX_SWEEP_BATCH: usize = 8;

    if state.pending_vfs_writeback_groups.is_empty() {
        return 0;
    }

    let now = state.vfs_writeback_sweep_tick;
    let mut tokens = [0u64; MAX_SWEEP_BATCH];
    let mut count = 0usize;
    state
        .pending_vfs_writeback_groups
        .for_each_active(|_handle, group| {
            if now.wrapping_sub(group.started_tick) >= STALE_WRITEBACK_GROUP_TICKS
                && count < MAX_SWEEP_BATCH
            {
                tokens[count] = group.token;
                count += 1;
            }
            count < MAX_SWEEP_BATCH
        });

    for token in tokens.iter().take(count) {
        release_vfs_writeback_requests_for_group(state, *token);
        force_complete_vfs_writeback_group_token(buf, state, *token, KERNITE_ERR_IO_ERROR as u64);
    }
    count
}

fn park_vfs_writeback_group(
    buf: *mut kernite_ipc_buffer,
    state: &mut ServerState,
    client_idx: u32,
    vaddr: u64,
    size: u64,
    flags: u64,
    op: u8,
    continuation: VfsWritebackContinuation,
) -> Result<bool, u64> {
    let _ = op;
    let idx = client_idx as usize;
    let vm = state.clients.vm(idx).ok_or(KERNITE_ERR_NOT_FOUND as u64)?;
    let mut segment_count = 0u32;
    unsafe {
        walk_file_backed_flush_segments(vm, vaddr, size, |_| {
            segment_count = segment_count.saturating_add(1);
            Ok(())
        })?;
    }
    if segment_count == 0 {
        return Ok(false);
    }
    if state.vfs_writeback_mp_send_slot == 0 {
        return Err(KERNITE_ERR_INVALID_OPERATION as u64);
    }
    let client_epoch = state
        .clients
        .epoch_of(idx)
        .ok_or(KERNITE_ERR_NOT_FOUND as u64)?;
    let group_token = state.pending_vfs_writeback_groups.alloc_token();
    let group = PendingVfsWritebackGroup {
        token: group_token,
        reply_target: crate::dispatch::current_reply_target(),
        client_idx,
        client_epoch,
        continuation,
        remaining: segment_count,
        first_error: TRONA_OK,
        started_tick: state.vfs_writeback_sweep_tick,
    };
    unsafe {
        state
            .pending_vfs_writeback_groups
            .alloc_with_token(&mut state.segment_allocator, group_token, group)
            .map_err(|_| KERNITE_ERR_OUT_OF_MEMORY as u64)?;
    };

    let vfs_mp_send_slot = state.vfs_writeback_mp_send_slot;
    let vm_ptr = state.clients.vm(idx).ok_or(KERNITE_ERR_NOT_FOUND as u64)? as *const ClientVm;
    let walk_result = unsafe {
        walk_file_backed_flush_segments(&*vm_ptr, vaddr, size, |segment| {
            let request = PendingVfsWritebackRequest { group_token };
            let request_alloc = state
                .pending_vfs_writeback_requests
                .alloc(&mut state.segment_allocator, request);
            let (request_handle, request_token) = match request_alloc {
                Ok(value) => value,
                Err(_) => {
                    complete_vfs_writeback_group_token(
                        buf,
                        state,
                        group_token,
                        KERNITE_ERR_OUT_OF_MEMORY as u64,
                    );
                    return Ok(());
                }
            };
            let send = send_vfs_msync_request(
                vfs_mp_send_slot,
                request_token,
                segment.mo_id,
                segment.mo_offset,
                segment.length,
                flags,
            );
            if let Err(code) = send {
                let _ = state.pending_vfs_writeback_requests.take(request_handle);
                complete_vfs_writeback_group_token(buf, state, group_token, code);
            }
            Ok(())
        })
    };
    if let Err(code) = walk_result {
        force_complete_vfs_writeback_group_token(buf, state, group_token, code);
    }
    Ok(true)
}

pub fn handle_munmap(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client_idx: u32,
    state: &mut ServerState,
) {
    let vaddr = regs[0];
    let size = regs[1];
    if size == 0 || size % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    match park_vfs_writeback_group(
        buf,
        state,
        client_idx,
        vaddr,
        size,
        MS_SYNC as u64,
        VFS_WRITEBACK_OP_MUNMAP,
        VfsWritebackContinuation::Munmap { vaddr, size },
    ) {
        Ok(true) => {}
        Ok(false) => {
            let idx = client_idx as usize;
            let clients = &mut state.clients;
            let self_vm = &mut state.self_vm;
            let mo_registry = &mut state.mo_registry;
            let frames = &mut state.frames;
            let Some((client, vm)) = clients.entry_and_vm_mut(idx) else {
                send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                return;
            };
            let pages = size / KERNITE_PAGE_BYTES;
            let result = unsafe {
                txn::force_unmap_range(
                    vm,
                    vaddr,
                    pages,
                    client.vspace_cap.as_raw(),
                    self_vm,
                    mo_registry,
                    frames,
                )
            };
            match result {
                Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
                Err(code) => send_reply(buf, code, &[], 0),
            };
        }
        Err(code) => {
            send_reply(buf, code, &[], 0);
        }
    };
}

pub fn handle_msync(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client_idx: u32,
    state: &mut ServerState,
) {
    let vaddr = regs[0];
    let size = regs[1];
    let flags = regs[2];
    if size == 0 || vaddr % KERNITE_PAGE_BYTES != 0 || !validate_msync_flags(flags) {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    match park_vfs_writeback_group(
        buf,
        state,
        client_idx,
        vaddr,
        size,
        flags,
        VFS_WRITEBACK_OP_MSYNC,
        VfsWritebackContinuation::Msync,
    ) {
        Ok(true) => {}
        Ok(false) => {
            send_reply(buf, TRONA_OK, &[], 0);
        }
        Err(code) => {
            send_reply(buf, code, &[], 0);
        }
    };
}

pub fn handle_vfs_writeback_done(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client_idx: u32,
    state: &mut ServerState,
) {
    if client_idx != state.vfs_pager_owner_client_idx {
        return;
    }
    let request_token = regs[0];
    let status = regs[1];
    let code = vfs_msync_reply_to_error(status);
    let Some((_handle, request)) = state
        .pending_vfs_writeback_requests
        .take_by_token(request_token)
    else {
        return;
    };
    complete_vfs_writeback_group_token(buf, state, request.group_token, code);
}

/// `MM_RESERVE_IMAGE(base, bytes)` — reserve a contiguous load envelope for an
/// image in the caller's own VSpace and return its packed [`ReservationId`] as
/// the image id (the teardown handle for `MM_UNMAP_IMAGE`). The range must lie
/// inside the process's planned runtime DSO window, must not overlap any
/// existing mapping or reservation, and is installed as `Image`-purpose under
/// the caller's badge.
pub fn handle_reserve_image(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
) {
    let base = regs[0];
    let bytes = regs[1];
    if bytes == 0 || base % KERNITE_PAGE_BYTES != 0 || bytes % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let Some(end) = base.checked_add(bytes) else {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    };
    if base < client.layout.dso_base || end > client.layout.dso_limit {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    }
    if !unsafe { range_is_free(vm, base, bytes, None) } {
        send_reply(buf, KERNITE_ERR_ALREADY_MAPPED as u64, &[], 0);
        return;
    }
    let range = ReservedRange {
        base,
        length: bytes,
        kind: ReservationKind::Arena,
        purpose: ReservationPurpose::Image,
        owner_badge: client.client_id as u64,
        stack_region_id: None,
    };
    match unsafe { vm.install_reservation(range, self_vm) } {
        Some(id) => send_reply(buf, TRONA_OK, &[id.pack()], 0),
        None => send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0),
    };
}

/// `MM_UNMAP_IMAGE(image_id)` — tear down every region tagged with the image
/// reservation `image_id` (unmap pages, release backing), then free the
/// reservation. Refuses an id that is not an `Image`-purpose reservation in the
/// caller's own VSpace, so a plain arena cannot be unmapped this way.
pub fn handle_unmap_image(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let image_id = ReservationId::unpack(regs[0]);
    let is_image = unsafe { vm.reservation(image_id) }
        .map(|r| r.purpose == ReservationPurpose::Image)
        .unwrap_or(false);
    if !is_image {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let vspace = client.vspace_cap.as_raw();
    // `txn::unmap` vacates each region as it unmaps it, so a batch of VA ranges
    // is captured (ending the immutable region borrow) before the slab is
    // mutated. Bounded passes clear any region count without an unbounded loop;
    // a well-formed image clears in one pass.
    for _pass in 0..64 {
        let mut ranges: [(u64, u64); 64] = [(0, 0); 64];
        let mut n = 0usize;
        for (_, region) in unsafe { vm.iter_regions() } {
            if region.reservation == Some(image_id) && n < ranges.len() {
                ranges[n] = (region.base, region.length / KERNITE_PAGE_BYTES);
                n += 1;
            }
        }
        if n == 0 {
            break;
        }
        for &(base, pages) in &ranges[..n] {
            let _ = unsafe { txn::unmap(vm, base, pages, vspace, self_vm, mo_registry, frames) };
        }
    }
    unsafe { vm.vacate_reservation(image_id) };
    send_reply(buf, TRONA_OK, &[], 0);
}

pub fn handle_mprotect(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let vaddr = regs[0];
    let size = regs[1];
    let new_prot = regs[2] as u8;
    if size == 0 || size % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let pages = size / KERNITE_PAGE_BYTES;
    let result = unsafe {
        txn::mprotect(
            vm,
            vaddr,
            pages,
            new_prot,
            client.vspace_cap.as_raw(),
            self_vm,
            mo_registry,
            frames,
        )
    };
    match result {
        Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
        Err(code) => send_reply(buf, code, &[], 0),
    };
}

fn align_up_page(value: u64) -> Option<u64> {
    let mask = KERNITE_PAGE_BYTES - 1;
    value.checked_add(mask).map(|v| v & !mask)
}

fn align_down_page(value: u64) -> u64 {
    value & !(KERNITE_PAGE_BYTES - 1)
}

unsafe fn heap_growth_start(vm: &ClientVm, prev_brk: u64) -> Option<u64> {
    let aligned_up = align_up_page(prev_brk)?;
    let aligned_down = align_down_page(prev_brk);
    if aligned_down == aligned_up || unsafe { vm.find_region(aligned_down) }.is_none() {
        Some(aligned_down)
    } else {
        Some(aligned_up)
    }
}

#[allow(clippy::too_many_arguments)]
fn map_heap_growth(
    buf: *mut kernite_ipc_buffer,
    client: &ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
    start: u64,
    end: u64,
) -> bool {
    if end <= start {
        return true;
    }
    let size = end - start;
    if size % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return false;
    }
    if !unsafe { range_is_free(vm, start, size, None) } {
        send_reply(buf, KERNITE_ERR_ALREADY_MAPPED as u64, &[], 0);
        return false;
    }

    let Some(mo_idx) = mo_registry.alloc_slot() else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return false;
    };
    let Some(mo_cap) = mo_registry.install(mo_idx, size, client.client_id, MoKind::Anon, frames)
    else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return false;
    };

    let pages = size / KERNITE_PAGE_BYTES;
    let plan = MappingPlan {
        va_base: start,
        pages,
        prot: 0x3,
        region_type: REGION_HEAP,
        fork_policy: ForkPolicy::InheritCow,
        lazy: false,
        mo_cap,
        mo_offset_pages: 0,
        eager_commit: true,
        backing: BackingDescriptor::Anon {
            mo_handle: MoHandle(mo_idx as u32),
            mo_offset: 0,
        },
        reservation: None,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    match unsafe { plan.apply(vm, client.vspace_cap.as_raw(), self_vm) } {
        Ok(_) => true,
        Err(code) => {
            mo_registry.vacate(mo_idx, frames);
            send_reply(buf, code, &[], 0);
            false
        }
    }
}

pub fn handle_brk(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &mut ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let new_brk = regs[0];
    if new_brk < client.layout.heap_base || new_brk > client.layout.heap_limit {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    }
    if new_brk > client.heap_current {
        let Some(map_start) = (unsafe { heap_growth_start(vm, client.heap_current) }) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        };
        let Some(map_end) = align_up_page(new_brk) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        };
        if !map_heap_growth(
            buf,
            client,
            vm,
            self_vm,
            mo_registry,
            frames,
            map_start,
            map_end,
        ) {
            return;
        }
    }
    client.heap_current = new_brk;
    send_reply(buf, TRONA_OK, &[], 0);
}

pub fn handle_sbrk(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &mut ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let increment = regs[0] as i64;
    let prev = client.heap_current;
    let new_brk = if increment >= 0 {
        prev.checked_add(increment as u64)
    } else {
        prev.checked_sub(increment.unsigned_abs())
    };
    let Some(new_brk) = new_brk else {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    };
    if new_brk < client.layout.heap_base || new_brk > client.layout.heap_limit {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    }
    if new_brk > prev {
        let Some(map_start) = (unsafe { heap_growth_start(vm, prev) }) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        };
        let Some(map_end) = align_up_page(new_brk) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        };
        if !map_heap_growth(
            buf,
            client,
            vm,
            self_vm,
            mo_registry,
            frames,
            map_start,
            map_end,
        ) {
            return;
        }
    }
    client.heap_current = new_brk;
    send_reply(buf, TRONA_OK, &[prev], 0);
}

fn log_shm_create_failure(
    client_id: u32,
    name_lo: u64,
    size: u64,
    err: u64,
    reason: &'static [u8],
) {
    trona_runtime::uerror!(|_lb| {
        _lb.str(b"[MMSRV] SHM create failed client=");
        _lb.hex(client_id as u64);
        _lb.str(b" name=");
        _lb.hex(name_lo);
        _lb.str(b" size=");
        _lb.dec(size);
        _lb.str(b" err=");
        _lb.dec(err);
        _lb.str(b" reason=");
        _lb.str(reason);
        _lb.putc(b'\n');
    });
}

pub fn handle_shm_create(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &ClientState,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let name_lo = regs[0];
    let _name_hi = regs[1];
    let size = regs[2];
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[MMSRV] SHM create begin client=");
        _lb.hex(client.client_id as u64);
        _lb.str(b" name=");
        _lb.hex(name_lo);
        _lb.str(b" size=");
        _lb.dec(size);
        _lb.putc(b'\n');
    });
    if size == 0 || size % KERNITE_PAGE_BYTES != 0 {
        log_shm_create_failure(
            client.client_id,
            name_lo,
            size,
            KERNITE_ERR_INVALID_ARGUMENT as u64,
            b"bad-size",
        );
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    if let Some(existing_idx) = mo_registry.find_shm_by_name(name_lo) {
        let Some(existing) = mo_registry.entry(existing_idx) else {
            log_shm_create_failure(
                client.client_id,
                name_lo,
                size,
                KERNITE_ERR_NOT_FOUND as u64,
                b"existing-entry-missing",
            );
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        };
        if size > existing.size_bytes {
            log_shm_create_failure(
                client.client_id,
                name_lo,
                size,
                KERNITE_ERR_ALREADY_EXISTS as u64,
                b"existing-too-small",
            );
            send_reply(buf, KERNITE_ERR_ALREADY_EXISTS as u64, &[], 0);
            return;
        }
        let pages = size / KERNITE_PAGE_BYTES;
        if let Err(err) = commit_mo_range(existing.mo_cap.as_raw(), 0, pages) {
            log_shm_create_failure(client.client_id, name_lo, size, err, b"existing-commit");
            send_reply(buf, err, &[], 0);
            return;
        }
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[MMSRV] SHM create existing ok client=");
            _lb.hex(client.client_id as u64);
            _lb.str(b" name=");
            _lb.hex(name_lo);
            _lb.str(b" idx=");
            _lb.dec(existing_idx as u64);
            _lb.str(b" cap=");
            _lb.hex(existing.mo_cap.as_raw());
            _lb.putc(b'\n');
        });
        send_reply_with_cap_copy(
            buf,
            existing.mo_cap.as_raw(),
            TRONA_OK,
            &[existing_idx as u64],
            b"mmsrv shm reply cap",
        );
        return;
    }
    let Some(mo_idx) = mo_registry.alloc_slot() else {
        log_shm_create_failure(
            client.client_id,
            name_lo,
            size,
            KERNITE_ERR_OUT_OF_MEMORY as u64,
            b"no-registry-slot",
        );
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    let Some(mo_cap_slot) = mo_registry.install(
        mo_idx,
        size,
        client.client_id,
        MoKind::Shm { name_hash: name_lo },
        frames,
    ) else {
        log_shm_create_failure(
            client.client_id,
            name_lo,
            size,
            KERNITE_ERR_OUT_OF_MEMORY as u64,
            b"install-mo",
        );
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    let pages = size / KERNITE_PAGE_BYTES;
    if let Err(err) = commit_mo_range(mo_cap_slot, 0, pages) {
        log_shm_create_failure(client.client_id, name_lo, size, err, b"commit");
        mo_registry.vacate(mo_idx, frames);
        send_reply(buf, err, &[], 0);
        return;
    }
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[MMSRV] SHM create ok client=");
        _lb.hex(client.client_id as u64);
        _lb.str(b" name=");
        _lb.hex(name_lo);
        _lb.str(b" idx=");
        _lb.dec(mo_idx as u64);
        _lb.str(b" cap=");
        _lb.hex(mo_cap_slot);
        _lb.str(b" pages=");
        _lb.dec(pages);
        _lb.putc(b'\n');
    });
    if !send_reply_with_cap_copy(
        buf,
        mo_cap_slot,
        TRONA_OK,
        &[mo_idx as u64],
        b"mmsrv shm reply cap",
    ) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] SHM create reply cap failed; vacating client=");
            _lb.hex(client.client_id as u64);
            _lb.str(b" name=");
            _lb.hex(name_lo);
            _lb.str(b" idx=");
            _lb.dec(mo_idx as u64);
            _lb.str(b" cap=");
            _lb.hex(mo_cap_slot);
            _lb.putc(b'\n');
        });
        mo_registry.vacate(mo_idx, frames);
    }
}

pub fn handle_shm_map(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &mut ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let hint = regs[0];
    let Ok(shm_id) = usize::try_from(regs[1]) else {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    };
    let offset = regs[2];
    let length = regs[3];
    let prot = regs[4];
    let _flags = regs[5];
    let user_caps = received_user_cap_count(buf);
    let recv_slot = recv_user_slot(0);

    if user_caps != 1 {
        delete_recv_user_caps(user_caps);
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    if length == 0 || length % KERNITE_PAGE_BYTES != 0 || offset % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let Some(mo) = mo_registry.entry(shm_id) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let mo_size = mo.size_bytes;
    let Some(end_offset) = offset.checked_add(length) else {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    };
    if end_offset > mo_size {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    }
    if recv_slot == 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let Ok(shm_idx_u32) = u32::try_from(shm_id) else {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    };

    let Some(va_base) = (unsafe { place_va(vm, client, hint, length) }) else {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    };

    // Move the caller's SHM MO cap out of receive scratch into a stable
    // slot the published region owns.
    let Some(stable_mo_slot) = trona_runtime::core::slot_alloc::alloc_slot() else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    let mv = trona_kernel::syscall::invoke(
        KERNITE_CAP_SELF_CSPACE as u64,
        KERNITE_INV_CNODE_MOVE as u64,
        stable_mo_slot.addr(),
        KERNITE_CAP_SELF_CSPACE as u64,
        recv_slot,
        0,
    );
    if mv.error != 0 {
        // move failed: `stable_mo_slot` (OwnedSlot, empty) Drop frees it.
        send_reply(buf, mv.error, &[], 0);
        return;
    }
    // The caller's SHM MO cap now occupies the slot; hand it off raw — the
    // published region owns it from here.
    let stable_mo_slot = stable_mo_slot.into_raw();

    let pages = length / KERNITE_PAGE_BYTES;
    let mo_offset_pages = offset / KERNITE_PAGE_BYTES;
    let plan = MappingPlan {
        va_base,
        pages,
        prot: prot as u8,
        region_type: REGION_MMAP,
        lazy: false,
        mo_cap: stable_mo_slot,
        mo_offset_pages,
        eager_commit: true,
        // SHM mapping: the child shares the same SHM MO (writable share).
        fork_policy: ForkPolicy::InheritShare,
        backing: BackingDescriptor::Shm {
            // SAFETY: stable_mo_slot holds the caller's SHM MO cap cnode_move'd
            // in and into_raw'd above; this OwnedCap is its sole persistent owner
            // (MappingPlan.mo_cap is a transient borrow consumed by plan.apply).
            mo_cap: unsafe { OwnedCap::adopt_received(stable_mo_slot) },
            shm_idx: shm_idx_u32,
            mo_offset: mo_offset_pages as u32,
        },
        reservation: None,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    // Bump the shared map count BEFORE publishing so a failed bump
    // (unreachable for a live shm slot) is reported before the kernel map,
    // and is cleanly undone if the map/publish then fails. The plan owns
    // the Shm cap, so this early return drops it.
    if !mo_registry.inc_map_count(shm_id) {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    }
    match unsafe { plan.apply(vm, client.vspace_cap.as_raw(), self_vm) } {
        Ok(region_id) => {
            // The published mapping holds the reference bumped above;
            // release_region_backing drops it on unmap.
            if let Some(next) = va_base.checked_add(length) {
                if next > client.mmap_hint {
                    client.mmap_hint = next;
                }
            }
            send_reply(
                buf,
                TRONA_OK,
                &[va_base, region_id.idx() as u64, region_id.epoch() as u64],
                0,
            );
        }
        Err(code) => {
            // Undo the speculative map-count bump; apply's own error path
            // already unmapped and dropped the Shm cap.
            let _ = mo_registry.dec_map_count(shm_id, frames);
            send_reply(buf, code, &[], 0);
        }
    }
}
pub fn handle_shm_destroy(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let key = regs[0];
    let Some(idx) = mo_registry.shm_index_for_key(key) else {
        send_reply(buf, TRONA_OK, &[], 0);
        return;
    };
    let _ = mo_registry.request_destroy_shm(idx, frames);
    send_reply(buf, TRONA_OK, &[], 0);
}

/// `MM_FILE_MMAP(vnode_slot, vnode_epoch, file_handle, file_offset,
/// length, prot, flags) -> (mo_idx, mo_id; caps=[mo_cap])`.
///
/// Materialise a file-backed MO bound to vfs's previously-registered
/// pager. The kernel issues `mo_id` from `MO_ATTACH_PAGER` and routes
/// page-absent faults to vfs's bound EventQueue as
/// `KERNITE_EVENT_TYPE_PAGER_REQUEST`. The caller (vfs) receives a
/// copy of the MO cap and the kernel-issued `mo_id`; subsequent
/// client `MM_MMAP_MO(mo_cap, ...)` calls land the MO in the target
/// vspace. mmsrv records the binding in `file_backed_registry` so
/// teardown / pager-detach paths can resolve `mo_id` back to the
/// originating vnode.
/// Handle `MM_MO_CREATE(length, flags) -> (caps=[mo_cap])`.
///
/// Caller asks mmsrv to retype a fresh anonymous MO of `length`
/// bytes (rounded to page granularity) out of its frame pool and
/// hand back the cap. The MO is owned by the caller's `client_id`
/// for reclaim accounting; mmsrv keeps the registry entry until
/// the cap chain is revoked or the owning client exits.
///
/// Used by callers that need a transient MO to ferry payload via
/// `caps[0]` on a downstream RPC — for example, the
/// `TRANSFER_KIND_MO` path of `BACKEND_WRITE` retypes a MO here,
/// writes the payload into a self-mapping, sends the cap to the
/// backend, then drops the local cap so the backend's mapping
/// holds the only reference until the backend unmaps.
pub fn handle_mo_create(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &mut ClientState,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let length = regs[0];
    let flags = regs[1];
    if flags != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    if length == 0 || length % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    let Some(mo_idx) = mo_registry.alloc_slot() else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    let Some(mo_cap_slot) =
        mo_registry.install(mo_idx, length, client.client_id, MoKind::Anon, frames)
    else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };

    if !send_reply_with_cap_copy(
        buf,
        mo_cap_slot,
        TRONA_OK,
        &[mo_idx as u64],
        b"mmsrv mo reply cap",
    ) {
        mo_registry.vacate(mo_idx, frames);
    }
}

pub fn handle_file_mmap(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &mut ClientState,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
    file_backed_registry: &mut FileBackedRegistry,
    vfs_pager_cap_slot: u64,
) {
    let vnode_slot = regs[0] as u32;
    let vnode_epoch = regs[1] as u32;
    let file_handle = regs[2];
    let file_offset = regs[3];
    let length = regs[4];
    let _prot = regs[5];
    let _flags = regs[6];

    if vfs_pager_cap_slot == 0 {
        // vfs has not yet registered its pager cap. File-backed MOs
        // cannot be materialised before `MM_REGISTER_VFS_PAGER`
        // lands — without an attached pager the kernel has no
        // delivery target for page-absent faults.
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    }
    if length == 0 || length % KERNITE_PAGE_BYTES != 0 || file_offset % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    if let Some(existing) = file_backed_registry.lookup(vnode_slot, vnode_epoch) {
        let Some(request_end) = file_offset.checked_add(length) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
            return;
        };
        let existing_end = existing.file_offset.saturating_add(existing.length);
        if existing.file_handle == file_handle
            && existing.file_offset <= file_offset
            && request_end <= existing_end
        {
            let mo_cap_raw = mo_registry
                .entry(existing.mo_idx as usize)
                .map(|e| e.mo_cap.as_raw())
                .unwrap_or(0);
            send_reply_with_cap_copy(
                buf,
                mo_cap_raw,
                TRONA_OK,
                &[existing.mo_idx as u64, existing.mo_id],
                b"mmsrv file reply cap",
            );
        } else {
            send_reply(buf, KERNITE_ERR_ALREADY_EXISTS as u64, &[], 0);
        }
        return;
    }

    let Some(mo_idx) = mo_registry.alloc_slot() else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    // `mo_id` is filled in below from the `MO_ATTACH_PAGER` reply;
    // installing the registry entry first reserves the slot and
    // satisfies the existing `MoRegistry::install` contract that
    // expects a fully-formed `MoKind`.
    let Some(mo_cap_slot) =
        mo_registry.install(mo_idx, length, client.client_id, MoKind::FileBacked, frames)
    else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };

    let attach = trona_kernel::syscall::invoke(
        mo_cap_slot,
        KERNITE_INV_MO_ATTACH_PAGER as u64,
        vfs_pager_cap_slot,
        0,
        0,
        0,
    );
    if attach.error != 0 {
        mo_registry.vacate(mo_idx, frames);
        send_reply(buf, attach.error, &[], 0);
        return;
    }
    let mo_id = attach.value;

    let Some(reg_idx) = file_backed_registry.alloc_slot() else {
        mo_registry.vacate(mo_idx, frames);
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    file_backed_registry.install(
        reg_idx,
        FileBackedEntry {
            mo_idx: mo_idx as u32,
            vnode_slot,
            vnode_epoch,
            mo_id,
            file_handle,
            file_offset,
            length,
            active: 1,
        },
    );

    if !send_reply_with_cap_copy(
        buf,
        mo_cap_slot,
        TRONA_OK,
        &[mo_idx as u64, mo_id],
        b"mmsrv file reply cap",
    ) {
        file_backed_registry.vacate(reg_idx);
        mo_registry.vacate(mo_idx, frames);
    }
}

pub fn handle_prefault_range(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &ClientState,
    vm: &ClientVm,
    mo_registry: &MoRegistry,
) {
    let vaddr = regs[0];
    let size = regs[1];
    let _prot_hint = regs[2];
    if size == 0 || size % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let (
        region_base,
        region_length,
        region_lazy,
        region_prot,
        region_type,
        mo_offset_base,
        mo_cap_raw,
    ) = {
        let Some(id) = (unsafe { vm.find_region(vaddr) }) else {
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        };
        let Some(r) = (unsafe { vm.region(id) }) else {
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        };
        let mo_cap_raw = match &r.backing {
            BackingDescriptor::Anon { mo_handle, .. }
            | BackingDescriptor::CowChild { mo_handle, .. }
            | BackingDescriptor::Image { mo_handle, .. } => {
                match mo_registry.entry(mo_handle.0 as usize) {
                    Some(e) => e.mo_cap.as_raw(),
                    None => {
                        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                        return;
                    }
                }
            }
            BackingDescriptor::Shm { mo_cap, .. } => mo_cap.as_raw(),
            BackingDescriptor::FileBacked { .. } | BackingDescriptor::Device { .. } => {
                send_reply(buf, KERNITE_ERR_NOT_SUPPORTED as u64, &[], 0);
                return;
            }
        };
        (
            r.base,
            r.length,
            r.lazy,
            r.prot,
            r.region_type,
            r.backing.mo_offset() as u64,
            mo_cap_raw,
        )
    };
    if vaddr < region_base || vaddr + size > region_base.saturating_add(region_length) {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    }
    let pages = size / KERNITE_PAGE_BYTES;
    if !region_lazy {
        send_reply(buf, TRONA_OK, &[pages], 0);
        return;
    }
    let page_delta = (vaddr - region_base) / KERNITE_PAGE_BYTES;
    let mo_offset_pages = mo_offset_base + page_delta;
    let commit_err =
        unsafe { crate::kernel_vm::commit_mo_pages(mo_cap_raw, mo_offset_pages, pages) };
    if commit_err != 0 {
        send_reply(buf, commit_err as u64, &[], 0);
        return;
    }
    // Status-only commit: on success every requested page is populated.
    let mapped_pages = pages;
    let perms_bits = (KERNITE_PAGE_FLAG_USER as u64)
        | if region_prot & 0x2 != 0 {
            KERNITE_PAGE_FLAG_WRITABLE as u64
        } else {
            0
        }
        | if region_prot & 0x4 != 0 {
            KERNITE_PAGE_FLAG_EXECUTABLE as u64
        } else {
            0
        };
    let count_and_flags = (mapped_pages << 32)
        | perms_bits
        | ((crate::region::kernel_region_kind(region_type) as u64) << 24);
    let map = trona_kernel::syscall::invoke(
        client.vspace_cap.as_raw(),
        KERNITE_INV_VSPACE_MAP_MO as u64,
        mo_cap_raw,
        vaddr,
        mo_offset_pages,
        count_and_flags,
    );
    if map.error != 0 {
        send_reply(buf, map.error, &[], 0);
        return;
    }
    send_reply(buf, TRONA_OK, &[map.value], 0);
}
pub fn handle_get_system_meminfo(
    buf: *mut kernite_ipc_buffer,
    state: &crate::main_loop::ServerState,
) {
    let total = state.frames.high_watermark_bytes();
    let (anon_bytes, shm_bytes, file_bytes) = state.mo_registry.bytes_by_kind();
    let committed = anon_bytes
        .saturating_add(shm_bytes)
        .saturating_add(file_bytes);
    let slab_bytes = state.mo_registry.slab_bytes();
    send_reply(
        buf,
        TRONA_OK,
        &[
            total,
            total.saturating_sub(committed),
            committed,
            file_bytes,
            slab_bytes,
            state.fault.oom_kills_total(),
            file_bytes,
        ],
        0,
    );
}

// ---------------------------------------------------------------------------
// Reservation / SHM-unmap / introspection opcodes.
// ---------------------------------------------------------------------------

/// `MM_RESERVE_RANGE(base, length, kind)` — reserve a VA range in the
/// caller's own VM (self-tier). Pure bookkeeping; the gap allocator then
/// avoids the range. The reservation records the caller's `client_id` as
/// its owner badge. Reply: the packed `ReservationId`.
pub fn handle_reserve_range(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
) {
    let base = regs[0];
    let length = regs[1];
    let kind_raw = regs[2];
    if length == 0 || length % KERNITE_PAGE_BYTES != 0 || base % KERNITE_PAGE_BYTES != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let Some(kind) = ReservationKind::from_u64(kind_raw) else {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    };
    // Guard reservations are mmsrv-internal: created alongside a stack
    // mapping and torn down with it. A client cannot reserve one directly
    // — it could never be dropped, since `MM_UNRESERVE_RANGE` vetoes the
    // Guard kind.
    if matches!(kind, ReservationKind::Guard) {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    match unsafe { txn::reserve_range(vm, base, length, kind, client.client_id as u64, self_vm) } {
        Ok(id) => send_reply(buf, TRONA_OK, &[id.pack()], 0),
        Err(code) => send_reply(buf, code, &[], 0),
    };
}

/// `MM_ALLOC_RANGE(length, align, bounds_lo, bounds_hi, kind)` — choose a
/// free VA range inside `[bounds_lo, bounds_hi)` in the caller's own VM and
/// reserve it (self-tier). mmsrv picks the base via the gap allocator, so
/// the reservation lands on a free interval by construction — there is no
/// fixed-base overlap to validate. Reply: `regs[0]` = chosen base,
/// `regs[1]` = packed `ReservationId`.
pub fn handle_alloc_range(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
) {
    let length = regs[0];
    let align = if regs[1] == 0 {
        KERNITE_PAGE_BYTES
    } else {
        regs[1]
    };
    let bounds_lo = regs[2];
    let bounds_hi = regs[3];
    let kind_raw = regs[4];
    if length == 0 || length % KERNITE_PAGE_BYTES != 0 || bounds_hi <= bounds_lo {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let Some(kind) = ReservationKind::from_u64(kind_raw) else {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    };
    if matches!(kind, ReservationKind::Guard) {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let found = unsafe {
        va_alloc::find_free_va_gap(vm, length, align, bounds_lo, bounds_lo..bounds_hi, None)
    };
    let Some(base) = found else {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    };
    match unsafe { txn::reserve_range(vm, base, length, kind, client.client_id as u64, self_vm) } {
        Ok(id) => send_reply(buf, TRONA_OK, &[base, id.pack()], 0),
        Err(code) => send_reply(buf, code, &[], 0),
    };
}

/// `MM_UNRESERVE_RANGE(base)` — drop the reservation covering `base` in
/// the caller's own VM.
pub fn handle_unreserve_range(buf: *mut kernite_ipc_buffer, regs: &[u64; 32], vm: &mut ClientVm) {
    let base = regs[0];
    match unsafe { txn::unreserve_range(vm, base) } {
        Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
        Err(code) => send_reply(buf, code, &[], 0),
    };
}

/// `MM_SHM_UNMAP(shm_id, _, vaddr)` — unmap a SHM mapping the caller
/// holds. Verifies the region at `vaddr` is SHM-backed by `shm_id`, then
/// drops the whole region (the SHM backing teardown releases the
/// per-mapping cap copy and decrements the registry map count).
pub fn handle_shm_unmap(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    client: &ClientState,
    vm: &mut ClientVm,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    let shm_id = regs[0];
    let vaddr = regs[2];
    let Some(id) = (unsafe { vm.find_region(vaddr) }) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let (matches_shm, region_length, region_base) = match unsafe { vm.region(id) } {
        // `MappedRegion` owns a cap (non-Copy); snapshot the scalars needed
        // before the `&mut vm` reborrow in `txn::unmap` below.
        Some(r) => (
            matches!(
                r.backing,
                BackingDescriptor::Shm { shm_idx, .. } if shm_idx as u64 == shm_id
            ),
            r.length,
            r.base,
        ),
        None => {
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        }
    };
    if !matches_shm {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let pages = region_length / KERNITE_PAGE_BYTES;
    let result = unsafe {
        txn::unmap(
            vm,
            region_base,
            pages,
            client.vspace_cap.as_raw(),
            self_vm,
            mo_registry,
            frames,
        )
    };
    match result {
        Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
        Err(code) => send_reply(buf, code, &[], 0),
    };
}

/// `MM_GET_COMMIT_AS()` — system-wide committed virtual address space,
/// in bytes.
pub fn handle_get_commit_as(buf: *mut kernite_ipc_buffer, state: &crate::main_loop::ServerState) {
    let committed = unsafe { state.clients.total_committed_as() };
    send_reply(buf, TRONA_OK, &[committed], 0);
}

/// VMA record returned by `MM_LIST_VMAS`. `#[repr(C)]`, byte-identical
/// to vfs's `VmaEntry` (`core/vfs/src/fs/procfs/pid.rs`): two `u64`,
/// eleven `u32`, then a `u64` (4 bytes of tail padding before the final
/// `u64`).
#[repr(C)]
struct MmsrvVmaEntry {
    base: u64,
    length: u64,
    prot: u32,
    region_type: u32,
    backing_kind: u32,
    mo_kind: u32,
    present_pages: u32,
    referenced_pages: u32,
    shared_pages: u32,
    shared_dirty_pages: u32,
    private_dirty_pages: u32,
    writeback_pages: u32,
    _reserved: u32,
    pss_bytes: u64,
}

/// `(backing_kind, mo_kind)` discriminants for a backing — projected for
/// procfs smaps.
fn backing_kinds(backing: &BackingDescriptor) -> (u32, u32) {
    match backing {
        BackingDescriptor::Anon { .. } => (0, 0),
        BackingDescriptor::CowChild { .. } => (1, 0),
        BackingDescriptor::FileBacked { .. } => (2, 2),
        BackingDescriptor::Shm { .. } => (3, 3),
        BackingDescriptor::Device { .. } => (4, 0),
        BackingDescriptor::Image { .. } => (5, 0),
    }
}

/// `MM_LIST_VMAS(pid)` — project the target process's regions into the
/// IPC buffer's `reserved[]` area as `MmsrvVmaEntry` records, filling
/// per-range residency from the kernel's `VSPACE_GET_RANGE_STATS`. Gated
/// to the vfs pager owner — the only client permitted to read another
/// process's VMA list (for `/proc/<pid>/{maps,smaps}`). Reply:
/// `regs[0]=count`.
pub fn handle_list_vmas(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    caller_idx: u32,
    state: &crate::main_loop::ServerState,
) {
    if state.vfs_pager_owner_client_idx == u32::MAX
        || caller_idx != state.vfs_pager_owner_client_idx
    {
        send_reply(buf, TRONA_PERMISSION_DENIED, &[], 0);
        return;
    }
    let pid = regs[0] as u32;
    let Some(target_idx) = state.clients.find_by_pid(pid) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let target_vspace = match state.clients.entry(target_idx) {
        Some(t) => t.vspace_cap.as_raw(),
        None => {
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        }
    };
    let Some(vm) = state.clients.vm(target_idx) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };

    let entry_size = core::mem::size_of::<MmsrvVmaEntry>();
    let max_entries = unsafe { (*buf).reserved.len() } / entry_size;
    let reserved_ptr = unsafe { (*buf).reserved.as_mut_ptr() } as *mut MmsrvVmaEntry;

    let mut count = 0usize;
    for (_, region) in unsafe { vm.iter_regions() } {
        if count >= max_entries {
            break;
        }
        let pages = region.length / KERNITE_PAGE_BYTES;
        let mut stats = TronaVSpaceRangeStats::zeroed();
        let _ =
            crate::kernel_vm::vspace_get_range_stats(target_vspace, region.base, pages, &mut stats);
        let (backing_kind, mo_kind) = backing_kinds(&region.backing);
        let entry = MmsrvVmaEntry {
            base: region.base,
            length: region.length,
            prot: region.prot as u32,
            region_type: region.region_type as u32,
            backing_kind,
            mo_kind,
            present_pages: stats.present_pages as u32,
            referenced_pages: stats.referenced_pages as u32,
            shared_pages: stats.shared_pages as u32,
            shared_dirty_pages: stats.shared_dirty_pages as u32,
            private_dirty_pages: stats.private_dirty_pages as u32,
            writeback_pages: stats.writeback_pages as u32,
            _reserved: 0,
            pss_bytes: stats.pss_bytes,
        };
        unsafe { core::ptr::write(reserved_ptr.add(count), entry) };
        count += 1;
    }
    send_reply(buf, TRONA_OK, &[count as u64], 0);
}

/// `MM_GET_CLIENT_VM_STATS(pid)` — per-process memory snapshot. Glues
/// the kernel's per-VSpace accounting (`VSPACE_GET_MEM_STATS`) to
/// mmsrv-owned heap / region metadata and packs the resulting
/// `TronaProcMemSnapshot` (20 `u64`) into `regs[0..20]` — fits one MP
/// record, so no `reserved[]` bulk channel. Gated to the vfs pager
/// owner, the only client permitted to read another process's stats
/// (for `/proc/<pid>/{stat,status,statm}`).
pub fn handle_get_client_vm_stats(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    caller_idx: u32,
    state: &crate::main_loop::ServerState,
) {
    if state.vfs_pager_owner_client_idx == u32::MAX
        || caller_idx != state.vfs_pager_owner_client_idx
    {
        send_reply(buf, TRONA_PERMISSION_DENIED, &[], 0);
        return;
    }
    let pid = regs[0] as u32;
    let Some(target_idx) = state.clients.find_by_pid(pid) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let Some(target) = state.clients.entry(target_idx) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let target_vspace = target.vspace_cap.as_raw();
    let heap_base = target.layout.heap_base;
    let heap_current = target.heap_current;

    let mut vstats = TronaVSpaceMemStats::default();
    let _ = crate::kernel_vm::vspace_get_mem_stats(target_vspace, &mut vstats);

    let region_count = match state.clients.vm(target_idx) {
        Some(vm) => unsafe { vm.iter_regions().count() as u64 },
        None => 0,
    };

    let snap = TronaProcMemSnapshot {
        vm_reserved_bytes: vstats.vm_reserved_bytes,
        vm_resident_pages: vstats.vm_resident_pages,
        vm_demand_pages: vstats.vm_demand_pages,
        vm_cow_pages: vstats.vm_cow_pages,
        vm_shared_pages: vstats.vm_shared_pages,
        vm_pt_pages: vstats.vm_pt_pages,
        vm_kstack_pages: vstats.vm_kstack_pages,
        resident_anon: vstats.resident_anon,
        resident_file: vstats.resident_file,
        resident_shm: vstats.resident_shm,
        vm_stk_bytes: vstats.vm_stk_bytes,
        vm_exe_bytes: vstats.vm_exe_bytes,
        vm_data_bytes: vstats.vm_data_bytes,
        vm_lib_bytes: vstats.vm_lib_bytes,
        heap_base,
        heap_current,
        region_count,
        file_backed_dirty_pages: 0,
        vm_peak_reserved_bytes: vstats.vm_peak_reserved_bytes,
        vm_peak_resident_pages: vstats.vm_peak_resident_pages,
    };

    // SAFETY: `TronaProcMemSnapshot` is `#[repr(C)]` of 20 contiguous
    // `u64`, so it reinterprets as `[u64; 20]` with no padding.
    let words: &[u64; 20] = unsafe { &*(&snap as *const TronaProcMemSnapshot as *const [u64; 20]) };
    send_reply(buf, TRONA_OK, words, 0);
}

/// Reservation record returned by `MM_LIST_RESERVATIONS`. `#[repr(C)]`,
/// byte-identical to vfs's `ReservationEntry`: three `u64` then a `u32`
/// kind discriminant and a `u32` tail pad (32 bytes, no implicit
/// padding).
#[repr(C)]
struct MmsrvReservationEntry {
    base: u64,
    length: u64,
    owner_badge: u64,
    kind: u32,
    _reserved: u32,
}

/// `MM_LIST_RESERVATIONS(pid)` — project the target process's
/// reservations into the IPC buffer's `reserved[]` area as
/// `MmsrvReservationEntry` records. Gated to the vfs pager owner — the
/// only client permitted to read another process's reservation list (for
/// `/proc/<pid>/reservations`). `owner_badge == 0` marks an unowned
/// exclusion zone (e.g. the null guard); nonzero is the owning client.
/// Reply: `regs[0]=count`.
pub fn handle_list_reservations(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    caller_idx: u32,
    state: &crate::main_loop::ServerState,
) {
    if state.vfs_pager_owner_client_idx == u32::MAX
        || caller_idx != state.vfs_pager_owner_client_idx
    {
        send_reply(buf, TRONA_PERMISSION_DENIED, &[], 0);
        return;
    }
    let pid = regs[0] as u32;
    let Some(target_idx) = state.clients.find_by_pid(pid) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let Some(vm) = state.clients.vm(target_idx) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };

    let entry_size = core::mem::size_of::<MmsrvReservationEntry>();
    let max_entries = unsafe { (*buf).reserved.len() } / entry_size;
    let reserved_ptr = unsafe { (*buf).reserved.as_mut_ptr() } as *mut MmsrvReservationEntry;

    let mut count = 0usize;
    for (_, reservation) in unsafe { vm.iter_reservations() } {
        if count >= max_entries {
            break;
        }
        let entry = MmsrvReservationEntry {
            base: reservation.base,
            length: reservation.length,
            owner_badge: reservation.owner_badge,
            kind: reservation.kind as u32,
            _reserved: 0,
        };
        unsafe { core::ptr::write(reserved_ptr.add(count), entry) };
        count += 1;
    }
    send_reply(buf, TRONA_OK, &[count as u64], 0);
}
