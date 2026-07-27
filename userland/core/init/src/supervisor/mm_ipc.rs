// SPDX-License-Identifier: GPL-2.0-only
//
//! mmsrv IPC wire helpers — the single point where init formats every
//! `MM_*` request and parses the reply. All callers go through these
//! helpers so the wire format and reply handling live in one place; if
//! the protocol grows a field, only this file changes.
//!
//! Two MP endpoints are involved:
//!
//! * Admin tier (init → mmsrv master service-EP) — driven on control
//!   capabilities, not a shared badge. `MM_REGISTER_CLIENT` is authorized
//!   by the per-server ROOT control cap (`mmsrv_root_control_cap`); every
//!   other admin verb (`MM_REGISTER_FAULT_PIPE`, `MM_FORK_VSPACE`,
//!   `MM_STAGE_IMAGE_REGION`, `MM_BEGIN/COMMIT/ABORT_EXEC_REPLACE`,
//!   `MM_DEREGISTER_CLIENT`) is driven on the per-client control cap
//!   resolved by `mmsrv_control_addr`. Two-operand verbs (fork, cross-client
//!   stage) use a two-step invoke (`*_SET_PARTNER` then operate).
//!
//! * `state.caps.mmsrv_self_mp` — init's own per-client request MP
//!   send. The send cap is unbadged; mmsrv maps the recv-side Watch
//!   cookie back to init's `client_id`. Serves the self-only labels
//!   init uses when it pre-stages anon regions in its own VSpace
//!   before splicing into a child (`MM_MMAP`, `MM_MUNMAP`).

use trona_kernel::core_types::{CapRef, TronaMsg};
use trona_kernel::{invoke, ipc};
use trona_runtime::core::slot_alloc::OwnedCap;
use uapi::{KERNITE_CAP_SELF_CSPACE, KERNITE_OK, KERNITE_RIGHT_ALL};

use crate::supervisor::SupervisorState;
use crate::supervisor::control_ipc::{admin_call, admin_call_with_caps, two_step_admin};

/// Copy a retained cap from init's CSpace into a freshly-allocated
/// transient slot. IPC cap sends MOVE the staged source slot, so callers
/// use this only for caps init must keep after the request returns.
fn copy_to_transient(src: CapRef, label: &[u8]) -> Result<u64, i32> {
    let temp = trona_runtime::core::slot_alloc::alloc_slot_or_idle(label);
    let r = invoke::cnode_copy_ref(
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        src,
        CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
        temp.borrow(),
        KERNITE_RIGHT_ALL as u64,
    );
    if r != 0 {
        // copy failed: `temp` is still empty — its OwnedSlot Drop frees the slot.
        return Err(r);
    }
    // Hand the now-filled slot to the caller (raw); `release_transient` reclaims it.
    Ok(temp.into_raw())
}

/// # Safety
/// `slot` is a transient cap slot the caller solely owns (e.g. a
/// `copy_to_transient` result); it is torn down and its index freed once here.
unsafe fn release_transient(slot: u64) {
    // SAFETY: exclusive ownership of `slot` is the caller's obligation per this
    // fn's `# Safety`.
    unsafe { trona_runtime::core::slot_alloc::delete_and_free(slot) };
}
// ---------------------------------------------------------------------------
// MM_* labels.
// ---------------------------------------------------------------------------

/// init-only: register a fresh client with mmsrv. mmsrv arms a Watch
/// over `request_mp_recv`'s STATE_READABLE on its service EQ.
pub const MM_REGISTER_CLIENT: u64 = 0x400;
/// init-only: drop every per-client region / VSpace / fault MP.
pub const MM_DEREGISTER_CLIENT: u64 = 0x401;
/// init-only: COW-fork the parent's anon regions into the child.
pub const MM_FORK_VSPACE: u64 = 0x402;
/// init-only: register a per-TCB fault MP recv side. Cookie =
/// `(client_id<<32 | tcb_id)`.
pub const MM_REGISTER_FAULT_PIPE: u64 = 0x403;
/// init-only: cross-VSpace ELF/PE byte staging — share a staging anon
/// region's MO from `src_client_id` into `dst_client_id` at `dst_va`.
pub const MM_STAGE_IMAGE_REGION: u64 = trona_protocol::mm::MM_STAGE_IMAGE_REGION;
/// init-only: open exec transaction. Reply.regs[0] = `txn_id`.
pub const MM_BEGIN_EXEC_REPLACE: u64 = 0x405;
/// init-only: atomic VSpace swap + pre-exec region teardown.
pub const MM_COMMIT_EXEC_REPLACE: u64 = 0x406;
/// init-only: discard staged image, leave client on pre-exec image.
pub const MM_ABORT_EXEC_REPLACE: u64 = 0x407;

/// self-only: anon mmap into caller's own VSpace. Reply: `(va_base,
/// region_id_idx, region_id_epoch)`.
pub const MM_MMAP: u64 = 0x410;
/// self-only: tear down a previously-mmaped range.
pub const MM_MUNMAP: u64 = 0x411;
/// self-only: commit/map an existing lazy range in the caller's own VSpace.
pub const MM_PREFAULT_RANGE: u64 = trona_protocol::mm::MM_PREFAULT_RANGE;
/// self-only: record a reserved VA range in the caller's own ClientVm so
/// mmsrv's gap allocator and FIXED-mmap path avoid it.
pub const MM_RESERVE_RANGE: u64 = trona_protocol::mm::MM_RESERVE_RANGE;
/// self-only: drop a previously reserved VA range.
#[allow(dead_code)]
pub const MM_UNRESERVE_RANGE: u64 = trona_protocol::mm::MM_UNRESERVE_RANGE;

// ---------------------------------------------------------------------------
// MM_MMAP / MM_STAGE_IMAGE_REGION argument constants.
// ---------------------------------------------------------------------------

/// `MM_MMAP` `kind` argument: anonymous private mapping.
pub const MMAP_KIND_ANON: u64 = 0;
/// `MM_MMAP` `kind` argument: anonymous user stack mapping.
pub const MMAP_KIND_ANON_STACK: u64 = trona_protocol::mm::MMAP_KIND_ANON_STACK;

/// POSIX-style protection bits accepted by `MM_MMAP` /
/// `MM_STAGE_IMAGE_REGION`.
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;

/// `MM_STAGE_IMAGE_REGION` flags bit 0 — landing region goes into the
/// destination client's pending exec VSpace instead of the active one.
pub const STAGE_FLAG_EXEC_TXN: u64 = trona_protocol::mm::STAGE_FLAG_EXEC_TXN;
/// `MM_STAGE_IMAGE_REGION` flags bit 1 — destination VMA is a user stack.
/// mmsrv preserves this in its RegionTable so kernel
/// `TCB_SET_STACK_BOUNDS` can validate the stack mapping.
pub const STAGE_FLAG_STACK: u64 = trona_protocol::mm::STAGE_FLAG_STACK;
/// Bit shift for `txn_id` packed into the upper 32 bits of the flags
/// word.
pub const STAGE_FLAG_TXN_ID_SHIFT: u32 = trona_protocol::mm::STAGE_FLAG_TXN_ID_SHIFT;
/// Stack guard width (pages) packed into the `MM_STAGE_IMAGE_REGION`
/// flags word, bits `[15:8]` — only meaningful with `STAGE_FLAG_STACK`.
/// The loader packs its planned `guard_pages` here so mmsrv reserves a
/// matching-width guard band below the staged stack.
pub const STAGE_GUARD_PAGES_SHIFT: u32 = trona_protocol::mm::STAGE_GUARD_PAGES_SHIFT;
pub const STAGE_GUARD_PAGES_MASK: u64 = trona_protocol::mm::STAGE_GUARD_PAGES_MASK;

/// `MM_STAGE_IMAGE_REGION` `regs[9]` image-kind tags. Each selects the
/// destination region type and `BackingDescriptor`: TEXT / RODATA install a
/// shared image MO (inherited read-only on fork), DATA installs a writable
/// image region (copy-on-write on fork), and NONE is a plain anonymous
/// mapping. The loader folds every bss tail into its enclosing writable run
/// (runs always satisfy `file_size == mem_size`), so init never stages a
/// standalone bss region and `STAGE_IMAGE_KIND_BSS` is not re-exported here.
pub const STAGE_IMAGE_KIND_NONE: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_NONE;
pub const STAGE_IMAGE_KIND_TEXT: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_TEXT;
pub const STAGE_IMAGE_KIND_DATA: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_DATA;
pub const STAGE_IMAGE_KIND_RODATA: u64 = trona_protocol::mm::STAGE_IMAGE_KIND_RODATA;

/// Derive the `MM_STAGE_IMAGE_REGION` image-kind tag from a run's POSIX
/// protection bits. `PROT_WRITE` takes precedence over `PROT_EXEC`, so a
/// writable run is always DATA (copy-on-write on fork) and never the
/// read-only-shared TEXT — sharing a writable run across fork would let
/// parent and child alias each other's writes. Read-only non-executable
/// runs become RODATA.
pub fn image_kind_from_prot(prot: u64) -> u64 {
    if prot & PROT_WRITE != 0 {
        STAGE_IMAGE_KIND_DATA
    } else if prot & PROT_EXEC != 0 {
        STAGE_IMAGE_KIND_TEXT
    } else {
        STAGE_IMAGE_KIND_RODATA
    }
}

// ---------------------------------------------------------------------------
// Helpers — admin-tier entry points resolve the target client's control cap
// via `mmsrv_control_addr` and invoke it (authorization + target identity in
// one); self-only helpers call on `mmsrv_self_mp`. The endpoint choice is
// fixed per helper to reflect the wire-protocol definition.
// ---------------------------------------------------------------------------

/// Step-1 label for the two-step fork verb (pin the child secondary).
pub const MM_FORK_SET_PARTNER: u64 = trona_protocol::mm::MM_FORK_SET_PARTNER;
/// Step-1 label for the two-step cross-client stage verb (pin the source).
pub const MM_STAGE_SET_SOURCE: u64 = trona_protocol::mm::MM_STAGE_SET_SOURCE;

/// Resolve a `client_id` to the raw addr of its mmsrv control cap. Covers
/// init's own self-registration, the two core servers init drives mmsrv
/// admin verbs on (namesrv / rsrcsrv fault-pipe registration), and every
/// per-client `ProcessRecord`. Returns 0 when unknown.
fn mmsrv_control_addr(state: &SupervisorState, client_id: u32) -> u64 {
    let caps = &state.caps;
    let cap = if client_id == caps.init_client_id {
        caps.mmsrv_self_control_cap.as_ref()
    } else if client_id == caps.namesrv_client_id {
        caps.namesrv_mmsrv_control_cap.as_ref()
    } else if client_id == caps.rsrcsrv_client_id {
        caps.rsrcsrv_mmsrv_control_cap.as_ref()
    } else {
        state
            .procs
            .find_by_client_id_any(client_id)
            .and_then(|p| p.mmsrv_control_cap.as_ref())
    };
    cap.map(OwnedCap::borrow).unwrap_or_default().addr()
}

fn self_call(state: &SupervisorState, msg: &TronaMsg, reply: &mut TronaMsg) -> Result<(), i32> {
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx,
            state
                .caps
                .mmsrv_self_mp
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr(),
            msg as *const _,
            reply as *mut _,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(err);
    }
    if reply.label != KERNITE_OK as u64 {
        return Err(reply.label as i32);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Admin-tier: init-only labels.
// ---------------------------------------------------------------------------

/// `MM_REGISTER_CLIENT(client_id, pid, layout; caps=[vspace, request_mp_recv?,
/// request_mp_send?])`. The 12-field `VmClientLayout` is unpacked into
/// `regs[2..14]` — heap_base, heap_limit, mmap_base, mmap_limit, dso_base,
/// dso_limit, elf_code_base, elf_code_limit, interpreter_base,
/// interpreter_limit, preloaded_base, preloaded_limit. mmsrv's
/// `ClientState::layout` stores it as one field, and the three image
/// windows let mmsrv validate subsequent staging runs against the same
/// plan the loader used.
///
/// `vspace_cap` and `request_mp_send` are retained by init, so this helper
/// sends transient copies. `request_mp_recv` is consumed: mmsrv becomes its
/// sole owner and init releases the emptied source slot after the send.
#[allow(clippy::too_many_arguments)]
pub fn mm_register_client(
    state: &SupervisorState,
    client_id: u32,
    pid: u32,
    vspace_cap: CapRef,
    request_mp_recv: Option<OwnedCap>,
    request_mp_send: Option<CapRef>,
    layout: trona_runtime::spawn::layout::VmClientLayout,
) -> Result<OwnedCap, i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_REGISTER_CLIENT;
    msg.length = 14;
    msg.regs[0] = client_id as u64;
    msg.regs[1] = pid as u64;
    msg.regs[2] = layout.heap_base;
    msg.regs[3] = layout.heap_limit;
    msg.regs[4] = layout.mmap_base;
    msg.regs[5] = layout.mmap_limit;
    msg.regs[6] = layout.dso_base;
    msg.regs[7] = layout.dso_limit;
    msg.regs[8] = layout.elf_code_base;
    msg.regs[9] = layout.elf_code_limit;
    msg.regs[10] = layout.interpreter_base;
    msg.regs[11] = layout.interpreter_limit;
    msg.regs[12] = layout.preloaded_base;
    msg.regs[13] = layout.preloaded_limit;

    let vspace_temp = copy_to_transient(vspace_cap, b"mm_register_client vspace transfer")?;
    // A self-tier send cap is meaningful only when mmsrv also receives the
    // matching recv side to watch. Core services registered before their
    // self-tier endpoint exists pass neither cap.
    if request_mp_recv.is_none() && request_mp_send.is_some() {
        // SAFETY: vspace_temp is the transient copy_to_transient minted above,
        // solely owned here.
        unsafe { release_transient(vspace_temp) };
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }

    let request_mp_recv = request_mp_recv.map(OwnedCap::into_transfer);
    let send_temp = if let Some(send) = request_mp_send {
        match copy_to_transient(send, b"mm_register_client request_mp_send transfer") {
            Ok(s) => s,
            Err(e) => {
                // SAFETY: vspace_temp is the transient minted above, solely owned.
                unsafe { release_transient(vspace_temp) };
                return Err(e);
            }
        }
    } else {
        0
    };

    let mut caps_full = [0u64; 3];
    caps_full[0] = vspace_temp;
    let mut cap_count = 1usize;
    if let Some(recv) = request_mp_recv.as_ref() {
        caps_full[cap_count] = recv.slot();
        cap_count += 1;
        if send_temp != 0 {
            caps_full[cap_count] = send_temp;
            cap_count += 1;
        }
    }
    let caps = &caps_full[..cap_count];
    let mut reply = TronaMsg::zeroed();
    // Register is authorized by the per-server ROOT control cap; mmsrv mints
    // this client's control cap and returns it in the reply's caps[0].
    let root = state
        .caps
        .mmsrv_root_control_cap
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    let Some(recv) = trona_runtime::core::slot_alloc::alloc_slot() else {
        // SAFETY: the send transients are solely owned here.
        unsafe {
            release_transient(vspace_temp);
            if send_temp != 0 {
                release_transient(send_temp);
            }
        }
        drop(request_mp_recv);
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    };
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    // SAFETY: arm the receive window so the minted control cap lands in `recv`.
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx,
            KERNITE_CAP_SELF_CSPACE as u64,
            recv.addr(),
            0,
        );
    }
    let result = admin_call_with_caps(root, &msg, caps, &mut reply);
    // SAFETY: vspace_temp / send_temp are transients copy_to_transient minted
    // above, solely owned here; freed once after the call returns. The moved
    // recv cap is reclaimed by TransferCap::drop below.
    unsafe {
        release_transient(vspace_temp);
        if send_temp != 0 {
            release_transient(send_temp);
        }
    }
    drop(request_mp_recv);
    match result {
        Ok(()) => {
            // The reply moved the control cap into `recv`; adopt it (preserving
            // invoke depth). `into_raw` forgets the OwnedSlot so the OwnedCap is
            // the sole owner of the slot.
            let raw = recv.into_raw();
            Ok(unsafe { OwnedCap::adopt_received(raw) })
        }
        // No cap received; `recv` (OwnedSlot) drops here, freeing the slot.
        Err(e) => Err(e),
    }
}

/// `MM_DEREGISTER_CLIENT(client_id)` — best-effort teardown notice.
/// Exit finalization must not wait for mmsrv's cleanup work; the
/// handler only replies when the request arrived as an `MP_CALL`.
pub fn mm_deregister_client(state: &SupervisorState, client_id: u32) {
    let endpoint = mmsrv_control_addr(state, client_id);
    if endpoint == 0 {
        return;
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_DEREGISTER_CLIENT;
    msg.length = 0;
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    let _ = unsafe { ipc::mp_write_ctx(ipc_ctx, endpoint, &raw const msg) };
}

/// `MM_REGISTER_FAULT_PIPE(client_id, tcb_id; caps=[fault_mp_recv])`.
/// mmsrv arms a Watch with cookie = `(client_id<<32 | tcb_id)` and
/// becomes the recv-side cap owner.
pub fn mm_register_fault_pipe(
    state: &SupervisorState,
    client_id: u32,
    tcb_id: u32,
    fault_mp_recv: OwnedCap,
) -> Result<(), i32> {
    let endpoint = mmsrv_control_addr(state, client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_REGISTER_FAULT_PIPE;
    msg.length = 1;
    msg.regs[0] = tcb_id as u64;
    let fault_mp_recv = fault_mp_recv.into_transfer();
    let caps = [fault_mp_recv.slot()];
    let mut reply = TronaMsg::zeroed();
    let result = admin_call_with_caps(endpoint, &msg, &caps, &mut reply);
    drop(fault_mp_recv);
    result
}

/// `MM_FORK_VSPACE(parent_client_id, child_client_id, exclude_count;
/// regs[3..3+exclude_count] = exclude_vas)`. Both clients must already
/// be registered. mmsrv walks parent's anon regions and issues
/// `KERNITE_INV_VSPACE_FORK_RANGE` per region, skipping any region
/// whose VA appears in the exclude list — used to keep the child's
/// cap-table region (mapped at `CHILD_CAP_TABLE_VA`) out of the COW
/// inherit so init can re-stage a fresh frame in the same slot.
pub fn mm_fork_vspace(
    state: &SupervisorState,
    parent_client_id: u32,
    child_client_id: u32,
    exclude_vas: &[u64],
) -> Result<(), i32> {
    let parent_addr = mmsrv_control_addr(state, parent_client_id);
    let child_addr = mmsrv_control_addr(state, child_client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_FORK_VSPACE;
    // regs[0] = nonce (filled by `two_step_admin`); regs[1] = exclude_count;
    // regs[2..2+count] = exclude_vas.
    msg.regs[1] = exclude_vas.len() as u64;
    let max_exclude = msg.regs.len().saturating_sub(2);
    let n = exclude_vas.len().min(max_exclude);
    for (i, &va) in exclude_vas.iter().take(n).enumerate() {
        msg.regs[2 + i] = va;
    }
    msg.length = (2 + n) as u64;
    let mut reply = TronaMsg::zeroed();
    // The child is the secondary (`MM_FORK_SET_PARTNER`); the parent is the
    // primary (operate) — matching mmsrv resolving parent from the invoked
    // badge and child from the consumed pending partner.
    two_step_admin(
        child_addr,
        parent_addr,
        MM_FORK_SET_PARTNER,
        &mut msg,
        &mut reply,
    )
}

/// `MM_STAGE_IMAGE_REGION(src_client_id, src_region_id_packed,
/// dst_client_id, dst_va, src_offset, file_size, mem_size, prot,
/// region_kind, flags)` — share an mmsrv-managed staging anon region
/// from `src_client_id` into `dst_client_id`'s VSpace at `dst_va`.
/// mmsrv looks up the source region by packed `RegionId`, extracts its
/// `Anon { mo_cap, mo_offset }` backing, and installs an MO at the
/// destination via `KERNITE_INV_VSPACE_MAP_MO`. `region_kind` (a
/// `STAGE_IMAGE_KIND_*` tag) selects the destination region's type and
/// `BackingDescriptor`, which in turn drives fork inheritance — image
/// text/rodata are shared read-only, image data copies on write, and
/// `NONE` is a plain anon mapping. The source MO refcount is bumped so
/// the staging caller may safely `MM_MUNMAP` the source region after
/// the splice.
#[allow(clippy::too_many_arguments)]
pub fn mm_stage_image_region(
    state: &SupervisorState,
    src_client_id: u32,
    src_region_id_packed: u64,
    dst_client_id: u32,
    dst_va: u64,
    src_offset: u64,
    file_size: u64,
    mem_size: u64,
    prot: u64,
    region_kind: u64,
    flags: u64,
) -> Result<(), i32> {
    let dst_addr = mmsrv_control_addr(state, dst_client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_STAGE_IMAGE_REGION;
    msg.length = 10;
    // regs[0] = nonce (cross-client two-step) or unused (EXEC_MO_SRC); regs[2]
    // (the former dst_client_id) is unused — dst comes from the invoked badge.
    msg.regs[1] = src_region_id_packed;
    msg.regs[3] = dst_va;
    msg.regs[4] = src_offset;
    msg.regs[5] = file_size;
    msg.regs[6] = mem_size;
    msg.regs[7] = prot;
    msg.regs[8] = flags;
    msg.regs[9] = region_kind;
    let mut reply = TronaMsg::zeroed();
    if flags & trona_protocol::mm::STAGE_FLAG_EXEC_MO_SRC != 0 {
        // The source is the held exec MO — no source *client*, so a single
        // invoke on the destination control cap.
        admin_call(dst_addr, &msg, &mut reply)
    } else {
        // Cross-client: pin the source client (`MM_STAGE_SET_SOURCE`) then
        // operate on the destination control cap.
        let src_addr = mmsrv_control_addr(state, src_client_id);
        two_step_admin(
            src_addr,
            dst_addr,
            MM_STAGE_SET_SOURCE,
            &mut msg,
            &mut reply,
        )
    }
}

/// `MM_STAGE_IMAGE_REGION` variant that targets a client's
/// `pending_exec` VSpace instead of the active one. The caller
/// passes the `txn_id` returned by `mm_begin_exec_replace`.
#[allow(clippy::too_many_arguments)]
pub fn mm_stage_image_region_exec(
    state: &SupervisorState,
    src_client_id: u32,
    src_region_id_packed: u64,
    dst_client_id: u32,
    dst_va: u64,
    src_offset: u64,
    file_size: u64,
    mem_size: u64,
    prot: u64,
    region_kind: u64,
    txn_id: u64,
) -> Result<(), i32> {
    mm_stage_image_region_exec_flags(
        state,
        src_client_id,
        src_region_id_packed,
        dst_client_id,
        dst_va,
        src_offset,
        file_size,
        mem_size,
        prot,
        region_kind,
        txn_id,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn mm_stage_image_region_exec_flags(
    state: &SupervisorState,
    src_client_id: u32,
    src_region_id_packed: u64,
    dst_client_id: u32,
    dst_va: u64,
    src_offset: u64,
    file_size: u64,
    mem_size: u64,
    prot: u64,
    region_kind: u64,
    txn_id: u64,
    extra_flags: u64,
) -> Result<(), i32> {
    let exec_flags = (txn_id << STAGE_FLAG_TXN_ID_SHIFT) | STAGE_FLAG_EXEC_TXN | extra_flags;
    mm_stage_image_region(
        state,
        src_client_id,
        src_region_id_packed,
        dst_client_id,
        dst_va,
        src_offset,
        file_size,
        mem_size,
        prot,
        region_kind,
        exec_flags,
    )
}

/// `MM_STAGE_IMAGE_REGION` variant sourcing a run from a caller-provided code
/// MemoryObject (`STAGE_FLAG_PROVIDED_MO`), transferred as `caps[0]`. A single
/// admin invoke on the destination control cap (no cross-client partner step),
/// so the run lands in the client's live VSpace; `extra_flags` adds
/// `STAGE_FLAG_EXEC_MATERIALIZE` for a private / zero-fill run and
/// `STAGE_FLAG_EXEC_TXN | txn_id << SHIFT` when the run instead lands in a
/// pending exec VSpace (an execve interpreter). mmsrv captures the transferred
/// cap and mints an attenuated (`R-X` text / `R--` rodata) per-run alias into
/// the region, so EXECUTE is never re-conferred here — only narrowed.
#[allow(clippy::too_many_arguments)]
pub fn mm_stage_image_region_provided_flags(
    state: &SupervisorState,
    dst_client_id: u32,
    code_mo: CapRef,
    dst_va: u64,
    src_offset: u64,
    file_size: u64,
    mem_size: u64,
    prot: u64,
    region_kind: u64,
    extra_flags: u64,
) -> Result<(), i32> {
    let dst_addr = mmsrv_control_addr(state, dst_client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_STAGE_IMAGE_REGION;
    msg.length = 10;
    msg.regs[3] = dst_va;
    msg.regs[4] = src_offset;
    msg.regs[5] = file_size;
    msg.regs[6] = mem_size;
    msg.regs[7] = prot;
    msg.regs[8] = trona_protocol::mm::STAGE_FLAG_PROVIDED_MO | extra_flags;
    msg.regs[9] = region_kind;
    // Stage a fresh copy of the code MO as caps[0]; the transfer moves the copy
    // into mmsrv (which dups an attenuated alias for the region and drops it),
    // so a per-run copy is consumed each call and the retained cap is untouched.
    let transient = copy_to_transient(code_mo, b"mm_stage_provided code mo transfer")?;
    let caps = [transient];
    let mut reply = TronaMsg::zeroed();
    let result = admin_call_with_caps(dst_addr, &msg, &caps, &mut reply);
    // SAFETY: `transient` is the copy_to_transient mint just above, solely owned
    // here; released whether or not the call succeeded.
    unsafe { release_transient(transient) };
    result
}

/// `MM_BEGIN_EXEC_REPLACE(client_id_from_badge, layout; caps=[new_vspace,
/// exec_mo])` — open an exec transaction. Reply: `(txn_id)`.
///
/// `layout` is the new image's planned layout, derived by `compute_vm_layout`
/// from the new image's geometry before this call. mmsrv stores it as
/// `PendingExecVm.pending_layout` and atomically swaps it into
/// `ClientState.layout` on commit (exec commit swaps layout and
/// address space together atomically). The three image windows
/// (`elf_code_*`, `interpreter_*`, `preloaded_*`) ride along so mmsrv
/// can validate staged regions against the planned image windows
/// during the transaction.
///
/// `new_vspace_cap` is copied into a transient slot before the move —
/// `exec_in_place` still uses the cap for `TCB_SET_SPACE` after commit.
/// `exec_mo_cap` is the exec source MemoryObject mmsrv stages the image's
/// segments from and holds for the transaction; the copy is rights-
/// preserving (cnode_copy diminishes, never escalates) and is only possible
/// because the exec MO holds GRANT — the kernel gates cnode_copy on it.
#[allow(clippy::too_many_arguments)]
pub fn mm_begin_exec_replace(
    state: &SupervisorState,
    client_id: u32,
    new_vspace_cap: CapRef,
    exec_mo_cap: CapRef,
    layout: trona_runtime::spawn::layout::VmClientLayout,
) -> Result<u64, i32> {
    let endpoint = mmsrv_control_addr(state, client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_BEGIN_EXEC_REPLACE;
    msg.length = 12;
    msg.regs[0] = layout.heap_base;
    msg.regs[1] = layout.heap_limit;
    msg.regs[2] = layout.mmap_base;
    msg.regs[3] = layout.mmap_limit;
    msg.regs[4] = layout.dso_base;
    msg.regs[5] = layout.dso_limit;
    msg.regs[6] = layout.elf_code_base;
    msg.regs[7] = layout.elf_code_limit;
    msg.regs[8] = layout.interpreter_base;
    msg.regs[9] = layout.interpreter_limit;
    msg.regs[10] = layout.preloaded_base;
    msg.regs[11] = layout.preloaded_limit;
    let vspace_temp = copy_to_transient(new_vspace_cap, b"mm_begin_exec_replace vspace transfer")?;
    let exec_mo_temp =
        match copy_to_transient(exec_mo_cap, b"mm_begin_exec_replace exec mo transfer") {
            Ok(t) => t,
            Err(e) => {
                // SAFETY: vspace_temp is the transient minted just above, solely
                // owned here; released on this error path before returning.
                unsafe { release_transient(vspace_temp) };
                return Err(e);
            }
        };
    let caps = [vspace_temp, exec_mo_temp];
    let mut reply = TronaMsg::zeroed();
    let result = admin_call_with_caps(endpoint, &msg, &caps, &mut reply);
    // SAFETY: both transients are copy_to_transient mints above, solely owned
    // here.
    unsafe {
        release_transient(vspace_temp);
        release_transient(exec_mo_temp);
    }
    result?;
    Ok(reply.regs[0])
}

/// `MM_COMMIT_EXEC_REPLACE(client_id, txn_id)` — atomic VSpace swap
/// followed by pre-exec region teardown.
pub fn mm_commit_exec_replace(
    state: &SupervisorState,
    client_id: u32,
    txn_id: u64,
) -> Result<(), i32> {
    let endpoint = mmsrv_control_addr(state, client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_COMMIT_EXEC_REPLACE;
    msg.length = 1;
    msg.regs[0] = txn_id;
    let mut reply = TronaMsg::zeroed();
    admin_call(endpoint, &msg, &mut reply)
}

/// `MM_ABORT_EXEC_REPLACE(client_id, txn_id)` — drop the staged
/// image and leave the client on its pre-exec VSpace.
pub fn mm_abort_exec_replace(
    state: &SupervisorState,
    client_id: u32,
    txn_id: u64,
) -> Result<(), i32> {
    let endpoint = mmsrv_control_addr(state, client_id);
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_ABORT_EXEC_REPLACE;
    msg.length = 1;
    msg.regs[0] = txn_id;
    let mut reply = TronaMsg::zeroed();
    admin_call(endpoint, &msg, &mut reply)
}

// ---------------------------------------------------------------------------
// Self-tier: init's own per-client labels (issued on `mmsrv_self_mp`).
// ---------------------------------------------------------------------------

/// `MM_MO_CREATE(length, flags) -> caps=[mo_cap]` — create a fresh
/// anonymous MemoryObject in mmsrv and return its cap into a slot init
/// owns. The MO has no pager backing; init can mmap it with
/// [`mm_mmap_mo_self`] to write into it.
///
/// Init never goes through `trona_runtime::client::mm::mo_create` —
/// that path resolves `mmsrv_ep()` from the runtime weak symbol,
/// which is 0 for init (init's mmsrv endpoint is its own
/// `state.caps.mmsrv_self_mp`, not a published service-EP cap). This
/// wrapper issues the request on init's self-tier MP, the same way
/// `mm_mmap_self` / `mm_munmap_self` do.
pub fn mm_mo_create_self(
    state: &SupervisorState,
    length: u64,
    flags: u64,
) -> Result<OwnedCap, i32> {
    let mo_slot = trona_runtime::core::slot_alloc::alloc_slot()
        .ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;
    let mut msg = TronaMsg::zeroed();
    msg.label = trona_protocol::mm::MM_MO_CREATE;
    msg.regs[0] = length;
    msg.regs[1] = flags;
    msg.length = 2;
    let mut reply = TronaMsg::zeroed();
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    // SAFETY: arm the receive window so mmsrv's reply cap lands in `mo_slot`.
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx,
            KERNITE_CAP_SELF_CSPACE as u64,
            mo_slot.addr(),
            0,
        );
    }
    let result = self_call(state, &msg, &mut reply);
    // Restore no arm on the receive window — owner-loop's sticky recv-scratch
    // re-arms on every iteration; if init exits between here and the next
    // owner-loop call, the in-flight read will pick up a fresh arm.
    if result.is_err() {
        // mo_slot is still empty (no cap moved in); its OwnedSlot Drop frees
        // the slot.
        return Err(result.unwrap_err());
    }
    Ok(mo_slot.assume_filled())
}

/// `MM_MMAP(kind=MMAP_KIND_MO, hint, size, prot, mo_offset, flags; caps=[mo_cap])`
/// — map a caller-supplied MO into init's own VSpace. `hint == 0` lets
/// mmsrv auto-place; a non-zero `hint` is `MM_FLAG_FIXED`. `mo_cap`
/// is consumed by the send (kernel `take_ref`); init no longer holds
/// it after this call returns. Returns the mapped VA.
pub fn mm_mmap_mo_self(
    state: &SupervisorState,
    mo_cap: OwnedCap,
    size: u64,
    prot: u64,
    mo_offset: u64,
    fixed: bool,
) -> Result<u64, i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_MMAP;
    msg.length = 6;
    msg.regs[0] = trona_protocol::mm::MMAP_KIND_MO;
    msg.regs[1] = 0; // hint — auto-place
    msg.regs[2] = size;
    msg.regs[3] = prot;
    msg.regs[4] = if fixed {
        trona_protocol::mm::MM_FLAG_FIXED
    } else {
        0
    };
    msg.regs[5] = mo_offset;
    let transfer = mo_cap.into_transfer();
    let mut reply = TronaMsg::zeroed();
    let ipc_ctx = trona_runtime::current_ipc_ctx();
    // SAFETY: `transfer.slot()` is the freshly-minted MO cap (OwnedCap moved
    // into TransferCap above); the kernel takes it on `mp_call` success.
    unsafe { trona_kernel::ipc::set_send_cap_ctx(ipc_ctx, 0, transfer.slot()) };
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ipc_ctx,
            state
                .caps
                .mmsrv_self_mp
                .as_ref()
                .map(OwnedCap::borrow)
                .unwrap_or_default()
                .addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    // Drop the TransferCap regardless — on success the cap was moved into
    // mmsrv (slot is now empty), on failure the cap is still in the slot
    // and Drop deletes + frees it.
    drop(transfer);
    unsafe { trona_kernel::ipc::clear_send_caps_ctx(ipc_ctx) };
    if err != 0 {
        return Err(err);
    }
    if reply.label != KERNITE_OK as u64 {
        return Err(reply.label as i32);
    }
    Ok(reply.regs[0])
}

/// `MM_MMAP(kind, hint, size, prot, flags)` — anon mmap into init's
/// own VSpace. Returns `(va_base, packed_region_id)` where
/// `packed_region_id = (epoch << 32) | (idx & 0xFFFF_FFFF)`.
pub fn mm_mmap_self(
    state: &SupervisorState,
    kind: u64,
    hint: u64,
    size: u64,
    prot: u64,
    flags: u64,
) -> Result<(u64, u64), i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_MMAP;
    msg.length = 5;
    msg.regs[0] = kind;
    msg.regs[1] = hint;
    msg.regs[2] = size;
    msg.regs[3] = prot;
    msg.regs[4] = flags;
    let mut reply = TronaMsg::zeroed();
    self_call(state, &msg, &mut reply)?;
    let va_base = reply.regs[0];
    let idx = reply.regs[1];
    let epoch = reply.regs[2];
    let packed = (epoch << 32) | (idx & 0xFFFF_FFFF);
    Ok((va_base, packed))
}

/// `MM_PREFAULT_RANGE(va, size, prot_hint)` — commit and present-map an
/// existing lazy range in init's own VSpace. Returns an error unless mmsrv
/// reports that every requested page was mapped, so callers never bulk-touch a
/// partially resident scratch window.
pub fn mm_prefault_self_exact(
    state: &SupervisorState,
    va: u64,
    size: u64,
    prot_hint: u64,
) -> Result<(), i32> {
    if size == 0 {
        return Ok(());
    }
    let page_bytes = uapi::KERNITE_PAGE_BYTES as u64;
    if va & (page_bytes - 1) != 0 || size & (page_bytes - 1) != 0 {
        return Err(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    if va.checked_add(size).is_none() {
        return Err(uapi::KERNITE_ERR_OUT_OF_RANGE as i32);
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = MM_PREFAULT_RANGE;
    msg.length = 3;
    msg.regs[0] = va;
    msg.regs[1] = size;
    msg.regs[2] = prot_hint;
    let mut reply = TronaMsg::zeroed();
    self_call(state, &msg, &mut reply)?;

    let expected_pages = size / page_bytes;
    if reply.regs[0] != expected_pages {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    Ok(())
}

/// `MM_MUNMAP(va, size)` — tear down a previously-mmaped range in
/// init's VSpace. The MO survives if any other VSpace still holds a
/// mapping.
pub fn mm_munmap_self(state: &SupervisorState, va: u64, size: u64) -> Result<(), i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_MUNMAP;
    msg.length = 2;
    msg.regs[0] = va;
    msg.regs[1] = size;
    let mut reply = TronaMsg::zeroed();
    self_call(state, &msg, &mut reply)
}

/// `MM_RESERVE_RANGE(base, length, kind)` — fence a VA range in init's
/// own ClientVm. `kind` is a
/// [`ReservationKind`](trona_server::slab::ReservationKind) discriminant.
/// Used at boot to protect init's directly-mapped arena windows from
/// mmsrv's allocator.
pub fn mm_reserve_range(
    state: &SupervisorState,
    base: u64,
    length: u64,
    kind: u64,
) -> Result<(), i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_RESERVE_RANGE;
    msg.length = 3;
    msg.regs[0] = base;
    msg.regs[1] = length;
    msg.regs[2] = kind;
    let mut reply = TronaMsg::zeroed();
    self_call(state, &msg, &mut reply)
}

/// `MM_UNRESERVE_RANGE(base, length)` — drop a prior reservation in
/// init's own ClientVm.
#[allow(dead_code)]
pub fn mm_unreserve_range(state: &SupervisorState, base: u64, length: u64) -> Result<(), i32> {
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_UNRESERVE_RANGE;
    msg.length = 2;
    msg.regs[0] = base;
    msg.regs[1] = length;
    let mut reply = TronaMsg::zeroed();
    self_call(state, &msg, &mut reply)
}
