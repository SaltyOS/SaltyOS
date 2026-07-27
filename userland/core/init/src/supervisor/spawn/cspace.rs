// SPDX-License-Identifier: GPL-2.0-only
//
//! Child CSpace seeding and cap-table delivery.
//!
//! Every spawned process expects three classes of cap to be reachable
//! at its first instruction:
//!
//! 1. **Self caps** at the well-known slots
//!    `KERNITE_CAP_SELF_TCB / VSPACE / CSPACE` (slots 0/1/2). These
//!    let substrate's syscall path resolve `self` without walking
//!    auxv.
//! 2. **System caps** — `KernelRng / Clock / SystemControl /
//!    SystemInfo / KernelDebug` — at substrate-recognised slots,
//!    cross-referenced by the cap table.
//! 3. **Service-specific caps** — server endpoints, signal pipes,
//!    badged client MPs, watch slabs, fault MP send sides, etc.,
//!    indexed by `role_id` in the cap table.
//!
//! The cap table itself is a `SaltyOSCapTableV1` written into a frame
//! mapped read-only at `CHILD_CAP_TABLE_VA` in the child VSpace. Each
//! entry records `(role_id → child_cspace_slot)`; the child resolves
//! a role at runtime by walking the table.
//!
//! Critical invariant: every entry in the cap table references a slot
//! that init has actually populated via `cnode_copy / cnode_mint /
//! cnode_move`. The previous `populate_cap_table` only stamped slot
//! numbers but never installed the caps; this module corrects that.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::spawn::cap_table::{CapTableBuilder, CapTableErr};
use trona_runtime::spawn::role_consts::{
    CAP_TBL_FLAG_RESERVED, ROLE_CLOCK, ROLE_KERNEL_DEBUG, ROLE_KERNEL_RNG, ROLE_SYSTEM_CONTROL,
    ROLE_SYSTEM_INFO,
};
use uapi::{
    KERNITE_CAP_SELF_CSPACE, KERNITE_CAP_SELF_TCB, KERNITE_CAP_SELF_VSPACE, KERNITE_PAGE_BYTES,
    KERNITE_PAGE_FLAG_USER, KERNITE_RIGHT_ALL,
};

use crate::internal_slots::{
    SCRATCH_FRAME_VA, SLOT_SELF_CSPACE, SLOT_SYSCAP_CLOCK, SLOT_SYSCAP_KERNEL_DEBUG,
    SLOT_SYSCAP_KERNEL_RNG, SLOT_SYSCAP_SYSTEM_CONTROL, SLOT_SYSCAP_SYSTEM_INFO,
};
use crate::supervisor::spawn::plan::ChildBundle;
// Cap-table VA: init maps the read-only cap-table frame at the shared
// layout contract's `CHILD_CAP_TABLE_VA` in every child; the child's
// substrate startup reads `AT_SALTYOS_STARTUP` to find it.
use trona_runtime::spawn::layout::CHILD_CAP_TABLE_VA;

/// Page-flag combo used for the read-only cap-table mapping in the
/// child.
const PAGE_FLAGS_R_USER: u64 = KERNITE_PAGE_FLAG_USER as u64;

fn cap_table_err(err: CapTableErr) -> i32 {
    match err {
        CapTableErr::Overflow => uapi::KERNITE_ERR_OUT_OF_MEMORY as i32,
        CapTableErr::SlotOutOfRange => uapi::KERNITE_ERR_OUT_OF_RANGE as i32,
        CapTableErr::DuplicateRole(_) => uapi::KERNITE_ERR_INVALID_ARGUMENT as i32,
    }
}

pub fn push_cap_table_entry(
    builder: &mut CapTableBuilder,
    role_id: u32,
    slot: u64,
    rights: u32,
    flags: u32,
) -> Result<(), i32> {
    builder
        .push(role_id, slot, rights, flags)
        .map_err(cap_table_err)
}

/// Copy `KERNITE_CAP_SELF_TCB / VSPACE / CSPACE` into the child's
/// CNode at slots 0 / 1 / 2. Substrate's startup resolves these by
/// the well-known slot convention before walking auxv, so they MUST
/// be in place before the child starts.
pub fn seed_self_caps(bundle: &ChildBundle) -> Result<(), i32> {
    let self_cspace = CapRef::flat(SLOT_SELF_CSPACE);
    let child_cspace = bundle
        .cspace
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();
    let r = invoke::cnode_copy(
        self_cspace,
        bundle
            .tcb
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr(),
        child_cspace,
        KERNITE_CAP_SELF_TCB as u64,
        KERNITE_RIGHT_ALL as u64,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::cnode_copy(
        self_cspace,
        bundle
            .vspace
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr(),
        child_cspace,
        KERNITE_CAP_SELF_VSPACE as u64,
        KERNITE_RIGHT_ALL as u64,
    );
    if r != 0 {
        return Err(r);
    }
    let r = invoke::cnode_copy(
        self_cspace,
        bundle
            .cspace
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr(),
        child_cspace,
        KERNITE_CAP_SELF_CSPACE as u64,
        KERNITE_RIGHT_ALL as u64,
    );
    if r != 0 {
        return Err(r);
    }
    Ok(())
}

/// Resolve a system role_id to the slot in init's CSpace where the
/// kernel installed it at boot. Returns 0 for unknown roles.
pub fn lookup_system_cap_slot(role: u32) -> u64 {
    match role {
        ROLE_KERNEL_RNG => SLOT_SYSCAP_KERNEL_RNG,
        ROLE_CLOCK => SLOT_SYSCAP_CLOCK,
        ROLE_SYSTEM_CONTROL => SLOT_SYSCAP_SYSTEM_CONTROL,
        ROLE_SYSTEM_INFO => SLOT_SYSCAP_SYSTEM_INFO,
        ROLE_KERNEL_DEBUG => SLOT_SYSCAP_KERNEL_DEBUG,
        _ => 0,
    }
}

/// Copy each system cap (`KernelRng / Clock / SystemControl /
/// SystemInfo / KernelDebug`) from init's CSpace into consecutive
/// slots starting at `dest_base` in the child's CNode, then push the
/// (`role_id → child_slot`) entries into the cap_table builder.
/// Updates `dest_base` past the last slot used so the caller can
/// continue placing service-specific caps without collision.
pub fn place_system_caps(
    child_cnode: CapRef,
    builder: &mut CapTableBuilder,
    dest_base: &mut u64,
) -> Result<(), i32> {
    let self_cspace = CapRef::flat(SLOT_SELF_CSPACE);
    let roles = [
        ROLE_KERNEL_RNG,
        ROLE_CLOCK,
        ROLE_SYSTEM_CONTROL,
        ROLE_SYSTEM_INFO,
        ROLE_KERNEL_DEBUG,
    ];
    for role in roles {
        let src_slot = lookup_system_cap_slot(role);
        if src_slot == 0 {
            continue;
        }
        let dest = *dest_base;
        let r = invoke::cnode_copy(
            self_cspace,
            src_slot,
            child_cnode,
            dest,
            KERNITE_RIGHT_ALL as u64,
        );
        if r != 0 {
            return Err(r);
        }
        push_cap_table_entry(builder, role, dest, 0, 0)?;
        *dest_base += 1;
    }
    Ok(())
}

/// Copy a cap from init's CSpace into the child's CNode at
/// `dest_slot` and push the cap_table entry. `src` is `None` when
/// the capability is not yet provisioned; in that case no cap_table
/// entry is emitted, leaving runtime lazy resolution or later slot
/// reservation paths to handle the role.
pub fn deliver_cap(
    child_cnode: CapRef,
    builder: &mut CapTableBuilder,
    role_id: u32,
    src: Option<CapRef>,
    dest_slot: u64,
    flags: u32,
) -> Result<(), i32> {
    let src_ref = match src {
        None => return Ok(()),
        Some(r) => r,
    };
    let r = invoke::cnode_copy_ref(
        CapRef::flat(SLOT_SELF_CSPACE),
        src_ref,
        child_cnode,
        CapRef::flat(dest_slot),
        KERNITE_RIGHT_ALL as u64,
    );
    if r != 0 {
        return Err(r);
    }
    push_cap_table_entry(builder, role_id, dest_slot, 0, flags)?;
    Ok(())
}

/// Mint a cap from init's CSpace into the child's CNode at
/// `dest_slot` with `badge` applied, then push the cap_table entry.
/// Used for the per-server master MP send sides which carry a stable
/// badge identifying the calling service. `src == None` omits the
/// role entry.
pub fn deliver_cap_minted(
    child_cnode: CapRef,
    builder: &mut CapTableBuilder,
    role_id: u32,
    src: Option<CapRef>,
    dest_slot: u64,
    badge: u64,
    flags: u32,
) -> Result<(), i32> {
    let src_ref = match src {
        None => return Ok(()),
        Some(r) => r,
    };
    let r = invoke::cnode_mint_ref(
        CapRef::flat(SLOT_SELF_CSPACE),
        src_ref,
        child_cnode,
        CapRef::flat(dest_slot),
        badge,
    );
    if r != 0 {
        return Err(r);
    }
    push_cap_table_entry(builder, role_id, dest_slot, 0, flags)?;
    Ok(())
}

/// Move (rather than copy) a cap from init's CSpace into the child's,
/// consuming the `OwnedCap`. The cap's kernel object becomes owned by
/// the child's CSpace; init's slot is cleared and freed on Drop.
/// Used for objects init minted only to hand off — namesrv master EQ,
/// mmsrv fault TCB, raw untyped chunks transferred to the new owner.
/// `src == None` omits the role entry.
pub fn deliver_cap_moved(
    child_cnode: CapRef,
    builder: &mut CapTableBuilder,
    role_id: u32,
    src: Option<OwnedCap>,
    dest_slot: u64,
    flags: u32,
) -> Result<(), i32> {
    let cap = match src {
        None => return Ok(()),
        Some(c) => c,
    };
    let r = invoke::cnode_move_ref(
        child_cnode,
        CapRef::flat(dest_slot),
        CapRef::flat(SLOT_SELF_CSPACE),
        cap.borrow(),
    );
    // Drop `cap` regardless: on success the kernel slot is now empty so
    // cnode_delete is a no-op, but slot_free still reclaims the slot.
    drop(cap);
    if r != 0 {
        return Err(r);
    }
    push_cap_table_entry(builder, role_id, dest_slot, 0, flags)?;
    Ok(())
}

/// Move a contiguous slab of pre-retyped caps from init's CSpace
/// `init_base..init_base + count` into the child's CNode
/// `dest_base..dest_base + count`, then push a single cap_table entry
/// at `role_id → dest_base` so the child's runtime can derive the
/// other slot indices from the base. The caller is responsible for
/// freeing the now-empty slots in `init_base..init_base+count`.
pub fn place_slab_moved(
    child_cnode: CapRef,
    builder: &mut CapTableBuilder,
    role_id: u32,
    init_base: u64,
    dest_base: u64,
    count: usize,
) -> Result<(), i32> {
    let self_cspace = CapRef::flat(SLOT_SELF_CSPACE);
    for i in 0..count as u64 {
        let r = invoke::cnode_move(child_cnode, dest_base + i, self_cspace, init_base + i);
        if r != 0 {
            return Err(r);
        }
    }
    push_cap_table_entry(builder, role_id, dest_base, 0, 0)?;
    Ok(())
}

/// Reserve an empty child CNode slot at `dest_base` and push the
/// role_id → base entry. The entry is flagged as reserved so runtime
/// weak-symbol installation does not treat the empty slot as a live cap.
pub fn place_empty_slot_range(
    builder: &mut CapTableBuilder,
    role_id: u32,
    dest_base: u64,
) -> Result<(), i32> {
    push_cap_table_entry(builder, role_id, dest_base, 0, CAP_TBL_FLAG_RESERVED)
}

/// Map a frame at `SCRATCH_FRAME_VA` in init's own VSpace, returning
/// the writable scratch pointer. Caller must pair every successful
/// call with [`unmap_self_scratch`].
fn map_self_scratch(frame: CapRef) -> Result<*mut u8, i32> {
    let r = invoke::vspace_map(
        CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64),
        frame,
        SCRATCH_FRAME_VA,
        (uapi::KERNITE_PAGE_FLAG_USER as u64) | (uapi::KERNITE_PAGE_FLAG_WRITABLE as u64),
    );
    if r != 0 {
        return Err(r);
    }
    Ok(SCRATCH_FRAME_VA as *mut u8)
}

fn unmap_self_scratch() -> Result<(), i32> {
    let r = invoke::vspace_unmap(
        CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64),
        SCRATCH_FRAME_VA,
    );
    if r != 0 {
        return Err(r);
    }
    Ok(())
}

/// Build the child's cap-table inside `cap_table_frame` and map it
/// read-only at `CHILD_CAP_TABLE_VA`. The caller provides a closure
/// that pushes the desired `(role_id → child_slot)` entries; the
/// scratch frame is unmapped before mapping into the child. Returns
/// the child VA at which the table lives.
pub fn build_and_map_cap_table<F>(
    child_vspace: CapRef,
    cap_table_frame: CapRef,
    populate: F,
) -> Result<u64, i32>
where
    F: FnOnce(&mut CapTableBuilder) -> Result<(), i32>,
{
    let scratch = map_self_scratch(cap_table_frame)?;
    let mut builder = unsafe { CapTableBuilder::new_at(scratch, KERNITE_PAGE_BYTES as usize) };
    let populate_result = populate(&mut builder);
    let _ = unsafe { builder.finalize() };
    unmap_self_scratch()?;
    populate_result?;

    let r = invoke::vspace_map(
        child_vspace,
        cap_table_frame,
        CHILD_CAP_TABLE_VA,
        PAGE_FLAGS_R_USER,
    );
    if r != 0 {
        return Err(r);
    }
    Ok(CHILD_CAP_TABLE_VA)
}
