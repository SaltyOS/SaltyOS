// SPDX-License-Identifier: GPL-2.0-only
//
//! Boot-time untyped split. The kernel hands init a single boot
//! untyped covering all RAM the bootloader carved off; init splits it
//! into four chunks at stage B:
//!
//!   * `init_private` — init's own retypes plus the direct-loader
//!     plumbing/image frames for rsrcsrv and mmsrv before mmsrv exists.
//!   * `namesrv_quota` — namesrv's direct-loader plumbing/image frames
//!     plus the boot untyped seed delivered via `ROLE_NAMESRV_BOOT_UNTYPED`.
//!   * `rsrcsrv_quota` — generic untyped seed for rsrcsrv to vend from
//!     once it is alive; fed via `ROLE_RSRCSRV_AUTHORITY_RAW`.
//!   * `mmsrv_pool` — mmsrv's frame buddy pool seed; fed via
//!     `ROLE_MMSRV_FRAME_POOL` and `ROLE_MMSRV_AUTHORITY_RAW`.
//!
//! The split is implemented as sequential `KERNITE_INV_UNTYPED_RETYPE
//! (OBJ_UNTYPED, size_bits)` calls against the boot untyped. Stage B
//! receives a measured [`BootUntypedPlan`] from `boot_budget`, then
//! picks the largest remaining mmsrv pool that still fits after the
//! kernel's alignment rules for sub-untyped carves.

use trona_kernel::core_types::CapRef;
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::OwnedCap;
use uapi::{KERNITE_ERR_OUT_OF_MEMORY, KERNITE_INV_UNTYPED_RETYPE, KERNITE_OBJ_UNTYPED};

use crate::internal_slots::SLOT_BOOT_UNTYPED;

pub struct UntypedChunks {
    pub init_private: Option<OwnedCap>,
    pub namesrv_quota: Option<OwnedCap>,
    pub rsrcsrv_quota: Option<OwnedCap>,
    pub mmsrv_pool: Option<OwnedCap>,
    pub namesrv_plumbing_size_bits: u64,
    pub namesrv_boot_size_bits: u64,
}

impl UntypedChunks {
    pub const fn zeroed() -> Self {
        Self {
            init_private: None,
            namesrv_quota: None,
            rsrcsrv_quota: None,
            mmsrv_pool: None,
            namesrv_plumbing_size_bits: 0,
            namesrv_boot_size_bits: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct BootUntypedPlan {
    pub init_private_size_bits: u64,
    pub namesrv_quota_size_bits: u64,
    pub namesrv_plumbing_size_bits: u64,
    pub namesrv_boot_size_bits: u64,
    pub rsrcsrv_quota_target_size_bits: u64,
}

const MIN_REMAINDER_SIZE_BITS: u64 = 12;

fn floor_log2(n: u64) -> u64 {
    if n <= 1 {
        0
    } else {
        63 - n.leading_zeros() as u64
    }
}

fn boot_untyped_stats() -> Option<(u64, u64)> {
    let (slot, _, size_bytes, available_bytes) = trona_runtime::runtime_get_boot_untyped_stats()?;
    if slot != SLOT_BOOT_UNTYPED {
        return None;
    }
    Some((size_bytes, available_bytes))
}

/// Retype one sub-untyped cap from `parent` into `dest_slot`.
/// On success, wraps the slot as an `OwnedCap` (depth 0).
fn retype_untyped(parent: CapRef, dest_slot: u64, size_bits: u64) -> Result<OwnedCap, i32> {
    // dest_slot is a freshly allocated init-CSpace slot; the kernel writes the
    // new untyped cap there on success.
    let r = invoke::untyped_retype(parent, KERNITE_OBJ_UNTYPED as u64, size_bits, dest_slot);
    if r != 0 {
        return Err(r);
    }
    // SAFETY: untyped_retype just filled dest_slot (err checked); init flat root
    // CSpace (depth 0), sole owner of this slot.
    Ok(unsafe { OwnedCap::from_raw(dest_slot, 0) })
}

/// Split the boot untyped into the four service quotas. Caller passes
/// pre-allocated (but empty) init-CSpace slot addresses for each chunk.
/// Returns `UntypedChunks` with each slot wrapped as an `OwnedCap`.
pub fn split(
    init_private_slot: u64,
    namesrv_quota_slot: u64,
    rsrcsrv_quota_slot: u64,
    mmsrv_pool_slot: u64,
    plan: BootUntypedPlan,
) -> Result<UntypedChunks, i32> {
    let available = boot_untyped_stats()
        .map(|(_, available)| available)
        .ok_or(KERNITE_ERR_OUT_OF_MEMORY as i32)?;

    let (rsrcsrv_bits, mmsrv_bits) = choose_tail_bits(available, plan)?;

    let boot = CapRef::flat(SLOT_BOOT_UNTYPED);
    let init_private = retype_untyped(boot, init_private_slot, plan.init_private_size_bits)?;
    let namesrv_quota = retype_untyped(boot, namesrv_quota_slot, plan.namesrv_quota_size_bits)?;
    let rsrcsrv_quota = retype_untyped(boot, rsrcsrv_quota_slot, rsrcsrv_bits)?;
    let mmsrv_pool = retype_untyped(boot, mmsrv_pool_slot, mmsrv_bits)?;

    Ok(UntypedChunks {
        init_private: Some(init_private),
        namesrv_quota: Some(namesrv_quota),
        rsrcsrv_quota: Some(rsrcsrv_quota),
        mmsrv_pool: Some(mmsrv_pool),
        namesrv_plumbing_size_bits: plan.namesrv_plumbing_size_bits,
        namesrv_boot_size_bits: plan.namesrv_boot_size_bits,
    })
}

fn choose_tail_bits(available: u64, plan: BootUntypedPlan) -> Result<(u64, u64), i32> {
    let max_rsrc = core::cmp::min(plan.rsrcsrv_quota_target_size_bits, floor_log2(available));
    for rsrc_bits in (MIN_REMAINDER_SIZE_BITS..=max_rsrc).rev() {
        let watermark = carve_split_prefix(plan, rsrc_bits)?;
        for mmsrv_bits in (MIN_REMAINDER_SIZE_BITS..=floor_log2(available)).rev() {
            let end = carve_untyped_at(watermark, mmsrv_bits)?;
            if end <= available {
                return Ok((rsrc_bits, mmsrv_bits));
            }
        }
    }
    Err(KERNITE_ERR_OUT_OF_MEMORY as i32)
}

fn carve_split_prefix(plan: BootUntypedPlan, rsrcsrv_bits: u64) -> Result<u64, i32> {
    let mut watermark = 0;
    watermark = carve_untyped_at(watermark, plan.init_private_size_bits)?;
    watermark = carve_untyped_at(watermark, plan.namesrv_quota_size_bits)?;
    carve_untyped_at(watermark, rsrcsrv_bits)
}

fn carve_untyped_at(watermark: u64, size_bits: u64) -> Result<u64, i32> {
    if !(12..=47).contains(&size_bits) {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let size = 1u64
        .checked_shl(size_bits as u32)
        .ok_or(KERNITE_ERR_OUT_OF_MEMORY as i32)?;
    let aligned = align_up(watermark, size)?;
    aligned
        .checked_add(size)
        .ok_or(KERNITE_ERR_OUT_OF_MEMORY as i32)
}

fn align_up(value: u64, align: u64) -> Result<u64, i32> {
    let rem = value % align;
    if rem == 0 {
        Ok(value)
    } else {
        value
            .checked_add(align - rem)
            .ok_or(KERNITE_ERR_OUT_OF_MEMORY as i32)
    }
}

/// Query the kernel for the boot untyped's `size_bits`. Used during
/// stage A to log how much RAM init received before the split.
pub fn boot_untyped_size_bits() -> u8 {
    boot_untyped_stats()
        .map(|(size_bytes, _)| floor_log2(size_bytes) as u8)
        .unwrap_or(0)
}

/// Suppress unused-warning for the dead constant: the wire layout of
/// `KERNITE_INV_UNTYPED_RETYPE` is exposed for documentation rather
/// than direct call by this module; readers expect to find it here.
#[allow(dead_code)]
const _RETYPE_OP: u64 = KERNITE_INV_UNTYPED_RETYPE as u64;
