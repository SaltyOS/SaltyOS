// SPDX-License-Identifier: GPL-2.0-only
//
//! mmsrv-internal CSpace bookkeeping. Fixed receive/watch ranges are
//! reserved once at boot via `slot_alloc::slot_alloc_consecutive_or_idle`
//! and treated as read-only afterwards. MemoryObject caps are allocated
//! individually by `MoRegistry`.

use uapi::KERNITE_CAP_SELF_CSPACE;

pub const CAP_SELF_CSPACE: u64 = KERNITE_CAP_SELF_CSPACE as u64;

/// Per-reactor receive window size. The kernel installs caps in
/// `[base .. base + cap_count)` on each `MP_READ`.
pub const RECV_WINDOW_LEN: u64 = 4;

pub static mut MAIN_RECV_BASE_SLOT: u64 = 0;
pub static mut FAULT_RECV_BASE_SLOT: u64 = 0;
pub static mut WATCH_POOL_BASE: u64 = 0;

fn recv_base_slot(base: *const u64) -> u64 {
    unsafe { core::ptr::read_volatile(base) }
}

/// Absolute slot index in mmsrv's CSpace at which the kernel installs
/// the `idx`-th user cap from an inbound main-reactor request.
pub fn recv_user_slot(idx: u64) -> u64 {
    recv_base_slot(&raw const MAIN_RECV_BASE_SLOT) + idx
}

pub fn main_recv_base_slot() -> u64 {
    recv_base_slot(&raw const MAIN_RECV_BASE_SLOT)
}

pub fn fault_recv_base_slot() -> u64 {
    recv_base_slot(&raw const FAULT_RECV_BASE_SLOT)
}

pub fn watch_pool_base() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const WATCH_POOL_BASE) }
}
