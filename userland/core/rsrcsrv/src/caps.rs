// SPDX-License-Identifier: GPL-2.0-only
//
//! rsrcsrv-internal CSpace slot bookkeeping. Each slot is reserved
//! once at startup via `slot_alloc::slot_alloc_consecutive_or_idle` and
//! treated as read-only afterwards.

use uapi::KERNITE_CAP_SELF_CSPACE;

pub const CAP_SELF_CSPACE: u64 = KERNITE_CAP_SELF_CSPACE as u64;

/// Window holding inbound cap-transfer slots. Sender-attached caps
/// land at the base; regular replies go back over the MessagePipe
/// endpoint that produced the request.
pub const RECV_WINDOW_LEN: u64 = 4;

pub static mut RECV_BASE_SLOT: u64 = 0;
pub static mut OBJECT_BACK_REF_BASE: u64 = 0;
pub static mut OBJECT_BACK_REF_LEN: u64 = 0;
pub static mut SELF_EXPAND_TEMP_SLOT: u64 = 0;

pub fn recv_base_slot() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const RECV_BASE_SLOT) }
}

pub fn recv_user_slot(idx: u64) -> u64 {
    recv_base_slot() + idx
}

pub fn recv_payload0_slot() -> u64 {
    recv_user_slot(0)
}

pub fn object_back_ref_base() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const OBJECT_BACK_REF_BASE) }
}

pub fn object_back_ref_len() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const OBJECT_BACK_REF_LEN) }
}

pub fn self_expand_temp_slot() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const SELF_EXPAND_TEMP_SLOT) }
}
