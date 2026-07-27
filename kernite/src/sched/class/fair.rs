// SPDX-License-Identifier: GPL-2.0-only
//! Fair / EEVDF-style scheduling class.
//!
//! Threads in this class share CPU time weighted by `fair_weight`.
//! The scheduler key combines the thread's `fair_vruntime` with a
//! per-thread slice account so an EEVDF treap can pick the leftmost
//! eligible thread efficiently.

use super::SCHED_CLASS_SHIFT;

/// Default Fair weight assigned at class entry. 1024 is the
/// conventional EEVDF baseline weight; larger values get
/// proportionally more CPU.
pub const FAIR_DEFAULT_WEIGHT: u16 = 1024;

/// Default scheduling slice for the Fair class, in nanoseconds.
/// The slice runtime accumulates against `fair_vruntime` at the
/// thread's weight; once exhausted, the scheduler picks the next
/// eligible thread.
pub const FAIR_DEFAULT_SLICE_NS: u64 = 1_000_000;

/// Sentinel for "lag accounting hasn't run yet" — see EEVDF lag
/// preservation across sleep / requeue.
pub const FAIR_LAG_INVALID_NS: i64 = i64::MIN;

/// Low byte of `FAIR_DEFAULT_WEIGHT`, packed into `Tcb.rt_priority`
/// when the thread runs in the Fair class.
pub const FAIR_DEFAULT_WEIGHT_LO: u8 = (FAIR_DEFAULT_WEIGHT & 0x00FF) as u8;

/// High byte of `FAIR_DEFAULT_WEIGHT`, packed into `Tcb.sched_flags`.
pub const FAIR_DEFAULT_WEIGHT_HI: u8 = (FAIR_DEFAULT_WEIGHT >> 8) as u8;

/// Reference weight used as the EEVDF virtual-time scale. All
/// `fair_vruntime` advances are in this base.
pub const FAIR_WEIGHT_BASE: u64 = FAIR_DEFAULT_WEIGHT as u64;

/// Virtual-time fixed-point shift. Scheduler keys carry vruntime
/// pre-multiplied by `1 << FAIR_VTIME_SHIFT` so weight ratios
/// preserve resolution.
pub const FAIR_VTIME_SHIFT: u32 = 10;

/// Reference virtual-time tick = `FAIR_WEIGHT_BASE << FAIR_VTIME_SHIFT`.
pub const FAIR_VTIME_BASE: u64 = FAIR_WEIGHT_BASE << FAIR_VTIME_SHIFT;

/// In-class key base for the Fair discriminant.
pub const FAIR_KEY_BASE: u64 = 2u64 << SCHED_CLASS_SHIFT;
