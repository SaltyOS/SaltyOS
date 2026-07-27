// SPDX-License-Identifier: GPL-2.0-only
//! Scheduling-class plane.
//!
//! Each class owns its own submodule with the class-specific
//! constants and (where applicable) per-class encoding / accounting
//! helpers. The shared discriminant set + key-encoding scheme lives
//! here; per-class numerics live in `deadline` / `rt` / `fair` /
//! `idle`.

pub mod deadline;
pub mod fair;
pub mod idle;
pub mod rt;

/// Scheduler class discriminant. Stored as `Tcb.sched_class` and as
/// the high two bits of the encoded scheduler key (see
/// `SCHED_CLASS_SHIFT`).
pub const SCHED_CLASS_DEADLINE: u8 = 0;
pub const SCHED_CLASS_RT_FIFO: u8 = 1;
pub const SCHED_CLASS_FAIR: u8 = 2;
pub const SCHED_CLASS_IDLE: u8 = 3;

/// Scheduler-key bit layout: top two bits encode the class, lower 62
/// bits encode the in-class priority value. Smaller keys win — the
/// ordering Deadline < RT < Fair < Idle falls out of the high-bit
/// stamp.
pub const SCHED_CLASS_SHIFT: u64 = 62;

/// Mask for the in-class priority bits (everything below the class
/// stamp).
pub const CLASS_KEY_MASK: u64 = (1u64 << SCHED_CLASS_SHIFT) - 1;
