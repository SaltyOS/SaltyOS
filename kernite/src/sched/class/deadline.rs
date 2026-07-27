// SPDX-License-Identifier: GPL-2.0-only
//! Deadline scheduling class.
//!
//! Threads in this class run earliest-deadline-first. The scheduler
//! key is the deadline value directly (truncated to fit the in-class
//! 62-bit field), so a tighter deadline produces a smaller key and
//! preempts looser-deadline peers in the same class.
//!
//! The class has no class-private constants beyond the discriminant
//! / key-base shared in `super`. Encoding lives on
//! `Tcb::encode_deadline_priority` so it can run alongside the
//! `recompute_sched_key` path.
