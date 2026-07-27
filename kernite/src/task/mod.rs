// SPDX-License-Identifier: GPL-2.0-only
//! Task lifecycle and control-plane helpers.
//!
//! Submodules:
//! * `state`     — TCB state predicates (R2 quiesce gate).
//! * `control`   — structural mutation (configure / set_space /
//!                 set_priority / set_sched_class / etc.).
//! * `wait`      — block / wake transitions for IPC + futex paths.
//! * `stop`      — `TCB_STOP` / `TCB_RESUME` plane.
//! * `quiesce`   — kill / exit / final destroy + cross-CPU drain.

pub(crate) mod control;
pub(crate) mod quiesce;
pub(crate) mod state;
pub(crate) mod stop;
pub(crate) mod wait;
