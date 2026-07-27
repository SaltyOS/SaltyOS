// SPDX-License-Identifier: GPL-2.0-only
//
//! init supervisor — single owner of system lifecycle.
//!
//! init drives the boot sequence (untyped 4-chunk split → namesrv →
//! rsrcsrv → mmsrv → retroactive fault binding → rest of services),
//! owns the global process table, dispatches all POSIX `INIT_*` labels
//! that wrappers send through per-client request MPs, fans lifecycle
//! events out to subscribers, and forwards fault reports from mmsrv
//! into kill/resume decisions.

pub mod boot;
pub mod boot_budget;
pub mod boot_core;
pub mod control_ipc;
pub mod cred;
pub mod dispatch;
pub mod fault;
pub mod itimer;
pub mod ldsrv_adopt;
pub mod lifecycle;
pub mod lifecycle_stream;
pub mod loader;
pub mod manifest;
pub mod mm_ipc;
pub mod namesrv_ipc;
pub mod owner_loop;
pub mod pgrp_session;
pub mod proc_info;
pub mod proc_table;
pub mod recv_window;
pub mod registry;
pub mod retype;
pub mod rlimit;
pub mod rsrc_ipc;
pub mod segment_alloc;
pub mod self_vm;
pub mod service_query;
pub mod signal;
pub mod spawn;
pub mod state;
pub mod thread;
pub mod unit_mgr;
pub mod untyped_split;
pub mod vfs_ipc;

pub use state::SupervisorState;
