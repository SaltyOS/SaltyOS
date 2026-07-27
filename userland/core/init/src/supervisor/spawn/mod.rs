// SPDX-License-Identifier: GPL-2.0-only
//
//! Spawn pipeline — the single in-place flow that brings a process
//! into existence regardless of which boot stage drives it. Every
//! transition (Stage C/D/E pre-mmsrv core service spawn, Stage G
//! post-mmsrv service spawn, POSIX fork, POSIX exec) composes from
//! the same building blocks:
//!
//! * [`plan`] — `SpawnKind`, `AddressSpacePlan`, `BootstrapPlan`,
//!   `ChildBundle`, `RealizeOutcome`, and the bundle layout.
//! * [`alloc`] — `SpawnAllocator` trait + direct/rsrcsrv backends.
//! * [`cspace`] — child CNode seed, system cap delivery, role-based
//!   cap-table builder + frame map.
//! * [`tcb`] — TCB / SchedContext invoke wrappers + the
//!   `configure_and_start_tcb` end-to-end bring-up.
//! * [`fault_wire`] — fault-MP wiring (register_client,
//!   register_fault_pipe, bind_fault_caps) including Stage F
//!   retroactive bind.
//!
//! `lifecycle::realize_process` composes these phases per
//! `SpawnKind` / `AddressSpacePlan`; the boot-side core spawner
//! (`boot_core::*`) does the same composition on top of a
//! `DirectUntypedAllocator` since rsrcsrv is not yet available.

pub mod alloc;
pub mod cspace;
pub mod fault_wire;
pub mod plan;
pub mod tcb;
