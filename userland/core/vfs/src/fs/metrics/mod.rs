// SPDX-License-Identifier: GPL-2.0-only
//
//! Shared metrics back-end for procfs / sysctlfs.
//!
//! Both `fs::procfs` (Linux-format projection) and `fs::sysctlfs`
//! (FreeBSD MIB) expose the same underlying kernel / mmsrv / init
//! statistics in different wire formats. This module is the single
//! place that talks to those sources — callers receive typed values
//! and only need to format.
//!
//! Sources:
//! - **Kernel** via `KERNITE_INV_SYSINFO_GET_MEMINFO` on a
//!   `SystemInfo` cap — raw PMM page-count snapshot.
//! - **mmsrv** via `MM_GET_SYSTEM_MEMINFO` / `MM_GET_COMMIT_AS` —
//!   policy-level memory aggregates and commit accounting.
//! - **init** via `INIT_GET_PROC_INFO` sub-ops — per-process and
//!   system-wide process / CPU snapshots.
//!
//! All getters return `Result<T, i32>`; the error is a raw kernite
//! / TRONA error code. Callers surface failures by emitting an
//! empty / placeholder value in their wire format.

pub(crate) mod cpu;
pub(crate) mod memory;
pub(crate) mod proc;

pub(crate) use cpu::{
    MAX_CPUS, SystemCpuHeader, SystemCpuTicks, boot_time_ns, system_cpu, uptime_ns,
};
pub(crate) use memory::{
    PolicySnapshot, TronaSysMemInfo, system_committed_as, system_kernel_snapshot,
    system_policy_snapshot,
};
pub(crate) use proc::{PerPidMemSnapshot, SystemProcStats, per_pid_mem_snapshot};
