// SPDX-License-Identifier: GPL-2.0-only
//! Shared metrics back-end for procfs / sysctlfs.
//!
//! Both `fs::procfs` (Linux-format projection) and `fs::sysctlfs` (FreeBSD
//! MIB) expose the same underlying kernel / mmsrv / procmgr statistics but
//! in different wire formats. This module is the single place that talks to
//! those sources — callers receive typed values and can focus on formatting.
//!
//! The three sources:
//! - **Kernel** via `SYS_SYSMEMINFO` (syscall 30) — raw PMM page-count snapshot.
//! - **mmsrv** via `MM_GET_SYSTEM_MEMINFO` / `MM_GET_COMMIT_AS` — policy-level
//!   memory aggregates and commit accounting.
//! - **procmgr** via `INIT_GET_PROC_TIMES` / `INIT_GET_SYSTEM_STATS` /
//!   `INIT_GET_KINFO_PROC` / `INIT_LIST_PIDS_BUF` / `INIT_GET_ARGV` /
//!   `INIT_GET_CLIENT_VM_STATS` — per-process and system-wide snapshots.
//!
//! All getters return `Result<T, i32>` where the error is a raw trona error
//! code (see `trona_runtime::core::server_consts::TRONA_*`). Callers surface failures by emitting
//! an empty / placeholder value in their wire format.

pub(crate) mod cpu;
pub(crate) mod memory;
pub(crate) mod proc;

pub(crate) use cpu::{SystemCpuHeader, SystemCpuTicks, boot_time_ns, system_cpu, uptime_ns};
pub(crate) use memory::{
    PolicySnapshot, TronaSysMemInfo, system_committed_as, system_kernel_snapshot,
    system_policy_snapshot,
};
pub(crate) use proc::{
    ArgvBuf, PerPidMemSnapshot, ProcTimes, SystemProcStats, kinfo_proc, list_pids,
    per_pid_mem_snapshot, proc_argv, proc_times, system_proc_stats,
};
