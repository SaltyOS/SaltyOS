// SPDX-License-Identifier: GPL-2.0-only
//! Built-in sysctl value providers.
//!
//! Each provider is a pair of read/write callbacks registered as a leaf on
//! the appropriate MIB subtree. Write callbacks are only provided for
//! read-write leaves (e.g. `kern.hostname`, `security.securelevel`).
//!
//! Live-data leaves do **not** call kernel syscalls directly. Every system
//! statistic flows through `crate::fs::metrics`, which itself routes to:
//!
//! * `INIT_GET_PROC_INFO` (init server, `regs[0] = sub-op`) for per-process
//!   bookkeeping (kinfo_proc, list_pids, argv, exe_path) and CPU runtime
//!   (`GET_CPU_INFO` sub-op).
//! * `MM_GET_SYSTEM_MEMINFO` / `MM_GET_COMMIT_AS` (mmsrv) for kernel/user
//!   page accounting and aggregate VA commit.
//! * Substrate `Clock` capability for boot/uptime reads.
//!
//! Keeping every provider on `metrics` (rather than re-implementing IPC
//! locally) guarantees that procfs and sysctlfs see byte-for-byte the same
//! snapshots, and the substrate IPC type names (`mp_call_ctx`,
//! `core_types`, `sysinfo_types`, `kinfo_types`) only need adjustment in
//! one place.

use super::tree::*;
use crate::owner::init_rpc::{
    SYSCTL_FILTER_PGRP, SYSCTL_FILTER_RUID, SYSCTL_FILTER_SESSION, SYSCTL_FILTER_TTY,
    SYSCTL_FILTER_UID, SysValueKind, begin_sysctl_read,
};

use trona_protocol::init::{TronaSysInfo, TronaSysInfoCpu};

use crate::fs::metrics::{
    SystemCpuHeader, SystemCpuTicks, TronaSysMemInfo, system_cpu, system_kernel_snapshot,
    system_policy_snapshot,
};

// =========================================================================
// Constants
// =========================================================================

/// Maximum CPU count we allocate stack space for in providers that aggregate
/// per-CPU ticks. `metrics::cpu::MAX_CPUS` is 256; 16 covers every
/// realistic SaltyOS deployment without burning kilobytes of stack on every
/// `query_sysinfo` call.
const MAX_STACK_CPUS: usize = 16;

/// Hz of the userland tick used for `cp_time` / `cp_times` accounting.
/// Distinct from the kernel scheduler tick — the binary `clockinfo` blob
/// reports this as `hz`.
const TICKS_PER_SEC: u64 = 100;

// =========================================================================
// metrics wrappers
// =========================================================================

/// Snapshot the system CPU header + per-CPU ticks via init server.
///
/// `system_cpu` returns the number of CPUs filled into the array — the
/// caller iterates `0..written`. Errors map to a zeroed header / zero
/// ticks (callers treat this as "no live data" and emit zero counters).
unsafe fn query_sysinfo() -> (SystemCpuHeader, [SystemCpuTicks; MAX_STACK_CPUS], usize) {
    let mut hdr = TronaSysInfo::zeroed();
    let mut cpus = [TronaSysInfoCpu::zeroed(); MAX_STACK_CPUS];
    let written = system_cpu(&mut hdr, &mut cpus).unwrap_or(0);
    (hdr, cpus, written)
}

/// Snapshot the kernel page accounting from mmsrv. Errors yield a zeroed
/// `TronaSysMemInfo` so leaf reads still produce a parseable value (typically
/// zero) rather than an aborted IPC chain.
unsafe fn query_kernel_snapshot() -> TronaSysMemInfo {
    system_kernel_snapshot().unwrap_or(TronaSysMemInfo::zeroed())
}

/// Convert nanoseconds to userland ticks (`HZ = TICKS_PER_SEC`). Used by
/// `kern.cp_time` / `kern.cp_times` / `kern.boottime`.
#[inline]
fn ns_to_ticks(ns: u64) -> u64 {
    (((ns as u128).saturating_mul(TICKS_PER_SEC as u128)) / 1_000_000_000u128) as u64
}

// =========================================================================
// Formatting helpers
// =========================================================================

fn copy_static(val: &[u8], buf: *mut u8, buf_len: usize) -> usize {
    let n = val.len().min(buf_len);
    unsafe { ::core::ptr::copy_nonoverlapping(val.as_ptr(), buf, n) };
    n
}

fn fmt_u32(mut v: u32, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while v > 0 && len < 10 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

fn fmt_u64(mut v: u64, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while v > 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

fn write_u32_to_buf(val: u32, buf: *mut u8, buf_len: usize) -> usize {
    let mut tmp = [0u8; 16];
    let len = fmt_u32(val, &mut tmp);
    if len < tmp.len() {
        tmp[len] = b'\n';
    }
    let total = len + 1;
    let n = total.min(buf_len);
    unsafe { ::core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
    n
}

fn write_u64_to_buf(val: u64, buf: *mut u8, buf_len: usize) -> usize {
    let mut tmp = [0u8; 24];
    let len = fmt_u64(val, &mut tmp);
    if len < tmp.len() {
        tmp[len] = b'\n';
    }
    let total = len + 1;
    let n = total.min(buf_len);
    unsafe { ::core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
    n
}

fn write_i32_to_buf(val: i32, buf: *mut u8, buf_len: usize) -> usize {
    let mut tmp = [0u8; 16];
    let pos;
    if val < 0 {
        tmp[0] = b'-';
        let abs = (val as i64).wrapping_neg() as u32;
        pos = 1 + fmt_u32(abs, &mut tmp[1..]);
    } else {
        pos = fmt_u32(val as u32, &mut tmp);
    }
    if pos < tmp.len() {
        tmp[pos] = b'\n';
    }
    let total = pos + 1;
    let n = total.min(buf_len);
    unsafe { ::core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
    n
}

unsafe fn parse_i32_from_buf(src: *const u8, len: usize) -> i32 {
    unsafe {
        let mut pos = 0usize;
        let neg = if pos < len && *src == b'-' {
            pos += 1;
            true
        } else {
            false
        };
        let mut end = len;
        while end > pos {
            let b = *src.add(end - 1);
            if b == b'\n' || b == b' ' || b == b'\t' {
                end -= 1;
            } else {
                break;
            }
        }
        let mut val: i32 = 0;
        while pos < end {
            let b = *src.add(pos);
            if !b.is_ascii_digit() {
                break;
            }
            val = val.wrapping_mul(10).wrapping_add((b - b'0') as i32);
            pos += 1;
        }
        if neg { val.wrapping_neg() } else { val }
    }
}

fn parse_u32_from_bytes(name: *const u8, len: usize) -> Option<u32> {
    if len == 0 {
        return None;
    }
    let mut val: u32 = 0;
    for i in 0..len {
        let b = unsafe { *name.add(i) };
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u32);
    }
    Some(val)
}

// =========================================================================
// kern.* leaves
// =========================================================================

unsafe fn read_ostype(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    SysctlOutcome::Ready(copy_static(b"SaltyOS\n", buf, buf_len))
}

unsafe fn read_osrelease(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    SysctlOutcome::Ready(copy_static(b"0.1.0\n", buf, buf_len))
}

/// Mutable hostname buffer. Defaults to `"saltyos"`, writable via sysctl.
static mut HOSTNAME: [u8; 256] = [0; 256];
static mut HOSTNAME_LEN: usize = 0;

unsafe fn read_hostname(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    unsafe {
        let len = *(&raw const HOSTNAME_LEN);
        let n = len.min(buf_len);
        ::core::ptr::copy_nonoverlapping((&raw const HOSTNAME) as *const u8, buf, n);
        SysctlOutcome::Ready(n)
    }
}

unsafe fn write_hostname(src: *const u8, len: usize) -> i32 {
    unsafe {
        let mut n = len;
        if n > 0 && *src.add(n - 1) == b'\n' {
            n -= 1;
        }
        if n > 255 {
            n = 255;
        }
        ::core::ptr::copy_nonoverlapping(src, (&raw mut HOSTNAME) as *mut u8, n);
        *(&raw mut HOSTNAME).cast::<u8>().add(n) = 0;
        *(&raw mut HOSTNAME_LEN) = n;
        0
    }
}

unsafe fn read_version(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    SysctlOutcome::Ready(copy_static(b"SaltyOS 0.1.0\n", buf, buf_len))
}

unsafe fn read_maxproc(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    SysctlOutcome::Ready(write_u32_to_buf(256, buf, buf_len))
}

unsafe fn read_kern_ncpu(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let (hdr, _, _) = unsafe { query_sysinfo() };
    SysctlOutcome::Ready(write_u32_to_buf(hdr.cpu_count, buf, buf_len))
}

/// `kern.cp_time` — 5×u64 binary blob `[user, nice, sys, intr, idle]`.
/// `nice` and `intr` are zero (SaltyOS does not separately account these).
/// Aggregates across all CPUs.
unsafe fn read_kern_cp_time(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let (_, cpus, written) = unsafe { query_sysinfo() };
    let mut user: u64 = 0;
    let mut sys: u64 = 0;
    let mut idle: u64 = 0;
    for i in 0..written {
        user = user.saturating_add(ns_to_ticks(cpus[i].user_time_ns));
        sys = sys.saturating_add(ns_to_ticks(cpus[i].system_time_ns));
        idle = idle.saturating_add(ns_to_ticks(cpus[i].idle_time_ns));
    }
    let arr: [u64; 5] = [user, 0, sys, 0, idle];
    let bytes = ::core::mem::size_of_val(&arr);
    if buf_len < bytes {
        return SysctlOutcome::Ready(0);
    }
    unsafe { ::core::ptr::copy_nonoverlapping(arr.as_ptr() as *const u8, buf, bytes) };
    SysctlOutcome::Ready(bytes)
}

/// `kern.cp_times` — `(5 × cpu_count) × u64`, one 5-tuple per CPU.
unsafe fn read_kern_cp_times(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let (_, cpus, written) = unsafe { query_sysinfo() };
    let needed = written * 5 * ::core::mem::size_of::<u64>();
    if buf_len < needed || needed == 0 {
        return SysctlOutcome::Ready(0);
    }
    unsafe {
        let mut out = buf;
        for i in 0..written {
            let arr: [u64; 5] = [
                ns_to_ticks(cpus[i].user_time_ns),
                0,
                ns_to_ticks(cpus[i].system_time_ns),
                0,
                ns_to_ticks(cpus[i].idle_time_ns),
            ];
            ::core::ptr::copy_nonoverlapping(
                arr.as_ptr() as *const u8,
                out,
                5 * ::core::mem::size_of::<u64>(),
            );
            out = out.add(5 * ::core::mem::size_of::<u64>());
        }
    }
    SysctlOutcome::Ready(needed)
}

/// `kern.boottime` — `struct timeval { tv_sec: u64, tv_usec: u64 }` packed
/// as two u64 words. `boot_time_ns` is wall-clock nanoseconds at boot.
unsafe fn read_kern_boottime(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let (hdr, _, _) = unsafe { query_sysinfo() };
    let tv_sec = hdr.boot_time_ns / 1_000_000_000;
    let tv_usec = (hdr.boot_time_ns % 1_000_000_000) / 1_000;
    let arr: [u64; 2] = [tv_sec, tv_usec];
    let bytes = ::core::mem::size_of_val(&arr);
    if buf_len < bytes {
        return SysctlOutcome::Ready(0);
    }
    unsafe { ::core::ptr::copy_nonoverlapping(arr.as_ptr() as *const u8, buf, bytes) };
    SysctlOutcome::Ready(bytes)
}

/// `kern.clockrate` — `struct clockinfo { hz, tick, profhz, stathz }`.
/// SaltyOS runs userland accounting at `TICKS_PER_SEC` Hz; `tick` is
/// `1_000_000 / hz` (microseconds per tick).
unsafe fn read_kern_clockrate(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let hz: u32 = TICKS_PER_SEC as u32;
    let tick: u32 = 1_000_000 / hz;
    let profhz: u32 = hz;
    let stathz: u32 = hz;
    let arr: [u32; 4] = [hz, tick, profhz, stathz];
    let bytes = ::core::mem::size_of_val(&arr);
    if buf_len < bytes {
        return SysctlOutcome::Ready(0);
    }
    unsafe { ::core::ptr::copy_nonoverlapping(arr.as_ptr() as *const u8, buf, bytes) };
    SysctlOutcome::Ready(bytes)
}

// =========================================================================
// hw.* leaves
// =========================================================================

unsafe fn read_hw_ncpu(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let (hdr, _, _) = unsafe { query_sysinfo() };
    SysctlOutcome::Ready(write_u32_to_buf(hdr.cpu_count, buf, buf_len))
}

unsafe fn read_hw_pagesize(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    SysctlOutcome::Ready(write_u32_to_buf(4096, buf, buf_len))
}

unsafe fn read_hw_physmem(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u64_to_buf(
        ks.pages_total * ks.page_size.max(4096),
        buf,
        buf_len,
    ))
}

unsafe fn read_hw_usermem(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u64_to_buf(
        ks.pages_free * ks.page_size.max(4096),
        buf,
        buf_len,
    ))
}

unsafe fn read_hw_machine(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    #[cfg(target_arch = "x86_64")]
    {
        return SysctlOutcome::Ready(copy_static(b"x86_64\n", buf, buf_len));
    }
    #[cfg(target_arch = "aarch64")]
    {
        return SysctlOutcome::Ready(copy_static(b"aarch64\n", buf, buf_len));
    }
    #[allow(unreachable_code)]
    SysctlOutcome::Ready(copy_static(b"unknown\n", buf, buf_len))
}

unsafe fn read_hw_model(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    #[cfg(target_arch = "x86_64")]
    {
        return SysctlOutcome::Ready(copy_static(b"SaltyOS x86_64\n", buf, buf_len));
    }
    #[cfg(target_arch = "aarch64")]
    {
        return SysctlOutcome::Ready(copy_static(b"SaltyOS aarch64\n", buf, buf_len));
    }
    #[allow(unreachable_code)]
    SysctlOutcome::Ready(copy_static(b"SaltyOS\n", buf, buf_len))
}

// =========================================================================
// vm.stats.vm.* leaves
// =========================================================================

unsafe fn read_vm_v_page_count(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_total as u32, buf, buf_len))
}

unsafe fn read_vm_v_free_count(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_free as u32, buf, buf_len))
}

unsafe fn read_vm_v_active_count(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_active as u32, buf, buf_len))
}

unsafe fn read_vm_v_inactive_count(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_inactive as u32, buf, buf_len))
}

unsafe fn read_vm_v_wire_count(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    let wired = ks
        .pages_mo_data
        .saturating_add(ks.pages_kernel_pagetable)
        .saturating_add(ks.pages_kernel_stack)
        .saturating_add(ks.pages_kernel_slab)
        .saturating_add(ks.pages_mo_meta)
        .saturating_add(ks.pages_page_cache)
        .saturating_add(ks.pages_emergency_reserve);
    SysctlOutcome::Ready(write_u32_to_buf(wired as u32, buf, buf_len))
}

unsafe fn read_vm_nr_free_pages(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_free as u32, buf, buf_len))
}

unsafe fn read_vm_nr_anon_pages(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    let anon_pages = ks
        .pages_mo_data
        .saturating_sub(ks.pages_file)
        .saturating_sub(ks.pages_anon_shared);
    SysctlOutcome::Ready(write_u32_to_buf(anon_pages as u32, buf, buf_len))
}

unsafe fn read_vm_nr_file_pages(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_file as u32, buf, buf_len))
}

unsafe fn read_vm_nr_shmem(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_anon_shared as u32, buf, buf_len))
}

unsafe fn read_vm_nr_slab_unreclaimable(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_kernel_slab as u32, buf, buf_len))
}

unsafe fn read_vm_nr_page_table_pages(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(
        ks.pages_kernel_pagetable as u32,
        buf,
        buf_len,
    ))
}

unsafe fn read_vm_nr_kernel_stack(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_kernel_stack as u32, buf, buf_len))
}

unsafe fn read_vm_nr_writeback(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(
        ks.pages_writeback_file as u32,
        buf,
        buf_len,
    ))
}

unsafe fn read_vm_nr_dirty(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let ks = unsafe { query_kernel_snapshot() };
    SysctlOutcome::Ready(write_u32_to_buf(ks.pages_dirty_file as u32, buf, buf_len))
}

unsafe fn read_vm_oom_kills_total(
    _ctx: &mut SysctlCtx,
    buf: *mut u8,
    buf_len: usize,
) -> SysctlOutcome {
    let value = system_policy_snapshot()
        .map(|p| p.oom_kills_total as u32)
        .unwrap_or(0);
    SysctlOutcome::Ready(write_u32_to_buf(value, buf, buf_len))
}

/// `vm.loadavg` — `struct loadavg { ldavg: [u32; 3], fscale: i32 }`.
/// SaltyOS does not implement exponential load averaging yet; `ldavg=[0;3]`.
/// `fscale=2048` matches FreeBSD convention.
unsafe fn read_vm_loadavg(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    let arr: [u32; 4] = [0, 0, 0, 2048u32];
    let bytes = ::core::mem::size_of_val(&arr);
    if buf_len < bytes {
        return SysctlOutcome::Ready(0);
    }
    unsafe { ::core::ptr::copy_nonoverlapping(arr.as_ptr() as *const u8, buf, bytes) };
    SysctlOutcome::Ready(bytes)
}

// =========================================================================
// security.* leaves
// =========================================================================

static mut SECURELEVEL: i32 = -1;

unsafe fn read_securelevel(_ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome {
    SysctlOutcome::Ready(unsafe { write_i32_to_buf(*(&raw const SECURELEVEL), buf, buf_len) })
}

/// FreeBSD semantics: `securelevel` can only increase (except from `-1`).
unsafe fn write_securelevel(src: *const u8, len: usize) -> i32 {
    unsafe {
        if len < 1 {
            return -1;
        }
        let val = parse_i32_from_buf(src, len);
        if val < *(&raw const SECURELEVEL) && *(&raw const SECURELEVEL) >= 0 {
            return -1;
        }
        *(&raw mut SECURELEVEL) = val;
        0
    }
}

// =========================================================================
// kern.proc.* — DynamicDirs and the `kern.proc.all` flat-blob leaf
// =========================================================================

/// `kern.proc.all` — `u32 count + KinfoProc[]`. Parks on init: the
/// `SysValue` machine pages every process's init-owned `KinfoProc`,
/// enriches `vm_size` / `vm_rss` from mmsrv, and emits the windowed blob
/// at finalize (so this reactor handler never blocks on init).
unsafe fn read_kern_proc_all(ctx: &mut SysctlCtx, _buf: *mut u8, _buf_len: usize) -> SysctlOutcome {
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::KinfoAll,
        0,
        0,
        0,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Ready(0),
    }
}

unsafe fn lookup_kern_proc_pid(
    ctx: &mut SysctlCtx,
    name: *const u8,
    name_len: usize,
    _buf: *mut u8,
    _buf_cap: usize,
) -> SysctlOutcome {
    let Some(pid) = parse_u32_from_bytes(name, name_len) else {
        return SysctlOutcome::Missing;
    };
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::KinfoSingle,
        pid,
        0,
        0,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Missing,
    }
}

static KERN_PROC_PID_DIR: DynamicDir = DynamicDir::new(b"pid", true, lookup_kern_proc_pid);

unsafe fn lookup_kern_proc_args(
    ctx: &mut SysctlCtx,
    name: *const u8,
    name_len: usize,
    _buf: *mut u8,
    _buf_cap: usize,
) -> SysctlOutcome {
    let Some(pid) = parse_u32_from_bytes(name, name_len) else {
        return SysctlOutcome::Missing;
    };
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::Argv,
        pid,
        0,
        0,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Missing,
    }
}

static KERN_PROC_ARGS_DIR: DynamicDir = DynamicDir::new(b"args", true, lookup_kern_proc_args);

unsafe fn lookup_kern_proc_pathname(
    ctx: &mut SysctlCtx,
    name: *const u8,
    name_len: usize,
    _buf: *mut u8,
    _buf_cap: usize,
) -> SysctlOutcome {
    let Some(pid) = parse_u32_from_bytes(name, name_len) else {
        return SysctlOutcome::Missing;
    };
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::ExePath,
        pid,
        0,
        0,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Missing,
    }
}

static KERN_PROC_PATHNAME_DIR: DynamicDir =
    DynamicDir::new(b"pathname", true, lookup_kern_proc_pathname);

// =========================================================================
// kern.proc filter DynamicDirs — pgrp / tty / uid / ruid / session
//
// FreeBSD semantics: filter dirs are not enumerated (readdir empty,
// `enumerates_pids = false`); `lookup(<value>)` parks on init, pages every
// `KinfoProc`, and keeps those whose selected field equals `<value>`
// (`SysValueKind::KinfoFilter`), packed as `u32 count + KinfoProc[]`.
// =========================================================================

unsafe fn lookup_kern_proc_pgrp(
    ctx: &mut SysctlCtx,
    name: *const u8,
    name_len: usize,
    _buf: *mut u8,
    _buf_cap: usize,
) -> SysctlOutcome {
    let Some(val) = parse_u32_from_bytes(name, name_len) else {
        return SysctlOutcome::Missing;
    };
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::KinfoFilter,
        0,
        SYSCTL_FILTER_PGRP,
        val,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Missing,
    }
}

static KERN_PROC_PGRP_DIR: DynamicDir = DynamicDir::new(b"pgrp", false, lookup_kern_proc_pgrp);

unsafe fn lookup_kern_proc_tty(
    ctx: &mut SysctlCtx,
    name: *const u8,
    name_len: usize,
    _buf: *mut u8,
    _buf_cap: usize,
) -> SysctlOutcome {
    let Some(val) = parse_u32_from_bytes(name, name_len) else {
        return SysctlOutcome::Missing;
    };
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::KinfoFilter,
        0,
        SYSCTL_FILTER_TTY,
        val,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Missing,
    }
}

static KERN_PROC_TTY_DIR: DynamicDir = DynamicDir::new(b"tty", false, lookup_kern_proc_tty);

unsafe fn lookup_kern_proc_uid(
    ctx: &mut SysctlCtx,
    name: *const u8,
    name_len: usize,
    _buf: *mut u8,
    _buf_cap: usize,
) -> SysctlOutcome {
    let Some(val) = parse_u32_from_bytes(name, name_len) else {
        return SysctlOutcome::Missing;
    };
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::KinfoFilter,
        0,
        SYSCTL_FILTER_UID,
        val,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Missing,
    }
}

static KERN_PROC_UID_DIR: DynamicDir = DynamicDir::new(b"uid", false, lookup_kern_proc_uid);

/// SaltyOS tracks `uid` only — no separate ruid/euid split in `KinfoProc`
/// at this time. `kern.proc.ruid.<n>` falls back to `uid` matching.
unsafe fn lookup_kern_proc_ruid(
    ctx: &mut SysctlCtx,
    name: *const u8,
    name_len: usize,
    _buf: *mut u8,
    _buf_cap: usize,
) -> SysctlOutcome {
    let Some(val) = parse_u32_from_bytes(name, name_len) else {
        return SysctlOutcome::Missing;
    };
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::KinfoFilter,
        0,
        SYSCTL_FILTER_RUID,
        val,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Missing,
    }
}

static KERN_PROC_RUID_DIR: DynamicDir = DynamicDir::new(b"ruid", false, lookup_kern_proc_ruid);

unsafe fn lookup_kern_proc_session(
    ctx: &mut SysctlCtx,
    name: *const u8,
    name_len: usize,
    _buf: *mut u8,
    _buf_cap: usize,
) -> SysctlOutcome {
    let Some(val) = parse_u32_from_bytes(name, name_len) else {
        return SysctlOutcome::Missing;
    };
    match begin_sysctl_read(
        ctx.state,
        SysValueKind::KinfoFilter,
        0,
        SYSCTL_FILTER_SESSION,
        val,
        ctx.offset,
        ctx.len,
        ctx.caller_badge,
    ) {
        Some(op_h) => SysctlOutcome::Parked(op_h),
        None => SysctlOutcome::Missing,
    }
}

static KERN_PROC_SESSION_DIR: DynamicDir =
    DynamicDir::new(b"session", false, lookup_kern_proc_session);

// =========================================================================
// Sub-node storage for vm.stats, vm.stats.vm, and kern.proc
// =========================================================================

static mut KERN_PROC_NODE: SysctlNode = SysctlNode::zeroed();
static mut VM_STATS_NODE: SysctlNode = SysctlNode::zeroed();
static mut VM_STATS_VM_NODE: SysctlNode = SysctlNode::zeroed();

/// Set a node's name without importing the private `set_node_name` from
/// `tree.rs`.
///
/// # Safety
///
/// `node` must be a valid, exclusively-accessible `SysctlNode` pointer.
unsafe fn set_node_name_pub(node: &mut SysctlNode, name: &[u8]) {
    let len = name.len().min(NODE_NAME_MAX);
    node.name[..len].copy_from_slice(&name[..len]);
    node.name_len = len as u8;
}

// =========================================================================
// Registration
// =========================================================================

/// Register all built-in sysctl providers on the MIB tree.
///
/// # Safety
///
/// Must be called after `init_tree()` during VFS bootstrap (single-threaded).
pub(crate) unsafe fn init_providers() {
    unsafe {
        // kern.*
        if let Some(kern) = lookup_node_mut(b"kern") {
            kern.add_leaf(
                b"ostype",
                CTLTYPE_STRING,
                CTLFLAG_RD,
                Some(read_ostype),
                None,
            );
            kern.add_leaf(
                b"osrelease",
                CTLTYPE_STRING,
                CTLFLAG_RD,
                Some(read_osrelease),
                None,
            );
            kern.add_leaf(
                b"hostname",
                CTLTYPE_STRING,
                CTLFLAG_RW,
                Some(read_hostname),
                Some(write_hostname),
            );
            kern.add_leaf(
                b"version",
                CTLTYPE_STRING,
                CTLFLAG_RD,
                Some(read_version),
                None,
            );
            kern.add_leaf(
                b"maxproc",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_maxproc),
                None,
            );
            kern.add_leaf(b"ncpu", CTLTYPE_INT, CTLFLAG_RD, Some(read_kern_ncpu), None);
            kern.add_leaf(
                b"cp_time",
                CTLTYPE_OPAQUE,
                CTLFLAG_RD,
                Some(read_kern_cp_time),
                None,
            );
            kern.add_leaf(
                b"cp_times",
                CTLTYPE_OPAQUE,
                CTLFLAG_RD,
                Some(read_kern_cp_times),
                None,
            );
            kern.add_leaf(
                b"boottime",
                CTLTYPE_OPAQUE,
                CTLFLAG_RD,
                Some(read_kern_boottime),
                None,
            );
            kern.add_leaf(
                b"clockrate",
                CTLTYPE_OPAQUE,
                CTLFLAG_RD,
                Some(read_kern_clockrate),
                None,
            );
        }

        // hw.*
        if let Some(hw) = lookup_node_mut(b"hw") {
            hw.add_leaf(b"ncpu", CTLTYPE_INT, CTLFLAG_RD, Some(read_hw_ncpu), None);
            hw.add_leaf(
                b"pagesize",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_hw_pagesize),
                None,
            );
            hw.add_leaf(
                b"physmem",
                CTLTYPE_U64,
                CTLFLAG_RD,
                Some(read_hw_physmem),
                None,
            );
            hw.add_leaf(
                b"usermem",
                CTLTYPE_U64,
                CTLFLAG_RD,
                Some(read_hw_usermem),
                None,
            );
            hw.add_leaf(
                b"machine",
                CTLTYPE_STRING,
                CTLFLAG_RD,
                Some(read_hw_machine),
                None,
            );
            hw.add_leaf(
                b"model",
                CTLTYPE_STRING,
                CTLFLAG_RD,
                Some(read_hw_model),
                None,
            );
        }

        // vm.stats and vm.stats.vm sub-nodes + leaves. Registration order
        // matters: parent nodes must be present before `lookup_node_mut`
        // can reach them via dotted-path traversal.
        {
            let stats = &raw mut VM_STATS_NODE;
            set_node_name_pub(&mut *stats, b"stats");
            if let Some(vm) = lookup_node_mut(b"vm") {
                vm.add_node(&raw const VM_STATS_NODE);
            }
        }
        {
            let stats_vm = &raw mut VM_STATS_VM_NODE;
            set_node_name_pub(&mut *stats_vm, b"vm");
            if let Some(stats) = lookup_node_mut(b"vm.stats") {
                stats.add_node(&raw const VM_STATS_VM_NODE);
            }
        }
        if let Some(vm_stats_vm) = lookup_node_mut(b"vm.stats.vm") {
            vm_stats_vm.add_leaf(
                b"v_page_count",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_v_page_count),
                None,
            );
            vm_stats_vm.add_leaf(
                b"v_free_count",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_v_free_count),
                None,
            );
            vm_stats_vm.add_leaf(
                b"v_active_count",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_v_active_count),
                None,
            );
            vm_stats_vm.add_leaf(
                b"v_inactive_count",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_v_inactive_count),
                None,
            );
            vm_stats_vm.add_leaf(
                b"v_wire_count",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_v_wire_count),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_free_pages",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_free_pages),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_anon_pages",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_anon_pages),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_file_pages",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_file_pages),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_shmem",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_shmem),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_slab_unreclaimable",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_slab_unreclaimable),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_page_table_pages",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_page_table_pages),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_kernel_stack",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_kernel_stack),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_writeback",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_writeback),
                None,
            );
            vm_stats_vm.add_leaf(
                b"nr_dirty",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_nr_dirty),
                None,
            );
            vm_stats_vm.add_leaf(
                b"oom_kills_total",
                CTLTYPE_INT,
                CTLFLAG_RD,
                Some(read_vm_oom_kills_total),
                None,
            );
        }

        // vm.loadavg lives directly under `vm`, not under `vm.stats`.
        if let Some(vm) = lookup_node_mut(b"vm") {
            vm.add_leaf(
                b"loadavg",
                CTLTYPE_OPAQUE,
                CTLFLAG_RD,
                Some(read_vm_loadavg),
                None,
            );
        }

        // kern.proc sub-node + leaves + dynamic dirs. Must register the
        // `kern.proc` node before adding children to it.
        {
            let proc_node = &raw mut KERN_PROC_NODE;
            set_node_name_pub(&mut *proc_node, b"proc");
            if let Some(kern) = lookup_node_mut(b"kern") {
                kern.add_node(&raw const KERN_PROC_NODE);
            }
        }
        if let Some(kproc) = lookup_node_mut(b"kern.proc") {
            kproc.add_leaf(
                b"all",
                CTLTYPE_OPAQUE,
                CTLFLAG_RD,
                Some(read_kern_proc_all),
                None,
            );
            kproc.add_dynamic(&raw const KERN_PROC_PID_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_ARGS_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_PATHNAME_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_PGRP_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_TTY_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_UID_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_RUID_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_SESSION_DIR);
        }

        // security.*
        if let Some(sec) = lookup_node_mut(b"security") {
            sec.add_leaf(
                b"securelevel",
                CTLTYPE_INT,
                CTLFLAG_RW,
                Some(read_securelevel),
                Some(write_securelevel),
            );
        }

        // Default hostname.
        let default = b"saltyos";
        HOSTNAME[..default.len()].copy_from_slice(default);
        HOSTNAME_LEN = default.len();
    }
}
