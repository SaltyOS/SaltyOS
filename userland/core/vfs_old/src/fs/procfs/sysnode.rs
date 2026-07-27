// SPDX-License-Identifier: GPL-2.0-only
//! /proc/{stat,meminfo,uptime,cpuinfo,loadavg} content generators.
//!
//! These files are Linux-format projections of the same kernel / mmsrv /
//! procmgr data that sysctlfs exposes as FreeBSD-style MIB leaves. Both
//! sides consume `crate::fs::metrics::*` getters; formatting is the only
//! thing that differs.

use uapi::TICKS_PER_SEC;

use crate::fs::metrics::{
    SystemCpuHeader, SystemCpuTicks, SystemProcStats, TronaSysMemInfo, system_committed_as,
    system_cpu, system_kernel_snapshot, system_policy_snapshot, system_proc_stats,
};

use super::generators::{append_bytes, append_u32_dec, append_u64_dec};

const MAX_CPUS: usize = 256;

#[inline]
fn ns_to_ticks(ns: u64) -> u64 {
    (((ns as u128).saturating_mul(TICKS_PER_SEC as u128)) / 1_000_000_000u128) as u64
}

/// Generate `/proc/stat` content.
pub(super) unsafe fn proc_gen_stat(buf: &mut [u8]) -> usize {
    let mut hdr = SystemCpuHeader::zeroed();
    let mut cpus = [SystemCpuTicks::zeroed(); MAX_CPUS];
    let written = match system_cpu(&mut hdr, &mut cpus) {
        Ok(n) => n,
        Err(_) => 0,
    };

    let stats = system_proc_stats().unwrap_or(SystemProcStats::default());

    let mut pos = 0usize;

    // Aggregate `cpu` line (sum of all per-CPU values).
    let mut agg_user: u64 = 0;
    let mut agg_sys: u64 = 0;
    let mut agg_idle: u64 = 0;
    for i in 0..written {
        agg_user = agg_user.saturating_add(ns_to_ticks(cpus[i].user_time_ns));
        agg_sys = agg_sys.saturating_add(ns_to_ticks(cpus[i].system_time_ns));
        agg_idle = agg_idle.saturating_add(ns_to_ticks(cpus[i].idle_time_ns));
    }

    write_cpu_line(buf, &mut pos, None, agg_user, agg_sys, agg_idle);
    for i in 0..written {
        write_cpu_line(
            buf,
            &mut pos,
            Some(i as u32),
            ns_to_ticks(cpus[i].user_time_ns),
            ns_to_ticks(cpus[i].system_time_ns),
            ns_to_ticks(cpus[i].idle_time_ns),
        );
    }

    // `intr`, `ctxt`, `btime`, `processes`, `procs_running`, `procs_blocked`.
    append_bytes(buf, &mut pos, b"intr 0\n");

    append_bytes(buf, &mut pos, b"ctxt ");
    append_u64_dec(buf, &mut pos, hdr.context_switches_total);
    append_bytes(buf, &mut pos, b"\n");

    append_bytes(buf, &mut pos, b"btime ");
    let btime_sec = hdr.boot_time_ns / 1_000_000_000;
    append_u64_dec(buf, &mut pos, btime_sec);
    append_bytes(buf, &mut pos, b"\n");

    append_bytes(buf, &mut pos, b"processes ");
    append_u32_dec(buf, &mut pos, stats.procs_total);
    append_bytes(buf, &mut pos, b"\n");

    append_bytes(buf, &mut pos, b"procs_running ");
    append_u32_dec(buf, &mut pos, stats.procs_running);
    append_bytes(buf, &mut pos, b"\n");

    append_bytes(buf, &mut pos, b"procs_blocked 0\n");

    pos
}

fn write_cpu_line(
    buf: &mut [u8],
    pos: &mut usize,
    cpu_idx: Option<u32>,
    user: u64,
    sys: u64,
    idle: u64,
) {
    append_bytes(buf, pos, b"cpu");
    match cpu_idx {
        Some(n) => append_u32_dec(buf, pos, n),
        None => append_bytes(buf, pos, b" "),
    }
    append_bytes(buf, pos, b" ");
    append_u64_dec(buf, pos, user);
    append_bytes(buf, pos, b" 0 "); // nice
    append_u64_dec(buf, pos, sys);
    append_bytes(buf, pos, b" ");
    append_u64_dec(buf, pos, idle);
    append_bytes(buf, pos, b" 0 0 0 0\n"); // iowait irq softirq steal
}

/// Generate `/proc/meminfo` content (bytes → kB conversion).
pub(super) unsafe fn proc_gen_meminfo(buf: &mut [u8]) -> usize {
    let ks = system_kernel_snapshot().unwrap_or(TronaSysMemInfo::zeroed());
    let policy = system_policy_snapshot().unwrap_or_default();
    let committed_as = system_committed_as().unwrap_or(0);

    let page_sz = ks.page_size.max(1);
    let mem_total = ks.pages_total * page_sz;
    let mem_free = ks.pages_free * page_sz;
    let emergency_reserve = ks.pages_emergency_reserve * page_sz;
    let cached = if policy.page_cache_bytes != 0 {
        policy.page_cache_bytes
    } else {
        ks.pages_page_cache * page_sz
    };
    let reclaimable = policy.reclaimable_bytes.min(cached);
    // MemAvailable: usable free pages (excluding the emergency reserve)
    // plus page-cache pages that mmsrv can safely reclaim right now.
    let mem_available = mem_free
        .saturating_sub(emergency_reserve)
        .saturating_add(reclaimable)
        .min(mem_total);
    let slab = ks.pages_kernel_slab * page_sz;
    let anon_pages = ks
        .pages_mo_data
        .saturating_sub(ks.pages_file)
        .saturating_sub(ks.pages_anon_shared)
        * page_sz;
    let shmem = ks.pages_anon_shared * page_sz;
    let mapped = ks.pages_file * page_sz;
    let dirty = ks.pages_dirty_file * page_sz;
    let writeback = ks.pages_writeback_file * page_sz;
    let active = ks.pages_active * page_sz;
    let inactive = ks.pages_inactive * page_sz;
    let sunreclaim = slab; // no reclaim accounting yet
    let kernel_stack = ks.pages_kernel_stack * page_sz;
    let page_tables = ks.pages_kernel_pagetable * page_sz;
    // CommitLimit: usable physical memory + 50% overcommit (no swap).
    let commit_base = mem_total.saturating_sub(emergency_reserve);
    let commit_limit = commit_base.saturating_add(commit_base / 2);

    let mut pos = 0usize;
    emit_mem_line(buf, &mut pos, b"MemTotal:", mem_total);
    emit_mem_line(buf, &mut pos, b"MemFree:", mem_free);
    emit_mem_line(buf, &mut pos, b"MemAvailable:", mem_available);
    emit_mem_line(buf, &mut pos, b"Buffers:", 0); // 0: no buffer cache
    emit_mem_line(buf, &mut pos, b"Cached:", cached);
    emit_mem_line(buf, &mut pos, b"SwapCached:", 0); // 0: no swap
    emit_mem_line(buf, &mut pos, b"Active:", active);
    emit_mem_line(buf, &mut pos, b"Inactive:", inactive);
    emit_mem_line(buf, &mut pos, b"AnonPages:", anon_pages);
    emit_mem_line(buf, &mut pos, b"Mapped:", mapped);
    emit_mem_line(buf, &mut pos, b"Shmem:", shmem);
    emit_mem_line(buf, &mut pos, b"Dirty:", dirty);
    emit_mem_line(buf, &mut pos, b"Writeback:", writeback);
    emit_mem_line(buf, &mut pos, b"Slab:", slab);
    emit_mem_line(buf, &mut pos, b"SReclaimable:", 0); // 0: no reclaim accounting
    emit_mem_line(buf, &mut pos, b"SUnreclaim:", sunreclaim);
    emit_mem_line(buf, &mut pos, b"KernelStack:", kernel_stack);
    emit_mem_line(buf, &mut pos, b"PageTables:", page_tables);
    emit_mem_line(buf, &mut pos, b"SwapTotal:", 0); // 0: no swap
    emit_mem_line(buf, &mut pos, b"SwapFree:", 0); // 0: no swap
    emit_mem_line(buf, &mut pos, b"VmallocTotal:", 0); // 0: no vmalloc
    emit_mem_line(buf, &mut pos, b"VmallocUsed:", 0); // 0: no vmalloc
    emit_mem_line(buf, &mut pos, b"VmallocChunk:", 0); // 0: no vmalloc
    emit_mem_line(buf, &mut pos, b"CommitLimit:", commit_limit);
    emit_mem_line(buf, &mut pos, b"Committed_AS:", committed_as);
    pos
}

fn emit_mem_line(buf: &mut [u8], pos: &mut usize, label: &[u8], bytes: u64) {
    append_bytes(buf, pos, label);
    append_bytes(buf, pos, b" ");
    append_u64_dec(buf, pos, bytes / 1024);
    append_bytes(buf, pos, b" kB\n");
}

/// Generate `/proc/uptime` content.
///
/// Format: `<up_sec>.<cs> <idle_sec>.<cs>\n`, centiseconds zero-padded.
pub(super) unsafe fn proc_gen_uptime(buf: &mut [u8]) -> usize {
    let up_ns = match crate::fs::metrics::uptime_ns() {
        Ok(n) => n,
        Err(_) => 0,
    };
    let (up_sec, up_cs) = ns_to_sec_cs(up_ns);

    let mut idle_hdr = SystemCpuHeader::zeroed();
    let mut idle_cpus = [SystemCpuTicks::zeroed(); MAX_CPUS];
    let idle_time_ns: u64 = match system_cpu(&mut idle_hdr, &mut idle_cpus) {
        Ok(n) => {
            let mut sum: u64 = 0;
            for i in 0..n {
                sum = sum.saturating_add(idle_cpus[i].idle_time_ns);
            }
            sum
        }
        Err(_) => 0,
    };
    let (idle_sec, idle_cs) = ns_to_sec_cs(idle_time_ns);

    let mut pos = 0usize;
    append_u64_dec(buf, &mut pos, up_sec);
    append_bytes(buf, &mut pos, b".");
    append_cs(buf, &mut pos, up_cs);
    append_bytes(buf, &mut pos, b" ");
    append_u64_dec(buf, &mut pos, idle_sec);
    append_bytes(buf, &mut pos, b".");
    append_cs(buf, &mut pos, idle_cs);
    append_bytes(buf, &mut pos, b"\n");
    pos
}

fn ns_to_sec_cs(ns: u64) -> (u64, u32) {
    let sec = ns / 1_000_000_000;
    let rem_ns = ns % 1_000_000_000;
    let cs = (rem_ns / 10_000_000) as u32; // 10^7 ns = 1 cs
    (sec, cs)
}

fn append_cs(buf: &mut [u8], pos: &mut usize, cs: u32) {
    let cs = cs.min(99);
    let tens = b'0' + ((cs / 10) as u8);
    let ones = b'0' + ((cs % 10) as u8);
    append_bytes(buf, pos, &[tens, ones]);
}

/// Generate `/proc/cpuinfo` content.
///
/// One block per online CPU. Fields follow the Linux layout so that
/// consumers counting `processor :` lines or reading `siblings` /
/// `cpu cores` work unchanged. CPU vendor / model / MHz are placeholders
/// pending CPUID / MIDR_EL1 brand-string extraction.
pub(super) unsafe fn proc_gen_cpuinfo(buf: &mut [u8]) -> usize {
    let mut hdr = SystemCpuHeader::zeroed();
    let mut dummy: [SystemCpuTicks; 0] = [];
    let _ = system_cpu(&mut hdr, &mut dummy);
    let cpu_count = hdr.cpu_count.max(1);

    let model_name: &[u8] = b"SaltyOS Generic CPU";
    let vendor: &[u8] = b"SaltyOS";

    let mut pos = 0usize;
    for i in 0..cpu_count {
        append_bytes(buf, &mut pos, b"processor\t: ");
        append_u32_dec(buf, &mut pos, i);
        append_bytes(buf, &mut pos, b"\nvendor_id\t: ");
        append_bytes(buf, &mut pos, vendor);
        append_bytes(buf, &mut pos, b"\nmodel name\t: ");
        append_bytes(buf, &mut pos, model_name);
        append_bytes(
            buf,
            &mut pos,
            b"\ncpu MHz\t\t: 0.000\ncache size\t: 0 KB\nphysical id\t: 0\nsiblings\t: ",
        );
        append_u32_dec(buf, &mut pos, cpu_count);
        append_bytes(buf, &mut pos, b"\ncore id\t\t: ");
        append_u32_dec(buf, &mut pos, i);
        append_bytes(buf, &mut pos, b"\ncpu cores\t: ");
        append_u32_dec(buf, &mut pos, cpu_count);
        append_bytes(buf, &mut pos, b"\nflags\t\t:\n\n");
    }
    pos
}

/// Generate `/proc/loadavg` content.
///
/// Load averages are placeholders (0.00) until a sampling task is added.
/// Running / total / last pid come from `INIT_GET_SYSTEM_STATS`.
pub(super) unsafe fn proc_gen_loadavg(buf: &mut [u8]) -> usize {
    let stats = system_proc_stats().unwrap_or(SystemProcStats::default());

    let mut pos = 0usize;
    append_bytes(buf, &mut pos, b"0.00 0.00 0.00 ");
    append_u32_dec(buf, &mut pos, stats.procs_running);
    append_bytes(buf, &mut pos, b"/");
    append_u32_dec(buf, &mut pos, stats.procs_total);
    append_bytes(buf, &mut pos, b" ");
    append_u32_dec(buf, &mut pos, stats.last_pid);
    append_bytes(buf, &mut pos, b"\n");
    pos
}
