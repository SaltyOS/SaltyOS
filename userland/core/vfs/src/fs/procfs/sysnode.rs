// SPDX-License-Identifier: GPL-2.0-only
//
//! `/proc/{stat,meminfo,uptime,cpuinfo,loadavg}` content
//! generators. These files are Linux-format projections of the
//! same kernel / mmsrv / init data sysctlfs exposes as
//! FreeBSD-style MIB leaves; both sides consume `fs::metrics::*`
//! getters and only the formatting differs.

use crate::fs::metrics::{
    MAX_CPUS, PolicySnapshot, SystemCpuHeader, SystemCpuTicks, SystemProcStats, TronaSysMemInfo,
    boot_time_ns, system_committed_as, system_cpu, system_kernel_snapshot, system_policy_snapshot,
    uptime_ns,
};

use super::generators::{append_bytes, append_u32_dec, append_u64_dec};

/// Linux `USER_HZ` — clock ticks per second the `/proc/stat` user
/// / system / idle accumulators report. Hard-wired to 100 (10 ms
/// tick) on every architecture so userspace tools relying on the
/// constant do not need a runtime `sysconf(_SC_CLK_TCK)` lookup.
pub(super) const TICKS_PER_SEC: u64 = 100;

#[inline]
fn ns_to_ticks(ns: u64) -> u64 {
    (((ns as u128).saturating_mul(TICKS_PER_SEC as u128)) / 1_000_000_000u128) as u64
}

/// Format `/proc/stat` from a prefetched [`SystemProcStats`]. The
/// `GET_SYSTEM_STATS` init query runs in the async prefetch phase
/// (`init_rpc`); the per-CPU lines, `ctxt`, and `btime` come from the
/// `SystemInfo` / `Clock` caps inline — kernel invokes that always
/// return, so there is no reactor cycle.
pub(crate) unsafe fn proc_gen_sys_stat(stats: &SystemProcStats, buf: &mut [u8]) -> usize {
    let mut hdr = SystemCpuHeader::zeroed();
    let mut cpus = [SystemCpuTicks::zeroed(); MAX_CPUS];
    let written = match system_cpu(&mut hdr, &mut cpus) {
        Ok(n) => n,
        Err(_) => 0,
    };

    let mut pos = 0usize;
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

    append_bytes(buf, &mut pos, b"intr 0\n");

    append_bytes(buf, &mut pos, b"ctxt ");
    append_u64_dec(buf, &mut pos, hdr.context_switches_total);
    append_bytes(buf, &mut pos, b"\n");

    append_bytes(buf, &mut pos, b"btime ");
    let btime_sec = boot_time_ns().unwrap_or(hdr.boot_time_ns) / 1_000_000_000;
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

/// Generate `/proc/meminfo`. Bytes-to-kB conversion lives in
/// `emit_mem_line`.
pub(super) unsafe fn proc_gen_meminfo(buf: &mut [u8]) -> usize {
    let ks = system_kernel_snapshot().unwrap_or(TronaSysMemInfo::zeroed());
    let policy = system_policy_snapshot().unwrap_or(PolicySnapshot::default());
    let committed_as = system_committed_as().unwrap_or(0);

    let page_sz = ks.page_size.max(1);
    let kernel_mem_total = ks.pages_total * page_sz;
    let kernel_mem_free = ks.pages_free * page_sz;
    let mem_total = if policy.mem_total_bytes != 0 {
        policy.mem_total_bytes
    } else {
        kernel_mem_total
    };
    let mem_free = if policy.mem_free_bytes != 0 {
        policy.mem_free_bytes
    } else {
        kernel_mem_free
    };
    let emergency_reserve = ks.pages_emergency_reserve * page_sz;
    let cached = if policy.page_cache_bytes != 0 {
        policy.page_cache_bytes
    } else {
        ks.pages_page_cache * page_sz
    };
    let reclaimable = policy.reclaimable_bytes.min(cached);
    let mem_available = mem_free
        .saturating_sub(emergency_reserve)
        .saturating_add(reclaimable)
        .min(mem_total);
    let slab = if policy.slab_bytes != 0 {
        policy.slab_bytes
    } else {
        ks.pages_kernel_slab * page_sz
    };
    let anon_pages = ks
        .pages_mo_data
        .saturating_sub(ks.pages_file)
        .saturating_sub(ks.pages_anon_shared)
        * page_sz;
    let shmem = ks.pages_anon_shared * page_sz;
    let mapped = ks.pages_file * page_sz;
    let dirty = ks.pages_dirty_file * page_sz;
    let writeback = ks.pages_writeback_file * page_sz;
    let active = if ks.pages_active != 0 {
        ks.pages_active * page_sz
    } else {
        policy
            .mem_used_bytes
            .saturating_sub(cached)
            .saturating_sub(slab)
    };
    let inactive = ks.pages_inactive * page_sz;
    let sunreclaim = slab;
    let kernel_stack = ks.pages_kernel_stack * page_sz;
    let page_tables = ks.pages_kernel_pagetable * page_sz;
    let commit_base = mem_total.saturating_sub(emergency_reserve);
    let commit_limit = commit_base.saturating_add(commit_base / 2);

    let mut pos = 0usize;
    emit_mem_line(buf, &mut pos, b"MemTotal:", mem_total);
    emit_mem_line(buf, &mut pos, b"MemFree:", mem_free);
    emit_mem_line(buf, &mut pos, b"MemAvailable:", mem_available);
    emit_mem_line(buf, &mut pos, b"Buffers:", 0);
    emit_mem_line(buf, &mut pos, b"Cached:", cached);
    emit_mem_line(buf, &mut pos, b"SwapCached:", 0);
    emit_mem_line(buf, &mut pos, b"Active:", active);
    emit_mem_line(buf, &mut pos, b"Inactive:", inactive);
    emit_mem_line(buf, &mut pos, b"AnonPages:", anon_pages);
    emit_mem_line(buf, &mut pos, b"Mapped:", mapped);
    emit_mem_line(buf, &mut pos, b"Shmem:", shmem);
    emit_mem_line(buf, &mut pos, b"Dirty:", dirty);
    emit_mem_line(buf, &mut pos, b"Writeback:", writeback);
    emit_mem_line(buf, &mut pos, b"Slab:", slab);
    emit_mem_line(buf, &mut pos, b"SReclaimable:", 0);
    emit_mem_line(buf, &mut pos, b"SUnreclaim:", sunreclaim);
    emit_mem_line(buf, &mut pos, b"KernelStack:", kernel_stack);
    emit_mem_line(buf, &mut pos, b"PageTables:", page_tables);
    emit_mem_line(buf, &mut pos, b"SwapTotal:", 0);
    emit_mem_line(buf, &mut pos, b"SwapFree:", 0);
    emit_mem_line(buf, &mut pos, b"VmallocTotal:", 0);
    emit_mem_line(buf, &mut pos, b"VmallocUsed:", 0);
    emit_mem_line(buf, &mut pos, b"VmallocChunk:", 0);
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

/// Generate `/proc/uptime`. Format:
/// `<up_sec>.<cs> <idle_sec>.<cs>\n`, centiseconds zero-padded.
pub(super) unsafe fn proc_gen_uptime(buf: &mut [u8]) -> usize {
    let up_ns = match uptime_ns() {
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
    let cs = (rem_ns / 10_000_000) as u32;
    (sec, cs)
}

fn append_cs(buf: &mut [u8], pos: &mut usize, cs: u32) {
    let cs = cs.min(99);
    let tens = b'0' + ((cs / 10) as u8);
    let ones = b'0' + ((cs % 10) as u8);
    append_bytes(buf, pos, &[tens, ones]);
}

/// Generate `/proc/cpuinfo`. One block per online CPU. Fields
/// follow the Linux layout so consumers counting `processor :`
/// lines or reading `siblings` / `cpu cores` work unchanged.
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

/// Format `/proc/loadavg` from a prefetched [`SystemProcStats`]. Pure
/// formatter — the `GET_SYSTEM_STATS` init query runs in the async
/// prefetch phase (`init_rpc`), not here.
pub(crate) fn proc_gen_loadavg(stats: &SystemProcStats, buf: &mut [u8]) -> usize {
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
