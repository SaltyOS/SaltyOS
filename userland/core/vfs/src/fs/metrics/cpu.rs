// SPDX-License-Identifier: GPL-2.0-only
//
//! Kernel CPU / uptime metrics. The kernel owns both the monotonic
//! clock (`Clock` cap) and the per-CPU runtime accumulators
//! (`SystemInfo` cap, `KERNITE_INV_SYSINFO_GET_INFO`), so procfs reads
//! them directly — no init round-trip, no reactor cycle.

use trona_protocol::init::{TronaSysInfo, TronaSysInfoCpu};

/// Upper bound for per-CPU runtime arrays in metrics callers.
/// Matches the kernel `MAX_CPUS` ceiling. The kernel reports the
/// actual online count via `TronaSysInfo.cpu_count`; callers must
/// not index beyond the returned `cpus_written`.
pub(crate) const MAX_CPUS: usize = 256;

pub(crate) type SystemCpuHeader = TronaSysInfo;
pub(crate) type SystemCpuTicks = TronaSysInfoCpu;

/// Read a full system CPU snapshot into caller-provided buffers.
///
/// Invokes the `SystemInfo` cap directly: the kernel writes the
/// header and up to `cpus.len()` per-CPU records, returning the count
/// actually written. Returns that count (clamped to the slice). A
/// `SystemInfo` invoke is a kernel operation that always returns
/// immediately, so calling it from the owner reactor cannot deadlock.
pub(crate) fn system_cpu(
    header: &mut SystemCpuHeader,
    cpus: &mut [SystemCpuTicks],
) -> Result<usize, i32> {
    *header = SystemCpuHeader::zeroed();
    let sysinfo = trona_runtime::client::caps::system_info_cap().addr();
    if sysinfo == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }
    let r = trona_kernel::syscall::system_get_info(
        sysinfo,
        header as *mut SystemCpuHeader,
        cpus.as_mut_ptr(),
        cpus.len() as u64,
    );
    if r.error != 0 {
        return Err(r.error as i32);
    }
    Ok((r.value as usize).min(cpus.len()))
}

/// Read only the uptime component. Uses the `Clock` cap directly
/// for a single-invoke fast path — no per-CPU snapshot required.
pub(crate) fn uptime_ns() -> Result<u64, i32> {
    let clock = trona_runtime::client::caps::clock_cap().addr();
    if clock == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }
    Ok(trona_kernel::syscall::clock_read_monotonic(clock))
}

/// Read the boot-time anchor. SaltyOS has no RTC plumbing yet, so
/// this falls back to the same monotonic value as `uptime_ns` when
/// the kernel has not populated a wall-clock origin (the
/// `boot_time_ns` field of the `SystemInfo` header).
pub(crate) fn boot_time_ns() -> Result<u64, i32> {
    let mut hdr = SystemCpuHeader::zeroed();
    let mut empty: [SystemCpuTicks; 0] = [];
    system_cpu(&mut hdr, &mut empty)?;
    if hdr.boot_time_ns != 0 {
        Ok(hdr.boot_time_ns)
    } else {
        uptime_ns()
    }
}
