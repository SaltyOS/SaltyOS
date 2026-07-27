// SPDX-License-Identifier: GPL-2.0-only
//! Kernel CPU / uptime metrics. Backed by `SYS_SYSINFO`.

use trona_kernel::core_types::{TronaSysInfo, TronaSysInfoCpu};
use trona_kernel::syscall::sys_sysinfo;
use uapi::*;

/// Upper bound for per-CPU runtime arrays in metrics callers. Matches the
/// kernel `MAX_CPUS` ceiling referenced by sysctlfs / procfs leaves. The
/// kernel reports the actual online count via `TronaSysInfo.cpu_count`;
/// callers must not index beyond the returned `cpus_written`.
pub(crate) const MAX_CPUS: usize = 256;

/// Typed alias for the header shape returned by `sys_sysinfo`.
pub(crate) type SystemCpuHeader = TronaSysInfo;

/// Typed alias for a single per-CPU runtime entry.
pub(crate) type SystemCpuTicks = TronaSysInfoCpu;

/// Read a full system CPU snapshot into caller-provided buffers.
///
/// The kernel fills `header` unconditionally and writes up to
/// `cpus.len()` entries of the per-CPU array. `header.cpu_count` records
/// the number of online CPUs (may be larger than `cpus.len()`); the
/// number of entries actually written is returned and also stored in
/// `header.cpus_written`.
pub(crate) fn system_cpu(
    header: &mut SystemCpuHeader,
    cpus: &mut [SystemCpuTicks],
) -> Result<usize, i32> {
    *header = SystemCpuHeader::zeroed();
    let capacity = cpus.len() as u64;
    match sys_sysinfo(header as *mut SystemCpuHeader, cpus.as_mut_ptr(), capacity) {
        Some(written) => Ok(written as usize),
        None => Err(TRONA_INVALID_OPERATION as i32),
    }
}

/// Read only the uptime component of the system CPU snapshot.
///
/// Uptime is counted in kernel-monotonic nanoseconds from [`crate::BOOT_TIME_NS`]
/// capture time; `/proc/uptime` and `kern.boottime` both derive from this.
pub(crate) fn uptime_ns() -> Result<u64, i32> {
    let mut hdr = SystemCpuHeader::zeroed();
    match sys_sysinfo(&raw mut hdr, core::ptr::null_mut(), 0) {
        Some(_) => Ok(hdr.uptime_ns),
        None => Err(TRONA_INVALID_OPERATION as i32),
    }
}

/// Read only the boot-time anchor component.
///
/// This is the wall-clock-ish timestamp the kernel captured immediately
/// after arch init. SaltyOS has no RTC plumbing yet, so callers should
/// treat this as a monotonic reference rather than an absolute epoch
/// until `docs/design/posix.md` documents a real wall clock path.
pub(crate) fn boot_time_ns() -> Result<u64, i32> {
    let mut hdr = SystemCpuHeader::zeroed();
    match sys_sysinfo(&raw mut hdr, core::ptr::null_mut(), 0) {
        Some(_) => Ok(hdr.boot_time_ns),
        None => Err(TRONA_INVALID_OPERATION as i32),
    }
}
