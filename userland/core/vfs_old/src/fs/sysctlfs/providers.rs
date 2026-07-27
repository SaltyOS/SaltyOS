// SPDX-License-Identifier: GPL-2.0-only
//! Built-in sysctl value providers.
//!
//! Each provider is a pair of read/write callbacks registered as a leaf on
//! the appropriate MIB subtree. Write callbacks are only provided for
//! read-write leaves (e.g. kern.hostname).
//!
//! Leaves that require live kernel data call `trona_kernel::syscall::sys_sysinfo()`
//! (SYS_SYSINFO = 29) for CPU/uptime statistics, or send
//! `MM_GET_SYSTEM_MEMINFO` to mmsrv for memory statistics.

use super::tree::*;

use trona_kernel::core_types::kinfo::KinfoProc;
use trona_kernel::core_types::{TronaMsg, TronaSysInfo, TronaSysInfoCpu};
use trona_kernel::ipc;
use trona_protocol::posix::procmgr::{
    INIT_GET_ARGV, INIT_GET_EXE_PATH, INIT_GET_KINFO_PROC, INIT_LIST_PIDS_BUF,
};
use uapi::*;

use crate::fs::metrics::{TronaSysMemInfo, system_kernel_snapshot};

// =========================================================================
// sysinfo helpers
// =========================================================================

/// Maximum CPU count we allocate stack space for.
const MAX_STACK_CPUS: usize = 16;

/// Call SYS_SYSINFO. Returns (header, cpu_array, cpus_written).
/// cpu_array is valid for indices 0..cpus_written.
unsafe fn query_sysinfo() -> (TronaSysInfo, [TronaSysInfoCpu; MAX_STACK_CPUS], usize) {
    unsafe {
        let mut hdr = TronaSysInfo::zeroed();
        let mut cpus = [TronaSysInfoCpu::zeroed(); MAX_STACK_CPUS];
        let written = match trona_kernel::syscall::sys_sysinfo(
            &raw mut hdr,
            cpus.as_mut_ptr(),
            MAX_STACK_CPUS as u64,
        ) {
            Some(n) => n as usize,
            None => 0,
        };
        (hdr, cpus, written)
    }
}

#[inline]
fn ns_to_ticks(ns: u64) -> u64 {
    (((ns as u128).saturating_mul(TICKS_PER_SEC as u128)) / 1_000_000_000u128) as u64
}

// =========================================================================
// kernel snapshot helper
// =========================================================================

/// Query SYS_SYSMEMINFO for a raw PMM snapshot. Returns zeroed on failure.
unsafe fn query_kernel_snapshot() -> TronaSysMemInfo {
    system_kernel_snapshot().unwrap_or(TronaSysMemInfo::zeroed())
}

// =========================================================================
// kern.ostype
// =========================================================================

unsafe fn read_ostype(buf: *mut u8, buf_len: usize) -> usize {
    copy_static(b"SaltyOS\n", buf, buf_len)
}

// =========================================================================
// kern.osrelease
// =========================================================================

unsafe fn read_osrelease(buf: *mut u8, buf_len: usize) -> usize {
    copy_static(b"0.1.0\n", buf, buf_len)
}

// =========================================================================
// kern.hostname
// =========================================================================

/// Mutable hostname buffer. Defaults to "saltyos", writable via sysctl.
static mut HOSTNAME: [u8; 256] = [0; 256];
static mut HOSTNAME_LEN: usize = 0;

unsafe fn read_hostname(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let len = *(&raw const HOSTNAME_LEN);
        let n = if len < buf_len { len } else { buf_len };
        core::ptr::copy_nonoverlapping((&raw const HOSTNAME) as *const u8, buf, n);
        n
    }
}

unsafe fn write_hostname(src: *const u8, len: usize) -> i32 {
    unsafe {
        // Strip trailing newline if present (echo "foo" > /sys/kern/hostname).
        let mut n = len;
        if n > 0 && *src.add(n - 1) == b'\n' {
            n -= 1;
        }
        if n > 255 {
            n = 255;
        }
        core::ptr::copy_nonoverlapping(src, (&raw mut HOSTNAME) as *mut u8, n);
        *(&raw mut HOSTNAME).cast::<u8>().add(n) = 0;
        *(&raw mut HOSTNAME_LEN) = n;
        0
    }
}

// =========================================================================
// kern.version
// =========================================================================

unsafe fn read_version(buf: *mut u8, buf_len: usize) -> usize {
    copy_static(b"SaltyOS 0.1.0\n", buf, buf_len)
}

// =========================================================================
// kern.maxproc
// =========================================================================

unsafe fn read_maxproc(buf: *mut u8, buf_len: usize) -> usize {
    write_u32_to_buf(256, buf, buf_len)
}

// =========================================================================
// kern.ncpu
// =========================================================================

unsafe fn read_kern_ncpu(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let (hdr, _, _) = query_sysinfo();
        write_u32_to_buf(hdr.cpu_count, buf, buf_len)
    }
}

// =========================================================================
// kern.cp_time
//
// Binary blob: 5 × u64 in order [user, nice, sys, intr, idle].
// nice and intr are zero (SaltyOS does not account these separately).
// Aggregate across all CPUs.
// =========================================================================

unsafe fn read_kern_cp_time(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let (_, cpus, written) = query_sysinfo();
        let mut user: u64 = 0;
        let mut sys: u64 = 0;
        let mut idle: u64 = 0;
        for i in 0..written {
            user = user.saturating_add(ns_to_ticks(cpus[i].user_time_ns));
            sys = sys.saturating_add(ns_to_ticks(cpus[i].system_time_ns));
            idle = idle.saturating_add(ns_to_ticks(cpus[i].idle_time_ns));
        }
        // [user, nice=0, sys, intr=0, idle]
        let arr: [u64; 5] = [user, 0, sys, 0, idle];
        let bytes = arr.len() * core::mem::size_of::<u64>();
        if buf_len < bytes {
            return 0;
        }
        core::ptr::copy_nonoverlapping(arr.as_ptr() as *const u8, buf, bytes);
        bytes
    }
}

// =========================================================================
// kern.cp_times
//
// Binary blob: (5 × cpu_count) u64 values. Each group of 5 is one CPU
// in order [user, nice=0, sys, intr=0, idle].
// =========================================================================

unsafe fn read_kern_cp_times(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let (_, cpus, written) = query_sysinfo();
        let needed = written * 5 * core::mem::size_of::<u64>();
        if buf_len < needed || needed == 0 {
            return 0;
        }
        let mut out = buf;
        for i in 0..written {
            let arr: [u64; 5] = [
                ns_to_ticks(cpus[i].user_time_ns),
                0,
                ns_to_ticks(cpus[i].system_time_ns),
                0,
                ns_to_ticks(cpus[i].idle_time_ns),
            ];
            core::ptr::copy_nonoverlapping(
                arr.as_ptr() as *const u8,
                out,
                5 * core::mem::size_of::<u64>(),
            );
            out = out.add(5 * core::mem::size_of::<u64>());
        }
        needed
    }
}

// =========================================================================
// kern.boottime
//
// Binary blob: struct timeval { tv_sec: u64, tv_usec: u64 }.
// boot_time_ns is wall-clock nanoseconds at boot; convert to sec+usec.
// =========================================================================

unsafe fn read_kern_boottime(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let (hdr, _, _) = query_sysinfo();
        let tv_sec = hdr.boot_time_ns / 1_000_000_000;
        let tv_usec = (hdr.boot_time_ns % 1_000_000_000) / 1_000;
        let arr: [u64; 2] = [tv_sec, tv_usec];
        let bytes = arr.len() * core::mem::size_of::<u64>();
        if buf_len < bytes {
            return 0;
        }
        core::ptr::copy_nonoverlapping(arr.as_ptr() as *const u8, buf, bytes);
        bytes
    }
}

// =========================================================================
// kern.clockrate
//
// Binary blob: struct clockinfo { hz: u32, tick: u32, profhz: u32, stathz: u32 }.
// SaltyOS runs at 100 Hz (TICKS_PER_SEC). tick = 1_000_000 / hz (µs per tick).
// =========================================================================

unsafe fn read_kern_clockrate(buf: *mut u8, buf_len: usize) -> usize {
    let hz: u32 = 100;
    let tick: u32 = 1_000_000 / hz; // microseconds per tick
    let profhz: u32 = hz;
    let stathz: u32 = hz;
    let arr: [u32; 4] = [hz, tick, profhz, stathz];
    let bytes = arr.len() * core::mem::size_of::<u32>();
    if buf_len < bytes {
        return 0;
    }
    unsafe { core::ptr::copy_nonoverlapping(arr.as_ptr() as *const u8, buf, bytes) };
    bytes
}

// =========================================================================
// hw.ncpu (real value from sysinfo, replacing placeholder)
// =========================================================================

unsafe fn read_hw_ncpu(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let (hdr, _, _) = query_sysinfo();
        write_u32_to_buf(hdr.cpu_count, buf, buf_len)
    }
}

// =========================================================================
// hw.pagesize
// =========================================================================

unsafe fn read_hw_pagesize(buf: *mut u8, buf_len: usize) -> usize {
    write_u32_to_buf(4096, buf, buf_len)
}

// =========================================================================
// hw.physmem (real value from mmsrv)
// =========================================================================

unsafe fn read_hw_physmem(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u64_to_buf(ks.pages_total * ks.page_size.max(4096), buf, buf_len)
    }
}

// =========================================================================
// hw.usermem
//
// Memory available to userspace right now (mem_free from mmsrv).
// =========================================================================

unsafe fn read_hw_usermem(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u64_to_buf(ks.pages_free * ks.page_size.max(4096), buf, buf_len)
    }
}

// =========================================================================
// hw.machine
// =========================================================================

unsafe fn read_hw_machine(buf: *mut u8, buf_len: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    return copy_static(b"x86_64\n", buf, buf_len);
    #[cfg(target_arch = "aarch64")]
    return copy_static(b"aarch64\n", buf, buf_len);
    #[allow(unreachable_code)]
    copy_static(b"unknown\n", buf, buf_len)
}

// =========================================================================
// hw.model
// =========================================================================

unsafe fn read_hw_model(buf: *mut u8, buf_len: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    return copy_static(b"SaltyOS x86_64\n", buf, buf_len);
    #[cfg(target_arch = "aarch64")]
    return copy_static(b"SaltyOS aarch64\n", buf, buf_len);
    #[allow(unreachable_code)]
    copy_static(b"SaltyOS\n", buf, buf_len)
}

// =========================================================================
// vm.stats.vm.v_page_count
// vm.stats.vm.v_free_count
// vm.stats.vm.v_active_count
// vm.stats.vm.v_inactive_count
// vm.stats.vm.v_wire_count
//
// All are u32 page counts. mem_total/4096 = v_page_count.
// Active/inactive now come from the kernel's referenced-page aging sweep;
// wired pages remain "everything currently not free/untyped-reserved".
// =========================================================================

unsafe fn read_vm_v_page_count(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_total as u32, buf, buf_len)
    }
}

unsafe fn read_vm_v_free_count(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_free as u32, buf, buf_len)
    }
}

unsafe fn read_vm_v_active_count(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_active as u32, buf, buf_len)
    }
}

unsafe fn read_vm_v_inactive_count(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_inactive as u32, buf, buf_len)
    }
}

unsafe fn read_vm_v_wire_count(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        // Wired = everything not free and not untyped-reserved
        let wired = ks
            .pages_mo_data
            .saturating_add(ks.pages_kernel_pagetable)
            .saturating_add(ks.pages_kernel_stack)
            .saturating_add(ks.pages_kernel_slab)
            .saturating_add(ks.pages_mo_meta)
            .saturating_add(ks.pages_page_cache)
            .saturating_add(ks.pages_emergency_reserve);
        write_u32_to_buf(wired as u32, buf, buf_len)
    }
}

// =========================================================================
// vm.stats.vm.nr_* — Linux-style per-category page counters.
// =========================================================================

unsafe fn read_vm_nr_free_pages(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_free as u32, buf, buf_len)
    }
}

unsafe fn read_vm_nr_anon_pages(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        let anon_pages = ks
            .pages_mo_data
            .saturating_sub(ks.pages_file)
            .saturating_sub(ks.pages_anon_shared);
        write_u32_to_buf(anon_pages as u32, buf, buf_len)
    }
}

unsafe fn read_vm_nr_file_pages(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_file as u32, buf, buf_len)
    }
}

unsafe fn read_vm_nr_shmem(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_anon_shared as u32, buf, buf_len)
    }
}

unsafe fn read_vm_nr_slab_unreclaimable(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_kernel_slab as u32, buf, buf_len)
    }
}

unsafe fn read_vm_nr_page_table_pages(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_kernel_pagetable as u32, buf, buf_len)
    }
}

unsafe fn read_vm_nr_kernel_stack(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_kernel_stack as u32, buf, buf_len)
    }
}

unsafe fn read_vm_nr_writeback(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_writeback_file as u32, buf, buf_len)
    }
}

unsafe fn read_vm_nr_dirty(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let ks = query_kernel_snapshot();
        write_u32_to_buf(ks.pages_dirty_file as u32, buf, buf_len)
    }
}

unsafe fn read_vm_oom_kills_total(buf: *mut u8, buf_len: usize) -> usize {
    let value = crate::fs::metrics::system_policy_snapshot()
        .map(|p| p.oom_kills_total as u32)
        .unwrap_or(0);
    unsafe { write_u32_to_buf(value, buf, buf_len) }
}

// =========================================================================
// vm.loadavg
//
// Binary blob: struct loadavg { ldavg: [u32; 3], fscale: i32 }.
// SaltyOS does not implement exponential load averaging yet; ldavg=[0,0,0].
// fscale=2048 matches FreeBSD convention.
// =========================================================================

unsafe fn read_vm_loadavg(buf: *mut u8, buf_len: usize) -> usize {
    // [ldavg[0], ldavg[1], ldavg[2], fscale] as u32 words (fscale reinterpreted)
    let arr: [u32; 4] = [0, 0, 0, 2048u32];
    let bytes = arr.len() * core::mem::size_of::<u32>();
    if buf_len < bytes {
        return 0;
    }
    unsafe { core::ptr::copy_nonoverlapping(arr.as_ptr() as *const u8, buf, bytes) };
    bytes
}

// =========================================================================
// security.securelevel
// =========================================================================

static mut SECURELEVEL: i32 = -1;

unsafe fn read_securelevel(buf: *mut u8, buf_len: usize) -> usize {
    unsafe { write_i32_to_buf(*(&raw const SECURELEVEL), buf, buf_len) }
}

unsafe fn write_securelevel(src: *const u8, len: usize) -> i32 {
    unsafe {
        if len < 1 {
            return -1;
        }
        let val = parse_i32_from_buf(src, len);
        // FreeBSD semantics: securelevel can only increase (except from -1).
        if val < *(&raw const SECURELEVEL) && *(&raw const SECURELEVEL) >= 0 {
            return -1;
        }
        *(&raw mut SECURELEVEL) = val;
        0
    }
}

// =========================================================================
// Formatting helpers
// =========================================================================

fn copy_static(val: &[u8], buf: *mut u8, buf_len: usize) -> usize {
    let n = if val.len() < buf_len {
        val.len()
    } else {
        buf_len
    };
    unsafe { core::ptr::copy_nonoverlapping(val.as_ptr(), buf, n) };
    n
}

fn write_u32_to_buf(val: u32, buf: *mut u8, buf_len: usize) -> usize {
    let mut tmp = [0u8; 16];
    let len = fmt_u32(val, &mut tmp);
    if len < tmp.len() {
        tmp[len] = b'\n';
    }
    let total = len + 1;
    let n = if total < buf_len { total } else { buf_len };
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
    n
}

fn write_u64_to_buf(val: u64, buf: *mut u8, buf_len: usize) -> usize {
    let mut tmp = [0u8; 24];
    let len = fmt_u64(val, &mut tmp);
    if len < tmp.len() {
        tmp[len] = b'\n';
    }
    let total = len + 1;
    let n = if total < buf_len { total } else { buf_len };
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
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
    let n = if total < buf_len { total } else { buf_len };
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
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

unsafe fn parse_i32_from_buf(src: *const u8, len: usize) -> i32 {
    unsafe {
        let mut pos = 0usize;
        let neg = if pos < len && *src == b'-' {
            pos += 1;
            true
        } else {
            false
        };
        // Skip leading whitespace / trailing newline.
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
            if b < b'0' || b > b'9' {
                break;
            }
            val = val.wrapping_mul(10).wrapping_add((b - b'0') as i32);
            pos += 1;
        }
        if neg { val.wrapping_neg() } else { val }
    }
}

// =========================================================================
// kern.proc — procmgr IPC helpers
// =========================================================================

/// Maximum path length for exe path (matches procfs MAX_PATH_LEN).
const PROC_MAX_PATH: usize = 256;

/// Maximum pid batch size per INIT_LIST_PIDS_BUF call.
/// IPC reserved area is [u64; 465] = 3720 bytes; at 4 bytes/pid → up to 930.
const PIDS_PER_BATCH: usize = 64;

/// Maximum argv length surfaced per call. Matches procmgr argv_buf size.
const ARGV_MAX: usize = 512;

/// Fetch a single KinfoProc from procmgr. Returns None on IPC failure or
/// if the pid is not found.
unsafe fn fetch_kinfo_proc(pid: u32) -> Option<KinfoProc> {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_KINFO_PROC;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let ctx = crate::ipc_ctx();
        let err = ipc::call_ctx(
            ctx,
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }
        let buf = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;
        let mut kp = KinfoProc::zeroed();
        let copy_len = core::mem::size_of::<KinfoProc>();
        core::ptr::copy_nonoverlapping(buf, &raw mut kp as *mut u8, copy_len);
        Some(kp)
    }
}

/// Fetch a batch of pids from procmgr into `out[0..cap]`.
/// Returns (count_written, total_pids). Uses a single IPC call.
unsafe fn fetch_pids_batch(offset: u32, out: *mut u32, cap: usize) -> (usize, u32) {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_LIST_PIDS_BUF;
        msg.length = 2;
        msg.regs[0] = offset as u64;
        msg.regs[1] = cap as u64;
        let ctx = crate::ipc_ctx();
        let err = ipc::call_ctx(
            ctx,
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return (0, 0);
        }
        let count = (reply.regs[0] as usize).min(cap);
        let total = reply.regs[1] as u32;
        let src = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u32;
        core::ptr::copy_nonoverlapping(src, out, count);
        (count, total)
    }
}

/// Fetch argv for a pid. Returns byte length in `out_bytes`, or 0 on failure.
/// Bytes are NUL-separated.
unsafe fn fetch_argv(pid: u32, out: *mut u8, out_cap: usize) -> usize {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_ARGV;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let ctx = crate::ipc_ctx();
        let err = ipc::call_ctx(
            ctx,
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let argv_len = (reply.regs[0] as usize).min(out_cap).min(ARGV_MAX);
        let src = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;
        core::ptr::copy_nonoverlapping(src, out, argv_len);
        argv_len
    }
}

/// Fetch exe path for a pid into `out`. Returns byte length or 0 on failure.
unsafe fn fetch_exe_path(pid: u32, out: *mut u8, out_cap: usize) -> usize {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_EXE_PATH;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let ctx = crate::ipc_ctx();
        let err = ipc::call_ctx(
            ctx,
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let path_len = (reply.regs[0] as usize).min(out_cap).min(PROC_MAX_PATH);
        if path_len == 0 {
            return 0;
        }
        // Path bytes packed into regs[1..] (not the reserved area).
        let src = &reply.regs[1] as *const u64 as *const u8;
        core::ptr::copy_nonoverlapping(src, out, path_len);
        path_len
    }
}

/// Parse an unsigned decimal integer from raw bytes. Returns None if empty or
/// any byte is non-digit.
fn parse_u32_from_bytes(name: *const u8, len: usize) -> Option<u32> {
    if len == 0 {
        return None;
    }
    let mut val: u32 = 0;
    for i in 0..len {
        let b = unsafe { *name.add(i) };
        if b < b'0' || b > b'9' {
            return None;
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u32);
    }
    Some(val)
}

/// Write an unsigned decimal u32 as ASCII into `buf`. Returns bytes written.
fn fmt_pid(pid: u32, buf: &mut [u8]) -> usize {
    if pid == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    let mut v = pid;
    while v > 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let n = len.min(buf.len());
    for i in 0..n {
        buf[i] = tmp[len - 1 - i];
    }
    n
}

// =========================================================================
// kern.proc.all — binary blob: u32 count + KinfoProc[]
// =========================================================================

unsafe fn read_kern_proc_all(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        if buf_len < 4 {
            return 0;
        }
        // Reserve first 4 bytes for count; will fill after iteration.
        let count_ptr = buf as *mut u32;
        let mut out_pos = 4usize;
        let kp_size = core::mem::size_of::<KinfoProc>();
        let mut count = 0u32;
        let mut offset = 0u32;
        let mut batch = [0u32; PIDS_PER_BATCH];
        loop {
            let (got, total) = fetch_pids_batch(offset, batch.as_mut_ptr(), PIDS_PER_BATCH);
            if got == 0 {
                break;
            }
            for i in 0..got {
                if out_pos + kp_size > buf_len {
                    break;
                }
                if let Some(kp) = fetch_kinfo_proc(batch[i]) {
                    core::ptr::copy_nonoverlapping(
                        &kp as *const KinfoProc as *const u8,
                        buf.add(out_pos),
                        kp_size,
                    );
                    out_pos += kp_size;
                    count += 1;
                }
            }
            offset += got as u32;
            if offset >= total || got < PIDS_PER_BATCH {
                break;
            }
        }
        core::ptr::write_unaligned(count_ptr, count);
        out_pos
    }
}

// =========================================================================
// kern.proc.pid DynamicDir — lookup by pid, list enumerates all pids
// =========================================================================

unsafe fn list_kern_proc_pid(out: *mut DynamicName, out_cap: usize) -> usize {
    unsafe {
        let mut written = 0usize;
        let mut offset = 0u32;
        let mut batch = [0u32; PIDS_PER_BATCH];
        'outer: loop {
            let (got, total) = fetch_pids_batch(offset, batch.as_mut_ptr(), PIDS_PER_BATCH);
            if got == 0 {
                break;
            }
            for i in 0..got {
                if written >= out_cap {
                    break 'outer;
                }
                let entry = &mut *out.add(written);
                *entry = DynamicName::zeroed();
                let n = fmt_pid(batch[i], &mut entry.bytes);
                entry.len = n as u8;
                written += 1;
            }
            offset += got as u32;
            if offset >= total || got < PIDS_PER_BATCH {
                break;
            }
        }
        written
    }
}

unsafe fn lookup_kern_proc_pid(
    name: *const u8,
    name_len: usize,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    let pid = parse_u32_from_bytes(name, name_len)?;
    let kp = unsafe { fetch_kinfo_proc(pid)? };
    let kp_size = core::mem::size_of::<KinfoProc>();
    if buf_cap < kp_size {
        return None;
    }
    unsafe { core::ptr::copy_nonoverlapping(&kp as *const KinfoProc as *const u8, buf, kp_size) };
    Some(kp_size)
}

static KERN_PROC_PID_DIR: DynamicDir =
    DynamicDir::new(b"pid", list_kern_proc_pid, lookup_kern_proc_pid);

// =========================================================================
// kern.proc.args DynamicDir — lookup returns NUL-separated argv
// =========================================================================

unsafe fn list_kern_proc_args(out: *mut DynamicName, out_cap: usize) -> usize {
    // Same enumeration as pid — list all active pids.
    unsafe { list_kern_proc_pid(out, out_cap) }
}

unsafe fn lookup_kern_proc_args(
    name: *const u8,
    name_len: usize,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    let pid = parse_u32_from_bytes(name, name_len)?;
    let n = unsafe { fetch_argv(pid, buf, buf_cap) };
    if n == 0 { None } else { Some(n) }
}

static KERN_PROC_ARGS_DIR: DynamicDir =
    DynamicDir::new(b"args", list_kern_proc_args, lookup_kern_proc_args);

// =========================================================================
// kern.proc.pathname DynamicDir — lookup returns exe path
// =========================================================================

unsafe fn list_kern_proc_pathname(out: *mut DynamicName, out_cap: usize) -> usize {
    unsafe { list_kern_proc_pid(out, out_cap) }
}

unsafe fn lookup_kern_proc_pathname(
    name: *const u8,
    name_len: usize,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    let pid = parse_u32_from_bytes(name, name_len)?;
    let n = unsafe { fetch_exe_path(pid, buf, buf_cap) };
    if n == 0 { None } else { Some(n) }
}

static KERN_PROC_PATHNAME_DIR: DynamicDir = DynamicDir::new(
    b"pathname",
    list_kern_proc_pathname,
    lookup_kern_proc_pathname,
);

// =========================================================================
// kern.proc filter DynamicDirs — pgrp / tty / uid / ruid / session
//
// FreeBSD convention: list returns empty (avoid expensive full scan for
// directory enumeration), lookup filters all pids by the named field value
// and returns a binary blob of u32_count + KinfoProc[] for matching entries.
// =========================================================================

/// Generic filter-by-field lookup: iterates all pids, fetches KinfoProc, and
/// packs entries whose `field` value equals `filter_val` into `buf`.
unsafe fn filter_lookup_by_field(
    filter_val: u32,
    field_of: unsafe fn(&KinfoProc) -> u32,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    unsafe {
        if buf_cap < 4 {
            return None;
        }
        let count_ptr = buf as *mut u32;
        let mut out_pos = 4usize;
        let kp_size = core::mem::size_of::<KinfoProc>();
        let mut count = 0u32;
        let mut offset = 0u32;
        let mut batch = [0u32; PIDS_PER_BATCH];
        'outer: loop {
            let (got, total) = fetch_pids_batch(offset, batch.as_mut_ptr(), PIDS_PER_BATCH);
            if got == 0 {
                break;
            }
            for i in 0..got {
                if out_pos + kp_size > buf_cap {
                    break 'outer;
                }
                if let Some(kp) = fetch_kinfo_proc(batch[i]) {
                    if field_of(&kp) == filter_val {
                        core::ptr::copy_nonoverlapping(
                            &kp as *const KinfoProc as *const u8,
                            buf.add(out_pos),
                            kp_size,
                        );
                        out_pos += kp_size;
                        count += 1;
                    }
                }
            }
            offset += got as u32;
            if offset >= total || got < PIDS_PER_BATCH {
                break;
            }
        }
        core::ptr::write_unaligned(count_ptr, count);
        Some(out_pos)
    }
}

/// Empty list — filter dirs do not enumerate child names.
unsafe fn list_empty(_out: *mut DynamicName, _out_cap: usize) -> usize {
    0
}

// --- kern.proc.pgrp ---

unsafe fn lookup_kern_proc_pgrp(
    name: *const u8,
    name_len: usize,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    let val = parse_u32_from_bytes(name, name_len)?;
    unsafe fn pgid_of(kp: &KinfoProc) -> u32 {
        kp.pgid
    }
    unsafe { filter_lookup_by_field(val, pgid_of, buf, buf_cap) }
}

static KERN_PROC_PGRP_DIR: DynamicDir = DynamicDir::new(b"pgrp", list_empty, lookup_kern_proc_pgrp);

// --- kern.proc.tty ---

unsafe fn lookup_kern_proc_tty(
    name: *const u8,
    name_len: usize,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    let val = parse_u32_from_bytes(name, name_len)?;
    unsafe fn tty_of(kp: &KinfoProc) -> u32 {
        kp.tty_dev
    }
    unsafe { filter_lookup_by_field(val, tty_of, buf, buf_cap) }
}

static KERN_PROC_TTY_DIR: DynamicDir = DynamicDir::new(b"tty", list_empty, lookup_kern_proc_tty);

// --- kern.proc.uid ---

unsafe fn lookup_kern_proc_uid(
    name: *const u8,
    name_len: usize,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    let val = parse_u32_from_bytes(name, name_len)?;
    unsafe fn uid_of(kp: &KinfoProc) -> u32 {
        kp.uid
    }
    unsafe { filter_lookup_by_field(val, uid_of, buf, buf_cap) }
}

static KERN_PROC_UID_DIR: DynamicDir = DynamicDir::new(b"uid", list_empty, lookup_kern_proc_uid);

// --- kern.proc.ruid ---

unsafe fn lookup_kern_proc_ruid(
    name: *const u8,
    name_len: usize,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    // SaltyOS tracks uid only (no separate ruid/euid split in KinfoProc at this time).
    let val = parse_u32_from_bytes(name, name_len)?;
    unsafe fn uid_of(kp: &KinfoProc) -> u32 {
        kp.uid
    }
    unsafe { filter_lookup_by_field(val, uid_of, buf, buf_cap) }
}

static KERN_PROC_RUID_DIR: DynamicDir = DynamicDir::new(b"ruid", list_empty, lookup_kern_proc_ruid);

// --- kern.proc.session ---

unsafe fn lookup_kern_proc_session(
    name: *const u8,
    name_len: usize,
    buf: *mut u8,
    buf_cap: usize,
) -> Option<usize> {
    let val = parse_u32_from_bytes(name, name_len)?;
    unsafe fn sid_of(kp: &KinfoProc) -> u32 {
        kp.sid
    }
    unsafe { filter_lookup_by_field(val, sid_of, buf, buf_cap) }
}

static KERN_PROC_SESSION_DIR: DynamicDir =
    DynamicDir::new(b"session", list_empty, lookup_kern_proc_session);

// =========================================================================
// Sub-node storage for vm.stats, vm.stats.vm, and kern.proc
// =========================================================================

/// Static node for the `kern.proc` MIB directory.
static mut KERN_PROC_NODE: SysctlNode = SysctlNode::zeroed();

/// Static node for the `vm.stats` MIB directory.
static mut VM_STATS_NODE: SysctlNode = SysctlNode::zeroed();

/// Static node for the `vm.stats.vm` MIB directory.
static mut VM_STATS_VM_NODE: SysctlNode = SysctlNode::zeroed();

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

        // vm.stats and vm.stats.vm sub-nodes + leaves.
        // Registration order matters: parent nodes must be registered before
        // lookup_node_mut can reach them via dotted-path traversal.
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

        // vm.loadavg — top-level under vm, not under vm.stats.
        if let Some(vm) = lookup_node_mut(b"vm") {
            vm.add_leaf(
                b"loadavg",
                CTLTYPE_OPAQUE,
                CTLFLAG_RD,
                Some(read_vm_loadavg),
                None,
            );
        }

        // kern.proc sub-node + leaves + dynamic dirs.
        // Must register the kern.proc node before adding children to it.
        {
            let proc_node = &raw mut KERN_PROC_NODE;
            set_node_name_pub(&mut *proc_node, b"proc");
            if let Some(kern) = lookup_node_mut(b"kern") {
                kern.add_node(&raw const KERN_PROC_NODE);
            }
        }
        if let Some(kproc) = lookup_node_mut(b"kern.proc") {
            // kern.proc.all — flat binary blob of all KinfoProc structs.
            kproc.add_leaf(
                b"all",
                CTLTYPE_OPAQUE,
                CTLFLAG_RD,
                Some(read_kern_proc_all),
                None,
            );
            // Per-pid, per-argv, per-pathname dynamic dirs.
            kproc.add_dynamic(&raw const KERN_PROC_PID_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_ARGS_DIR);
            kproc.add_dynamic(&raw const KERN_PROC_PATHNAME_DIR);
            // Filter dirs — list returns empty, lookup filters by field value.
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

        // Initialize hostname default.
        let default = b"saltyos";
        HOSTNAME[..default.len()].copy_from_slice(default);
        HOSTNAME_LEN = default.len();
    }
}

/// Set a node's name — thin wrapper so providers.rs can initialize sub-nodes
/// without importing the private `set_node_name` from tree.rs.
///
/// # Safety
///
/// `node` must be a valid, exclusively-accessible `SysctlNode` pointer.
unsafe fn set_node_name_pub(node: &mut SysctlNode, name: &[u8]) {
    let len = if name.len() < NODE_NAME_MAX {
        name.len()
    } else {
        NODE_NAME_MAX
    };
    node.name[..len].copy_from_slice(&name[..len]);
    node.name_len = len as u8;
}
