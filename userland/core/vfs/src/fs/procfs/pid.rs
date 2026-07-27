// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-process `/proc/<pid>/` IPC queries and content generators.
//!
//! All routines share the same shape: query init via the
//! `INIT_GET_PROC_INFO` sub-op family for process-table state,
//! query mmsrv for region / VMA snapshots, and format the result
//! into Linux-shaped ASCII.

use trona_kernel::core_types::{IPC_BUFFER_RESERVED_BYTES, IpcContext, TronaMsg};
use trona_kernel::ipc::mp_call_ctx;
use trona_protocol::common::TRONA_OK;
use trona_protocol::init::{INIT_GET_PROC_INFO, INIT_GET_PROC_INFO_SUB_GET_PROC_INFO_FULL};

use crate::fs::metrics::proc::{ProcInfoFull, ProcTimes};
use trona_protocol::mm::{MM_LIST_RESERVATIONS, MM_LIST_VMAS};

use crate::fs::metrics::proc::ArgvBuf;
use crate::fs::metrics::{PerPidMemSnapshot, per_pid_mem_snapshot};

use super::generators::{
    append_bytes, append_u32_dec, append_u64_dec, fmt_u32, fmt_u64, fmt_u64_hex,
};
use super::sysnode::TICKS_PER_SEC;

#[inline]
unsafe fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

/// Query init for a process-table summary. Returns true on
/// success.
pub(super) unsafe fn proc_get_info(
    pid: u32,
    ppid: &mut u32,
    pgid: &mut u32,
    sid: &mut u32,
    state: &mut u8,
    name: &mut [u8; 32],
    start_time_ns: &mut u64,
    tty_dev: &mut u64,
    tty_pgrp: &mut u32,
) -> bool {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_PROC_INFO;
        msg.length = 2;
        msg.regs[0] = INIT_GET_PROC_INFO_SUB_GET_PROC_INFO_FULL;
        msg.regs[1] = pid as u64;
        let err = mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::init_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }
        *ppid = reply.regs[1] as u32;
        *pgid = reply.regs[2] as u32;
        *sid = reply.regs[3] as u32;
        *state = reply.regs[4] as u8;
        let src = &reply.regs[5] as *const u64 as *const u8;
        for i in 0..32 {
            name[i] = *src.add(i);
        }
        *start_time_ns = reply.regs[9];
        *tty_dev = reply.regs[10];
        *tty_pgrp = reply.regs[11] as u32;
        true
    }
}

/// Fetch per-process memory stats via the metrics layer.
#[inline]
pub(super) fn proc_get_mem_stats(pid: u32) -> Option<PerPidMemSnapshot> {
    per_pid_mem_snapshot(pid).ok()
}

/// Probe whether `pid` is currently tracked by init.
pub(super) unsafe fn proc_pid_exists(pid: u32) -> bool {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        let mut start_time_ns: u64 = 0;
        let mut tty_dev: u64 = 0;
        let mut tty_pgrp: u32 = 0;
        proc_get_info(
            pid,
            &mut ppid,
            &mut pgid,
            &mut sid,
            &mut state,
            &mut name,
            &mut start_time_ns,
            &mut tty_dev,
            &mut tty_pgrp,
        )
    }
}

/// Append `<label><value>\n` (u32) to `buf`.
unsafe fn append_kv_u32(buf: &mut [u8], pos: &mut usize, label: &[u8], value: u32) {
    append_bytes(buf, pos, label);
    append_u32_dec(buf, pos, value);
    append_bytes(buf, pos, b"\n");
}

/// Append `<label><kb> kB\n` to `buf`.
unsafe fn append_kv_kb(buf: &mut [u8], pos: &mut usize, label: &[u8], kb: u64) {
    append_bytes(buf, pos, label);
    append_u64_dec(buf, pos, kb);
    append_bytes(buf, pos, b" kB\n");
}

/// Append `<label> <kb> kB\n` (smaps spacing) to `buf`.
fn smaps_emit_kb(buf: &mut [u8], pos: &mut usize, label: &[u8], kb: u64) {
    append_bytes(buf, pos, label);
    append_bytes(buf, pos, b" ");
    append_u64_dec(buf, pos, kb);
    append_bytes(buf, pos, b" kB\n");
}

/// Format `/proc/<pid>/status` from prefetched init results. Pure
/// formatter — `info` / `pt` run in the async prefetch phase; `mem`
/// (`GET_CLIENT_VM_STATS`) is optional (Vm*/Rss* report 0 until that
/// init arm lands).
pub(crate) unsafe fn proc_gen_status(
    pid: u32,
    info: &ProcInfoFull,
    pt: &ProcTimes,
    mem: Option<&PerPidMemSnapshot>,
    buf: &mut [u8],
) -> usize {
    unsafe {
        let ppid = info.ppid;
        let pgid = info.pgid;
        let sid = info.sid;
        let state = info.state;
        let mut name = info.name;

        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            name[0] = b'?';
            name_len = 1;
        }

        let buf_size = buf.len();
        let dst = buf.as_mut_ptr();
        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // Name.
        for b in b"Name:\t" {
            if pos < buf_size {
                *dst.add(pos) = *b;
                pos += 1;
            }
        }
        for i in 0..name_len {
            if pos < buf_size {
                *dst.add(pos) = name[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *dst.add(pos) = b'\n';
            pos += 1;
        }

        // State letter.
        for b in b"State:\t" {
            if pos < buf_size {
                *dst.add(pos) = *b;
                pos += 1;
            }
        }
        // init `ProcessState` discriminant → Linux state char:
        // Active=1→R, Stopped=2→T, Zombie=3→Z.
        let st_char = match state {
            1 => b'R',
            2 => b'T',
            3 => b'Z',
            _ => b'?',
        };
        if pos < buf_size {
            *dst.add(pos) = st_char;
            pos += 1;
        }
        if pos < buf_size {
            *dst.add(pos) = b'\n';
            pos += 1;
        }

        // Pid / PPid / Pgid / Sid lines.
        for (label, value) in [
            (&b"Pid:\t"[..], pid),
            (&b"PPid:\t"[..], ppid),
            (&b"Pgid:\t"[..], pgid),
            (&b"Sid:\t"[..], sid),
        ] {
            for b in label {
                if pos < buf_size {
                    *dst.add(pos) = *b;
                    pos += 1;
                }
            }
            let n = fmt_u32(value, &mut tmp);
            for i in 0..n {
                if pos < buf_size {
                    *dst.add(pos) = tmp[i];
                    pos += 1;
                }
            }
            if pos < buf_size {
                *dst.add(pos) = b'\n';
                pos += 1;
            }
        }

        let threads = if pt.num_threads == 0 {
            1
        } else {
            pt.num_threads
        };
        let snap = mem.copied().unwrap_or_default();

        let page_sz: u64 = 4096;
        let vm_size_kb = snap.vm_reserved_bytes / 1024;
        let vm_rss_kb = snap.vm_resident_pages * (page_sz / 1024);
        let vm_peak_kb = snap.vm_peak_reserved_bytes / 1024;
        let vm_hwm_kb = snap.vm_peak_resident_pages * (page_sz / 1024);
        let vm_data_kb = snap.vm_data_bytes / 1024;
        let vm_stk_kb = snap.vm_stk_bytes / 1024;
        let vm_exe_kb = snap.vm_exe_bytes / 1024;
        let vm_lib_kb = snap.vm_lib_bytes / 1024;
        let rss_anon_kb = snap.resident_anon * (page_sz / 1024);
        let rss_file_kb = snap.resident_file * (page_sz / 1024);
        let rss_shm_kb = snap.resident_shm * (page_sz / 1024);
        let vm_pt_kb = snap.vm_pt_pages * (page_sz / 1024);

        let mut pos_ref = pos;
        append_kv_u32(buf, &mut pos_ref, b"Threads:\t", threads);
        append_kv_kb(buf, &mut pos_ref, b"VmPeak:\t", vm_peak_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmSize:\t", vm_size_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmLck:\t", 0);
        append_kv_kb(buf, &mut pos_ref, b"VmHWM:\t", vm_hwm_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmRSS:\t", vm_rss_kb);
        append_kv_kb(buf, &mut pos_ref, b"RssAnon:\t", rss_anon_kb);
        append_kv_kb(buf, &mut pos_ref, b"RssFile:\t", rss_file_kb);
        append_kv_kb(buf, &mut pos_ref, b"RssShmem:\t", rss_shm_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmData:\t", vm_data_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmStk:\t", vm_stk_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmExe:\t", vm_exe_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmLib:\t", vm_lib_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmPTE:\t", vm_pt_kb);
        append_kv_kb(buf, &mut pos_ref, b"VmSwap:\t", 0);
        append_kv_kb(buf, &mut pos_ref, b"HugetlbPages:\t", 0);
        pos = pos_ref;

        pos
    }
}

/// Format `/proc/<pid>/stat` from prefetched init results. Pure
/// formatter — `info` (`GET_PROC_INFO_FULL`) and `pt` (`GET_PROC_TIMES`)
/// run in the async prefetch phase; `mem` (`GET_CLIENT_VM_STATS`) is
/// optional (vsize/rss report 0 until that init arm lands).
pub(crate) unsafe fn proc_gen_stat(
    pid: u32,
    info: &ProcInfoFull,
    pt: &ProcTimes,
    mem: Option<&PerPidMemSnapshot>,
    buf: &mut [u8],
) -> usize {
    unsafe {
        let ppid = info.ppid;
        let pgid = info.pgid;
        let sid = info.sid;
        let state = info.state;
        let mut name = info.name;
        let start_time_ns = info.start_time_ns;
        let tty_dev = info.tty_dev;
        let tty_pgrp = info.tty_pgrp;

        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            name[0] = b'?';
            name_len = 1;
        }

        let buf_size = buf.len();
        let dst = buf.as_mut_ptr();
        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n {
            if pos < buf_size {
                *dst.add(pos) = tmp[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *dst.add(pos) = b' ';
            pos += 1;
        }
        if pos < buf_size {
            *dst.add(pos) = b'(';
            pos += 1;
        }
        for i in 0..name_len {
            if pos < buf_size {
                *dst.add(pos) = name[i];
                pos += 1;
            }
        }
        if pos < buf_size {
            *dst.add(pos) = b')';
            pos += 1;
        }
        if pos < buf_size {
            *dst.add(pos) = b' ';
            pos += 1;
        }
        // init `ProcessState` discriminant → Linux stat state char:
        // Active=1→R, Stopped=2→T, Zombie=3→Z (others unknown).
        let st_char = match state {
            1 => b'R',
            2 => b'T',
            3 => b'Z',
            _ => b'?',
        };
        if pos < buf_size {
            *dst.add(pos) = st_char;
            pos += 1;
        }
        if pos < buf_size {
            *dst.add(pos) = b' ';
            pos += 1;
        }
        for value in [ppid, pgid, sid] {
            let n = fmt_u32(value, &mut tmp);
            for i in 0..n {
                if pos < buf_size {
                    *dst.add(pos) = tmp[i];
                    pos += 1;
                }
            }
            if pos < buf_size {
                *dst.add(pos) = b' ';
                pos += 1;
            }
        }
        // Last space inserted by the loop above is intentional —
        // the next field follows directly.

        let ticks_per_sec = TICKS_PER_SEC;
        let proc_start_ns = if pt.start_time_ns != 0 {
            pt.start_time_ns
        } else {
            start_time_ns
        };
        let start_ticks = proc_start_ns.saturating_mul(ticks_per_sec) / 1_000_000_000;
        let num_threads = if pt.num_threads == 0 {
            1
        } else {
            pt.num_threads as u64
        };
        let extra_fields: [u64; 16] = [
            tty_dev,
            tty_pgrp as u64,
            0,
            0,
            0,
            0,
            0,
            (((pt.user_time_ns as u128).saturating_mul(ticks_per_sec as u128)) / 1_000_000_000u128)
                as u64,
            (((pt.system_time_ns as u128).saturating_mul(ticks_per_sec as u128))
                / 1_000_000_000u128) as u64,
            0,
            0,
            0,
            0,
            num_threads,
            0,
            start_ticks,
        ];
        for field in extra_fields {
            let mut tmp64 = [0u8; 20];
            let n = fmt_u64(field, &mut tmp64);
            for i in 0..n {
                if pos < buf_size {
                    *dst.add(pos) = tmp64[i];
                    pos += 1;
                }
            }
            if pos < buf_size {
                *dst.add(pos) = b' ';
                pos += 1;
            }
        }

        let snap = mem.copied().unwrap_or_default();
        for field in [snap.vm_reserved_bytes, snap.vm_resident_pages] {
            let mut tmp64 = [0u8; 20];
            let n = fmt_u64(field, &mut tmp64);
            for i in 0..n {
                if pos < buf_size {
                    *dst.add(pos) = tmp64[i];
                    pos += 1;
                }
            }
            if pos < buf_size {
                *dst.add(pos) = b' ';
                pos += 1;
            }
        }
        if pos > 0 && *dst.add(pos - 1) == b' ' {
            pos -= 1;
        }
        if pos < buf_size {
            *dst.add(pos) = b'\n';
            pos += 1;
        }
        pos
    }
}

/// VMA entry layout returned by `MM_LIST_VMAS`. 64 bytes,
/// `#[repr(C)]`, must match mmsrv's `MmsrvVmaEntry`.
#[repr(C)]
struct VmaEntry {
    base: u64,
    length: u64,
    prot: u32,
    region_type: u32,
    backing_kind: u32,
    mo_kind: u32,
    present_pages: u32,
    referenced_pages: u32,
    shared_pages: u32,
    shared_dirty_pages: u32,
    private_dirty_pages: u32,
    writeback_pages: u32,
    _reserved: u32,
    pss_bytes: u64,
}

/// Generate `/proc/<pid>/maps`.
pub(super) unsafe fn proc_gen_maps(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return 0;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_LIST_VMAS;
        msg.length = 2;
        msg.regs[0] = pid as u64;
        msg.regs[1] = 0;
        let err = mp_call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let entry_count = reply.regs[0] as usize;
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;

        let entry_size = ::core::mem::size_of::<VmaEntry>();
        let max_entries = IPC_BUFFER_RESERVED_BYTES / entry_size;
        let count = entry_count.min(max_entries);

        let mut pos = 0usize;
        let mut tmp = [0u8; 20];

        for i in 0..count {
            let entry_ptr = reserved_ptr.add(i * entry_size) as *const VmaEntry;
            let e = &*entry_ptr;
            let end = e.base.wrapping_add(e.length);

            let n = fmt_u64_hex(e.base, &mut tmp);
            append_bytes(buf, &mut pos, &tmp[..n]);
            append_bytes(buf, &mut pos, b"-");
            let n = fmt_u64_hex(end, &mut tmp);
            append_bytes(buf, &mut pos, &tmp[..n]);
            append_bytes(buf, &mut pos, b" ");

            let prot = e.prot;
            let r = if prot & 1 != 0 { b'r' } else { b'-' };
            let w = if prot & 2 != 0 { b'w' } else { b'-' };
            let x = if prot & 4 != 0 { b'x' } else { b'-' };
            append_bytes(buf, &mut pos, &[r, w, x, b'p']);
            append_bytes(buf, &mut pos, b" 00000000 00:00 0 ");

            let region_name: &[u8] = match e.region_type {
                x if x == uapi::KERNITE_REGION_KIND_HEAP as u32 => b"[heap]",
                x if x == uapi::KERNITE_REGION_KIND_STACK as u32 => b"[stack]",
                _ => b"",
            };
            append_bytes(buf, &mut pos, region_name);
            append_bytes(buf, &mut pos, b"\n");
        }
        pos
    }
}

/// Reservation entry layout returned by `MM_LIST_RESERVATIONS`. 32 bytes,
/// `#[repr(C)]`, must match mmsrv's `MmsrvReservationEntry`.
#[repr(C)]
struct ReservationEntry {
    base: u64,
    length: u64,
    owner_badge: u64,
    kind: u32,
    _reserved: u32,
}

/// Generate `/proc/<pid>/reservations` — the process's VA reservations
/// (arena / guard / exclusion / system zones) and the badge that owns
/// each. SaltyOS-specific: reservations are mmsrv bookkeeping that the
/// kernel VMA list (`maps`) cannot see, so this complements it. Each
/// line is `<base>-<end> <kind> <owner>`, where `<owner>` is `[unowned]`
/// for the badge-0 exclusion zones (e.g. the null guard).
pub(super) unsafe fn proc_gen_reservations(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return 0;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_LIST_RESERVATIONS;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = mp_call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let entry_count = reply.regs[0] as usize;
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;

        let entry_size = ::core::mem::size_of::<ReservationEntry>();
        let max_entries = IPC_BUFFER_RESERVED_BYTES / entry_size;
        let count = entry_count.min(max_entries);

        let mut pos = 0usize;
        let mut tmp = [0u8; 20];

        for i in 0..count {
            let entry_ptr = reserved_ptr.add(i * entry_size) as *const ReservationEntry;
            let e = &*entry_ptr;
            let end = e.base.wrapping_add(e.length);

            let n = fmt_u64_hex(e.base, &mut tmp);
            append_bytes(buf, &mut pos, &tmp[..n]);
            append_bytes(buf, &mut pos, b"-");
            let n = fmt_u64_hex(end, &mut tmp);
            append_bytes(buf, &mut pos, &tmp[..n]);
            append_bytes(buf, &mut pos, b" ");

            let kind_str: &[u8] = match e.kind {
                0 => b"arena",
                1 => b"guard",
                2 => b"exclusion",
                3 => b"system",
                _ => b"unknown",
            };
            append_bytes(buf, &mut pos, kind_str);
            append_bytes(buf, &mut pos, b" ");

            if e.owner_badge == 0 {
                append_bytes(buf, &mut pos, b"[unowned]");
            } else {
                let n = fmt_u64_hex(e.owner_badge, &mut tmp);
                append_bytes(buf, &mut pos, &tmp[..n]);
            }
            append_bytes(buf, &mut pos, b"\n");
        }
        pos
    }
}

/// Format `/proc/<pid>/cmdline` from a prefetched [`ArgvBuf`]. Pure
/// formatter — the paginated `GET_ARGV` init queries run in the async
/// prefetch phase (`init_rpc`), not here. The blob is already
/// NUL-separated as Linux `cmdline` expects.
pub(crate) fn proc_gen_cmdline(argv: &ArgvBuf, buf: &mut [u8]) -> usize {
    let src = argv.as_slice();
    let copy = src.len().min(buf.len());
    buf[..copy].copy_from_slice(&src[..copy]);
    copy
}

/// Format `/proc/<pid>/comm` (the process short name + newline) from a
/// prefetched [`ProcInfoFull`]. Pure formatter — the init query that
/// fills `info` runs in the async prefetch phase (`init_rpc`), not here.
pub(crate) fn proc_gen_comm(info: &ProcInfoFull, buf: &mut [u8]) -> usize {
    let name = &info.name;
    let mut name_len = 0usize;
    while name_len < 32 && name[name_len] != 0 {
        name_len += 1;
    }
    if name_len == 0 {
        return 0;
    }
    let max = buf.len().saturating_sub(1);
    let copy = if name_len < max { name_len } else { max };
    buf[..copy].copy_from_slice(&name[..copy]);
    if copy < buf.len() {
        buf[copy] = b'\n';
        copy + 1
    } else {
        copy
    }
}

/// Generate `/proc/<pid>/statm` — pages format.
pub(super) unsafe fn proc_gen_statm(pid: u32, buf: &mut [u8]) -> usize {
    let Some(snap) = proc_get_mem_stats(pid) else {
        return 0;
    };
    let page_sz: u64 = 4096;
    let size = snap.vm_reserved_bytes / page_sz;
    let resident = snap.vm_resident_pages;
    let shared = snap.vm_shared_pages;
    let text = snap.vm_exe_bytes / page_sz;
    let lib = snap.vm_lib_bytes / page_sz;
    let data = snap.vm_data_bytes / page_sz;

    let mut pos = 0usize;
    append_u64_dec(buf, &mut pos, size);
    append_bytes(buf, &mut pos, b" ");
    append_u64_dec(buf, &mut pos, resident);
    append_bytes(buf, &mut pos, b" ");
    append_u64_dec(buf, &mut pos, shared);
    append_bytes(buf, &mut pos, b" ");
    append_u64_dec(buf, &mut pos, text);
    append_bytes(buf, &mut pos, b" ");
    append_u64_dec(buf, &mut pos, lib);
    append_bytes(buf, &mut pos, b" ");
    append_u64_dec(buf, &mut pos, data);
    append_bytes(buf, &mut pos, b" 0\n");
    pos
}

/// Generate `/proc/<pid>/io` — placeholder until I/O accounting
/// lands.
pub(super) unsafe fn proc_gen_io(_pid: u32, buf: &mut [u8]) -> usize {
    const BODY: &[u8] = b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n";
    let n = BODY.len().min(buf.len());
    buf[..n].copy_from_slice(&BODY[..n]);
    n
}

/// Generate `/proc/<pid>/smaps` — VMA-by-VMA expansion of `maps`.
pub(super) unsafe fn proc_gen_smaps(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        let ctx = ipc_ctx();
        if (*ctx).ipc_buffer.is_null() {
            return 0;
        }
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = MM_LIST_VMAS;
        msg.length = 2;
        msg.regs[0] = pid as u64;
        msg.regs[1] = 0;
        let err = mp_call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }
        let entry_count = reply.regs[0] as usize;
        let reserved_ptr = (*(*ctx).ipc_buffer).reserved.as_ptr() as *const u8;

        let entry_size = ::core::mem::size_of::<VmaEntry>();
        let max_entries = IPC_BUFFER_RESERVED_BYTES / entry_size;
        let count = entry_count.min(max_entries);

        let page_sz_kb: u64 = 4;
        let mut pos = 0usize;
        let mut tmp = [0u8; 20];

        for i in 0..count {
            let entry_ptr = reserved_ptr.add(i * entry_size) as *const VmaEntry;
            let e = &*entry_ptr;
            let end = e.base.wrapping_add(e.length);

            let n = fmt_u64_hex(e.base, &mut tmp);
            append_bytes(buf, &mut pos, &tmp[..n]);
            append_bytes(buf, &mut pos, b"-");
            let n = fmt_u64_hex(end, &mut tmp);
            append_bytes(buf, &mut pos, &tmp[..n]);
            append_bytes(buf, &mut pos, b" ");
            let prot = e.prot;
            let r = if prot & 1 != 0 { b'r' } else { b'-' };
            let w = if prot & 2 != 0 { b'w' } else { b'-' };
            let x = if prot & 4 != 0 { b'x' } else { b'-' };
            append_bytes(buf, &mut pos, &[r, w, x, b'p']);
            append_bytes(buf, &mut pos, b" 00000000 00:00 0\n");

            let size_kb = (e.length / 1024).max(1);
            let rss_kb = e.present_pages as u64 * page_sz_kb;
            let referenced_kb = e.referenced_pages as u64 * page_sz_kb;
            let shared_kb = e.shared_pages as u64 * page_sz_kb;
            let private_kb = rss_kb.saturating_sub(shared_kb);
            let pss_kb = e.pss_bytes / 1024;
            let shared_dirty = e.shared_dirty_pages as u64 * page_sz_kb;
            let private_dirty = e.private_dirty_pages as u64 * page_sz_kb;
            let shared_clean = shared_kb.saturating_sub(shared_dirty);
            let private_clean = private_kb.saturating_sub(private_dirty);
            let anon_kb = if e.mo_kind == 0 || e.mo_kind == 1 {
                rss_kb
            } else {
                0
            };

            smaps_emit_kb(buf, &mut pos, b"Size:", size_kb);
            smaps_emit_kb(buf, &mut pos, b"Rss:", rss_kb);
            smaps_emit_kb(buf, &mut pos, b"Pss:", pss_kb);
            smaps_emit_kb(buf, &mut pos, b"Shared_Clean:", shared_clean);
            smaps_emit_kb(buf, &mut pos, b"Shared_Dirty:", shared_dirty);
            smaps_emit_kb(buf, &mut pos, b"Private_Clean:", private_clean);
            smaps_emit_kb(buf, &mut pos, b"Private_Dirty:", private_dirty);
            smaps_emit_kb(buf, &mut pos, b"Referenced:", referenced_kb);
            smaps_emit_kb(buf, &mut pos, b"Anonymous:", anon_kb);
            smaps_emit_kb(buf, &mut pos, b"Swap:", 0);
            smaps_emit_kb(buf, &mut pos, b"KernelPageSize:", 4);
            smaps_emit_kb(buf, &mut pos, b"MMUPageSize:", 4);
            smaps_emit_kb(buf, &mut pos, b"Locked:", 0);
        }
        pos
    }
}

/// Generate `/proc/<pid>/cgroup` — Linux compat single root entry.
pub(super) unsafe fn proc_gen_cgroup(_pid: u32, buf: &mut [u8]) -> usize {
    const BODY: &[u8] = b"0::/\n";
    let n = BODY.len().min(buf.len());
    buf[..n].copy_from_slice(&BODY[..n]);
    n
}

/// Generate `/proc/<pid>/oom_score`.
pub(super) unsafe fn proc_gen_oom_score(_pid: u32, buf: &mut [u8]) -> usize {
    const BODY: &[u8] = b"0\n";
    let n = BODY.len().min(buf.len());
    buf[..n].copy_from_slice(&BODY[..n]);
    n
}
